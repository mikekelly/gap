//! GAP Server - Gated Agent Proxy daemon
//!
//! This binary runs the proxy server and management API.
//! It handles:
//! - MITM proxy with TLS termination
//! - Plugin execution for request transformation
//! - Management API for configuration
//! - Secure credential storage

pub mod api;

#[cfg(target_os = "macos")]
pub mod launchd;

use gap_lib::{storage, tls::CertificateAuthority, Registry, Config, ProxyServer};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "gap-server")]
#[command(author, version, about = "Gated Agent Proxy Server", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Proxy port
    #[arg(long, default_value = "9443", global = true)]
    proxy_port: u16,

    /// Management API port
    #[arg(long, default_value = "9080", global = true)]
    api_port: u16,

    /// Data directory (for container/Linux mode)
    #[arg(long, global = true)]
    data_dir: Option<String>,

    /// Log level
    #[arg(long, default_value = "info", global = true)]
    log_level: String,
}

#[derive(Subcommand)]
enum Command {
    /// Check if the gap-server service is running (macOS only)
    #[cfg(target_os = "macos")]
    Status,

    /// Install the gap-server as a LaunchAgent (macOS only)
    #[cfg(target_os = "macos")]
    Install,

    /// Uninstall the gap-server LaunchAgent (macOS only)
    #[cfg(target_os = "macos")]
    Uninstall {
        /// Remove all data including ~/.gap/ directory
        #[arg(long)]
        purge: bool,
    },
}

/// Cleanup orphaned helper process (macOS only)
/// Removes LaunchAgent plist and attempts to unload the service
#[cfg(target_os = "macos")]
fn cleanup_orphaned_helper() {
    let home = std::env::var("HOME").unwrap_or_default();
    let plist_path = format!("{}/Library/LaunchAgents/com.mikekelly.gap-server.plist", home);

    // Try to unload via launchctl (old command)
    let _ = std::process::Command::new("launchctl")
        .args(["unload", &plist_path])
        .status();

    // Also try bootout (newer macOS)
    if let Ok(output) = std::process::Command::new("id").args(["-u"]).output() {
        if let Ok(uid) = String::from_utf8_lossy(&output.stdout).trim().parse::<u32>() {
            let _ = std::process::Command::new("launchctl")
                .args(["bootout", &format!("gui/{}", uid), "com.mikekelly.gap-server"])
                .status();
        }
    }

    // Note: We don't call `sfltool resetbtm` as it requires admin authentication
    // The BTM entries will become stale but shouldn't block new installs since
    // the bundle ID is the same and macOS will update the registration.

    // Remove the plist file
    if let Err(e) = std::fs::remove_file(&plist_path) {
        tracing::warn!("Failed to remove plist: {}", e);
    } else {
        tracing::info!("Removed LaunchAgent plist at {}", plist_path);
    }
}

/// Check if the binary still exists and cleanup if it doesn't
/// Returns Ok(true) if should continue running, Ok(false) if should exit
#[cfg(target_os = "macos")]
async fn check_binary_exists_and_cleanup(exe_path: &std::path::Path) -> anyhow::Result<bool> {
    // Check if we're running from inside GAP.app
    let exe_str = exe_path.to_string_lossy();
    if !exe_str.contains("/GAP.app/Contents/Library/LoginItems/") {
        // Not running from GAP.app, no need to check
        return Ok(true);
    }

    // Check if main app still exists (use try_exists for proper error handling)
    let main_app_path = std::path::Path::new("/Applications/GAP.app");
    if main_app_path.try_exists().unwrap_or(true) {
        // App still exists (or we couldn't check), continue running
        return Ok(true);
    }

    // App was deleted - clean up and signal to exit
    tracing::info!("GAP.app deleted, cleaning up orphaned helper process");
    cleanup_orphaned_helper();
    tracing::info!("Cleanup complete, exiting");

    Ok(false)
}

/// Spawn a background task that periodically checks if the binary still exists
#[cfg(target_os = "macos")]
fn spawn_periodic_binary_check() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        let exe_path = match std::env::current_exe() {
            Ok(path) => path,
            Err(e) => {
                tracing::warn!("Failed to get current exe path: {}", e);
                return;
            }
        };

        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));

        loop {
            interval.tick().await;

            match check_binary_exists_and_cleanup(&exe_path).await {
                Ok(true) => {
                    // Continue running
                }
                Ok(false) => {
                    // Binary was deleted, exit
                    std::process::exit(0);
                }
                Err(e) => {
                    tracing::error!("Error checking binary existence: {}", e);
                }
            }
        }
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install default crypto provider for rustls (required for TLS operations)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let args = Args::parse();

    // Handle subcommands (macOS only)
    #[cfg(target_os = "macos")]
    if let Some(command) = args.command {
        return match command {
            Command::Status => {
                launchd::status();
                Ok(())
            }
            Command::Install => launchd::install(),
            Command::Uninstall { purge } => launchd::uninstall(purge),
        };
    }

    // Default: run the server

    // Initialize tracing with configured log level (must be early for logging to work)
    tracing_subscriber::fmt()
        .with_env_filter(args.log_level.clone())
        .init();

    // Orphan detection at startup: if running from within GAP.app, check if main app still exists
    #[cfg(target_os = "macos")]
    if let Ok(exe_path) = std::env::current_exe() {
        match check_binary_exists_and_cleanup(&exe_path).await {
            Ok(false) => {
                // App was deleted, cleanup happened, exit
                std::process::exit(0);
            }
            Ok(true) => {
                // Continue running
            }
            Err(e) => {
                tracing::warn!("Error during startup orphan check: {}", e);
            }
        }
    }

    // Build configuration
    let config = Config::new()
        .with_proxy_port(args.proxy_port)
        .with_api_port(args.api_port);

    let config = if let Some(data_dir) = args.data_dir {
        config.with_data_dir(data_dir)
    } else {
        config
    };

    tracing::info!("Starting GAP Server");
    tracing::info!("Proxy port: {}", config.proxy_port);
    tracing::info!("API port: {}", config.api_port);

    // Create storage
    let data_dir_path = config.data_dir.as_ref().map(PathBuf::from);
    let store = storage::create_store(data_dir_path).await?;
    let store = Arc::from(store); // Convert Box to Arc

    // Load or generate CA certificate
    let ca = load_or_generate_ca(&*store).await?;
    tracing::info!("CA certificate loaded/generated");

    // Load or generate management certificate
    load_or_generate_mgmt_cert(&*store, &ca).await?;
    tracing::info!("Management certificate loaded/generated");

    // Create registry for centralized metadata storage
    let registry = Arc::new(Registry::new(Arc::clone(&store)));
    tracing::info!("Registry initialized");

    // Log initial token count from registry
    let initial_tokens = registry.list_tokens().await?;
    tracing::info!("Loaded {} agent tokens from storage", initial_tokens.len());

    // Create ProxyServer with store and registry
    let proxy = ProxyServer::new(
        config.proxy_port,
        ca,
        Arc::clone(&store),
        Arc::clone(&registry),
    )?;

    // Spawn proxy server in background
    let proxy_port = config.proxy_port;
    let _proxy_handle = tokio::spawn(async move {
        tracing::info!("Proxy server starting on 127.0.0.1:{}", proxy_port);
        if let Err(e) = proxy.start().await {
            tracing::error!("Proxy server error: {}", e);
        }
    });

    // Spawn periodic binary check (macOS only)
    #[cfg(target_os = "macos")]
    let _check_handle = spawn_periodic_binary_check();

    // Load management certificate for HTTPS
    let mgmt_cert_pem = store.get("mgmt:cert").await?
        .ok_or_else(|| anyhow::anyhow!("Management certificate not found"))?;
    let mgmt_key_pem = store.get("mgmt:key").await?
        .ok_or_else(|| anyhow::anyhow!("Management key not found"))?;

    // Create TLS configuration
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        mgmt_cert_pem,
        mgmt_key_pem
    ).await?;

    // Create API state with storage backend, registry, and TLS config
    let api_state = api::ApiState::new_with_tls(
        config.proxy_port,
        config.api_port,
        Arc::clone(&store),
        Arc::clone(&registry),
        tls_config.clone(),
    );

    // Load persisted password hash from registry (if server was previously initialized)
    if let Ok(Some(hash)) = registry.get_password_hash().await {
        api_state.set_password_hash(hash).await;
        tracing::info!("Loaded password hash from registry");
    }

    // Build the API router
    let app = api::create_router(api_state);

    // Bind address for HTTPS server
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], config.api_port));

    tracing::info!("Management API listening on https://0.0.0.0:{}", config.api_port);

    // Start HTTPS API server (main task)
    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

/// Load CA from storage or generate a new one
async fn load_or_generate_ca(store: &dyn storage::SecretStore) -> anyhow::Result<CertificateAuthority> {
    const CA_CERT_KEY: &str = "ca:cert";
    const CA_KEY_KEY: &str = "ca:key";

    // Try to load from storage
    let ca = match (store.get(CA_CERT_KEY).await?, store.get(CA_KEY_KEY).await?) {
        (Some(cert_pem), Some(key_pem)) => {
            let cert_pem_str = String::from_utf8(cert_pem)?;
            let key_pem_str = String::from_utf8(key_pem)?;
            tracing::info!("Loaded CA from storage");
            CertificateAuthority::from_pem(&cert_pem_str, &key_pem_str)?
        }
        _ => {
            // Generate new CA
            tracing::info!("Generating new CA certificate");
            let ca = CertificateAuthority::generate()?;

            // Save to storage for next time
            store.set(CA_CERT_KEY, ca.ca_cert_pem().as_bytes()).await?;
            store.set(CA_KEY_KEY, ca.ca_key_pem().as_bytes()).await?;
            tracing::info!("CA certificate saved to storage");

            ca
        }
    };

    // Export CA cert to well-known filesystem location
    let ca_path = gap_lib::ca_cert_path();
    if let Some(parent) = ca_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&ca_path, ca.ca_cert_pem())?;
    tracing::info!("CA certificate exported to {}", ca_path.display());

    Ok(ca)
}

/// Load management certificate from storage or generate a new one
async fn load_or_generate_mgmt_cert(
    store: &dyn storage::SecretStore,
    ca: &CertificateAuthority,
) -> anyhow::Result<()> {
    use gap_lib::tls::der_to_pem;

    const MGMT_CERT_KEY: &str = "mgmt:cert";
    const MGMT_KEY_KEY: &str = "mgmt:key";

    // Try to load from storage
    match (store.get(MGMT_CERT_KEY).await?, store.get(MGMT_KEY_KEY).await?) {
        (Some(_cert_pem), Some(_key_pem)) => {
            tracing::info!("Loaded management certificate from storage");
            Ok(())
        }
        _ => {
            // Generate new management certificate with default SANs
            tracing::info!("Generating new management certificate");
            let sans = vec![
                "DNS:localhost".to_string(),
                "IP:127.0.0.1".to_string(),
                "IP:::1".to_string(),
            ];

            let (cert_der, key_der) = ca.sign_server_cert(&sans)?;

            // Convert DER to PEM format using library function
            let cert_pem = der_to_pem(&cert_der, "CERTIFICATE");
            let key_pem = der_to_pem(&key_der, "PRIVATE KEY");

            // Save to storage
            store.set(MGMT_CERT_KEY, cert_pem.as_bytes()).await?;
            store.set(MGMT_KEY_KEY, key_pem.as_bytes()).await?;
            tracing::info!("Management certificate saved to storage");

            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gap_lib::storage::{FileStore, SecretStore};

    #[test]
    fn test_args_parsing() {
        let args = Args::parse_from(["gap-server"]);
        assert_eq!(args.proxy_port, 9443);
        assert_eq!(args.api_port, 9080);
    }

    #[tokio::test]
    async fn test_load_or_generate_mgmt_cert_creates_new() {
        // Create a temporary store
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(temp_dir.path().to_path_buf()).await.unwrap();
        let ca = CertificateAuthority::generate().unwrap();

        // Store the CA
        store.set("ca:cert", ca.ca_cert_pem().as_bytes()).await.unwrap();
        store.set("ca:key", ca.ca_key_pem().as_bytes()).await.unwrap();

        // Call load_or_generate_mgmt_cert - should create new cert with default SANs
        load_or_generate_mgmt_cert(&store, &ca).await.unwrap();

        // Verify cert and key were stored
        let stored_cert = store.get("mgmt:cert").await.unwrap();
        let stored_key = store.get("mgmt:key").await.unwrap();

        assert!(stored_cert.is_some());
        assert!(stored_key.is_some());

        // Verify they look like PEM
        let cert_str = String::from_utf8(stored_cert.unwrap()).unwrap();
        let key_str = String::from_utf8(stored_key.unwrap()).unwrap();
        assert!(cert_str.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_str.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[tokio::test]
    async fn test_load_or_generate_mgmt_cert_loads_existing() {
        // Create a temporary store with existing mgmt cert
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(temp_dir.path().to_path_buf()).await.unwrap();
        let ca = CertificateAuthority::generate().unwrap();

        // Pre-generate and store a management cert
        let sans = vec!["DNS:test.local".to_string()];
        let (_cert_der, _key_der) = ca.sign_server_cert(&sans).unwrap();

        // Simple PEM formatting (good enough for test)
        let cert_pem = format!("-----BEGIN CERTIFICATE-----\ntestcert\n-----END CERTIFICATE-----\n");
        let key_pem = format!("-----BEGIN PRIVATE KEY-----\ntestkey\n-----END PRIVATE KEY-----\n");

        store.set("mgmt:cert", cert_pem.as_bytes()).await.unwrap();
        store.set("mgmt:key", key_pem.as_bytes()).await.unwrap();

        // Call load_or_generate_mgmt_cert - should load existing, not regenerate
        load_or_generate_mgmt_cert(&store, &ca).await.unwrap();

        // Verify cert wasn't regenerated (still has our test values)
        let loaded_cert = store.get("mgmt:cert").await.unwrap().unwrap();
        let loaded_key = store.get("mgmt:key").await.unwrap().unwrap();
        assert_eq!(String::from_utf8(loaded_cert).unwrap(), cert_pem);
        assert_eq!(String::from_utf8(loaded_key).unwrap(), key_pem);
    }

    #[test]
    fn test_args_custom_ports() {
        let args = Args::parse_from(["gap-server", "--proxy-port", "8443", "--api-port", "8080"]);
        assert_eq!(args.proxy_port, 8443);
        assert_eq!(args.api_port, 8080);
    }

    #[test]
    fn test_args_data_dir() {
        let args = Args::parse_from(["gap-server", "--data-dir", "/var/lib/gap"]);
        assert_eq!(args.data_dir, Some("/var/lib/gap".to_string()));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_status_subcommand_parses() {
        let args = Args::parse_from(["gap-server", "status"]);
        assert!(matches!(args.command, Some(Command::Status)));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_install_subcommand_parses() {
        let args = Args::parse_from(["gap-server", "install"]);
        assert!(matches!(args.command, Some(Command::Install)));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_uninstall_subcommand_parses() {
        let args = Args::parse_from(["gap-server", "uninstall"]);
        assert!(matches!(args.command, Some(Command::Uninstall { purge: false })));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_uninstall_subcommand_with_purge_flag() {
        let args = Args::parse_from(["gap-server", "uninstall", "--purge"]);
        assert!(matches!(args.command, Some(Command::Uninstall { purge: true })));
    }

    #[tokio::test]
    async fn test_load_or_generate_ca_exports_to_filesystem() {
        use std::fs;

        // Create a temporary store
        let temp_dir = tempfile::tempdir().unwrap();
        let store = FileStore::new(temp_dir.path().to_path_buf()).await.unwrap();

        // Set up a temporary HOME directory for the test
        let temp_home = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", temp_home.path());

        // Load or generate CA - this should export the cert to the filesystem
        let ca = load_or_generate_ca(&store).await.unwrap();

        // Verify the CA cert was exported to the well-known path
        let ca_path = gap_lib::ca_cert_path();
        assert!(ca_path.exists(), "CA certificate should be exported to {}", ca_path.display());

        // Verify the content matches what the CA has
        let exported_content = fs::read_to_string(&ca_path).unwrap();
        assert_eq!(exported_content, ca.ca_cert_pem());
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_periodic_binary_check_detects_deletion() {
        use std::path::PathBuf;

        // Simulate running from GAP.app LoginItems
        let fake_exe_path = PathBuf::from("/Applications/GAP.app/Contents/Library/LoginItems/gap-server");

        // Test case 1: When /Applications/GAP.app exists, should return Ok(true)
        // (This will only pass if GAP.app actually exists, otherwise it will return Ok(false))
        // For a proper test, we need to check based on actual existence
        let app_exists = std::path::Path::new("/Applications/GAP.app").exists();
        let result = check_binary_exists_and_cleanup(&fake_exe_path).await;
        assert_eq!(result.unwrap(), app_exists);

        // Test case 2: When not running from GAP.app, should always return Ok(true)
        let non_app_path = PathBuf::from("/usr/local/bin/gap-server");
        let result = check_binary_exists_and_cleanup(&non_app_path).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_cleanup_removes_launchagent_plist() {
        use std::fs;

        // Set up a temporary HOME directory
        let temp_home = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", temp_home.path());

        // Create the LaunchAgents directory and plist file
        let launchagents_dir = temp_home.path().join("Library/LaunchAgents");
        fs::create_dir_all(&launchagents_dir).unwrap();

        let plist_path = launchagents_dir.join("com.mikekelly.gap-server.plist");
        fs::write(&plist_path, "<?xml version=\"1.0\"?><plist></plist>").unwrap();
        assert!(plist_path.exists());

        // Call cleanup
        cleanup_orphaned_helper();

        // Verify plist was removed
        assert!(!plist_path.exists(), "plist should be removed by cleanup");
    }
}
