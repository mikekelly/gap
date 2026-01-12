//! ACP Server - Agent Credential Proxy daemon
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

use acp_lib::{storage, tls::CertificateAuthority, Registry, Config, ProxyServer};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "acp-server")]
#[command(author, version, about = "Agent Credential Proxy Server", long_about = None)]
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
    /// Check if the acp-server service is running (macOS only)
    #[cfg(target_os = "macos")]
    Status,

    /// Install the acp-server as a LaunchAgent (macOS only)
    #[cfg(target_os = "macos")]
    Install,

    /// Uninstall the acp-server LaunchAgent (macOS only)
    #[cfg(target_os = "macos")]
    Uninstall {
        /// Remove all data including ~/.acp/ directory
        #[arg(long)]
        purge: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Handle subcommands
    if let Some(command) = args.command {
        return match command {
            #[cfg(target_os = "macos")]
            Command::Status => {
                launchd::status();
                Ok(())
            }
            #[cfg(target_os = "macos")]
            Command::Install => launchd::install(),
            #[cfg(target_os = "macos")]
            Command::Uninstall { purge } => launchd::uninstall(purge),
        };
    }

    // Default: run the server
    // Initialize tracing with configured log level
    tracing_subscriber::fmt()
        .with_env_filter(args.log_level.clone())
        .init();

    // Build configuration
    let config = Config::new()
        .with_proxy_port(args.proxy_port)
        .with_api_port(args.api_port);

    let config = if let Some(data_dir) = args.data_dir {
        config.with_data_dir(data_dir)
    } else {
        config
    };

    tracing::info!("Starting ACP Server");
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

    // Create API state with storage backend and registry
    let api_state = api::ApiState::new(
        config.proxy_port,
        config.api_port,
        Arc::clone(&store),
        Arc::clone(&registry),
    );

    // Load persisted password hash from registry (if server was previously initialized)
    if let Ok(Some(hash)) = registry.get_password_hash().await {
        api_state.set_password_hash(hash).await;
        tracing::info!("Loaded password hash from registry");
    }

    // Build the API router
    let app = api::create_router(api_state);

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
    match (store.get(CA_CERT_KEY).await?, store.get(CA_KEY_KEY).await?) {
        (Some(cert_pem), Some(key_pem)) => {
            let cert_pem_str = String::from_utf8(cert_pem)?;
            let key_pem_str = String::from_utf8(key_pem)?;
            tracing::info!("Loaded CA from storage");
            Ok(CertificateAuthority::from_pem(&cert_pem_str, &key_pem_str)?)
        }
        _ => {
            // Generate new CA
            tracing::info!("Generating new CA certificate");
            let ca = CertificateAuthority::generate()?;

            // Save to storage for next time
            store.set(CA_CERT_KEY, ca.ca_cert_pem().as_bytes()).await?;
            store.set(CA_KEY_KEY, ca.ca_key_pem().as_bytes()).await?;
            tracing::info!("CA certificate saved to storage");

            Ok(ca)
        }
    }
}

/// Load management certificate from storage or generate a new one
async fn load_or_generate_mgmt_cert(
    store: &dyn storage::SecretStore,
    ca: &CertificateAuthority,
) -> anyhow::Result<()> {
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

            // Convert DER to PEM format
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

/// Convert DER to PEM format with line wrapping
fn der_to_pem(der: &[u8], label: &str) -> String {
    use std::fmt::Write;

    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // Base64 encode with line wrapping at 64 characters
    let mut encoded = String::new();
    let mut line_buf = String::new();

    let chunks = der.chunks_exact(3);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let b1 = chunk[0] as usize;
        let b2 = chunk[1] as usize;
        let b3 = chunk[2] as usize;

        line_buf.push(ALPHABET[b1 >> 2] as char);
        line_buf.push(ALPHABET[((b1 & 0x03) << 4) | (b2 >> 4)] as char);
        line_buf.push(ALPHABET[((b2 & 0x0f) << 2) | (b3 >> 6)] as char);
        line_buf.push(ALPHABET[b3 & 0x3f] as char);

        if line_buf.len() >= 64 {
            let _ = writeln!(encoded, "{}", line_buf);
            line_buf.clear();
        }
    }

    // Handle remainder
    if !remainder.is_empty() {
        let b1 = remainder[0] as usize;
        line_buf.push(ALPHABET[b1 >> 2] as char);

        if remainder.len() == 1 {
            line_buf.push(ALPHABET[(b1 & 0x03) << 4] as char);
            line_buf.push_str("==");
        } else {
            let b2 = remainder[1] as usize;
            line_buf.push(ALPHABET[((b1 & 0x03) << 4) | (b2 >> 4)] as char);
            line_buf.push(ALPHABET[(b2 & 0x0f) << 2] as char);
            line_buf.push('=');
        }
    }

    if !line_buf.is_empty() {
        let _ = writeln!(encoded, "{}", line_buf);
    }

    format!("-----BEGIN {}-----\n{}-----END {}-----\n", label, encoded, label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use acp_lib::storage::{FileStore, SecretStore};

    #[test]
    fn test_args_parsing() {
        let args = Args::parse_from(["acp-server"]);
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
        let args = Args::parse_from(["acp-server", "--proxy-port", "8443", "--api-port", "8080"]);
        assert_eq!(args.proxy_port, 8443);
        assert_eq!(args.api_port, 8080);
    }

    #[test]
    fn test_args_data_dir() {
        let args = Args::parse_from(["acp-server", "--data-dir", "/var/lib/acp"]);
        assert_eq!(args.data_dir, Some("/var/lib/acp".to_string()));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_status_subcommand_parses() {
        let args = Args::parse_from(["acp-server", "status"]);
        assert!(matches!(args.command, Some(Command::Status)));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_install_subcommand_parses() {
        let args = Args::parse_from(["acp-server", "install"]);
        assert!(matches!(args.command, Some(Command::Install)));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_uninstall_subcommand_parses() {
        let args = Args::parse_from(["acp-server", "uninstall"]);
        assert!(matches!(args.command, Some(Command::Uninstall { purge: false })));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_uninstall_subcommand_with_purge_flag() {
        let args = Args::parse_from(["acp-server", "uninstall", "--purge"]);
        assert!(matches!(args.command, Some(Command::Uninstall { purge: true })));
    }
}
