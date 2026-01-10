//! ACP Server - Agent Credential Proxy daemon
//!
//! This binary runs the proxy server and management API.
//! It handles:
//! - MITM proxy with TLS termination
//! - Plugin execution for request transformation
//! - Management API for configuration
//! - Secure credential storage

pub mod api;

use acp_lib::{storage, tls::CertificateAuthority, TokenCache, Registry, Config, ProxyServer};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "acp-server")]
#[command(author, version, about = "Agent Credential Proxy Server", long_about = None)]
struct Args {
    /// Proxy port
    #[arg(long, default_value = "9443")]
    proxy_port: u16,

    /// Management API port
    #[arg(long, default_value = "9080")]
    api_port: u16,

    /// Data directory (for container/Linux mode)
    #[arg(long)]
    data_dir: Option<String>,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

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

    // Create token cache (will load tokens lazily from storage)
    let token_cache = Arc::new(TokenCache::new(Arc::clone(&store)));

    // Log initial token count
    let initial_tokens = token_cache.list().await?;
    tracing::info!("Loaded {} agent tokens from storage", initial_tokens.len());

    // Create registry for centralized metadata storage
    let registry = Arc::new(Registry::new(Arc::clone(&store)));
    tracing::info!("Registry initialized");

    // Create ProxyServer with token cache and store
    let proxy = ProxyServer::new(config.proxy_port, ca, Arc::clone(&token_cache), Arc::clone(&store))?;

    // Spawn proxy server in background
    let proxy_port = config.proxy_port;
    let _proxy_handle = tokio::spawn(async move {
        tracing::info!("Proxy server starting on 127.0.0.1:{}", proxy_port);
        if let Err(e) = proxy.start().await {
            tracing::error!("Proxy server error: {}", e);
        }
    });

    // Create API state with token cache, storage backend, and registry
    let api_state = api::ApiState::new(
        config.proxy_port,
        config.api_port,
        token_cache,
        Arc::clone(&store),
        registry,
    );

    // Build the API router
    let app = api::create_router(api_state);

    // Bind to the API port
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", config.api_port))
        .await?;

    tracing::info!("Management API listening on 0.0.0.0:{}", config.api_port);

    // Start API server (main task)
    axum::serve(listener, app).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_parsing() {
        let args = Args::parse_from(["acp-server"]);
        assert_eq!(args.proxy_port, 9443);
        assert_eq!(args.api_port, 9080);
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
}
