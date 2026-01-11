//! Proxy Core - MITM HTTPS proxy with agent authentication
//!
//! This module implements:
//! - HTTP CONNECT tunnel establishment
//! - Agent-side TLS with dynamic certificates
//! - Upstream TLS with system CA verification
//! - Bidirectional proxying
//! - Bearer token authentication

use crate::error::{AcpError, Result};
use crate::registry::Registry;
use crate::storage::SecretStore;
use crate::tls::CertificateAuthority;
use crate::types::AgentToken;
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, error, info};

/// ProxyServer handles MITM HTTPS proxy with agent authentication
pub struct ProxyServer {
    /// Port to listen on
    port: u16,
    /// Certificate Authority for dynamic cert generation
    ca: Arc<CertificateAuthority>,
    /// Secret store for loading plugins and credentials
    store: Arc<dyn SecretStore>,
    /// Registry for centralized metadata storage
    registry: Arc<Registry>,
    /// TLS connector for upstream connections
    upstream_connector: TlsConnector,
}

impl ProxyServer {
    /// Create a new ProxyServer instance with secret store and registry
    pub fn new(
        port: u16,
        ca: CertificateAuthority,
        store: Arc<dyn SecretStore>,
        registry: Arc<Registry>,
    ) -> Result<Self> {
        // Configure upstream TLS connector with system CA trust
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        };

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let upstream_connector = TlsConnector::from(Arc::new(tls_config));

        Ok(Self {
            port,
            ca: Arc::new(ca),
            store,
            registry,
            upstream_connector,
        })
    }

    /// Create a new ProxyServer instance from a Vec of tokens (for backward compatibility in tests)
    #[cfg(test)]
    pub async fn new_from_vec_async(port: u16, ca: CertificateAuthority, tokens: Vec<AgentToken>) -> Result<Self> {
        use crate::storage::FileStore;
        use crate::registry::TokenEntry;

        // Create a temporary FileStore for testing
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = Arc::new(
            FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore"),
        ) as Arc<dyn SecretStore>;

        let registry = Arc::new(Registry::new(Arc::clone(&store)));

        // Pre-populate storage with tokens in new format (token:{value})
        for token in &tokens {
            let token_json = serde_json::to_vec(&token).expect("serialize token");
            let store_key = format!("token:{}", token.token);
            store.set(&store_key, &token_json).await.expect("store token");

            // Add to registry
            let entry = TokenEntry {
                token_value: token.token.clone(),
                name: token.name.clone(),
                created_at: token.created_at,
            };
            registry.add_token(&entry).await.expect("add token to registry");
        }

        Self::new(port, ca, store, registry)
    }

    /// Start the proxy server
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", self.port))
            .await
            .map_err(|e| AcpError::network(format!("Failed to bind to port {}: {}", self.port, e)))?;

        info!("Proxy server listening on 127.0.0.1:{}", self.port);

        loop {
            let (stream, addr) = listener
                .accept()
                .await
                .map_err(|e| AcpError::network(format!("Failed to accept connection: {}", e)))?;

            debug!("Accepted connection from {}", addr);

            let ca = Arc::clone(&self.ca);
            let store = Arc::clone(&self.store);
            let registry = Arc::clone(&self.registry);
            let upstream_connector = self.upstream_connector.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, ca, store, registry, upstream_connector).await {
                    error!("Connection error: {}", e);
                }
            });
        }
    }
}

/// Handle a single proxy connection
async fn handle_connection(
    stream: TcpStream,
    ca: Arc<CertificateAuthority>,
    store: Arc<dyn SecretStore>,
    registry: Arc<Registry>,
    upstream_connector: TlsConnector,
) -> Result<()> {
    // Read the CONNECT request
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .await
        .map_err(|e| AcpError::network(format!("Failed to read request line: {}", e)))?;

    debug!("Request line: {}", request_line.trim());

    // Parse CONNECT request
    let target = parse_connect_request(&request_line)?;
    debug!("Target: {}", target);

    // Read headers to find Proxy-Authorization
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .map_err(|e| AcpError::network(format!("Failed to read header: {}", e)))?;

        if line == "\r\n" || line == "\n" {
            break;
        }
        headers.push(line);
    }

    // Validate authentication
    let _agent_token = validate_auth(&headers, &registry, &*store).await?;

    // Get the underlying stream back from BufReader
    // The BufReader may have buffered bytes that are part of the TLS handshake,
    // so we need to check the buffer and handle any buffered data
    let mut stream = reader.into_inner();

    // Send 200 Connection Established
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|e| AcpError::network(format!("Failed to send CONNECT response: {}", e)))?;

    debug!("Sent 200 Connection Established");

    // Now upgrade to TLS on both sides
    let (hostname, port) = parse_host_port(&target)?;

    // Agent-side TLS: accept with dynamic cert
    let agent_stream = accept_agent_tls(stream, &hostname, &ca).await?;
    debug!("Agent-side TLS established");

    // Upstream TLS: connect to target
    let upstream_stream = connect_upstream(&hostname, port, upstream_connector).await?;
    debug!("Upstream TLS established");

    // Bidirectional proxy with HTTP transformation
    proxy_streams_with_transform(agent_stream, upstream_stream, &hostname, &*store, &*registry).await?;

    Ok(())
}

/// Parse CONNECT request line to extract target
fn parse_connect_request(line: &str) -> Result<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(AcpError::protocol("Invalid CONNECT request"));
    }

    if parts[0] != "CONNECT" {
        return Err(AcpError::protocol(format!(
            "Expected CONNECT, got {}",
            parts[0]
        )));
    }

    Ok(parts[1].to_string())
}

/// Validate Proxy-Authorization header
async fn validate_auth(
    headers: &[String],
    registry: &Registry,
    _store: &dyn SecretStore,
) -> Result<AgentToken> {
    for header in headers {
        let header = header.trim();
        if header.to_lowercase().starts_with("proxy-authorization:") {
            let value = header[20..].trim(); // Skip "proxy-authorization:"

            // Extract Bearer token
            let token_value = if let Some(bearer_token) = value.strip_prefix("Bearer ") {
                bearer_token.to_string()
            } else {
                return Err(AcpError::auth("Invalid authorization scheme, expected Bearer"));
            };

            // Check if token exists in registry and get its details
            let tokens = registry.list_tokens().await?;
            if let Some(token_entry) = tokens.iter().find(|t| t.token_value == token_value) {
                // Construct AgentToken from registry TokenEntry
                let prefix = if token_value.len() >= 12 {
                    token_value[..12].to_string()
                } else {
                    token_value.clone()
                };
                return Ok(AgentToken {
                    id: token_value.clone(),
                    name: token_entry.name.clone(),
                    prefix,
                    token: token_value,
                    created_at: token_entry.created_at,
                });
            }

            return Err(AcpError::auth("Invalid bearer token"));
        }
    }

    Err(AcpError::auth("Missing Proxy-Authorization header"))
}

/// Parse host:port from target
fn parse_host_port(target: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() != 2 {
        return Err(AcpError::protocol(format!("Invalid target: {}", target)));
    }

    let hostname = parts[0].to_string();
    let port = parts[1]
        .parse::<u16>()
        .map_err(|_| AcpError::protocol(format!("Invalid port: {}", parts[1])))?;

    Ok((hostname, port))
}

/// Accept agent-side TLS connection with dynamic cert
async fn accept_agent_tls(
    stream: TcpStream,
    hostname: &str,
    ca: &CertificateAuthority,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>> {
    // Generate certificate for this hostname (returns DER format)
    let (cert_der, key_der) = ca
        .sign_for_hostname(hostname, None)
        .map_err(|e| AcpError::tls(format!("Failed to sign certificate: {}", e)))?;

    // Convert DER bytes to rustls types
    // For a self-signed CA, we need to include the CA cert in the chain
    // so the client can verify the signature
    let certs = vec![
        CertificateDer::from(cert_der),
        CertificateDer::from(ca.ca_cert_der()),
    ];

    // Parse private key from DER
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| AcpError::tls(format!("Failed to parse key DER: {:?}", e)))?;

    // Build server config
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .map_err(|e| AcpError::tls(format!("Failed to create server config: {}", e)))?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Accept TLS connection
    let tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| AcpError::tls(format!("Failed to accept TLS: {}", e)))?;

    Ok(tls_stream)
}

/// Connect to upstream server with TLS
async fn connect_upstream(
    hostname: &str,
    port: u16,
    connector: TlsConnector,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    // Connect TCP
    let tcp_stream = TcpStream::connect(format!("{}:{}", hostname, port))
        .await
        .map_err(|e| AcpError::network(format!("Failed to connect to upstream: {}", e)))?;

    // Upgrade to TLS
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|_| AcpError::tls(format!("Invalid server name: {}", hostname)))?;

    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| AcpError::tls(format!("Failed to connect upstream TLS: {}", e)))?;

    Ok(tls_stream)
}

/// Proxy data bidirectionally with HTTP request transformation
async fn proxy_streams_with_transform<A, U>(
    mut agent: A,
    mut upstream: U,
    hostname: &str,
    store: &dyn SecretStore,
    registry: &Registry,
) -> Result<()>
where
    A: AsyncReadExt + AsyncWriteExt + Unpin,
    U: AsyncReadExt + AsyncWriteExt + Unpin,
{
    use crate::proxy_transforms::parse_and_transform;

    // Read the first HTTP request from agent
    let mut buffer = Vec::new();
    let mut temp_buf = [0u8; 8192];

    // Read until we have a complete HTTP request (ends with \r\n\r\n or \n\n)
    loop {
        let n = agent.read(&mut temp_buf).await
            .map_err(|e| AcpError::network(format!("Failed to read from agent: {}", e)))?;

        if n == 0 {
            // Connection closed
            return Ok(());
        }

        buffer.extend_from_slice(&temp_buf[..n]);

        // Check if we have a complete request
        if buffer.windows(4).any(|w| w == b"\r\n\r\n") || buffer.windows(2).any(|w| w == b"\n\n") {
            break;
        }

        // Safety: don't read forever
        if buffer.len() > 1024 * 1024 {
            return Err(AcpError::protocol("HTTP request too large"));
        }
    }

    // Transform the request
    let transformed_bytes = parse_and_transform(&buffer, hostname, store, registry).await?;

    // Forward transformed request to upstream
    upstream.write_all(&transformed_bytes).await
        .map_err(|e| AcpError::network(format!("Failed to write to upstream: {}", e)))?;

    debug!("Forwarded transformed request to upstream");

    // Now do standard bidirectional proxying for the rest of the connection
    let (mut agent_read, mut agent_write) = tokio::io::split(agent);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    let agent_to_upstream = async {
        tokio::io::copy(&mut agent_read, &mut upstream_write)
            .await
            .map_err(|e| AcpError::network(format!("Agent to upstream copy failed: {}", e)))
    };

    let upstream_to_agent = async {
        tokio::io::copy(&mut upstream_read, &mut agent_write)
            .await
            .map_err(|e| AcpError::network(format!("Upstream to agent copy failed: {}", e)))
    };

    tokio::select! {
        result = agent_to_upstream => {
            debug!("Agent to upstream finished: {:?}", result);
            result?;
        }
        result = upstream_to_agent => {
            debug!("Upstream to agent finished: {:?}", result);
            result?;
        }
    }

    Ok(())
}

/// Proxy data bidirectionally between agent and upstream
#[allow(dead_code)]
async fn proxy_streams<A, U>(agent: A, upstream: U) -> Result<()>
where
    A: AsyncReadExt + AsyncWriteExt + Unpin,
    U: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let (mut agent_read, mut agent_write) = tokio::io::split(agent);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

    // Spawn two tasks for bidirectional copying
    let agent_to_upstream = async {
        tokio::io::copy(&mut agent_read, &mut upstream_write)
            .await
            .map_err(|e| AcpError::network(format!("Agent to upstream copy failed: {}", e)))
    };

    let upstream_to_agent = async {
        tokio::io::copy(&mut upstream_read, &mut agent_write)
            .await
            .map_err(|e| AcpError::network(format!("Upstream to agent copy failed: {}", e)))
    };

    // Run both until either completes
    tokio::select! {
        result = agent_to_upstream => {
            debug!("Agent to upstream finished: {:?}", result);
            result?;
        }
        result = upstream_to_agent => {
            debug!("Upstream to agent finished: {:?}", result);
            result?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_connect_request() {
        let result = parse_connect_request("CONNECT example.com:443 HTTP/1.1\r\n");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "example.com:443");
    }

    #[test]
    fn test_parse_connect_request_invalid() {
        let result = parse_connect_request("GET / HTTP/1.1\r\n");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_host_port() {
        let result = parse_host_port("example.com:443");
        assert!(result.is_ok());
        let (host, port) = result.unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_host_port_invalid() {
        assert!(parse_host_port("example.com").is_err());
        assert!(parse_host_port("example.com:abc").is_err());
    }

    #[tokio::test]
    async fn test_validate_auth_valid() {
        use crate::storage::FileStore;
        use crate::registry::TokenEntry;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = Arc::new(
            FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore"),
        ) as Arc<dyn crate::storage::SecretStore>;

        let registry = Arc::new(crate::registry::Registry::new(Arc::clone(&store)));

        // Create token and store it directly
        let token = AgentToken::new("Test Agent");
        let token_value = token.token.clone();
        let token_json = serde_json::to_vec(&token).expect("serialize token");
        let store_key = format!("token:{}", token.token);
        store.set(&store_key, &token_json).await.expect("store token");

        // Add to registry
        let entry = TokenEntry {
            token_value: token.token.clone(),
            name: token.name.clone(),
            created_at: token.created_at,
        };
        registry.add_token(&entry).await.expect("add token to registry");

        let headers = vec![format!("Proxy-Authorization: Bearer {}", token_value)];

        let result = validate_auth(&headers, &registry, &*store).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_auth_invalid_token() {
        use crate::storage::FileStore;
        use crate::registry::TokenEntry;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = Arc::new(
            FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore"),
        ) as Arc<dyn crate::storage::SecretStore>;

        let registry = Arc::new(crate::registry::Registry::new(Arc::clone(&store)));

        // Create token and store it directly
        let token = AgentToken::new("Test Agent");
        let token_json = serde_json::to_vec(&token).expect("serialize token");
        let store_key = format!("token:{}", token.token);
        store.set(&store_key, &token_json).await.expect("store token");

        // Add to registry
        let entry = TokenEntry {
            token_value: token.token.clone(),
            name: token.name.clone(),
            created_at: token.created_at,
        };
        registry.add_token(&entry).await.expect("add token to registry");

        let headers = vec!["Proxy-Authorization: Bearer wrong-token".to_string()];

        let result = validate_auth(&headers, &registry, &*store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_auth_missing() {
        use crate::storage::FileStore;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = Arc::new(
            FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore"),
        ) as Arc<dyn crate::storage::SecretStore>;

        let registry = Arc::new(crate::registry::Registry::new(Arc::clone(&store)));
        let headers = vec!["Host: example.com".to_string()];

        let result = validate_auth(&headers, &registry, &*store).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_proxy_server_creation() {
        let ca = CertificateAuthority::generate().expect("CA generation failed");
        let tokens = vec![AgentToken::new("Test Agent")];

        let proxy = ProxyServer::new_from_vec_async(9443, ca, tokens).await;
        assert!(proxy.is_ok());
    }
}
