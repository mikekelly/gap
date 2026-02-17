//! Proxy Core - MITM HTTPS proxy with agent authentication
//!
//! This module implements:
//! - HTTP CONNECT tunnel establishment
//! - Agent-side TLS with dynamic certificates
//! - Upstream TLS with system CA verification
//! - Bidirectional proxying
//! - Bearer token authentication

use crate::error::{GapError, Result};
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
    /// TLS acceptor for proxy connections (HTTPS on port 9443)
    proxy_acceptor: TlsAcceptor,
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

        // Generate localhost certificate for the proxy's TLS
        // Use "localhost" as the hostname since the proxy listens on 127.0.0.1
        let (cert_der, key_der) = ca
            .sign_for_hostname("localhost", None)
            .map_err(|e| GapError::tls(format!("Failed to sign localhost certificate: {}", e)))?;

        // Convert DER bytes to rustls types
        // Include CA cert in chain so clients can verify
        let certs = vec![
            CertificateDer::from(cert_der),
            CertificateDer::from(ca.ca_cert_der()),
        ];

        // Parse private key from DER
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_der)
            .map_err(|e| GapError::tls(format!("Failed to parse key DER: {:?}", e)))?;

        // Build server config for proxy TLS
        let proxy_server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key_der)
            .map_err(|e| GapError::tls(format!("Failed to create proxy server config: {}", e)))?;

        let proxy_acceptor = TlsAcceptor::from(Arc::new(proxy_server_config));

        Ok(Self {
            port,
            ca: Arc::new(ca),
            store,
            registry,
            upstream_connector,
            proxy_acceptor,
        })
    }

    /// Create a new ProxyServer instance with a custom upstream TLS connector
    ///
    /// Same as `new()` but accepts a caller-provided `TlsConnector` for upstream
    /// connections instead of building one from `webpki_roots`. This is useful
    /// when the upstream server uses a private/internal CA (e.g., in tests or
    /// enterprise environments with custom root CAs).
    pub fn new_with_upstream_tls(
        port: u16,
        ca: CertificateAuthority,
        store: Arc<dyn SecretStore>,
        registry: Arc<Registry>,
        upstream_connector: TlsConnector,
    ) -> Result<Self> {
        // Generate localhost certificate for the proxy's TLS
        // Use "localhost" as the hostname since the proxy listens on 127.0.0.1
        let (cert_der, key_der) = ca
            .sign_for_hostname("localhost", None)
            .map_err(|e| GapError::tls(format!("Failed to sign localhost certificate: {}", e)))?;

        // Convert DER bytes to rustls types
        // Include CA cert in chain so clients can verify
        let certs = vec![
            CertificateDer::from(cert_der),
            CertificateDer::from(ca.ca_cert_der()),
        ];

        // Parse private key from DER
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_der)
            .map_err(|e| GapError::tls(format!("Failed to parse key DER: {:?}", e)))?;

        // Build server config for proxy TLS
        let proxy_server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key_der)
            .map_err(|e| GapError::tls(format!("Failed to create proxy server config: {}", e)))?;

        let proxy_acceptor = TlsAcceptor::from(Arc::new(proxy_server_config));

        Ok(Self {
            port,
            ca: Arc::new(ca),
            store,
            registry,
            upstream_connector,
            proxy_acceptor,
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
            .map_err(|e| GapError::network(format!("Failed to bind to port {}: {}", self.port, e)))?;

        info!("Proxy server listening on 127.0.0.1:{}", self.port);

        loop {
            let (stream, addr) = listener
                .accept()
                .await
                .map_err(|e| GapError::network(format!("Failed to accept connection: {}", e)))?;

            debug!("Accepted connection from {}", addr);

            let ca = Arc::clone(&self.ca);
            let store = Arc::clone(&self.store);
            let registry = Arc::clone(&self.registry);
            let upstream_connector = self.upstream_connector.clone();
            let proxy_acceptor = self.proxy_acceptor.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, ca, store, registry, upstream_connector, proxy_acceptor).await {
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
    proxy_acceptor: TlsAcceptor,
) -> Result<()> {
    // First, accept the TLS connection from the proxy client
    let tls_stream = proxy_acceptor
        .accept(stream)
        .await
        .map_err(|e| GapError::tls(format!("Failed to accept proxy TLS: {}", e)))?;

    debug!("Proxy TLS connection established");

    // Read the CONNECT request
    let mut reader = BufReader::new(tls_stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .await
        .map_err(|e| GapError::network(format!("Failed to read request line: {}", e)))?;

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
            .map_err(|e| GapError::network(format!("Failed to read header: {}", e)))?;

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
        .map_err(|e| GapError::network(format!("Failed to send CONNECT response: {}", e)))?;

    debug!("Sent 200 Connection Established");

    // Now upgrade to TLS on both sides
    let (hostname, port) = parse_host_port(&target)?;

    // Agent-side TLS: accept with dynamic cert
    let agent_stream = accept_agent_tls(stream, &hostname, &ca).await?;
    debug!("Agent-side TLS established");

    // Upstream TLS: connect to target
    let upstream_stream = connect_upstream(&hostname, port, upstream_connector).await?;
    debug!("Upstream TLS established");

    // Bidirectional proxy with HTTP transformation via hyper
    // hyper handles ALL requests per connection (not just the first one)
    proxy_via_hyper(agent_stream, upstream_stream, hostname, store, registry).await?;

    Ok(())
}

/// Parse CONNECT request line to extract target
fn parse_connect_request(line: &str) -> Result<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(GapError::protocol("Invalid CONNECT request"));
    }

    if parts[0] != "CONNECT" {
        return Err(GapError::protocol(format!(
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
                return Err(GapError::auth("Invalid authorization scheme, expected Bearer"));
            };

            // Check if token exists in registry using O(1) lookup
            if let Some(metadata) = registry.get_token(&token_value).await? {
                // Construct AgentToken from registry TokenMetadata
                let prefix = if token_value.len() >= 12 {
                    token_value[..12].to_string()
                } else {
                    token_value.clone()
                };
                return Ok(AgentToken {
                    id: token_value.clone(),
                    name: metadata.name,
                    prefix,
                    token: token_value,
                    created_at: metadata.created_at,
                });
            }

            return Err(GapError::auth("Invalid bearer token"));
        }
    }

    Err(GapError::auth("Missing Proxy-Authorization header"))
}

/// Parse host:port from target
fn parse_host_port(target: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() != 2 {
        return Err(GapError::protocol(format!("Invalid target: {}", target)));
    }

    let hostname = parts[0].to_string();
    let port = parts[1]
        .parse::<u16>()
        .map_err(|_| GapError::protocol(format!("Invalid port: {}", parts[1])))?;

    Ok((hostname, port))
}

/// Accept agent-side TLS connection with dynamic cert
async fn accept_agent_tls<S>(
    stream: S,
    hostname: &str,
    ca: &CertificateAuthority,
) -> Result<tokio_rustls::server::TlsStream<S>>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Generate certificate for this hostname (returns DER format)
    let (cert_der, key_der) = ca
        .sign_for_hostname(hostname, None)
        .map_err(|e| GapError::tls(format!("Failed to sign certificate: {}", e)))?;

    // Convert DER bytes to rustls types
    // For a self-signed CA, we need to include the CA cert in the chain
    // so the client can verify the signature
    let certs = vec![
        CertificateDer::from(cert_der),
        CertificateDer::from(ca.ca_cert_der()),
    ];

    // Parse private key from DER
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| GapError::tls(format!("Failed to parse key DER: {:?}", e)))?;

    // Build server config
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .map_err(|e| GapError::tls(format!("Failed to create server config: {}", e)))?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Accept TLS connection
    let tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| GapError::tls(format!("Failed to accept TLS: {}", e)))?;

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
        .map_err(|e| GapError::network(format!("Failed to connect to upstream: {}", e)))?;

    // Upgrade to TLS
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string())
        .map_err(|_| GapError::tls(format!("Invalid server name: {}", hostname)))?;

    let tls_stream = connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| GapError::tls(format!("Failed to connect upstream TLS: {}", e)))?;

    Ok(tls_stream)
}

/// Proxy HTTP requests between agent and upstream using hyper.
///
/// Replaces the old `proxy_streams_with_transform()`: instead of only transforming
/// the first request then falling back to raw byte copying, this function uses hyper
/// to parse and transform ALL HTTP requests on the connection.
///
/// Architecture:
/// - Agent side: hyper server reads HTTP/1.1 requests from the agent
/// - For each request: convert to GAPRequest, apply plugin transforms, convert back
/// - Upstream side: hyper client forwards the transformed request
/// - Response flows back to agent unchanged
async fn proxy_via_hyper<A, U>(
    agent_stream: A,
    upstream_stream: U,
    hostname: String,
    store: Arc<dyn SecretStore>,
    registry: Arc<Registry>,
) -> Result<()>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use hyper::client::conn::http1 as client_http1;
    use hyper::server::conn::http1 as server_http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use http_body_util::BodyExt;

    // Client-side: handshake with upstream
    let upstream_io = TokioIo::new(upstream_stream);
    let (sender, conn) = client_http1::handshake(upstream_io).await?;
    tokio::spawn(async move { let _ = conn.await; });

    // Wrap sender in Arc<Mutex> because http1::SendRequest is not Clone
    // and send_request takes &mut self. HTTP/1.1 is sequential anyway.
    let sender = Arc::new(tokio::sync::Mutex::new(sender));

    // Server-side: serve agent connection, transforming each request
    let agent_io = TokioIo::new(agent_stream);

    let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let hostname = hostname.clone();
        let store = Arc::clone(&store);
        let registry = Arc::clone(&registry);
        let sender = Arc::clone(&sender);

        async move {
            // Collect the incoming body
            let (parts, body) = req.into_parts();
            let body_bytes = body.collect().await
                .map_err(|e| GapError::network(e.to_string()))?
                .to_bytes();
            let req = hyper::Request::from_parts(parts, ());

            // Convert to GAPRequest
            let gap_req = hyper_to_gap_request(&req, body_bytes, &hostname);

            // Apply plugin transforms (credential injection, etc.)
            let gap_req = crate::proxy_transforms::transform_request(
                gap_req, &hostname, store.as_ref(), &registry
            ).await?;

            // Convert back to hyper request
            let hyper_req = gap_request_to_hyper(&gap_req)?;

            // Forward to upstream
            let mut sender = sender.lock().await;
            let resp = sender.send_request(hyper_req).await
                .map_err(|e| GapError::network(e.to_string()))?;

            Ok::<_, GapError>(resp)
        }
    });

    server_http1::Builder::new()
        .serve_connection(agent_io, service)
        .await
        .map_err(|e| GapError::network(e.to_string()))?;

    Ok(())
}

/// Convert a hyper Request + collected body bytes to a GAPRequest
///
/// Used by the hyper-based proxy pipeline to convert incoming requests
/// into the format expected by `transform_request()`.
fn hyper_to_gap_request<B>(
    req: &hyper::Request<B>,
    body_bytes: bytes::Bytes,
    hostname: &str,
) -> crate::types::GAPRequest {
    use std::collections::HashMap;

    let method = req.method().as_str().to_string();

    // Construct full URL: the request URI in HTTP/1.1 is typically just the path
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = format!("https://{}{}", hostname, path_and_query);

    // Collect headers
    let mut headers = HashMap::new();
    for (key, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(key.as_str().to_string(), v.to_string());
        }
    }

    crate::types::GAPRequest {
        method,
        url,
        headers,
        body: body_bytes.to_vec(),
    }
}

/// Convert a GAPRequest back to a hyper Request
///
/// Used by the hyper-based proxy pipeline to convert transformed requests
/// back into hyper format for forwarding upstream.
fn gap_request_to_hyper(
    req: &crate::types::GAPRequest,
) -> Result<hyper::Request<http_body_util::Full<bytes::Bytes>>> {
    use crate::http_utils::extract_path_from_url;

    let path = extract_path_from_url(&req.url)?;

    let method: hyper::Method = req.method.parse().map_err(|_| {
        GapError::protocol(format!("Invalid HTTP method: {}", req.method))
    })?;

    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(&path);

    for (key, value) in &req.headers {
        builder = builder.header(key.as_str(), value.as_str());
    }

    let body = http_body_util::Full::new(bytes::Bytes::from(req.body.clone()));
    let hyper_req = builder.body(body)?;

    Ok(hyper_req)
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
        // Install default crypto provider for rustls (required for TLS operations)
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let ca = CertificateAuthority::generate().expect("CA generation failed");
        let tokens = vec![AgentToken::new("Test Agent")];

        let proxy = ProxyServer::new_from_vec_async(9443, ca, tokens).await;
        assert!(proxy.is_ok());
    }

    #[tokio::test]
    async fn test_proxy_tls_acceptor_creation() {
        // Install default crypto provider for rustls (required for TLS operations)
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Create CA
        let ca = CertificateAuthority::generate().expect("CA generation failed");

        // Create token
        let token = AgentToken::new("Test Agent");

        // Create proxy server - this should successfully create the TLS acceptor
        let proxy = ProxyServer::new_from_vec_async(19443, ca, vec![token])
            .await
            .expect("create proxy with TLS acceptor");

        // Verify the proxy was created successfully
        // The fact that this doesn't panic means the TLS acceptor was created successfully
        assert_eq!(proxy.port, 19443);
    }

    #[test]
    fn test_hyper_to_gap_request_get() {
        let hyper_req = hyper::Request::builder()
            .method("GET")
            .uri("/api/data?q=test")
            .header("Host", "api.example.com")
            .header("Accept", "application/json")
            .body(())
            .unwrap();

        let body_bytes = bytes::Bytes::new();
        let gap_req = hyper_to_gap_request(&hyper_req, body_bytes, "api.example.com");

        assert_eq!(gap_req.method, "GET");
        assert_eq!(gap_req.url, "https://api.example.com/api/data?q=test");
        assert_eq!(gap_req.get_header("host"), Some(&"api.example.com".to_string()));
        assert_eq!(gap_req.get_header("accept"), Some(&"application/json".to_string()));
        assert!(gap_req.body.is_empty());
    }

    #[test]
    fn test_hyper_to_gap_request_post_with_body() {
        let hyper_req = hyper::Request::builder()
            .method("POST")
            .uri("/api/submit")
            .header("Host", "api.example.com")
            .header("Content-Type", "application/json")
            .body(())
            .unwrap();

        let body_bytes = bytes::Bytes::from(r#"{"key":"value"}"#);
        let gap_req = hyper_to_gap_request(&hyper_req, body_bytes, "api.example.com");

        assert_eq!(gap_req.method, "POST");
        assert_eq!(gap_req.url, "https://api.example.com/api/submit");
        assert_eq!(gap_req.body, br#"{"key":"value"}"#);
    }

    #[test]
    fn test_hyper_to_gap_request_root_path() {
        let hyper_req = hyper::Request::builder()
            .method("GET")
            .uri("/")
            .header("Host", "example.com")
            .body(())
            .unwrap();

        let gap_req = hyper_to_gap_request(&hyper_req, bytes::Bytes::new(), "example.com");
        assert_eq!(gap_req.url, "https://example.com/");
    }

    #[test]
    fn test_gap_request_to_hyper_get() {
        use crate::types::GAPRequest;

        let gap_req = GAPRequest::new("GET", "https://api.example.com/data?q=test")
            .with_header("Host", "api.example.com")
            .with_header("Accept", "application/json");

        let hyper_req = gap_request_to_hyper(&gap_req).expect("conversion should succeed");

        assert_eq!(hyper_req.method(), hyper::Method::GET);
        assert_eq!(hyper_req.uri().path_and_query().unwrap().as_str(), "/data?q=test");
        assert_eq!(hyper_req.headers().get("Host").unwrap(), "api.example.com");
        assert_eq!(hyper_req.headers().get("Accept").unwrap(), "application/json");
    }

    #[test]
    fn test_gap_request_to_hyper_post_with_body() {
        use crate::types::GAPRequest;

        let gap_req = GAPRequest::new("POST", "https://api.example.com/submit")
            .with_header("Content-Type", "application/json")
            .with_body(br#"{"key":"value"}"#.to_vec());

        let hyper_req = gap_request_to_hyper(&gap_req).expect("conversion should succeed");

        assert_eq!(hyper_req.method(), hyper::Method::POST);
        assert_eq!(hyper_req.uri().path_and_query().unwrap().as_str(), "/submit");
    }

    #[test]
    fn test_gap_request_to_hyper_roundtrip() {
        // Create a GAPRequest, convert to hyper, convert back, verify equivalence
        use crate::types::GAPRequest;

        let original = GAPRequest::new("PUT", "https://api.example.com/items/42")
            .with_header("Host", "api.example.com")
            .with_header("Content-Type", "text/plain")
            .with_body(b"updated content".to_vec());

        // Convert to hyper
        let hyper_req = gap_request_to_hyper(&original).expect("to hyper");

        // Convert back
        let body_bytes = bytes::Bytes::from(original.body.clone());
        let roundtripped = hyper_to_gap_request(&hyper_req, body_bytes, "api.example.com");

        assert_eq!(roundtripped.method, original.method);
        assert_eq!(roundtripped.url, original.url);
        assert_eq!(roundtripped.body, original.body);
        // Headers should be present (hyper lowercases header names)
        assert_eq!(roundtripped.get_header("content-type"), Some(&"text/plain".to_string()));
    }

    /// Test proxy_via_hyper: transforms requests through hyper HTTP pipeline.
    ///
    /// Sets up a mock "upstream" HTTP/1.1 server behind a DuplexStream,
    /// and verifies that proxy_via_hyper correctly:
    /// 1. Receives the HTTP request from the agent side
    /// 2. Applies plugin transforms (credential injection)
    /// 3. Forwards the transformed request upstream
    /// 4. Returns the upstream response to the agent
    #[tokio::test]
    async fn test_proxy_via_hyper_transforms_and_forwards() {
        use crate::registry::{PluginEntry, Registry};
        use crate::storage::FileStore;
        use http_body_util::{BodyExt, Full};
        use hyper_util::rt::TokioIo;

        // -- Setup store with plugin + credentials --
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = Arc::new(
            FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore"),
        ) as Arc<dyn SecretStore>;
        let registry = Arc::new(Registry::new(Arc::clone(&store)));

        // Plugin that injects Authorization header
        let plugin_code = r#"
        var plugin = {
            name: "test-hyper",
            matchPatterns: ["api.test.com"],
            credentialSchema: ["api_key"],
            transform: function(request, credentials) {
                request.headers["Authorization"] = "Bearer " + credentials.api_key;
                return request;
            }
        };
        "#;
        store.set("plugin:test-hyper", plugin_code.as_bytes()).await.unwrap();
        let plugin_entry = PluginEntry {
            name: "test-hyper".to_string(),
            hosts: vec!["api.test.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
        };
        registry.add_plugin(&plugin_entry).await.unwrap();
        registry.set_credential("test-hyper", "api_key", "my-secret-key").await.unwrap();

        // -- Create paired DuplexStreams --
        // Agent side: agent_client writes HTTP requests, proxy reads them
        let (agent_client, agent_proxy) = tokio::io::duplex(8192);
        // Upstream side: proxy writes transformed requests, upstream_server reads them
        let (upstream_proxy, upstream_server) = tokio::io::duplex(8192);

        // -- Spawn a mock upstream HTTP server --
        let upstream_handle = tokio::spawn(async move {
            let io = TokioIo::new(upstream_server);
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                        // Capture the Authorization header the proxy injected
                        let auth = req.headers()
                            .get("authorization")
                            .map(|v| v.to_str().unwrap_or("").to_string())
                            .unwrap_or_default();

                        let body = format!("auth={}", auth);
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::new(Full::new(bytes::Bytes::from(body)))
                        )
                    }),
                )
                .await
                .expect("upstream server error");
        });

        // -- Spawn proxy_via_hyper --
        let proxy_store = Arc::clone(&store);
        let proxy_registry = Arc::clone(&registry);
        let proxy_handle = tokio::spawn(async move {
            proxy_via_hyper(
                agent_proxy,
                upstream_proxy,
                "api.test.com".to_string(),
                proxy_store,
                proxy_registry,
            )
            .await
        });

        // -- Agent sends a request through the proxy --
        let agent_io = TokioIo::new(agent_client);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(agent_io).await
            .expect("agent handshake");
        tokio::spawn(async move { let _ = conn.await; });

        let req = hyper::Request::builder()
            .method("GET")
            .uri("/data?q=test")
            .header("Host", "api.test.com")
            .body(Full::new(bytes::Bytes::new()))
            .unwrap();

        let resp = sender.send_request(req).await.expect("send request");
        assert_eq!(resp.status(), 200);

        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        // The upstream server should have received the injected Authorization header
        assert_eq!(body_str, "auth=Bearer my-secret-key");

        // Clean up
        drop(sender);
        let _ = proxy_handle.await;
        let _ = upstream_handle.await;
    }
}
