//! Proxy Core - MITM HTTPS proxy with agent authentication
//!
//! This module implements:
//! - HTTP CONNECT tunnel establishment
//! - Agent-side TLS with dynamic certificates (H1 and H2 via ALPN)
//! - Upstream TLS with system CA verification
//! - Bidirectional proxying (HTTP/1.1 and HTTP/2)
//! - Bearer token authentication

use crate::database::GapDatabase;
use crate::error::{GapError, Result};
use crate::tls::CertificateAuthority;
use crate::types::{ActivityEntry, AgentToken};
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use rand::Rng;
use tracing::{debug, error, info, Instrument};

/// ProxyServer handles MITM HTTPS proxy with agent authentication
pub struct ProxyServer {
    /// Port to listen on
    port: u16,
    /// Certificate Authority for dynamic cert generation
    ca: Arc<CertificateAuthority>,
    /// Database for tokens, plugins, credentials, and activity logging
    db: Arc<GapDatabase>,
    /// Root certificates for upstream TLS connections.
    /// Stored as root certs (not a pre-built connector) so we can build
    /// per-connection connectors with ALPN matching the agent's negotiated protocol.
    upstream_root_certs: Arc<rustls::RootCertStore>,
    /// TLS acceptor for proxy connections (HTTPS on port 9443)
    proxy_acceptor: TlsAcceptor,
    /// Optional broadcast sender for real-time activity streaming (SSE).
    /// When set, each proxied request's ActivityEntry is sent here in addition
    /// to being logged to the database.
    activity_tx: Option<tokio::sync::broadcast::Sender<ActivityEntry>>,
}

impl ProxyServer {
    /// Create a new ProxyServer instance with GapDatabase
    pub fn new(
        port: u16,
        ca: CertificateAuthority,
        db: Arc<GapDatabase>,
    ) -> Result<Self> {
        // Store root certs for building per-connection upstream TLS connectors
        let upstream_root_certs = Arc::new(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
        });

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
            db,
            upstream_root_certs,
            proxy_acceptor,
            activity_tx: None,
        })
    }

    /// Create a new ProxyServer instance with custom upstream root certificates
    ///
    /// Same as `new()` but accepts caller-provided root certificates for upstream
    /// TLS verification instead of using `webpki_roots`. This is useful when the
    /// upstream server uses a private/internal CA (e.g., in tests or enterprise
    /// environments with custom root CAs).
    pub fn new_with_upstream_tls(
        port: u16,
        ca: CertificateAuthority,
        db: Arc<GapDatabase>,
        upstream_root_certs: Arc<rustls::RootCertStore>,
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
            db,
            upstream_root_certs,
            proxy_acceptor,
            activity_tx: None,
        })
    }

    /// Set the broadcast sender for real-time activity streaming.
    /// When set, each proxied request's ActivityEntry is broadcast in addition
    /// to being logged to the database.
    pub fn set_activity_broadcast(&mut self, tx: tokio::sync::broadcast::Sender<ActivityEntry>) {
        self.activity_tx = Some(tx);
    }

    /// Create a new ProxyServer instance from a Vec of tokens (for backward compatibility in tests)
    #[cfg(test)]
    pub async fn new_from_vec_async(port: u16, ca: CertificateAuthority, tokens: Vec<AgentToken>) -> Result<Self> {
        let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

        for token in &tokens {
            db.add_token(&token.token, &token.name, token.created_at)
                .await
                .expect("add token to db");
        }

        Self::new(port, ca, db)
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
            let db = Arc::clone(&self.db);
            let upstream_root_certs = Arc::clone(&self.upstream_root_certs);
            let proxy_acceptor = self.proxy_acceptor.clone();
            let activity_tx = self.activity_tx.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, ca, db, upstream_root_certs, proxy_acceptor, activity_tx).await {
                    error!("Connection error: {}", e);
                }
            });
        }
    }
}

/// A stream wrapper that prepends buffered bytes before reading from the inner stream.
///
/// Used for protocol detection: we read the first byte to determine TLS vs plain HTTP,
/// then wrap the stream so the consumer (TLS acceptor or HTTP parser) sees the complete
/// data including that first byte.
///
/// Implements both AsyncRead (prefix + inner) and AsyncWrite (delegates to inner).
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // First, drain any remaining prefix bytes
        if this.prefix_pos < this.prefix.len() {
            let remaining = &this.prefix[this.prefix_pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.prefix_pos += to_copy;
            return std::task::Poll::Ready(Ok(()));
        }

        // Then delegate to inner stream
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Handle a single proxy connection
async fn handle_connection(
    stream: TcpStream,
    ca: Arc<CertificateAuthority>,
    db: Arc<GapDatabase>,
    upstream_root_certs: Arc<rustls::RootCertStore>,
    proxy_acceptor: TlsAcceptor,
    activity_tx: Option<tokio::sync::broadcast::Sender<ActivityEntry>>,
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
    let agent_token = validate_auth(&headers, &db).await?;

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

    let (hostname, port) = parse_host_port(&target)?;

    // Peek at first byte to detect protocol: TLS ClientHello starts with 0x16,
    // plain HTTP starts with an ASCII method character (G, P, H, D, O, T, C).
    //
    // Since TLS streams don't have a native peek method, we read one byte and
    // wrap the stream in PrefixedStream to prepend it back for the consumer.
    let mut first_byte = [0u8; 1];
    let n = stream.read(&mut first_byte).await
        .map_err(|e| GapError::network(format!("Failed to read first byte of inner stream: {}", e)))?;

    if n == 0 {
        return Err(GapError::network("Client closed connection after CONNECT"));
    }

    let is_tls = first_byte[0] == 0x16;
    debug!("Inner protocol detection: first_byte=0x{:02x} is_tls={}", first_byte[0], is_tls);

    // Wrap stream with the consumed byte prepended so downstream consumers
    // (TLS handshake or HTTP parser) see the complete data.
    let stream = PrefixedStream::new(first_byte.to_vec(), stream);

    if is_tls {
        // --- HTTPS path (existing): MITM TLS on both sides ---

        // Agent-side TLS: accept with dynamic cert, detect negotiated protocol
        let (agent_stream, is_h2) = accept_agent_tls(stream, &hostname, &ca).await?;
        debug!("Agent-side TLS established (h2={})", is_h2);

        // Build upstream TLS connector with matching ALPN protocol.
        let alpn = if is_h2 {
            vec![b"h2".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates((*upstream_root_certs).clone())
            .with_no_client_auth();
        client_config.alpn_protocols = alpn;
        let connector = TlsConnector::from(Arc::new(client_config));

        // Upstream TLS: connect to target
        let upstream_stream = connect_upstream(&hostname, port, connector).await?;
        debug!("Upstream TLS established");

        // Bidirectional proxy with HTTP transformation via hyper
        proxy_via_hyper(agent_stream, upstream_stream, hostname, db, agent_token.name.clone(), is_h2, true, activity_tx).await?;
    } else {
        // --- Plain HTTP path: no TLS on either side ---
        debug!("Plain HTTP detected through CONNECT tunnel to {}:{}", hostname, port);

        // Connect to upstream over plain TCP (no TLS)
        let upstream_stream = TcpStream::connect(format!("{}:{}", hostname, port))
            .await
            .map_err(|e| GapError::network(format!("Failed to connect upstream (plain): {}", e)))?;
        debug!("Upstream plain TCP established");

        // Proxy via hyper with use_tls=false (HTTP/1.1 only for plain HTTP)
        proxy_via_hyper(stream, upstream_stream, hostname, db, agent_token.name.clone(), false, false, activity_tx).await?;
    }

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
    db: &GapDatabase,
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

            // Check if token exists in database
            if let Some(metadata) = db.get_token(&token_value).await? {
                // Construct AgentToken from TokenMetadata
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

/// Accept agent-side TLS connection with dynamic cert.
///
/// Advertises both h2 and http/1.1 via ALPN. Returns the TLS stream and
/// whether the agent negotiated HTTP/2.
async fn accept_agent_tls<S>(
    stream: S,
    hostname: &str,
    ca: &CertificateAuthority,
) -> Result<(tokio_rustls::server::TlsStream<S>, bool)>
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

    // Build server config with ALPN advertising both h2 and http/1.1
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .map_err(|e| GapError::tls(format!("Failed to create server config: {}", e)))?;

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Accept TLS connection
    let tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| GapError::tls(format!("Failed to accept TLS: {}", e)))?;

    // Detect negotiated protocol from the server connection state
    let is_h2 = tls_stream
        .get_ref()
        .1
        .alpn_protocol() == Some(b"h2".as_slice());

    Ok((tls_stream, is_h2))
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
/// Supports both HTTP/1.1 and HTTP/2 based on the `is_h2` flag (determined
/// by ALPN negotiation during agent-side TLS handshake).
///
/// The `use_tls` flag controls URL scheme construction: when true, requests
/// are constructed with `https://`; when false, `http://`. This allows the
/// same transform pipeline to handle both HTTPS (MITM TLS) and plain HTTP
/// traffic through a CONNECT tunnel.
///
/// Architecture:
/// - Agent side: `hyper_util::server::conn::auto::Builder` handles both H1/H2
/// - For each request: convert to GAPRequest, apply plugin transforms, convert back
/// - Upstream side: matching hyper client (H1 or H2)
/// - Response flows back to agent unchanged
async fn proxy_via_hyper<A, U>(
    agent_stream: A,
    upstream_stream: U,
    hostname: String,
    db: Arc<GapDatabase>,
    agent_name: String,
    is_h2: bool,
    use_tls: bool,
    activity_tx: Option<tokio::sync::broadcast::Sender<ActivityEntry>>,
) -> Result<()>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use http_body_util::BodyExt;

    let upstream_io = TokioIo::new(upstream_stream);
    let agent_io = TokioIo::new(agent_stream);

    if is_h2 {
        // HTTP/2 upstream handshake
        let (sender, conn) = hyper::client::conn::http2::handshake(
            TokioExecutor::new(),
            upstream_io,
        ).await.map_err(|e| GapError::network(e.to_string()))?;
        tokio::spawn(async move { let _ = conn.await; });

        // H2 SendRequest is Clone, no Mutex needed (concurrent requests supported)
        let activity_tx_h2 = activity_tx;
        let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
            let hostname = hostname.clone();
            let db = Arc::clone(&db);
            let agent_name = agent_name.clone();
            let mut sender = sender.clone();
            let activity_tx = activity_tx_h2.clone();

            async move {
                let request_id: u64 = rand::thread_rng().gen();
                let request_id_str = format!("{:016x}", request_id);
                let (parts, body) = req.into_parts();
                let body_bytes = body.collect().await
                    .map_err(|e| GapError::network(e.to_string()))?
                    .to_bytes();
                let req = hyper::Request::from_parts(parts, ());

                let gap_req = hyper_to_gap_request(&req, body_bytes, &hostname, use_tls);
                let method = gap_req.method.clone();
                let url = gap_req.url.clone();

                let span = tracing::info_span!("proxy_request",
                    request_id = %request_id_str,
                    method = %method,
                    url = %url,
                );

                let (gap_req, plugin_info) = crate::proxy_transforms::transform_request(
                    gap_req, &hostname, &*db, use_tls
                ).instrument(span.clone()).await?;

                let hyper_req = gap_request_to_hyper(&gap_req)?;

                let resp = sender.send_request(hyper_req).await
                    .map_err(|e| GapError::network(e.to_string()))?;

                let status = resp.status().as_u16();
                let _enter = span.enter();
                debug!("Response status: {}", status);
                drop(_enter);

                // Log activity asynchronously (don't block the response)
                let db_log = Arc::clone(&db);
                let agent_name_log = agent_name.clone();
                tokio::spawn(async move {
                    let entry = ActivityEntry {
                        timestamp: chrono::Utc::now(),
                        request_id: Some(request_id_str),
                        method,
                        url,
                        agent_id: Some(agent_name_log),
                        status,
                        plugin_name: Some(plugin_info.name),
                        plugin_sha: plugin_info.commit_sha,
                        source_hash: plugin_info.source_hash,
                        request_headers: plugin_info.scrubbed_headers,
                        rejection_stage: None,
                        rejection_reason: None,
                    };
                    if let Err(e) = db_log.log_activity(&entry).await {
                        tracing::warn!("Failed to log activity: {}", e);
                    }
                    // Broadcast to SSE subscribers (ignore errors if no receivers)
                    if let Some(ref tx) = activity_tx {
                        let _ = tx.send(entry);
                    }
                });

                Ok::<_, GapError>(resp)
            }
        });

        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(agent_io, service)
            .await
            .map_err(|e| GapError::network(e.to_string()))?;
    } else {
        // HTTP/1.1 upstream handshake
        let (sender, conn) = hyper::client::conn::http1::handshake(upstream_io).await?;
        tokio::spawn(async move { let _ = conn.await; });

        // Wrap sender in Arc<Mutex> because http1::SendRequest is not Clone
        // and send_request takes &mut self. HTTP/1.1 is sequential anyway.
        let sender = Arc::new(tokio::sync::Mutex::new(sender));

        let activity_tx_h1 = activity_tx;
        let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
            let hostname = hostname.clone();
            let db = Arc::clone(&db);
            let agent_name = agent_name.clone();
            let sender = Arc::clone(&sender);
            let activity_tx = activity_tx_h1.clone();

            async move {
                let request_id: u64 = rand::thread_rng().gen();
                let request_id_str = format!("{:016x}", request_id);
                let (parts, body) = req.into_parts();
                let body_bytes = body.collect().await
                    .map_err(|e| GapError::network(e.to_string()))?
                    .to_bytes();
                let req = hyper::Request::from_parts(parts, ());

                let gap_req = hyper_to_gap_request(&req, body_bytes, &hostname, use_tls);
                let method = gap_req.method.clone();
                let url = gap_req.url.clone();

                let span = tracing::info_span!("proxy_request",
                    request_id = %request_id_str,
                    method = %method,
                    url = %url,
                );

                let (gap_req, plugin_info) = crate::proxy_transforms::transform_request(
                    gap_req, &hostname, &*db, use_tls
                ).instrument(span.clone()).await?;

                let hyper_req = gap_request_to_hyper(&gap_req)?;

                let mut sender = sender.lock().await;
                let resp = sender.send_request(hyper_req).await
                    .map_err(|e| GapError::network(e.to_string()))?;

                let status = resp.status().as_u16();
                let _enter = span.enter();
                debug!("Response status: {}", status);
                drop(_enter);

                // Log activity asynchronously (don't block the response)
                let db_log = Arc::clone(&db);
                let agent_name_log = agent_name.clone();
                tokio::spawn(async move {
                    let entry = ActivityEntry {
                        timestamp: chrono::Utc::now(),
                        request_id: Some(request_id_str),
                        method,
                        url,
                        agent_id: Some(agent_name_log),
                        status,
                        plugin_name: Some(plugin_info.name),
                        plugin_sha: plugin_info.commit_sha,
                        source_hash: plugin_info.source_hash,
                        request_headers: plugin_info.scrubbed_headers,
                        rejection_stage: None,
                        rejection_reason: None,
                    };
                    if let Err(e) = db_log.log_activity(&entry).await {
                        tracing::warn!("Failed to log activity: {}", e);
                    }
                    // Broadcast to SSE subscribers (ignore errors if no receivers)
                    if let Some(ref tx) = activity_tx {
                        let _ = tx.send(entry);
                    }
                });

                Ok::<_, GapError>(resp)
            }
        });

        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(agent_io, service)
            .await
            .map_err(|e| GapError::network(e.to_string()))?;
    }

    Ok(())
}

/// Convert a hyper Request + collected body bytes to a GAPRequest
///
/// Used by the hyper-based proxy pipeline to convert incoming requests
/// into the format expected by `transform_request()`.
///
/// The `use_tls` flag determines the URL scheme: `https://` when true (MITM TLS),
/// `http://` when false (plain HTTP through CONNECT tunnel).
fn hyper_to_gap_request<B>(
    req: &hyper::Request<B>,
    body_bytes: bytes::Bytes,
    hostname: &str,
    use_tls: bool,
) -> crate::types::GAPRequest {
    use std::collections::HashMap;

    let method = req.method().as_str().to_string();

    // Construct full URL: the request URI in HTTP/1.1 is typically just the path
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let scheme = if use_tls { "https" } else { "http" };
    let url = format!("{}://{}{}", scheme, hostname, path_and_query);

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
        let db = GapDatabase::in_memory().await.unwrap();

        let token = AgentToken::new("Test Agent");
        let token_value = token.token.clone();

        db.add_token(&token.token, &token.name, token.created_at)
            .await
            .expect("add token to db");

        let headers = vec![format!("Proxy-Authorization: Bearer {}", token_value)];

        let result = validate_auth(&headers, &db).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_auth_invalid_token() {
        let db = GapDatabase::in_memory().await.unwrap();

        let token = AgentToken::new("Test Agent");
        db.add_token(&token.token, &token.name, token.created_at)
            .await
            .expect("add token to db");

        let headers = vec!["Proxy-Authorization: Bearer wrong-token".to_string()];

        let result = validate_auth(&headers, &db).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_auth_missing() {
        let db = GapDatabase::in_memory().await.unwrap();
        let headers = vec!["Host: example.com".to_string()];

        let result = validate_auth(&headers, &db).await;
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
        let gap_req = hyper_to_gap_request(&hyper_req, body_bytes, "api.example.com", true);

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
        let gap_req = hyper_to_gap_request(&hyper_req, body_bytes, "api.example.com", true);

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

        let gap_req = hyper_to_gap_request(&hyper_req, bytes::Bytes::new(), "example.com", true);
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
        let roundtripped = hyper_to_gap_request(&hyper_req, body_bytes, "api.example.com", true);

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
    /// 5. Logs activity to the database
    #[tokio::test]
    async fn test_proxy_via_hyper_transforms_and_forwards() {
        use crate::database::GapDatabase;
        use crate::types::PluginEntry;
        use http_body_util::{BodyExt, Full};
        use hyper_util::rt::TokioIo;

        // -- Setup database with plugin + credentials --
        let db = Arc::new(GapDatabase::in_memory().await.unwrap());

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
        let plugin_entry = PluginEntry {
            name: "test-hyper".to_string(),
            hosts: vec!["api.test.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
            dangerously_permit_http: false,
        };
        db.add_plugin(&plugin_entry, plugin_code).await.unwrap();
        db.set_credential("test-hyper", "api_key", "my-secret-key").await.unwrap();

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

        // -- Spawn proxy_via_hyper (H1 mode) --
        let proxy_db = Arc::clone(&db);
        let proxy_handle = tokio::spawn(async move {
            proxy_via_hyper(
                agent_proxy,
                upstream_proxy,
                "api.test.com".to_string(),
                proxy_db,
                "test-agent".to_string(),
                false, // is_h2 = false for H1
                true,  // use_tls = true (HTTPS)
                None,  // no activity broadcast
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

        // Give the spawned activity logger a moment to complete
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Verify activity was logged
        let activity = db.get_activity(None).await.unwrap();
        assert_eq!(activity.len(), 1);
        assert_eq!(activity[0].method, "GET");
        assert_eq!(activity[0].url, "https://api.test.com/data?q=test");
        assert_eq!(activity[0].agent_id, Some("test-agent".to_string()));
        assert_eq!(activity[0].status, 200);
        assert_eq!(activity[0].plugin_name, Some("test-hyper".to_string()));
        assert_eq!(activity[0].plugin_sha, None);

        // Verify scrubbed request headers were logged
        assert!(activity[0].request_headers.is_some());
        let headers_json = activity[0].request_headers.as_ref().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(headers_json).unwrap();
        // Credential value "my-secret-key" should be redacted in the logged headers
        let auth_value = parsed.get("Authorization")
            .or_else(|| parsed.get("authorization"))
            .expect("Authorization header should be present");
        assert!(auth_value.as_str().unwrap().contains("[REDACTED]"),
            "Credential should be scrubbed, got: {}", auth_value);
        assert!(!auth_value.as_str().unwrap().contains("my-secret-key"),
            "Raw credential should not appear in logged headers");
    }

    #[test]
    fn test_hyper_to_gap_request_http_scheme() {
        let hyper_req = hyper::Request::builder()
            .method("GET")
            .uri("/api/data?q=test")
            .header("Host", "api.example.com")
            .body(())
            .unwrap();

        // use_tls = false should produce http:// URL
        let gap_req = hyper_to_gap_request(&hyper_req, bytes::Bytes::new(), "api.example.com", false);
        assert_eq!(gap_req.url, "http://api.example.com/api/data?q=test");
    }

    /// Test proxy_via_hyper with use_tls=false: plain HTTP proxy path.
    ///
    /// Verifies that when use_tls is false, the transform pipeline receives
    /// http:// URLs and the request is correctly proxied through the hyper pipeline.
    #[tokio::test]
    async fn test_proxy_via_hyper_plain_http() {
        use crate::database::GapDatabase;
        use crate::types::PluginEntry;
        use http_body_util::{BodyExt, Full};
        use hyper_util::rt::TokioIo;

        // -- Setup database with plugin + credentials --
        // Use a plugin that matches on the hostname and injects a header
        let db = Arc::new(GapDatabase::in_memory().await.unwrap());

        let plugin_code = r#"
        var plugin = {
            name: "test-http",
            matchPatterns: ["api.httptest.com"],
            dangerously_permit_http: true,
            credentialSchema: ["api_key"],
            transform: function(request, credentials) {
                request.headers["Authorization"] = "Bearer " + credentials.api_key;
                // Expose the URL scheme to the upstream so we can verify it
                request.headers["X-Url-Received"] = request.url;
                return request;
            }
        };
        "#;
        let plugin_entry = PluginEntry {
            name: "test-http".to_string(),
            hosts: vec!["api.httptest.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
            dangerously_permit_http: true,
        };
        db.add_plugin(&plugin_entry, plugin_code).await.unwrap();
        db.set_credential("test-http", "api_key", "http-secret").await.unwrap();

        // -- Create paired DuplexStreams --
        let (agent_client, agent_proxy) = tokio::io::duplex(8192);
        let (upstream_proxy, upstream_server) = tokio::io::duplex(8192);

        // -- Spawn a mock upstream HTTP server --
        let upstream_handle = tokio::spawn(async move {
            let io = TokioIo::new(upstream_server);
            hyper::server::conn::http1::Builder::new()
                .serve_connection(
                    io,
                    hyper::service::service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                        let url_header = req.headers()
                            .get("x-url-received")
                            .map(|v| v.to_str().unwrap_or("").to_string())
                            .unwrap_or_default();
                        let auth = req.headers()
                            .get("authorization")
                            .map(|v| v.to_str().unwrap_or("").to_string())
                            .unwrap_or_default();

                        let body = format!("url={} auth={}", url_header, auth);
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::new(Full::new(bytes::Bytes::from(body)))
                        )
                    }),
                )
                .await
                .expect("upstream server error");
        });

        // -- Spawn proxy_via_hyper (H1 mode, plain HTTP) --
        let proxy_db = Arc::clone(&db);
        let proxy_handle = tokio::spawn(async move {
            proxy_via_hyper(
                agent_proxy,
                upstream_proxy,
                "api.httptest.com".to_string(),
                proxy_db,
                "test-agent".to_string(),
                false, // is_h2 = false for H1
                false, // use_tls = false (plain HTTP)
                None,  // no activity broadcast
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
            .header("Host", "api.httptest.com")
            .body(Full::new(bytes::Bytes::new()))
            .unwrap();

        let resp = sender.send_request(req).await.expect("send request");
        assert_eq!(resp.status(), 200);

        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        // The plugin should have seen an http:// URL (not https://)
        assert!(body_str.contains("url=http://api.httptest.com/data?q=test"),
            "Expected http:// URL, got: {}", body_str);
        // Credential injection should still work
        assert!(body_str.contains("auth=Bearer http-secret"),
            "Expected credential injection, got: {}", body_str);

        // Clean up
        drop(sender);
        let _ = proxy_handle.await;
        let _ = upstream_handle.await;
    }

    #[tokio::test]
    async fn test_prefixed_stream_read_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Create a duplex stream to test with
        let (client, server) = tokio::io::duplex(1024);

        // Wrap the server side with a prefix byte (simulating protocol detection)
        let prefix = vec![0x16]; // TLS ClientHello indicator
        let mut prefixed = PrefixedStream::new(prefix, server);

        // Write through the prefixed stream (should pass through to inner)
        prefixed.write_all(b"hello").await.unwrap();

        // Read from the client side
        let mut buf = [0u8; 5];
        let mut client = client;
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // Write from client to prefixed stream
        client.write_all(b"world").await.unwrap();

        // Read from prefixed stream: should get prefix byte first, then "world"
        let mut read_buf = [0u8; 6];
        prefixed.read_exact(&mut read_buf).await.unwrap();
        assert_eq!(read_buf[0], 0x16); // prefix byte
        assert_eq!(&read_buf[1..], b"world");
    }
}
