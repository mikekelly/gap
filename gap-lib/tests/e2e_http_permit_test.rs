//! E2E tests for the `dangerously_permit_http` flag.
//!
//! Verifies that the proxy blocks credential injection over plain HTTP unless
//! the plugin explicitly opts in with `dangerously_permit_http: true`.
//!
//! Architecture:
//!   Client --TLS(proxy CA)--> Proxy (CONNECT) --plain TCP--> Echo HTTP Server
//!
//! The CONNECT tunnel always uses TLS to the proxy. After the tunnel is
//! established, the client sends plain HTTP (no inner TLS handshake).
//! The proxy detects the non-TLS traffic and routes accordingly.

use gap_lib::database::GapDatabase;
use gap_lib::proxy::{ProxyServer, TokenCache};
use gap_lib::tls::CertificateAuthority;
use gap_lib::types::{AgentToken, PluginEntry};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build a TLS connector that trusts only the provided CA cert (PEM).
fn create_tls_connector(ca_cert_pem: &str) -> TlsConnector {
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    for cert in ca_certs {
        root_store.add(cert).expect("add CA cert to root store");
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Spawn a plain HTTP echo server (no TLS) on a random port.
///
/// Returns (port, received_request_rx) where received_request_rx receives
/// true when a request is received (used to verify requests are/aren't forwarded).
async fn spawn_plain_http_echo_server() -> (u16, tokio::sync::mpsc::Receiver<String>) {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    let port = portpicker::pick_unused_port().expect("pick echo port");
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(16);

    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("bind echo server");

    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(tcp);
                let tx = tx.clone();
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let tx = tx.clone();
                            async move {
                                // Capture the API key header to verify credential injection
                                let api_key = req
                                    .headers()
                                    .get("x-api-key")
                                    .map(|v| v.to_str().unwrap_or("").to_string())
                                    .unwrap_or_default();

                                // Signal that a request was received
                                let _ = tx.send(api_key.clone()).await;

                                let body = format!("api_key={}", api_key);
                                Ok::<_, hyper::Error>(
                                    hyper::Response::builder()
                                        .status(200)
                                        .header("content-type", "text/plain")
                                        .body(Full::new(Bytes::from(body)))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            });
        }
    });

    (port, rx)
}

/// Set up a GapDatabase with a plugin, credentials, and a token.
/// Returns (Arc<GapDatabase>, token_value).
async fn setup_test_db(
    plugin_name: &str,
    plugin_code: &str,
    match_host: &str,
    dangerously_permit_http: bool,
) -> (Arc<GapDatabase>, String) {
    let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

    let plugin_entry = PluginEntry {
        name: plugin_name.to_string(),
        hosts: vec![match_host.to_string()],
        credential_schema: vec!["api_key".to_string()],
        commit_sha: None,
        dangerously_permit_http,
        weight: 0,
        installed_at: None,
    };
    db.add_plugin(&plugin_entry, plugin_code)
        .await
        .expect("store plugin");

    db.set_credential(plugin_name, "api_key", "test-secret-42")
        .await
        .expect("set credential");

    let token = AgentToken::new();
    let token_value = token.token.clone();
    db.add_token(&token.token, token.created_at, None)
        .await
        .expect("store token");

    (db, token_value)
}

/// Connect to the proxy, establish CONNECT tunnel, then send plain HTTP.
///
/// Returns the response body as a String, or an error string.
async fn send_http_through_proxy(
    proxy_port: u16,
    echo_port: u16,
    token_value: &str,
    proxy_ca_cert_pem: &str,
) -> Result<String, String> {
    // Step 1: TCP connect to proxy
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .map_err(|e| format!("TCP connect failed: {}", e))?;

    // Step 2: TLS handshake with proxy
    let proxy_connector = create_tls_connector(proxy_ca_cert_pem);
    let server_name = ServerName::try_from("localhost").expect("localhost server name");
    let mut proxy_tls = proxy_connector
        .connect(server_name, tcp_stream)
        .await
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

    // Step 3: Send CONNECT to proxy (target is 127.0.0.1:echo_port)
    let connect_request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        echo_port, echo_port, token_value
    );
    proxy_tls
        .write_all(connect_request.as_bytes())
        .await
        .map_err(|e| format!("Failed to send CONNECT: {}", e))?;
    proxy_tls.flush().await.map_err(|e| format!("Failed to flush: {}", e))?;

    // Step 4: Read "200 Connection Established"
    let mut connect_response = vec![0u8; 1024];
    let n = proxy_tls
        .read(&mut connect_response)
        .await
        .map_err(|e| format!("Failed to read CONNECT response: {}", e))?;
    let connect_response_str = String::from_utf8_lossy(&connect_response[..n]);
    if !connect_response_str.contains("200") {
        return Err(format!(
            "Expected 200 Connection Established, got: {}",
            connect_response_str
        ));
    }

    // Step 5: Send plain HTTP GET through the tunnel (no inner TLS)
    let http_request = format!(
        "GET /test HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        echo_port
    );
    proxy_tls
        .write_all(http_request.as_bytes())
        .await
        .map_err(|e| format!("Failed to send HTTP request: {}", e))?;
    proxy_tls
        .flush()
        .await
        .map_err(|e| format!("Failed to flush HTTP request: {}", e))?;

    // Step 6: Read response (with timeout)
    let mut response_buf = vec![0u8; 32 * 1024];
    let read_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        proxy_tls.read(&mut response_buf),
    )
    .await;

    match read_result {
        Ok(Ok(0)) => Err("Connection closed without response (blocked)".to_string()),
        Ok(Ok(n)) => {
            let response_str = String::from_utf8_lossy(&response_buf[..n]).to_string();
            // Extract body from HTTP response
            if let Some(body_start) = response_str.find("\r\n\r\n") {
                Ok(response_str[body_start + 4..].to_string())
            } else {
                Ok(response_str)
            }
        }
        Ok(Err(e)) => Err(format!("Read error (connection likely dropped): {}", e)),
        Err(_) => Err("Timeout waiting for response".to_string()),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Test that plain HTTP requests are blocked when plugin does NOT have
/// `dangerously_permit_http: true`.
///
/// Verifies:
/// 1. The proxy blocks the request
/// 2. The echo server does NOT receive the request (credentials not leaked)
#[tokio::test]
async fn test_http_blocked_without_dangerously_permit_http() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // --- Spawn plain HTTP echo server ---
    let (echo_port, mut request_rx) = spawn_plain_http_echo_server().await;

    // --- Plugin WITHOUT dangerously_permit_http ---
    let plugin_code = r#"var plugin = {
    name: "test-no-http",
    matchPatterns: ["127.0.0.1"],
    credentialSchema: { fields: [{ name: "api_key", label: "API Key", type: "password", required: true }] },
    transform: function(request, credentials) {
        request.headers["X-Api-Key"] = credentials.api_key;
        return request;
    }
};"#;

    let (db, token_value) =
        setup_test_db("test-no-http", plugin_code, "127.0.0.1", false).await;

    // --- Create proxy ---
    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();

    let proxy_port = portpicker::pick_unused_port().expect("pick proxy port");
    let proxy = ProxyServer::new(proxy_port, proxy_ca, db, "127.0.0.1".to_string(), Arc::new(TokenCache::new())).expect("create proxy");

    tokio::spawn(async move {
        let _ = proxy.start().await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // --- Send request through proxy ---
    let result = send_http_through_proxy(proxy_port, echo_port, &token_value, &proxy_ca_cert_pem).await;

    // The request should be blocked
    assert!(
        result.is_err(),
        "Expected HTTP request to be blocked, but got: {:?}",
        result
    );

    // Verify the echo server did NOT receive the request
    // (Give a small window for any async delivery)
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    let received = request_rx.try_recv();
    assert!(
        received.is_err(),
        "Echo server should NOT have received a request (credentials would have leaked), but got: {:?}",
        received
    );
}

/// Test that plain HTTP requests succeed when plugin HAS
/// `dangerously_permit_http: true`.
///
/// Verifies:
/// 1. The request goes through the proxy
/// 2. Credentials ARE injected into the forwarded request headers
/// 3. The echo server receives the request with the injected credential
#[tokio::test]
async fn test_http_allowed_with_dangerously_permit_http() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // --- Spawn plain HTTP echo server ---
    let (echo_port, mut request_rx) = spawn_plain_http_echo_server().await;

    // --- Plugin WITH dangerously_permit_http: true ---
    let plugin_code = r#"var plugin = {
    name: "test-permit-http",
    matchPatterns: ["127.0.0.1"],
    dangerously_permit_http: true,
    credentialSchema: { fields: [{ name: "api_key", label: "API Key", type: "password", required: true }] },
    transform: function(request, credentials) {
        request.headers["X-Api-Key"] = credentials.api_key;
        return request;
    }
};"#;

    let (db, token_value) =
        setup_test_db("test-permit-http", plugin_code, "127.0.0.1", true).await;

    // --- Create proxy ---
    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();

    let proxy_port = portpicker::pick_unused_port().expect("pick proxy port");
    let proxy = ProxyServer::new(proxy_port, proxy_ca, db, "127.0.0.1".to_string(), Arc::new(TokenCache::new())).expect("create proxy");

    tokio::spawn(async move {
        let _ = proxy.start().await;
    });
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // --- Send request through proxy ---
    let result = send_http_through_proxy(proxy_port, echo_port, &token_value, &proxy_ca_cert_pem).await;

    // The request should succeed
    assert!(
        result.is_ok(),
        "Expected HTTP request to succeed with dangerously_permit_http, but got error: {:?}",
        result
    );

    let body = result.unwrap();
    assert!(
        body.contains("api_key=test-secret-42"),
        "Expected credential to be injected, got body: {}",
        body
    );

    // Verify the echo server received the request with credentials
    let received = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        request_rx.recv(),
    )
    .await
    .expect("should receive within timeout")
    .expect("should have received a request");

    assert_eq!(
        received, "test-secret-42",
        "Echo server should have received the injected credential"
    );
}
