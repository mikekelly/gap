//! End-to-end tests for HeaderSet functionality through the full proxy pipeline.
//!
//! Tests verify that:
//! 1. Header sets inject static headers into matching requests
//! 2. Weight-based priority works between header sets and plugins
//! 3. Path-based matching restricts header injection to specific paths
//!
//! Uses the same two-CA architecture as `e2e_proxy_full_test.rs`:
//!   Client --TLS(proxy CA)--> Proxy (CONNECT) --TLS(server CA)--> Echo HTTPS Server

use gap_lib::database::GapDatabase;
use gap_lib::proxy::{ProxyServer, TokenCache};
use gap_lib::tls::CertificateAuthority;
use gap_lib::types::{AgentToken, PluginEntry};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ── Fixture paths ────────────────────────────────────────────────────────────

const TEST_SERVER_CA_CERT: &str = include_str!("fixtures/test_server_ca_cert.pem");
const TEST_SERVER_CA_KEY: &str = include_str!("fixtures/test_server_ca_key.pem");

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build a root certificate store that trusts only the provided CA cert (PEM).
fn create_root_cert_store(ca_cert_pem: &str) -> Arc<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    for cert in ca_certs {
        root_store.add(cert).expect("add CA cert to root store");
    }
    Arc::new(root_store)
}

/// Build a TLS connector that trusts only the provided CA cert (PEM).
fn create_tls_connector(ca_cert_pem: &str) -> TlsConnector {
    let root_store = create_root_cert_store(ca_cert_pem);
    let config = rustls::ClientConfig::builder()
        .with_root_certificates((*root_store).clone())
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Load the test server CA from the checked-in fixture files.
fn load_test_server_ca() -> CertificateAuthority {
    CertificateAuthority::from_pem(TEST_SERVER_CA_CERT, TEST_SERVER_CA_KEY)
        .expect("load test server CA from fixtures")
}

/// Spawn an echo HTTPS server that returns request details as JSON.
///
/// Accepts connections in a loop, parses each HTTP request, and returns a JSON
/// body containing the method, url, headers, and body.
async fn spawn_echo_server(server_ca: &CertificateAuthority) -> u16 {
    use rustls::pki_types::CertificateDer;
    use rustls::ServerConfig;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    let echo_port = portpicker::pick_unused_port().expect("pick echo port");

    let (cert_der, key_der) = server_ca
        .sign_for_hostname("localhost", None)
        .expect("sign server cert for localhost");

    let certs = vec![
        CertificateDer::from(cert_der),
        CertificateDer::from(server_ca.ca_cert_der()),
    ];
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(key_der).expect("parse echo server key");

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .expect("build echo server TLS config");

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(format!("127.0.0.1:{}", echo_port))
        .await
        .expect("bind echo server");

    tokio::spawn(async move {
        loop {
            let (tcp_stream, _addr) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls_stream = match acceptor.accept(tcp_stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let mut buf = vec![0u8; 16 * 1024];
                let n = match tls_stream.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };
                let buf = &buf[..n];

                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut req = httparse::Request::new(&mut headers);
                let _ = req.parse(buf);

                let method = req.method.unwrap_or("UNKNOWN").to_string();
                let url = req.path.unwrap_or("/").to_string();

                let mut headers_json = String::from("{");
                let mut first = true;
                for h in req.headers.iter() {
                    if h.name.is_empty() {
                        break;
                    }
                    if !first {
                        headers_json.push(',');
                    }
                    first = false;
                    let val = String::from_utf8_lossy(h.value);
                    headers_json.push_str(&format!(
                        "\"{}\":\"{}\"",
                        h.name.to_lowercase(),
                        val
                    ));
                }
                headers_json.push('}');

                let body = format!(
                    "{{\"method\":\"{}\",\"url\":\"{}\",\"headers\":{},\"body\":\"\"}}",
                    method, url, headers_json
                );

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );

                let _ = tls_stream.write_all(response.as_bytes()).await;
                let _ = tls_stream.flush().await;
            });
        }
    });

    echo_port
}

/// Send a request through the proxy pipeline and return the parsed JSON response.
///
/// Handles the full flow: TCP -> outer TLS -> CONNECT -> inner TLS -> HTTP request.
/// Returns the JSON body from the echo server, or an error string if the proxy
/// rejects the request.
async fn proxy_request(
    proxy_port: u16,
    echo_port: u16,
    proxy_ca_cert_pem: &str,
    token_value: &str,
    request_path: &str,
) -> Result<serde_json::Value, String> {
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
        .map_err(|e| format!("proxy TLS handshake failed: {}", e))?;

    // Step 3: Send CONNECT
    let connect_request = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        echo_port, echo_port, token_value
    );
    proxy_tls
        .write_all(connect_request.as_bytes())
        .await
        .map_err(|e| format!("send CONNECT failed: {}", e))?;
    proxy_tls
        .flush()
        .await
        .map_err(|e| format!("flush CONNECT failed: {}", e))?;

    // Step 4: Read "200 Connection Established"
    let mut connect_response = vec![0u8; 1024];
    let n = proxy_tls
        .read(&mut connect_response)
        .await
        .map_err(|e| format!("read CONNECT response failed: {}", e))?;
    let connect_response_str = String::from_utf8_lossy(&connect_response[..n]);
    if !connect_response_str.contains("200") {
        return Err(format!(
            "Expected 200 Connection Established, got: {}",
            connect_response_str
        ));
    }

    // Step 5: Inner TLS handshake
    let inner_connector = create_tls_connector(proxy_ca_cert_pem);
    let inner_server_name =
        ServerName::try_from("localhost").expect("localhost server name for inner TLS");
    let mut inner_tls = inner_connector
        .connect(inner_server_name, proxy_tls)
        .await
        .map_err(|e| format!("inner TLS handshake failed: {}", e))?;

    // Step 6: Send HTTP GET request
    let http_request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        request_path, echo_port
    );
    inner_tls
        .write_all(http_request.as_bytes())
        .await
        .map_err(|e| format!("send GET request failed: {}", e))?;
    inner_tls
        .flush()
        .await
        .map_err(|e| format!("flush GET request failed: {}", e))?;

    // Step 7: Read response
    let mut response_buf = vec![0u8; 32 * 1024];
    let n = inner_tls
        .read(&mut response_buf)
        .await
        .map_err(|e| format!("read response failed: {}", e))?;

    if n == 0 {
        return Err("Connection closed (0 bytes read) — proxy likely rejected the request".to_string());
    }

    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    // Check for non-200 HTTP status (proxy rejection)
    if let Some(status_line_end) = response_str.find("\r\n") {
        let status_line = &response_str[..status_line_end];
        if status_line.contains("403") || status_line.contains("502") || status_line.contains("500") {
            return Err(format!("Proxy rejected request: {}", status_line));
        }
    }

    let body_start = response_str
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let body = &response_str[body_start..];

    serde_json::from_str(body)
        .map_err(|e| format!("parse echo response JSON failed: {} (body: {})", e, body))
}

/// Start a proxy server with the given DB and return (proxy_port, proxy_ca_cert_pem).
async fn start_proxy(
    db: Arc<GapDatabase>,
    server_ca_cert_pem: &str,
) -> (u16, String) {
    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();
    let upstream_root_certs = create_root_cert_store(server_ca_cert_pem);
    let proxy_port = portpicker::pick_unused_port().expect("pick proxy port");

    let proxy = ProxyServer::new_with_upstream_tls(
        proxy_port,
        proxy_ca,
        db,
        upstream_root_certs,
        "127.0.0.1".to_string(),
        Arc::new(TokenCache::new()),
    )
    .expect("create proxy");

    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    (proxy_port, proxy_ca_cert_pem)
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Test that a header set injects static headers into matching requests.
///
/// Flow: create header set with Authorization and X-Custom headers, proxy a
/// request through, verify both headers appear in the upstream request.
#[tokio::test]
async fn test_e2e_header_set_injection() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();
    let echo_port = spawn_echo_server(&server_ca).await;

    // Set up DB with header set
    let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

    let hs_id = db.add_header_set(&["localhost".to_string()], 0)
        .await
        .expect("add header set");
    db.set_header_set_header(&hs_id, "Authorization", "Bearer test-secret-key")
        .await
        .expect("set Authorization header");
    db.set_header_set_header(&hs_id, "X-Custom", "my-value")
        .await
        .expect("set X-Custom header");

    // Add agent token
    let token = AgentToken::new();
    let token_value = token.token.clone();
    db.add_token(&token.token, token.created_at, None)
        .await
        .expect("store token");

    let (proxy_port, proxy_ca_cert_pem) = start_proxy(db, &server_ca_cert_pem).await;

    let json = proxy_request(proxy_port, echo_port, &proxy_ca_cert_pem, &token_value, "/test")
        .await
        .expect("proxy request should succeed");

    // Verify injected headers
    let auth = json["headers"]["authorization"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        auth, "Bearer test-secret-key",
        "Expected Authorization header to be 'Bearer test-secret-key', got: {:?}\nFull response: {}",
        auth, json
    );

    let custom = json["headers"]["x-custom"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        custom, "my-value",
        "Expected X-Custom header to be 'my-value', got: {:?}\nFull response: {}",
        custom, json
    );

    let method = json["method"].as_str().unwrap_or("");
    assert_eq!(method, "GET", "Expected method GET, got: {}", method);
}

/// Test weight-based priority between a plugin and a header set.
///
/// Plugin has weight=5 (sets X-Source: plugin), header set has weight=10
/// (sets X-Source: header-set). Higher weight wins, so the header set's
/// value should appear upstream.
#[tokio::test]
async fn test_e2e_header_set_vs_plugin_weight() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();
    let echo_port = spawn_echo_server(&server_ca).await;

    let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

    // Add plugin with weight=5
    let plugin_code = r#"var plugin = {
    name: "test-plugin",
    matchPatterns: ["localhost"],
    credentialSchema: ["api_key"],
    weight: 5,
    transform: function(request, credentials) {
        request.headers["X-Source"] = "plugin";
        return request;
    }
};"#;
    let plugin_entry = PluginEntry {
        id: "test-plugin".to_string(),
        source: None,
        hosts: vec!["localhost".to_string()],
        credential_schema: vec!["api_key".to_string()],
        commit_sha: None,
        dangerously_permit_http: false,
        weight: 5,
        installed_at: None,
    };
    let plugin_id = db.add_plugin(&plugin_entry, plugin_code)
        .await
        .expect("store plugin");
    db.set_credential(&plugin_id, "api_key", "dummy-key")
        .await
        .expect("set credential");

    // Add header set with weight=10 (higher priority)
    let hs_id = db.add_header_set(&["localhost".to_string()], 10)
        .await
        .expect("add header set");
    db.set_header_set_header(&hs_id, "X-Source", "header-set")
        .await
        .expect("set X-Source header");

    // Add agent token
    let token = AgentToken::new();
    let token_value = token.token.clone();
    db.add_token(&token.token, token.created_at, None)
        .await
        .expect("store token");

    let (proxy_port, proxy_ca_cert_pem) = start_proxy(db, &server_ca_cert_pem).await;

    let json = proxy_request(proxy_port, echo_port, &proxy_ca_cert_pem, &token_value, "/test")
        .await
        .expect("proxy request should succeed");

    // Header set (weight=10) should win over plugin (weight=5)
    let x_source = json["headers"]["x-source"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        x_source, "header-set",
        "Expected X-Source to be 'header-set' (weight 10 > 5), got: {:?}\nFull response: {}",
        x_source, json
    );
}

/// Test path-specific matching for header sets.
///
/// Header set matches only `localhost/api/*`. Requests to `/api/v1/data` should
/// get headers injected; requests to `/other/path` should be rejected (no
/// matching handler).
#[tokio::test]
async fn test_e2e_header_set_path_matching() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();
    let echo_port = spawn_echo_server(&server_ca).await;

    let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

    // Header set matching only /api/* paths
    let hs_id = db.add_header_set(&["localhost/api/*".to_string()], 0)
        .await
        .expect("add header set");
    db.set_header_set_header(&hs_id, "X-Api-Key", "secret")
        .await
        .expect("set X-Api-Key header");

    // Add agent token
    let token = AgentToken::new();
    let token_value = token.token.clone();
    db.add_token(&token.token, token.created_at, None)
        .await
        .expect("store token");

    let (proxy_port, proxy_ca_cert_pem) = start_proxy(db, &server_ca_cert_pem).await;

    // Request to /api/v1/data should match and inject the header
    let json = proxy_request(
        proxy_port,
        echo_port,
        &proxy_ca_cert_pem,
        &token_value,
        "/api/v1/data",
    )
    .await
    .expect("proxy request to /api/v1/data should succeed");

    let api_key = json["headers"]["x-api-key"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        api_key, "secret",
        "Expected X-Api-Key to be 'secret' for /api/v1/data, got: {:?}\nFull response: {}",
        api_key, json
    );

    // Request to /other/path should NOT match (no plugin or header set)
    let result = proxy_request(
        proxy_port,
        echo_port,
        &proxy_ca_cert_pem,
        &token_value,
        "/other/path",
    )
    .await;

    // The proxy should reject this request since no handler matches
    assert!(
        result.is_err(),
        "Expected proxy to reject request to /other/path (no matching handler), but got: {:?}",
        result
    );
}

/// Test that a plugin with higher weight beats a header set with lower weight.
///
/// Plugin has weight=10 (sets X-Source: plugin), header set has weight=5
/// (sets X-Source: header-set). Higher weight wins, so the plugin's value
/// should appear upstream. This is the inverse of `test_e2e_header_set_vs_plugin_weight`.
#[tokio::test]
async fn test_e2e_plugin_beats_header_set_by_weight() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();
    let echo_port = spawn_echo_server(&server_ca).await;

    let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

    // Add plugin with weight=10 (higher priority)
    let plugin_code = r#"var plugin = {
    name: "weighted-plugin",
    matchPatterns: ["localhost"],
    credentialSchema: ["api_key"],
    weight: 10,
    transform: function(request, credentials) {
        request.headers["X-Source"] = "plugin";
        return request;
    }
};"#;
    let plugin_entry = PluginEntry {
        id: "weighted-plugin".to_string(),
        source: None,
        hosts: vec!["localhost".to_string()],
        credential_schema: vec!["api_key".to_string()],
        commit_sha: None,
        dangerously_permit_http: false,
        weight: 10,
        installed_at: None,
    };
    let plugin_id = db.add_plugin(&plugin_entry, plugin_code)
        .await
        .expect("store plugin");
    db.set_credential(&plugin_id, "api_key", "dummy-key")
        .await
        .expect("set credential");

    // Add header set with weight=5 (lower priority)
    let hs_id = db.add_header_set(&["localhost".to_string()], 5)
        .await
        .expect("add header set");
    db.set_header_set_header(&hs_id, "X-Source", "header-set")
        .await
        .expect("set X-Source header");

    // Add agent token
    let token = AgentToken::new();
    let token_value = token.token.clone();
    db.add_token(&token.token, token.created_at, None)
        .await
        .expect("store token");

    let (proxy_port, proxy_ca_cert_pem) = start_proxy(db, &server_ca_cert_pem).await;

    let json = proxy_request(proxy_port, echo_port, &proxy_ca_cert_pem, &token_value, "/test")
        .await
        .expect("proxy request should succeed");

    // Plugin (weight=10) should win over header set (weight=5)
    let x_source = json["headers"]["x-source"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        x_source, "plugin",
        "Expected X-Source to be 'plugin' (weight 10 > 5), got: {:?}\nFull response: {}",
        x_source, json
    );
}

/// Test weight-based priority between two header sets.
///
/// Header set A has weight=5, header set B has weight=10. Both match
/// `localhost` and set the same header. Higher weight wins.
#[tokio::test]
async fn test_e2e_header_set_vs_header_set_weight() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();
    let echo_port = spawn_echo_server(&server_ca).await;

    let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

    // Header set A with weight=5
    let hs_a_id = db.add_header_set(&["localhost".to_string()], 5)
        .await
        .expect("add header set A");
    db.set_header_set_header(&hs_a_id, "X-Source", "hs-a")
        .await
        .expect("set X-Source for hs-a");

    // Header set B with weight=10
    let hs_b_id = db.add_header_set(&["localhost".to_string()], 10)
        .await
        .expect("add header set B");
    db.set_header_set_header(&hs_b_id, "X-Source", "hs-b")
        .await
        .expect("set X-Source for hs-b");

    // Add agent token
    let token = AgentToken::new();
    let token_value = token.token.clone();
    db.add_token(&token.token, token.created_at, None)
        .await
        .expect("store token");

    let (proxy_port, proxy_ca_cert_pem) = start_proxy(db, &server_ca_cert_pem).await;

    let json = proxy_request(proxy_port, echo_port, &proxy_ca_cert_pem, &token_value, "/test")
        .await
        .expect("proxy request should succeed");

    // Header set B (weight=10) should win over header set A (weight=5)
    let x_source = json["headers"]["x-source"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        x_source, "hs-b",
        "Expected X-Source to be 'hs-b' (weight 10 > 5), got: {:?}\nFull response: {}",
        x_source, json
    );
}

/// Test that when two header sets have the same weight, the oldest one wins.
///
/// Both header sets have weight=0. Header set A is created first, then after
/// a brief sleep, header set B is created. The tiebreak rule favors the older
/// entry, so header set A should win.
#[tokio::test]
async fn test_e2e_same_weight_oldest_wins() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();
    let echo_port = spawn_echo_server(&server_ca).await;

    let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

    // Header set A (created first) with weight=0
    let hs_older_id = db.add_header_set(&["localhost".to_string()], 0)
        .await
        .expect("add older header set");
    db.set_header_set_header(&hs_older_id, "X-Source", "older")
        .await
        .expect("set X-Source for older hs");

    // Sleep to ensure different timestamps
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Header set B (created second) with weight=0
    let hs_newer_id = db.add_header_set(&["localhost".to_string()], 0)
        .await
        .expect("add newer header set");
    db.set_header_set_header(&hs_newer_id, "X-Source", "newer")
        .await
        .expect("set X-Source for newer hs");

    // Add agent token
    let token = AgentToken::new();
    let token_value = token.token.clone();
    db.add_token(&token.token, token.created_at, None)
        .await
        .expect("store token");

    let (proxy_port, proxy_ca_cert_pem) = start_proxy(db, &server_ca_cert_pem).await;

    let json = proxy_request(proxy_port, echo_port, &proxy_ca_cert_pem, &token_value, "/test")
        .await
        .expect("proxy request should succeed");

    // Same weight → oldest wins, so "older" should appear
    let x_source = json["headers"]["x-source"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        x_source, "older",
        "Expected X-Source to be 'older' (same weight, oldest wins), got: {:?}\nFull response: {}",
        x_source, json
    );
}

/// Test path-specific header set wins by weight when both match.
///
/// Header set A (weight=10) matches `localhost/api/v1/*`, header set B (weight=5)
/// matches `localhost` (catch-all). For a request to `/api/v1/data`, both match
/// and weight decides (A wins). For `/other`, only B matches, so B wins.
#[tokio::test]
async fn test_e2e_path_specific_header_set_wins_by_weight() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();
    let echo_port = spawn_echo_server(&server_ca).await;

    let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

    // Header set A: path-specific with higher weight
    let hs_specific_id = db.add_header_set(&["localhost/api/v1/*".to_string()], 10)
        .await
        .expect("add specific header set");
    db.set_header_set_header(&hs_specific_id, "X-Source", "specific")
        .await
        .expect("set X-Source for specific hs");

    // Header set B: catch-all with lower weight
    let hs_catchall_id = db.add_header_set(&["localhost".to_string()], 5)
        .await
        .expect("add catchall header set");
    db.set_header_set_header(&hs_catchall_id, "X-Source", "catchall")
        .await
        .expect("set X-Source for catchall hs");

    // Add agent token
    let token = AgentToken::new();
    let token_value = token.token.clone();
    db.add_token(&token.token, token.created_at, None)
        .await
        .expect("store token");

    let (proxy_port, proxy_ca_cert_pem) = start_proxy(db, &server_ca_cert_pem).await;

    // Request to /api/v1/data — both match, weight decides (specific wins)
    let json = proxy_request(
        proxy_port,
        echo_port,
        &proxy_ca_cert_pem,
        &token_value,
        "/api/v1/data",
    )
    .await
    .expect("proxy request to /api/v1/data should succeed");

    let x_source = json["headers"]["x-source"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        x_source, "specific",
        "Expected X-Source to be 'specific' (weight 10 > 5) for /api/v1/data, got: {:?}\nFull response: {}",
        x_source, json
    );

    // Request to /other — only catchall matches
    let json = proxy_request(
        proxy_port,
        echo_port,
        &proxy_ca_cert_pem,
        &token_value,
        "/other",
    )
    .await
    .expect("proxy request to /other should succeed");

    let x_source = json["headers"]["x-source"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        x_source, "catchall",
        "Expected X-Source to be 'catchall' (only matching handler) for /other, got: {:?}\nFull response: {}",
        x_source, json
    );
}
