//! End-to-end tests for proxy scope enforcement.
//!
//! These tests verify that token scoping is wired up correctly in the proxy:
//! - CONNECT-phase host denial (403 before tunnel)
//! - Request-phase path denial (403 after tunnel established)
//! - Permitted request passes through the full proxy pipeline
//!
//! Exhaustive matcher coverage lives in `scope_matcher` unit tests.
//! These tests prove enforcement is integrated at the proxy layer.

use gap_lib::database::GapDatabase;
use gap_lib::proxy::{ProxyServer, TokenCache};
use gap_lib::tls::CertificateAuthority;
use gap_lib::types::{AgentToken, PluginEntry, TokenScope};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ── Fixture paths ────────────────────────────────────────────────────────────

const TEST_SERVER_CA_CERT: &str = include_str!("fixtures/test_server_ca_cert.pem");
const TEST_SERVER_CA_KEY: &str = include_str!("fixtures/test_server_ca_key.pem");

// ── Helpers ──────────────────────────────────────────────────────────────────

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

fn create_tls_connector(ca_cert_pem: &str) -> TlsConnector {
    let root_store = create_root_cert_store(ca_cert_pem);
    let config = rustls::ClientConfig::builder()
        .with_root_certificates((*root_store).clone())
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn load_test_server_ca() -> CertificateAuthority {
    CertificateAuthority::from_pem(TEST_SERVER_CA_CERT, TEST_SERVER_CA_KEY)
        .expect("load test server CA from fixtures")
}

/// Spawn an echo HTTPS server on a free port using a cert signed by `server_ca`.
///
/// Returns a JSON body with the method, url, headers, and body for every request.
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
                    headers_json
                        .push_str(&format!("\"{}\":\"{}\"", h.name.to_lowercase(), val));
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

/// Plugin with a single credential, matching "localhost".
const PLUGIN_CODE: &str = r#"var plugin = {
    name: "test-server-gap",
    matchPatterns: ["localhost"],
    credentialSchema: {
        fields: [
            { name: "test_credential_one", label: "Credential", type: "password", required: true }
        ]
    },
    transform: function(request, credentials) {
        request.headers["X-Test-Credential"] = credentials.test_credential_one;
        return request;
    }
};"#;

/// Set up a GapDatabase with a plugin, credential, and a scoped token.
///
/// Returns (db, token_value) where the token has the given scopes attached.
async fn setup_scoped_db(scopes: Option<&[TokenScope]>) -> (Arc<GapDatabase>, String) {
    let db = Arc::new(
        GapDatabase::in_memory()
            .await
            .expect("create in-memory db"),
    );

    // Store plugin
    let plugin_entry = PluginEntry {
        id: "test-server-gap".to_string(),
        source: None,
        hosts: vec!["localhost".to_string()],
        credential_schema: vec!["test_credential_one".to_string()],
        commit_sha: None,
        dangerously_permit_http: false,
        weight: 0,
        installed_at: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    };
    let plugin_id = db.add_plugin(&plugin_entry, PLUGIN_CODE, "default", "default")
        .await
        .expect("store plugin");

    // Store credential
    db.set_credential(&plugin_id, "test_credential_one", "secret-value", "default", "default")
        .await
        .expect("set credential");

    // Store agent token with scopes
    let token = AgentToken::new();
    let token_value = token.token.clone();
    db.add_token(&token.token, token.created_at, scopes)
        .await
        .expect("store token");

    (db, token_value)
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Verify that a scoped token that doesn't match the CONNECT target host
/// is denied at the CONNECT phase with a 403 response.
#[tokio::test]
async fn test_scoped_token_connect_denied() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();
    let server_ca = load_test_server_ca();
    let echo_port = spawn_echo_server(&server_ca).await;

    // Token scoped to a host that does NOT match localhost
    let scopes = vec![TokenScope {
        host_pattern: "notlocalhost.example.com".to_string(),
        port: None,
        path_pattern: "/*".to_string(),
        methods: None,
    }];
    let (db, token_value) = setup_scoped_db(Some(&scopes)).await;

    let upstream_root_certs = create_root_cert_store(&server_ca.ca_cert_pem());
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

    // Step 1: TCP + TLS to proxy
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("TCP connect to proxy");

    let proxy_connector = create_tls_connector(&proxy_ca_cert_pem);
    let server_name = ServerName::try_from("localhost").expect("localhost server name");
    let mut proxy_tls = proxy_connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake with proxy");

    // Step 2: Send CONNECT to a host the token is NOT scoped for
    let connect_request = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        echo_port, echo_port, token_value
    );
    proxy_tls
        .write_all(connect_request.as_bytes())
        .await
        .expect("send CONNECT request");
    proxy_tls.flush().await.expect("flush CONNECT");

    // Step 3: Read response — expect 403 Forbidden
    let mut connect_response = vec![0u8; 1024];
    let n = proxy_tls
        .read(&mut connect_response)
        .await
        .expect("read CONNECT response");
    let connect_response_str = String::from_utf8_lossy(&connect_response[..n]);

    assert!(
        connect_response_str.contains("403"),
        "Expected 403 Forbidden for out-of-scope CONNECT, got: {}",
        connect_response_str
    );
}

/// Verify that a scoped token allowing the host but restricting the path
/// permits the CONNECT but denies the inner HTTP request with 403.
#[tokio::test]
async fn test_scoped_token_connect_allowed_request_denied() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();
    let server_ca = load_test_server_ca();
    let echo_port = spawn_echo_server(&server_ca).await;

    // Token scoped to localhost but only /allowed/* paths
    let scopes = vec![TokenScope {
        host_pattern: "localhost".to_string(),
        port: None,
        path_pattern: "/allowed/*".to_string(),
        methods: None,
    }];
    let (db, token_value) = setup_scoped_db(Some(&scopes)).await;

    let upstream_root_certs = create_root_cert_store(&server_ca.ca_cert_pem());
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

    // Step 1: TCP + TLS to proxy
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("TCP connect to proxy");

    let proxy_connector = create_tls_connector(&proxy_ca_cert_pem);
    let server_name = ServerName::try_from("localhost").expect("localhost server name");
    let mut proxy_tls = proxy_connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake with proxy");

    // Step 2: CONNECT to localhost — host matches, should succeed
    let connect_request = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        echo_port, echo_port, token_value
    );
    proxy_tls
        .write_all(connect_request.as_bytes())
        .await
        .expect("send CONNECT request");
    proxy_tls.flush().await.expect("flush CONNECT");

    let mut connect_response = vec![0u8; 1024];
    let n = proxy_tls
        .read(&mut connect_response)
        .await
        .expect("read CONNECT response");
    let connect_response_str = String::from_utf8_lossy(&connect_response[..n]);
    assert!(
        connect_response_str.contains("200"),
        "Expected 200 Connection Established (host matches scope), got: {}",
        connect_response_str
    );

    // Step 3: Inner TLS handshake over the tunnel
    let inner_connector = create_tls_connector(&proxy_ca_cert_pem);
    let inner_server_name =
        ServerName::try_from("localhost").expect("localhost server name for inner TLS");
    let mut inner_tls = inner_connector
        .connect(inner_server_name, proxy_tls)
        .await
        .expect("inner TLS handshake with proxy tunnel");

    // Step 4: Send request to a path NOT allowed by scope
    let http_request = format!(
        "GET /denied/path HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        echo_port
    );
    inner_tls
        .write_all(http_request.as_bytes())
        .await
        .expect("send GET request to denied path");
    inner_tls.flush().await.expect("flush GET request");

    // Step 5: Read response — expect 403 from the proxy's per-request scope check
    let mut response_buf = vec![0u8; 32 * 1024];
    let n = inner_tls
        .read(&mut response_buf)
        .await
        .expect("read response");
    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    assert!(
        response_str.contains("403"),
        "Expected 403 for out-of-scope request path, got: {}",
        response_str
    );
    assert!(
        response_str.contains("Forbidden by token scope"),
        "Expected scope denial body, got: {}",
        response_str
    );
}

/// Verify that a scoped token permitting the host and path allows the
/// request through the full proxy pipeline, reaching the echo server.
#[tokio::test]
async fn test_scoped_token_connect_allowed_request_permitted() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();
    let server_ca = load_test_server_ca();
    let echo_port = spawn_echo_server(&server_ca).await;

    // Token scoped to localhost, all paths
    let scopes = vec![TokenScope {
        host_pattern: "localhost".to_string(),
        port: None,
        path_pattern: "/*".to_string(),
        methods: None,
    }];
    let (db, token_value) = setup_scoped_db(Some(&scopes)).await;

    let upstream_root_certs = create_root_cert_store(&server_ca.ca_cert_pem());
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

    // Step 1: TCP + TLS to proxy
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("TCP connect to proxy");

    let proxy_connector = create_tls_connector(&proxy_ca_cert_pem);
    let server_name = ServerName::try_from("localhost").expect("localhost server name");
    let mut proxy_tls = proxy_connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake with proxy");

    // Step 2: CONNECT to localhost — host matches scope, should succeed
    let connect_request = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        echo_port, echo_port, token_value
    );
    proxy_tls
        .write_all(connect_request.as_bytes())
        .await
        .expect("send CONNECT request");
    proxy_tls.flush().await.expect("flush CONNECT");

    let mut connect_response = vec![0u8; 1024];
    let n = proxy_tls
        .read(&mut connect_response)
        .await
        .expect("read CONNECT response");
    let connect_response_str = String::from_utf8_lossy(&connect_response[..n]);
    assert!(
        connect_response_str.contains("200"),
        "Expected 200 Connection Established, got: {}",
        connect_response_str
    );

    // Step 3: Inner TLS handshake over the tunnel
    let inner_connector = create_tls_connector(&proxy_ca_cert_pem);
    let inner_server_name =
        ServerName::try_from("localhost").expect("localhost server name for inner TLS");
    let mut inner_tls = inner_connector
        .connect(inner_server_name, proxy_tls)
        .await
        .expect("inner TLS handshake with proxy tunnel");

    // Step 4: Send request to /get — allowed by scope "/*"
    let http_request = format!(
        "GET /get HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        echo_port
    );
    inner_tls
        .write_all(http_request.as_bytes())
        .await
        .expect("send GET request");
    inner_tls.flush().await.expect("flush GET request");

    // Step 5: Read response — should reach echo server and return 200
    let mut response_buf = vec![0u8; 32 * 1024];
    let n = inner_tls
        .read(&mut response_buf)
        .await
        .expect("read echo response");
    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    // Parse the HTTP response
    let body_start = response_str
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let body = &response_str[body_start..];

    assert!(
        response_str.starts_with("HTTP/1.1 200"),
        "Expected 200 OK from echo server, got: {}",
        response_str
    );

    let json: serde_json::Value =
        serde_json::from_str(body).expect("parse echo response JSON body");

    // Verify the request reached the echo server
    let method = json["method"].as_str().unwrap_or("");
    assert_eq!(method, "GET", "Expected method GET, got: {}", method);

    let url = json["url"].as_str().unwrap_or("");
    assert!(
        url.contains("/get"),
        "Expected URL to contain '/get', got: {}",
        url
    );

    // Verify the plugin injected the credential
    let credential = json["headers"]["x-test-credential"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        credential, "secret-value",
        "Expected X-Test-Credential to be 'secret-value', got: {:?}\nFull body: {}",
        credential, body
    );
}
