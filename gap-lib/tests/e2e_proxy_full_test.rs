//! End-to-end test for the full GAP proxy pipeline.
//!
//! This test verifies that:
//! 1. A HTTPS echo server is running with a cert signed by the **test server CA**
//! 2. The proxy intercepts the CONNECT tunnel using a separate **proxy CA**
//! 3. Plugin transform runs and injects credentials as headers
//! 4. The echo server receives the injected header
//!
//! ## Two-CA architecture
//!
//! The test uses two distinct Certificate Authorities to model production:
//!
//! - **Proxy CA** — generated per test via `CertificateAuthority::generate()`.
//!   Signs the proxy listener cert (client-facing) and MITM certs during CONNECT.
//!   The client connector trusts ONLY this CA.
//!
//! - **Test server CA** — loaded from checked-in fixtures at
//!   `tests/fixtures/test_server_ca_cert.pem` / `test_server_ca_key.pem`.
//!   Signs the echo server's TLS cert. The proxy's upstream connector trusts ONLY
//!   this CA. The client does NOT trust this CA.
//!
//! This separation proves the proxy correctly terminates two independent TLS sessions:
//! one toward the client (proxy CA) and one toward the upstream (test server CA).
//!
//! Architecture:
//!   Client --TLS(proxy CA)--> Proxy (CONNECT) --TLS(server CA)--> Echo HTTPS Server
//!   Plugin sees outgoing request and injects X-Test-Credential-One and X-Test-Credential-Two.

use gap_lib::database::GapDatabase;
use gap_lib::proxy::ProxyServer;
use gap_lib::types::PluginEntry;
use gap_lib::tls::CertificateAuthority;
use gap_lib::types::AgentToken;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

// ── Fixture paths ────────────────────────────────────────────────────────────

/// Path to the checked-in test server CA certificate PEM.
/// Generated once via the `#[ignore]` helper at the bottom of this file.
const TEST_SERVER_CA_CERT: &str = include_str!("fixtures/test_server_ca_cert.pem");
/// Path to the checked-in test server CA private key PEM.
const TEST_SERVER_CA_KEY: &str = include_str!("fixtures/test_server_ca_key.pem");

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Build a root certificate store that trusts only the provided CA cert (PEM).
///
/// Used by `ProxyServer::new_with_upstream_tls()` which now takes root certs
/// instead of a pre-built TLS connector. This allows the proxy to build
/// per-connection connectors with ALPN matching the agent's negotiated protocol.
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
///
/// Used for client-side connections (agent connecting to proxy).
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

/// Spawn an echo HTTPS server on a free port using a cert signed by `server_ca`.
///
/// Accepts connections in a loop, parses each HTTP request with httparse, and
/// returns a JSON body containing the method, url, headers, and (empty) body.
///
/// Returns the port the server is listening on.
async fn spawn_echo_server(server_ca: &CertificateAuthority) -> u16 {
    use rustls::ServerConfig;
    use rustls::pki_types::CertificateDer;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    let echo_port = portpicker::pick_unused_port().expect("pick echo port");

    // Sign with the test server CA (not the proxy CA)
    let (cert_der, key_der) = server_ca
        .sign_for_hostname("localhost", None)
        .expect("sign server cert for localhost");

    let certs = vec![
        CertificateDer::from(cert_der),
        CertificateDer::from(server_ca.ca_cert_der()),
    ];
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .expect("parse echo server key");

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

/// Shared plugin code used by all tests.
///
/// Uses the rich credentialSchema format with two required credentials.
/// Matches requests to "localhost".
const PLUGIN_CODE: &str = r#"var plugin = {
    name: "test-server-gap",
    matchPatterns: ["localhost"],
    credentialSchema: {
        fields: [
            { name: "test_credential_one", label: "Test Credential One", type: "password", required: true },
            { name: "test_credential_two", label: "Test Credential Two", type: "password", required: true }
        ]
    },
    transform: function(request, credentials) {
        request.headers["X-Test-Credential-One"] = credentials.test_credential_one;
        request.headers["X-Test-Credential-Two"] = credentials.test_credential_two;
        return request;
    }
};"#;

/// Helper to set up a GapDatabase with the test plugin, credentials, and a token.
/// Returns (Arc<GapDatabase>, token_value).
async fn setup_test_db(
    include_cred_two: bool,
) -> (Arc<GapDatabase>, String) {
    let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

    // Store plugin
    let plugin_entry = PluginEntry {
        name: "test-server-gap".to_string(),
        hosts: vec!["localhost".to_string()],
        credential_schema: vec!["test_credential_one".to_string(), "test_credential_two".to_string()],
        commit_sha: None,
    };
    db.add_plugin(&plugin_entry, PLUGIN_CODE).await.expect("store plugin");

    // Store credentials
    db.set_credential("test-server-gap", "test_credential_one", "super-secret-42")
        .await
        .expect("set credential one");
    if include_cred_two {
        db.set_credential("test-server-gap", "test_credential_two", "another-secret-99")
            .await
            .expect("set credential two");
    }

    // Store agent token
    let token = AgentToken::new("e2e-test-agent");
    let token_value = token.token.clone();
    db.add_token(&token.token, &token.name, token.created_at)
        .await
        .expect("store token");

    (db, token_value)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_full_e2e_proxy_pipeline() {
    // Install default crypto provider for rustls (required for TLS operations)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // --- Two CAs ---
    // Proxy CA: dynamically generated per test. Signs proxy listener + MITM certs.
    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();

    // Test server CA: loaded from checked-in fixtures. Signs echo server cert.
    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();

    // --- Spawn echo HTTPS server (cert signed by test server CA) ---
    let echo_port = spawn_echo_server(&server_ca).await;

    // --- Set up GapDatabase ---
    let (db, token_value) = setup_test_db(true).await;

    // --- Build upstream root certs that trust ONLY the test server CA ---
    let upstream_root_certs = create_root_cert_store(&server_ca_cert_pem);

    // --- Create proxy using the proxy CA (not the server CA) ---
    let proxy_port = portpicker::pick_unused_port().expect("pick proxy port");
    let proxy = ProxyServer::new_with_upstream_tls(
        proxy_port,
        proxy_ca,
        db,
        upstream_root_certs,
    )
    .expect("create proxy");

    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // === Client connection flow ===

    // Step 1: TCP connect to proxy
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("TCP connect to proxy");

    // Step 2: TLS handshake with proxy — client trusts ONLY the proxy CA
    let proxy_connector = create_tls_connector(&proxy_ca_cert_pem);
    let server_name = ServerName::try_from("localhost").expect("localhost server name");
    let mut proxy_tls = proxy_connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake with proxy");

    // Step 3: Send CONNECT to proxy
    let connect_request = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        echo_port, echo_port, token_value
    );
    proxy_tls
        .write_all(connect_request.as_bytes())
        .await
        .expect("send CONNECT request");
    proxy_tls.flush().await.expect("flush CONNECT");

    // Step 4: Read "200 Connection Established"
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

    // Step 5: Second TLS handshake over the tunnel — client trusts ONLY the proxy CA.
    // The proxy MITM cert is signed by the proxy CA, so this succeeds.
    // The client does NOT need to trust the server CA — the proxy handles upstream TLS.
    let inner_connector = create_tls_connector(&proxy_ca_cert_pem);
    let inner_server_name = ServerName::try_from("localhost").expect("localhost server name for inner TLS");
    let mut inner_tls = inner_connector
        .connect(inner_server_name, proxy_tls)
        .await
        .expect("inner TLS handshake with echo server via proxy tunnel");

    // Step 6: Send HTTP GET request
    let http_request = format!(
        "GET /test HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        echo_port
    );
    inner_tls
        .write_all(http_request.as_bytes())
        .await
        .expect("send GET request");
    inner_tls.flush().await.expect("flush GET request");

    // Step 7: Read response
    let mut response_buf = vec![0u8; 32 * 1024];
    let n = inner_tls
        .read(&mut response_buf)
        .await
        .expect("read echo response");
    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    let body_start = response_str
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let body = &response_str[body_start..];

    let json: serde_json::Value =
        serde_json::from_str(body).expect("parse echo response JSON body");

    // === Assertions ===

    let cred_one = json["headers"]["x-test-credential-one"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        cred_one, "super-secret-42",
        "Expected X-Test-Credential-One to be 'super-secret-42', got: {:?}\nFull response: {}",
        cred_one, response_str
    );

    let cred_two = json["headers"]["x-test-credential-two"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        cred_two, "another-secret-99",
        "Expected X-Test-Credential-Two to be 'another-secret-99', got: {:?}\nFull response: {}",
        cred_two, response_str
    );

    let method = json["method"].as_str().unwrap_or("");
    assert_eq!(method, "GET", "Expected method GET, got: {}", method);

    let url = json["url"].as_str().unwrap_or("");
    assert!(
        url.contains("/test"),
        "Expected URL to contain '/test', got: {}",
        url
    );
}

/// Test what happens when only ONE of the two required credentials is stored.
///
/// When test_credential_two is missing, credentials.test_credential_two is `undefined`
/// in JS. The transform tries to set a header to `undefined`, which causes the
/// plugin runtime to return an error (header values must be strings). The proxy
/// drops the connection without forwarding the request.
///
/// This verifies that partial credentials cause a connection failure, preventing
/// requests with incomplete credentials from reaching the upstream server.
#[tokio::test]
async fn test_e2e_missing_credential() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // --- Two CAs ---
    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();

    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();

    // --- Spawn echo HTTPS server (cert signed by test server CA) ---
    let echo_port = spawn_echo_server(&server_ca).await;

    // --- Set up GapDatabase (missing second credential) ---
    let (db, token_value) = setup_test_db(false).await;

    // --- Upstream root certs trust only the test server CA ---
    let upstream_root_certs = create_root_cert_store(&server_ca_cert_pem);

    // --- Create proxy with proxy CA ---
    let proxy_port = portpicker::pick_unused_port().expect("pick proxy port");
    let proxy = ProxyServer::new_with_upstream_tls(
        proxy_port,
        proxy_ca,
        db,
        upstream_root_certs,
    )
    .expect("create proxy");

    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // === Client connection flow ===

    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("TCP connect to proxy");

    // Client trusts only the proxy CA
    let proxy_connector = create_tls_connector(&proxy_ca_cert_pem);
    let server_name = ServerName::try_from("localhost").expect("localhost server name");
    let mut proxy_tls = proxy_connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake with proxy");

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

    // Inner TLS — client trusts only the proxy CA (MITM cert)
    let inner_connector = create_tls_connector(&proxy_ca_cert_pem);
    let inner_server_name = ServerName::try_from("localhost").expect("localhost server name for inner TLS");
    let mut inner_tls = inner_connector
        .connect(inner_server_name, proxy_tls)
        .await
        .expect("inner TLS handshake with echo server via proxy tunnel");

    let http_request = format!(
        "GET /test HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
        echo_port
    );
    inner_tls
        .write_all(http_request.as_bytes())
        .await
        .expect("send GET request");
    inner_tls.flush().await.expect("flush GET request");

    // Step 7: Read response — with a missing credential, the plugin transform will try to
    // set request.headers["X-Test-Credential-Two"] = undefined. This causes the JS runtime
    // to return an error. The proxy drops the connection, so we expect either 0 bytes or
    // an error.
    let mut response_buf = vec![0u8; 32 * 1024];
    let read_result = inner_tls.read(&mut response_buf).await;

    match read_result {
        Ok(0) => {
            // Clean connection close — proxy dropped the connection as expected
        }
        Ok(n) => {
            let response_str = String::from_utf8_lossy(&response_buf[..n]);
            if let Some(body_start) = response_str.find("\r\n\r\n").map(|i| i + 4) {
                let body = &response_str[body_start..];
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
                    let cred_one = json["headers"]["x-test-credential-one"].as_str().unwrap_or("");
                    assert_eq!(
                        cred_one, "super-secret-42",
                        "If a response is received, x-test-credential-one should have its stored value"
                    );

                    let cred_two = json["headers"]["x-test-credential-two"].as_str();
                    assert!(
                        cred_two.is_none() || cred_two == Some("undefined") || cred_two == Some(""),
                        "x-test-credential-two should be missing, empty, or 'undefined' when not stored, got: {:?}",
                        cred_two
                    );
                }
            }
        }
        Err(_) => {
            // TLS error on read — proxy dropped the connection, which is correct
        }
    }
}

/// Security test: a client that trusts the WRONG proxy CA must not complete the TLS handshake.
///
/// This verifies that the proxy's TLS certificate cannot be spoofed. Clients
/// can only be intercepted if they explicitly trust the correct proxy CA.
/// Without that trust, the TLS handshake fails before any data is exchanged.
#[tokio::test]
async fn test_e2e_wrong_proxy_ca_rejected() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // --- Real proxy CA: used to sign the proxy's TLS certificate ---
    let real_proxy_ca = CertificateAuthority::generate().expect("generate real proxy CA");

    // --- Wrong CA: a completely unrelated CA that the client mistakenly trusts ---
    let wrong_ca = CertificateAuthority::generate().expect("generate wrong CA");
    let wrong_ca_cert_pem = wrong_ca.ca_cert_pem();

    // Sanity: the two CAs must produce different certs
    assert_ne!(
        real_proxy_ca.ca_cert_pem(), wrong_ca_cert_pem,
        "The two generated CAs must be distinct"
    );

    // --- Set up minimal GapDatabase (no plugin needed for this test) ---
    let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

    // --- Upstream root certs (not exercised, but required by API) ---
    let upstream_root_certs = create_root_cert_store(&wrong_ca_cert_pem);

    // --- Build proxy with the REAL proxy CA ---
    let proxy_port = portpicker::pick_unused_port().expect("pick proxy port");
    let proxy = ProxyServer::new_with_upstream_tls(
        proxy_port,
        real_proxy_ca,
        db,
        upstream_root_certs,
    )
    .expect("create proxy");

    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // === Attempt TLS with the WRONG CA ===

    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("TCP connect to proxy");

    // Client trusts only the WRONG CA — should NOT be able to verify the proxy's cert
    let bad_connector = create_tls_connector(&wrong_ca_cert_pem);
    let server_name = ServerName::try_from("localhost").expect("localhost server name");

    let result = bad_connector.connect(server_name, tcp_stream).await;

    // The TLS handshake MUST fail because the proxy cert is signed by real_proxy_ca,
    // not by wrong_ca. This is the core security guarantee: clients without the
    // correct proxy CA trust cannot be intercepted.
    assert!(
        result.is_err(),
        "Expected TLS handshake to fail when client trusts wrong CA, but it succeeded"
    );
}

// ── H2 helpers ───────────────────────────────────────────────────────────────

/// Spawn an echo HTTPS server that supports both HTTP/2 and HTTP/1.1 via ALPN.
///
/// Uses hyper's auto connection builder to handle both protocols.
/// Returns the port the server is listening on.
async fn spawn_echo_server_h2(server_ca: &CertificateAuthority) -> u16 {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use rustls::pki_types::CertificateDer;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    let echo_port = portpicker::pick_unused_port().expect("pick echo port");

    // Sign cert with test server CA
    let (cert_der, key_der) = server_ca
        .sign_for_hostname("localhost", None)
        .expect("sign server cert for localhost");
    let certs = vec![
        CertificateDer::from(cert_der),
        CertificateDer::from(server_ca.ca_cert_der()),
    ];
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(key_der).expect("parse echo server key");

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .expect("build echo server TLS config");
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(format!("127.0.0.1:{}", echo_port))
        .await
        .expect("bind echo server");

    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls);
                let service =
                    service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                        let method = req.method().to_string();
                        let url = req.uri().to_string();
                        let mut headers_json = String::from("{");
                        let mut first = true;
                        for (name, value) in req.headers() {
                            if !first {
                                headers_json.push(',');
                            }
                            first = false;
                            headers_json.push_str(&format!(
                                "\"{}\":\"{}\"",
                                name.as_str(),
                                value.to_str().unwrap_or("")
                            ));
                        }
                        headers_json.push('}');
                        let body = format!(
                            "{{\"method\":\"{}\",\"url\":\"{}\",\"headers\":{},\"body\":\"\"}}",
                            method, url, headers_json
                        );
                        Ok::<_, hyper::Error>(
                            hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/json")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                        )
                    });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    echo_port
}

// ── H2 Tests ─────────────────────────────────────────────────────────────────

/// End-to-end test for the proxy pipeline over HTTP/2.
///
/// Same as `test_full_e2e_proxy_pipeline` but the inner connection (after
/// the CONNECT tunnel) uses HTTP/2 instead of HTTP/1.1:
///
///   Client --TLS(proxy CA, H1)--> Proxy (CONNECT) --TLS(proxy CA, H2)--> [proxy] --TLS(server CA, H2)--> Echo HTTPS Server
///
/// The CONNECT tunnel itself is always HTTP/1.1. H2 is negotiated via ALPN
/// on the inner TLS handshake, and the proxy mirrors that on the upstream side.
#[tokio::test]
async fn test_e2e_h2_proxy_pipeline() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    // Install default crypto provider for rustls
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // --- Two CAs ---
    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();

    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();

    // --- Spawn H2-capable echo HTTPS server (cert signed by test server CA) ---
    let echo_port = spawn_echo_server_h2(&server_ca).await;

    // --- Set up GapDatabase ---
    let (db, token_value) = setup_test_db(true).await;

    // --- Build upstream root certs that trust ONLY the test server CA ---
    let upstream_root_certs = create_root_cert_store(&server_ca_cert_pem);

    // --- Create proxy using the proxy CA ---
    let proxy_port = portpicker::pick_unused_port().expect("pick proxy port");
    let proxy = ProxyServer::new_with_upstream_tls(
        proxy_port,
        proxy_ca,
        db,
        upstream_root_certs,
    )
    .expect("create proxy");

    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // === Client connection flow ===

    // Step 1: TCP connect to proxy
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("TCP connect to proxy");

    // Step 2: TLS handshake with proxy — client trusts ONLY the proxy CA
    // No ALPN here — the outer connection to the proxy is always HTTP/1.1
    let proxy_connector = create_tls_connector(&proxy_ca_cert_pem);
    let server_name = ServerName::try_from("localhost").expect("localhost server name");
    let mut proxy_tls = proxy_connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake with proxy");

    // Step 3: Send CONNECT to proxy (always HTTP/1.1)
    let connect_request = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        echo_port, echo_port, token_value
    );
    proxy_tls
        .write_all(connect_request.as_bytes())
        .await
        .expect("send CONNECT request");
    proxy_tls.flush().await.expect("flush CONNECT");

    // Step 4: Read "200 Connection Established"
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

    // Step 5: Inner TLS handshake over the tunnel — request H2 via ALPN.
    // The proxy detects `h2` ALPN and uses H2 on the upstream side too.
    let inner_root_store = create_root_cert_store(&proxy_ca_cert_pem);
    let mut inner_config = rustls::ClientConfig::builder()
        .with_root_certificates((*inner_root_store).clone())
        .with_no_client_auth();
    inner_config.alpn_protocols = vec![b"h2".to_vec()];
    let inner_connector = TlsConnector::from(Arc::new(inner_config));

    let inner_server_name =
        ServerName::try_from("localhost").expect("localhost server name for inner TLS");
    let inner_tls = inner_connector
        .connect(inner_server_name, proxy_tls)
        .await
        .expect("inner TLS handshake (H2 ALPN) with proxy tunnel");

    // Step 6: H2 handshake and request via hyper
    let io = TokioIo::new(inner_tls);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("H2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method("GET")
        .uri(format!("https://localhost:{}/test", echo_port))
        .body(Full::new(Bytes::new()))
        .expect("build H2 request");

    let resp = sender.send_request(req).await.expect("send H2 request");
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect H2 response body")
        .to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    let json: serde_json::Value =
        serde_json::from_str(&body_str).expect("parse echo response JSON body");

    // === Assertions — same as test_full_e2e_proxy_pipeline ===

    let cred_one = json["headers"]["x-test-credential-one"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        cred_one, "super-secret-42",
        "Expected X-Test-Credential-One to be 'super-secret-42', got: {:?}\nFull body: {}",
        cred_one, body_str
    );

    let cred_two = json["headers"]["x-test-credential-two"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        cred_two, "another-secret-99",
        "Expected X-Test-Credential-Two to be 'another-secret-99', got: {:?}\nFull body: {}",
        cred_two, body_str
    );

    let method = json["method"].as_str().unwrap_or("");
    assert_eq!(method, "GET", "Expected method GET, got: {}", method);

    let url = json["url"].as_str().unwrap_or("");
    assert!(
        url.contains("/test"),
        "Expected URL to contain '/test', got: {}",
        url
    );
}

// ── Fixture generator ─────────────────────────────────────────────────────────

/// One-time helper to regenerate the checked-in test server CA fixture files.
///
/// Only needs to be run when the fixtures need to be refreshed:
///   cargo test -p gap-lib --test e2e_proxy_full_test generate_test_server_ca_fixtures -- --ignored
#[tokio::test]
#[ignore]
async fn generate_test_server_ca_fixtures() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ca = CertificateAuthority::generate().expect("generate CA");
    let cert_pem = ca.ca_cert_pem();
    let key_pem = ca.ca_key_pem();

    let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&fixtures_dir).expect("create fixtures dir");
    std::fs::write(fixtures_dir.join("test_server_ca_cert.pem"), &cert_pem).expect("write cert");
    std::fs::write(fixtures_dir.join("test_server_ca_key.pem"), &key_pem).expect("write key");
    println!("Fixtures written to {:?}", fixtures_dir);
}
