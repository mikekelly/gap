//! End-to-end test for the full GAP proxy pipeline.
//!
//! This test verifies that:
//! 1. A HTTPS echo server is running with a CA-signed cert
//! 2. The proxy intercepts the CONNECT tunnel
//! 3. Plugin transform runs and injects credentials as headers
//! 4. The echo server receives the injected header
//!
//! Architecture:
//!   Client --TLS--> Proxy (CONNECT) --TLS--> Echo HTTPS Server
//!   Plugin sees outgoing request and injects X-Test-Credential header.

use gap_lib::proxy::ProxyServer;
use gap_lib::registry::{PluginEntry, Registry, TokenEntry};
use gap_lib::storage::{FileStore, SecretStore};
use gap_lib::tls::CertificateAuthority;
use gap_lib::types::AgentToken;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

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

/// Spawn an echo HTTPS server on a free port.
///
/// Accepts one connection, parses the HTTP request with httparse, and returns a
/// JSON body containing the method, url, headers, and (empty) body.
/// Uses a certificate signed by `ca` with an IP SAN for 127.0.0.1.
///
/// Returns the port the server is listening on.
async fn spawn_echo_server(ca: &CertificateAuthority) -> u16 {
    use rustls::ServerConfig;
    use rustls::pki_types::CertificateDer;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    let echo_port = portpicker::pick_unused_port().expect("pick echo port");

    // Generate a cert for 127.0.0.1 using IP SAN
    let (cert_der, key_der) = ca
        .sign_server_cert(&["IP:127.0.0.1".to_string()])
        .expect("sign server cert for 127.0.0.1");

    let certs = vec![
        CertificateDer::from(cert_der),
        CertificateDer::from(ca.ca_cert_der()),
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
        // Accept connections in a loop so the server stays alive across reconnects
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

                // Read up to 16 KiB — enough for any test request
                let mut buf = vec![0u8; 16 * 1024];
                let n = match tls_stream.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return,
                };
                let buf = &buf[..n];

                // Parse HTTP request with httparse
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut req = httparse::Request::new(&mut headers);
                let _ = req.parse(buf);

                let method = req.method.unwrap_or("UNKNOWN").to_string();
                let url = req.path.unwrap_or("/").to_string();

                // Collect headers into a JSON object string
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
                    // lowercase header name for consistent comparison
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

#[tokio::test]
async fn test_full_e2e_proxy_pipeline() {
    // Install default crypto provider for rustls (required for TLS operations)
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // --- Generate shared CA ---
    let ca = CertificateAuthority::generate().expect("generate CA");
    let ca_cert_pem = ca.ca_cert_pem();

    // --- Spawn echo HTTPS server ---
    let echo_port = spawn_echo_server(&ca).await;

    // --- Set up FileStore and Registry ---
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let store = Arc::new(
        FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore"),
    ) as Arc<dyn SecretStore>;
    let registry = Arc::new(Registry::new(Arc::clone(&store)));

    // --- Store plugin code ---
    // The plugin matches requests to 127.0.0.1 and injects X-Test-Credential header.
    let plugin_code = r#"var plugin = {
    name: "test-server-gap",
    matchPatterns: ["127.0.0.1"],
    credentialSchema: ["test_token"],
    transform: function(request, credentials) {
        request.headers["X-Test-Credential"] = credentials.test_token;
        return request;
    }
};"#;
    store
        .set("plugin:test-server-gap", plugin_code.as_bytes())
        .await
        .expect("store plugin code");

    // Register plugin in registry (so find_matching_plugin can find it)
    let plugin_entry = PluginEntry {
        name: "test-server-gap".to_string(),
        hosts: vec!["127.0.0.1".to_string()],
        credential_schema: vec!["test_token".to_string()],
        commit_sha: None,
    };
    registry
        .add_plugin(&plugin_entry)
        .await
        .expect("register plugin");

    // --- Store credentials in registry ---
    registry
        .set_credential("test-server-gap", "test_token", "super-secret-42")
        .await
        .expect("set credential");

    // --- Store agent token ---
    let token = AgentToken::new("e2e-test-agent");
    let token_value = token.token.clone();
    let token_json = serde_json::to_vec(&token).expect("serialize token");
    store
        .set(&format!("token:{}", token.token), &token_json)
        .await
        .expect("store token");
    let token_entry = TokenEntry {
        token_value: token.token.clone(),
        name: token.name.clone(),
        created_at: token.created_at,
    };
    registry
        .add_token(&token_entry)
        .await
        .expect("register token");

    // --- Build upstream TLS connector that trusts only the gap CA ---
    // (not webpki_roots, since the echo server uses our self-signed CA)
    let mut root_store = rustls::RootCertStore::empty();
    let ca_certs = rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    for cert in ca_certs {
        root_store.add(cert).expect("add CA cert to upstream root store");
    }
    let upstream_tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let upstream_connector = TlsConnector::from(Arc::new(upstream_tls_config));

    // --- Create proxy with custom upstream TLS connector ---
    let proxy_port = portpicker::pick_unused_port().expect("pick proxy port");
    let proxy = ProxyServer::new_with_upstream_tls(
        proxy_port,
        ca,
        Arc::clone(&store),
        Arc::clone(&registry),
        upstream_connector,
    )
    .expect("create proxy");

    // Prevent temp_dir cleanup while servers are running
    std::mem::forget(temp_dir);

    // --- Start proxy in background ---
    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    // Allow servers to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // === Client connection flow ===

    // Step 1: TCP connect to proxy
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("TCP connect to proxy");

    // Step 2: TLS handshake with proxy (trust CA, SNI=localhost)
    let proxy_connector = create_tls_connector(&ca_cert_pem);
    let server_name = ServerName::try_from("localhost").expect("localhost server name");
    let mut proxy_tls = proxy_connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake with proxy");

    // Step 3: Send CONNECT to proxy
    let connect_request = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
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

    // Step 5: Second TLS handshake over the tunnel (trust CA, server name = 127.0.0.1 as IP)
    let inner_connector = create_tls_connector(&ca_cert_pem);
    let ip_server_name = ServerName::IpAddress(rustls::pki_types::IpAddr::from(
        std::net::Ipv4Addr::new(127, 0, 0, 1),
    ));
    let mut inner_tls = inner_connector
        .connect(ip_server_name, proxy_tls)
        .await
        .expect("inner TLS handshake with echo server via proxy tunnel");

    // Step 6: Send HTTP GET request
    let http_request = format!(
        "GET /test HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
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

    // Find the JSON body (after the blank line separating headers from body)
    let body_start = response_str
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let body = &response_str[body_start..];

    // Parse JSON
    let json: serde_json::Value =
        serde_json::from_str(body).expect("parse echo response JSON body");

    // === Assertions ===

    // The plugin must have injected the credential header
    let credential_header = json["headers"]["x-test-credential"]
        .as_str()
        .unwrap_or("");
    assert_eq!(
        credential_header, "super-secret-42",
        "Expected X-Test-Credential to be 'super-secret-42', got: {:?}\nFull response: {}",
        credential_header, response_str
    );

    // Verify HTTP method
    let method = json["method"].as_str().unwrap_or("");
    assert_eq!(method, "GET", "Expected method GET, got: {}", method);

    // Verify URL contains /test
    let url = json["url"].as_str().unwrap_or("");
    assert!(
        url.contains("/test"),
        "Expected URL to contain '/test', got: {}",
        url
    );
}
