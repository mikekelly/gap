//! End-to-end test for HTTP message signing (RFC 9421) through the proxy pipeline.
//!
//! This test verifies that:
//! 1. A plugin can use `GAP.crypto.httpSignature()` to sign requests
//! 2. Signature headers (Signature, Signature-Input) are forwarded through the proxy
//! 3. An upstream server can verify the Ed25519 signatures
//!
//! ## Architecture
//!
//!   Client --TLS(proxy CA)--> Proxy (CONNECT) --TLS(server CA)--> Verifying HTTPS Server
//!   Plugin signs the request using Ed25519 via GAP.crypto.httpSignature().
//!   The verifying server reconstructs the RFC 9421 signature base and verifies
//!   the Ed25519 signature using ring.
//!
//! ## Verification approach
//!
//! We use ring for verification instead of httpsig-hyper because httpsig-hyper
//! re-orders signature parameters (alg before keyid) when reconstructing the
//! signature base, while GAP's JS implementation outputs keyid before alg.
//! Both orderings are valid per RFC 9421, but the signature is computed over
//! the exact parameter order used during signing. Manual verification with ring
//! avoids this incompatibility and directly proves the signature is valid.

use base64::prelude::*;
use gap_lib::database::GapDatabase;
use gap_lib::proxy::{ProxyServer, TokenCache};
use gap_lib::tls::CertificateAuthority;
use gap_lib::types::{AgentToken, PluginEntry};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
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

/// Plugin code for HTTP message signing.
///
/// Uses GAP.crypto.httpSignature() to sign requests with Ed25519.
/// Signs: @method and content-type headers.
const SIGNING_PLUGIN_CODE: &str = r#"var plugin = {
    name: "signing-test",
    matchPatterns: ["localhost"],
    credentialSchema: {
        fields: [
            { name: "private_key", label: "Private Key", type: "password", required: true },
            { name: "key_id", label: "Key ID", type: "text", required: true }
        ]
    },
    transform: function(request, credentials) {
        var keyDer = GAP.util.base64(credentials.private_key, true);
        var result = GAP.crypto.httpSignature({
            request: request,
            components: ["@method", "content-type"],
            algorithm: "ed25519",
            keyId: credentials.key_id,
            keyDer: keyDer
        });
        request.headers["Signature-Input"] = result.signatureInput;
        request.headers["Signature"] = result.signature;
        return request;
    }
};"#;

/// Set up GapDatabase with the signing plugin, credentials, and a token.
/// Returns (Arc<GapDatabase>, token_value).
async fn setup_test_db(pkcs8_b64: &str, key_id: &str) -> (Arc<GapDatabase>, String) {
    let db = Arc::new(
        GapDatabase::in_memory()
            .await
            .expect("create in-memory db"),
    );

    let plugin_entry = PluginEntry {
        id: "signing-test".to_string(),
        source: None,
        hosts: vec!["localhost".to_string()],
        credential_schema: vec!["private_key".to_string(), "key_id".to_string()],
        commit_sha: None,
        dangerously_permit_http: false,
        weight: 0,
        installed_at: None,
    };
    let plugin_id = db.add_plugin(&plugin_entry, SIGNING_PLUGIN_CODE)
        .await
        .expect("store plugin");

    db.set_credential(&plugin_id, "private_key", pkcs8_b64)
        .await
        .expect("set private_key credential");
    db.set_credential(&plugin_id, "key_id", key_id)
        .await
        .expect("set key_id credential");

    let token = AgentToken::new();
    let token_value = token.token.clone();
    db.add_token(&token.token, token.created_at, None)
        .await
        .expect("store token");

    (db, token_value)
}

/// Reconstruct the RFC 9421 signature base from request components and
/// the Signature-Input header value, then verify the signature with ring.
///
/// Returns (verified: bool, error_msg: Option<String>).
fn verify_signature_with_ring(
    method: &str,
    headers: &[(String, String)],
    public_key_bytes: &[u8],
) -> (bool, Option<String>) {
    // Find signature-input and signature headers
    let sig_input = headers
        .iter()
        .find(|(k, _)| k == "signature-input")
        .map(|(_, v)| v.as_str());
    let signature = headers
        .iter()
        .find(|(k, _)| k == "signature")
        .map(|(_, v)| v.as_str());

    let (sig_input, signature) = match (sig_input, signature) {
        (Some(si), Some(s)) => (si, s),
        _ => return (false, Some("Missing signature or signature-input header".into())),
    };

    // Parse signature-input: "sig1=(...);params"
    // Extract the params part after the label
    let params_start = match sig_input.find('=') {
        Some(i) => i + 1,
        None => return (false, Some("Invalid signature-input format".into())),
    };
    let sig_params = &sig_input[params_start..];

    // Parse covered components from the inner list: ("@method" "content-type")
    let list_end = match sig_params.find(')') {
        Some(i) => i,
        None => return (false, Some("No closing paren in signature-input".into())),
    };
    let component_list = &sig_params[1..list_end]; // strip parens
    let components: Vec<&str> = component_list
        .split('"')
        .filter(|s| !s.is_empty() && s.trim() != "")
        .filter(|s| !s.chars().all(|c| c == ' '))
        .collect();

    // Build signature base lines
    let mut lines: Vec<String> = Vec::new();
    for comp in &components {
        let value = if *comp == "@method" {
            method.to_uppercase()
        } else {
            // Look up header value (case-insensitive)
            match headers.iter().find(|(k, _)| k.to_lowercase() == *comp) {
                Some((_, v)) => v.clone(),
                None => {
                    return (
                        false,
                        Some(format!("Component '{}' not found in headers", comp)),
                    );
                }
            }
        };
        lines.push(format!("\"{}\": {}", comp, value));
    }
    lines.push(format!("\"@signature-params\": {}", sig_params));

    let signature_base = lines.join("\n");

    // Extract signature bytes: "sig1=:base64...:"
    let sig_start = match signature.find("=:") {
        Some(i) => i + 2,
        None => return (false, Some("Invalid signature format".into())),
    };
    let sig_end = match signature.rfind(':') {
        Some(i) if i > sig_start => i,
        _ => return (false, Some("Invalid signature format (no trailing colon)".into())),
    };
    let sig_b64 = &signature[sig_start..sig_end];
    let sig_bytes = match BASE64_STANDARD.decode(sig_b64) {
        Ok(b) => b,
        Err(e) => return (false, Some(format!("Invalid base64 in signature: {}", e))),
    };

    // Verify with ring
    let public_key = UnparsedPublicKey::new(&ED25519, public_key_bytes);
    match public_key.verify(signature_base.as_bytes(), &sig_bytes) {
        Ok(()) => (true, None),
        Err(e) => (false, Some(format!("Ed25519 verification failed: {}", e))),
    }
}

/// Spawn a verifying HTTPS server on a free port.
///
/// This server receives requests through the proxy, extracts Signature and
/// Signature-Input headers, reconstructs the RFC 9421 signature base, and
/// verifies the Ed25519 signature using ring. Returns JSON with the result.
async fn spawn_verifying_server(
    server_ca: &CertificateAuthority,
    public_key_bytes: Vec<u8>,
) -> u16 {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use rustls::pki_types::CertificateDer;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    let port = portpicker::pick_unused_port().expect("pick verifying server port");

    let (cert_der, key_der) = server_ca
        .sign_for_hostname("localhost", None)
        .expect("sign server cert for localhost");
    let certs = vec![
        CertificateDer::from(cert_der),
        CertificateDer::from(server_ca.ca_cert_der()),
    ];
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(key_der).expect("parse server key");

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .expect("build verifying server TLS config");

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("bind verifying server");

    let pub_key = Arc::new(public_key_bytes);

    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let pub_key = pub_key.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls);
                let service =
                    service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let pub_key = pub_key.clone();
                        async move {
                            let method = req.method().to_string();

                            // Collect headers as (name, value) pairs
                            let mut header_pairs: Vec<(String, String)> = Vec::new();
                            let mut headers_json = String::from("{");
                            let mut first = true;
                            for (name, value) in req.headers() {
                                let val = value.to_str().unwrap_or("");
                                header_pairs.push((name.as_str().to_string(), val.to_string()));
                                if !first {
                                    headers_json.push(',');
                                }
                                first = false;
                                let escaped_val =
                                    val.replace('\\', "\\\\").replace('"', "\\\"");
                                headers_json.push_str(&format!(
                                    "\"{}\":\"{}\"",
                                    name.as_str(),
                                    escaped_val
                                ));
                            }
                            headers_json.push('}');

                            let (verified, error) =
                                verify_signature_with_ring(&method, &header_pairs, &pub_key);

                            let body = if verified {
                                format!(
                                    "{{\"verified\":true,\"method\":\"{}\",\"headers\":{}}}",
                                    method, headers_json
                                )
                            } else {
                                let err_msg = error.unwrap_or_default();
                                let escaped_err =
                                    err_msg.replace('\\', "\\\\").replace('"', "\\\"");
                                format!(
                                    "{{\"verified\":false,\"method\":\"{}\",\"error\":\"{}\",\"headers\":{}}}",
                                    method, escaped_err, headers_json
                                )
                            };

                            Ok::<_, hyper::Error>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        }
                    });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    port
}

/// Spawn a verifying HTTPS server with H2 support via ALPN.
async fn spawn_verifying_server_h2(
    server_ca: &CertificateAuthority,
    public_key_bytes: Vec<u8>,
) -> u16 {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto;
    use rustls::pki_types::CertificateDer;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    let port = portpicker::pick_unused_port().expect("pick verifying server h2 port");

    let (cert_der, key_der) = server_ca
        .sign_for_hostname("localhost", None)
        .expect("sign server cert for localhost");
    let certs = vec![
        CertificateDer::from(cert_der),
        CertificateDer::from(server_ca.ca_cert_der()),
    ];
    let key_der =
        rustls::pki_types::PrivateKeyDer::try_from(key_der).expect("parse server key");

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .expect("build verifying server H2 TLS config");
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("bind verifying server h2");

    let pub_key = Arc::new(public_key_bytes);

    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let pub_key = pub_key.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls);
                let service =
                    service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let pub_key = pub_key.clone();
                        async move {
                            let method = req.method().to_string();

                            let mut header_pairs: Vec<(String, String)> = Vec::new();
                            let mut headers_json = String::from("{");
                            let mut first = true;
                            for (name, value) in req.headers() {
                                let val = value.to_str().unwrap_or("");
                                header_pairs.push((name.as_str().to_string(), val.to_string()));
                                if !first {
                                    headers_json.push(',');
                                }
                                first = false;
                                let escaped_val =
                                    val.replace('\\', "\\\\").replace('"', "\\\"");
                                headers_json.push_str(&format!(
                                    "\"{}\":\"{}\"",
                                    name.as_str(),
                                    escaped_val
                                ));
                            }
                            headers_json.push('}');

                            let (verified, error) =
                                verify_signature_with_ring(&method, &header_pairs, &pub_key);

                            let body = if verified {
                                format!(
                                    "{{\"verified\":true,\"method\":\"{}\",\"headers\":{}}}",
                                    method, headers_json
                                )
                            } else {
                                let err_msg = error.unwrap_or_default();
                                let escaped_err =
                                    err_msg.replace('\\', "\\\\").replace('"', "\\\"");
                                format!(
                                    "{{\"verified\":false,\"method\":\"{}\",\"error\":\"{}\",\"headers\":{}}}",
                                    method, escaped_err, headers_json
                                )
                            };

                            Ok::<_, hyper::Error>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        }
                    });
                let _ = auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
        }
    });

    port
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// Helper: perform the CONNECT tunnel + inner TLS + send POST request flow (H1).
/// Returns the response body as a string.
async fn send_signed_request_h1(
    proxy_port: u16,
    echo_port: u16,
    proxy_ca_cert_pem: &str,
    token_value: &str,
) -> String {
    // Step 1: TCP connect to proxy
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("TCP connect to proxy");

    // Step 2: TLS handshake with proxy
    let proxy_connector = create_tls_connector(proxy_ca_cert_pem);
    let server_name = ServerName::try_from("localhost").expect("localhost server name");
    let mut proxy_tls = proxy_connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake with proxy");

    // Step 3: Send CONNECT
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

    // Step 5: Inner TLS handshake over the tunnel
    let inner_connector = create_tls_connector(proxy_ca_cert_pem);
    let inner_server_name =
        ServerName::try_from("localhost").expect("localhost server name for inner TLS");
    let mut inner_tls = inner_connector
        .connect(inner_server_name, proxy_tls)
        .await
        .expect("inner TLS handshake");

    // Step 6: Send POST request with Content-Type
    let http_request = format!(
        "POST /api/data HTTP/1.1\r\nHost: localhost:{}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}",
        echo_port
    );
    inner_tls
        .write_all(http_request.as_bytes())
        .await
        .expect("send POST request");
    inner_tls.flush().await.expect("flush POST request");

    // Step 7: Read response
    let mut response_buf = vec![0u8; 32 * 1024];
    let n = inner_tls
        .read(&mut response_buf)
        .await
        .expect("read response");
    let response_str = String::from_utf8_lossy(&response_buf[..n]);

    let body_start = response_str
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    response_str[body_start..].to_string()
}

/// Generate an Ed25519 keypair and return (pkcs8_b64, public_key_raw_bytes, key_id).
fn generate_ed25519_keypair() -> (String, Vec<u8>, String) {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate Ed25519 keypair");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse keypair");
    let pub_key_raw = key_pair.public_key().as_ref().to_vec();
    let pkcs8_b64 = BASE64_STANDARD.encode(pkcs8.as_ref());
    let key_id = "e2e-test-key".to_string();
    (pkcs8_b64, pub_key_raw, key_id)
}

/// E2E test: HTTP message signing through proxy over HTTP/1.1.
///
/// Validates that GAP.crypto.httpSignature() produces valid Ed25519 signatures
/// that survive the proxy pipeline and can be verified by the upstream server.
#[tokio::test]
async fn test_e2e_crypto_httpsig_h1() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Generate Ed25519 keypair
    let (pkcs8_b64, pub_key_raw, key_id) = generate_ed25519_keypair();

    // Two CAs
    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();
    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();

    // Spawn verifying server with the Ed25519 public key
    let server_port = spawn_verifying_server(&server_ca, pub_key_raw).await;

    // Set up DB with signing plugin
    let (db, token_value) = setup_test_db(&pkcs8_b64, &key_id).await;

    // Upstream root certs trust test server CA
    let upstream_root_certs = create_root_cert_store(&server_ca_cert_pem);

    // Create proxy
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

    // Send a signed request through the proxy
    let body =
        send_signed_request_h1(proxy_port, server_port, &proxy_ca_cert_pem, &token_value).await;

    let json: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|_| panic!("parse response JSON: {}", body));

    let verified = json["verified"].as_bool().unwrap_or(false);
    assert!(
        verified,
        "Signature should be verified by upstream server. Response: {}",
        body
    );
    assert_eq!(
        json["method"].as_str().unwrap_or(""),
        "POST",
        "Method should be POST"
    );
}

/// E2E test: HTTP message signing through proxy over HTTP/2.
///
/// Same flow as H1 but the inner connection uses H2 via ALPN negotiation.
/// This proves the signature headers survive H2 transport through the proxy.
#[tokio::test]
async fn test_e2e_crypto_httpsig_h2() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (pkcs8_b64, pub_key_raw, key_id) = generate_ed25519_keypair();

    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();
    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();

    let server_port = spawn_verifying_server_h2(&server_ca, pub_key_raw).await;

    let (db, token_value) = setup_test_db(&pkcs8_b64, &key_id).await;
    let upstream_root_certs = create_root_cert_store(&server_ca_cert_pem);

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

    // TCP connect to proxy
    let tcp_stream = TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("TCP connect to proxy");

    // Outer TLS (no ALPN, always H1 for CONNECT)
    let proxy_connector = create_tls_connector(&proxy_ca_cert_pem);
    let server_name = ServerName::try_from("localhost").expect("localhost server name");
    let mut proxy_tls = proxy_connector
        .connect(server_name, tcp_stream)
        .await
        .expect("TLS handshake with proxy");

    // CONNECT
    let connect_request = format!(
        "CONNECT localhost:{} HTTP/1.1\r\nHost: localhost:{}\r\nProxy-Authorization: Bearer {}\r\n\r\n",
        server_port, server_port, token_value
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

    // Inner TLS with H2 ALPN
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
        .expect("inner TLS handshake (H2 ALPN)");

    // H2 handshake
    let io = TokioIo::new(inner_tls);
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("H2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("https://localhost:{}/api/data", server_port))
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from("{}")))
        .expect("build H2 request");

    let resp = sender.send_request(req).await.expect("send H2 request");
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect H2 response body")
        .to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    let json: serde_json::Value = serde_json::from_str(&body_str)
        .unwrap_or_else(|_| panic!("parse response JSON: {}", body_str));

    let verified = json["verified"].as_bool().unwrap_or(false);
    assert!(
        verified,
        "Signature should be verified over H2. Response: {}",
        body_str
    );
    assert_eq!(
        json["method"].as_str().unwrap_or(""),
        "POST",
        "Method should be POST"
    );
}

/// Test that Signature-Input header contains expected components and metadata.
///
/// Validates the format of the signature headers produced by GAP.crypto.httpSignature().
#[tokio::test]
async fn test_e2e_crypto_httpsig_header_format() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (pkcs8_b64, pub_key_raw, key_id) = generate_ed25519_keypair();

    let proxy_ca = CertificateAuthority::generate().expect("generate proxy CA");
    let proxy_ca_cert_pem = proxy_ca.ca_cert_pem();
    let server_ca = load_test_server_ca();
    let server_ca_cert_pem = server_ca.ca_cert_pem();

    let server_port = spawn_verifying_server(&server_ca, pub_key_raw).await;

    let (db, token_value) = setup_test_db(&pkcs8_b64, &key_id).await;
    let upstream_root_certs = create_root_cert_store(&server_ca_cert_pem);

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

    let body =
        send_signed_request_h1(proxy_port, server_port, &proxy_ca_cert_pem, &token_value).await;

    let json: serde_json::Value =
        serde_json::from_str(&body).unwrap_or_else(|_| panic!("parse response JSON: {}", body));

    let headers = &json["headers"];

    // Check Signature-Input header format
    let sig_input = headers["signature-input"]
        .as_str()
        .expect("Missing signature-input header");
    assert!(
        sig_input.contains("@method"),
        "Signature-Input should contain @method component: {}",
        sig_input
    );
    assert!(
        sig_input.contains("content-type"),
        "Signature-Input should contain content-type component: {}",
        sig_input
    );
    assert!(
        sig_input.contains(&format!("keyid=\"{}\"", key_id)),
        "Signature-Input should contain keyid: {}",
        sig_input
    );
    assert!(
        sig_input.contains("alg=\"ed25519\""),
        "Signature-Input should contain alg: {}",
        sig_input
    );
    assert!(
        sig_input.contains("created="),
        "Signature-Input should contain created timestamp: {}",
        sig_input
    );

    // Check Signature header format: sig1=:base64...:
    let sig = headers["signature"]
        .as_str()
        .expect("Missing signature header");
    assert!(
        sig.starts_with("sig1=:"),
        "Signature should start with 'sig1=:': {}",
        sig
    );
    assert!(
        sig.ends_with(':'),
        "Signature should end with ':': {}",
        sig
    );

    // Use httpsig-hyper to parse the signature headers and extract metadata.
    // This validates that the headers are well-formed RFC 9421 structured fields
    // parseable by a standard library.
    {
        use bytes::Bytes;
        use http_body_util::Full;
        use httpsig_hyper::*;

        // Build a hyper Request with the exact headers from the response
        let req = http::Request::builder()
            .method("POST")
            .uri("https://localhost/api/data")
            .header("content-type", "application/json")
            .header("signature-input", sig_input)
            .header("signature", sig)
            .body(Full::new(Bytes::new()))
            .unwrap();

        // httpsig-hyper should be able to detect and parse the signature headers
        assert!(
            <http::Request<Full<Bytes>> as MessageSignature>::has_message_signature(&req),
            "httpsig-hyper should detect the presence of signature headers"
        );

        // Extract algorithm and key ID from the parsed headers
        let alg_key_ids =
            <http::Request<Full<Bytes>> as MessageSignature>::get_alg_key_ids(&req)
                .expect("httpsig-hyper should parse algorithm and key IDs");
        assert!(
            !alg_key_ids.is_empty(),
            "Should have at least one signature entry"
        );

        // Verify the parsed metadata matches what the plugin produced
        let (sig_name, (alg, kid)) = alg_key_ids.iter().next().unwrap();
        assert_eq!(sig_name, "sig1", "Signature name should be sig1");
        assert_eq!(
            alg.as_ref().map(|a| a.as_str()),
            Some("ed25519"),
            "Algorithm should be ed25519"
        );
        assert_eq!(
            kid.as_deref(),
            Some("e2e-test-key"),
            "Key ID should match"
        );
    }

    // Verify the signature was actually valid (server already verified)
    let verified = json["verified"].as_bool().unwrap_or(false);
    assert!(
        verified,
        "The signature should be valid: {}",
        body
    );
}
