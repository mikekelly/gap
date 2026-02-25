//! Integration tests for HTTPS proxy TLS functionality
//!
//! Tests verify that:
//! 1. Proxy accepts TLS connections
//! 2. Certificate is valid (localhost, signed by CA)
//! 3. Token authentication works over TLS
//! 4. Invalid/missing tokens are rejected

use gap_lib::database::GapDatabase;
use gap_lib::proxy::{ProxyServer, TokenCache};
use gap_lib::tls::CertificateAuthority;
use gap_lib::types::AgentToken;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Helper to create a TLS connector that trusts the CA
fn create_tls_connector(ca_cert_pem: &str) -> TlsConnector {
    let mut root_store = rustls::RootCertStore::empty();
    // Parse CA cert and add to root store
    let ca_certs = rustls_pemfile::certs(&mut ca_cert_pem.as_bytes())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    for cert in ca_certs {
        root_store.add(cert).expect("add CA cert");
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    TlsConnector::from(Arc::new(config))
}

/// Helper to create a test proxy server with a single token
/// Returns (ProxyServer, CA cert PEM for client verification, token value)
async fn create_test_proxy(port: u16, token: AgentToken) -> (ProxyServer, String, String) {
    let ca = CertificateAuthority::generate().expect("generate CA");
    let ca_cert_pem = ca.ca_cert_pem();
    let token_value = token.token.clone();

    // Create an in-memory GapDatabase for testing
    let db = Arc::new(GapDatabase::in_memory().await.expect("create in-memory db"));

    // Store the token in the database
    db.add_token(&token.token, token.created_at, None, "default", "default")
        .await
        .expect("store token");

    let proxy = ProxyServer::new(port, ca, db, "127.0.0.1".to_string(), Arc::new(TokenCache::new())).expect("create proxy");

    (proxy, ca_cert_pem, token_value)
}

#[tokio::test]
async fn test_proxy_accepts_tls_connection() {
    // Install default crypto provider for rustls
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let token = AgentToken::new();
    let port = portpicker::pick_unused_port().expect("pick port");

    let (proxy, ca_cert_pem, _token_value) = create_test_proxy(port, token).await;

    // Start proxy in background
    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    // Give proxy time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect with TLS
    let connector = create_tls_connector(&ca_cert_pem);
    let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("TCP connect");

    let server_name = ServerName::try_from("localhost").expect("server name");
    let tls_stream = connector.connect(server_name, stream).await;

    assert!(tls_stream.is_ok(), "TLS handshake should succeed");
}

#[tokio::test]
async fn test_proxy_connect_with_valid_token() {
    // Install default crypto provider for rustls
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let token = AgentToken::new();
    let port = portpicker::pick_unused_port().expect("pick port");

    let (proxy, ca_cert_pem, token_value) = create_test_proxy(port, token).await;

    // Start proxy in background
    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    // Give proxy time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect with TLS
    let connector = create_tls_connector(&ca_cert_pem);
    let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("TCP connect");

    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("TLS connect");

    // Send CONNECT request with valid auth
    // Note: We use a non-existent host to avoid actually connecting upstream
    // The proxy will fail on upstream connect, but we verify auth works
    let connect_request = format!(
        "CONNECT test.example.com:443 HTTP/1.1\r\n\
         Host: test.example.com:443\r\n\
         Proxy-Authorization: Bearer {}\r\n\
         \r\n",
        token_value
    );

    tls_stream
        .write_all(connect_request.as_bytes())
        .await
        .expect("write CONNECT");

    // Read response
    let mut reader = BufReader::new(tls_stream);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .await
        .expect("read response");

    // Should get 200 Connection Established (auth succeeded)
    // OR a connection error to upstream (which still means auth passed)
    // Either way, we should NOT get 407 Proxy Authentication Required
    assert!(
        !response_line.contains("407"),
        "Expected auth to succeed, got: {}",
        response_line
    );
}

#[tokio::test]
async fn test_proxy_connect_rejects_invalid_token() {
    // Install default crypto provider for rustls
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let token = AgentToken::new();
    let port = portpicker::pick_unused_port().expect("pick port");

    let (proxy, ca_cert_pem, _token_value) = create_test_proxy(port, token).await;

    // Start proxy in background
    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    // Give proxy time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect with TLS
    let connector = create_tls_connector(&ca_cert_pem);
    let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("TCP connect");

    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("TLS connect");

    // Send CONNECT request with INVALID token
    let connect_request = "CONNECT test.example.com:443 HTTP/1.1\r\n\
         Host: test.example.com:443\r\n\
         Proxy-Authorization: Bearer invalid-token-that-does-not-exist\r\n\
         \r\n";

    tls_stream
        .write_all(connect_request.as_bytes())
        .await
        .expect("write CONNECT");

    // Read response - connection should close or return error
    let mut reader = BufReader::new(tls_stream);
    let mut response = String::new();

    // Read whatever response we get (might be empty if connection closed)
    let read_result = tokio::time::timeout(
        tokio::time::Duration::from_millis(500),
        reader.read_line(&mut response),
    )
    .await;

    // Either:
    // 1. Connection closed (timeout or 0 bytes read)
    // 2. Got an error response (not 200)
    match read_result {
        Ok(Ok(0)) => {
            // Connection closed - expected behavior
        }
        Ok(Ok(_)) => {
            // Got a response - should NOT be 200 Connection Established
            assert!(
                !response.contains("200"),
                "Invalid token should not get 200, got: {}",
                response
            );
        }
        Ok(Err(_)) | Err(_) => {
            // Read error or timeout - acceptable, connection was rejected
        }
    }
}

#[tokio::test]
async fn test_proxy_connect_rejects_missing_auth() {
    // Install default crypto provider for rustls
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let token = AgentToken::new();
    let port = portpicker::pick_unused_port().expect("pick port");

    let (proxy, ca_cert_pem, _token_value) = create_test_proxy(port, token).await;

    // Start proxy in background
    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    // Give proxy time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect with TLS
    let connector = create_tls_connector(&ca_cert_pem);
    let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("TCP connect");

    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("TLS connect");

    // Send CONNECT request WITHOUT Proxy-Authorization header
    let connect_request = "CONNECT test.example.com:443 HTTP/1.1\r\n\
         Host: test.example.com:443\r\n\
         \r\n";

    tls_stream
        .write_all(connect_request.as_bytes())
        .await
        .expect("write CONNECT");

    // Read response - connection should close or return error
    let mut reader = BufReader::new(tls_stream);
    let mut response = String::new();

    // Read whatever response we get (might be empty if connection closed)
    let read_result = tokio::time::timeout(
        tokio::time::Duration::from_millis(500),
        reader.read_line(&mut response),
    )
    .await;

    // Either:
    // 1. Connection closed (timeout or 0 bytes read)
    // 2. Got an error response (not 200)
    match read_result {
        Ok(Ok(0)) => {
            // Connection closed - expected behavior
        }
        Ok(Ok(_)) => {
            // Got a response - should NOT be 200 Connection Established
            assert!(
                !response.contains("200"),
                "Missing auth should not get 200, got: {}",
                response
            );
        }
        Ok(Err(_)) | Err(_) => {
            // Read error or timeout - acceptable, connection was rejected
        }
    }
}

#[tokio::test]
async fn test_proxy_certificate_valid_for_localhost() {
    // Install default crypto provider for rustls
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let token = AgentToken::new();
    let port = portpicker::pick_unused_port().expect("pick port");

    let (proxy, ca_cert_pem, _token_value) = create_test_proxy(port, token).await;

    // Start proxy in background
    tokio::spawn(async move {
        let _ = proxy.start().await;
    });

    // Give proxy time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create a strict TLS connector that validates certificates
    let connector = create_tls_connector(&ca_cert_pem);

    let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
        .await
        .expect("TCP connect");

    // This will verify the certificate is valid for "localhost"
    let server_name = ServerName::try_from("localhost").expect("server name");
    let result = connector.connect(server_name, stream).await;

    // If TLS handshake succeeds, the certificate is valid for localhost
    // and is signed by our CA
    assert!(
        result.is_ok(),
        "Certificate should be valid for localhost and signed by CA: {:?}",
        result.err()
    );
}
