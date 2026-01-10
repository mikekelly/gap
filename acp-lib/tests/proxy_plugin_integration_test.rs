//! Integration tests for proxy HTTP parsing and plugin execution
//!
//! Tests the complete flow:
//! 1. Parse HTTP request from raw bytes
//! 2. Match host against plugins
//! 3. Load credentials
//! 4. Execute plugin transform
//! 5. Serialize back to HTTP

use acp_lib::plugin_runtime::PluginRuntime;
use acp_lib::storage::{FileStore, SecretStore};
use acp_lib::types::{ACPCredentials, ACPRequest};

/// Test HTTP request parsing
///
/// This test verifies we can parse a raw HTTP request into an ACPRequest struct
#[test]
fn test_parse_http_request() {
    let raw_request = b"GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n";

    let request = parse_http_request(raw_request).unwrap();

    assert_eq!(request.method, "GET");
    assert_eq!(request.url, "https://api.example.com/v1/users");
    assert_eq!(request.get_header("Host"), Some(&"api.example.com".to_string()));
    assert_eq!(request.get_header("Content-Type"), Some(&"application/json".to_string()));
    assert_eq!(request.body, b"");
}

/// Test HTTP request parsing with body
#[test]
fn test_parse_http_request_with_body() {
    let raw_request = b"POST /v1/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"test\":true}";

    let request = parse_http_request(raw_request).unwrap();

    assert_eq!(request.method, "POST");
    assert_eq!(request.url, "https://api.example.com/v1/data");
    assert_eq!(request.body, b"{\"test\":true}");
}

/// Test serializing ACPRequest back to HTTP
#[test]
fn test_serialize_http_request() {
    let request = ACPRequest::new("GET", "https://api.example.com/v1/users")
        .with_header("Host", "api.example.com")
        .with_header("Content-Type", "application/json");

    let http_bytes = serialize_http_request(&request).unwrap();
    let http_str = String::from_utf8_lossy(&http_bytes);

    assert!(http_str.starts_with("GET /v1/users HTTP/1.1\r\n"));
    assert!(http_str.contains("Host: api.example.com\r\n"));
    assert!(http_str.contains("Content-Type: application/json\r\n"));
    assert!(http_str.ends_with("\r\n\r\n"));
}

/// Test serializing ACPRequest with body
#[test]
fn test_serialize_http_request_with_body() {
    let request = ACPRequest::new("POST", "https://api.example.com/v1/data")
        .with_header("Host", "api.example.com")
        .with_header("Content-Type", "application/json")
        .with_body(b"{\"test\":true}".to_vec());

    let http_bytes = serialize_http_request(&request).unwrap();
    let http_str = String::from_utf8_lossy(&http_bytes);

    assert!(http_str.starts_with("POST /v1/data HTTP/1.1\r\n"));
    assert!(http_str.contains("Host: api.example.com\r\n"));
    assert!(http_str.contains("Content-Length: 13\r\n"));
    assert!(http_str.ends_with("\r\n\r\n{\"test\":true}"));
}

/// Test matching host against plugins
#[tokio::test]
async fn test_find_matching_plugin() {
    let temp_dir = std::env::temp_dir().join(format!(
        "acp_proxy_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let store = FileStore::new(temp_dir.clone()).await.unwrap();

    // Create two plugins with different match patterns
    let plugin1_code = r#"
    var plugin = {
        name: "exa-plugin",
        matchPatterns: ["api.exa.ai"],
        credentialSchema: ["api_key"],
        transform: function(request, credentials) {
            request.headers["Authorization"] = "Bearer " + credentials.api_key;
            return request;
        }
    };
    "#;

    let plugin2_code = r#"
    var plugin = {
        name: "s3-plugin",
        matchPatterns: ["*.s3.amazonaws.com"],
        credentialSchema: ["access_key", "secret_key"],
        transform: function(request, credentials) {
            request.headers["X-AWS-Access-Key"] = credentials.access_key;
            return request;
        }
    };
    "#;

    store.set("plugin:exa-plugin", plugin1_code.as_bytes()).await.unwrap();
    store.set("plugin:s3-plugin", plugin2_code.as_bytes()).await.unwrap();

    // Find matching plugin for api.exa.ai
    let matching_plugin = find_matching_plugin("api.exa.ai", &store).await.unwrap();
    assert!(matching_plugin.is_some());
    assert_eq!(matching_plugin.unwrap().name, "exa-plugin");

    // Find matching plugin for bucket.s3.amazonaws.com
    let matching_plugin = find_matching_plugin("bucket.s3.amazonaws.com", &store).await.unwrap();
    assert!(matching_plugin.is_some());
    assert_eq!(matching_plugin.unwrap().name, "s3-plugin");

    // No match for unknown host
    let matching_plugin = find_matching_plugin("api.unknown.com", &store).await.unwrap();
    assert!(matching_plugin.is_none());

    // Cleanup
    tokio::fs::remove_dir_all(temp_dir).await.ok();
}

/// Test end-to-end: Parse HTTP -> Find plugin -> Execute transform -> Serialize
#[tokio::test]
async fn test_proxy_plugin_execution_flow() {
    let temp_dir = std::env::temp_dir().join(format!(
        "acp_proxy_e2e_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let store = FileStore::new(temp_dir.clone()).await.unwrap();

    // Install a plugin
    let plugin_code = r#"
    var plugin = {
        name: "test-api",
        matchPatterns: ["api.example.com"],
        credentialSchema: ["api_key"],
        transform: function(request, credentials) {
            request.headers["Authorization"] = "Bearer " + credentials.api_key;
            return request;
        }
    };
    "#;

    store.set("plugin:test-api", plugin_code.as_bytes()).await.unwrap();

    // Store credentials
    let mut creds = ACPCredentials::new();
    creds.set("api_key", "secret123");
    store.set("credential:test-api:default", serde_json::to_string(&creds).unwrap().as_bytes()).await.unwrap();

    // Parse incoming HTTP request
    let raw_request = b"GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n";
    let request = parse_http_request(raw_request).unwrap();

    // Find matching plugin
    let plugin = find_matching_plugin("api.example.com", &store).await.unwrap();
    assert!(plugin.is_some());
    let plugin = plugin.unwrap();

    // Load credentials for the plugin
    let creds_key = format!("credential:{}:default", plugin.name);
    let creds_bytes = store.get(&creds_key).await.unwrap().unwrap();
    let creds: ACPCredentials = serde_json::from_slice(&creds_bytes).unwrap();

    // Execute transform
    let mut runtime = PluginRuntime::new().unwrap();
    runtime.load_plugin(&plugin.name, &store).await.unwrap();
    let transformed = runtime.execute_transform(&plugin.name, request, &creds).unwrap();

    // Verify transformation
    assert_eq!(transformed.get_header("Authorization"), Some(&"Bearer secret123".to_string()));

    // Serialize back to HTTP
    let http_bytes = serialize_http_request(&transformed).unwrap();
    let http_str = String::from_utf8_lossy(&http_bytes);
    assert!(http_str.contains("Authorization: Bearer secret123\r\n"));

    // Cleanup
    tokio::fs::remove_dir_all(temp_dir).await.ok();
}

// Use the actual implementations from acp_lib
use acp_lib::{parse_http_request, serialize_http_request, find_matching_plugin};
