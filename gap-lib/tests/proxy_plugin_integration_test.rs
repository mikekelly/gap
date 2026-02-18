//! Integration tests for proxy HTTP parsing and plugin execution
//!
//! Tests the complete flow:
//! 1. Parse HTTP request from raw bytes
//! 2. Match host against plugins
//! 3. Load credentials
//! 4. Execute plugin transform
//! 5. Serialize back to HTTP

use gap_lib::database::GapDatabase;
use gap_lib::plugin_runtime::PluginRuntime;
use gap_lib::types::PluginEntry;
use gap_lib::types::{GAPCredentials, GAPRequest};


/// Test HTTP request parsing
///
/// This test verifies we can parse a raw HTTP request into an GAPRequest struct
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

/// Test serializing GAPRequest back to HTTP
#[test]
fn test_serialize_http_request() {
    let request = GAPRequest::new("GET", "https://api.example.com/v1/users")
        .with_header("Host", "api.example.com")
        .with_header("Content-Type", "application/json");

    let http_bytes = serialize_http_request(&request).unwrap();
    let http_str = String::from_utf8_lossy(&http_bytes);

    assert!(http_str.starts_with("GET /v1/users HTTP/1.1\r\n"));
    assert!(http_str.contains("Host: api.example.com\r\n"));
    assert!(http_str.contains("Content-Type: application/json\r\n"));
    assert!(http_str.ends_with("\r\n\r\n"));
}

/// Test serializing GAPRequest with body
#[test]
fn test_serialize_http_request_with_body() {
    let request = GAPRequest::new("POST", "https://api.example.com/v1/data")
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
    let db = GapDatabase::in_memory().await.unwrap();

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

    let entry1 = PluginEntry {
        name: "exa-plugin".to_string(),
        hosts: vec!["api.exa.ai".to_string()],
        credential_schema: vec!["api_key".to_string()],
        commit_sha: None,
            dangerously_permit_http: false,
    };
    db.add_plugin(&entry1, plugin1_code).await.unwrap();

    let entry2 = PluginEntry {
        name: "s3-plugin".to_string(),
        hosts: vec!["*.s3.amazonaws.com".to_string()],
        credential_schema: vec!["access_key".to_string(), "secret_key".to_string()],
        commit_sha: None,
            dangerously_permit_http: false,
    };
    db.add_plugin(&entry2, plugin2_code).await.unwrap();

    // Find matching plugin for api.exa.ai
    let matching_plugin = find_matching_plugin("api.exa.ai", &db).await.unwrap();
    assert!(matching_plugin.is_some());
    assert_eq!(matching_plugin.unwrap().name, "exa-plugin");

    // Find matching plugin for bucket.s3.amazonaws.com
    let matching_plugin = find_matching_plugin("bucket.s3.amazonaws.com", &db).await.unwrap();
    assert!(matching_plugin.is_some());
    assert_eq!(matching_plugin.unwrap().name, "s3-plugin");

    // No match for unknown host
    let matching_plugin = find_matching_plugin("api.unknown.com", &db).await.unwrap();
    assert!(matching_plugin.is_none());
}

/// Test end-to-end: Parse HTTP -> Find plugin -> Execute transform -> Serialize
#[tokio::test]
async fn test_proxy_plugin_execution_flow() {
    let db = GapDatabase::in_memory().await.unwrap();

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

    let plugin_entry = PluginEntry {
        name: "test-api".to_string(),
        hosts: vec!["api.example.com".to_string()],
        credential_schema: vec!["api_key".to_string()],
        commit_sha: None,
            dangerously_permit_http: false,
    };
    db.add_plugin(&plugin_entry, plugin_code).await.unwrap();

    // Store credentials
    db.set_credential("test-api", "api_key", "secret123").await.unwrap();

    // Parse incoming HTTP request
    let raw_request = b"GET /v1/users HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n";
    let request = parse_http_request(raw_request).unwrap();

    // Find matching plugin
    let plugin = find_matching_plugin("api.example.com", &db).await.unwrap();
    assert!(plugin.is_some());
    let plugin = plugin.unwrap();

    // Load credentials for the plugin
    let creds_map = db.get_plugin_credentials(&plugin.name).await.unwrap().unwrap();
    let mut creds = GAPCredentials::new();
    for (field, value) in &creds_map {
        creds.set(field, value);
    }

    // Execute transform
    let mut runtime = PluginRuntime::new().unwrap();
    runtime.load_plugin(&plugin.name, &db).await.unwrap();
    let transformed = runtime.execute_transform(&plugin.name, request, &creds).unwrap();

    // Verify transformation
    assert_eq!(transformed.get_header("Authorization"), Some(&"Bearer secret123".to_string()));

    // Serialize back to HTTP
    let http_bytes = serialize_http_request(&transformed).unwrap();
    let http_str = String::from_utf8_lossy(&http_bytes);
    assert!(http_str.contains("Authorization: Bearer secret123\r\n"));
}

// Use the actual implementations from gap_lib
use gap_lib::http_utils::{parse_http_request, serialize_http_request};
use gap_lib::find_matching_plugin;
use gap_lib::proxy_transforms::parse_and_transform;

/// Test the complete proxy transform pipeline
#[tokio::test]
async fn test_complete_proxy_transform_pipeline() {
    let db = GapDatabase::in_memory().await.unwrap();

    // Install a simple plugin
    let plugin_code = r#"
    var plugin = {
        name: "test-transform",
        matchPatterns: ["api.test.com"],
        credentialSchema: ["secret"],
        transform: function(request, credentials) {
            request.headers["X-Transformed"] = "true";
            request.headers["X-Secret"] = credentials.secret;
            return request;
        }
    };
    "#;

    let plugin_entry = PluginEntry {
        name: "test-transform".to_string(),
        hosts: vec!["api.test.com".to_string()],
        credential_schema: vec!["secret".to_string()],
        commit_sha: None,
            dangerously_permit_http: false,
    };
    db.add_plugin(&plugin_entry, plugin_code).await.unwrap();

    // Set credentials directly in database
    db.set_credential("test-transform", "secret", "my-secret-value")
        .await
        .unwrap();

    // Simulate an incoming HTTP request (as raw bytes)
    let raw_http = b"GET /api/data HTTP/1.1\r\nHost: api.test.com\r\nUser-Agent: TestAgent/1.0\r\n\r\n";

    // Transform the request using the proxy pipeline
    let transformed_bytes = parse_and_transform(raw_http, "api.test.com", &db)
        .await
        .unwrap();

    // Parse the result to verify transformation
    let transformed_request = parse_http_request(&transformed_bytes).unwrap();

    // Verify the plugin transformation was applied
    assert_eq!(transformed_request.method, "GET");
    assert_eq!(transformed_request.url, "https://api.test.com/api/data");
    assert_eq!(transformed_request.get_header("Host"), Some(&"api.test.com".to_string()));
    assert_eq!(transformed_request.get_header("User-Agent"), Some(&"TestAgent/1.0".to_string()));
    assert_eq!(transformed_request.get_header("X-Transformed"), Some(&"true".to_string()));
    assert_eq!(transformed_request.get_header("X-Secret"), Some(&"my-secret-value".to_string()));
}
