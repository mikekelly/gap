//! Integration test for proxy transform with actual credential storage
//!
//! Tests that the proxy correctly:
//! 1. Accepts a SecretStore
//! 2. Intercepts HTTP requests after TLS handshake
//! 3. Loads credentials by field pattern (credential:{plugin}:{field})
//! 4. Applies plugin transforms
//! 5. Forwards transformed requests

use gap_lib::registry::{PluginEntry, Registry};
use gap_lib::storage::{FileStore, SecretStore};
use gap_lib::proxy_transforms::parse_and_transform;
use std::sync::Arc;

/// Test that parse_and_transform correctly loads multi-field credentials
#[tokio::test]
async fn test_parse_and_transform_with_multi_field_credentials() {
    let temp_dir = std::env::temp_dir().join(format!(
        "gap_proxy_creds_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let store = Arc::new(FileStore::new(temp_dir.clone()).await.unwrap()) as Arc<dyn SecretStore>;
    let registry = Registry::new(Arc::clone(&store));

    // Install a plugin that uses multiple credential fields
    let plugin_code = r#"
    var plugin = {
        name: "multi-cred-api",
        matchPatterns: ["api.multicred.com"],
        credentialSchema: ["access_key", "secret_key", "region"],
        transform: function(request, credentials) {
            request.headers["X-Access-Key"] = credentials.access_key;
            request.headers["X-Secret-Key"] = credentials.secret_key;
            request.headers["X-Region"] = credentials.region;
            return request;
        }
    };
    "#;

    store.set("plugin:multi-cred-api", plugin_code.as_bytes()).await.unwrap();

    // Add plugin to registry
    let plugin_entry = PluginEntry {
        name: "multi-cred-api".to_string(),
        hosts: vec!["api.multicred.com".to_string()],
        credential_schema: vec!["access_key".to_string(), "secret_key".to_string(), "region".to_string()],
        commit_sha: None,
    };
    registry.add_plugin(&plugin_entry).await.unwrap();

    // Set credentials directly in registry (no separate storage entries needed)
    registry.set_credential("multi-cred-api", "access_key", "AKIAIOSFODNN7EXAMPLE").await.unwrap();
    registry.set_credential("multi-cred-api", "secret_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").await.unwrap();
    registry.set_credential("multi-cred-api", "region", "us-west-2").await.unwrap();

    // Simulate an incoming HTTP request
    let raw_http = b"GET /api/data HTTP/1.1\r\nHost: api.multicred.com\r\nUser-Agent: TestAgent/1.0\r\n\r\n";

    // Transform the request
    let transformed_bytes = parse_and_transform(raw_http, "api.multicred.com", &*store, &registry)
        .await
        .unwrap();

    // Parse the result to verify transformation
    let transformed_str = String::from_utf8_lossy(&transformed_bytes);

    // Verify all credential fields were loaded and used
    assert!(transformed_str.contains("X-Access-Key: AKIAIOSFODNN7EXAMPLE\r\n"));
    assert!(transformed_str.contains("X-Secret-Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n"));
    assert!(transformed_str.contains("X-Region: us-west-2\r\n"));

    // Cleanup
    tokio::fs::remove_dir_all(temp_dir).await.ok();
}

/// Test that parse_and_transform works with single-field credentials (backward compat)
#[tokio::test]
async fn test_parse_and_transform_with_single_field_credential() {
    let temp_dir = std::env::temp_dir().join(format!(
        "gap_proxy_single_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let store = Arc::new(FileStore::new(temp_dir.clone()).await.unwrap()) as Arc<dyn SecretStore>;
    let registry = Registry::new(Arc::clone(&store));

    // Install a simple plugin
    let plugin_code = r#"
    var plugin = {
        name: "simple-api",
        matchPatterns: ["api.simple.com"],
        credentialSchema: ["api_key"],
        transform: function(request, credentials) {
            request.headers["Authorization"] = "Bearer " + credentials.api_key;
            return request;
        }
    };
    "#;

    store.set("plugin:simple-api", plugin_code.as_bytes()).await.unwrap();

    // Add plugin to registry
    let plugin_entry = PluginEntry {
        name: "simple-api".to_string(),
        hosts: vec!["api.simple.com".to_string()],
        credential_schema: vec!["api_key".to_string()],
        commit_sha: None,
    };
    registry.add_plugin(&plugin_entry).await.unwrap();

    // Set credential directly in registry (no separate storage entry needed)
    registry.set_credential("simple-api", "api_key", "secret-api-key-123").await.unwrap();

    // Simulate an incoming HTTP request
    let raw_http = b"GET /api/data HTTP/1.1\r\nHost: api.simple.com\r\n\r\n";

    // Transform the request
    let transformed_bytes = parse_and_transform(raw_http, "api.simple.com", &*store, &registry)
        .await
        .unwrap();

    // Verify transformation
    let transformed_str = String::from_utf8_lossy(&transformed_bytes);
    assert!(transformed_str.contains("Authorization: Bearer secret-api-key-123\r\n"));

    // Cleanup
    tokio::fs::remove_dir_all(temp_dir).await.ok();
}

/// Test that parse_and_transform rejects hosts with no matching plugin
/// Security: proxy should NOT act as an open proxy for arbitrary hosts
#[tokio::test]
async fn test_parse_and_transform_rejects_unregistered_host() {
    let temp_dir = std::env::temp_dir().join(format!(
        "gap_proxy_unregistered_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let store = Arc::new(FileStore::new(temp_dir.clone()).await.unwrap()) as Arc<dyn SecretStore>;
    let registry = Registry::new(Arc::clone(&store));

    // Note: NO plugins installed - this is an arbitrary host

    // Simulate an incoming HTTP request to an unregistered host
    let raw_http = b"GET /api/data HTTP/1.1\r\nHost: unknown.example.com\r\n\r\n";

    // Transform should REJECT - not pass through
    let result = parse_and_transform(raw_http, "unknown.example.com", &*store, &registry).await;

    // Must be an error - the proxy should not allow connections to arbitrary hosts
    assert!(result.is_err(), "Expected error for unregistered host, but got Ok");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not allowed") || err_msg.contains("no plugin") || err_msg.contains("forbidden"),
        "Error should indicate host is not allowed: {}",
        err_msg
    );

    // Cleanup
    tokio::fs::remove_dir_all(temp_dir).await.ok();
}

/// Test that parse_and_transform rejects hosts with plugin but no credentials
/// Security: Having a plugin without credentials means it's not fully configured
#[tokio::test]
async fn test_parse_and_transform_rejects_missing_credentials() {
    let temp_dir = std::env::temp_dir().join(format!(
        "gap_proxy_missing_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let store = Arc::new(FileStore::new(temp_dir.clone()).await.unwrap()) as Arc<dyn SecretStore>;
    let registry = Registry::new(Arc::clone(&store));

    // Install a plugin
    let plugin_code = r#"
    var plugin = {
        name: "no-creds-api",
        matchPatterns: ["api.nocreds.com"],
        credentialSchema: ["api_key"],
        transform: function(request, credentials) {
            request.headers["Authorization"] = "Bearer " + credentials.api_key;
            return request;
        }
    };
    "#;

    store.set("plugin:no-creds-api", plugin_code.as_bytes()).await.unwrap();

    // Add plugin to registry
    let plugin_entry = PluginEntry {
        name: "no-creds-api".to_string(),
        hosts: vec!["api.nocreds.com".to_string()],
        credential_schema: vec!["api_key".to_string()],
        commit_sha: None,
    };
    registry.add_plugin(&plugin_entry).await.unwrap();

    // Note: NOT storing credentials - plugin exists but is not configured

    // Simulate an incoming HTTP request
    let raw_http = b"GET /api/data HTTP/1.1\r\nHost: api.nocreds.com\r\n\r\n";

    // Transform should REJECT - not pass through
    let result = parse_and_transform(raw_http, "api.nocreds.com", &*store, &registry).await;

    // Must be an error - can't proxy without credentials
    assert!(result.is_err(), "Expected error for missing credentials, but got Ok");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("credentials") || err_msg.contains("not configured"),
        "Error should indicate credentials missing: {}",
        err_msg
    );

    // Cleanup
    tokio::fs::remove_dir_all(temp_dir).await.ok();
}
