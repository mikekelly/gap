//! Integration test for proxy transform with actual credential storage
//!
//! Tests that the proxy correctly:
//! 1. Accepts a GapDatabase
//! 2. Intercepts HTTP requests after TLS handshake
//! 3. Loads credentials from database
//! 4. Applies plugin transforms
//! 5. Forwards transformed requests

use gap_lib::database::GapDatabase;
use gap_lib::types::PluginEntry;
use gap_lib::proxy_transforms::parse_and_transform;

/// Test that parse_and_transform correctly loads multi-field credentials
#[tokio::test]
async fn test_parse_and_transform_with_multi_field_credentials() {
    let db = GapDatabase::in_memory().await.unwrap();

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

    let plugin_entry = PluginEntry {
        id: "multi-cred-api".to_string(),
        source: None,
        hosts: vec!["api.multicred.com".to_string()],
        credential_schema: vec!["access_key".to_string(), "secret_key".to_string(), "region".to_string()],
        commit_sha: None,
        dangerously_permit_http: false,
        weight: 0,
        installed_at: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    };
    let plugin_id = db.add_plugin(&plugin_entry, plugin_code, "default", "default").await.unwrap();

    // Set credentials directly in database
    db.set_credential(&plugin_id, "access_key", "AKIAIOSFODNN7EXAMPLE", "default", "default").await.unwrap();
    db.set_credential(&plugin_id, "secret_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "default", "default").await.unwrap();
    db.set_credential(&plugin_id, "region", "us-west-2", "default", "default").await.unwrap();

    // Simulate an incoming HTTP request
    let raw_http = b"GET /api/data HTTP/1.1\r\nHost: api.multicred.com\r\nUser-Agent: TestAgent/1.0\r\n\r\n";

    // Transform the request
    let transformed_bytes = parse_and_transform(raw_http, "api.multicred.com", &db)
        .await
        .unwrap();

    // Parse the result to verify transformation
    let transformed_str = String::from_utf8_lossy(&transformed_bytes);

    // Verify all credential fields were loaded and used
    assert!(transformed_str.contains("X-Access-Key: AKIAIOSFODNN7EXAMPLE\r\n"));
    assert!(transformed_str.contains("X-Secret-Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\r\n"));
    assert!(transformed_str.contains("X-Region: us-west-2\r\n"));
}

/// Test that parse_and_transform works with single-field credentials (backward compat)
#[tokio::test]
async fn test_parse_and_transform_with_single_field_credential() {
    let db = GapDatabase::in_memory().await.unwrap();

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

    let plugin_entry = PluginEntry {
        id: "simple-api".to_string(),
        source: None,
        hosts: vec!["api.simple.com".to_string()],
        credential_schema: vec!["api_key".to_string()],
        commit_sha: None,
        dangerously_permit_http: false,
        weight: 0,
        installed_at: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    };
    let plugin_id = db.add_plugin(&plugin_entry, plugin_code, "default", "default").await.unwrap();

    // Set credential directly in database
    db.set_credential(&plugin_id, "api_key", "secret-api-key-123", "default", "default").await.unwrap();

    // Simulate an incoming HTTP request
    let raw_http = b"GET /api/data HTTP/1.1\r\nHost: api.simple.com\r\n\r\n";

    // Transform the request
    let transformed_bytes = parse_and_transform(raw_http, "api.simple.com", &db)
        .await
        .unwrap();

    // Verify transformation
    let transformed_str = String::from_utf8_lossy(&transformed_bytes);
    assert!(transformed_str.contains("Authorization: Bearer secret-api-key-123\r\n"));
}

/// Test that parse_and_transform rejects hosts with no matching plugin
/// Security: proxy should NOT act as an open proxy for arbitrary hosts
#[tokio::test]
async fn test_parse_and_transform_rejects_unregistered_host() {
    let db = GapDatabase::in_memory().await.unwrap();

    // Note: NO plugins installed - this is an arbitrary host

    // Simulate an incoming HTTP request to an unregistered host
    let raw_http = b"GET /api/data HTTP/1.1\r\nHost: unknown.example.com\r\n\r\n";

    // Transform should REJECT - not pass through
    let result = parse_and_transform(raw_http, "unknown.example.com", &db).await;

    // Must be an error - the proxy should not allow connections to arbitrary hosts
    assert!(result.is_err(), "Expected error for unregistered host, but got Ok");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not allowed") || err_msg.contains("no plugin") || err_msg.contains("forbidden"),
        "Error should indicate host is not allowed: {}",
        err_msg
    );
}

/// Test that parse_and_transform rejects hosts with plugin but no credentials
/// Security: Having a plugin without credentials means it's not fully configured
#[tokio::test]
async fn test_parse_and_transform_rejects_missing_credentials() {
    let db = GapDatabase::in_memory().await.unwrap();

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

    let plugin_entry = PluginEntry {
        id: "no-creds-api".to_string(),
        source: None,
        hosts: vec!["api.nocreds.com".to_string()],
        credential_schema: vec!["api_key".to_string()],
        commit_sha: None,
        dangerously_permit_http: false,
        weight: 0,
        installed_at: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    };
    db.add_plugin(&plugin_entry, plugin_code, "default", "default").await.unwrap();

    // Note: NOT storing credentials - plugin exists but is not configured

    // Simulate an incoming HTTP request
    let raw_http = b"GET /api/data HTTP/1.1\r\nHost: api.nocreds.com\r\n\r\n";

    // Transform should REJECT - not pass through
    let result = parse_and_transform(raw_http, "api.nocreds.com", &db).await;

    // Must be an error - can't proxy without credentials
    assert!(result.is_err(), "Expected error for missing credentials, but got Ok");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("credentials") || err_msg.contains("not configured"),
        "Error should indicate credentials missing: {}",
        err_msg
    );
}
