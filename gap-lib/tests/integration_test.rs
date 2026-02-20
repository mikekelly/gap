//! Integration tests for the GAP system
//!
//! Tests the full pipeline: GapDatabase -> PluginRuntime -> Transform execution

use gap_lib::database::GapDatabase;
use gap_lib::plugin_runtime::PluginRuntime;
use gap_lib::types::PluginEntry;
use gap_lib::types::{GAPCredentials, GAPRequest};

/// Integration test: Load test-api plugin and execute a transform
///
/// This tests the complete flow:
/// 1. Create an in-memory GapDatabase
/// 2. Store the test-api plugin code
/// 3. Create a PluginRuntime
/// 4. Load the plugin from the database
/// 5. Execute the transform function
/// 6. Verify the Authorization header is set correctly
#[tokio::test]
async fn test_full_plugin_pipeline() {
    let db = GapDatabase::in_memory().await.unwrap();

    // Load test plugin code from the plugins directory
    let plugin_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("plugins")
        .join("test-api.js");

    let plugin_code = tokio::fs::read_to_string(&plugin_path)
        .await
        .expect("Failed to read test-api.js - make sure plugins/test-api.js exists");

    // Store the plugin in the database
    let plugin_entry = PluginEntry {
        name: "test-api".to_string(),
        hosts: vec!["api.example.com".to_string()],
        credential_schema: vec!["api_key".to_string()],
        commit_sha: None,
        dangerously_permit_http: false,
        weight: 0,
        installed_at: None,
    };
    db.add_plugin(&plugin_entry, &plugin_code).await.unwrap();

    // Create PluginRuntime
    let mut runtime = PluginRuntime::new().unwrap();

    // Load the plugin
    let plugin = runtime.load_plugin("test-api", &db).await.unwrap();

    // Verify plugin metadata
    assert_eq!(plugin.name, "test-api");
    assert_eq!(plugin.match_patterns, vec!["api.example.com"]);
    assert_eq!(plugin.credential_schema, vec!["api_key"]);
    assert!(plugin.matches_host("api.example.com"));
    assert!(!plugin.matches_host("other.example.com"));

    // Create a test request
    let request = GAPRequest::new("GET", "https://api.example.com/v1/users")
        .with_header("Content-Type", "application/json");

    // Create credentials
    let mut credentials = GAPCredentials::new();
    credentials.set("api_key", "test_secret_key_12345");

    // Execute the transform
    let transformed = runtime
        .execute_transform("test-api", request.clone(), &credentials)
        .unwrap();

    // Verify the transform worked
    assert_eq!(transformed.method, "GET");
    assert_eq!(transformed.url, "https://api.example.com/v1/users");
    assert_eq!(
        transformed.get_header("Content-Type"),
        Some(&"application/json".to_string())
    );
    assert_eq!(
        transformed.get_header("Authorization"),
        Some(&"Bearer test_secret_key_12345".to_string())
    );
}

/// Smoke test: Verify multiple plugins can coexist
#[tokio::test]
async fn test_multiple_plugins() {
    let db = GapDatabase::in_memory().await.unwrap();

    // Create two different plugins
    let plugin1_code = r#"
    var plugin = {
        name: "service-a",
        matchPatterns: ["service-a.example.com"],
        credentialSchema: ["token"],
        transform: function(request, credentials) {
            request.headers["X-Service-A-Token"] = credentials.token;
            return request;
        }
    };
    "#;

    let plugin2_code = r#"
    var plugin = {
        name: "service-b",
        matchPatterns: ["service-b.example.com"],
        credentialSchema: ["api_key", "secret"],
        transform: function(request, credentials) {
            request.headers["X-API-Key"] = credentials.api_key;
            request.headers["X-Secret"] = credentials.secret;
            return request;
        }
    };
    "#;

    let entry_a = PluginEntry {
        name: "service-a".to_string(),
        hosts: vec!["service-a.example.com".to_string()],
        credential_schema: vec!["token".to_string()],
        commit_sha: None,
        dangerously_permit_http: false,
        weight: 0,
        installed_at: None,
    };
    db.add_plugin(&entry_a, plugin1_code).await.unwrap();

    let entry_b = PluginEntry {
        name: "service-b".to_string(),
        hosts: vec!["service-b.example.com".to_string()],
        credential_schema: vec!["api_key".to_string(), "secret".to_string()],
        commit_sha: None,
        dangerously_permit_http: false,
        weight: 0,
        installed_at: None,
    };
    db.add_plugin(&entry_b, plugin2_code).await.unwrap();

    let mut runtime = PluginRuntime::new().unwrap();

    // Load both plugins
    let plugin_a = runtime.load_plugin("service-a", &db).await.unwrap();
    let plugin_b = runtime.load_plugin("service-b", &db).await.unwrap();

    assert_eq!(plugin_a.name, "service-a");
    assert_eq!(plugin_b.name, "service-b");
    assert_eq!(plugin_a.credential_schema, vec!["token"]);
    assert_eq!(plugin_b.credential_schema, vec!["api_key", "secret"]);

    // Execute transform for the last loaded plugin (plugin B)
    // Note: Loading plugin B overwrites the global `plugin` object in the JS context,
    // so we can only execute the most recently loaded plugin's transform.
    let request_b = GAPRequest::new("POST", "https://service-b.example.com/api");
    let mut creds_b = GAPCredentials::new();
    creds_b.set("api_key", "key_456");
    creds_b.set("secret", "secret_789");

    let transformed_b = runtime
        .execute_transform("service-b", request_b, &creds_b)
        .unwrap();
    assert_eq!(
        transformed_b.get_header("X-API-Key"),
        Some(&"key_456".to_string())
    );
    assert_eq!(
        transformed_b.get_header("X-Secret"),
        Some(&"secret_789".to_string())
    );

    // Both plugins' metadata is preserved even though only the last one can execute transforms
}

/// Smoke test: Verify plugin with complex credential schema
#[tokio::test]
async fn test_plugin_with_multiple_credentials() {
    let db = GapDatabase::in_memory().await.unwrap();

    // Plugin that uses multiple credentials
    let plugin_code = r#"
    var plugin = {
        name: "aws-like",
        matchPatterns: ["*.s3.amazonaws.com"],
        credentialSchema: ["access_key_id", "secret_access_key", "region"],
        transform: function(request, credentials) {
            // Simulate AWS-style auth header
            var auth = "AWS4-HMAC-SHA256 Credential=" + credentials.access_key_id;
            auth += "/20240101/" + credentials.region + "/s3/aws4_request";
            request.headers["Authorization"] = auth;
            request.headers["X-Amz-Region"] = credentials.region;
            return request;
        }
    };
    "#;

    let plugin_entry = PluginEntry {
        name: "aws-like".to_string(),
        hosts: vec!["*.s3.amazonaws.com".to_string()],
        credential_schema: vec![
            "access_key_id".to_string(),
            "secret_access_key".to_string(),
            "region".to_string(),
        ],
        commit_sha: None,
        dangerously_permit_http: false,
        weight: 0,
        installed_at: None,
    };
    db.add_plugin(&plugin_entry, plugin_code).await.unwrap();

    let mut runtime = PluginRuntime::new().unwrap();
    let plugin = runtime.load_plugin("aws-like", &db).await.unwrap();

    assert_eq!(plugin.credential_schema.len(), 3);
    assert!(plugin.credential_schema.contains(&"access_key_id".to_string()));
    assert!(plugin.credential_schema.contains(&"secret_access_key".to_string()));
    assert!(plugin.credential_schema.contains(&"region".to_string()));

    // Test wildcard matching
    assert!(plugin.matches_host("my-bucket.s3.amazonaws.com"));
    assert!(!plugin.matches_host("s3.amazonaws.com")); // No subdomain
    assert!(!plugin.matches_host("a.b.s3.amazonaws.com")); // Multiple subdomains

    let request = GAPRequest::new("GET", "https://my-bucket.s3.amazonaws.com/object");
    let mut creds = GAPCredentials::new();
    creds.set("access_key_id", "AKIAIOSFODNN7EXAMPLE");
    creds.set("secret_access_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    creds.set("region", "us-west-2");

    let transformed = runtime.execute_transform("aws-like", request, &creds).unwrap();

    assert!(transformed
        .get_header("Authorization")
        .unwrap()
        .contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(transformed
        .get_header("Authorization")
        .unwrap()
        .contains("us-west-2"));
    assert_eq!(
        transformed.get_header("X-Amz-Region"),
        Some(&"us-west-2".to_string())
    );
}
