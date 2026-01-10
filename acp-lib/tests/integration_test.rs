//! Integration tests for the ACP system
//!
//! Tests the full pipeline: FileStore -> PluginRuntime -> Transform execution

use acp_lib::plugin_runtime::PluginRuntime;
use acp_lib::storage::{FileStore, SecretStore};
use acp_lib::types::{ACPCredentials, ACPRequest};

/// Integration test: Load test-api plugin and execute a transform
///
/// This tests the complete flow:
/// 1. Create a FileStore
/// 2. Store the test-api plugin code
/// 3. Create a PluginRuntime
/// 4. Load the plugin from the store
/// 5. Execute the transform function
/// 6. Verify the Authorization header is set correctly
#[tokio::test]
async fn test_full_plugin_pipeline() {
    // Create a temporary directory for the test store
    let temp_dir = std::env::temp_dir().join(format!(
        "acp_integration_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    // Create FileStore
    let store = FileStore::new(temp_dir.clone()).await.unwrap();

    // Load test plugin code from the plugins directory
    let plugin_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("plugins")
        .join("test-api.js");

    let plugin_code = tokio::fs::read_to_string(&plugin_path)
        .await
        .expect("Failed to read test-api.js - make sure plugins/test-api.js exists");

    // Store the plugin in the FileStore
    store
        .set("plugin:test-api", plugin_code.as_bytes())
        .await
        .unwrap();

    // Create PluginRuntime
    let mut runtime = PluginRuntime::new().unwrap();

    // Load the plugin
    let plugin = runtime.load_plugin("test-api", &store).await.unwrap();

    // Verify plugin metadata
    assert_eq!(plugin.name, "test-api");
    assert_eq!(plugin.match_patterns, vec!["api.example.com"]);
    assert_eq!(plugin.credential_schema, vec!["api_key"]);
    assert!(plugin.matches_host("api.example.com"));
    assert!(!plugin.matches_host("other.example.com"));

    // Create a test request
    let request = ACPRequest::new("GET", "https://api.example.com/v1/users")
        .with_header("Content-Type", "application/json");

    // Create credentials
    let mut credentials = ACPCredentials::new();
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

    // Cleanup
    tokio::fs::remove_dir_all(temp_dir).await.ok();
}

/// Smoke test: Verify multiple plugins can coexist
#[tokio::test]
async fn test_multiple_plugins() {
    let temp_dir = std::env::temp_dir().join(format!(
        "acp_multi_plugin_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let store = FileStore::new(temp_dir.clone()).await.unwrap();

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

    store
        .set("plugin:service-a", plugin1_code.as_bytes())
        .await
        .unwrap();
    store
        .set("plugin:service-b", plugin2_code.as_bytes())
        .await
        .unwrap();

    let mut runtime = PluginRuntime::new().unwrap();

    // Load both plugins
    let plugin_a = runtime.load_plugin("service-a", &store).await.unwrap();
    let plugin_b = runtime.load_plugin("service-b", &store).await.unwrap();

    assert_eq!(plugin_a.name, "service-a");
    assert_eq!(plugin_b.name, "service-b");
    assert_eq!(plugin_a.credential_schema, vec!["token"]);
    assert_eq!(plugin_b.credential_schema, vec!["api_key", "secret"]);

    // Execute transform for the last loaded plugin (plugin B)
    // Note: Loading plugin B overwrites the global `plugin` object in the JS context,
    // so we can only execute the most recently loaded plugin's transform.
    let request_b = ACPRequest::new("POST", "https://service-b.example.com/api");
    let mut creds_b = ACPCredentials::new();
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

    // Cleanup
    tokio::fs::remove_dir_all(temp_dir).await.ok();
}

/// Smoke test: Verify plugin with complex credential schema
#[tokio::test]
async fn test_plugin_with_multiple_credentials() {
    let temp_dir = std::env::temp_dir().join(format!(
        "acp_multi_cred_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    let store = FileStore::new(temp_dir.clone()).await.unwrap();

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

    store
        .set("plugin:aws-like", plugin_code.as_bytes())
        .await
        .unwrap();

    let mut runtime = PluginRuntime::new().unwrap();
    let plugin = runtime.load_plugin("aws-like", &store).await.unwrap();

    assert_eq!(plugin.credential_schema.len(), 3);
    assert!(plugin.credential_schema.contains(&"access_key_id".to_string()));
    assert!(plugin.credential_schema.contains(&"secret_access_key".to_string()));
    assert!(plugin.credential_schema.contains(&"region".to_string()));

    // Test wildcard matching
    assert!(plugin.matches_host("my-bucket.s3.amazonaws.com"));
    assert!(!plugin.matches_host("s3.amazonaws.com")); // No subdomain
    assert!(!plugin.matches_host("a.b.s3.amazonaws.com")); // Multiple subdomains

    let request = ACPRequest::new("GET", "https://my-bucket.s3.amazonaws.com/object");
    let mut creds = ACPCredentials::new();
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

    // Cleanup
    tokio::fs::remove_dir_all(temp_dir).await.ok();
}
