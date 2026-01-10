//! Integration tests for bundled plugins
//!
//! Tests the bundled plugins in the plugins/ directory to ensure they
//! correctly implement their transform logic.

use acp_lib::plugin_runtime::PluginRuntime;
use acp_lib::types::{ACPCredentials, ACPPlugin, ACPRequest};
use std::fs;

/// Helper to load a plugin file directly (not from store)
fn load_plugin_from_file(runtime: &mut PluginRuntime, name: &str, path: &str) -> acp_lib::Result<ACPPlugin> {
    let code = fs::read_to_string(path)
        .map_err(|e| acp_lib::AcpError::plugin(format!("Failed to read plugin file {}: {}", path, e)))?;

    runtime.load_plugin_from_code(name, &code)
}

#[test]
fn test_exa_plugin_exists() {
    // Test that the exa plugin file exists
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../plugins/exa.js");
    assert!(std::path::Path::new(path).exists(), "exa.js plugin file should exist");
}

#[test]
fn test_exa_plugin_loads() {
    let mut runtime = PluginRuntime::new().unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../plugins/exa.js");

    let result = load_plugin_from_file(&mut runtime, "exa", path);
    assert!(result.is_ok(), "exa plugin should load successfully");
}

#[test]
fn test_exa_plugin_schema() {
    let mut runtime = PluginRuntime::new().unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../plugins/exa.js");

    let plugin = load_plugin_from_file(&mut runtime, "exa", path).unwrap();

    assert_eq!(plugin.name, "exa");
    assert_eq!(plugin.match_patterns, vec!["api.exa.ai"]);
    assert_eq!(plugin.credential_schema, vec!["api_key"]);
}

#[test]
fn test_exa_plugin_adds_authorization_header() {
    let mut runtime = PluginRuntime::new().unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../plugins/exa.js");

    load_plugin_from_file(&mut runtime, "exa", path).unwrap();

    let request = ACPRequest::new("POST", "https://api.exa.ai/search")
        .with_header("Content-Type", "application/json")
        .with_body(b"{\"query\":\"test\"}".to_vec());

    let mut credentials = ACPCredentials::new();
    credentials.set("api_key", "test-api-key-12345");

    let transformed = runtime.execute_transform("exa", request, &credentials).unwrap();

    // Exa API expects "Bearer {api_key}" format
    assert_eq!(
        transformed.get_header("Authorization"),
        Some(&"Bearer test-api-key-12345".to_string()),
        "Should add Authorization header with Bearer token"
    );

    // Other headers and fields should be preserved
    assert_eq!(transformed.method, "POST");
    assert_eq!(transformed.url, "https://api.exa.ai/search");
    assert_eq!(transformed.get_header("Content-Type"), Some(&"application/json".to_string()));
    assert_eq!(transformed.body, b"{\"query\":\"test\"}");
}

#[test]
fn test_aws_s3_plugin_exists() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../plugins/aws-s3.js");
    assert!(std::path::Path::new(path).exists(), "aws-s3.js plugin file should exist");
}

#[test]
fn test_aws_s3_plugin_loads() {
    let mut runtime = PluginRuntime::new().unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../plugins/aws-s3.js");

    let result = load_plugin_from_file(&mut runtime, "aws-s3", path);
    assert!(result.is_ok(), "aws-s3 plugin should load successfully");
}

#[test]
fn test_aws_s3_plugin_schema() {
    let mut runtime = PluginRuntime::new().unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../plugins/aws-s3.js");

    let plugin = load_plugin_from_file(&mut runtime, "aws-s3", path).unwrap();

    assert_eq!(plugin.name, "aws-s3");
    assert_eq!(plugin.match_patterns, vec!["*.s3.amazonaws.com", "s3.amazonaws.com"]);
    assert_eq!(plugin.credential_schema, vec!["access_key_id", "secret_access_key", "region"]);
}

#[test]
fn test_aws_s3_plugin_signs_get_request() {
    let mut runtime = PluginRuntime::new().unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../plugins/aws-s3.js");

    load_plugin_from_file(&mut runtime, "aws-s3", path).unwrap();

    let request = ACPRequest::new("GET", "https://my-bucket.s3.amazonaws.com/my-file.txt");

    let mut credentials = ACPCredentials::new();
    credentials.set("access_key_id", "AKIAIOSFODNN7EXAMPLE");
    credentials.set("secret_access_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    credentials.set("region", "us-east-1");

    let transformed = runtime.execute_transform("aws-s3", request, &credentials).unwrap();

    // Should have Authorization header with AWS4-HMAC-SHA256
    let auth_header = transformed.get_header("Authorization")
        .expect("Should have Authorization header");
    assert!(auth_header.starts_with("AWS4-HMAC-SHA256"), "Authorization should use AWS Signature v4");
    assert!(auth_header.contains("Credential=AKIAIOSFODNN7EXAMPLE"), "Should include access key");
    assert!(auth_header.contains("SignedHeaders="), "Should list signed headers");
    assert!(auth_header.contains("Signature="), "Should include signature");

    // Should have required AWS headers
    assert!(transformed.get_header("x-amz-date").is_some(), "Should have x-amz-date header");
    assert!(transformed.get_header("host").is_some(), "Should have host header");

    // Original request properties preserved
    assert_eq!(transformed.method, "GET");
    assert_eq!(transformed.url, "https://my-bucket.s3.amazonaws.com/my-file.txt");
}

#[test]
fn test_aws_s3_plugin_signs_put_request_with_body() {
    let mut runtime = PluginRuntime::new().unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../plugins/aws-s3.js");

    load_plugin_from_file(&mut runtime, "aws-s3", path).unwrap();

    let body_content = b"test file content";
    let request = ACPRequest::new("PUT", "https://my-bucket.s3.us-west-2.amazonaws.com/upload.txt")
        .with_header("Content-Type", "text/plain")
        .with_body(body_content.to_vec());

    let mut credentials = ACPCredentials::new();
    credentials.set("access_key_id", "AKIAIOSFODNN7EXAMPLE");
    credentials.set("secret_access_key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    credentials.set("region", "us-west-2");

    let transformed = runtime.execute_transform("aws-s3", request, &credentials).unwrap();

    // Should have Authorization header
    let auth_header = transformed.get_header("Authorization").unwrap();
    assert!(auth_header.starts_with("AWS4-HMAC-SHA256"), "Should use AWS Signature v4");

    // Should have content hash header for PUT requests
    assert!(transformed.get_header("x-amz-content-sha256").is_some(), "Should have content hash");

    // Body should be preserved
    assert_eq!(transformed.body, body_content);
    assert_eq!(transformed.get_header("Content-Type"), Some(&"text/plain".to_string()));
}
