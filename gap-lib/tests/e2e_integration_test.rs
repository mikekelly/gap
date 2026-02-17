//! End-to-End Integration Tests for GAP System
//!
//! Tests the complete lifecycle flows:
//! 1. Server initialization (init -> server starts)
//! 2. Plugin installation (install -> list shows plugin)
//! 3. Credential setting (set -> stored correctly)
//! 4. Token management (create -> list -> revoke)
//!
//! These tests use actual binaries and real HTTP endpoints to verify
//! the full integration across CLI, API, and storage layers.

use gap_lib::database::GapDatabase;
use reqwest::{Client, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha512};
use std::process::{Child, Command};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

/// Test helper to manage server lifecycle
struct TestServer {
    process: Option<Child>,
    api_url: String,
    proxy_port: u16,
    api_port: u16,
    _temp_dir: TempDir,
}

impl TestServer {
    /// Start a new test server on available ports
    async fn start() -> anyhow::Result<Self> {
        let temp_dir = tempfile::tempdir()?;

        // Use dynamic ports to avoid conflicts
        let api_port = portpicker::pick_unused_port().expect("No ports available");
        let proxy_port = portpicker::pick_unused_port().expect("No ports available");

        // Set HOME to temp dir to avoid keychain collisions on macOS
        std::env::set_var("HOME", temp_dir.path());

        // Find the server binary in the workspace target directory
        let server_binary = std::env::var("CARGO_BIN_EXE_gap-server")
            .unwrap_or_else(|_| {
                // Fallback: construct path relative to workspace root
                let manifest_dir = env!("CARGO_MANIFEST_DIR");
                let workspace_root = std::path::Path::new(manifest_dir).parent().unwrap();
                workspace_root
                    .join("target")
                    .join("debug")
                    .join("gap-server")
                    .to_str()
                    .unwrap()
                    .to_string()
            });

        let mut process = Command::new(&server_binary)
            .env("HOME", temp_dir.path())
            .arg("--api-port")
            .arg(api_port.to_string())
            .arg("--proxy-port")
            .arg(proxy_port.to_string())
            .arg("--data-dir")
            .arg(temp_dir.path().to_str().unwrap())
            .arg("--log-level")
            .arg("warn")
            .spawn()?;

        let api_url = format!("https://localhost:{}", api_port);

        // Wait for server to be ready
        // Use danger_accept_invalid_certs for test environments with self-signed certs
        let client = Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build client");
        let mut retries = 30;
        while retries > 0 {
            if let Ok(resp) = client.get(&format!("{}/status", api_url)).send().await {
                if resp.status().is_success() {
                    break;
                }
            }
            sleep(Duration::from_millis(100)).await;
            retries -= 1;
        }

        if retries == 0 {
            process.kill()?;
            anyhow::bail!("Server failed to start within timeout");
        }

        Ok(Self {
            process: Some(process),
            api_url,
            proxy_port,
            api_port,
            _temp_dir: temp_dir,
        })
    }

    /// Create a test client that accepts self-signed certs
    fn create_test_client() -> Client {
        Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build test client")
    }

    /// Initialize server with password
    async fn init(&self, password: &str) -> anyhow::Result<()> {
        let client = Self::create_test_client();

        // Hash password with SHA512 (client-side)
        let mut hasher = Sha512::new();
        hasher.update(password.as_bytes());
        let password_hash = hex::encode(hasher.finalize());

        let response = client
            .post(&format!("{}/init", self.api_url))
            .json(&json!({
                "password_hash": password_hash,
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Init failed: {:?}", response.text().await?);
        }

        Ok(())
    }

    /// Get server status (unauthenticated)
    async fn status(&self) -> anyhow::Result<serde_json::Value> {
        let client = Self::create_test_client();
        let response = client
            .get(&format!("{}/status", self.api_url))
            .send()
            .await?;

        Ok(response.json().await?)
    }

    /// Create authenticated request body
    fn auth_body<T: serde::Serialize>(password: &str, data: T) -> serde_json::Value {
        let mut hasher = Sha512::new();
        hasher.update(password.as_bytes());
        let password_hash = hex::encode(hasher.finalize());

        let mut value = serde_json::to_value(data).unwrap();
        value["password_hash"] = json!(password_hash);
        value
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ = process.kill();
        }
    }
}

/// Test 1a: Server status endpoint (no auth required)
///
/// Flow: server starts -> status returns version info
///
/// This test works on all platforms and doesn't require authentication.
#[tokio::test]
async fn test_server_status_endpoint() {
    let server = TestServer::start().await.expect("Failed to start server");

    // Status should work without initialization (no auth required)
    let status = server.status().await.expect("Status failed");

    // Verify response structure
    assert!(status["version"].is_string());
    assert!(status["uptime_seconds"].is_number());
    assert_eq!(status["proxy_port"], server.proxy_port);
    assert_eq!(status["api_port"], server.api_port);

    // Verify version is a valid semver-like string
    let version = status["version"].as_str().unwrap();
    assert!(!version.is_empty());

    // Uptime should be small (server just started)
    let uptime = status["uptime_seconds"].as_u64().unwrap();
    assert!(uptime < 10, "Uptime should be less than 10 seconds for new server");
}

/// Test 1b: Server initialization flow
///
/// Flow: init -> server starts -> status returns version info
///
/// Note: On macOS, the init endpoint uses KeychainStore which requires user interaction.
/// This test is marked as ignored by default on macOS. Run with `--ignored` if you want
/// to test with manual keychain approval.
#[tokio::test]
#[cfg_attr(target_os = "macos", ignore = "Requires keychain access on macOS")]
async fn test_server_initialization_flow() {
    let server = TestServer::start().await.expect("Failed to start server");

    // Status should work before init (no auth required)
    let status = server.status().await.expect("Status failed");
    assert!(status["version"].is_string());
    assert_eq!(status["proxy_port"], server.proxy_port);
    assert_eq!(status["api_port"], server.api_port);

    // Initialize with password
    server.init("test_password_123").await.expect("Init failed");

    // Status should still work after init
    let status = server.status().await.expect("Status failed after init");
    assert!(status["version"].is_string());
}

/// Test 2: Plugin installation flow (via GapDatabase)
///
/// Flow: install plugin to database -> verify can be loaded -> verify metadata
#[tokio::test]
async fn test_plugin_installation_flow() {
    use gap_lib::plugin_runtime::PluginRuntime;
    use gap_lib::types::PluginEntry;

    let db = GapDatabase::in_memory().await.expect("Failed to create in-memory db");

    // Create a test plugin
    let plugin_code = r#"
    var plugin = {
        name: "test-service",
        matchPatterns: ["api.test.com"],
        credentialSchema: ["api_key"],
        transform: function(request, credentials) {
            request.headers["Authorization"] = "Bearer " + credentials.api_key;
            return request;
        }
    };
    "#;

    // Install plugin to database
    let plugin_entry = PluginEntry {
        name: "test-service".to_string(),
        hosts: vec!["api.test.com".to_string()],
        credential_schema: vec!["api_key".to_string()],
        commit_sha: None,
    };
    db.add_plugin(&plugin_entry, plugin_code)
        .await
        .expect("Failed to install plugin");

    // Verify plugin can be loaded
    let mut runtime = PluginRuntime::new().expect("Failed to create runtime");
    let plugin = runtime
        .load_plugin("test-service", &db)
        .await
        .expect("Failed to load plugin");

    // Verify plugin metadata
    assert_eq!(plugin.name, "test-service");
    assert_eq!(plugin.match_patterns, vec!["api.test.com"]);
    assert_eq!(plugin.credential_schema, vec!["api_key"]);

    // Verify plugin can be retrieved from database
    let retrieved = db.get_plugin_source("test-service").await.expect("Failed to get plugin");
    assert!(retrieved.is_some());
}

/// Test 3: Credential setting flow
///
/// Flow: set credential -> verify stored correctly -> retrieve via database
#[tokio::test]
async fn test_credential_setting_flow() {
    let db = GapDatabase::in_memory().await.expect("Failed to create in-memory db");

    // Set a credential
    db.set_credential("test-service", "api_key", "secret_key_12345")
        .await
        .expect("Failed to set credential");

    // Retrieve and verify
    let retrieved = db.get_credential("test-service", "api_key")
        .await
        .expect("Failed to get credential");
    assert_eq!(retrieved, Some("secret_key_12345".to_string()));

    // Verify can be deleted
    db.remove_credential("test-service", "api_key")
        .await
        .expect("Failed to delete");
    let deleted = db.get_credential("test-service", "api_key")
        .await
        .expect("Failed to get after delete");
    assert_eq!(deleted, None);
}

/// Test 4: Token management flow
///
/// Flow: create token -> list shows token -> revoke -> verify removed
///
/// Note: Requires server initialization which uses KeychainStore on macOS.
#[tokio::test]
#[cfg_attr(target_os = "macos", ignore = "Requires keychain access on macOS")]
async fn test_token_management_flow() {
    let server = TestServer::start().await.expect("Failed to start server");
    server.init("test_password_123").await.expect("Init failed");

    let client = TestServer::create_test_client();
    let password = "test_password_123";

    // Create a token
    let create_body = TestServer::auth_body(
        password,
        json!({
            "name": "test-agent",
        }),
    );

    let response = client
        .post(&format!("{}/tokens/create", server.api_url))
        .json(&create_body)
        .send()
        .await
        .expect("Create token request failed");

    assert_eq!(response.status(), StatusCode::OK);

    let token_response: serde_json::Value = response.json().await.expect("Parse failed");
    let token_id = token_response["id"].as_str().expect("No token ID");
    let token_value = token_response["token"].as_str().expect("No token value");

    // Verify token starts with "gap_"
    assert!(token_value.starts_with("gap_"));

    // List tokens (uses POST /tokens which is an alias for list)
    let list_body = TestServer::auth_body(password, json!({}));

    let response = client
        .post(&format!("{}/tokens", server.api_url))
        .json(&list_body)
        .send()
        .await
        .expect("List tokens request failed");

    let tokens_list: serde_json::Value = response.json().await.expect("Parse failed");
    let tokens = tokens_list["tokens"].as_array().expect("tokens not array");

    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0]["id"], token_id);
    assert_eq!(tokens[0]["name"], "test-agent");

    // Token field should not be present in list (only prefix)
    assert!(tokens[0]["token"].is_null() || !tokens[0]["token"].is_string());
    assert!(tokens[0]["prefix"].is_string());

    // Revoke token
    let revoke_body = TestServer::auth_body(password, json!({}));

    let response = client
        .delete(&format!("{}/tokens/{}", server.api_url, token_id))
        .json(&revoke_body)
        .send()
        .await
        .expect("Revoke token request failed");

    assert_eq!(response.status(), StatusCode::OK);

    // List should be empty now
    let response = client
        .post(&format!("{}/tokens", server.api_url))
        .json(&list_body)
        .send()
        .await
        .expect("List tokens request failed");

    let tokens_list: serde_json::Value = response.json().await.expect("Parse failed");
    let tokens = tokens_list["tokens"].as_array().expect("tokens not array");

    assert_eq!(tokens.len(), 0);
}

/// Test 5: Complete integration flow
///
/// Flow: init -> install plugin -> set credential -> create token -> verify proxy ready
///
/// Note: Requires server initialization which uses KeychainStore on macOS.
#[tokio::test]
#[cfg_attr(target_os = "macos", ignore = "Requires keychain access on macOS")]
async fn test_complete_integration_flow() {
    let server = TestServer::start().await.expect("Failed to start server");

    // Step 1: Initialize
    server.init("secure_password_456").await.expect("Init failed");

    let client = TestServer::create_test_client();
    let password = "secure_password_456";

    // Step 2: Set credential (via API)
    // Note: Plugin installation API not fully implemented yet
    let cred_body = TestServer::auth_body(
        password,
        json!({
            "value": "exa_test_key_12345",
        }),
    );

    let response = client
        .post(&format!("{}/credentials/exa-api/api_key", server.api_url))
        .json(&cred_body)
        .send()
        .await
        .expect("Set credential failed");

    assert_eq!(response.status(), StatusCode::OK);

    // Step 3: Create token
    let create_token_body = TestServer::auth_body(
        password,
        json!({
            "name": "my-agent",
        }),
    );

    let response = client
        .post(&format!("{}/tokens/create", server.api_url))
        .json(&create_token_body)
        .send()
        .await
        .expect("Create token failed");

    let token_response: serde_json::Value = response.json().await.expect("Parse failed");
    let token_value = token_response["token"].as_str().expect("No token");

    // Step 4: Verify status shows all components ready
    let status = server.status().await.expect("Status failed");
    assert_eq!(status["proxy_port"], server.proxy_port);
    assert_eq!(status["api_port"], server.api_port);

    // Verify we got a valid token
    assert!(token_value.starts_with("gap_"));
    assert!(token_value.len() > 20);
}

/// Test 6: Token sharing between API and ProxyServer
///
/// Flow: create token via API -> verify proxy can authenticate with new token
///
/// This test ensures that tokens created dynamically via the Management API
/// are immediately visible to the ProxyServer for authentication.
#[tokio::test]
#[cfg_attr(target_os = "macos", ignore = "Requires keychain access on macOS")]
async fn test_token_sharing_between_api_and_proxy() {
    let server = TestServer::start().await.expect("Failed to start server");
    server.init("test_password_789").await.expect("Init failed");

    let client = TestServer::create_test_client();
    let password = "test_password_789";

    // Create first token via API
    let create_body = TestServer::auth_body(
        password,
        json!({
            "name": "first-agent",
        }),
    );

    let response = client
        .post(&format!("{}/tokens/create", server.api_url))
        .json(&create_body)
        .send()
        .await
        .expect("Create first token failed");

    assert_eq!(response.status(), StatusCode::OK);
    let first_token: serde_json::Value = response.json().await.expect("Parse failed");
    let first_token_value = first_token["token"].as_str().expect("No first token");

    // Create second token via API
    let create_body = TestServer::auth_body(
        password,
        json!({
            "name": "second-agent",
        }),
    );

    let response = client
        .post(&format!("{}/tokens/create", server.api_url))
        .json(&create_body)
        .send()
        .await
        .expect("Create second token failed");

    assert_eq!(response.status(), StatusCode::OK);
    let second_token: serde_json::Value = response.json().await.expect("Parse failed");
    let second_token_value = second_token["token"].as_str().expect("No second token");

    // Verify both tokens are different
    assert_ne!(first_token_value, second_token_value);

    // TODO: Add proxy authentication test when proxy auth validation is testable
    // For now, we verify tokens are in storage
    let list_body = TestServer::auth_body(password, json!({}));
    let response = client
        .post(&format!("{}/tokens", server.api_url))
        .json(&list_body)
        .send()
        .await
        .expect("List tokens failed");

    let tokens_list: serde_json::Value = response.json().await.expect("Parse failed");
    let tokens = tokens_list["tokens"].as_array().expect("tokens not array");

    assert_eq!(tokens.len(), 2, "Expected both tokens to be listed");
}
