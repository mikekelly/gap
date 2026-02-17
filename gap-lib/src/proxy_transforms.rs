//! Proxy HTTP transformation utilities
//!
//! Handles HTTP parsing and plugin transform execution for the proxy.

use crate::error::{GapError, Result};
use crate::http_utils::{parse_http_request, serialize_http_request};
use crate::plugin_matcher::find_matching_plugin;
use crate::plugin_runtime::PluginRuntime;
use crate::registry::Registry;
use crate::storage::SecretStore;
use crate::types::{GAPCredentials, GAPRequest};
use tracing::{debug, warn};

/// Load all credential fields for a plugin from Registry
///
/// Credentials are now stored directly in the registry as a nested HashMap.
/// No separate storage lookups needed.
async fn load_plugin_credentials<S: SecretStore + ?Sized>(
    plugin_name: &str,
    _store: &S,
    registry: &Registry,
) -> Result<GAPCredentials> {
    let mut credentials = GAPCredentials::new();

    // Get credentials directly from registry (they're stored there now)
    if let Some(plugin_creds) = registry.get_plugin_credentials(plugin_name).await? {
        for (field, value) in plugin_creds {
            credentials.set(&field, &value);
        }
    }

    Ok(credentials)
}

/// Apply plugin transforms to a GAPRequest
///
/// This is the core transformation logic: plugin lookup, credential loading,
/// and JS transform execution. Used by both the legacy byte-based pipeline
/// and the new hyper-based pipeline.
///
/// CRITICAL: PluginRuntime is not Send - this function scopes the runtime
/// in a sync block to ensure it is dropped before any `.await` points.
pub async fn transform_request<S: SecretStore + ?Sized>(
    request: GAPRequest,
    hostname: &str,
    store: &S,
    registry: &Registry,
) -> Result<GAPRequest> {
    // Find matching plugin
    // SECURITY: Only allow connections to hosts with registered plugins
    let plugin = match find_matching_plugin(hostname, store, registry).await? {
        Some(p) => {
            debug!("Found matching plugin: {}", p.name);
            p
        }
        None => {
            warn!("BLOCKED: Host {} has no matching plugin - not allowed", hostname);
            return Err(GapError::auth(format!(
                "Host '{}' is not allowed: no plugin registered for this host",
                hostname
            )));
        }
    };

    // Load credentials for the plugin
    let credentials = load_plugin_credentials(&plugin.name, store, registry).await?;

    // SECURITY: Only allow connections when credentials are configured
    if credentials.credentials.is_empty() {
        warn!(
            "BLOCKED: Plugin {} has no credentials configured - not allowed",
            plugin.name
        );
        return Err(GapError::auth(format!(
            "Host '{}' is not allowed: plugin '{}' has no credentials configured",
            hostname, plugin.name
        )));
    }

    debug!("Loaded {} credential fields for plugin {}", credentials.credentials.len(), plugin.name);

    // Load plugin code from storage
    let plugin_key = format!("plugin:{}", plugin.name);
    let plugin_code_bytes = store.get(&plugin_key).await?
        .ok_or_else(|| GapError::plugin(format!("Plugin code not found for {}", plugin.name)))?;
    let plugin_code = String::from_utf8(plugin_code_bytes)
        .map_err(|e| GapError::plugin(format!("Invalid UTF-8 in plugin code: {}", e)))?;

    // Execute transform
    // CRITICAL: Scope the PluginRuntime to ensure it's dropped before any await
    let transformed_request = {
        let mut runtime = PluginRuntime::new()?;
        runtime.load_plugin_from_code(&plugin.name, &plugin_code)?;
        runtime.execute_transform(&plugin.name, request, &credentials)?
    };

    debug!("Transform executed successfully");

    Ok(transformed_request)
}

/// Parse HTTP request bytes and apply plugin transforms
///
/// Thin wrapper around `transform_request` that handles parse/serialize.
/// CRITICAL: PluginRuntime is not Send - this function is scoped to ensure
/// the runtime is dropped before any `.await` points.
pub async fn parse_and_transform<S: SecretStore + ?Sized>(
    request_bytes: &[u8],
    hostname: &str,
    store: &S,
    registry: &Registry,
) -> Result<Vec<u8>> {
    // Parse HTTP request
    let request = parse_http_request(request_bytes)?;
    debug!("Parsed HTTP request: {} {}", request.method, request.url);

    // Apply transforms
    let transformed_request = transform_request(request, hostname, store, registry).await?;

    // Serialize back to HTTP
    let transformed_bytes = serialize_http_request(&transformed_request)?;

    Ok(transformed_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{PluginEntry, Registry};
    use crate::storage::FileStore;
    use crate::types::GAPRequest;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_load_plugin_credentials_uses_registry() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = Arc::new(
            FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore"),
        ) as Arc<dyn SecretStore>;
        let registry = Registry::new(Arc::clone(&store));

        // Set credentials with actual values directly in registry
        registry
            .set_credential("exa", "api_key", "test-api-key-value")
            .await
            .expect("set credential");
        registry
            .set_credential("exa", "secret", "test-secret-value")
            .await
            .expect("set credential");

        // Load credentials using the new Registry-based approach
        let credentials = load_plugin_credentials("exa", &*store, &registry)
            .await
            .expect("load credentials");

        assert_eq!(credentials.credentials.len(), 2);
        assert_eq!(credentials.get("api_key"), Some(&"test-api-key-value".to_string()));
        assert_eq!(credentials.get("secret"), Some(&"test-secret-value".to_string()));
    }

    /// Helper to set up a plugin + credentials in registry/store for testing
    async fn setup_test_plugin(
        store: &Arc<dyn SecretStore>,
        registry: &Registry,
    ) {
        let plugin_code = r#"
        var plugin = {
            name: "test-api",
            matchPatterns: ["api.test.com"],
            credentialSchema: ["api_key"],
            transform: function(request, credentials) {
                request.headers["Authorization"] = "Bearer " + credentials.api_key;
                return request;
            }
        };
        "#;
        store.set("plugin:test-api", plugin_code.as_bytes()).await.unwrap();
        let plugin_entry = PluginEntry {
            name: "test-api".to_string(),
            hosts: vec!["api.test.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
        };
        registry.add_plugin(&plugin_entry).await.unwrap();
        registry.set_credential("test-api", "api_key", "secret-key-123").await.unwrap();
    }

    #[tokio::test]
    async fn test_transform_request_applies_plugin() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = Arc::new(
            FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore"),
        ) as Arc<dyn SecretStore>;
        let registry = Registry::new(Arc::clone(&store));
        setup_test_plugin(&store, &registry).await;

        let request = GAPRequest::new("GET", "https://api.test.com/data")
            .with_header("Host", "api.test.com");

        let result = transform_request(request, "api.test.com", &*store, &registry)
            .await
            .expect("transform should succeed");

        // Plugin should have added Authorization header
        assert_eq!(
            result.get_header("Authorization"),
            Some(&"Bearer secret-key-123".to_string())
        );
        // Method and URL should be preserved
        assert_eq!(result.method, "GET");
        assert_eq!(result.url, "https://api.test.com/data");
    }

    #[tokio::test]
    async fn test_transform_request_rejects_unregistered_host() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = Arc::new(
            FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore"),
        ) as Arc<dyn SecretStore>;
        let registry = Registry::new(Arc::clone(&store));

        let request = GAPRequest::new("GET", "https://evil.com/data")
            .with_header("Host", "evil.com");

        let result = transform_request(request, "evil.com", &*store, &registry).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not allowed"));
    }

    #[tokio::test]
    async fn test_transform_request_rejects_missing_credentials() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = Arc::new(
            FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore"),
        ) as Arc<dyn SecretStore>;
        let registry = Registry::new(Arc::clone(&store));

        // Add plugin but NO credentials
        let plugin_code = r#"
        var plugin = {
            name: "no-creds",
            matchPatterns: ["api.nocreds.com"],
            credentialSchema: ["api_key"],
            transform: function(request, credentials) { return request; }
        };
        "#;
        store.set("plugin:no-creds", plugin_code.as_bytes()).await.unwrap();
        let plugin_entry = PluginEntry {
            name: "no-creds".to_string(),
            hosts: vec!["api.nocreds.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
        };
        registry.add_plugin(&plugin_entry).await.unwrap();

        let request = GAPRequest::new("GET", "https://api.nocreds.com/data")
            .with_header("Host", "api.nocreds.com");

        let result = transform_request(request, "api.nocreds.com", &*store, &registry).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("credentials"));
    }

    #[tokio::test]
    async fn test_parse_and_transform_delegates_to_transform_request() {
        // Verify that parse_and_transform produces the same result as
        // parse -> transform_request -> serialize
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = Arc::new(
            FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore"),
        ) as Arc<dyn SecretStore>;
        let registry = Registry::new(Arc::clone(&store));
        setup_test_plugin(&store, &registry).await;

        let raw_http = b"GET /data HTTP/1.1\r\nHost: api.test.com\r\n\r\n";

        let result = parse_and_transform(raw_http, "api.test.com", &*store, &registry)
            .await
            .expect("parse_and_transform should succeed");

        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("Authorization: Bearer secret-key-123"));
    }
}
