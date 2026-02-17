//! Proxy HTTP transformation utilities
//!
//! Handles HTTP parsing and plugin transform execution for the proxy.

use crate::database::GapDatabase;
use crate::error::{GapError, Result};
use crate::http_utils::{parse_http_request, serialize_http_request};
use crate::plugin_matcher::find_matching_plugin;
use crate::plugin_runtime::PluginRuntime;
use crate::types::{GAPCredentials, GAPRequest};
use tracing::{debug, warn};

/// Load all credential fields for a plugin from GapDatabase
///
/// Credentials are stored in the database's credentials table.
async fn load_plugin_credentials(
    plugin_name: &str,
    db: &GapDatabase,
) -> Result<GAPCredentials> {
    let mut credentials = GAPCredentials::new();

    if let Some(plugin_creds) = db.get_plugin_credentials(plugin_name).await? {
        for (field, value) in plugin_creds {
            credentials.set(&field, &value);
        }
    }

    Ok(credentials)
}

/// Plugin info returned alongside the transformed request
#[derive(Debug)]
pub struct PluginInfo {
    pub name: String,
    pub commit_sha: Option<String>,
}

/// Apply plugin transforms to a GAPRequest
///
/// This is the core transformation logic: plugin lookup, credential loading,
/// and JS transform execution. Used by both the legacy byte-based pipeline
/// and the new hyper-based pipeline.
///
/// Returns the transformed request and info about the plugin that handled it.
///
/// CRITICAL: PluginRuntime is not Send - this function scopes the runtime
/// in a sync block to ensure it is dropped before any `.await` points.
pub async fn transform_request(
    request: GAPRequest,
    hostname: &str,
    db: &GapDatabase,
) -> Result<(GAPRequest, PluginInfo)> {
    // Find matching plugin
    // SECURITY: Only allow connections to hosts with registered plugins
    let plugin = match find_matching_plugin(hostname, db).await? {
        Some(p) => {
            debug!(
                "Found matching plugin: {} (sha: {})",
                p.name,
                p.commit_sha.as_deref().unwrap_or("unknown")
            );
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

    let plugin_info = PluginInfo {
        name: plugin.name.clone(),
        commit_sha: plugin.commit_sha.clone(),
    };

    // Load credentials for the plugin
    let credentials = load_plugin_credentials(&plugin.name, db).await?;

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

    // Load plugin code from database
    let plugin_code = db.get_plugin_source(&plugin.name).await?
        .ok_or_else(|| GapError::plugin(format!("Plugin code not found for {}", plugin.name)))?;

    // Execute transform
    // CRITICAL: Scope the PluginRuntime to ensure it's dropped before any await
    let transformed_request = {
        let mut runtime = PluginRuntime::new()?;
        runtime.load_plugin_from_code(&plugin.name, &plugin_code)?;
        runtime.execute_transform(&plugin.name, request, &credentials)?
    };

    debug!("Transform executed successfully");

    Ok((transformed_request, plugin_info))
}

/// Parse HTTP request bytes and apply plugin transforms
///
/// Thin wrapper around `transform_request` that handles parse/serialize.
/// CRITICAL: PluginRuntime is not Send - this function is scoped to ensure
/// the runtime is dropped before any `.await` points.
pub async fn parse_and_transform(
    request_bytes: &[u8],
    hostname: &str,
    db: &GapDatabase,
) -> Result<Vec<u8>> {
    // Parse HTTP request
    let request = parse_http_request(request_bytes)?;
    debug!("Parsed HTTP request: {} {}", request.method, request.url);

    // Apply transforms
    let (transformed_request, _plugin_info) = transform_request(request, hostname, db).await?;

    // Serialize back to HTTP
    let transformed_bytes = serialize_http_request(&transformed_request)?;

    Ok(transformed_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::GapDatabase;
    use crate::types::PluginEntry;
    use crate::types::GAPRequest;

    #[tokio::test]
    async fn test_load_plugin_credentials_uses_database() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Set credentials
        db.set_credential("exa", "api_key", "test-api-key-value")
            .await
            .expect("set credential");
        db.set_credential("exa", "secret", "test-secret-value")
            .await
            .expect("set credential");

        let credentials = load_plugin_credentials("exa", &db)
            .await
            .expect("load credentials");

        assert_eq!(credentials.credentials.len(), 2);
        assert_eq!(credentials.get("api_key"), Some(&"test-api-key-value".to_string()));
        assert_eq!(credentials.get("secret"), Some(&"test-secret-value".to_string()));
    }

    /// Helper to set up a plugin + credentials in database for testing
    async fn setup_test_plugin(db: &GapDatabase) {
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
        let plugin_entry = PluginEntry {
            name: "test-api".to_string(),
            hosts: vec!["api.test.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
        };
        db.add_plugin(&plugin_entry, plugin_code).await.unwrap();
        db.set_credential("test-api", "api_key", "secret-key-123").await.unwrap();
    }

    #[tokio::test]
    async fn test_transform_request_applies_plugin() {
        let db = GapDatabase::in_memory().await.unwrap();
        setup_test_plugin(&db).await;

        let request = GAPRequest::new("GET", "https://api.test.com/data")
            .with_header("Host", "api.test.com");

        let (result, plugin_info) = transform_request(request, "api.test.com", &db)
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
        // Plugin info should be populated
        assert_eq!(plugin_info.name, "test-api");
    }

    #[tokio::test]
    async fn test_transform_request_rejects_unregistered_host() {
        let db = GapDatabase::in_memory().await.unwrap();

        let request = GAPRequest::new("GET", "https://evil.com/data")
            .with_header("Host", "evil.com");

        let result = transform_request(request, "evil.com", &db).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not allowed"));
    }

    #[tokio::test]
    async fn test_transform_request_rejects_missing_credentials() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Add plugin but NO credentials
        let plugin_code = r#"
        var plugin = {
            name: "no-creds",
            matchPatterns: ["api.nocreds.com"],
            credentialSchema: ["api_key"],
            transform: function(request, credentials) { return request; }
        };
        "#;
        let plugin_entry = PluginEntry {
            name: "no-creds".to_string(),
            hosts: vec!["api.nocreds.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
        };
        db.add_plugin(&plugin_entry, plugin_code).await.unwrap();

        let request = GAPRequest::new("GET", "https://api.nocreds.com/data")
            .with_header("Host", "api.nocreds.com");

        let result = transform_request(request, "api.nocreds.com", &db).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("credentials"));
    }

    #[tokio::test]
    async fn test_parse_and_transform_delegates_to_transform_request() {
        let db = GapDatabase::in_memory().await.unwrap();
        setup_test_plugin(&db).await;

        let raw_http = b"GET /data HTTP/1.1\r\nHost: api.test.com\r\n\r\n";

        let result = parse_and_transform(raw_http, "api.test.com", &db)
            .await
            .expect("parse_and_transform should succeed");

        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("Authorization: Bearer secret-key-123"));
    }
}
