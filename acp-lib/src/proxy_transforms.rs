//! Proxy HTTP transformation utilities
//!
//! Handles HTTP parsing and plugin transform execution for the proxy.

use crate::error::{AcpError, Result};
use crate::http_utils::{parse_http_request, serialize_http_request};
use crate::plugin_matcher::find_matching_plugin;
use crate::plugin_runtime::PluginRuntime;
use crate::registry::Registry;
use crate::storage::SecretStore;
use crate::types::ACPCredentials;
use tracing::{debug, warn};

/// Load all credential fields for a plugin from Registry
///
/// Credentials are now stored directly in the registry as a nested HashMap.
/// No separate storage lookups needed.
async fn load_plugin_credentials<S: SecretStore + ?Sized>(
    plugin_name: &str,
    _store: &S,
    registry: &Registry,
) -> Result<ACPCredentials> {
    let mut credentials = ACPCredentials::new();

    // Get credentials directly from registry (they're stored there now)
    if let Some(plugin_creds) = registry.get_plugin_credentials(plugin_name).await? {
        for (field, value) in plugin_creds {
            credentials.set(&field, &value);
        }
    }

    Ok(credentials)
}

/// Parse HTTP request and apply plugin transforms
///
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

    // Find matching plugin
    let plugin = match find_matching_plugin(hostname, store, registry).await? {
        Some(p) => {
            debug!("Found matching plugin: {}", p.name);
            p
        }
        None => {
            debug!("No plugin match for {}, passing through", hostname);
            // No plugin, return original bytes
            return Ok(request_bytes.to_vec());
        }
    };

    // Load credentials for the plugin
    // The API stores credentials as credential:{plugin}:{field_name}
    // We need to load all fields and build a credentials object
    let credentials = load_plugin_credentials(&plugin.name, store, registry).await?;

    if credentials.credentials.is_empty() {
        warn!(
            "No credentials found for plugin {}, passing through",
            plugin.name
        );
        // No credentials, return original bytes
        return Ok(request_bytes.to_vec());
    }

    debug!("Loaded {} credential fields for plugin {}", credentials.credentials.len(), plugin.name);

    // Load plugin code from storage
    let plugin_key = format!("plugin:{}", plugin.name);
    let plugin_code_bytes = store.get(&plugin_key).await?
        .ok_or_else(|| AcpError::plugin(format!("Plugin code not found for {}", plugin.name)))?;
    let plugin_code = String::from_utf8(plugin_code_bytes)
        .map_err(|e| AcpError::plugin(format!("Invalid UTF-8 in plugin code: {}", e)))?;

    // Execute transform
    // CRITICAL: Scope the PluginRuntime to ensure it's dropped before any await
    let transformed_request = {
        let mut runtime = PluginRuntime::new()?;
        runtime.load_plugin_from_code(&plugin.name, &plugin_code)?;
        runtime.execute_transform(&plugin.name, request, &credentials)?
    };

    debug!("Transform executed successfully");

    // Serialize back to HTTP
    let transformed_bytes = serialize_http_request(&transformed_request)?;

    Ok(transformed_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{CredentialEntry, Registry};
    use crate::storage::FileStore;
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
}
