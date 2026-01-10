//! Proxy HTTP transformation utilities
//!
//! Handles HTTP parsing and plugin transform execution for the proxy.

use crate::error::{AcpError, Result};
use crate::http_utils::{parse_http_request, serialize_http_request};
use crate::plugin_matcher::find_matching_plugin;
use crate::plugin_runtime::PluginRuntime;
use crate::storage::SecretStore;
use crate::types::ACPCredentials;
use tracing::{debug, warn};

/// Load all credential fields for a plugin from storage
///
/// Credentials are stored as credential:{plugin}:{field_name}
/// This function lists all keys and filters by the plugin name prefix
async fn load_plugin_credentials<S: SecretStore + ?Sized>(
    plugin_name: &str,
    store: &S,
) -> Result<ACPCredentials> {
    let prefix = format!("credential:{}:", plugin_name);
    let mut credentials = ACPCredentials::new();

    // List all keys with the plugin prefix
    let matching_keys = store.list(&prefix).await?;
    for key in matching_keys {
        if let Some(field_name) = key.strip_prefix(&prefix) {
            // Load the credential value
            if let Some(value_bytes) = store.get(&key).await? {
                let value = String::from_utf8(value_bytes)
                    .map_err(|e| AcpError::storage(format!("Invalid UTF-8 in credential {}: {}", key, e)))?;
                credentials.set(field_name, &value);
            }
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
) -> Result<Vec<u8>> {
    // Parse HTTP request
    let request = parse_http_request(request_bytes)?;
    debug!("Parsed HTTP request: {} {}", request.method, request.url);

    // Find matching plugin
    let plugin = match find_matching_plugin(hostname, store).await? {
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
    let credentials = load_plugin_credentials(&plugin.name, store).await?;

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
