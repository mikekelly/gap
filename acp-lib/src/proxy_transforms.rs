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

/// Parse HTTP request and apply plugin transforms
///
/// CRITICAL: PluginRuntime is not Send - this function is scoped to ensure
/// the runtime is dropped before any `.await` points.
pub async fn parse_and_transform<S: SecretStore>(
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

    // Load credentials for the plugin (key pattern: credential:{plugin_name}:default)
    let creds_key = format!("credential:{}:default", plugin.name);
    let credentials = match store.get(&creds_key).await? {
        Some(creds_bytes) => {
            let creds: ACPCredentials = serde_json::from_slice(&creds_bytes)
                .map_err(|e| AcpError::storage(format!("Failed to parse credentials: {}", e)))?;
            debug!("Loaded credentials for plugin {}", plugin.name);
            creds
        }
        None => {
            warn!(
                "No credentials found for plugin {}, passing through",
                plugin.name
            );
            // No credentials, return original bytes
            return Ok(request_bytes.to_vec());
        }
    };

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
