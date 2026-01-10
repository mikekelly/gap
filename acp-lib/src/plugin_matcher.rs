//! Plugin matching utilities
//!
//! Provides functions to find plugins that match a given host.

use crate::error::Result;
use crate::plugin_runtime::PluginRuntime;
use crate::storage::SecretStore;
use crate::types::ACPPlugin;

/// Find a plugin that matches the given host
///
/// Loads all plugins from storage and checks their match patterns.
/// Returns the first matching plugin, or None if no match is found.
///
/// # Arguments
/// * `host` - The hostname to match against (e.g., "api.example.com")
/// * `store` - SecretStore to load plugins from
///
/// # Returns
/// Option containing the matching plugin, or None
pub async fn find_matching_plugin<S: SecretStore>(
    host: &str,
    store: &S,
) -> Result<Option<ACPPlugin>> {
    // List all plugin keys (pattern: "plugin:*")
    let all_keys = store.list("plugin:").await?;
    let plugin_keys: Vec<String> = all_keys
        .into_iter()
        .filter(|k| k.starts_with("plugin:"))
        .collect();

    // Load and check each plugin
    for key in plugin_keys {
        // Extract plugin name from key (remove "plugin:" prefix)
        let plugin_name = &key[7..];

        // Load plugin metadata (don't need to execute it yet)
        let plugin_code = store.get(&key).await?;
        if let Some(code_bytes) = plugin_code {
            let code = String::from_utf8_lossy(&code_bytes);

            // Create a runtime to extract metadata
            let mut runtime = PluginRuntime::new()?;
            if let Ok(plugin) = runtime.load_plugin_from_code(plugin_name, &code) {
                // Check if this plugin matches the host
                if plugin.matches_host(host) {
                    return Ok(Some(plugin));
                }
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::FileStore;

    #[tokio::test]
    async fn test_find_matching_plugin_exact_match() {
        let temp_dir = std::env::temp_dir().join(format!(
            "acp_matcher_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let store = FileStore::new(temp_dir.clone()).await.unwrap();

        let plugin_code = r#"
        var plugin = {
            name: "test",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;

        store.set("plugin:test", plugin_code.as_bytes()).await.unwrap();

        let result = find_matching_plugin("api.example.com", &store).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "test");

        tokio::fs::remove_dir_all(temp_dir).await.ok();
    }

    #[tokio::test]
    async fn test_find_matching_plugin_wildcard() {
        let temp_dir = std::env::temp_dir().join(format!(
            "acp_matcher_wildcard_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let store = FileStore::new(temp_dir.clone()).await.unwrap();

        let plugin_code = r#"
        var plugin = {
            name: "s3",
            matchPatterns: ["*.s3.amazonaws.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;

        store.set("plugin:s3", plugin_code.as_bytes()).await.unwrap();

        let result = find_matching_plugin("bucket.s3.amazonaws.com", &store).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "s3");

        tokio::fs::remove_dir_all(temp_dir).await.ok();
    }

    #[tokio::test]
    async fn test_find_matching_plugin_no_match() {
        let temp_dir = std::env::temp_dir().join(format!(
            "acp_matcher_nomatch_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let store = FileStore::new(temp_dir.clone()).await.unwrap();

        let plugin_code = r#"
        var plugin = {
            name: "test",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;

        store.set("plugin:test", plugin_code.as_bytes()).await.unwrap();

        let result = find_matching_plugin("api.other.com", &store).await.unwrap();
        assert!(result.is_none());

        tokio::fs::remove_dir_all(temp_dir).await.ok();
    }
}
