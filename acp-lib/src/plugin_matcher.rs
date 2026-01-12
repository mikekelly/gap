//! Plugin matching utilities
//!
//! Provides functions to find plugins that match a given host.

use crate::error::Result;
use crate::plugin_runtime::PluginRuntime;
use crate::registry::Registry;
use crate::storage::SecretStore;
use crate::types::ACPPlugin;

/// Check if a host pattern matches a given host
///
/// Supports exact matches and single-level wildcard patterns (*.example.com).
///
/// # Arguments
/// * `pattern` - The pattern to match against (e.g., "api.example.com" or "*.s3.amazonaws.com")
/// * `host` - The hostname to check
///
/// # Returns
/// true if the pattern matches the host
fn matches_host_pattern(pattern: &str, host: &str) -> bool {
    if pattern.starts_with("*.") {
        // Wildcard match: *.example.com matches foo.example.com but not evil.com.example.com
        let suffix = &pattern[1..]; // Remove leading * to get .example.com

        if !host.ends_with(suffix) || host.len() <= suffix.len() {
            return false;
        }

        // Extract the subdomain part before the suffix
        let subdomain = &host[..host.len() - suffix.len()];

        // Subdomain should not contain dots (only single-level wildcard)
        !subdomain.contains('.')
    } else {
        // Exact match
        host == pattern
    }
}

/// Find a plugin that matches the given host
///
/// Uses the Registry to check plugin host patterns, then loads only the matched plugin code.
/// Returns the first matching plugin, or None if no match is found.
///
/// # Arguments
/// * `host` - The hostname to match against (e.g., "api.example.com")
/// * `store` - SecretStore to load plugin code from
/// * `registry` - Registry to list available plugins
///
/// # Returns
/// Option containing the matching plugin, or None
pub async fn find_matching_plugin<S: SecretStore + ?Sized>(
    host: &str,
    store: &S,
    registry: &Registry,
) -> Result<Option<ACPPlugin>> {
    // Get all plugin entries from registry
    let plugin_entries = registry.list_plugins().await?;

    // Find first plugin whose host patterns match (cheap string matching)
    for entry in plugin_entries {
        // Check if any of this plugin's host patterns match
        let host_matches = entry.hosts.iter().any(|pattern| matches_host_pattern(pattern, host));

        if host_matches {
            // Only NOW load the plugin code from storage
            let key = format!("plugin:{}", entry.name);
            let plugin_code = store.get(&key).await?;

            if let Some(code_bytes) = plugin_code {
                let code = String::from_utf8_lossy(&code_bytes);

                // Create a runtime and load the plugin
                let mut runtime = PluginRuntime::new()?;
                if let Ok(plugin) = runtime.load_plugin_from_code(&entry.name, &code) {
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
    use crate::registry::{PluginEntry, Registry};
    use crate::storage::FileStore;
    use std::sync::Arc;

    // Test the host pattern matching logic
    #[test]
    fn test_matches_host_pattern_exact() {
        assert!(matches_host_pattern("api.example.com", "api.example.com"));
        assert!(!matches_host_pattern("api.example.com", "other.example.com"));
        assert!(!matches_host_pattern("api.example.com", "api.other.com"));
    }

    #[test]
    fn test_matches_host_pattern_wildcard() {
        // Single-level wildcard should match
        assert!(matches_host_pattern("*.example.com", "api.example.com"));
        assert!(matches_host_pattern("*.example.com", "foo.example.com"));

        // Should NOT match base domain (no subdomain)
        assert!(!matches_host_pattern("*.example.com", "example.com"));

        // Should NOT match multi-level subdomains
        assert!(!matches_host_pattern("*.example.com", "a.b.example.com"));
        assert!(!matches_host_pattern("*.example.com", "evil.com.example.com"));

        // Should NOT match different suffix
        assert!(!matches_host_pattern("*.example.com", "api.other.com"));
    }

    #[test]
    fn test_matches_host_pattern_wildcard_edge_cases() {
        // Empty subdomain should not match
        assert!(!matches_host_pattern("*.example.com", ".example.com"));

        // Wildcard pattern edge cases
        assert!(matches_host_pattern("*.s3.amazonaws.com", "bucket.s3.amazonaws.com"));
        assert!(!matches_host_pattern("*.s3.amazonaws.com", "s3.amazonaws.com"));
    }

    #[tokio::test]
    async fn test_find_matching_plugin_exact_match() {
        let temp_dir = std::env::temp_dir().join(format!(
            "acp_matcher_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let store = Arc::new(FileStore::new(temp_dir.clone()).await.unwrap());
        let registry = Registry::new(Arc::clone(&store) as Arc<dyn SecretStore>);

        let plugin_code = r#"
        var plugin = {
            name: "test",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;

        store.set("plugin:test", plugin_code.as_bytes()).await.unwrap();

        // Add to registry
        let entry = PluginEntry {
            name: "test".to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
        };
        registry.add_plugin(&entry).await.unwrap();

        let result = find_matching_plugin("api.example.com", &*store, &registry).await.unwrap();
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

        let store = Arc::new(FileStore::new(temp_dir.clone()).await.unwrap());
        let registry = Registry::new(Arc::clone(&store) as Arc<dyn SecretStore>);

        let plugin_code = r#"
        var plugin = {
            name: "s3",
            matchPatterns: ["*.s3.amazonaws.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;

        store.set("plugin:s3", plugin_code.as_bytes()).await.unwrap();

        // Add to registry
        let entry = PluginEntry {
            name: "s3".to_string(),
            hosts: vec!["*.s3.amazonaws.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
        };
        registry.add_plugin(&entry).await.unwrap();

        let result = find_matching_plugin("bucket.s3.amazonaws.com", &*store, &registry).await.unwrap();
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

        let store = Arc::new(FileStore::new(temp_dir.clone()).await.unwrap());
        let registry = Registry::new(Arc::clone(&store) as Arc<dyn SecretStore>);

        let plugin_code = r#"
        var plugin = {
            name: "test",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;

        store.set("plugin:test", plugin_code.as_bytes()).await.unwrap();

        // Add to registry
        let entry = PluginEntry {
            name: "test".to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
        };
        registry.add_plugin(&entry).await.unwrap();

        let result = find_matching_plugin("api.other.com", &*store, &registry).await.unwrap();
        assert!(result.is_none());

        tokio::fs::remove_dir_all(temp_dir).await.ok();
    }

    #[tokio::test]
    async fn test_matches_using_registry_hosts_not_js() {
        // This test verifies that we use PluginEntry.hosts for matching,
        // not JavaScript execution.
        //
        // Current behavior: loads JS for every plugin to check matches (inefficient)
        // Desired behavior: check PluginEntry.hosts BEFORE loading JS
        //
        // We'll store INVALID JavaScript. If matching happens AFTER we check PluginEntry.hosts,
        // we should still be able to reject non-matches efficiently.
        let temp_dir = std::env::temp_dir().join(format!(
            "acp_matcher_registry_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let store = Arc::new(FileStore::new(temp_dir.clone()).await.unwrap());
        let registry = Registry::new(Arc::clone(&store) as Arc<dyn SecretStore>);

        // Add three plugins with different host patterns
        let entry1 = PluginEntry {
            name: "nomatch1".to_string(),
            hosts: vec!["api.other.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
        };
        registry.add_plugin(&entry1).await.unwrap();

        let entry2 = PluginEntry {
            name: "nomatch2".to_string(),
            hosts: vec!["api.another.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
        };
        registry.add_plugin(&entry2).await.unwrap();

        let entry3 = PluginEntry {
            name: "match".to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
        };
        registry.add_plugin(&entry3).await.unwrap();

        // Store INVALID JavaScript for the non-matching plugins
        // If the matcher loads these, it will fail
        let invalid_code = "THIS IS NOT VALID JAVASCRIPT!!! { syntax error }";
        store.set("plugin:nomatch1", invalid_code.as_bytes()).await.unwrap();
        store.set("plugin:nomatch2", invalid_code.as_bytes()).await.unwrap();

        // Store VALID JavaScript only for the matching plugin
        let valid_code = r#"
        var plugin = {
            name: "match",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;
        store.set("plugin:match", valid_code.as_bytes()).await.unwrap();

        // This should succeed by:
        // 1. Checking PluginEntry.hosts for all three plugins
        // 2. Finding that "match" matches "api.example.com"
        // 3. Loading ONLY "match" plugin code (not the invalid ones)
        // 4. Returning the matched plugin
        //
        // If we load invalid JS code, this test will fail
        let result = find_matching_plugin("api.example.com", &*store, &registry).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "match");

        tokio::fs::remove_dir_all(temp_dir).await.ok();
    }
}
