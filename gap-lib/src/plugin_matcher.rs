//! Plugin matching utilities
//!
//! Provides functions to find plugins and header sets that match a given
//! host, port, and path.  Both entity types participate in the same
//! weight-based priority system via `find_matching_handler`.

use crate::database::GapDatabase;
use crate::error::Result;
use crate::plugin_runtime::PluginRuntime;
use crate::types::{GAPPlugin, HeaderSet};
use chrono::{DateTime, Utc};

/// Result of `find_matching_handler` — either a JS plugin or a static header set.
#[derive(Debug)]
pub enum MatchResult {
    Plugin(GAPPlugin),
    HeaderSet(HeaderSet),
}

/// Check if a host pattern matches a given host (single-level wildcard).
///
/// Supports exact matches and `*.example.com` patterns that match a single
/// subdomain level only.
pub fn matches_host_pattern(pattern: &str, host: &str) -> bool {
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

/// Matches a pattern against host, port, and path.
///
/// Pattern format: `host[:port][/path[*]]`
/// - Port is optional; if absent, matches any port
/// - Path is optional; if absent, matches all paths
/// - Trailing `*` in path means prefix match; otherwise exact
/// - Host supports `*.example.com` single-level wildcard (existing behavior)
pub fn matches_host_path_pattern(pattern: &str, host: &str, port: Option<u16>, path: &str) -> bool {
    // Split pattern on first `/` -> host_port_part + optional path_part
    let (host_port_part, path_part) = match pattern.find('/') {
        Some(idx) => (&pattern[..idx], Some(&pattern[idx..])),
        None => (pattern, None),
    };

    // Parse host_port_part: if contains `:`, split into pattern_host + pattern_port
    let (pattern_host, pattern_port) = if let Some(colon_idx) = host_port_part.rfind(':') {
        // Only treat as port if what follows the colon parses as u16
        // (avoids misparse of IPv6 or wildcard patterns containing colons)
        let potential_port = &host_port_part[colon_idx + 1..];
        if let Ok(p) = potential_port.parse::<u16>() {
            (&host_port_part[..colon_idx], Some(p))
        } else {
            (host_port_part, None)
        }
    } else {
        (host_port_part, None)
    };

    // 1. Match host
    if !matches_host_pattern(pattern_host, host) {
        return false;
    }

    // 2. Match port (if pattern specifies one)
    if let Some(pp) = pattern_port {
        match port {
            Some(rp) if rp == pp => {}
            _ => return false,
        }
    }

    // 3. Match path
    if let Some(path_part) = path_part {
        if path_part.ends_with('*') {
            let prefix = &path_part[..path_part.len() - 1];
            if !path.starts_with(prefix) {
                return false;
            }
        } else if path != path_part {
            return false;
        }
    }

    true
}

/// Candidate used internally for sorting during handler selection.
struct MatchCandidate {
    weight: i32,
    timestamp: DateTime<Utc>,
    kind: CandidateKind,
}

enum CandidateKind {
    Plugin { name: String, entry: crate::types::PluginEntry },
    HeaderSet(HeaderSet),
}

/// Find the highest-priority handler (plugin or header set) for a request.
///
/// Both plugins and header sets participate in the same priority system:
/// highest weight wins, oldest timestamp breaks ties.
///
/// Only the winning plugin's source code is loaded from the database.
pub async fn find_matching_handler(
    host: &str,
    port: Option<u16>,
    path: &str,
    db: &GapDatabase,
) -> Result<Option<MatchResult>> {
    let plugin_entries = db.list_plugins().await?;
    let header_sets = db.list_header_sets().await?;

    let mut candidates: Vec<MatchCandidate> = Vec::new();

    // Collect matching plugin entries (metadata only, no source load)
    for entry in plugin_entries {
        let host_matches = entry
            .hosts
            .iter()
            .any(|pattern| matches_host_path_pattern(pattern, host, port, path));
        if host_matches {
            candidates.push(MatchCandidate {
                weight: entry.weight,
                timestamp: entry.installed_at.unwrap_or_else(Utc::now),
                kind: CandidateKind::Plugin {
                    name: entry.name.clone(),
                    entry,
                },
            });
        }
    }

    // Collect matching header sets
    for hs in header_sets {
        let hs_matches = hs
            .match_patterns
            .iter()
            .any(|pattern| matches_host_path_pattern(pattern, host, port, path));
        if hs_matches {
            candidates.push(MatchCandidate {
                weight: hs.weight,
                timestamp: hs.created_at,
                kind: CandidateKind::HeaderSet(hs),
            });
        }
    }

    if candidates.is_empty() {
        return Ok(None);
    }

    // Sort: highest weight first, then oldest timestamp first (tiebreaker)
    candidates.sort_by(|a, b| {
        b.weight
            .cmp(&a.weight)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    });

    // Take the winner and materialise the full result
    let winner = candidates.into_iter().next().unwrap();
    match winner.kind {
        CandidateKind::Plugin { name, entry } => {
            // Load plugin source only for the winner
            let plugin_code = db.get_plugin_source(&name).await?;
            if let Some(code) = plugin_code {
                let mut runtime = PluginRuntime::new()?;
                if let Ok(mut plugin) = runtime.load_plugin_from_code(&name, &code) {
                    plugin.commit_sha = entry.commit_sha.clone();
                    plugin.dangerously_permit_http = entry.dangerously_permit_http;
                    plugin.weight = entry.weight;
                    return Ok(Some(MatchResult::Plugin(plugin)));
                }
            }
            Ok(None)
        }
        CandidateKind::HeaderSet(hs) => Ok(Some(MatchResult::HeaderSet(hs))),
    }
}

/// Find a plugin that matches the given host.
///
/// Thin wrapper around `find_matching_handler` for backwards compatibility.
/// Only returns Plugin matches, ignoring header sets.
pub async fn find_matching_plugin(
    host: &str,
    db: &GapDatabase,
) -> Result<Option<GAPPlugin>> {
    match find_matching_handler(host, None, "/", db).await? {
        Some(MatchResult::Plugin(p)) => Ok(Some(p)),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::GapDatabase;
    use crate::types::PluginEntry;

    // ── matches_host_pattern tests ──────────────────────────────────

    #[test]
    fn test_matches_host_pattern_exact() {
        assert!(matches_host_pattern("api.example.com", "api.example.com"));
        assert!(!matches_host_pattern("api.example.com", "other.example.com"));
        assert!(!matches_host_pattern("api.example.com", "api.other.com"));
    }

    #[test]
    fn test_matches_host_pattern_wildcard() {
        assert!(matches_host_pattern("*.example.com", "api.example.com"));
        assert!(matches_host_pattern("*.example.com", "foo.example.com"));
        assert!(!matches_host_pattern("*.example.com", "example.com"));
        assert!(!matches_host_pattern("*.example.com", "a.b.example.com"));
        assert!(!matches_host_pattern("*.example.com", "evil.com.example.com"));
        assert!(!matches_host_pattern("*.example.com", "api.other.com"));
    }

    #[test]
    fn test_matches_host_pattern_wildcard_edge_cases() {
        assert!(!matches_host_pattern("*.example.com", ".example.com"));
        assert!(matches_host_pattern("*.s3.amazonaws.com", "bucket.s3.amazonaws.com"));
        assert!(!matches_host_pattern("*.s3.amazonaws.com", "s3.amazonaws.com"));
    }

    // ── matches_host_path_pattern tests ─────────────────────────────

    #[test]
    fn test_matches_host_path_pattern_basic() {
        // Host-only pattern matches any path
        assert!(matches_host_path_pattern("api.example.com", "api.example.com", None, "/"));
        assert!(matches_host_path_pattern("api.example.com", "api.example.com", None, "/v1/chat"));
        assert!(!matches_host_path_pattern("api.example.com", "other.com", None, "/"));

        // Host + exact path
        assert!(matches_host_path_pattern("api.example.com/v1/chat", "api.example.com", None, "/v1/chat"));
        assert!(!matches_host_path_pattern("api.example.com/v1/chat", "api.example.com", None, "/v1/other"));
        assert!(!matches_host_path_pattern("api.example.com/v1/chat", "api.example.com", None, "/v1/chat/extra"));

        // Host + path prefix wildcard
        assert!(matches_host_path_pattern("api.example.com/v1/*", "api.example.com", None, "/v1/chat"));
        assert!(matches_host_path_pattern("api.example.com/v1/*", "api.example.com", None, "/v1/completions"));
        assert!(matches_host_path_pattern("api.example.com/v1/*", "api.example.com", None, "/v1/"));
        assert!(!matches_host_path_pattern("api.example.com/v1/*", "api.example.com", None, "/v2/chat"));
    }

    #[test]
    fn test_matches_host_path_pattern_port() {
        // With port: only matches if request port matches
        assert!(matches_host_path_pattern("api.example.com:8080", "api.example.com", Some(8080), "/"));
        assert!(!matches_host_path_pattern("api.example.com:8080", "api.example.com", Some(443), "/"));
        assert!(!matches_host_path_pattern("api.example.com:8080", "api.example.com", None, "/"));

        // Without port in pattern: matches any port
        assert!(matches_host_path_pattern("api.example.com", "api.example.com", Some(443), "/"));
        assert!(matches_host_path_pattern("api.example.com", "api.example.com", Some(8080), "/"));
        assert!(matches_host_path_pattern("api.example.com", "api.example.com", None, "/"));

        // Port + path combined
        assert!(matches_host_path_pattern("api.example.com:443/v1/*", "api.example.com", Some(443), "/v1/chat"));
        assert!(!matches_host_path_pattern("api.example.com:443/v1/*", "api.example.com", Some(8080), "/v1/chat"));
    }

    #[test]
    fn test_matches_host_path_pattern_wildcard_host() {
        // Wildcard host + path
        assert!(matches_host_path_pattern("*.example.com/api/*", "sub.example.com", None, "/api/data"));
        assert!(!matches_host_path_pattern("*.example.com/api/*", "example.com", None, "/api/data"));
        assert!(!matches_host_path_pattern("*.example.com/api/*", "sub.example.com", None, "/other/data"));
    }

    // ── find_matching_plugin (backwards compat wrapper) tests ────────

    #[tokio::test]
    async fn test_find_matching_plugin_exact_match() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin_code = r#"
        var plugin = {
            name: "test",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;

        let entry = PluginEntry {
            name: "test".to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&entry, plugin_code).await.unwrap();

        let result = find_matching_plugin("api.example.com", &db).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "test");
    }

    #[tokio::test]
    async fn test_find_matching_plugin_wildcard() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin_code = r#"
        var plugin = {
            name: "s3",
            matchPatterns: ["*.s3.amazonaws.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;

        let entry = PluginEntry {
            name: "s3".to_string(),
            hosts: vec!["*.s3.amazonaws.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&entry, plugin_code).await.unwrap();

        let result = find_matching_plugin("bucket.s3.amazonaws.com", &db).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "s3");
    }

    #[tokio::test]
    async fn test_find_matching_plugin_no_match() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin_code = r#"
        var plugin = {
            name: "test",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;

        let entry = PluginEntry {
            name: "test".to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&entry, plugin_code).await.unwrap();

        let result = find_matching_plugin("api.other.com", &db).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_matches_using_registry_hosts_not_js() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry1 = PluginEntry {
            name: "nomatch1".to_string(),
            hosts: vec!["api.other.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        };
        let invalid_code = "THIS IS NOT VALID JAVASCRIPT!!! { syntax error }";
        db.add_plugin(&entry1, invalid_code).await.unwrap();

        let entry2 = PluginEntry {
            name: "nomatch2".to_string(),
            hosts: vec!["api.another.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&entry2, invalid_code).await.unwrap();

        let valid_code = r#"
        var plugin = {
            name: "match",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;
        let entry3 = PluginEntry {
            name: "match".to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&entry3, valid_code).await.unwrap();

        let result = find_matching_plugin("api.example.com", &db).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "match");
    }

    // ── find_matching_handler tests ─────────────────────────────────

    #[tokio::test]
    async fn test_find_matching_handler_weight_priority() {
        // Plugin weight=10 vs header_set weight=5 -> plugin wins
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin_code = r#"
        var plugin = {
            name: "high-weight",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;
        let entry = PluginEntry {
            name: "high-weight".to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 10,
            installed_at: None,
        };
        db.add_plugin(&entry, plugin_code).await.unwrap();

        db.add_header_set("low-weight-hs", &["api.example.com".to_string()], 5)
            .await
            .unwrap();

        let result = find_matching_handler("api.example.com", None, "/", &db)
            .await
            .unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            MatchResult::Plugin(p) => assert_eq!(p.name, "high-weight"),
            MatchResult::HeaderSet(_) => panic!("Expected Plugin, got HeaderSet"),
        }
    }

    #[tokio::test]
    async fn test_find_matching_handler_timestamp_tiebreak() {
        // Same weight, oldest wins — header set created first should win
        let db = GapDatabase::in_memory().await.unwrap();

        // Header set created first (will have an earlier timestamp)
        db.add_header_set("older-hs", &["api.example.com".to_string()], 5)
            .await
            .unwrap();

        // Small delay to ensure different timestamps
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let plugin_code = r#"
        var plugin = {
            name: "newer-plugin",
            matchPatterns: ["api.example.com"],
            credentialSchema: [],
            transform: function(request, credentials) { return request; }
        };
        "#;
        let entry = PluginEntry {
            name: "newer-plugin".to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 5,
            installed_at: None,
        };
        db.add_plugin(&entry, plugin_code).await.unwrap();

        let result = find_matching_handler("api.example.com", None, "/", &db)
            .await
            .unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            MatchResult::HeaderSet(hs) => assert_eq!(hs.name, "older-hs"),
            MatchResult::Plugin(_) => panic!("Expected HeaderSet (older), got Plugin"),
        }
    }

    #[tokio::test]
    async fn test_find_matching_handler_header_set() {
        // Header set matches, no plugins
        let db = GapDatabase::in_memory().await.unwrap();

        db.add_header_set("my-hs", &["api.example.com".to_string()], 0)
            .await
            .unwrap();

        let result = find_matching_handler("api.example.com", None, "/", &db)
            .await
            .unwrap();
        assert!(result.is_some());
        match result.unwrap() {
            MatchResult::HeaderSet(hs) => assert_eq!(hs.name, "my-hs"),
            MatchResult::Plugin(_) => panic!("Expected HeaderSet, got Plugin"),
        }

        // Non-matching host returns None
        let result = find_matching_handler("other.com", None, "/", &db)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_find_matching_handler_path_matching() {
        // Test that path patterns work in find_matching_handler
        let db = GapDatabase::in_memory().await.unwrap();

        db.add_header_set("specific-path", &["api.example.com/v1/chat".to_string()], 10)
            .await
            .unwrap();
        db.add_header_set("wildcard-path", &["api.example.com/v1/*".to_string()], 5)
            .await
            .unwrap();

        // Exact path match wins (higher weight)
        let result = find_matching_handler("api.example.com", None, "/v1/chat", &db)
            .await
            .unwrap();
        match result.unwrap() {
            MatchResult::HeaderSet(hs) => assert_eq!(hs.name, "specific-path"),
            _ => panic!("Expected specific-path HeaderSet"),
        }

        // Wildcard match for different path
        let result = find_matching_handler("api.example.com", None, "/v1/completions", &db)
            .await
            .unwrap();
        match result.unwrap() {
            MatchResult::HeaderSet(hs) => assert_eq!(hs.name, "wildcard-path"),
            _ => panic!("Expected wildcard-path HeaderSet"),
        }

        // No match for unrelated path
        let result = find_matching_handler("api.example.com", None, "/v2/chat", &db)
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
