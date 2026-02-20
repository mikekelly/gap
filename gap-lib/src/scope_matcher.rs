//! Scope matching for agent tokens
//!
//! Tokens can carry optional scope restrictions — a whitelist of permitted
//! host/path/method patterns.  The functions here enforce those restrictions
//! at two points in the proxy pipeline:
//!
//! 1. **CONNECT phase** (`check_scopes_host`): only host and port are known.
//! 2. **Per-request phase** (`check_scopes_request`): full URL info is available.
//!
//! Semantics:
//! - `scopes = None` → unrestricted token, permit everything.
//! - `scopes = Some([])` → empty whitelist, deny everything.
//! - `scopes = Some([...])` → permit if ANY scope matches.

use crate::types::TokenScope;

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Match a host against a host_pattern (case-insensitive, single-level wildcard).
///
/// Consistent with `matches_host_pattern` in `plugin_matcher.rs`.
fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern.starts_with("*.") {
        // Wildcard: *.example.com matches sub.example.com but NOT example.com
        // or a.b.example.com (single level only).
        let suffix = &pattern[1..]; // ".example.com"
        let host_lower = host.to_ascii_lowercase();
        let suffix_lower = suffix.to_ascii_lowercase();

        if !host_lower.ends_with(&suffix_lower) || host_lower.len() <= suffix_lower.len() {
            return false;
        }
        let subdomain = &host_lower[..host_lower.len() - suffix_lower.len()];
        !subdomain.contains('.')
    } else {
        // Exact match (case-insensitive)
        pattern.eq_ignore_ascii_case(host)
    }
}

/// Match a path against a path_pattern.
///
/// - Pattern ending with `/*`: prefix match — path must start with the part
///   before `*`.  We also accept the prefix itself without a trailing `/`
///   (e.g. `/v1/*` matches `/v1`).
/// - Otherwise: exact match.
///
/// Path matching is case-sensitive.
fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern.ends_with("/*") {
        // prefix is everything before the '*', e.g. "/v1/"
        let prefix = &pattern[..pattern.len() - 1]; // "/v1/"
        // Accept "/v1/anything" or "/v1" (the prefix without its trailing slash)
        if path.starts_with(prefix) {
            return true;
        }
        // Also accept the prefix stripped of its trailing slash
        let prefix_no_slash = prefix.trim_end_matches('/');
        path == prefix_no_slash
    } else {
        path == pattern
    }
}

/// Match a method against an optional methods list (case-insensitive).
fn method_matches(scope_methods: &Option<Vec<String>>, method: &str) -> bool {
    match scope_methods {
        None => true, // any method
        Some(methods) => methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method)),
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// CONNECT-phase check: only host and port, no path/method info available yet.
///
/// Returns `true` if the connection should be permitted.
pub fn check_scopes_host(scopes: &Option<Vec<TokenScope>>, host: &str, port: u16) -> bool {
    let scopes = match scopes {
        None => return true,       // unrestricted token
        Some(s) => s,
    };

    if scopes.is_empty() {
        return false; // empty whitelist — deny all
    }

    scopes.iter().any(|scope| {
        if !host_matches(&scope.host_pattern, host) {
            return false;
        }
        if let Some(p) = scope.port {
            if p != port {
                return false;
            }
        }
        true
    })
}

/// Per-request check: full URL info available.
///
/// Returns `true` if the request should be permitted.
pub fn check_scopes_request(
    scopes: &Option<Vec<TokenScope>>,
    host: &str,
    port: u16,
    path: &str,
    method: &str,
) -> bool {
    let scopes = match scopes {
        None => return true,
        Some(s) => s,
    };

    if scopes.is_empty() {
        return false;
    }

    scopes.iter().any(|scope| {
        if !host_matches(&scope.host_pattern, host) {
            return false;
        }
        if let Some(p) = scope.port {
            if p != port {
                return false;
            }
        }
        if !path_matches(&scope.path_pattern, path) {
            return false;
        }
        if !method_matches(&scope.methods, method) {
            return false;
        }
        true
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TokenScope;

    // Helper to build a minimal TokenScope
    fn scope(host_pattern: &str, port: Option<u16>, path_pattern: &str, methods: Option<Vec<&str>>) -> TokenScope {
        TokenScope {
            host_pattern: host_pattern.to_string(),
            port,
            path_pattern: path_pattern.to_string(),
            methods: methods.map(|ms| ms.iter().map(|m| m.to_string()).collect()),
        }
    }

    // ── check_scopes_host ────────────────────────────────────────────────────

    #[test]
    fn host_none_scopes_permits_any() {
        // None = unrestricted token
        assert!(check_scopes_host(&None, "example.com", 443));
        assert!(check_scopes_host(&None, "anything.else", 8080));
    }

    #[test]
    fn host_empty_scopes_denies_everything() {
        let scopes = Some(vec![]);
        assert!(!check_scopes_host(&scopes, "example.com", 443));
        assert!(!check_scopes_host(&scopes, "other.com", 80));
    }

    #[test]
    fn host_exact_match_permits_and_denies() {
        let scopes = Some(vec![scope("example.com", None, "/*", None)]);
        assert!(check_scopes_host(&scopes, "example.com", 443));
        assert!(!check_scopes_host(&scopes, "other.com", 443));
    }

    #[test]
    fn host_port_restriction_permits_matching_port_denies_others() {
        let scopes = Some(vec![scope("example.com", Some(8080), "/*", None)]);
        assert!(check_scopes_host(&scopes, "example.com", 8080));
        assert!(!check_scopes_host(&scopes, "example.com", 443));
        assert!(!check_scopes_host(&scopes, "example.com", 80));
    }

    #[test]
    fn host_no_port_restriction_permits_any_port() {
        let scopes = Some(vec![scope("example.com", None, "/*", None)]);
        assert!(check_scopes_host(&scopes, "example.com", 443));
        assert!(check_scopes_host(&scopes, "example.com", 8080));
        assert!(check_scopes_host(&scopes, "example.com", 80));
    }

    #[test]
    fn host_wildcard_matching() {
        let scopes = Some(vec![scope("*.example.com", None, "/*", None)]);
        // Single subdomain — permitted
        assert!(check_scopes_host(&scopes, "sub.example.com", 443));
        // Apex — denied (no subdomain)
        assert!(!check_scopes_host(&scopes, "example.com", 443));
        // Multi-level subdomain — denied (single-level wildcard only)
        assert!(!check_scopes_host(&scopes, "a.b.example.com", 443));
    }

    #[test]
    fn host_multiple_scopes_any_match_permits() {
        let scopes = Some(vec![
            scope("alpha.com", None, "/*", None),
            scope("beta.com", None, "/*", None),
        ]);
        assert!(check_scopes_host(&scopes, "alpha.com", 443));
        assert!(check_scopes_host(&scopes, "beta.com", 443));
        assert!(!check_scopes_host(&scopes, "gamma.com", 443));
    }

    #[test]
    fn host_case_insensitive_matching() {
        let scopes = Some(vec![scope("Example.COM", None, "/*", None)]);
        assert!(check_scopes_host(&scopes, "example.com", 443));
        assert!(check_scopes_host(&scopes, "EXAMPLE.COM", 443));
        assert!(check_scopes_host(&scopes, "Example.Com", 443));
    }

    // ── check_scopes_request ─────────────────────────────────────────────────

    #[test]
    fn request_none_scopes_permits_any() {
        assert!(check_scopes_request(&None, "example.com", 443, "/v1/users", "GET"));
    }

    #[test]
    fn request_empty_scopes_denies_everything() {
        let scopes = Some(vec![]);
        assert!(!check_scopes_request(&scopes, "example.com", 443, "/", "GET"));
    }

    #[test]
    fn request_path_exact_match() {
        let scopes = Some(vec![scope("example.com", None, "/v1/users", None)]);
        assert!(check_scopes_request(&scopes, "example.com", 443, "/v1/users", "GET"));
        assert!(!check_scopes_request(&scopes, "example.com", 443, "/v1/users/123", "GET"));
        assert!(!check_scopes_request(&scopes, "example.com", 443, "/v1", "GET"));
    }

    #[test]
    fn request_path_wildcard_root_matches_everything() {
        let scopes = Some(vec![scope("example.com", None, "/*", None)]);
        assert!(check_scopes_request(&scopes, "example.com", 443, "/", "GET"));
        assert!(check_scopes_request(&scopes, "example.com", 443, "/anything", "GET"));
        assert!(check_scopes_request(&scopes, "example.com", 443, "/deep/nested/path", "GET"));
    }

    #[test]
    fn request_path_wildcard_prefix() {
        let scopes = Some(vec![scope("example.com", None, "/v1/*", None)]);
        // Matches paths under /v1/
        assert!(check_scopes_request(&scopes, "example.com", 443, "/v1/users", "GET"));
        assert!(check_scopes_request(&scopes, "example.com", 443, "/v1/users/123", "GET"));
        assert!(check_scopes_request(&scopes, "example.com", 443, "/v1/", "GET"));
        // Also matches the prefix itself without trailing slash (lenient)
        assert!(check_scopes_request(&scopes, "example.com", 443, "/v1", "GET"));
        // Does NOT match different prefix
        assert!(!check_scopes_request(&scopes, "example.com", 443, "/v2/users", "GET"));
        assert!(!check_scopes_request(&scopes, "example.com", 443, "/other", "GET"));
    }

    #[test]
    fn request_method_restriction_permits_listed_denies_others() {
        let scopes = Some(vec![scope("example.com", None, "/*", Some(vec!["GET", "POST"]))]);
        assert!(check_scopes_request(&scopes, "example.com", 443, "/", "GET"));
        assert!(check_scopes_request(&scopes, "example.com", 443, "/", "POST"));
        assert!(!check_scopes_request(&scopes, "example.com", 443, "/", "DELETE"));
        assert!(!check_scopes_request(&scopes, "example.com", 443, "/", "PUT"));
    }

    #[test]
    fn request_method_none_permits_any() {
        let scopes = Some(vec![scope("example.com", None, "/*", None)]);
        assert!(check_scopes_request(&scopes, "example.com", 443, "/", "GET"));
        assert!(check_scopes_request(&scopes, "example.com", 443, "/", "DELETE"));
        assert!(check_scopes_request(&scopes, "example.com", 443, "/", "PATCH"));
    }

    #[test]
    fn request_full_combination_all_must_match_within_same_scope() {
        // Scope 1: example.com:443/v1/* GET only
        // Scope 2: other.com any port /api/* any method
        let scopes = Some(vec![
            scope("example.com", Some(443), "/v1/*", Some(vec!["GET"])),
            scope("other.com", None, "/api/*", None),
        ]);

        // Matches scope 1
        assert!(check_scopes_request(
            &scopes, "example.com", 443, "/v1/users", "GET"
        ));
        // Wrong port for scope 1, wrong host for scope 2 — denied
        assert!(!check_scopes_request(
            &scopes, "example.com", 8080, "/v1/users", "GET"
        ));
        // Wrong method for scope 1, wrong host for scope 2 — denied
        assert!(!check_scopes_request(
            &scopes, "example.com", 443, "/v1/users", "DELETE"
        ));
        // Matches scope 2
        assert!(check_scopes_request(
            &scopes, "other.com", 80, "/api/data", "POST"
        ));
    }

    #[test]
    fn request_multiple_scopes_second_matches() {
        let scopes = Some(vec![
            scope("first.com", None, "/a/*", None),
            scope("second.com", None, "/b/*", None),
        ]);
        // Only second scope matches
        assert!(check_scopes_request(&scopes, "second.com", 443, "/b/resource", "GET"));
        assert!(!check_scopes_request(&scopes, "second.com", 443, "/a/resource", "GET"));
    }

    #[test]
    fn request_method_case_insensitive() {
        let scopes = Some(vec![scope("example.com", None, "/*", Some(vec!["get", "POST"]))]);
        assert!(check_scopes_request(&scopes, "example.com", 443, "/", "GET"));
        assert!(check_scopes_request(&scopes, "example.com", 443, "/", "get"));
        assert!(check_scopes_request(&scopes, "example.com", 443, "/", "post"));
        assert!(check_scopes_request(&scopes, "example.com", 443, "/", "POST"));
        assert!(!check_scopes_request(&scopes, "example.com", 443, "/", "DELETE"));
    }
}
