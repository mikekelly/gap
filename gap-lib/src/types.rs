//! Core types for GAP
//!
//! Defines the data structures used throughout the proxy:
//! - Request/response handling
//! - Plugin definitions
//! - Credential storage
//! - Agent tokens
//! - Configuration

use chrono::{DateTime, Utc};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::fmt;

/// HTTP request representation for proxying
///
/// Contains all information needed to forward and transform an HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GAPRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Full URL including scheme, host, path, query
    pub url: String,
    /// HTTP headers as key-value pairs
    pub headers: HashMap<String, String>,
    /// Request body as raw bytes
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

impl GAPRequest {
    /// Create a new request
    pub fn new(method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            url: url.into(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Add a header to the request
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    /// Set the request body
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Get a header value
    pub fn get_header(&self, key: &str) -> Option<&String> {
        self.headers.get(key)
    }
}

/// Credentials for a specific plugin
///
/// String key-value map that plugins can use to access secrets.
/// Scoped to a single plugin - keys are namespaced in storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GAPCredentials {
    /// Credential key-value pairs
    pub credentials: HashMap<String, String>,
}

impl GAPCredentials {
    /// Create empty credentials
    pub fn new() -> Self {
        Self::default()
    }

    /// Create credentials from a map
    pub fn from_map(credentials: HashMap<String, String>) -> Self {
        Self { credentials }
    }

    /// Get a credential value
    pub fn get(&self, key: &str) -> Option<&String> {
        self.credentials.get(key)
    }

    /// Set a credential value
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.credentials.insert(key.into(), value.into());
    }

    /// Check if credentials contain a key
    pub fn contains_key(&self, key: &str) -> bool {
        self.credentials.contains_key(key)
    }
}

/// Plugin definition
///
/// Describes a JavaScript plugin that transforms requests for specific hosts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GAPPlugin {
    /// Unique plugin name (e.g., "exa", "aws-s3")
    pub name: String,
    /// Host patterns to match (supports wildcards like "*.s3.amazonaws.com")
    pub match_patterns: Vec<String>,
    /// Required credential keys (e.g., ["api_key"], ["access_key_id", "secret_access_key"])
    pub credential_schema: Vec<String>,
    /// JavaScript transform function source code
    pub transform: String,
    /// Git commit SHA (short) of the installed plugin version
    pub commit_sha: Option<String>,
    /// SHA-256 hash of the actual JS source code loaded at runtime
    pub source_hash: Option<String>,
    /// Whether the plugin explicitly permits credential injection over plain HTTP.
    /// Default is false (safe). When false, the proxy blocks plain HTTP requests
    /// to prevent credentials from being sent in cleartext.
    #[serde(default)]
    pub dangerously_permit_http: bool,
    /// Ordering weight for plugin/header-set priority (higher weight = higher priority).
    #[serde(default)]
    pub weight: i32,
}

impl GAPPlugin {
    /// Create a new plugin
    pub fn new(
        name: impl Into<String>,
        match_patterns: Vec<String>,
        credential_schema: Vec<String>,
        transform: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            match_patterns,
            credential_schema,
            transform: transform.into(),
            commit_sha: None,
            source_hash: None,
            dangerously_permit_http: false,
            weight: 0,
        }
    }

    /// Check if this plugin matches a given host
    pub fn matches_host(&self, host: &str) -> bool {
        self.match_patterns.iter().any(|pattern| {
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
        })
    }
}

/// A scope restriction for a token — defines what hosts/paths/methods are permitted.
///
/// Deserializes from two JSON forms:
/// - String: `"example.com"`, `"example.com:8080"`, `"example.com/v1/*"`, `"*.example.com/api/*"`
/// - Object: `{"match": "example.com/v1/*", "methods": ["GET", "POST"]}`
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TokenScope {
    pub host_pattern: String,
    pub port: Option<u16>,
    pub path_pattern: String,
    pub methods: Option<Vec<String>>,
}

/// Parse a scope string like "host[:port][/path]" into its components.
fn parse_scope_string(s: &str) -> Result<(String, Option<u16>, String), String> {
    let (host_part, path_pattern) = if let Some(slash_pos) = s.find('/') {
        let host_part = &s[..slash_pos];
        let path_part = &s[slash_pos..]; // includes the leading /
        (host_part, path_part.to_string())
    } else {
        (s, "/*".to_string())
    };

    // Parse host:port — split at last ':' but only if host doesn't start with '['
    // (basic IPv6 guard) and the part after ':' is a valid u16.
    let (host_pattern, port) = if let Some(colon_pos) = host_part.rfind(':') {
        let potential_port = &host_part[colon_pos + 1..];
        if let Ok(p) = potential_port.parse::<u16>() {
            (host_part[..colon_pos].to_string(), Some(p))
        } else {
            (host_part.to_string(), None)
        }
    } else {
        (host_part.to_string(), None)
    };

    Ok((host_pattern, port, path_pattern))
}

impl<'de> Deserialize<'de> for TokenScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TokenScopeVisitor;

        impl<'de> Visitor<'de> for TokenScopeVisitor {
            type Value = TokenScope;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "a scope string like \"example.com/path\" or an object with \"match\" field",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<TokenScope, E>
            where
                E: de::Error,
            {
                let (host_pattern, port, path_pattern) =
                    parse_scope_string(value).map_err(de::Error::custom)?;
                Ok(TokenScope {
                    host_pattern,
                    port,
                    path_pattern,
                    methods: None,
                })
            }

            fn visit_map<M>(self, mut map: M) -> Result<TokenScope, M::Error>
            where
                M: MapAccess<'de>,
            {
                // Compact form: {"match": "host[:port][/path]", "methods": [...]}
                let mut match_str: Option<String> = None;
                let mut methods: Option<Vec<String>> = None;
                // Expanded form: {"host_pattern": "...", "port": ..., "path_pattern": "...", "methods": [...]}
                let mut host_pattern: Option<String> = None;
                let mut port: Option<u16> = None;
                let mut path_pattern: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "match" => {
                            match_str = Some(map.next_value()?);
                        }
                        "methods" => {
                            methods = Some(map.next_value()?);
                        }
                        "host_pattern" => {
                            host_pattern = Some(map.next_value()?);
                        }
                        "port" => {
                            port = map.next_value()?;
                        }
                        "path_pattern" => {
                            path_pattern = Some(map.next_value()?);
                        }
                        _ => {
                            // Skip unknown fields
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                if let Some(match_val) = match_str {
                    // Compact form: parse "host[:port][/path]" string
                    let (hp, p, pp) =
                        parse_scope_string(&match_val).map_err(de::Error::custom)?;
                    Ok(TokenScope {
                        host_pattern: hp,
                        port: p,
                        path_pattern: pp,
                        methods,
                    })
                } else if let Some(hp) = host_pattern {
                    // Expanded struct form — host_pattern is the only required field
                    Ok(TokenScope {
                        host_pattern: hp,
                        port,
                        path_pattern: path_pattern.unwrap_or_else(|| "/*".to_string()),
                        methods,
                    })
                } else {
                    Err(de::Error::custom(
                        "object must have either a \"match\" field or a \"host_pattern\" field",
                    ))
                }
            }
        }

        deserializer.deserialize_any(TokenScopeVisitor)
    }
}

/// Lightweight token info carried through the proxy pipeline after authentication.
#[derive(Debug, Clone)]
pub struct ValidatedToken {
    pub prefix: String,
    pub scopes: Option<Vec<TokenScope>>,
}

/// Agent authentication token
///
/// Represents a bearer token used by an agent to authenticate proxy requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentToken {
    /// Token prefix (first 12 chars) for display/identification
    pub prefix: String,
    /// Full token value
    pub token: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

impl AgentToken {
    /// Create a new token with a cryptographically random value
    pub fn new() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let random_bytes: [u8; 16] = rng.gen();
        let token = format!("gap_{}", hex::encode(random_bytes));
        let prefix = token[..12].to_string();

        Self {
            prefix,
            token,
            created_at: Utc::now(),
        }
    }

    /// Verify if a token matches this stored token
    pub fn verify(&self, token: &str) -> bool {
        self.token == token
    }
}

/// Application configuration
///
/// Runtime configuration for both the proxy and management API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Proxy port (default: 9443)
    pub proxy_port: u16,
    /// Management API port (default: 9080)
    pub api_port: u16,
    /// CA certificate output path
    pub ca_cert_path: String,
    /// Data directory for file-based storage (Linux/container mode)
    pub data_dir: Option<String>,
    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy_port: 9443,
            api_port: 9080,
            ca_cert_path: "~/.gap/ca.crt".to_string(),
            data_dir: None,
            log_level: "info".to_string(),
        }
    }
}

impl Config {
    /// Create a new config with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Set proxy port
    pub fn with_proxy_port(mut self, port: u16) -> Self {
        self.proxy_port = port;
        self
    }

    /// Set API port
    pub fn with_api_port(mut self, port: u16) -> Self {
        self.api_port = port;
        self
    }

    /// Set data directory
    pub fn with_data_dir(mut self, dir: impl Into<String>) -> Self {
        self.data_dir = Some(dir.into());
        self
    }
}

/// Activity log entry for proxy request tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub timestamp: DateTime<Utc>,
    /// Hex request correlation ID for tracing
    pub request_id: Option<String>,
    pub method: String,
    pub url: String,
    pub agent_id: Option<String>,
    pub status: u16,
    /// Name of the plugin that handled this request
    pub plugin_name: Option<String>,
    /// Git commit SHA of the plugin that handled this request
    pub plugin_sha: Option<String>,
    /// SHA-256 hash of the plugin source code that handled this request
    pub source_hash: Option<String>,
    /// JSON string of post-transform request headers with credential values scrubbed
    pub request_headers: Option<String>,
    /// Pipeline stage where request was rejected (auth, no_matching_plugin, missing_credentials, http_blocked, upstream_error)
    pub rejection_stage: Option<String>,
    /// Human-readable reason for rejection
    pub rejection_reason: Option<String>,
}

/// Detailed request/response data for a single proxied request.
/// Stored separately from ActivityEntry to keep list queries fast.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RequestDetails {
    pub request_id: String,
    // Pre-transform (incoming from agent)
    pub req_headers: Option<String>,        // JSON object
    pub req_body: Option<Vec<u8>>,          // Up to 64KB
    // Post-transform (after plugin, scrubbed)
    pub transformed_url: Option<String>,
    pub transformed_headers: Option<String>, // JSON, credential values scrubbed
    pub transformed_body: Option<Vec<u8>>,   // Credential values scrubbed, up to 64KB
    // Origin response (scrubbed)
    pub response_status: Option<u16>,
    pub response_headers: Option<String>,    // JSON, credential values scrubbed
    pub response_body: Option<Vec<u8>>,      // Credential values scrubbed, up to 64KB
    // Metadata
    pub body_truncated: bool,
}

/// Filter for querying activity logs
#[derive(Debug, Default, Clone)]
pub struct ActivityFilter {
    /// Filter by URL domain (LIKE match)
    pub domain: Option<String>,
    /// Filter by URL path prefix (LIKE match)
    pub path: Option<String>,
    /// Filter by plugin name (exact match)
    pub plugin: Option<String>,
    /// Filter by agent ID (exact match)
    pub agent: Option<String>,
    /// Filter by HTTP method (exact match)
    pub method: Option<String>,
    /// Entries after this time
    pub since: Option<DateTime<Utc>>,
    /// Filter by request correlation ID (exact match)
    pub request_id: Option<String>,
    /// Max results (default 100)
    pub limit: Option<u32>,
}

/// Management audit log entry for tracking API mutations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementLogEntry {
    pub timestamp: DateTime<Utc>,
    /// Operation name: "token_create", "plugin_install", etc.
    pub operation: String,
    /// Resource type: "token", "plugin", "credential", "server"
    pub resource_type: String,
    /// Resource identifier (plugin name, token ID, "plugin/key")
    pub resource_id: Option<String>,
    /// JSON with operation-specific context (never secrets)
    pub detail: Option<String>,
    /// Whether the operation succeeded
    pub success: bool,
    /// Error message if the operation failed
    pub error_message: Option<String>,
}

/// Filter for querying management audit logs
#[derive(Debug, Default, Clone)]
pub struct ManagementLogFilter {
    pub operation: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub success: Option<bool>,
    pub since: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
}

// --- Registry-origin types (migrated from registry.rs) ---
// These types are used by GapDatabase and the API layer for listing/querying
// tokens, plugins, and credentials.

/// Token metadata (without the token value, which is used as the hash key)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenMetadata {
    pub created_at: DateTime<Utc>,
    pub scopes: Option<Vec<TokenScope>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Token entry returned by list operations (includes the token value)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenEntry {
    pub token_value: String,
    pub created_at: DateTime<Utc>,
    pub scopes: Option<Vec<TokenScope>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Plugin metadata entry (name, hosts, credential schema, optional commit SHA)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginEntry {
    pub name: String,
    pub hosts: Vec<String>,
    pub credential_schema: Vec<String>,
    /// Git commit SHA (short) of the installed version
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
    /// Whether the plugin explicitly permits credential injection over plain HTTP.
    #[serde(default)]
    pub dangerously_permit_http: bool,
    /// Ordering weight for plugin/header-set priority (higher weight = higher priority).
    #[serde(default)]
    pub weight: i32,
    /// Timestamp when the plugin was installed (populated from DB reads, None on construction for insertion).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_at: Option<DateTime<Utc>>,
}

/// Credential metadata entry (plugin + field name, no value)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialEntry {
    pub plugin: String,
    pub field: String,
}

/// A named set of static headers to inject into matching requests.
///
/// HeaderSets provide credential injection without JavaScript plugins —
/// useful for simple API-key-in-header patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeaderSet {
    pub name: String,
    pub match_patterns: Vec<String>,
    pub weight: i32,
    pub created_at: DateTime<Utc>,
}

/// Append-only record of every plugin version ever installed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginVersion {
    pub plugin_name: String,
    pub commit_sha: Option<String>,
    pub source_hash: String,
    pub source_code: String,
    pub installed_at: DateTime<Utc>,
}

// Serde helper for binary data
mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<u8>::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gap_request_creation() {
        let req = GAPRequest::new("GET", "https://api.example.com/users")
            .with_header("Authorization", "Bearer token")
            .with_body(b"test body".to_vec());

        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "https://api.example.com/users");
        assert_eq!(req.get_header("Authorization"), Some(&"Bearer token".to_string()));
        assert_eq!(req.body, b"test body");
    }

    #[test]
    fn test_gap_request_serialization() {
        let req = GAPRequest::new("POST", "https://api.example.com/data")
            .with_header("Content-Type", "application/json")
            .with_body(b"{\"test\":true}".to_vec());

        let json = serde_json::to_string(&req).unwrap();
        let deserialized: GAPRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(req, deserialized);
    }

    #[test]
    fn test_credentials_operations() {
        let mut creds = GAPCredentials::new();
        assert!(!creds.contains_key("api_key"));

        creds.set("api_key", "secret123");
        assert!(creds.contains_key("api_key"));
        assert_eq!(creds.get("api_key"), Some(&"secret123".to_string()));
    }

    #[test]
    fn test_credentials_from_map() {
        let mut map = HashMap::new();
        map.insert("access_key".to_string(), "AKIA123".to_string());
        map.insert("secret_key".to_string(), "secret456".to_string());

        let creds = GAPCredentials::from_map(map);
        assert_eq!(creds.get("access_key"), Some(&"AKIA123".to_string()));
        assert_eq!(creds.get("secret_key"), Some(&"secret456".to_string()));
    }

    #[test]
    fn test_plugin_exact_host_match() {
        let plugin = GAPPlugin::new(
            "test-plugin",
            vec!["api.example.com".to_string()],
            vec!["api_key".to_string()],
            "function transform(req, creds) { return req; }",
        );

        assert!(plugin.matches_host("api.example.com"));
        assert!(!plugin.matches_host("other.example.com"));
        assert!(!plugin.matches_host("api.example.com.evil.com"));
    }

    #[test]
    fn test_plugin_wildcard_host_match() {
        let plugin = GAPPlugin::new(
            "s3-plugin",
            vec!["*.s3.amazonaws.com".to_string()],
            vec!["access_key".to_string(), "secret_key".to_string()],
            "function transform(req, creds) { return req; }",
        );

        assert!(plugin.matches_host("bucket.s3.amazonaws.com"));
        assert!(plugin.matches_host("my-bucket.s3.amazonaws.com"));
        assert!(!plugin.matches_host("s3.amazonaws.com")); // No leading subdomain
        assert!(!plugin.matches_host("evil.com.s3.amazonaws.com")); // Doesn't end with pattern
    }

    #[test]
    fn test_plugin_multiple_patterns() {
        let plugin = GAPPlugin::new(
            "multi-plugin",
            vec![
                "api.example.com".to_string(),
                "*.example.org".to_string(),
            ],
            vec![],
            "function transform(req, creds) { return req; }",
        );

        assert!(plugin.matches_host("api.example.com"));
        assert!(plugin.matches_host("sub.example.org"));
        assert!(!plugin.matches_host("example.org"));
        assert!(!plugin.matches_host("example.com"));
    }

    #[test]
    fn test_agent_token_creation() {
        let token = AgentToken::new();

        assert_eq!(token.prefix.len(), 12);
        assert!(token.token.starts_with("gap_"));
        // gap_ (4 chars) + 32 hex chars = 36 total
        assert_eq!(token.token.len(), 36);
    }

    #[test]
    fn test_agent_token_verification() {
        let token = AgentToken::new();
        let token_value = token.token.clone();

        assert!(token.verify(&token_value));
        assert!(!token.verify("wrong_token"));
    }

    #[test]
    fn test_agent_token_serialization() {
        let token = AgentToken::new();
        let json = serde_json::to_string(&token).unwrap();

        // Token should be in serialized output (needed for storage)
        assert!(json.contains(&token.token));
        assert!(json.contains(&token.prefix));
    }

    // --- TokenScope deserialization tests ---

    #[test]
    fn test_token_scope_deserialize_host_only() {
        let scope: TokenScope = serde_json::from_str(r#""example.com""#).unwrap();
        assert_eq!(scope.host_pattern, "example.com");
        assert_eq!(scope.port, None);
        assert_eq!(scope.path_pattern, "/*");
        assert_eq!(scope.methods, None);
    }

    #[test]
    fn test_token_scope_deserialize_host_and_port() {
        let scope: TokenScope = serde_json::from_str(r#""example.com:8080""#).unwrap();
        assert_eq!(scope.host_pattern, "example.com");
        assert_eq!(scope.port, Some(8080));
        assert_eq!(scope.path_pattern, "/*");
        assert_eq!(scope.methods, None);
    }

    #[test]
    fn test_token_scope_deserialize_host_and_path() {
        let scope: TokenScope = serde_json::from_str(r#""example.com/v1/*""#).unwrap();
        assert_eq!(scope.host_pattern, "example.com");
        assert_eq!(scope.port, None);
        assert_eq!(scope.path_pattern, "/v1/*");
        assert_eq!(scope.methods, None);
    }

    #[test]
    fn test_token_scope_deserialize_host_port_and_path() {
        let scope: TokenScope = serde_json::from_str(r#""example.com:443/api/v2/*""#).unwrap();
        assert_eq!(scope.host_pattern, "example.com");
        assert_eq!(scope.port, Some(443));
        assert_eq!(scope.path_pattern, "/api/v2/*");
        assert_eq!(scope.methods, None);
    }

    #[test]
    fn test_token_scope_deserialize_wildcard_host() {
        let scope: TokenScope = serde_json::from_str(r#""*.example.com""#).unwrap();
        assert_eq!(scope.host_pattern, "*.example.com");
        assert_eq!(scope.port, None);
        assert_eq!(scope.path_pattern, "/*");
        assert_eq!(scope.methods, None);
    }

    #[test]
    fn test_token_scope_deserialize_object_with_methods() {
        let scope: TokenScope = serde_json::from_str(
            r#"{"match": "example.com/v1/*", "methods": ["GET", "POST"]}"#,
        )
        .unwrap();
        assert_eq!(scope.host_pattern, "example.com");
        assert_eq!(scope.port, None);
        assert_eq!(scope.path_pattern, "/v1/*");
        assert_eq!(scope.methods, Some(vec!["GET".to_string(), "POST".to_string()]));
    }

    #[test]
    fn test_token_scope_deserialize_object_without_methods() {
        let scope: TokenScope =
            serde_json::from_str(r#"{"match": "example.com"}"#).unwrap();
        assert_eq!(scope.host_pattern, "example.com");
        assert_eq!(scope.port, None);
        assert_eq!(scope.path_pattern, "/*");
        assert_eq!(scope.methods, None);
    }

    #[test]
    fn test_token_scope_deserialize_mixed_array() {
        let scopes: Vec<TokenScope> = serde_json::from_str(
            r#"["example.com", {"match": "api.test.com/v1/*", "methods": ["GET"]}]"#,
        )
        .unwrap();
        assert_eq!(scopes.len(), 2);

        assert_eq!(scopes[0].host_pattern, "example.com");
        assert_eq!(scopes[0].port, None);
        assert_eq!(scopes[0].path_pattern, "/*");
        assert_eq!(scopes[0].methods, None);

        assert_eq!(scopes[1].host_pattern, "api.test.com");
        assert_eq!(scopes[1].port, None);
        assert_eq!(scopes[1].path_pattern, "/v1/*");
        assert_eq!(scopes[1].methods, Some(vec!["GET".to_string()]));
    }

    #[test]
    fn test_token_scope_deserialize_expanded_form() {
        let json = r#"{"host_pattern": "example.com", "port": 8080, "path_pattern": "/v1/*", "methods": ["GET"]}"#;
        let scope: TokenScope = serde_json::from_str(json).unwrap();
        assert_eq!(scope.host_pattern, "example.com");
        assert_eq!(scope.port, Some(8080));
        assert_eq!(scope.path_pattern, "/v1/*");
        assert_eq!(scope.methods, Some(vec!["GET".to_string()]));
    }

    #[test]
    fn test_token_scope_round_trip() {
        let scope = TokenScope {
            host_pattern: "api.example.com".to_string(),
            port: Some(443),
            path_pattern: "/v2/*".to_string(),
            methods: Some(vec!["GET".to_string(), "POST".to_string()]),
        };
        let json = serde_json::to_string(&scope).unwrap();
        let deserialized: TokenScope = serde_json::from_str(&json).unwrap();
        assert_eq!(scope, deserialized);
    }

    #[test]
    fn test_config_defaults() {
        let config = Config::default();

        assert_eq!(config.proxy_port, 9443);
        assert_eq!(config.api_port, 9080);
        assert_eq!(config.log_level, "info");
        assert!(config.data_dir.is_none());
    }

    #[test]
    fn test_config_builder() {
        let config = Config::new()
            .with_proxy_port(8443)
            .with_api_port(8080)
            .with_data_dir("/var/lib/gap");

        assert_eq!(config.proxy_port, 8443);
        assert_eq!(config.api_port, 8080);
        assert_eq!(config.data_dir, Some("/var/lib/gap".to_string()));
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();

        assert_eq!(config, deserialized);
    }
}
