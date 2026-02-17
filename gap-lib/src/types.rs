//! Core types for GAP
//!
//! Defines the data structures used throughout the proxy:
//! - Request/response handling
//! - Plugin definitions
//! - Credential storage
//! - Agent tokens
//! - Configuration

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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

/// Agent authentication token
///
/// Represents a bearer token used by an agent to authenticate proxy requests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentToken {
    /// Unique token ID
    pub id: String,
    /// Human-readable name for the agent
    pub name: String,
    /// Token prefix (first 8 chars) for display
    pub prefix: String,
    /// Full token value (stored securely)
    pub token: String,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

impl AgentToken {
    /// Create a new token with generated ID and value
    pub fn new(name: impl Into<String>) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Generate a simple token (in production, use crypto-random)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let token = format!("gap_{:x}", timestamp);
        let prefix = token.chars().take(8).collect();

        Self {
            id: uuid_v4(),
            name: name.into(),
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

// Simple UUID v4 generator (for testing; in production use uuid crate)
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (nanos >> 96) as u32,
        ((nanos >> 80) & 0xffff) as u16,
        ((nanos >> 64) & 0xfff) as u16,
        ((nanos >> 48) & 0xffff) as u16,
        (nanos & 0xffffffffffff) as u64,
    )
}

/// Activity log entry for proxy request tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub url: String,
    pub agent_id: Option<String>,
    pub status: u16,
}

// --- Registry-origin types (migrated from registry.rs) ---
// These types are used by GapDatabase and the API layer for listing/querying
// tokens, plugins, and credentials.

/// Token metadata (without the token value, which is used as the hash key)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenMetadata {
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// Token entry returned by list operations (includes the token value)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenEntry {
    pub token_value: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
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
}

/// Credential metadata entry (plugin + field name, no value)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialEntry {
    pub plugin: String,
    pub field: String,
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
        let token = AgentToken::new("Test Agent");

        assert!(!token.id.is_empty());
        assert_eq!(token.name, "Test Agent");
        assert_eq!(token.prefix.len(), 8);
        assert!(token.token.starts_with("gap_"));
    }

    #[test]
    fn test_agent_token_verification() {
        let token = AgentToken::new("Test Agent");
        let token_value = token.token.clone();

        assert!(token.verify(&token_value));
        assert!(!token.verify("wrong_token"));
    }

    #[test]
    fn test_agent_token_serialization() {
        let token = AgentToken::new("Test Agent");
        let json = serde_json::to_string(&token).unwrap();

        // Token should be in serialized output (needed for storage)
        assert!(json.contains(&token.token));
        // Other fields should be present too
        assert!(json.contains(&token.name));
        assert!(json.contains(&token.prefix));
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
