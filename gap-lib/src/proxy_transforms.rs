//! Proxy HTTP transformation utilities
//!
//! Handles HTTP parsing and plugin transform execution for the proxy.

use crate::database::GapDatabase;
use crate::error::{GapError, Result};
use crate::http_utils::{parse_http_request, serialize_http_request};
use crate::plugin_matcher::{find_matching_handler, MatchResult};
use crate::plugin_runtime::PluginRuntime;
use crate::types::{GAPCredentials, GAPRequest};
use base64::Engine;
use std::collections::HashMap;
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
    pub id: String,
    pub commit_sha: Option<String>,
    pub source_hash: Option<String>,
    /// JSON string of post-transform request headers with credential values scrubbed
    pub scrubbed_headers: Option<String>,
    /// Raw credential values for scrubbing post-transform body and response.
    /// Transient — never serialized, never stored.
    pub credential_values: HashMap<String, String>,
}

/// Scrub credential values from post-transform request headers.
///
/// Replaces literal credential values, their base64 encodings, hex encodings,
/// and Basic auth headers containing credentials with `[REDACTED]`.
/// Returns a JSON object string of the scrubbed headers.
fn scrub_headers(request: &GAPRequest, credentials: &HashMap<String, String>) -> String {
    let mut headers: Vec<(String, String)> = request
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    for cred_value in credentials.values() {
        if cred_value.is_empty() {
            continue;
        }

        // 1. Handle Basic auth headers: decode base64, check for credential, redact whole token
        for header in &mut headers {
            if header.1.starts_with("Basic ") {
                let b64_part = &header.1[6..];
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64_part) {
                    if let Ok(decoded_str) = String::from_utf8(decoded) {
                        if decoded_str.contains(cred_value) {
                            header.1 = "Basic [REDACTED]".to_string();
                        }
                    }
                }
            }
        }

        // 2. Base64-encoded value replacement
        let b64_value = base64::engine::general_purpose::STANDARD.encode(cred_value);
        for header in &mut headers {
            if header.1.contains(&b64_value) {
                header.1 = header.1.replace(&b64_value, "[REDACTED]");
            }
        }

        // 3. Hex-encoded value replacement (plugins have GAP.util.hex())
        let hex_value = hex::encode(cred_value.as_bytes());
        for header in &mut headers {
            if header.1.contains(&hex_value) {
                header.1 = header.1.replace(&hex_value, "[REDACTED]");
            }
        }

        // 4. Literal value replacement
        for header in &mut headers {
            if header.1.contains(cred_value) {
                header.1 = header.1.replace(cred_value, "[REDACTED]");
            }
        }
    }

    // Serialize as JSON object (deterministic key order via BTreeMap)
    let header_map: std::collections::BTreeMap<&str, &str> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    serde_json::to_string(&header_map).unwrap_or_default()
}

/// Maximum body size stored in request details (64KB).
pub const MAX_BODY_SIZE: usize = 64 * 1024;

/// Truncate a body to MAX_BODY_SIZE, returning (truncated_body, was_truncated).
pub fn truncate_body(body: &[u8]) -> (&[u8], bool) {
    if body.len() > MAX_BODY_SIZE {
        (&body[..MAX_BODY_SIZE], true)
    } else {
        (body, false)
    }
}

/// Scrub credential values from a request/response body.
///
/// For UTF-8 bodies: replaces literal values, base64 encodings, and hex encodings.
/// For non-UTF-8 bodies: returns body unchanged (binary data unlikely to contain text credentials).
/// Body is truncated to `max_len` bytes if larger.
pub fn scrub_body(body: &[u8], credentials: &HashMap<String, String>, max_len: usize) -> (Vec<u8>, bool) {
    let truncated = body.len() > max_len;
    let body = if truncated { &body[..max_len] } else { body };

    // Only scrub UTF-8 text bodies
    let Ok(text) = std::str::from_utf8(body) else {
        return (body.to_vec(), truncated);
    };

    let mut scrubbed = text.to_string();
    for cred_value in credentials.values() {
        if cred_value.is_empty() {
            continue;
        }

        // Base64-encoded value
        let b64_value = base64::engine::general_purpose::STANDARD.encode(cred_value);
        if scrubbed.contains(&b64_value) {
            scrubbed = scrubbed.replace(&b64_value, "[REDACTED]");
        }

        // Hex-encoded value
        let hex_value = hex::encode(cred_value.as_bytes());
        if scrubbed.contains(&hex_value) {
            scrubbed = scrubbed.replace(&hex_value, "[REDACTED]");
        }

        // Literal value (last to avoid double-redaction)
        if scrubbed.contains(cred_value.as_str()) {
            scrubbed = scrubbed.replace(cred_value.as_str(), "[REDACTED]");
        }
    }

    (scrubbed.into_bytes(), truncated)
}

/// Scrub credential values from response headers and return as JSON string.
///
/// Same scrub strategy as `scrub_headers` but takes `Vec<(String, String)>`
/// (since response headers aren't a GAPRequest).
pub fn scrub_response_headers(headers: &[(String, String)], credentials: &HashMap<String, String>) -> String {
    let mut headers: Vec<(String, String)> = headers.to_vec();

    for cred_value in credentials.values() {
        if cred_value.is_empty() {
            continue;
        }

        // Base64-encoded value
        let b64_value = base64::engine::general_purpose::STANDARD.encode(cred_value);
        for header in &mut headers {
            if header.1.contains(&b64_value) {
                header.1 = header.1.replace(&b64_value, "[REDACTED]");
            }
        }

        // Hex-encoded value
        let hex_value = hex::encode(cred_value.as_bytes());
        for header in &mut headers {
            if header.1.contains(&hex_value) {
                header.1 = header.1.replace(&hex_value, "[REDACTED]");
            }
        }

        // Literal value
        for header in &mut headers {
            if header.1.contains(cred_value.as_str()) {
                header.1 = header.1.replace(cred_value.as_str(), "[REDACTED]");
            }
        }
    }

    // Serialize as JSON object (deterministic key order)
    let header_map: std::collections::BTreeMap<&str, &str> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    serde_json::to_string(&header_map).unwrap_or_default()
}

/// Apply plugin or header-set transforms to a GAPRequest.
///
/// This is the core transformation logic: handler lookup, credential/header
/// loading, and transform execution. Used by both the legacy byte-based
/// pipeline and the new hyper-based pipeline.
///
/// The `use_tls` flag indicates whether the connection to the upstream server
/// uses TLS. When false (plain HTTP), plugins must have `dangerously_permit_http: true`
/// to allow credential injection — header sets always require TLS.
///
/// Returns the transformed request and info about the handler that processed it.
///
/// CRITICAL: PluginRuntime is not Send — this function scopes the runtime
/// in a sync block to ensure it is dropped before any `.await` points.
pub async fn transform_request(
    request: GAPRequest,
    hostname: &str,
    port: Option<u16>,
    path: &str,
    db: &GapDatabase,
    use_tls: bool,
) -> Result<(GAPRequest, PluginInfo)> {
    // Find matching handler (plugin or header set)
    // SECURITY: Only allow connections to hosts with registered handlers
    let handler = match find_matching_handler(hostname, port, path, db).await? {
        Some(h) => h,
        None => {
            warn!("BLOCKED: Host {} has no matching plugin or header set - not allowed", hostname);
            return Err(GapError::auth(format!(
                "Host '{}' is not allowed: no matching plugin or header set",
                hostname
            )));
        }
    };

    match handler {
        MatchResult::Plugin(plugin) => {
            debug!(
                "Found matching plugin: {} (sha: {})",
                plugin.id,
                plugin.commit_sha.as_deref().unwrap_or("unknown")
            );

            // SECURITY: Block plain HTTP requests unless the plugin explicitly opts in.
            if !use_tls && !plugin.dangerously_permit_http {
                warn!(
                    "BLOCKED: Plugin {} does not permit HTTP - credentials would be sent in plaintext. \
                     Set dangerously_permit_http: true in plugin manifest to allow.",
                    plugin.id
                );
                return Err(GapError::auth(format!(
                    "Plugin '{}' does not permit credential injection over plain HTTP. \
                     Set dangerously_permit_http: true in the plugin manifest to allow.",
                    plugin.id
                )));
            }

            // Load credentials for the plugin
            let credentials = load_plugin_credentials(&plugin.id, db).await?;

            // SECURITY: Only allow connections when credentials are configured
            if credentials.credentials.is_empty() {
                warn!(
                    "BLOCKED: Plugin {} has no credentials configured - not allowed",
                    plugin.id
                );
                return Err(GapError::auth(format!(
                    "Host '{}' is not allowed: plugin '{}' has no credentials configured",
                    hostname, plugin.id
                )));
            }

            debug!("Loaded {} credential fields for plugin {}", credentials.credentials.len(), plugin.id);

            // Load plugin code from database
            let plugin_code = db.get_plugin_source(&plugin.id).await?
                .ok_or_else(|| GapError::plugin(format!("Plugin code not found for {}", plugin.id)))?;

            // Execute transform
            // CRITICAL: Scope the PluginRuntime to ensure it's dropped before any await
            let transformed_request = {
                let mut runtime = PluginRuntime::new()?;
                runtime.load_plugin_from_code(&plugin.id, &plugin_code)?;
                runtime.execute_transform(&plugin.id, request, &credentials)?
            };

            debug!("Transform executed successfully");

            // Scrub credential values from post-transform headers for audit logging.
            let scrubbed = scrub_headers(&transformed_request, &credentials.credentials);

            let plugin_info = PluginInfo {
                id: plugin.id.clone(),
                commit_sha: plugin.commit_sha.clone(),
                source_hash: plugin.source_hash.clone(),
                scrubbed_headers: Some(scrubbed),
                credential_values: credentials.credentials.clone(),
            };

            Ok((transformed_request, plugin_info))
        }
        MatchResult::HeaderSet(header_set) => {
            debug!("Found matching header set: {}", header_set.id);

            // SECURITY: HeaderSets always require TLS.
            if !use_tls {
                warn!(
                    "BLOCKED: Header set '{}' does not permit header injection over plain HTTP",
                    header_set.id
                );
                return Err(GapError::auth(format!(
                    "Header set '{}' does not permit header injection over plain HTTP",
                    header_set.id
                )));
            }

            // Load headers for this set
            let header_values = db.get_header_set_headers(&header_set.id).await?;

            if header_values.is_empty() {
                warn!(
                    "BLOCKED: Header set '{}' has no headers configured",
                    header_set.id
                );
                return Err(GapError::auth(format!(
                    "header set '{}' has no headers configured",
                    header_set.id
                )));
            }

            debug!("Loaded {} headers for header set {}", header_values.len(), header_set.id);

            // Inject headers into request (overwrite if exists)
            let mut modified_request = request;
            for (name, value) in &header_values {
                modified_request.headers.insert(name.clone(), value.clone());
            }

            // Scrub: treat header values as the credentials for scrubbing
            let scrubbed = scrub_headers(&modified_request, &header_values);

            let plugin_info = PluginInfo {
                id: header_set.id,
                commit_sha: None,
                source_hash: None,
                scrubbed_headers: Some(scrubbed),
                credential_values: header_values,
            };

            Ok((modified_request, plugin_info))
        }
    }
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

    // Apply transforms (parse_and_transform is only used for HTTPS)
    // Extract path from the parsed request URL by finding the path segment after host
    let req_path = {
        let url = &request.url;
        // URL format: https://host/path or https://host:port/path
        if let Some(after_scheme) = url.find("://").map(|i| &url[i + 3..]) {
            after_scheme.find('/').map(|i| after_scheme[i..].to_string())
                .unwrap_or_else(|| "/".to_string())
        } else {
            "/".to_string()
        }
    };
    let (transformed_request, _plugin_info) =
        transform_request(request, hostname, None, &req_path, db, true).await?;

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
            id: "test-api".to_string(),
            source: None,
            hosts: vec!["api.test.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
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

        let (result, plugin_info) = transform_request(request, "api.test.com", None, "/", &db, true)
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
        assert_eq!(plugin_info.id, "test-api");
    }

    #[tokio::test]
    async fn test_transform_request_rejects_unregistered_host() {
        let db = GapDatabase::in_memory().await.unwrap();

        let request = GAPRequest::new("GET", "https://evil.com/data")
            .with_header("Host", "evil.com");

        let result = transform_request(request, "evil.com", None, "/", &db, true).await;
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
            id: "no-creds".to_string(),
            source: None,
            hosts: vec!["api.nocreds.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&plugin_entry, plugin_code).await.unwrap();

        let request = GAPRequest::new("GET", "https://api.nocreds.com/data")
            .with_header("Host", "api.nocreds.com");

        let result = transform_request(request, "api.nocreds.com", None, "/", &db, true).await;
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

    #[test]
    fn test_scrub_headers_literal_bearer_token() {
        let request = GAPRequest::new("GET", "https://api.test.com/data")
            .with_header("Authorization", "Bearer sk-secret-123")
            .with_header("Host", "api.test.com");

        let mut credentials = HashMap::new();
        credentials.insert("api_key".to_string(), "sk-secret-123".to_string());

        let scrubbed = scrub_headers(&request, &credentials);
        let parsed: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();

        assert_eq!(parsed["Authorization"], "Bearer [REDACTED]");
        // Non-credential headers should be preserved
        assert_eq!(parsed["Host"], "api.test.com");
    }

    #[test]
    fn test_scrub_headers_basic_auth() {
        // Basic auth: base64("user:password")
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:my-secret-pw");
        let request = GAPRequest::new("GET", "https://api.test.com/data")
            .with_header("Authorization", &format!("Basic {}", encoded));

        let mut credentials = HashMap::new();
        credentials.insert("password".to_string(), "my-secret-pw".to_string());

        let scrubbed = scrub_headers(&request, &credentials);
        let parsed: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();

        assert_eq!(parsed["Authorization"], "Basic [REDACTED]");
    }

    #[test]
    fn test_scrub_headers_base64_encoded_value() {
        // Credential value appears as base64 in a custom header
        let secret = "my-api-key";
        let b64_secret = base64::engine::general_purpose::STANDARD.encode(secret);
        let request = GAPRequest::new("GET", "https://api.test.com/data")
            .with_header("X-Custom-Auth", &format!("Token {}", b64_secret));

        let mut credentials = HashMap::new();
        credentials.insert("api_key".to_string(), secret.to_string());

        let scrubbed = scrub_headers(&request, &credentials);
        let parsed: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();

        // The base64-encoded value should be redacted
        assert!(!parsed["X-Custom-Auth"].as_str().unwrap().contains(&b64_secret));
        assert!(parsed["X-Custom-Auth"].as_str().unwrap().contains("[REDACTED]"));
    }

    #[test]
    fn test_scrub_headers_hex_encoded_value() {
        // Credential value appears as hex in a custom header (via GAP.util.hex())
        let secret = "my-api-key";
        let hex_secret = hex::encode(secret.as_bytes());
        let request = GAPRequest::new("GET", "https://api.test.com/data")
            .with_header("X-Hex-Auth", &hex_secret);

        let mut credentials = HashMap::new();
        credentials.insert("api_key".to_string(), secret.to_string());

        let scrubbed = scrub_headers(&request, &credentials);
        let parsed: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();

        assert!(!parsed["X-Hex-Auth"].as_str().unwrap().contains(&hex_secret));
        assert_eq!(parsed["X-Hex-Auth"], "[REDACTED]");
    }

    #[test]
    fn test_scrub_headers_multiple_credentials() {
        let request = GAPRequest::new("POST", "https://api.test.com/data")
            .with_header("Authorization", "Bearer first-secret")
            .with_header("X-Api-Key", "second-secret");

        let mut credentials = HashMap::new();
        credentials.insert("token".to_string(), "first-secret".to_string());
        credentials.insert("api_key".to_string(), "second-secret".to_string());

        let scrubbed = scrub_headers(&request, &credentials);
        let parsed: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();

        assert_eq!(parsed["Authorization"], "Bearer [REDACTED]");
        assert_eq!(parsed["X-Api-Key"], "[REDACTED]");
    }

    #[test]
    fn test_scrub_headers_empty_credentials_preserved() {
        let request = GAPRequest::new("GET", "https://api.test.com/data")
            .with_header("Authorization", "Bearer token-value")
            .with_header("Host", "api.test.com");

        let credentials = HashMap::new();

        let scrubbed = scrub_headers(&request, &credentials);
        let parsed: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();

        // With no credentials to scrub, headers should be preserved as-is
        assert_eq!(parsed["Authorization"], "Bearer token-value");
        assert_eq!(parsed["Host"], "api.test.com");
    }

    #[test]
    fn test_scrub_headers_skips_empty_credential_values() {
        let request = GAPRequest::new("GET", "https://api.test.com/data")
            .with_header("Authorization", "Bearer real-token");

        let mut credentials = HashMap::new();
        credentials.insert("empty_field".to_string(), "".to_string());
        credentials.insert("token".to_string(), "real-token".to_string());

        let scrubbed = scrub_headers(&request, &credentials);
        let parsed: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();

        // Empty credential values should not cause issues
        assert_eq!(parsed["Authorization"], "Bearer [REDACTED]");
    }

    #[tokio::test]
    async fn test_transform_request_returns_scrubbed_headers() {
        let db = GapDatabase::in_memory().await.unwrap();
        setup_test_plugin(&db).await;

        let request = GAPRequest::new("GET", "https://api.test.com/data")
            .with_header("Host", "api.test.com");

        let (_result, plugin_info) = transform_request(request, "api.test.com", None, "/", &db, true)
            .await
            .expect("transform should succeed");

        // scrubbed_headers should be set
        assert!(plugin_info.scrubbed_headers.is_some());
        let scrubbed = plugin_info.scrubbed_headers.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();

        // The credential value "secret-key-123" should be redacted
        assert_eq!(parsed["Authorization"], "Bearer [REDACTED]");
        // Non-credential headers preserved
        assert_eq!(parsed["Host"], "api.test.com");
    }

    #[tokio::test]
    async fn test_transform_request_blocks_http_without_permit_flag() {
        let db = GapDatabase::in_memory().await.unwrap();
        // setup_test_plugin creates a plugin WITHOUT dangerously_permit_http
        setup_test_plugin(&db).await;

        let request = GAPRequest::new("GET", "http://api.test.com/data")
            .with_header("Host", "api.test.com");

        // use_tls=false should be blocked because plugin doesn't permit HTTP
        let result = transform_request(request, "api.test.com", None, "/", &db, false).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("does not permit") || err_msg.contains("plain HTTP"),
            "Expected HTTP blocking error, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_transform_request_allows_http_with_permit_flag() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Plugin WITH dangerously_permit_http: true
        let plugin_code = r#"
        var plugin = {
            name: "http-ok",
            matchPatterns: ["api.httpok.com"],
            dangerously_permit_http: true,
            credentialSchema: ["api_key"],
            transform: function(request, credentials) {
                request.headers["Authorization"] = "Bearer " + credentials.api_key;
                return request;
            }
        };
        "#;
        let plugin_entry = PluginEntry {
            id: "http-ok".to_string(),
            source: None,
            hosts: vec!["api.httpok.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
            dangerously_permit_http: true,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&plugin_entry, plugin_code).await.unwrap();
        db.set_credential("http-ok", "api_key", "http-secret").await.unwrap();

        let request = GAPRequest::new("GET", "http://api.httpok.com/data")
            .with_header("Host", "api.httpok.com");

        // use_tls=false should be allowed because plugin permits HTTP
        let (result, plugin_info) = transform_request(request, "api.httpok.com", None, "/", &db, false)
            .await
            .expect("transform should succeed with dangerously_permit_http=true");

        assert_eq!(
            result.get_header("Authorization"),
            Some(&"Bearer http-secret".to_string())
        );
        assert_eq!(plugin_info.id, "http-ok");
    }

    #[tokio::test]
    async fn test_transform_request_allows_https_without_permit_flag() {
        let db = GapDatabase::in_memory().await.unwrap();
        // setup_test_plugin creates a plugin WITHOUT dangerously_permit_http
        setup_test_plugin(&db).await;

        let request = GAPRequest::new("GET", "https://api.test.com/data")
            .with_header("Host", "api.test.com");

        // use_tls=true should always work regardless of dangerously_permit_http
        let (result, _) = transform_request(request, "api.test.com", None, "/", &db, true)
            .await
            .expect("HTTPS transform should succeed even without permit flag");

        assert_eq!(
            result.get_header("Authorization"),
            Some(&"Bearer secret-key-123".to_string())
        );
    }

    #[test]
    fn test_scrub_body_literal_replacement() {
        let body = br#"{"api_key":"sk-secret-123","data":"hello"}"#;
        let mut credentials = HashMap::new();
        credentials.insert("api_key".to_string(), "sk-secret-123".to_string());

        let (scrubbed, truncated) = scrub_body(body, &credentials, 64 * 1024);
        assert!(!truncated);
        let text = String::from_utf8(scrubbed).unwrap();
        assert!(!text.contains("sk-secret-123"));
        assert!(text.contains("[REDACTED]"));
        assert!(text.contains("hello"));
    }

    #[test]
    fn test_scrub_body_base64_replacement() {
        let secret = "my-secret-key";
        let b64 = base64::engine::general_purpose::STANDARD.encode(secret);
        let body = format!(r#"{{"token":"{}"}}"#, b64);
        let mut credentials = HashMap::new();
        credentials.insert("key".to_string(), secret.to_string());

        let (scrubbed, _) = scrub_body(body.as_bytes(), &credentials, 64 * 1024);
        let text = String::from_utf8(scrubbed).unwrap();
        assert!(!text.contains(&b64));
        assert!(text.contains("[REDACTED]"));
    }

    #[test]
    fn test_scrub_body_binary_passthrough() {
        // Non-UTF-8 binary data should pass through unchanged
        let body: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x01, 0x80];
        let mut credentials = HashMap::new();
        credentials.insert("key".to_string(), "secret".to_string());

        let (scrubbed, truncated) = scrub_body(&body, &credentials, 64 * 1024);
        assert!(!truncated);
        assert_eq!(scrubbed, body);
    }

    #[test]
    fn test_scrub_body_truncation() {
        let body = vec![b'A'; 100_000]; // 100KB
        let credentials = HashMap::new();

        let (scrubbed, truncated) = scrub_body(&body, &credentials, 64 * 1024);
        assert!(truncated);
        assert_eq!(scrubbed.len(), 64 * 1024);
    }

    #[test]
    fn test_scrub_body_empty_credentials() {
        let body = b"some body content";
        let credentials = HashMap::new();

        let (scrubbed, _) = scrub_body(body, &credentials, 64 * 1024);
        assert_eq!(scrubbed, body);
    }

    #[test]
    fn test_scrub_response_headers_literal() {
        let headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Api-Key".to_string(), "secret-value-here".to_string()),
        ];
        let mut credentials = HashMap::new();
        credentials.insert("key".to_string(), "secret-value-here".to_string());

        let scrubbed = scrub_response_headers(&headers, &credentials);
        let parsed: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();
        assert_eq!(parsed["Content-Type"], "application/json");
        assert_eq!(parsed["X-Api-Key"], "[REDACTED]");
    }

    #[test]
    fn test_scrub_response_headers_empty_credentials() {
        let headers = vec![
            ("Content-Type".to_string(), "text/html".to_string()),
        ];
        let credentials = HashMap::new();

        let scrubbed = scrub_response_headers(&headers, &credentials);
        let parsed: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();
        assert_eq!(parsed["Content-Type"], "text/html");
    }

    #[test]
    fn test_truncate_body_under_limit() {
        let body = vec![0u8; 100];
        let (truncated, was_truncated) = truncate_body(&body);
        assert!(!was_truncated);
        assert_eq!(truncated.len(), 100);
    }

    #[test]
    fn test_truncate_body_over_limit() {
        let body = vec![0u8; 100_000];
        let (truncated, was_truncated) = truncate_body(&body);
        assert!(was_truncated);
        assert_eq!(truncated.len(), 64 * 1024);
    }

    #[tokio::test]
    async fn test_transform_request_returns_credential_values() {
        let db = GapDatabase::in_memory().await.unwrap();
        setup_test_plugin(&db).await;

        let request = GAPRequest::new("GET", "https://api.test.com/data")
            .with_header("Host", "api.test.com");

        let (_result, plugin_info) = transform_request(request, "api.test.com", None, "/", &db, true)
            .await
            .expect("transform should succeed");

        // credential_values should be populated
        assert!(!plugin_info.credential_values.is_empty());
        assert_eq!(plugin_info.credential_values.get("api_key"), Some(&"secret-key-123".to_string()));
    }

    // ── HeaderSet transform tests ───────────────────────────────────

    #[tokio::test]
    async fn test_transform_request_header_set_injects_headers() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Create a header set matching the host
        db.add_header_set("test-hs", &["api.hs.com".to_string()], 0)
            .await
            .unwrap();
        db.set_header_set_header("test-hs", "Authorization", "Bearer hs-secret-123")
            .await
            .unwrap();
        db.set_header_set_header("test-hs", "X-Custom", "custom-value")
            .await
            .unwrap();

        let request = GAPRequest::new("GET", "https://api.hs.com/data")
            .with_header("Host", "api.hs.com");

        let (result, plugin_info) = transform_request(request, "api.hs.com", None, "/", &db, true)
            .await
            .expect("header set transform should succeed");

        // Headers should be injected
        assert_eq!(
            result.get_header("Authorization"),
            Some(&"Bearer hs-secret-123".to_string())
        );
        assert_eq!(
            result.get_header("X-Custom"),
            Some(&"custom-value".to_string())
        );
        // Original headers preserved
        assert_eq!(result.get_header("Host"), Some(&"api.hs.com".to_string()));
        // Plugin info should identify the header set
        assert_eq!(plugin_info.id, "test-hs");
        assert!(plugin_info.commit_sha.is_none());
        assert!(plugin_info.source_hash.is_none());
    }

    #[tokio::test]
    async fn test_transform_request_header_set_blocks_http() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.add_header_set("http-hs", &["api.httphs.com".to_string()], 0)
            .await
            .unwrap();
        db.set_header_set_header("http-hs", "Authorization", "Bearer secret")
            .await
            .unwrap();

        let request = GAPRequest::new("GET", "http://api.httphs.com/data")
            .with_header("Host", "api.httphs.com");

        // use_tls=false should be blocked for header sets
        let result = transform_request(request, "api.httphs.com", None, "/", &db, false).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("does not permit") || err_msg.contains("plain HTTP"),
            "Expected HTTP blocking error, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_transform_request_header_set_empty_headers() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Header set with no headers configured
        db.add_header_set("empty-hs", &["api.empty.com".to_string()], 0)
            .await
            .unwrap();

        let request = GAPRequest::new("GET", "https://api.empty.com/data")
            .with_header("Host", "api.empty.com");

        let result = transform_request(request, "api.empty.com", None, "/", &db, true).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no headers configured"),
            "Expected missing headers error, got: {}",
            err_msg
        );
    }

    #[tokio::test]
    async fn test_transform_request_header_set_scrubs_values() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.add_header_set("scrub-hs", &["api.scrub.com".to_string()], 0)
            .await
            .unwrap();
        db.set_header_set_header("scrub-hs", "Authorization", "Bearer scrub-secret-val")
            .await
            .unwrap();

        let request = GAPRequest::new("GET", "https://api.scrub.com/data")
            .with_header("Host", "api.scrub.com");

        let (_result, plugin_info) = transform_request(request, "api.scrub.com", None, "/", &db, true)
            .await
            .expect("header set transform should succeed");

        // Scrubbed headers should not contain the secret value
        assert!(plugin_info.scrubbed_headers.is_some());
        let scrubbed = plugin_info.scrubbed_headers.unwrap();
        assert!(!scrubbed.contains("scrub-secret-val"));
        assert!(scrubbed.contains("[REDACTED]"));

        // credential_values should contain the header values for response body scrubbing
        assert_eq!(
            plugin_info.credential_values.get("Authorization"),
            Some(&"Bearer scrub-secret-val".to_string())
        );
    }
}
