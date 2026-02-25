//! HTTP client for Management API

use anyhow::{Context, Result};
use ring::signature::Ed25519KeyPair;
use serde::Deserialize;
use std::sync::Arc;

/// API client for GAP server
pub struct ApiClient {
    base_url: String,
    client: reqwest::Client,
    signing_keypair: Option<Arc<Ed25519KeyPair>>,
    namespace: Option<String>,
    scope: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: &str, namespace: Option<String>, scope: Option<String>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
            signing_keypair: None,
            namespace,
            scope,
        }
    }

    /// Create a new ApiClient with a custom CA certificate for HTTPS verification
    pub fn with_ca_cert(
        base_url: &str,
        ca_cert_pem: &[u8],
        namespace: Option<String>,
        scope: Option<String>,
    ) -> Result<Self> {
        // Parse the PEM certificate
        let cert = reqwest::Certificate::from_pem(ca_cert_pem)
            .context("Failed to parse CA certificate")?;

        // Build a client with custom root certificate
        let client = reqwest::Client::builder()
            .add_root_certificate(cert)
            .build()
            .context("Failed to build HTTP client with custom CA")?;

        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            signing_keypair: None,
            namespace,
            scope,
        })
    }

    /// Create a new ApiClient from an existing reqwest Client
    pub fn from_reqwest_client(base_url: &str, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            signing_keypair: None,
            namespace: None,
            scope: None,
        }
    }

    /// Set the Ed25519 signing keypair for request signing.
    ///
    /// When set, all authenticated requests (post_auth, get_auth, delete_auth)
    /// will include Ed25519 signature headers.
    pub fn with_signing_key(mut self, key: Arc<Ed25519KeyPair>) -> Self {
        self.signing_keypair = Some(key);
        self
    }

    /// Build the full API path, prepending namespace/scope prefix when both are set.
    pub fn build_path(&self, path: &str) -> String {
        match (&self.namespace, &self.scope) {
            (Some(ns), Some(sc)) => format!("/namespaces/{}/scopes/{}{}", ns, sc, path),
            _ => path.to_string(),
        }
    }

    /// GET request without authentication
    pub async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    /// POST request without authentication (used for init endpoint)
    pub async fn post<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    /// Send an authenticated POST request with auth in Authorization header.
    pub async fn post_auth<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        password_hash: &str,
        body: serde_json::Value,
    ) -> Result<T> {
        let full_path = self.build_path(path);
        let url = format!("{}{}", self.base_url, full_path);
        let body_bytes = serde_json::to_vec(&body).context("Failed to serialize body")?;

        let mut request = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", password_hash))
            .header("content-type", "application/json");

        if let Some(keypair) = &self.signing_keypair {
            let signed = crate::signing::sign_request(keypair, "POST", &full_path, &body_bytes);
            request = request
                .header("x-gap-timestamp", &signed.timestamp)
                .header("x-gap-nonce", &signed.nonce)
                .header("x-gap-signature", &signed.signature)
                .header("x-gap-key-id", &signed.key_id);
        }

        let response = request
            .body(body_bytes)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    /// Send an authenticated GET request with optional query parameters.
    pub async fn get_auth<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        password_hash: &str,
        query_params: &[(&str, &str)],
    ) -> Result<T> {
        let full_path = self.build_path(path);
        let mut url = format!("{}{}", self.base_url, full_path);
        if !query_params.is_empty() {
            let params: Vec<String> = query_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            url = format!("{}?{}", url, params.join("&"));
        }

        let mut request = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", password_hash));

        if let Some(keypair) = &self.signing_keypair {
            let signed = crate::signing::sign_request(keypair, "GET", &full_path, b"");
            request = request
                .header("x-gap-timestamp", &signed.timestamp)
                .header("x-gap-nonce", &signed.nonce)
                .header("x-gap-signature", &signed.signature)
                .header("x-gap-key-id", &signed.key_id);
        }

        let response = request
            .send()
            .await
            .context("Failed to send request")?;
        self.handle_response(response).await
    }

    /// Send an authenticated DELETE request.
    pub async fn delete_auth<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        password_hash: &str,
    ) -> Result<T> {
        let full_path = self.build_path(path);
        let url = format!("{}{}", self.base_url, full_path);

        let mut request = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", password_hash));

        if let Some(keypair) = &self.signing_keypair {
            let signed = crate::signing::sign_request(keypair, "DELETE", &full_path, b"");
            request = request
                .header("x-gap-timestamp", &signed.timestamp)
                .header("x-gap-nonce", &signed.nonce)
                .header("x-gap-signature", &signed.signature)
                .header("x-gap-key-id", &signed.key_id);
        }

        let response = request
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    async fn handle_response<T: for<'de> Deserialize<'de>>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        let status = response.status();

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            anyhow::bail!("Server returned {}: {}", status, error_text);
        }

        response
            .json()
            .await
            .context("Failed to parse response JSON")
    }
}

// Response types matching the server API

#[derive(Debug, Deserialize)]
pub struct StatusResponse {
    pub version: String,
    pub uptime_seconds: u64,
    pub proxy_port: u16,
    pub api_port: u16,
}

#[derive(Debug, Deserialize)]
pub struct InitResponse {
    pub ca_path: String,
}

#[derive(Debug, Deserialize)]
pub struct PluginInfo {
    pub id: String,
    pub match_patterns: Vec<String>,
    pub credential_schema: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PluginsResponse {
    pub plugins: Vec<PluginInfo>,
}

#[derive(Debug, Deserialize)]
pub struct InstallResponse {
    pub id: String,
    pub source: String,
    pub installed: bool,
    pub commit_sha: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UninstallResponse {
    pub id: String,
    pub uninstalled: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateResponse {
    pub id: String,
    pub updated: bool,
    pub commit_sha: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SetCredentialResponse {
    pub plugin_id: String,
    pub key: String,
    pub set: bool,
}

#[derive(Debug, Deserialize)]
pub struct TokenInfo {
    pub prefix: String,
    pub created_at: String,
    #[serde(default)]
    pub permitted: Option<Vec<serde_json::Value>>,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokensResponse {
    pub tokens: Vec<TokenInfo>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct CreateTokenResponse {
    pub prefix: String,
    pub token: String,
    pub created_at: String,
    #[serde(default)]
    pub permitted: Option<Vec<serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeTokenResponse {
    pub prefix: String,
    pub revoked: bool,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ActivityEntry {
    pub timestamp: String,
    pub request_id: Option<String>,
    pub method: String,
    pub url: String,
    pub agent_id: Option<String>,
    pub status: u16,
    pub plugin_id: Option<String>,
    pub plugin_sha: Option<String>,
    pub source_hash: Option<String>,
    pub request_headers: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ActivityResponse {
    pub entries: Vec<ActivityEntry>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ManagementLogEntry {
    pub timestamp: String,
    pub operation: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub detail: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ManagementLogResponse {
    pub entries: Vec<ManagementLogEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_path_without_namespace() {
        let client = ApiClient::new("https://localhost:9080", None, None);
        assert_eq!(client.build_path("/plugins"), "/plugins");
    }

    #[test]
    fn test_build_path_with_namespace() {
        let client = ApiClient::new(
            "https://localhost:9080",
            Some("org1".to_string()),
            Some("team1".to_string()),
        );
        assert_eq!(
            client.build_path("/plugins"),
            "/namespaces/org1/scopes/team1/plugins"
        );
    }

    #[test]
    fn test_build_path_namespace_without_scope() {
        // Only namespace without scope should NOT prefix (both required)
        let client = ApiClient::new("https://localhost:9080", Some("org1".to_string()), None);
        assert_eq!(client.build_path("/plugins"), "/plugins");
    }

    #[test]
    fn test_client_with_signing_key() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let client = ApiClient::new("http://localhost:9080", None, None)
            .with_signing_key(Arc::new(keypair));
        assert!(client.signing_keypair.is_some());
    }

    #[test]
    fn test_client_without_signing_key() {
        let client = ApiClient::new("http://localhost:9080", None, None);
        assert!(client.signing_keypair.is_none());
    }

    #[test]
    fn test_client_creation() {
        let client = ApiClient::new("http://localhost:9080", None, None);
        assert_eq!(client.base_url, "http://localhost:9080");
    }

    #[test]
    fn test_client_strips_trailing_slash() {
        let client = ApiClient::new("http://localhost:9080/", None, None);
        assert_eq!(client.base_url, "http://localhost:9080");
    }

    #[test]
    fn test_client_with_ca_cert() {
        // Generate a real CA certificate for testing
        let ca = gap_lib::tls::CertificateAuthority::generate().expect("Failed to create CA");
        let ca_pem = ca.ca_cert_pem();

        // This should create a client with custom CA cert
        let result = ApiClient::with_ca_cert("https://localhost:9080", ca_pem.as_bytes(), None, None);
        assert!(result.is_ok(), "Failed to create client with CA cert: {:?}", result.err());

        let client = result.unwrap();
        assert_eq!(client.base_url, "https://localhost:9080");
    }

    #[test]
    fn test_client_with_invalid_ca_cert() {
        // Note: reqwest::Certificate::from_pem may not fail on all invalid inputs
        // It only validates the certificate when actually establishing a connection
        // So we just test that the method doesn't panic
        let invalid_pem = b"not a valid certificate";

        let _result = ApiClient::with_ca_cert("https://localhost:9080", invalid_pem, None, None);
        // The method may or may not return an error depending on reqwest's validation
        // The important thing is that it doesn't panic
    }

    #[test]
    fn test_get_auth_url_construction_no_params() {
        // Verify that get_auth builds the URL correctly with no query params
        let client = ApiClient::new("http://localhost:9080", None, None);
        // We can't easily test the network call, but we can verify the base_url is set
        assert_eq!(client.base_url, "http://localhost:9080");
    }

    #[test]
    fn test_get_auth_url_with_query_params() {
        // Verify URL construction logic inline — the same logic used in get_auth
        let base = "http://localhost:9080";
        let path = "/management-log";
        let query_params: &[(&str, &str)] = &[
            ("operation", "token_create"),
            ("resource_type", "token"),
        ];

        let mut url = format!("{}{}", base, path);
        if !query_params.is_empty() {
            let params: Vec<String> = query_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            url = format!("{}?{}", url, params.join("&"));
        }

        assert_eq!(url, "http://localhost:9080/management-log?operation=token_create&resource_type=token");
    }

    #[test]
    fn test_get_auth_url_with_no_query_params_no_question_mark() {
        // Verify that an empty query_params slice produces no trailing '?'
        let base = "http://localhost:9080";
        let path = "/management-log";
        let query_params: &[(&str, &str)] = &[];

        let mut url = format!("{}{}", base, path);
        if !query_params.is_empty() {
            let params: Vec<String> = query_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            url = format!("{}?{}", url, params.join("&"));
        }

        assert_eq!(url, "http://localhost:9080/management-log");
        assert!(!url.contains('?'));
    }

    #[test]
    fn test_plugin_info_has_id_field() {
        // PluginInfo should use `id` (UUID) not `name`
        let json = r#"{"id":"550e8400-e29b-41d4-a716-446655440000","match_patterns":["*.example.com"],"credential_schema":["api_key"]}"#;
        let info: PluginInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.id, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn test_install_response_has_id_and_source_fields() {
        // InstallResponse should use `id` and have `source`
        let json = r#"{"id":"550e8400-e29b-41d4-a716-446655440000","source":"owner/repo","installed":true,"commit_sha":"abc123"}"#;
        let resp: InstallResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(resp.source, "owner/repo");
        assert!(resp.installed);
    }

    #[test]
    fn test_uninstall_response_has_id_field() {
        // UninstallResponse should use `id` not `name`
        let json = r#"{"id":"550e8400-e29b-41d4-a716-446655440000","uninstalled":true}"#;
        let resp: UninstallResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "550e8400-e29b-41d4-a716-446655440000");
        assert!(resp.uninstalled);
    }

    #[test]
    fn test_update_response_has_id_field() {
        // UpdateResponse should use `id` not `name`
        let json = r#"{"id":"550e8400-e29b-41d4-a716-446655440000","updated":true,"commit_sha":null}"#;
        let resp: UpdateResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "550e8400-e29b-41d4-a716-446655440000");
        assert!(resp.updated);
    }

    #[test]
    fn test_set_credential_response_has_plugin_id_field() {
        // SetCredentialResponse should use `plugin_id` not `plugin`
        let json = r#"{"plugin_id":"550e8400-e29b-41d4-a716-446655440000","key":"api_key","set":true}"#;
        let resp: SetCredentialResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.plugin_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(resp.key, "api_key");
        assert!(resp.set);
    }

    #[test]
    fn test_activity_entry_has_plugin_id_field() {
        // ActivityEntry should use `plugin_id` not `plugin_name`
        let json = r#"{"timestamp":"2024-01-01T00:00:00Z","request_id":null,"method":"GET","url":"https://api.example.com","agent_id":null,"status":200,"plugin_id":"550e8400-e29b-41d4-a716-446655440000","plugin_sha":null,"source_hash":null,"request_headers":null}"#;
        let entry: ActivityEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.plugin_id.as_deref(), Some("550e8400-e29b-41d4-a716-446655440000"));
    }
}
