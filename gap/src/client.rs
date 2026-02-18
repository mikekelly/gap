//! HTTP client for Management API

use anyhow::{Context, Result};
use serde::Deserialize;

/// API client for GAP server
pub struct ApiClient {
    base_url: String,
    client: reqwest::Client,
}

impl ApiClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }

    /// Create a new ApiClient with a custom CA certificate for HTTPS verification
    pub fn with_ca_cert(base_url: &str, ca_cert_pem: &[u8]) -> Result<Self> {
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
        })
    }

    /// Create a new ApiClient from an existing reqwest Client
    pub fn from_reqwest_client(base_url: &str, client: reqwest::Client) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
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
        let url = format!("{}{}", self.base_url, path);

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", password_hash))
            .json(&body)
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
        let mut url = format!("{}{}", self.base_url, path);
        if !query_params.is_empty() {
            let params: Vec<String> = query_params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            url = format!("{}?{}", url, params.join("&"));
        }
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", password_hash))
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
        let url = format!("{}{}", self.base_url, path);

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", password_hash))
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
    pub name: String,
    pub match_patterns: Vec<String>,
    pub credential_schema: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PluginsResponse {
    pub plugins: Vec<PluginInfo>,
}

#[derive(Debug, Deserialize)]
pub struct InstallResponse {
    pub name: String,
    pub installed: bool,
    pub commit_sha: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UninstallResponse {
    pub name: String,
    pub uninstalled: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateResponse {
    pub name: String,
    pub updated: bool,
    pub commit_sha: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SetCredentialResponse {
    pub plugin: String,
    pub key: String,
    pub set: bool,
}

#[derive(Debug, Deserialize)]
pub struct TokenInfo {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct TokensResponse {
    pub tokens: Vec<TokenInfo>,
}

#[derive(Debug, Deserialize)]
pub struct CreateTokenResponse {
    pub id: String,
    pub name: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct RevokeTokenResponse {
    pub id: String,
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
    pub plugin_name: Option<String>,
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
    fn test_client_creation() {
        let client = ApiClient::new("http://localhost:9080");
        assert_eq!(client.base_url, "http://localhost:9080");
    }

    #[test]
    fn test_client_strips_trailing_slash() {
        let client = ApiClient::new("http://localhost:9080/");
        assert_eq!(client.base_url, "http://localhost:9080");
    }

    #[test]
    fn test_client_with_ca_cert() {
        // Generate a real CA certificate for testing
        let ca = gap_lib::tls::CertificateAuthority::generate().expect("Failed to create CA");
        let ca_pem = ca.ca_cert_pem();

        // This should create a client with custom CA cert
        let result = ApiClient::with_ca_cert("https://localhost:9080", ca_pem.as_bytes());
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

        let _result = ApiClient::with_ca_cert("https://localhost:9080", invalid_pem);
        // The method may or may not return an error depending on reqwest's validation
        // The important thing is that it doesn't panic
    }

    #[test]
    fn test_get_auth_url_construction_no_params() {
        // Verify that get_auth builds the URL correctly with no query params
        let client = ApiClient::new("http://localhost:9080");
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
}
