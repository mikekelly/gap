//! HTTP client for Management API

use anyhow::{Context, Result};
use serde::Deserialize;

/// API client for ACP server
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

    /// POST request with authentication
    pub async fn post_auth<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        password_hash: &str,
        body: serde_json::Value,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        // Merge password_hash into body
        let mut body_with_auth = body;
        if let Some(obj) = body_with_auth.as_object_mut() {
            obj.insert("password_hash".to_string(), serde_json::Value::String(password_hash.to_string()));
        }

        let response = self
            .client
            .post(&url)
            .json(&body_with_auth)
            .send()
            .await
            .context("Failed to send request")?;

        self.handle_response(response).await
    }

    /// DELETE request with authentication
    pub async fn delete_auth<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        password_hash: &str,
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);

        let body = serde_json::json!({
            "password_hash": password_hash
        });

        let response = self
            .client
            .delete(&url)
            .json(&body)
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
}

#[derive(Debug, Deserialize)]
pub struct UninstallResponse {
    pub name: String,
    pub uninstalled: bool,
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
pub struct ActivityEntry {
    pub timestamp: String,
    pub agent: String,
    pub method: String,
    pub url: String,
    pub status: u16,
}

#[derive(Debug, Deserialize)]
pub struct ActivityResponse {
    pub entries: Vec<ActivityEntry>,
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
}
