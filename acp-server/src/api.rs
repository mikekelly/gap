//! Management API for ACP Server
//!
//! Provides HTTP endpoints for:
//! - Server status
//! - Plugin management
//! - Credential management
//! - Token management
//! - Activity monitoring

use acp_lib::AgentToken;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRequest, FromRequestParts, Path, Request, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// API server state
#[derive(Clone)]
pub struct ApiState {
    /// Server start time for uptime calculation
    pub start_time: std::time::Instant,
    /// Proxy port
    pub proxy_port: u16,
    /// API port
    pub api_port: u16,
    /// Password hash (Argon2)
    pub password_hash: Arc<RwLock<Option<String>>>,
    /// Stored agent tokens
    pub tokens: Arc<RwLock<HashMap<String, AgentToken>>>,
    /// Recent activity log
    pub activity: Arc<RwLock<Vec<ActivityEntry>>>,
}

impl ApiState {
    pub fn new(proxy_port: u16, api_port: u16) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            proxy_port,
            api_port,
            password_hash: Arc::new(RwLock::new(None)),
            tokens: Arc::new(RwLock::new(HashMap::new())),
            activity: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn set_password_hash(&self, hash: String) {
        *self.password_hash.write().await = Some(hash);
    }
}

/// Activity log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityEntry {
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub url: String,
    pub agent_id: Option<String>,
    pub status: u16,
}

/// Status response
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StatusResponse {
    pub version: String,
    pub uptime_seconds: u64,
    pub proxy_port: u16,
    pub api_port: u16,
}

/// Request body containing password_hash for authentication
#[derive(Debug, Deserialize, Clone)]
pub struct AuthenticatedRequest<T> {
    /// SHA512 hash of password (hex encoded)
    pub password_hash: String,
    #[serde(flatten)]
    pub data: T,
}

/// Extractor that validates authentication
pub struct Authenticated<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S> for Authenticated<T>
where
    S: Send + Sync,
    ApiState: FromRequestParts<S>,
    T: for<'de> Deserialize<'de>,
{
    type Rejection = (StatusCode, String);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();

        // Extract state
        let state = ApiState::from_request_parts(&mut parts, state)
            .await
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to extract state".to_string(),
                )
            })?;

        // Read body
        let bytes = Bytes::from_request(Request::from_parts(parts, body), state)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request body: {}", e)))?;

        // Parse as authenticated request
        let auth_req: AuthenticatedRequest<T> =
            serde_json::from_slice(&bytes).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid JSON: {}", e),
                )
            })?;

        // Verify password hash
        let stored_hash = state.password_hash.read().await;
        if let Some(ref hash_str) = *stored_hash {
            // Hash the provided SHA512 hash with Argon2 (stored hash is Argon2 of SHA512)
            let parsed_hash = PasswordHash::new(hash_str).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Invalid stored hash: {}", e),
                )
            })?;

            // The client sends SHA512(password), we verify Argon2(SHA512(password))
            Argon2::default()
                .verify_password(auth_req.password_hash.as_bytes(), &parsed_hash)
                .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()))?;

            Ok(Authenticated(auth_req.data))
        } else {
            Err((
                StatusCode::UNAUTHORIZED,
                "Server not initialized".to_string(),
            ))
        }
    }
}

/// Plugin list response
#[derive(Debug, Serialize)]
pub struct PluginsResponse {
    pub plugins: Vec<String>,
}

/// Token creation request
#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
}

/// Token response (includes full token only on creation)
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub token: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<AgentToken> for TokenResponse {
    fn from(token: AgentToken) -> Self {
        Self {
            id: token.id.clone(),
            name: token.name.clone(),
            prefix: token.prefix.clone(),
            token: None, // Don't expose token by default
            created_at: token.created_at,
        }
    }
}

/// Tokens list response
#[derive(Debug, Serialize)]
pub struct TokensResponse {
    pub tokens: Vec<TokenResponse>,
}

/// Credential set request
#[derive(Debug, Deserialize)]
pub struct SetCredentialRequest {
    pub value: String,
}

/// Activity response
#[derive(Debug, Serialize)]
pub struct ActivityResponse {
    pub entries: Vec<ActivityEntry>,
}

/// API error response
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
    }
}

/// Create the API router
pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/status", get(get_status))
        .route("/plugins", get(get_plugins))
        .route("/tokens", get(get_tokens).post(create_token))
        .route("/tokens/:id", delete(delete_token))
        .route(
            "/credentials/:plugin/:key",
            post(set_credential).delete(delete_credential),
        )
        .route("/activity", get(get_activity))
        .with_state(state)
}

/// GET /status - Server status (no auth required)
async fn get_status(State(state): State<ApiState>) -> Json<StatusResponse> {
    let uptime = state.start_time.elapsed().as_secs();

    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        proxy_port: state.proxy_port,
        api_port: state.api_port,
    })
}

/// GET /plugins - List installed plugins (requires auth)
async fn get_plugins(
    State(_state): State<ApiState>,
    Authenticated(_): Authenticated<serde_json::Value>,
) -> Json<PluginsResponse> {
    // TODO: Load from storage in future implementation
    Json(PluginsResponse {
        plugins: vec![],
    })
}

/// GET /tokens - List agent tokens (requires auth)
async fn get_tokens(
    State(state): State<ApiState>,
    Authenticated(_): Authenticated<serde_json::Value>,
) -> Json<TokensResponse> {
    let tokens = state.tokens.read().await;
    let token_list: Vec<TokenResponse> = tokens.values().map(|t| t.clone().into()).collect();

    Json(TokensResponse { tokens: token_list })
}

/// POST /tokens - Create new agent token (requires auth)
async fn create_token(
    State(state): State<ApiState>,
    Authenticated(req): Authenticated<CreateTokenRequest>,
) -> Json<TokenResponse> {
    let token = AgentToken::new(&req.name);
    let token_value = token.token.clone();

    // Store token
    let mut tokens = state.tokens.write().await;
    tokens.insert(token.id.clone(), token.clone());

    // Return with full token (only time it's revealed)
    Json(TokenResponse {
        id: token.id,
        name: token.name,
        prefix: token.prefix,
        token: Some(token_value),
        created_at: token.created_at,
    })
}

/// DELETE /tokens/:id - Revoke agent token (requires auth)
async fn delete_token(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Authenticated(_): Authenticated<serde_json::Value>,
) -> StatusCode {
    let mut tokens = state.tokens.write().await;
    if tokens.remove(&id).is_some() {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

/// POST /credentials/:plugin/:key - Set credential (requires auth)
async fn set_credential(
    State(_state): State<ApiState>,
    Path((plugin, key)): Path<(String, String)>,
    Authenticated(_req): Authenticated<SetCredentialRequest>,
) -> StatusCode {
    // TODO: Store in SecretStore in future implementation
    tracing::info!("Setting credential {}:{}", plugin, key);
    StatusCode::OK
}

/// DELETE /credentials/:plugin/:key - Delete credential (requires auth)
async fn delete_credential(
    State(_state): State<ApiState>,
    Path((plugin, key)): Path<(String, String)>,
    Authenticated(_): Authenticated<serde_json::Value>,
) -> StatusCode {
    // TODO: Delete from SecretStore in future implementation
    tracing::info!("Deleting credential {}:{}", plugin, key);
    StatusCode::OK
}

/// GET /activity - Get recent activity (requires auth)
async fn get_activity(
    State(state): State<ApiState>,
    Authenticated(_): Authenticated<serde_json::Value>,
) -> Json<ActivityResponse> {
    let activity = state.activity.read().await;
    Json(ActivityResponse {
        entries: activity.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    #[tokio::test]
    async fn test_get_status_without_auth() {
        let state = ApiState::new(9443, 9080);
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let status: StatusResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(status.proxy_port, 9443);
        assert_eq!(status.api_port, 9080);
        assert!(status.uptime_seconds < 10); // Should be very recent
    }

    #[tokio::test]
    async fn test_status_response_serialization() {
        let status = StatusResponse {
            version: "0.1.0".to_string(),
            uptime_seconds: 42,
            proxy_port: 9443,
            api_port: 9080,
        };

        let json = serde_json::to_string(&status).unwrap();
        let deserialized: StatusResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(status, deserialized);
    }
}
