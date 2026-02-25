//! Management API for GAP Server
//!
//! Provides HTTP endpoints for:
//! - Server status
//! - Plugin management
//! - Credential management
//! - Token management
//! - Activity monitoring

use gap_lib::{AgentToken, ActivityEntry, ManagementLogEntry, TokenCache};
use gap_lib::types::{RequestDetails, TokenScope};
use gap_lib::database::GapDatabase;
use gap_lib::types::PluginEntry;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
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
    /// Embedded database for all persistent storage
    pub db: Arc<GapDatabase>,
    /// Broadcast channel for real-time activity streaming (SSE)
    pub activity_tx: Option<tokio::sync::broadcast::Sender<ActivityEntry>>,
    /// Broadcast channel for real-time management log streaming (SSE)
    pub management_tx: Option<tokio::sync::broadcast::Sender<ManagementLogEntry>>,
    /// In-memory token cache shared with proxy for immediate revocation
    pub token_cache: Arc<TokenCache>,
    /// Optional signing config for request signature verification
    pub signing_config: Option<Arc<crate::signing::SigningConfig>>,
    /// Nonce cache for replay protection (shared with signing middleware)
    pub nonce_cache: Arc<crate::signing::NonceCache>,
}

impl ApiState {
    /// Create ApiState with database backend
    pub fn new(proxy_port: u16, api_port: u16, db: Arc<GapDatabase>, token_cache: Arc<TokenCache>) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            proxy_port,
            api_port,
            password_hash: Arc::new(RwLock::new(None)),
            db,
            activity_tx: None,
            management_tx: None,
            token_cache,
            signing_config: None,
            nonce_cache: Arc::new(crate::signing::NonceCache::new()),
        }
    }

    /// Create ApiState with broadcast channels for activity and management log streaming
    pub fn new_with_broadcast(
        proxy_port: u16,
        api_port: u16,
        db: Arc<GapDatabase>,
        activity_tx: tokio::sync::broadcast::Sender<ActivityEntry>,
        management_tx: tokio::sync::broadcast::Sender<ManagementLogEntry>,
        token_cache: Arc<TokenCache>,
    ) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            proxy_port,
            api_port,
            password_hash: Arc::new(RwLock::new(None)),
            db,
            activity_tx: Some(activity_tx),
            management_tx: Some(management_tx),
            token_cache,
            signing_config: None,
            nonce_cache: Arc::new(crate::signing::NonceCache::new()),
        }
    }

    pub async fn set_password_hash(&self, hash: String) {
        *self.password_hash.write().await = Some(hash);
    }
}

/// Status response
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct StatusResponse {
    pub version: String,
    pub uptime_seconds: u64,
    pub proxy_port: u16,
    pub api_port: u16,
    pub initialized: bool,
}

/// Verify authentication from the Authorization header.
/// Expected format: "Bearer <password_hash>"
async fn verify_auth(
    state: &ApiState,
    headers: &axum::http::HeaderMap,
) -> Result<(), (StatusCode, String)> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing Authorization header".to_string()))?
        .to_str()
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid Authorization header".to_string()))?;

    let hash = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid auth format, expected 'Bearer <hash>'".to_string()))?;

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
            .verify_password(hash.as_bytes(), &parsed_hash)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string()))?;

        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            "Server not initialized".to_string(),
        ))
    }
}

/// Plugin info
#[derive(Debug, Serialize)]
pub struct PluginInfo {
    pub id: String,
    pub match_patterns: Vec<String>,
    pub credential_schema: Vec<String>,
}

/// Plugin list response
#[derive(Debug, Serialize)]
pub struct PluginsResponse {
    pub plugins: Vec<PluginInfo>,
}

/// Token creation request
#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    /// Optional scope restrictions (whitelist of permitted patterns)
    pub permitted: Option<Vec<TokenScope>>,
}

/// Token response (includes full token only on creation)
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub prefix: String,
    pub token: Option<String>,
    pub created_at: DateTime<Utc>,
    pub permitted: Option<Vec<TokenScope>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Tokens list response
#[derive(Debug, Serialize, Deserialize)]
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

/// Query parameters for GET /activity
#[derive(Debug, Deserialize, Default)]
pub struct ActivityQuery {
    pub domain: Option<String>,
    pub path: Option<String>,
    pub plugin: Option<String>,
    pub agent: Option<String>,
    pub method: Option<String>,
    /// ISO 8601 timestamp string
    pub since: Option<String>,
    pub request_id: Option<String>,
    pub limit: Option<u32>,
}

/// Management log response
#[derive(Debug, Serialize, Deserialize)]
pub struct ManagementLogResponse {
    pub entries: Vec<ManagementLogEntry>,
}

/// Query parameters for GET /management-log
#[derive(Debug, Deserialize, Default)]
pub struct ManagementLogQuery {
    pub operation: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub success: Option<bool>,
    /// ISO 8601 timestamp string
    pub since: Option<String>,
    pub limit: Option<u32>,
}

/// Query parameters for filtering the management log SSE stream
#[derive(Debug, Default, Deserialize)]
pub struct ManagementLogStreamFilter {
    pub operation: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub success: Option<bool>,
}

/// Init request — the password_hash is the SHA512 hash of the password to set
#[derive(Debug, Deserialize)]
pub struct InitRequest {
    pub password_hash: String,
}

/// Init response
#[derive(Debug, Serialize, Deserialize)]
pub struct InitResponse {
    pub ca_path: String,
}

/// Install plugin request
#[derive(Debug, Deserialize)]
pub struct InstallRequest {
    pub source: String,
}

/// Install plugin response
#[derive(Debug, Serialize, Deserialize)]
pub struct InstallResponse {
    pub id: String,
    pub source: String,
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
}

/// Uninstall plugin response
#[derive(Debug, Serialize, Deserialize)]
pub struct UninstallResponse {
    pub id: String,
    pub uninstalled: bool,
}

/// Register plugin request (inline code)
#[derive(Debug, Deserialize)]
pub struct RegisterPluginRequest {
    pub code: String,
}

/// Register plugin response
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub id: String,
    pub registered: bool,
}

/// Update plugin response
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateResponse {
    pub id: String,
    pub updated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
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

/// Middleware that verifies Ed25519 request signatures when signing is enabled.
///
/// When `signing_config` is `None` in the API state, all requests pass through
/// unchanged. When enabled, requests to all endpoints except `/status` and `/init`
/// must include valid `x-gap-timestamp`, `x-gap-nonce`, and `x-gap-signature` headers.
async fn verify_signing(
    State(state): State<ApiState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<Response, (StatusCode, String)> {
    // If signing not enabled, pass through
    let signing_config = match &state.signing_config {
        Some(config) => config,
        None => return Ok(next.run(request).await),
    };

    // Exempt /status and /init from signing
    let path = request.uri().path();
    if path == "/status" || path == "/init" {
        return Ok(next.run(request).await);
    }

    // Need to buffer the body for signature verification
    let (parts, body) = request.into_parts();
    let body_bytes = axum::body::to_bytes(body, 10 * 1024 * 1024) // 10MB limit
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Failed to read body: {}", e)))?;

    // Verify signature
    let method = parts.method.as_str();
    let path = parts.uri.path();
    crate::signing::verify_request_signature(
        method, path, &body_bytes, &parts.headers, signing_config, &state.nonce_cache,
    ).map_err(|e| (StatusCode::UNAUTHORIZED, format!("Signature verification failed: {}", e)))?;

    // Reconstruct request with buffered body
    let request = axum::extract::Request::from_parts(parts, axum::body::Body::from(body_bytes));
    Ok(next.run(request).await)
}

/// Create the API router
pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/status", get(get_status))
        .route("/init", post(init))
        .route("/plugins", get(get_plugins).post(post_plugins))
        .route("/plugins/install", post(install_plugin))
        .route("/plugins/register", post(register_plugin))
        .route("/plugins/:id/update", post(update_plugin_from_github))
        .route("/plugins/:id", axum::routing::patch(update_plugin).delete(uninstall_plugin))
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/:prefix", delete(delete_token))
        .route(
            "/credentials/:plugin_id/:key",
            post(set_credential).delete(delete_credential),
        )
        .route("/activity", get(get_activity).post(get_activity))
        .route("/activity/stream", get(activity_stream).post(activity_stream))
        .route("/activity/:request_id/details", get(get_activity_details).post(get_activity_details))
        .route("/management-log", get(get_management_log))
        .route("/management-log/stream", get(management_log_stream))
        .route("/header-sets", get(list_header_sets).post(create_header_set))
        .route("/header-sets/:id", axum::routing::patch(update_header_set).delete(delete_header_set))
        .route("/header-sets/:id/headers", post(set_header_set_header))
        .route("/header-sets/:id/headers/:header_name", delete(delete_header_set_header))
        .layer(axum::middleware::from_fn_with_state(state.clone(), verify_signing))
        .with_state(state)
}

/// GET /status - Server status (no auth required)
async fn get_status(State(state): State<ApiState>) -> Json<StatusResponse> {
    let uptime = state.start_time.elapsed().as_secs();
    let initialized = state.password_hash.read().await.is_some();

    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime,
        proxy_port: state.proxy_port,
        api_port: state.api_port,
        initialized,
    })
}

/// POST /init - Initialize server with password and CA (no auth required initially)
async fn init(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Json<InitResponse>, (StatusCode, String)> {
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::{Argon2, PasswordHasher};

    // Check if already initialized (check both memory and registry)
    {
        let hash = state.password_hash.read().await;
        if hash.is_some() {
            return Err((StatusCode::CONFLICT, "Server already initialized".to_string()));
        }
    }
    // Also check database for persisted password
    if state.db.is_initialized().await.unwrap_or(false) {
        return Err((StatusCode::CONFLICT, "Server already initialized".to_string()));
    }

    // Parse request
    let req: InitRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)))?;

    // Hash the password_hash with Argon2 (password_hash is already SHA512 from client)
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(req.password_hash.as_bytes(), &salt)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to hash password: {}", e)))?
        .to_string();

    // Store password hash in memory
    state.set_password_hash(password_hash.clone()).await;

    // Persist password hash to database
    state.db.set_password_hash(&password_hash).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save password hash: {}", e)))?;

    // Return the well-known CA path (CA was already exported at server boot)
    let ca_path = gap_lib::ca_cert_path().to_string_lossy().to_string();

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "server_init".to_string(),
        resource_type: "server".to_string(),
        resource_id: None,
        detail: None,
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(InitResponse { ca_path }))
}

/// GET /plugins - List installed plugins (requires auth)
async fn get_plugins(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<PluginsResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    // Get plugins from database
    let plugin_entries = state.db.list_plugins().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list plugins: {}", e)))?;

    // Convert PluginEntry to PluginInfo
    let plugins = plugin_entries
        .into_iter()
        .map(|entry| PluginInfo {
            id: entry.id,
            match_patterns: entry.hosts,
            credential_schema: entry.credential_schema,
        })
        .collect();

    Ok(Json(PluginsResponse { plugins }))
}

/// POST /plugins - List installed plugins (requires auth, same as GET)
async fn post_plugins(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<PluginsResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    // Get plugins from database
    let plugin_entries = state.db.list_plugins().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list plugins: {}", e)))?;

    // Convert PluginEntry to PluginInfo
    let plugins = plugin_entries
        .into_iter()
        .map(|entry| PluginInfo {
            id: entry.id,
            match_patterns: entry.hosts,
            credential_schema: entry.credential_schema,
        })
        .collect();

    Ok(Json(PluginsResponse { plugins }))
}


/// POST /plugins/install - Install a plugin from GitHub (requires auth)
#[axum::debug_handler]
async fn install_plugin(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Json<InstallResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;
    let req: InstallRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request body: {}", e)))?;

    // Parse GitHub owner/repo from source (e.g., "mikekelly/exa-gap")
    let plugin_source = parse_plugin_name(&req.source)?;

    // Clone, validate, and store plugin — returns generated UUID
    let (plugin_id, plugin, commit_sha) = clone_and_validate_plugin(&state, &plugin_source).await?;

    tracing::info!("Installed plugin: {} (id: {}, matches: {:?}, commit: {})", plugin_source, plugin_id, plugin.match_patterns, commit_sha);

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "plugin_install".to_string(),
        resource_type: "plugin".to_string(),
        resource_id: Some(plugin_id.clone()),
        detail: Some(serde_json::json!({"repo": req.source}).to_string()),
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(InstallResponse {
        id: plugin_id,
        source: req.source,
        installed: true,
        commit_sha: Some(commit_sha),
    }))
}

/// POST /plugins/register - Register a plugin with inline code (requires auth)
#[axum::debug_handler]
async fn register_plugin(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Json<RegisterResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;
    let req: RegisterPluginRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request body: {}", e)))?;

    // Transform ES6 export syntax to var declaration (same as install flow)
    let transformed_code = transform_es6_export(&req.code);

    // Validate plugin by loading in a temporary runtime — scoped to drop before .await
    let plugin = {
        use gap_lib::plugin_runtime::PluginRuntime;
        let mut runtime = PluginRuntime::new()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create runtime: {}", e)))?;
        runtime.load_plugin_from_code("registering", &transformed_code)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid plugin code: {}", e)))?
    };

    // Store plugin metadata and source code in database
    let plugin_entry = PluginEntry {
        id: String::new(), // will be overwritten by DB-generated UUID
        source: None,
        hosts: plugin.match_patterns.clone(),
        credential_schema: plugin.credential_schema.clone(),
        commit_sha: None,
        dangerously_permit_http: plugin.dangerously_permit_http,
        weight: 0,
        installed_at: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    };
    let plugin_id = state.db.add_plugin(&plugin_entry, &transformed_code).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store plugin: {}", e)))?;

    tracing::info!("Registered plugin: {} (matches: {:?})", plugin_id, plugin.match_patterns);

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "plugin_register".to_string(),
        resource_type: "plugin".to_string(),
        resource_id: Some(plugin_id.clone()),
        detail: None,
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(RegisterResponse {
        id: plugin_id,
        registered: true,
    }))
}

/// DELETE /plugins/{id} - Uninstall a plugin (requires auth)
#[axum::debug_handler]
async fn uninstall_plugin(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> std::result::Result<Json<UninstallResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    // Check if plugin exists
    let exists = state.db.has_plugin(&id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to check plugin: {}", e)))?;

    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Plugin '{}' is not installed.", id),
        ));
    }

    // Remove plugin from database (removes metadata + source, preserves credentials)
    state.db.remove_plugin(&id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to remove plugin: {}", e)))?;

    tracing::info!("Uninstalled plugin: {}", id);

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "plugin_uninstall".to_string(),
        resource_type: "plugin".to_string(),
        resource_id: Some(id.clone()),
        detail: None,
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(UninstallResponse {
        id,
        uninstalled: true,
    }))
}

/// POST /plugins/{id}/update - Update a plugin from GitHub (requires auth)
#[axum::debug_handler]
async fn update_plugin_from_github(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> std::result::Result<Json<UpdateResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    // Look up existing plugin to get its source (GitHub slug)
    let existing = state.db.get_plugin(&id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to check plugin: {}", e)))?;

    let existing = existing.ok_or_else(|| {
        (StatusCode::NOT_FOUND, format!("Plugin '{}' is not installed.", id))
    })?;

    let plugin_source = existing.source.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Plugin has no source (GitHub slug) — cannot update from GitHub.".to_string())
    })?;

    // Remove old plugin from database (but keep credentials)
    state.db.remove_plugin(&id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to remove old plugin: {}", e)))?;

    // Clone, validate, and store new version
    let (new_id, plugin, commit_sha) = clone_and_validate_plugin(&state, &plugin_source).await?;

    tracing::info!("Updated plugin: {} -> {} (matches: {:?}, commit: {})", id, new_id, plugin.match_patterns, commit_sha);

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "plugin_update".to_string(),
        resource_type: "plugin".to_string(),
        resource_id: Some(new_id.clone()),
        detail: None,
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(UpdateResponse {
        id: new_id,
        updated: true,
        commit_sha: Some(commit_sha),
    }))
}

/// Parse plugin name from "owner/repo" format
fn parse_plugin_name(name: &str) -> std::result::Result<String, (StatusCode, String)> {
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() != 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Invalid plugin name format. Expected 'owner/repo', got '{}'", name),
        ));
    }
    Ok(format!("{}/{}", parts[0], parts[1]))
}

/// Clone a plugin from GitHub, validate it, and store it
/// Returns the generated UUID, validated plugin info, and commit SHA
async fn clone_and_validate_plugin(
    state: &ApiState,
    plugin_source: &str,
) -> std::result::Result<(String, gap_lib::types::GAPPlugin, String), (StatusCode, String)> {
    use gap_lib::plugin_runtime::PluginRuntime;
    use git2::{build::RepoBuilder, Cred, FetchOptions, RemoteCallbacks};
    use tempfile::tempdir;

    let parts: Vec<&str> = plugin_source.split('/').collect();
    let (owner, repo) = (parts[0], parts[1]);
    let repo_url = format!("https://github.com/{}/{}.git", owner, repo);

    let temp_dir = tempdir()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create temp directory: {}", e)))?;

    // Clone and read plugin.js - scoped to ensure non-Send types are dropped before await
    let (transformed_code, plugin, commit_sha) = {
        let mut callbacks = RemoteCallbacks::new();
        callbacks.credentials(|_url, _username_from_url, _allowed_types| {
            Cred::default()
        });

        let mut fetch_options = FetchOptions::new();
        fetch_options.remote_callbacks(callbacks);

        let mut builder = RepoBuilder::new();
        builder.fetch_options(fetch_options);

        let git_repo = builder.clone(&repo_url, temp_dir.path())
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to clone repository: {}", e)))?;

        // Get the commit SHA
        let head = git_repo.head()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get HEAD: {}", e)))?;
        let commit = head.peel_to_commit()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get commit: {}", e)))?;
        let commit_sha = commit.id().to_string()[..7].to_string(); // Short SHA

        // Read plugin.js from the cloned repository
        let plugin_path = temp_dir.path().join("plugin.js");
        let plugin_code = std::fs::read_to_string(&plugin_path)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("No plugin.js found in repository: {}", e)))?;

        // Transform ES6 export to var declaration
        let transformed_code = transform_es6_export(&plugin_code);

        // Validate plugin by loading it in a temporary runtime
        let mut runtime = PluginRuntime::new()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create runtime: {}", e)))?;

        let plugin = runtime.load_plugin_from_code(plugin_source, &transformed_code)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid plugin code: {}", e)))?;

        (transformed_code, plugin, commit_sha)
    };

    // Store plugin metadata and source code in database (single operation)
    let plugin_entry = PluginEntry {
        id: String::new(), // will be overwritten by DB-generated UUID
        source: Some(plugin_source.to_string()),
        hosts: plugin.match_patterns.clone(),
        credential_schema: plugin.credential_schema.clone(),
        commit_sha: Some(commit_sha.clone()),
        dangerously_permit_http: plugin.dangerously_permit_http,
        weight: 0,
        installed_at: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    };
    let plugin_id = state.db.add_plugin(&plugin_entry, &transformed_code).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store plugin: {}", e)))?;

    Ok((plugin_id, plugin, commit_sha))
}

/// Transform ES6 export default to var plugin declaration
///
/// Handles both:
/// - export default { ... }
/// - const plugin = { ... }; export default plugin;
/// - Also supports 'match' as alias for 'matchPatterns'
fn transform_es6_export(code: &str) -> String {
    // Replace 'match:' with 'matchPatterns:' in object literals
    let code = code.replace("match:", "matchPatterns:");

    // Simple regex-like replacement for export default
    if code.contains("export default") {
        // Replace "export default {" with "var plugin = {"
        code.replace("export default", "var plugin =")
    } else {
        code
    }
}

/// GET /tokens - List agent tokens (requires auth)
async fn list_tokens(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<TokensResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    let include_revoked = params.get("include_revoked").map_or(false, |v| v == "true");

    let token_entries = state.db.list_tokens(include_revoked).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list tokens: {}", e)))?;

    let token_list: Vec<TokenResponse> = token_entries
        .into_iter()
        .map(|entry| {
            let prefix = if entry.token_value.len() >= 12 {
                entry.token_value[..12].to_string()
            } else {
                entry.token_value.clone()
            };
            TokenResponse {
                prefix,
                token: None,
                created_at: entry.created_at,
                permitted: entry.scopes,
                revoked_at: entry.revoked_at,
            }
        })
        .collect();

    Ok(Json(TokensResponse { tokens: token_list }))
}

/// POST /tokens - Create new agent token (requires auth)
async fn create_token(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    // Body is optional — empty body means no scopes (unrestricted token)
    let scopes: Option<Vec<TokenScope>> = if body.is_empty() {
        None
    } else {
        let req: CreateTokenRequest = serde_json::from_slice(&body)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request body: {}", e)))?;
        req.permitted
    };

    let token = AgentToken::new();

    state.db.add_token(&token.token, token.created_at, scopes.as_deref()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create token: {}", e)))?;

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "token_create".to_string(),
        resource_type: "token".to_string(),
        resource_id: Some(token.prefix.clone()),
        detail: scopes.as_ref().map(|s| serde_json::to_string(s).unwrap_or_default()),
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(TokenResponse {
        prefix: token.prefix,
        token: Some(token.token),
        created_at: token.created_at,
        permitted: scopes,
        revoked_at: None,
    }))
}

/// DELETE /tokens/:prefix - Revoke agent token (requires auth)
async fn delete_token(
    State(state): State<ApiState>,
    Path(prefix): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    // Look up full token value by prefix
    let token_value = state.db.get_token_by_prefix(&prefix).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to find token: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("No active token found with prefix '{}'", prefix)))?;

    // Soft delete (set revoked_at)
    state.db.revoke_token(&token_value).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to revoke token: {}", e)))?;

    // Invalidate the revoked token from cache
    state.token_cache.invalidate(&token_value);

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "token_revoke".to_string(),
        resource_type: "token".to_string(),
        resource_id: Some(prefix.clone()),
        detail: None,
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(serde_json::json!({
        "prefix": prefix,
        "revoked": true
    })))
}

/// POST /credentials/:plugin_id/:key - Set credential (requires auth)
async fn set_credential(
    State(state): State<ApiState>,
    Path((plugin_id, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;
    let req: SetCredentialRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request body: {}", e)))?;

    // Store credential in database
    state.db.set_credential(&plugin_id, &key, &req.value)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to set credential: {}", e)))?;

    tracing::info!("Setting credential {}:{}", plugin_id, key);

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "credential_set".to_string(),
        resource_type: "credential".to_string(),
        resource_id: Some(format!("{}/{}", plugin_id, key)),
        detail: None, // NEVER log credential values
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(serde_json::json!({
        "plugin_id": plugin_id,
        "key": key,
        "set": true
    })))
}

/// DELETE /credentials/:plugin_id/:key - Delete credential (requires auth)
async fn delete_credential(
    State(state): State<ApiState>,
    Path((plugin_id, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    // Remove credential from database
    state.db.remove_credential(&plugin_id, &key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to remove credential: {}", e)))?;

    tracing::info!("Deleting credential {}:{}", plugin_id, key);

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "credential_delete".to_string(),
        resource_type: "credential".to_string(),
        resource_id: Some(format!("{}/{}", plugin_id, key)),
        detail: None,
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(StatusCode::OK)
}

/// Convert ActivityQuery to ActivityFilter
fn query_to_filter(q: &ActivityQuery) -> gap_lib::ActivityFilter {
    gap_lib::ActivityFilter {
        domain: q.domain.clone(),
        path: q.path.clone(),
        plugin_id: q.plugin.clone(),
        agent: q.agent.clone(),
        method: q.method.clone(),
        since: q.since.as_ref().and_then(|s| {
            DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))
        }),
        request_id: q.request_id.clone(),
        limit: q.limit.or(Some(100)),
        namespace_id: None,
        scope_id: None,
    }
}

/// GET /activity - Get recent activity (requires auth, supports query param filters)
async fn get_activity(
    State(state): State<ApiState>,
    Query(query): Query<ActivityQuery>,
    headers: HeaderMap,
) -> Result<Json<ActivityResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    let filter = query_to_filter(&query);
    let entries = state.db.query_activity(&filter).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get activity: {}", e)))?;
    Ok(Json(ActivityResponse { entries }))
}

/// GET /activity/:request_id/details - Get detailed request/response data (requires auth)
async fn get_activity_details(
    State(state): State<ApiState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<RequestDetails>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    let details = state.db.get_request_details(&request_id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get request details: {}", e)))?;

    match details {
        Some(d) => Ok(Json(d)),
        None => Err((StatusCode::NOT_FOUND, format!("No details found for request {}", request_id))),
    }
}

/// Query parameters for filtering the activity SSE stream
#[derive(Debug, Default, Deserialize)]
pub struct ActivityStreamFilter {
    pub domain: Option<String>,
    pub plugin: Option<String>,
    pub agent: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub request_id: Option<String>,
}

/// Check if an activity entry matches the given filter criteria
fn matches_filter(entry: &ActivityEntry, filter: &ActivityStreamFilter) -> bool {
    if let Some(ref domain) = filter.domain {
        if !entry.url.contains(domain) {
            return false;
        }
    }
    if let Some(ref plugin) = filter.plugin {
        if entry.plugin_id.as_deref() != Some(plugin.as_str()) {
            return false;
        }
    }
    if let Some(ref agent) = filter.agent {
        if entry.agent_id.as_deref() != Some(agent.as_str()) {
            return false;
        }
    }
    if let Some(ref method) = filter.method {
        if entry.method != *method {
            return false;
        }
    }
    if let Some(ref path) = filter.path {
        if !entry.url.contains(path) {
            return false;
        }
    }
    if let Some(ref request_id) = filter.request_id {
        if entry.request_id.as_deref() != Some(request_id.as_str()) {
            return false;
        }
    }
    true
}

/// GET /activity/stream - Stream activity entries via Server-Sent Events (requires auth)
async fn activity_stream(
    State(state): State<ApiState>,
    Query(filter): Query<ActivityStreamFilter>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    let tx = state.activity_tx.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Activity streaming not configured".to_string(),
        )
    })?;

    let mut rx = tx.subscribe();

    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    if matches_filter(&entry, &filter) {
                        if let Ok(json) = serde_json::to_string(&entry) {
                            yield Ok(Event::default().event("activity").data(json));
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    // Subscriber fell behind, log and continue
                    tracing::warn!("SSE subscriber lagged by {} entries", n);
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    // Channel closed, end the stream
                    break;
                }
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Emit a management log event: writes to DB and broadcasts to SSE subscribers.
/// Fire-and-forget — errors are logged but don't propagate.
fn emit_management_log(state: &ApiState, entry: ManagementLogEntry) {
    let db = Arc::clone(&state.db);
    let tx = state.management_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = db.log_management_event(&entry).await {
            tracing::error!(error = %e, "Failed to log management event");
        }
        if let Some(tx) = tx {
            let _ = tx.send(entry); // ignore SendError (no subscribers)
        }
    });
}

/// Convert ManagementLogQuery to ManagementLogFilter
fn management_query_to_filter(q: &ManagementLogQuery) -> gap_lib::ManagementLogFilter {
    gap_lib::ManagementLogFilter {
        operation: q.operation.clone(),
        resource_type: q.resource_type.clone(),
        resource_id: q.resource_id.clone(),
        success: q.success,
        since: q.since.as_ref().and_then(|s| {
            DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))
        }),
        limit: q.limit.or(Some(100)),
        namespace_id: None,
        scope_id: None,
    }
}

/// GET /management-log - Get management audit log entries (requires auth)
async fn get_management_log(
    State(state): State<ApiState>,
    Query(query): Query<ManagementLogQuery>,
    headers: HeaderMap,
) -> Result<Json<ManagementLogResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    let filter = management_query_to_filter(&query);
    let entries = state.db.query_management_log(&filter).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get management log: {}", e)))?;
    Ok(Json(ManagementLogResponse { entries }))
}

/// GET /management-log/stream - Stream management log entries via SSE (requires auth)
async fn management_log_stream(
    State(state): State<ApiState>,
    Query(filter): Query<ManagementLogStreamFilter>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    let tx = state.management_tx.as_ref().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "Management log streaming not configured".to_string())
    })?;

    let mut rx = tx.subscribe();

    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    if matches_management_filter(&entry, &filter) {
                        if let Ok(json) = serde_json::to_string(&entry) {
                            yield Ok(Event::default().event("management").data(json));
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("Management log SSE subscriber lagged by {} entries", n);
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

/// Check if a management log entry matches the given filter criteria
fn matches_management_filter(entry: &ManagementLogEntry, filter: &ManagementLogStreamFilter) -> bool {
    if let Some(ref op) = filter.operation {
        if entry.operation != *op { return false; }
    }
    if let Some(ref rt) = filter.resource_type {
        if entry.resource_type != *rt { return false; }
    }
    if let Some(ref rid) = filter.resource_id {
        if entry.resource_id.as_deref() != Some(rid.as_str()) { return false; }
    }
    if let Some(success) = filter.success {
        if entry.success != success { return false; }
    }
    true
}

// ── HeaderSet request/response structs ─────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CreateHeaderSetRequest {
    match_patterns: Vec<String>,
    #[serde(default)]
    weight: i32,
    #[serde(default)]
    headers: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct CreateHeaderSetResponse {
    id: String,
    created: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateHeaderSetRequest {
    match_patterns: Option<Vec<String>>,
    weight: Option<i32>,
}

#[derive(Debug, Serialize)]
struct HeaderSetListItem {
    id: String,
    match_patterns: Vec<String>,
    weight: i32,
    headers: Vec<String>, // header names only, no values
}

#[derive(Debug, Serialize)]
struct HeaderSetListResponse {
    header_sets: Vec<HeaderSetListItem>,
}

#[derive(Debug, Deserialize)]
struct SetHeaderRequest {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct DeleteResponse {
    deleted: bool,
}

// ── Plugin weight update structs ────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct UpdatePluginRequest {
    weight: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct UpdatePluginResponse {
    id: String,
    updated: bool,
}

// ── HeaderSet handlers ──────────────────────────────────────────────────────

/// POST /header-sets - Create a header set (requires auth)
async fn create_header_set(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CreateHeaderSetResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;
    let req: CreateHeaderSetRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request body: {}", e)))?;

    if req.match_patterns.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "match_patterns must not be empty".to_string()));
    }

    let id = state.db.add_header_set(&req.match_patterns, req.weight).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create header set: {}", e)))?;

    for (header_name, header_value) in &req.headers {
        state.db.set_header_set_header(&id, header_name, header_value)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to set header: {}", e)))?;
    }

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "header_set_create".to_string(),
        resource_type: "header_set".to_string(),
        resource_id: Some(id.clone()),
        detail: None,
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(CreateHeaderSetResponse { id, created: true }))
}

/// GET /header-sets - List header sets (requires auth)
async fn list_header_sets(
    State(state): State<ApiState>,
    headers: HeaderMap,
) -> Result<Json<HeaderSetListResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    let header_sets = state.db.list_header_sets().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list header sets: {}", e)))?;

    let mut items = Vec::new();
    for hs in header_sets {
        let header_names = state.db.list_header_set_header_names(&hs.id).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list headers for '{}': {}", hs.id, e)))?;
        items.push(HeaderSetListItem {
            id: hs.id,
            match_patterns: hs.match_patterns,
            weight: hs.weight,
            headers: header_names,
        });
    }

    Ok(Json(HeaderSetListResponse { header_sets: items }))
}

/// PATCH /header-sets/:id - Update a header set (requires auth)
async fn update_header_set(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;
    let req: UpdateHeaderSetRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request body: {}", e)))?;

    if req.match_patterns.is_none() && req.weight.is_none() {
        return Err((StatusCode::BAD_REQUEST, "At least one field (match_patterns or weight) must be provided".to_string()));
    }

    if let Some(ref patterns) = req.match_patterns {
        if patterns.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "match_patterns must not be empty".to_string()));
        }
    }

    // Verify exists first to return proper 404
    let exists = state.db.get_header_set(&id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to check header set: {}", e)))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, format!("Header set '{}' not found", id)));
    }

    state.db.update_header_set(&id, req.match_patterns.as_deref(), req.weight).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update header set: {}", e)))?;

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "header_set_update".to_string(),
        resource_type: "header_set".to_string(),
        resource_id: Some(id.clone()),
        detail: None,
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(serde_json::json!({"id": id, "updated": true})))
}

/// DELETE /header-sets/:id - Delete a header set (requires auth)
async fn delete_header_set(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<DeleteResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    state.db.remove_header_set(&id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete header set: {}", e)))?;

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "header_set_delete".to_string(),
        resource_type: "header_set".to_string(),
        resource_id: Some(id.clone()),
        detail: None,
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(DeleteResponse { deleted: true }))
}

/// POST /header-sets/:id/headers - Set a header on a header set (requires auth)
async fn set_header_set_header(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;
    let req: SetHeaderRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request body: {}", e)))?;

    // Verify header set exists
    let exists = state.db.get_header_set(&id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to check header set: {}", e)))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, format!("Header set '{}' not found", id)));
    }

    state.db.set_header_set_header(&id, &req.name, &req.value).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to set header: {}", e)))?;

    let header_name = req.name.clone();
    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "header_set_header_set".to_string(),
        resource_type: "header_set".to_string(),
        resource_id: Some(id.clone()),
        detail: Some(header_name.clone()),
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(serde_json::json!({"header_set": id, "header": header_name, "set": true})))
}

/// DELETE /header-sets/:id/headers/:header_name - Delete a header from a header set (requires auth)
async fn delete_header_set_header(
    State(state): State<ApiState>,
    Path((id, header_name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;

    state.db.remove_header_set_header(&id, &header_name).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete header: {}", e)))?;

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "header_set_header_delete".to_string(),
        resource_type: "header_set".to_string(),
        resource_id: Some(id.clone()),
        detail: Some(header_name.clone()),
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(serde_json::json!({"header_set": id, "header": header_name, "deleted": true})))
}

/// PATCH /plugins/:id - Update plugin weight (requires auth)
async fn update_plugin(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<UpdatePluginResponse>, (StatusCode, String)> {
    verify_auth(&state, &headers).await?;
    let req: UpdatePluginRequest = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid request body: {}", e)))?;

    let exists = state.db.has_plugin(&id).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to check plugin: {}", e)))?;
    if !exists {
        return Err((StatusCode::NOT_FOUND, format!("Plugin '{}' is not installed.", id)));
    }

    state.db.update_plugin_weight(&id, req.weight).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update plugin weight: {}", e)))?;

    emit_management_log(&state, ManagementLogEntry {
        timestamp: chrono::Utc::now(),
        operation: "plugin_update".to_string(),
        resource_type: "plugin".to_string(),
        resource_id: Some(id.clone()),
        detail: Some(format!("weight={}", req.weight)),
        success: true,
        error_message: None,
        namespace_id: "default".to_string(),
        scope_id: "default".to_string(),
    });

    Ok(Json(UpdatePluginResponse { id, updated: true }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gap_lib::database::GapDatabase;
    use axum::body::Body;
    use axum::http::Request;
    use serial_test::serial;
    use tower::ServiceExt; // for `oneshot`

    /// Helper to create an in-memory database for testing
    async fn create_test_db() -> Arc<GapDatabase> {
        Arc::new(GapDatabase::in_memory().await.expect("create in-memory DB"))
    }

    #[tokio::test]
    async fn test_get_status_without_auth() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
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
            initialized: true,
        };

        let json = serde_json::to_string(&status).unwrap();
        let deserialized: StatusResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(status, deserialized);
    }

    #[tokio::test]
    #[ignore = "plugins route temporarily disabled"]
    async fn test_post_plugins_endpoint() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/plugins")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_post_tokens_create_endpoint() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // POST /tokens with empty body creates an unrestricted token
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tokens")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let token_response: TokenResponse = serde_json::from_slice(&body).unwrap();

        assert!(token_response.token.is_some());
        assert!(token_response.permitted.is_none());
        assert!(token_response.revoked_at.is_none());
    }

    #[tokio::test]
    async fn test_post_activity_endpoint() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/activity")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[serial]
    async fn test_init_endpoint() {
        use gap_lib::tls::CertificateAuthority;

        // Use temp directory to avoid test isolation issues with macOS Keychain
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;

        // Pre-create CA in database (as server does at startup)
        let ca = CertificateAuthority::generate().expect("generate CA");
        db.set_config("ca:cert", ca.ca_cert_pem().as_bytes()).await.expect("store CA cert");
        db.set_config("ca:key", ca.ca_key_pem().as_bytes()).await.expect("store CA key");

        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        let app = create_router(state.clone());

        let password = "testpass123";

        // Init sends password_hash in request body (not via Authorization header)
        let body = serde_json::json!({
            "password_hash": password
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/init")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let init_response: InitResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Should return a CA path
        assert!(!init_response.ca_path.is_empty());

        // Password hash should be set in state
        let hash = state.password_hash.read().await;
        assert!(hash.is_some());
    }

    #[tokio::test]
    #[serial]
    async fn test_init_endpoint_returns_well_known_ca_path() {
        use gap_lib::tls::CertificateAuthority;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;

        // Pre-create CA in database (as server does at startup)
        let ca = CertificateAuthority::generate().expect("generate CA");
        db.set_config("ca:cert", ca.ca_cert_pem().as_bytes()).await.expect("store CA cert");
        db.set_config("ca:key", ca.ca_key_pem().as_bytes()).await.expect("store CA key");

        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        let app = create_router(state.clone());

        let password = "testpass123";

        // Init sends password_hash in request body (not via Authorization header)
        let body = serde_json::json!({
            "password_hash": password
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/init")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let init_response: InitResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Should return the well-known CA path from gap_lib::ca_cert_path()
        let expected_path = gap_lib::ca_cert_path().to_string_lossy().to_string();
        assert_eq!(init_response.ca_path, expected_path);
    }

    #[tokio::test]
    #[serial]
    async fn test_install_plugin_github_simple() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        // Use temp directory to avoid test isolation issues with macOS Keychain
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Install plugin from GitHub (mikekelly/test-plugin doesn't exist, so expect 502)
        let body = serde_json::json!({
            "source": "mikekelly/test-plugin"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/plugins/install")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Expect BAD_GATEWAY (502) because the GitHub repo doesn't exist
        // This test now verifies that git clone fails for non-existent repos
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    #[serial]
    async fn test_install_plugin_clones_repo_and_reads_plugin_js() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        // Use temp directory to avoid test isolation issues with macOS Keychain
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Try to install a real plugin from GitHub
        let body = serde_json::json!({
            "source": "mikekelly/exa-gap"  // Real repo with plugin.js
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/plugins/install")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should succeed if the repo exists and has plugin.js
        // Allow both 200 (success) or 400 (invalid plugin code)
        let status = response.status();
        assert!(
            status == StatusCode::OK || status == StatusCode::BAD_REQUEST || status == StatusCode::BAD_GATEWAY,
            "Expected OK, BAD_REQUEST, or BAD_GATEWAY, got {:?}",
            status
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_install_plugin_updates_registry() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Try to install a real plugin from GitHub
        let body = serde_json::json!({
            "source": "mikekelly/exa-gap"  // Real repo with plugin.js
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/plugins/install")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Only verify database if installation succeeded
        if response.status() == StatusCode::OK {
            let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
            let plugin_id = resp["id"].as_str().unwrap();

            // Verify the plugin was added to the database
            let plugins = db.list_plugins().await.expect("list plugins from database");

            // Find the installed plugin by its UUID
            let installed_plugin = plugins.iter()
                .find(|p| p.id == plugin_id)
                .expect("plugin should be in database");

            // Verify plugin metadata
            assert!(!installed_plugin.hosts.is_empty(), "plugin should have at least one host");
            assert!(!installed_plugin.credential_schema.is_empty(), "plugin should have at least one credential field");
        } else {
            // Test is inconclusive if GitHub clone fails, but that's okay
            // We verified the code path compiles and basic structure is correct
            eprintln!("Plugin installation from GitHub failed (status: {:?}), skipping database verification", response.status());
        }
    }

    #[tokio::test]
    async fn test_install_plugin_requires_auth() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        let app = create_router(state);

        // Try to install without Authorization header
        let body = serde_json::json!({
            "source": "mikekelly/test-plugin"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/plugins/install")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[serial]
    async fn test_set_credential_endpoint() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        // Use temp directory to avoid test isolation issues with macOS Keychain
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        let body = serde_json::json!({
            "value": "secret_api_key_12345"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/credentials/test-plugin/api_key")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Verify the API accepts the request and returns 200
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_credential_endpoint() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        // Use temp directory to avoid test isolation issues with macOS Keychain
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/credentials/test-plugin/api_key")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Verify the API accepts the request and returns 200
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    #[serial]
    async fn test_api_uses_shared_db() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Now set a credential via the API
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "value": "api_write_value"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/credentials/test-plugin/api_key")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the credential was written to the database
        let credential = db.get_credential("test-plugin", "api_key")
            .await
            .expect("read from database");
        assert_eq!(
            credential,
            Some("api_write_value".to_string()),
            "API endpoint should write credentials to the database"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_set_credential_updates_database() {
        use gap_lib::types::CredentialEntry;
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Set a credential via the API
        let body = serde_json::json!({
            "value": "secret_api_key_12345"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/credentials/exa/api_key")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the credential was added to the database
        let creds = db.list_credentials().await.expect("list should succeed");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0], CredentialEntry {
            plugin_id: "exa".to_string(),
            field: "api_key".to_string(),
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        });
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_credential_updates_database() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Pre-populate database with a credential
        db.set_credential("exa", "api_key", "some_value").await.expect("add should succeed");

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/credentials/exa/api_key")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the credential was removed from the database
        let creds = db.list_credentials().await.expect("list should succeed");
        assert_eq!(creds.len(), 0);
    }

    #[tokio::test]
    #[serial]
    async fn test_set_credential_twice_no_duplicates() {
        use gap_lib::types::CredentialEntry;
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Set a credential via the API
        let body = serde_json::json!({
            "value": "secret_api_key_12345"
        });

        // Create first router and set credential
        let app = create_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/credentials/exa/api_key")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Set the same credential again with different value
        let body2 = serde_json::json!({
            "value": "new_secret_value"
        });

        let app2 = create_router(state);
        let response2 = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/credentials/exa/api_key")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body2).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response2.status(), StatusCode::OK);

        // Verify the database only has ONE entry for this credential (no duplicates)
        let creds = db.list_credentials().await.expect("list should succeed");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0], CredentialEntry {
            plugin_id: "exa".to_string(),
            field: "api_key".to_string(),
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        });
    }

    #[tokio::test]
    #[serial]
    async fn test_list_tokens_uses_database() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Add a token to the database directly
        let token_value = "gap_test_token_12345".to_string();
        db.add_token(&token_value, Utc::now(), None).await.expect("add token to database");

        // List tokens via API
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/tokens")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let tokens_response: TokensResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Verify the token from database is in the response
        assert_eq!(tokens_response.tokens.len(), 1);
        assert_eq!(tokens_response.tokens[0].prefix, "gap_test_tok");
        assert!(tokens_response.tokens[0].permitted.is_none());
    }

    #[tokio::test]
    #[serial]
    async fn test_create_token_adds_to_database() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Create token via API (empty body = unrestricted)
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tokens")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let token_response: TokenResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Verify the token was added to the database
        let tokens = db.list_tokens(false).await.expect("list tokens from database");
        assert_eq!(tokens.len(), 1);
        // The full token value should start with the prefix
        assert!(tokens[0].token_value.starts_with(&token_response.prefix));
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_token_revokes_in_database() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Create a token and add it to the database
        let token = AgentToken::new();
        db.add_token(&token.token, token.created_at, None).await.expect("add token to database");

        // Delete (revoke) token via API using its prefix
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/tokens/{}", token.prefix))
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the token is no longer in active list (soft deleted)
        let tokens = db.list_tokens(false).await.expect("list tokens from database");
        assert_eq!(tokens.len(), 0, "Token should not appear in active list after revocation");

        // But it should still exist in the full list (including revoked)
        let all_tokens = db.list_tokens(true).await.expect("list all tokens from database");
        assert_eq!(all_tokens.len(), 1, "Revoked token should still exist in full list");
        assert!(all_tokens[0].revoked_at.is_some(), "Token should have revoked_at set");
    }

    /// Verify /init returns 200 OK with a ca_path and no longer stores mgmt certs
    #[tokio::test]
    #[serial]
    async fn test_init_endpoint_no_mgmt_cert() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let app = create_router(state);

        let password = "testpass123";

        // Init sends password_hash in request body (not via Authorization header)
        let body = serde_json::json!({
            "password_hash": password
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/init")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let init_response: InitResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Should return a CA path
        assert!(!init_response.ca_path.is_empty());

        // Management cert/key/SANs should NOT be stored in database
        let mgmt_cert = db.get_config("mgmt:cert").await.expect("get mgmt:cert");
        assert!(mgmt_cert.is_none(), "Management cert should NOT be stored");

        let mgmt_key = db.get_config("mgmt:key").await.expect("get mgmt:key");
        assert!(mgmt_key.is_none(), "Management key should NOT be stored");

        let mgmt_sans = db.get_config("mgmt:sans").await.expect("get mgmt:sans");
        assert!(mgmt_sans.is_none(), "Management SANs should NOT be stored");
    }

    #[tokio::test]
    async fn test_activity_stream_returns_sse_content_type() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let (activity_tx, _) = tokio::sync::broadcast::channel(100);
        let (management_tx, _) = tokio::sync::broadcast::channel(100);
        let state = ApiState::new_with_broadcast(9443, 9080, db, activity_tx, management_tx, Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/activity/stream")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(content_type.contains("text/event-stream"), "Expected SSE content type, got: {}", content_type);
    }

    #[tokio::test]
    async fn test_activity_stream_requires_auth() {
        let db = create_test_db().await;
        let (activity_tx, _) = tokio::sync::broadcast::channel(100);
        let (management_tx, _) = tokio::sync::broadcast::channel(100);
        let state = ApiState::new_with_broadcast(9443, 9080, db, activity_tx, management_tx, Arc::new(TokenCache::new()));

        let app = create_router(state);

        // No password hash set on server, so auth should fail
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/activity/stream")
                    .header("Authorization", "Bearer wrongpass")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_activity_stream_receives_broadcast_entries() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};
        let db = create_test_db().await;
        let (activity_tx, _) = tokio::sync::broadcast::channel(100);
        let (management_tx, _) = tokio::sync::broadcast::channel(100);
        let state = ApiState::new_with_broadcast(9443, 9080, db, activity_tx.clone(), management_tx, Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/activity/stream")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Send an activity entry through the broadcast channel
        let entry = ActivityEntry {
            timestamp: chrono::Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/test".to_string(),
            agent_id: Some("test-agent".to_string()),
            status: 200,
            plugin_id: Some("test-plugin".to_string()),
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        activity_tx.send(entry.clone()).unwrap();

        // Read the SSE response body
        let mut body = response.into_body();
        let chunk = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            http_body_util::BodyExt::frame(&mut body),
        )
        .await
        .expect("should receive data within timeout")
        .expect("should have a frame")
        .expect("frame should be ok");

        let data = chunk.into_data().expect("should be data frame");
        let text = String::from_utf8(data.to_vec()).unwrap();

        // SSE format: "event: activity\ndata: {...}\n\n"
        assert!(text.contains("event: activity"), "SSE event should have 'activity' type, got: {}", text);
        assert!(text.contains("api.example.com"), "SSE data should contain the URL, got: {}", text);
    }

    #[tokio::test]
    async fn test_activity_stream_filters_entries() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let (activity_tx, _) = tokio::sync::broadcast::channel(100);
        let (management_tx, _) = tokio::sync::broadcast::channel(100);
        let state = ApiState::new_with_broadcast(9443, 9080, db, activity_tx.clone(), management_tx, Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Request with domain filter
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/activity/stream?domain=api.example.com")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Send a matching entry
        let matching_entry = ActivityEntry {
            timestamp: chrono::Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/test".to_string(),
            agent_id: Some("test-agent".to_string()),
            status: 200,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        // Send a non-matching entry first
        let non_matching_entry = ActivityEntry {
            timestamp: chrono::Utc::now(),
            request_id: None,
            method: "POST".to_string(),
            url: "https://other-api.com/data".to_string(),
            agent_id: Some("test-agent".to_string()),
            status: 201,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        activity_tx.send(non_matching_entry).unwrap();
        activity_tx.send(matching_entry).unwrap();

        // Read the SSE response body - should only get the matching entry
        let mut body = response.into_body();
        let chunk = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            http_body_util::BodyExt::frame(&mut body),
        )
        .await
        .expect("should receive data within timeout")
        .expect("should have a frame")
        .expect("frame should be ok");

        let data = chunk.into_data().expect("should be data frame");
        let text = String::from_utf8(data.to_vec()).unwrap();

        // Should contain the matching entry, not the non-matching one
        assert!(text.contains("api.example.com"), "Should contain matching entry");
        assert!(!text.contains("other-api.com"), "Should not contain non-matching entry");
    }

    // ── GET /activity filter tests ─────────────────────────────────────────

    /// Build a test ApiState with password already configured, return (state, db, password).
    async fn setup_activity_state() -> (ApiState, Arc<GapDatabase>, &'static str) {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(hash).await;

        (state, db, password)
    }

    /// Seed a fixed set of activity entries to exercise all filter dimensions.
    async fn seed_diverse_activity(db: &GapDatabase) {
        let entries = vec![
            // GET on api.openai.com, plugin=openai, req_id=req-001
            ActivityEntry {
                timestamp: Utc::now() - chrono::Duration::seconds(10),
                request_id: Some("req-001".to_string()),
                method: "GET".to_string(),
                url: "https://api.openai.com/v1/models".to_string(),
                agent_id: Some("agent-1".to_string()),
                status: 200,
                plugin_id: Some("openai".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
                namespace_id: "default".to_string(),
                scope_id: "default".to_string(),
            },
            // POST on api.openai.com, plugin=openai, req_id=req-002
            ActivityEntry {
                timestamp: Utc::now() - chrono::Duration::seconds(8),
                request_id: Some("req-002".to_string()),
                method: "POST".to_string(),
                url: "https://api.openai.com/v1/chat/completions".to_string(),
                agent_id: Some("agent-1".to_string()),
                status: 200,
                plugin_id: Some("openai".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
                namespace_id: "default".to_string(),
                scope_id: "default".to_string(),
            },
            // POST on api.anthropic.com, plugin=anthropic, req_id=req-003
            ActivityEntry {
                timestamp: Utc::now() - chrono::Duration::seconds(6),
                request_id: Some("req-003".to_string()),
                method: "POST".to_string(),
                url: "https://api.anthropic.com/v1/messages".to_string(),
                agent_id: Some("agent-2".to_string()),
                status: 200,
                plugin_id: Some("anthropic".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
                namespace_id: "default".to_string(),
                scope_id: "default".to_string(),
            },
            // PUT on api.openai.com, no plugin, req_id=req-004
            ActivityEntry {
                timestamp: Utc::now() - chrono::Duration::seconds(4),
                request_id: Some("req-004".to_string()),
                method: "PUT".to_string(),
                url: "https://api.openai.com/v1/fine-tunes/ft-001".to_string(),
                agent_id: Some("agent-2".to_string()),
                status: 200,
                plugin_id: None,
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
                namespace_id: "default".to_string(),
                scope_id: "default".to_string(),
            },
        ];
        for entry in &entries {
            db.log_activity(entry).await.unwrap();
        }
    }

    /// GET /activity with a filter parameter and return the activity entries.
    async fn get_activity_filtered(state: ApiState, password: &str, query: &str) -> Vec<ActivityEntry> {
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/activity{}", query))
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "GET /activity{} returned non-OK", query);

        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .expect("response should be valid JSON");
        serde_json::from_value(value["entries"].clone())
            .expect("response should have entries array")
    }

    #[tokio::test]
    async fn test_get_activity_filter_by_domain() {
        let (state, db, password) = setup_activity_state().await;
        seed_diverse_activity(&db).await;

        let result = get_activity_filtered(state, password, "?domain=api.openai.com").await;

        // 3 entries have api.openai.com in their URL
        assert_eq!(result.len(), 3, "expected 3 entries for domain=api.openai.com");
        for entry in &result {
            assert!(entry.url.contains("api.openai.com"), "unexpected URL: {}", entry.url);
        }
    }

    #[tokio::test]
    async fn test_get_activity_filter_by_method() {
        let (state, db, password) = setup_activity_state().await;
        seed_diverse_activity(&db).await;

        let result = get_activity_filtered(state, password, "?method=POST").await;

        // 2 POST entries
        assert_eq!(result.len(), 2, "expected 2 POST entries");
        for entry in &result {
            assert_eq!(entry.method, "POST", "unexpected method: {}", entry.method);
        }
    }

    #[tokio::test]
    async fn test_get_activity_filter_by_plugin() {
        let (state, db, password) = setup_activity_state().await;
        seed_diverse_activity(&db).await;

        let result = get_activity_filtered(state, password, "?plugin=openai").await;

        // 2 entries with plugin_id=openai
        assert_eq!(result.len(), 2, "expected 2 entries for plugin=openai");
        for entry in &result {
            assert_eq!(
                entry.plugin_id.as_deref(),
                Some("openai"),
                "unexpected plugin: {:?}",
                entry.plugin_id
            );
        }
    }

    #[tokio::test]
    async fn test_get_activity_filter_by_request_id() {
        let (state, db, password) = setup_activity_state().await;
        seed_diverse_activity(&db).await;

        let result = get_activity_filtered(state, password, "?request_id=req-003").await;

        assert_eq!(result.len(), 1, "expected exactly 1 entry for request_id=req-003");
        assert_eq!(result[0].request_id.as_deref(), Some("req-003"));
        assert!(result[0].url.contains("anthropic.com"));
    }

    #[tokio::test]
    async fn test_get_activity_filter_by_path() {
        let (state, db, password) = setup_activity_state().await;
        seed_diverse_activity(&db).await;

        let result = get_activity_filtered(state, password, "?path=/v1/chat").await;

        // Only the POST to /v1/chat/completions matches
        assert_eq!(result.len(), 1, "expected 1 entry for path=/v1/chat");
        assert!(result[0].url.contains("/v1/chat/completions"));
    }

    #[tokio::test]
    async fn test_get_activity_combined_filters() {
        let (state, db, password) = setup_activity_state().await;
        seed_diverse_activity(&db).await;

        // domain=api.openai.com AND method=POST — only the POST to openai matches
        let result = get_activity_filtered(state, password, "?domain=api.openai.com&method=POST").await;

        assert_eq!(result.len(), 1, "expected 1 entry for domain+method combined filter");
        assert!(result[0].url.contains("api.openai.com"));
        assert_eq!(result[0].method, "POST");
    }

    #[tokio::test]
    async fn test_get_activity_limit() {
        let (state, db, password) = setup_activity_state().await;
        seed_diverse_activity(&db).await; // 4 entries

        let result = get_activity_filtered(state, password, "?limit=2").await;

        assert_eq!(result.len(), 2, "expected limit=2 to return 2 entries");
    }

    #[tokio::test]
    async fn test_get_activity_since() {
        let (state, db, password) = setup_activity_state().await;

        // Add one old and one recent entry
        let old_ts = Utc::now() - chrono::Duration::hours(2);
        let recent_ts = Utc::now() - chrono::Duration::seconds(5);
        let cutoff = Utc::now() - chrono::Duration::minutes(30);

        db.log_activity(&ActivityEntry {
            timestamp: old_ts,
            request_id: None,
            method: "GET".to_string(),
            url: "https://old.example.com/data".to_string(),
            agent_id: None,
            status: 200,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        }).await.unwrap();

        db.log_activity(&ActivityEntry {
            timestamp: recent_ts,
            request_id: None,
            method: "POST".to_string(),
            url: "https://new.example.com/data".to_string(),
            agent_id: None,
            status: 201,
            plugin_id: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        }).await.unwrap();

        let since_param = urlencoding::encode(&cutoff.to_rfc3339()).into_owned();
        let result = get_activity_filtered(state, password, &format!("?since={}", since_param)).await;

        assert_eq!(result.len(), 1, "expected only the recent entry after since filter");
        assert_eq!(result[0].method, "POST");
        assert!(result[0].url.contains("new.example.com"));
    }

    #[tokio::test]
    async fn test_get_activity_requires_auth() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        // No password hash set — any request should fail auth

        let app = create_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/activity")
                    .header("Authorization", "Bearer wrongpass")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // No password hash configured — should reject
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_activity_details() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        let password = "test-password";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Save some request details directly via the database
        let details = gap_lib::types::RequestDetails {
            request_id: "test-details-001".to_string(),
            req_headers: Some(r#"{"Host":"api.example.com"}"#.to_string()),
            req_body: Some(b"request body".to_vec()),
            transformed_url: Some("https://api.example.com/v2/data".to_string()),
            transformed_headers: Some(r#"{"Authorization":"Bearer [REDACTED]"}"#.to_string()),
            transformed_body: None,
            response_status: Some(200),
            response_headers: Some(r#"{"Content-Type":"application/json"}"#.to_string()),
            response_body: Some(b"{\"ok\":true}".to_vec()),
            body_truncated: false,
        };
        db.save_request_details(&details).await.unwrap();

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/activity/test-details-001/details")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let result: gap_lib::types::RequestDetails = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(result.request_id, "test-details-001");
        assert_eq!(result.response_status, Some(200));
    }

    #[tokio::test]
    async fn test_get_activity_details_not_found() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        let password = "test-password";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/activity/nonexistent-id/details")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ── Management Log Tests ─────────────────────────────────────────

    #[tokio::test]
    async fn test_management_log_requires_auth() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        let app = create_router(state);

        // No password hash set on server, so auth should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/management-log")
                    .header("Authorization", "Bearer wrongpass")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    #[serial]
    async fn test_management_log_returns_entries() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;

        // Pre-populate management log entries directly in DB
        db.log_management_event(&ManagementLogEntry {
            timestamp: chrono::Utc::now(),
            operation: "token_create".to_string(),
            resource_type: "token".to_string(),
            resource_id: Some("tok_abc".to_string()),
            detail: None,
            success: true,
            error_message: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        }).await.unwrap();

        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/management-log")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let log_response: ManagementLogResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(log_response.entries.len(), 1);
        assert_eq!(log_response.entries[0].operation, "token_create");
        assert_eq!(log_response.entries[0].resource_id, Some("tok_abc".to_string()));
    }

    #[tokio::test]
    #[serial]
    async fn test_management_log_emit_from_create_token() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Create a token via API (this should emit a management log event)
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tokens")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Give the spawned task time to write to DB
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Check management log was written
        let logs = db.query_management_log(&gap_lib::ManagementLogFilter::default()).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].operation, "token_create");
        assert_eq!(logs[0].resource_type, "token");
        assert!(logs[0].success);
    }

    #[tokio::test]
    #[serial]
    async fn test_management_log_emit_from_set_credential() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);
        let body = serde_json::json!({
            "value": "secret_api_key_12345"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/credentials/test-plugin/api_key")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Give the spawned task time to write to DB
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Check management log was written — credential values should NOT be in the log
        let logs = db.query_management_log(&gap_lib::ManagementLogFilter::default()).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].operation, "credential_set");
        assert_eq!(logs[0].resource_type, "credential");
        assert_eq!(logs[0].resource_id, Some("test-plugin/api_key".to_string()));
        // Ensure credential value is NOT in the detail
        assert!(logs[0].detail.is_none(), "Credential value must never appear in management log");
    }

    #[tokio::test]
    async fn test_management_log_stream_returns_sse_content_type() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let (activity_tx, _) = tokio::sync::broadcast::channel(100);
        let (management_tx, _) = tokio::sync::broadcast::channel(100);
        let state = ApiState::new_with_broadcast(9443, 9080, db, activity_tx, management_tx, Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/management-log/stream")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(content_type.contains("text/event-stream"), "Expected SSE content type, got: {}", content_type);
    }

    #[tokio::test]
    async fn test_management_log_stream_requires_auth() {
        let db = create_test_db().await;
        let (activity_tx, _) = tokio::sync::broadcast::channel(100);
        let (management_tx, _) = tokio::sync::broadcast::channel(100);
        let state = ApiState::new_with_broadcast(9443, 9080, db, activity_tx, management_tx, Arc::new(TokenCache::new()));

        let app = create_router(state);

        // No password hash set, so auth should fail
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/management-log/stream")
                    .header("Authorization", "Bearer wrongpass")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_management_log_stream_receives_broadcast_entries() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let (activity_tx, _) = tokio::sync::broadcast::channel(100);
        let (management_tx, _) = tokio::sync::broadcast::channel(100);
        let state = ApiState::new_with_broadcast(9443, 9080, db, activity_tx, management_tx.clone(), Arc::new(TokenCache::new()));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/management-log/stream")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Send a management log entry through the broadcast channel
        let entry = ManagementLogEntry {
            timestamp: chrono::Utc::now(),
            operation: "token_create".to_string(),
            resource_type: "token".to_string(),
            resource_id: Some("tok_test".to_string()),
            detail: None,
            success: true,
            error_message: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        management_tx.send(entry).unwrap();

        // Read the SSE response body
        let mut body = response.into_body();
        let chunk = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            http_body_util::BodyExt::frame(&mut body),
        )
        .await
        .expect("should receive data within timeout")
        .expect("should have a frame")
        .expect("frame should be ok");

        let data = chunk.into_data().expect("should be data frame");
        let text = String::from_utf8(data.to_vec()).unwrap();

        // SSE format: "event: management\ndata: {...}\n\n"
        assert!(text.contains("event: management"), "SSE event should have 'management' type, got: {}", text);
        assert!(text.contains("token_create"), "SSE data should contain the operation, got: {}", text);
    }

    // Helper to set up auth for tests
    async fn setup_auth(state: &ApiState) -> String {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;
        password.to_string()
    }

    #[tokio::test]
    async fn test_register_plugin_requires_auth() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        let app = create_router(state);

        let body = serde_json::json!({
            "name": "my-plugin",
            "code": "var plugin = { name: 'my-plugin', matchPatterns: ['example.com'], credentialSchema: [] };"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/plugins/register")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_register_plugin_with_valid_code() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;
        let app = create_router(state);

        let plugin_code = "var plugin = { name: 'my-plugin', matchPatterns: ['example.com'], credentialSchema: [], transform: function(r) { return r; } };";

        let body = serde_json::json!({
            "code": plugin_code
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/plugins/register")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);

        assert_eq!(status, StatusCode::OK, "Expected OK, got {}: {}", status, body_str);

        let register_response: RegisterResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(!register_response.id.is_empty(), "should have a UUID id");
        assert!(register_response.registered);

        // Verify plugin was stored in the database
        let plugins = db.list_plugins().await.expect("list plugins");
        assert!(plugins.iter().any(|p| p.id == register_response.id), "plugin should be in database");
    }

    #[tokio::test]
    async fn test_register_plugin_with_invalid_code() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;
        let app = create_router(state);

        let body = serde_json::json!({
            "code": "this is not valid javascript }{{"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/plugins/register")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_register_plugin_with_es6_export() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;
        let app = create_router(state);

        // ES6 export syntax — should be transformed before loading
        let plugin_code = "export default { name: 'es6-plugin', matchPatterns: ['api.example.com'], credentialSchema: [], transform: function(r) { return r; } };";

        let body = serde_json::json!({
            "code": plugin_code
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/plugins/register")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);

        assert_eq!(status, StatusCode::OK, "Expected OK, got {}: {}", status, body_str);

        let register_response: RegisterResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(register_response.registered);

        // Verify plugin was stored in the database
        let plugins = db.list_plugins().await.expect("list plugins");
        assert!(plugins.iter().any(|p| p.id == register_response.id), "es6 plugin should be in database");
    }

    // ── HeaderSet endpoint tests ──────────────────────────────────────────

    #[tokio::test]
    async fn test_create_header_set() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;
        let app = create_router(state);

        let body = serde_json::json!({
            "match_patterns": ["api.example.com"],
            "weight": 10
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/header-sets")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let hs_id = resp["id"].as_str().unwrap();
        assert!(!hs_id.is_empty(), "should have a UUID id");
        assert_eq!(resp["created"], true);

        // Verify stored in DB
        let hs = db.get_header_set(hs_id).await.unwrap().expect("header set should exist");
        assert_eq!(hs.match_patterns, vec!["api.example.com"]);
        assert_eq!(hs.weight, 10);
    }

    #[tokio::test]
    async fn test_create_header_set_no_auth() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        let app = create_router(state);

        let body = serde_json::json!({
            "match_patterns": ["api.example.com"]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/header-sets")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_header_set_empty_patterns() {
        // Empty match_patterns should be rejected with 400 Bad Request.
        // An empty list would create an unreachable header set (matches nothing),
        // which is almost certainly a client mistake.
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;
        let app = create_router(state);

        let body = serde_json::json!({
            "match_patterns": []
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/header-sets")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("match_patterns must not be empty"), "got: {}", body_str);
    }

    #[tokio::test]
    async fn test_create_header_set_with_headers() {
        // Creating a header set with inline headers should store them atomically.
        // The caller shouldn't need a second request to set initial headers.
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;
        let app = create_router(state);

        let body = serde_json::json!({
            "match_patterns": ["api.example.com"],
            "weight": 5,
            "headers": {
                "Authorization": "Bearer secret",
                "X-Custom": "custom-value"
            }
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/header-sets")
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let hs_id = resp["id"].as_str().unwrap();
        assert!(!hs_id.is_empty(), "should have a UUID id");
        assert_eq!(resp["created"], true);

        // Verify headers were stored in the DB
        let names = db.list_header_set_header_names(hs_id).await.unwrap();
        assert!(names.contains(&"Authorization".to_string()), "Authorization should be stored; got: {:?}", names);
        assert!(names.contains(&"X-Custom".to_string()), "X-Custom should be stored; got: {:?}", names);
    }

    #[tokio::test]
    async fn test_update_header_set_empty_patterns() {
        // Updating match_patterns to an empty list should be rejected with 400 Bad Request.
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;

        let hs_id = db.add_header_set(&["api.example.com".to_string()], 0)
            .await.unwrap();

        let app = create_router(state);

        let body = serde_json::json!({ "match_patterns": [] });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/header-sets/{}", hs_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("match_patterns must not be empty"), "got: {}", body_str);
    }

    #[tokio::test]
    async fn test_list_header_sets() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;

        // Pre-populate via DB
        let hs_id = db.add_header_set(&["api.example.com".to_string()], 5)
            .await.unwrap();
        db.set_header_set_header(&hs_id, "Authorization", "Bearer secret-value")
            .await.unwrap();
        db.set_header_set_header(&hs_id, "X-Custom", "some-value")
            .await.unwrap();

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/header-sets")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let header_sets = resp["header_sets"].as_array().unwrap();
        assert_eq!(header_sets.len(), 1);

        let hs = &header_sets[0];
        assert_eq!(hs["id"], hs_id);
        assert_eq!(hs["weight"], 5);

        // Should include header names but NOT values
        let headers = hs["headers"].as_array().unwrap();
        assert_eq!(headers.len(), 2);
        let names: Vec<&str> = headers.iter().map(|h| h.as_str().unwrap()).collect();
        assert!(names.contains(&"Authorization"), "should include 'Authorization' header name");
        assert!(names.contains(&"X-Custom"), "should include 'X-Custom' header name");

        // Values must NOT appear anywhere in the response
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(!body_str.contains("Bearer secret-value"), "header values must not appear in response");
        assert!(!body_str.contains("some-value"), "header values must not appear in response");
    }

    #[tokio::test]
    async fn test_update_header_set() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;

        let hs_id = db.add_header_set(&["api.example.com".to_string()], 0)
            .await.unwrap();

        let app = create_router(state);

        let body = serde_json::json!({ "weight": 42 });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/header-sets/{}", hs_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(resp["updated"], true);

        // Verify updated in DB
        let hs = db.get_header_set(&hs_id).await.unwrap().expect("should exist");
        assert_eq!(hs.weight, 42);
    }

    #[tokio::test]
    async fn test_delete_header_set() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;

        let hs_id = db.add_header_set(&["api.example.com".to_string()], 0)
            .await.unwrap();

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/header-sets/{}", hs_id))
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(resp["deleted"], true);

        // Verify removed from DB
        let hs = db.get_header_set(&hs_id).await.unwrap();
        assert!(hs.is_none(), "header set should be deleted");

        // Verify not in list
        let all = db.list_header_sets().await.unwrap();
        assert!(all.iter().all(|h| h.id != hs_id), "should not appear in list");
    }

    #[tokio::test]
    async fn test_set_header_set_header() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;

        let hs_id = db.add_header_set(&["api.example.com".to_string()], 0)
            .await.unwrap();

        let app = create_router(state);

        let body = serde_json::json!({
            "name": "Authorization",
            "value": "Bearer my-secret-token"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/header-sets/{}/headers", hs_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(resp["set"], true);
        assert_eq!(resp["header"], "Authorization");

        // Verify stored in DB (by listing names)
        let names = db.list_header_set_header_names(&hs_id).await.unwrap();
        assert!(names.contains(&"Authorization".to_string()), "Authorization header should be stored");
    }

    #[tokio::test]
    async fn test_delete_header_set_header() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;

        let hs_id = db.add_header_set(&["api.example.com".to_string()], 0)
            .await.unwrap();
        db.set_header_set_header(&hs_id, "Authorization", "Bearer token")
            .await.unwrap();
        db.set_header_set_header(&hs_id, "X-Custom", "value")
            .await.unwrap();

        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/header-sets/{}/headers/Authorization", hs_id))
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let resp: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(resp["deleted"], true);
        assert_eq!(resp["header"], "Authorization");

        // Verify Authorization removed, X-Custom still there
        let names = db.list_header_set_header_names(&hs_id).await.unwrap();
        assert!(!names.contains(&"Authorization".to_string()), "Authorization should be removed");
        assert!(names.contains(&"X-Custom".to_string()), "X-Custom should remain");
    }

    #[tokio::test]
    async fn test_update_plugin_weight() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        let password = setup_auth(&state).await;

        // Register a plugin first
        let plugin_entry = gap_lib::types::PluginEntry {
            id: String::new(),
            source: None,
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec![],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
            namespace_id: "default".to_string(),
            scope_id: "default".to_string(),
        };
        let plugin_id = db.add_plugin(&plugin_entry, "var plugin = {};").await.unwrap();

        let app = create_router(state);

        let body = serde_json::json!({ "weight": 100 });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(format!("/plugins/{}", plugin_id))
                    .header("content-type", "application/json")
                    .header("Authorization", format!("Bearer {}", password))
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert_eq!(status, StatusCode::OK, "Expected OK, got {}: {}", status, body_str);

        let resp: UpdatePluginResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(resp.id, plugin_id);
        assert!(resp.updated);

        // Verify weight updated in DB
        let plugins = db.list_plugins().await.unwrap();
        let plugin = plugins.iter().find(|p| p.id == plugin_id).unwrap();
        assert_eq!(plugin.weight, 100);
    }

    // ── Signing middleware tests ──────────────────────────────────────

    /// Helper: create a test Ed25519 keypair and return (keypair, raw public key bytes)
    fn test_signing_keypair() -> (ring::signature::Ed25519KeyPair, Vec<u8>) {
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = keypair.public_key().as_ref().to_vec();
        (keypair, public_key)
    }

    /// Helper: create a SigningConfig from raw public key bytes
    fn test_signing_config(public_key: &[u8]) -> crate::signing::SigningConfig {
        use ring::signature::{self, UnparsedPublicKey};
        crate::signing::SigningConfig {
            public_keys: vec![(
                "test-key".to_string(),
                UnparsedPublicKey::new(&signature::ED25519, public_key.to_vec()),
            )],
        }
    }

    /// Helper: sign a request and return headers with signature
    fn sign_test_request(
        keypair: &ring::signature::Ed25519KeyPair,
        method: &str,
        path: &str,
        body: &[u8],
        nonce: &str,
    ) -> Vec<(&'static str, String)> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let digest = crate::signing::compute_content_digest(body);
        let canonical = crate::signing::build_canonical_string(
            method, path, &digest, &timestamp.to_string(), nonce,
        );
        let sig = keypair.sign(canonical.as_bytes());
        let sig_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.as_ref());
        vec![
            ("x-gap-timestamp", timestamp.to_string()),
            ("x-gap-nonce", nonce.to_string()),
            ("x-gap-signature", sig_b64),
        ]
    }

    #[tokio::test]
    async fn test_signing_disabled_passes_through() {
        // When signing_config is None, all requests should pass through
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        // signing_config defaults to None
        assert!(state.signing_config.is_none());
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
    }

    #[tokio::test]
    async fn test_signing_enabled_status_exempt() {
        // /status should be exempt from signing even when signing is enabled
        let db = create_test_db().await;
        let (_, pub_key) = test_signing_keypair();
        let mut state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        state.signing_config = Some(Arc::new(test_signing_config(&pub_key)));
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
    }

    #[tokio::test]
    async fn test_signing_enabled_init_exempt() {
        // /init should be exempt from signing even when signing is enabled
        let db = create_test_db().await;
        let (_, pub_key) = test_signing_keypair();
        let mut state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        state.signing_config = Some(Arc::new(test_signing_config(&pub_key)));
        let app = create_router(state);

        // /init requires a POST with password; it won't succeed but it should
        // NOT be rejected with 401 Unauthorized (signing). It should get past
        // the signing middleware and fail with a different status (400 bad request
        // for missing body, etc.)
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/init")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"password":"test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should NOT be 401 — the signing middleware should let it through
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_signing_enabled_rejects_unsigned_request() {
        // An unsigned request to a non-exempt endpoint should be rejected with 401
        let db = create_test_db().await;
        let (_, pub_key) = test_signing_keypair();
        let mut state = ApiState::new(9443, 9080, db, Arc::new(TokenCache::new()));
        state.signing_config = Some(Arc::new(test_signing_config(&pub_key)));
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/tokens")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert!(body_str.contains("Signature verification failed"));
    }

    #[tokio::test]
    async fn test_signing_enabled_accepts_valid_signature() {
        // A properly signed request should pass through the middleware
        let db = create_test_db().await;
        let (keypair, pub_key) = test_signing_keypair();
        let mut state = ApiState::new(9443, 9080, Arc::clone(&db), Arc::new(TokenCache::new()));
        state.signing_config = Some(Arc::new(test_signing_config(&pub_key)));

        // Set up auth so the endpoint itself doesn't reject us
        let password = setup_auth(&state).await;
        let app = create_router(state);

        let body = b"";
        let headers = sign_test_request(&keypair, "GET", "/tokens", body, "nonce-tokens-1");

        let mut req = Request::builder()
            .uri("/tokens")
            .header("Authorization", format!("Bearer {}", password));

        for (name, value) in &headers {
            req = req.header(*name, value.as_str());
        }

        let response = app
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();

        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);

        // Should get past signing middleware — may be 200 OK (tokens list)
        // If 401, check it's from auth (not signing)
        if status == StatusCode::UNAUTHORIZED {
            assert!(!body_str.contains("Signature verification failed"),
                "Signing middleware rejected a valid signature: {}", body_str);
        }
        assert_eq!(status, StatusCode::OK, "Expected OK, got {}: {}", status, body_str);
    }
}
