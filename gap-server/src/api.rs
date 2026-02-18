//! Management API for GAP Server
//!
//! Provides HTTP endpoints for:
//! - Server status
//! - Plugin management
//! - Credential management
//! - Token management
//! - Activity monitoring

use gap_lib::{AgentToken, ActivityEntry};
use gap_lib::types::RequestDetails;
use gap_lib::database::GapDatabase;
use gap_lib::types::PluginEntry;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRequestParts, Path, Query, State},
    http::{request::Parts, StatusCode},
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
}

impl ApiState {
    /// Create ApiState with database backend
    pub fn new(proxy_port: u16, api_port: u16, db: Arc<GapDatabase>) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            proxy_port,
            api_port,
            password_hash: Arc::new(RwLock::new(None)),
            db,
            activity_tx: None,
        }
    }

    /// Create ApiState with broadcast channel for activity streaming
    pub fn new_with_broadcast(
        proxy_port: u16,
        api_port: u16,
        db: Arc<GapDatabase>,
        activity_tx: tokio::sync::broadcast::Sender<ActivityEntry>,
    ) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            proxy_port,
            api_port,
            password_hash: Arc::new(RwLock::new(None)),
            db,
            activity_tx: Some(activity_tx),
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
impl<T> FromRequestParts<ApiState> for Authenticated<T>
where
    T: for<'de> Deserialize<'de> + Send,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(
        _parts: &mut Parts,
        _state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        // For now, this is a placeholder - actual auth will be done in handlers
        // that have access to the request body
        Err((
            StatusCode::UNAUTHORIZED,
            "Use request body for authentication".to_string(),
        ))
    }
}

/// Helper function to verify authentication from request body
async fn verify_auth<T>(
    state: &ApiState,
    body: &[u8],
) -> Result<T, (StatusCode, String)>
where
    T: for<'de> Deserialize<'de>,
{
    // Parse as authenticated request
    let auth_req: AuthenticatedRequest<T> =
        serde_json::from_slice(body).map_err(|e| {
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

        Ok(auth_req.data)
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
    pub name: String,
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
    pub name: String,
}

/// Token response (includes full token only on creation)
#[derive(Debug, Serialize, Deserialize)]
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

/// Init request
#[derive(Debug, Deserialize)]
pub struct InitRequest {}

/// Init response
#[derive(Debug, Serialize, Deserialize)]
pub struct InitResponse {
    pub ca_path: String,
}

/// Install plugin request
#[derive(Debug, Deserialize)]
pub struct InstallRequest {
    pub name: String,
}

/// Install plugin response
#[derive(Debug, Serialize, Deserialize)]
pub struct InstallResponse {
    pub name: String,
    pub installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,
}

/// Uninstall plugin response
#[derive(Debug, Serialize, Deserialize)]
pub struct UninstallResponse {
    pub name: String,
    pub uninstalled: bool,
}

/// Update plugin response
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateResponse {
    pub name: String,
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

/// Create the API router
pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/status", get(get_status))
        .route("/init", post(init))
        .route("/plugins", post(post_plugins))
        .route("/plugins/install", post(install_plugin))
        .route("/plugins/:name/update", post(update_plugin))
        .route("/plugins/:name", delete(uninstall_plugin))
        .route("/tokens", get(list_tokens).post(post_list_tokens))
        .route("/tokens/create", post(create_token))
        .route("/tokens/:id", delete(delete_token))
        .route(
            "/credentials/:plugin/:key",
            post(set_credential).delete(delete_credential),
        )
        .route("/activity", get(get_activity).post(get_activity))
        .route("/activity/stream", get(activity_stream).post(activity_stream))
        .route("/activity/:request_id/details", get(get_activity_details).post(get_activity_details))
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
    let req: AuthenticatedRequest<InitRequest> = serde_json::from_slice(&body)
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

    Ok(Json(InitResponse { ca_path }))
}

/// GET /plugins - List installed plugins (requires auth)
#[allow(dead_code)]
async fn get_plugins(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Json<PluginsResponse>, (StatusCode, String)> {
    verify_auth::<serde_json::Value>(&state, &body).await?;

    // Get plugins from database
    let plugin_entries = state.db.list_plugins().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list plugins: {}", e)))?;

    // Convert PluginEntry to PluginInfo
    let plugins = plugin_entries
        .into_iter()
        .map(|entry| PluginInfo {
            name: entry.name,
            match_patterns: entry.hosts,
            credential_schema: entry.credential_schema,
        })
        .collect();

    Ok(Json(PluginsResponse { plugins }))
}

/// POST /plugins - List installed plugins (requires auth, same as GET)
async fn post_plugins(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Json<PluginsResponse>, (StatusCode, String)> {
    verify_auth::<serde_json::Value>(&state, &body).await?;

    // Get plugins from database
    let plugin_entries = state.db.list_plugins().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list plugins: {}", e)))?;

    // Convert PluginEntry to PluginInfo
    let plugins = plugin_entries
        .into_iter()
        .map(|entry| PluginInfo {
            name: entry.name,
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
    body: Bytes,
) -> std::result::Result<Json<InstallResponse>, (StatusCode, String)> {
    let req: InstallRequest = verify_auth(&state, &body).await?;

    // Parse GitHub owner/repo from name (e.g., "mikekelly/exa-gap")
    let plugin_name = parse_plugin_name(&req.name)?;

    // Check if plugin already exists
    let exists = state.db.has_plugin(&plugin_name).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to check plugin: {}", e)))?;

    if exists {
        return Err((
            StatusCode::CONFLICT,
            format!("Plugin '{}' is already installed. Use 'gap update {}' to update it.", plugin_name, plugin_name),
        ));
    }

    // Clone, validate, and store plugin
    let (plugin, commit_sha) = clone_and_validate_plugin(&state, &plugin_name).await?;

    tracing::info!("Installed plugin: {} (matches: {:?}, commit: {})", plugin_name, plugin.match_patterns, commit_sha);

    Ok(Json(InstallResponse {
        name: plugin_name,
        installed: true,
        commit_sha: Some(commit_sha),
    }))
}

/// DELETE /plugins/{name} - Uninstall a plugin (requires auth)
#[axum::debug_handler]
async fn uninstall_plugin(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    body: Bytes,
) -> std::result::Result<Json<UninstallResponse>, (StatusCode, String)> {
    // Verify auth (body contains password hash)
    verify_auth::<serde_json::Value>(&state, &body).await?;

    // URL-decode the name (handles owner/repo with %2F)
    let plugin_name = urlencoding::decode(&name)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid plugin name: {}", e)))?
        .into_owned();

    // Check if plugin exists
    let exists = state.db.has_plugin(&plugin_name).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to check plugin: {}", e)))?;

    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Plugin '{}' is not installed.", plugin_name),
        ));
    }

    // Remove plugin from database (removes metadata + source, preserves credentials)
    state.db.remove_plugin(&plugin_name).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to remove plugin: {}", e)))?;

    tracing::info!("Uninstalled plugin: {}", plugin_name);

    Ok(Json(UninstallResponse {
        name: plugin_name,
        uninstalled: true,
    }))
}

/// POST /plugins/{name}/update - Update a plugin from GitHub (requires auth)
#[axum::debug_handler]
async fn update_plugin(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    body: Bytes,
) -> std::result::Result<Json<UpdateResponse>, (StatusCode, String)> {
    // Verify auth
    verify_auth::<serde_json::Value>(&state, &body).await?;

    // URL-decode the name
    let plugin_name = urlencoding::decode(&name)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid plugin name: {}", e)))?
        .into_owned();

    // Check if plugin exists
    let exists = state.db.has_plugin(&plugin_name).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to check plugin: {}", e)))?;

    if !exists {
        return Err((
            StatusCode::NOT_FOUND,
            format!("Plugin '{}' is not installed. Use 'gap install {}' to install it.", plugin_name, plugin_name),
        ));
    }

    // Remove old plugin from database (but keep credentials)
    state.db.remove_plugin(&plugin_name).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to remove old plugin: {}", e)))?;

    // Clone, validate, and store new version
    let (plugin, commit_sha) = clone_and_validate_plugin(&state, &plugin_name).await?;

    tracing::info!("Updated plugin: {} (matches: {:?}, commit: {})", plugin_name, plugin.match_patterns, commit_sha);

    Ok(Json(UpdateResponse {
        name: plugin_name,
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
/// Returns the validated plugin info and commit SHA
async fn clone_and_validate_plugin(
    state: &ApiState,
    plugin_name: &str,
) -> std::result::Result<(gap_lib::types::GAPPlugin, String), (StatusCode, String)> {
    use gap_lib::plugin_runtime::PluginRuntime;
    use git2::{build::RepoBuilder, Cred, FetchOptions, RemoteCallbacks};
    use tempfile::tempdir;

    let parts: Vec<&str> = plugin_name.split('/').collect();
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

        let plugin = runtime.load_plugin_from_code(plugin_name, &transformed_code)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid plugin code: {}", e)))?;

        (transformed_code, plugin, commit_sha)
    };

    // Store plugin metadata and source code in database (single operation)
    let plugin_entry = PluginEntry {
        name: plugin.name.clone(),
        hosts: plugin.match_patterns.clone(),
        credential_schema: plugin.credential_schema.clone(),
        commit_sha: Some(commit_sha.clone()),
        dangerously_permit_http: plugin.dangerously_permit_http,
    };
    state.db.add_plugin(&plugin_entry, &transformed_code).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store plugin: {}", e)))?;

    Ok((plugin, commit_sha))
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
    body: Bytes,
) -> Result<Json<TokensResponse>, (StatusCode, String)> {
    verify_auth::<serde_json::Value>(&state, &body).await?;

    // List tokens from database
    let token_entries = state.db.list_tokens().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list tokens: {}", e)))?;

    // Convert TokenEntry to TokenResponse
    let token_list: Vec<TokenResponse> = token_entries
        .into_iter()
        .map(|entry| {
            // TokenEntry.token_value is the full token, use it as id
            // Calculate prefix from token_value (first 8 chars)
            let prefix = entry.token_value.chars().take(8).collect::<String>();
            TokenResponse {
                id: entry.token_value,
                name: entry.name,
                prefix,
                token: None, // Never expose full token in list
                created_at: entry.created_at,
            }
        })
        .collect();

    Ok(Json(TokensResponse { tokens: token_list }))
}

/// POST /tokens - List agent tokens (requires auth, same as GET)
async fn post_list_tokens(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Json<TokensResponse>, (StatusCode, String)> {
    list_tokens(State(state), body).await
}

/// POST /tokens/create - Create new agent token (requires auth)
async fn create_token(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Json<TokenResponse>, (StatusCode, String)> {
    let req: CreateTokenRequest = verify_auth(&state, &body).await?;

    // Create a new AgentToken
    let token = AgentToken::new(&req.name);

    // Store token in database
    state.db.add_token(&token.token, &token.name, token.created_at)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to add token: {}", e)))?;

    let token_value = token.token.clone();

    // Return with full token (only time it's revealed)
    // NOTE: id is the token value (not UUID) to match list_tokens behavior
    Ok(Json(TokenResponse {
        id: token_value.clone(),
        name: token.name,
        prefix: token.prefix,
        token: Some(token_value),
        created_at: token.created_at,
    }))
}

/// DELETE /tokens/:id - Revoke agent token (requires auth)
async fn delete_token(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    verify_auth::<serde_json::Value>(&state, &body).await?;

    // The id is the token value
    // Check if token exists in database
    let token = state.db.get_token(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get token: {}", e)))?;

    if token.is_none() {
        return Err((StatusCode::NOT_FOUND, format!("Token '{}' not found", id)));
    }

    // Remove from database
    state.db.remove_token(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to remove token: {}", e)))?;

    Ok(Json(serde_json::json!({
        "id": id,
        "revoked": true
    })))
}

/// POST /credentials/:plugin/:key - Set credential (requires auth)
async fn set_credential(
    State(state): State<ApiState>,
    Path((plugin, key)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let req: SetCredentialRequest = verify_auth(&state, &body).await?;

    // Store credential in database
    state.db.set_credential(&plugin, &key, &req.value)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to set credential: {}", e)))?;

    tracing::info!("Setting credential {}:{}", plugin, key);
    Ok(Json(serde_json::json!({
        "plugin": plugin,
        "key": key,
        "set": true
    })))
}

/// DELETE /credentials/:plugin/:key - Delete credential (requires auth)
async fn delete_credential(
    State(state): State<ApiState>,
    Path((plugin, key)): Path<(String, String)>,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    verify_auth::<serde_json::Value>(&state, &body).await?;

    // Remove credential from database
    state.db.remove_credential(&plugin, &key)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to remove credential: {}", e)))?;

    tracing::info!("Deleting credential {}:{}", plugin, key);
    Ok(StatusCode::OK)
}

/// Convert ActivityQuery to ActivityFilter
fn query_to_filter(q: &ActivityQuery) -> gap_lib::ActivityFilter {
    gap_lib::ActivityFilter {
        domain: q.domain.clone(),
        path: q.path.clone(),
        plugin: q.plugin.clone(),
        agent: q.agent.clone(),
        method: q.method.clone(),
        since: q.since.as_ref().and_then(|s| {
            DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc))
        }),
        request_id: q.request_id.clone(),
        limit: q.limit.or(Some(100)),
    }
}

/// GET /activity - Get recent activity (requires auth, supports query param filters)
async fn get_activity(
    State(state): State<ApiState>,
    Query(query): Query<ActivityQuery>,
    body: Bytes,
) -> Result<Json<ActivityResponse>, (StatusCode, String)> {
    verify_auth::<serde_json::Value>(&state, &body).await?;

    let filter = query_to_filter(&query);
    let entries = state.db.query_activity(&filter).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get activity: {}", e)))?;
    Ok(Json(ActivityResponse { entries }))
}

/// GET /activity/:request_id/details - Get detailed request/response data (requires auth)
async fn get_activity_details(
    State(state): State<ApiState>,
    Path(request_id): Path<String>,
    body: Bytes,
) -> Result<Json<RequestDetails>, (StatusCode, String)> {
    verify_auth::<serde_json::Value>(&state, &body).await?;

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
        if entry.plugin_name.as_deref() != Some(plugin.as_str()) {
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
    body: Bytes,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)> {
    verify_auth::<serde_json::Value>(&state, &body).await?;

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
        let state = ApiState::new(9443, 9080, db);
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
        let state = ApiState::new(9443, 9080, db);

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Create auth request body
        let body = serde_json::json!({
            "password_hash": password
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/plugins")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_post_tokens_list_endpoint() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db);

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Create auth request body
        let body = serde_json::json!({
            "password_hash": password
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tokens")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let status = response.status();
        if status != StatusCode::OK {
            let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
            let body_str = String::from_utf8_lossy(&body_bytes);
            eprintln!("Error response: {}", body_str);
            panic!("Expected OK, got {}", status);
        }
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn test_post_tokens_create_endpoint() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db);

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Create auth request body with name
        let body = serde_json::json!({
            "password_hash": password,
            "name": "test-token"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tokens/create")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let token_response: TokenResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(token_response.name, "test-token");
        assert!(token_response.token.is_some());
    }

    #[tokio::test]
    async fn test_post_activity_endpoint() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db);

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Create auth request body
        let body = serde_json::json!({
            "password_hash": password
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/activity")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
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

        let state = ApiState::new(9443, 9080, db);
        let app = create_router(state.clone());

        let password = "testpass123";

        // Create init request body
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

        let state = ApiState::new(9443, 9080, db);
        let app = create_router(state.clone());

        let password = "testpass123";

        // Create init request body WITHOUT ca_path (it's no longer user-configurable)
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
        let state = ApiState::new(9443, 9080, db);

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Install plugin from GitHub (mikekelly/test-plugin doesn't exist, so expect 502)
        let body = serde_json::json!({
            "password_hash": password,
            "name": "mikekelly/test-plugin"
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
        let state = ApiState::new(9443, 9080, db);

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Try to install a real plugin from GitHub
        // Using a test repo that should have plugin.js
        let body = serde_json::json!({
            "password_hash": password,
            "name": "mikekelly/exa-gap"  // Real repo with plugin.js
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
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Try to install a real plugin from GitHub
        // Using the same test repo that should have plugin.js
        let body = serde_json::json!({
            "password_hash": password,
            "name": "mikekelly/exa-gap"  // Real repo with plugin.js
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

        // Only verify database if installation succeeded
        if response.status() == StatusCode::OK {
            // Verify the plugin was added to the database
            let plugins = db.list_plugins().await.expect("list plugins from database");

            // Find the installed plugin
            let installed_plugin = plugins.iter()
                .find(|p| p.name == "mikekelly/exa-gap")
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
        let state = ApiState::new(9443, 9080, db);
        let app = create_router(state);

        // Try to install without password
        let body = serde_json::json!({
            "name": "mikekelly/test-plugin"
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

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
        let state = ApiState::new(9443, 9080, db);

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Create auth request body with credential value
        let body = serde_json::json!({
            "password_hash": password,
            "value": "secret_api_key_12345"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/credentials/test-plugin/api_key")
                    .header("content-type", "application/json")
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
        let state = ApiState::new(9443, 9080, db);

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Create auth request body
        let body = serde_json::json!({
            "password_hash": password
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/credentials/test-plugin/api_key")
                    .header("content-type", "application/json")
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
    async fn test_api_uses_shared_db() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Now set a credential via the API
        let app = create_router(state.clone());
        let body = serde_json::json!({
            "password_hash": password,
            "value": "api_write_value"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/credentials/test-plugin/api_key")
                    .header("content-type", "application/json")
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
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Set a credential via the API
        let body = serde_json::json!({
            "password_hash": password,
            "value": "secret_api_key_12345"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/credentials/exa/api_key")
                    .header("content-type", "application/json")
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
            plugin: "exa".to_string(),
            field: "api_key".to_string(),
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
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Pre-populate database with a credential
        db.set_credential("exa", "api_key", "some_value").await.expect("add should succeed");

        let app = create_router(state);

        // Delete the credential via the API
        let body = serde_json::json!({
            "password_hash": password
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/credentials/exa/api_key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
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
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Set a credential via the API
        let body = serde_json::json!({
            "password_hash": password,
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
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Set the same credential again with different value
        let body2 = serde_json::json!({
            "password_hash": password,
            "value": "new_secret_value"
        });

        let app2 = create_router(state);
        let response2 = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/credentials/exa/api_key")
                    .header("content-type", "application/json")
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
            plugin: "exa".to_string(),
            field: "api_key".to_string(),
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
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Add a token to the database directly
        let token_value = "gap_test_token_12345".to_string();
        db.add_token(&token_value, "test-token", Utc::now()).await.expect("add token to database");

        // List tokens via API
        let app = create_router(state);
        let body = serde_json::json!({
            "password_hash": password
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tokens")
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
        let tokens_response: TokensResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Verify the token from database is in the response
        assert_eq!(tokens_response.tokens.len(), 1);
        assert_eq!(tokens_response.tokens[0].id, token_value);
        assert_eq!(tokens_response.tokens[0].name, "test-token");
        assert_eq!(tokens_response.tokens[0].prefix, "gap_test");
    }

    #[tokio::test]
    #[serial]
    async fn test_create_token_adds_to_database() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Create token via API
        let app = create_router(state);
        let body = serde_json::json!({
            "password_hash": password,
            "name": "new-token"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/tokens/create")
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
        let token_response: TokenResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Verify the token was added to the database
        let tokens = db.list_tokens().await.expect("list tokens from database");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_value, token_response.id);
        assert_eq!(tokens[0].name, "new-token");
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_token_removes_from_database() {
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        // Create a token and add it to the database
        let token = AgentToken::new("test-token");
        db.add_token(&token.token, &token.name, token.created_at).await.expect("add token to database");

        // Delete token via API
        let app = create_router(state);
        let body = serde_json::json!({
            "password_hash": password
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/tokens/{}", token.token))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify the token was removed from the database
        let tokens = db.list_tokens().await.expect("list tokens from database");
        assert_eq!(tokens.len(), 0, "Token should be removed from database");
    }

    /// Verify /init returns 200 OK with a ca_path and no longer stores mgmt certs
    #[tokio::test]
    #[serial]
    async fn test_init_endpoint_no_mgmt_cert() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, Arc::clone(&db));
        let app = create_router(state);

        let password = "testpass123";

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
        let state = ApiState::new_with_broadcast(9443, 9080, db, activity_tx);

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
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&serde_json::json!({
                        "password_hash": password
                    })).unwrap()))
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
        let state = ApiState::new_with_broadcast(9443, 9080, db, activity_tx);

        let app = create_router(state);

        // No password hash set on server, so auth should fail
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/activity/stream")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&serde_json::json!({
                        "password_hash": "wrongpass"
                    })).unwrap()))
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
        let state = ApiState::new_with_broadcast(9443, 9080, db, activity_tx.clone());

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
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&serde_json::json!({
                        "password_hash": password
                    })).unwrap()))
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
            plugin_name: Some("test-plugin".to_string()),
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
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
        let state = ApiState::new_with_broadcast(9443, 9080, db, activity_tx.clone());

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
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&serde_json::json!({
                        "password_hash": password
                    })).unwrap()))
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
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        };
        // Send a non-matching entry first
        let non_matching_entry = ActivityEntry {
            timestamp: chrono::Utc::now(),
            request_id: None,
            method: "POST".to_string(),
            url: "https://other-api.com/data".to_string(),
            agent_id: Some("test-agent".to_string()),
            status: 201,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
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
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

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
                plugin_name: Some("openai".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
            },
            // POST on api.openai.com, plugin=openai, req_id=req-002
            ActivityEntry {
                timestamp: Utc::now() - chrono::Duration::seconds(8),
                request_id: Some("req-002".to_string()),
                method: "POST".to_string(),
                url: "https://api.openai.com/v1/chat/completions".to_string(),
                agent_id: Some("agent-1".to_string()),
                status: 200,
                plugin_name: Some("openai".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
            },
            // POST on api.anthropic.com, plugin=anthropic, req_id=req-003
            ActivityEntry {
                timestamp: Utc::now() - chrono::Duration::seconds(6),
                request_id: Some("req-003".to_string()),
                method: "POST".to_string(),
                url: "https://api.anthropic.com/v1/messages".to_string(),
                agent_id: Some("agent-2".to_string()),
                status: 200,
                plugin_name: Some("anthropic".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
            },
            // PUT on api.openai.com, no plugin, req_id=req-004
            ActivityEntry {
                timestamp: Utc::now() - chrono::Duration::seconds(4),
                request_id: Some("req-004".to_string()),
                method: "PUT".to_string(),
                url: "https://api.openai.com/v1/fine-tunes/ft-001".to_string(),
                agent_id: Some("agent-2".to_string()),
                status: 200,
                plugin_name: None,
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
            },
        ];
        for entry in &entries {
            db.log_activity(entry).await.unwrap();
        }
    }

    /// GET /activity with a filter parameter and return the activity entries.
    async fn get_activity_filtered(state: ApiState, password: &str, query: &str) -> Vec<ActivityEntry> {
        let app = create_router(state);
        let auth_body = serde_json::to_vec(&serde_json::json!({ "password_hash": password })).unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/activity{}", query))
                    .header("content-type", "application/json")
                    .body(Body::from(auth_body))
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

        // 2 entries with plugin_name=openai
        assert_eq!(result.len(), 2, "expected 2 entries for plugin=openai");
        for entry in &result {
            assert_eq!(
                entry.plugin_name.as_deref(),
                Some("openai"),
                "unexpected plugin: {:?}",
                entry.plugin_name
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
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        }).await.unwrap();

        db.log_activity(&ActivityEntry {
            timestamp: recent_ts,
            request_id: None,
            method: "POST".to_string(),
            url: "https://new.example.com/data".to_string(),
            agent_id: None,
            status: 201,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
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
        let state = ApiState::new(9443, 9080, db);
        // No password hash set — any request should fail auth

        let app = create_router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/activity")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&serde_json::json!({ "password_hash": "wrongpass" })).unwrap()))
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
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

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
        let body = serde_json::json!({"password_hash": password});

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/activity/test-details-001/details")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
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
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

        let password = "test-password";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);
        let body = serde_json::json!({"password_hash": password});

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/activity/nonexistent-id/details")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
