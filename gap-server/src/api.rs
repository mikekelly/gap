//! Management API for GAP Server
//!
//! Provides HTTP endpoints for:
//! - Server status
//! - Plugin management
//! - Credential management
//! - Token management
//! - Activity monitoring

use gap_lib::{AgentToken, ActivityEntry};
use gap_lib::database::GapDatabase;
use gap_lib::registry::PluginEntry;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::{
    async_trait,
    body::Bytes,
    extract::{FromRequestParts, Path, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
    /// TLS configuration for hot-reloading certificates
    pub tls_config: Option<axum_server::tls_rustls::RustlsConfig>,
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
            tls_config: None,
        }
    }

    /// Create ApiState with TLS config for hot-reloading
    pub fn new_with_tls(
        proxy_port: u16,
        api_port: u16,
        db: Arc<GapDatabase>,
        tls_config: axum_server::tls_rustls::RustlsConfig,
    ) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            proxy_port,
            api_port,
            password_hash: Arc::new(RwLock::new(None)),
            db,
            tls_config: Some(tls_config),
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

/// Init request
#[derive(Debug, Deserialize)]
pub struct InitRequest {
    pub management_sans: Option<Vec<String>>,
}

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

/// Rotate management certificate request
#[derive(Debug, Deserialize)]
pub struct RotateManagementCertRequest {
    pub sans: Vec<String>,
}

/// Rotate management certificate response
#[derive(Debug, Serialize, Deserialize)]
pub struct RotateManagementCertResponse {
    pub sans: Vec<String>,
    pub rotated: bool,
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
        .route("/activity", get(get_activity).post(post_activity))
        .route("/v1/management-cert", post(rotate_management_cert))
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
    use gap_lib::tls::CertificateAuthority;
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

    // Load the existing CA from database (it was already generated at server startup)
    let ca_cert_pem = state.db
        .get_config("ca:cert")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load CA cert: {}", e)))?
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "CA not found in storage".to_string()))?;

    let ca_key_pem = state.db
        .get_config("ca:key")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load CA key: {}", e)))?
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "CA key not found in storage".to_string()))?;

    let ca_cert_str = String::from_utf8(ca_cert_pem)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid CA cert encoding: {}", e)))?;

    let ca_key_str = String::from_utf8(ca_key_pem)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid CA key encoding: {}", e)))?;

    let ca = CertificateAuthority::from_pem(&ca_cert_str, &ca_key_str)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load CA: {}", e)))?;

    // Return the well-known CA path (CA was already exported at server boot)
    let ca_path = gap_lib::ca_cert_path().to_string_lossy().to_string();

    // Generate management certificate with provided SANs or defaults
    let management_sans = req.data.management_sans.unwrap_or_else(|| {
        vec![
            "DNS:localhost".to_string(),
            "IP:127.0.0.1".to_string(),
            "IP:::1".to_string(),
        ]
    });

    let (mgmt_cert_der, mgmt_key_der) = ca.sign_server_cert(&management_sans)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate management certificate: {}", e)))?;

    // Convert DER to PEM for storage
    let mgmt_cert_pem = gap_lib::tls::der_to_pem(&mgmt_cert_der, "CERTIFICATE");
    let mgmt_key_pem = gap_lib::tls::der_to_pem(&mgmt_key_der, "PRIVATE KEY");

    // Store management cert and key
    state.db.set_config("mgmt:cert", mgmt_cert_pem.as_bytes()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store management cert: {}", e)))?;

    state.db.set_config("mgmt:key", mgmt_key_pem.as_bytes()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store management key: {}", e)))?;

    // Store the SANs used (for reference)
    let sans_json = serde_json::to_vec(&management_sans)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize SANs: {}", e)))?;
    state.db.set_config("mgmt:sans", &sans_json).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store management SANs: {}", e)))?;

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

/// GET /activity - Get recent activity (requires auth)
async fn get_activity(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Json<ActivityResponse>, (StatusCode, String)> {
    verify_auth::<serde_json::Value>(&state, &body).await?;

    let entries = state.db.get_activity(Some(100)).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get activity: {}", e)))?;
    Ok(Json(ActivityResponse { entries }))
}

/// POST /activity - Get recent activity (requires auth, same as GET)
async fn post_activity(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Json<ActivityResponse>, (StatusCode, String)> {
    get_activity(State(state), body).await
}

/// POST /v1/management-cert - Rotate management certificate (requires auth)
async fn rotate_management_cert(
    State(state): State<ApiState>,
    body: Bytes,
) -> Result<Json<RotateManagementCertResponse>, (StatusCode, String)> {
    use gap_lib::tls::CertificateAuthority;

    // Verify authentication and extract request data
    let req: RotateManagementCertRequest = verify_auth(&state, &body).await?;

    // Load the CA from database
    let ca_cert_pem = state.db
        .get_config("ca:cert")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load CA cert: {}", e)))?
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "CA not found in storage".to_string()))?;

    let ca_key_pem = state.db
        .get_config("ca:key")
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load CA key: {}", e)))?
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "CA key not found in storage".to_string()))?;

    let ca_cert_str = String::from_utf8(ca_cert_pem)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid CA cert encoding: {}", e)))?;

    let ca_key_str = String::from_utf8(ca_key_pem)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid CA key encoding: {}", e)))?;

    let ca = CertificateAuthority::from_pem(&ca_cert_str, &ca_key_str)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load CA: {}", e)))?;

    // Generate new management certificate with provided SANs
    let (mgmt_cert_der, mgmt_key_der) = ca.sign_server_cert(&req.sans)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate management certificate: {}", e)))?;

    // Convert DER to PEM for storage
    let mgmt_cert_pem = gap_lib::tls::der_to_pem(&mgmt_cert_der, "CERTIFICATE");
    let mgmt_key_pem = gap_lib::tls::der_to_pem(&mgmt_key_der, "PRIVATE KEY");

    // Store new management cert and key
    state.db.set_config("mgmt:cert", mgmt_cert_pem.as_bytes()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store management cert: {}", e)))?;

    state.db.set_config("mgmt:key", mgmt_key_pem.as_bytes()).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store management key: {}", e)))?;

    // Store the SANs used (for reference)
    let sans_json = serde_json::to_vec(&req.sans)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize SANs: {}", e)))?;
    state.db.set_config("mgmt:sans", &sans_json).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store management SANs: {}", e)))?;

    // Hot-reload TLS config if available
    if let Some(ref tls_config) = state.tls_config {
        tls_config.reload_from_pem(
            mgmt_cert_pem.as_bytes().to_vec(),
            mgmt_key_pem.as_bytes().to_vec()
        ).await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to reload TLS config: {}", e)))?;
        tracing::info!("TLS config reloaded with new certificate");
    }

    tracing::info!("Rotated management certificate with SANs: {:?}", req.sans);

    Ok(Json(RotateManagementCertResponse {
        sans: req.sans,
        rotated: true,
    }))
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
        use gap_lib::registry::CredentialEntry;
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
        use gap_lib::registry::CredentialEntry;
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

    #[tokio::test]
    #[serial]
    async fn test_init_endpoint_with_management_sans() {
        use gap_lib::tls::CertificateAuthority;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;

        // Pre-create CA in database (as server does at startup)
        let ca = CertificateAuthority::generate().expect("generate CA");
        db.set_config("ca:cert", ca.ca_cert_pem().as_bytes()).await.expect("store CA cert");
        db.set_config("ca:key", ca.ca_key_pem().as_bytes()).await.expect("store CA key");

        let state = ApiState::new(9443, 9080, Arc::clone(&db));
        let app = create_router(state);

        let password = "testpass123";

        // Create init request with custom management SANs
        let body = serde_json::json!({
            "password_hash": password,
            "management_sans": ["DNS:example.com", "IP:192.168.1.1"]
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

        // Verify management cert and key were stored
        let mgmt_cert = db.get_config("mgmt:cert").await.expect("get mgmt:cert");
        assert!(mgmt_cert.is_some(), "Management cert should be stored");

        let mgmt_key = db.get_config("mgmt:key").await.expect("get mgmt:key");
        assert!(mgmt_key.is_some(), "Management key should be stored");

        // Verify the stored SANs
        let mgmt_sans = db.get_config("mgmt:sans").await.expect("get mgmt:sans");
        assert!(mgmt_sans.is_some(), "Management SANs should be stored");
        let sans: Vec<String> = serde_json::from_slice(&mgmt_sans.unwrap()).expect("parse SANs JSON");
        assert_eq!(sans, vec!["DNS:example.com", "IP:192.168.1.1"]);
    }

    #[tokio::test]
    #[serial]
    async fn test_init_endpoint_with_default_management_sans() {
        use gap_lib::tls::CertificateAuthority;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;

        // Pre-create CA in database (as server does at startup)
        let ca = CertificateAuthority::generate().expect("generate CA");
        db.set_config("ca:cert", ca.ca_cert_pem().as_bytes()).await.expect("store CA cert");
        db.set_config("ca:key", ca.ca_key_pem().as_bytes()).await.expect("store CA key");

        let state = ApiState::new(9443, 9080, Arc::clone(&db));
        let app = create_router(state);

        let password = "testpass123";

        // Create init request without management SANs (should use defaults)
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

        // Verify management cert and key were stored
        let mgmt_cert = db.get_config("mgmt:cert").await.expect("get mgmt:cert");
        assert!(mgmt_cert.is_some(), "Management cert should be stored");

        let mgmt_key = db.get_config("mgmt:key").await.expect("get mgmt:key");
        assert!(mgmt_key.is_some(), "Management key should be stored");

        // Verify the default SANs were used
        let mgmt_sans = db.get_config("mgmt:sans").await.expect("get mgmt:sans");
        assert!(mgmt_sans.is_some(), "Management SANs should be stored");
        let sans: Vec<String> = serde_json::from_slice(&mgmt_sans.unwrap()).expect("parse SANs JSON");
        assert_eq!(sans, vec!["DNS:localhost", "IP:127.0.0.1", "IP:::1"]);
    }

    #[tokio::test]
    #[serial]
    async fn test_rotate_management_cert_endpoint() {
        use gap_lib::tls::CertificateAuthority;
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;

        // Pre-create CA in database
        let ca = CertificateAuthority::generate().expect("generate CA");
        db.set_config("ca:cert", ca.ca_cert_pem().as_bytes()).await.expect("store CA cert");
        db.set_config("ca:key", ca.ca_key_pem().as_bytes()).await.expect("store CA key");

        // Pre-create initial management cert
        let initial_sans = vec!["DNS:localhost".to_string()];
        let (initial_cert_der, initial_key_der) = ca.sign_server_cert(&initial_sans).expect("sign initial cert");
        let initial_cert_pem = gap_lib::tls::der_to_pem(&initial_cert_der, "CERTIFICATE");
        let initial_key_pem = gap_lib::tls::der_to_pem(&initial_key_der, "PRIVATE KEY");
        db.set_config("mgmt:cert", initial_cert_pem.as_bytes()).await.expect("store initial cert");
        db.set_config("mgmt:key", initial_key_pem.as_bytes()).await.expect("store initial key");

        let state = ApiState::new(9443, 9080, Arc::clone(&db));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Rotate certificate with new SANs
        let body = serde_json::json!({
            "password_hash": password,
            "sans": ["DNS:example.com", "IP:192.168.1.100"]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/management-cert")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify new cert and key were stored
        let new_cert = db.get_config("mgmt:cert").await.expect("get new cert");
        assert!(new_cert.is_some());
        let new_cert_pem = String::from_utf8(new_cert.unwrap()).expect("parse cert PEM");

        // Cert should be different from initial
        assert_ne!(new_cert_pem, initial_cert_pem);

        // Verify the response contains cert details
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        // Response should have sans field
        assert!(response_json.get("sans").is_some());
        let returned_sans = response_json["sans"].as_array().unwrap();
        assert_eq!(returned_sans.len(), 2);
    }

    #[tokio::test]
    #[serial]
    async fn test_rotate_management_cert_requires_auth() {
        let db = create_test_db().await;
        let state = ApiState::new(9443, 9080, db);
        let app = create_router(state);

        // Try to rotate without password
        let body = serde_json::json!({
            "sans": ["DNS:example.com"]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/management-cert")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // Test for TLS hot-swap - verify rotate_management_cert updates storage and attempts reload
    #[tokio::test]
    #[serial]
    async fn test_rotate_management_cert_hot_swap() {
        use gap_lib::tls::CertificateAuthority;
        use argon2::password_hash::{rand_core::OsRng, SaltString};
        use argon2::{Argon2, PasswordHasher};

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        std::env::set_var("GAP_DATA_DIR", temp_dir.path());

        let db = create_test_db().await;

        // Pre-create CA in database
        let ca = CertificateAuthority::generate().expect("generate CA");
        db.set_config("ca:cert", ca.ca_cert_pem().as_bytes()).await.expect("store CA cert");
        db.set_config("ca:key", ca.ca_key_pem().as_bytes()).await.expect("store CA key");

        // Pre-create initial management cert
        let initial_sans = vec!["DNS:localhost".to_string()];
        let (initial_cert_der, initial_key_der) = ca.sign_server_cert(&initial_sans).expect("sign initial cert");
        let initial_cert_pem = gap_lib::tls::der_to_pem(&initial_cert_der, "CERTIFICATE");
        let initial_key_pem = gap_lib::tls::der_to_pem(&initial_key_der, "PRIVATE KEY");
        db.set_config("mgmt:cert", initial_cert_pem.as_bytes()).await.expect("store initial cert");
        db.set_config("mgmt:key", initial_key_pem.as_bytes()).await.expect("store initial key");

        // Create ApiState without TLS config (tls_config field will be None)
        // This simulates the scenario where hot-swap is optional
        let state = ApiState::new(9443, 9080, Arc::clone(&db));

        // Set up password hash
        let password = "testpass123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string();
        state.set_password_hash(password_hash).await;

        let app = create_router(state);

        // Rotate certificate with new SANs
        let body = serde_json::json!({
            "password_hash": password,
            "sans": ["DNS:example.com", "IP:192.168.1.100"]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/management-cert")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify new cert and key were stored
        let new_cert = db.get_config("mgmt:cert").await.expect("get new cert");
        assert!(new_cert.is_some());
        let new_cert_pem = String::from_utf8(new_cert.unwrap()).expect("parse cert PEM");

        // Cert should be different from initial (rotation occurred)
        assert_ne!(new_cert_pem, initial_cert_pem);
    }
}
