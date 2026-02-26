use crate::error::{GapError, Result};
use crate::types::{
    ActivityEntry, ActivityFilter, CredentialEntry, HeaderSet, ManagementLogEntry,
    ManagementLogFilter, PluginEntry, PluginVersion, RequestDetails, TokenEntry, TokenMetadata,
    TokenScope,
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgArguments;
use sqlx::{Arguments, PgPool, Row};
use std::collections::HashMap;
use uuid::Uuid;

const POSTGRES_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    token_value TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    has_scopes BOOLEAN NOT NULL DEFAULT FALSE,
    namespace_id TEXT NOT NULL DEFAULT 'default',
    scope_id TEXT NOT NULL DEFAULT 'default'
);

CREATE TABLE IF NOT EXISTS token_scopes (
    token_value TEXT NOT NULL REFERENCES tokens(token_value),
    host_pattern TEXT NOT NULL,
    port INTEGER,
    path_pattern TEXT NOT NULL DEFAULT '/*',
    methods TEXT
);

CREATE INDEX IF NOT EXISTS idx_token_scopes_token ON token_scopes(token_value);

CREATE TABLE IF NOT EXISTS credentials (
    plugin_id TEXT NOT NULL,
    field TEXT NOT NULL,
    value TEXT NOT NULL,
    namespace_id TEXT NOT NULL DEFAULT 'default',
    scope_id TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (namespace_id, scope_id, plugin_id, field)
);

CREATE TABLE IF NOT EXISTS access_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    request_id TEXT,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    agent_id TEXT,
    status INTEGER NOT NULL,
    plugin_id TEXT,
    plugin_sha TEXT,
    source_hash TEXT,
    request_headers TEXT,
    rejection_stage TEXT,
    rejection_reason TEXT,
    namespace_id TEXT NOT NULL DEFAULT 'default',
    scope_id TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_access_logs_url ON access_logs(url);

CREATE TABLE IF NOT EXISTS plugin_versions (
    id BIGSERIAL PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    hosts TEXT NOT NULL DEFAULT '[]',
    credential_schema TEXT NOT NULL DEFAULT '[]',
    commit_sha TEXT,
    source_hash TEXT NOT NULL,
    source_code TEXT NOT NULL,
    installed_at TIMESTAMPTZ NOT NULL,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    dangerously_permit_http BOOLEAN NOT NULL DEFAULT FALSE,
    weight INTEGER NOT NULL DEFAULT 0,
    namespace_id TEXT NOT NULL DEFAULT 'default',
    scope_id TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_plugin_versions_plugin ON plugin_versions(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_versions_hash ON plugin_versions(source_hash);

CREATE TABLE IF NOT EXISTS management_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    operation TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    success BOOLEAN NOT NULL,
    error_message TEXT NOT NULL DEFAULT '',
    namespace_id TEXT NOT NULL DEFAULT 'default',
    scope_id TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_management_logs_timestamp ON management_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_management_logs_operation ON management_logs(operation);

CREATE TABLE IF NOT EXISTS request_details (
    request_id TEXT PRIMARY KEY,
    req_headers TEXT,
    req_body BYTEA,
    transformed_url TEXT,
    transformed_headers TEXT,
    transformed_body BYTEA,
    response_status INTEGER,
    response_headers TEXT,
    response_body BYTEA,
    body_truncated BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS header_sets (
    id TEXT PRIMARY KEY,
    match_patterns TEXT NOT NULL DEFAULT '[]',
    weight INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    namespace_id TEXT NOT NULL DEFAULT 'default',
    scope_id TEXT NOT NULL DEFAULT 'default'
);

CREATE TABLE IF NOT EXISTS header_set_headers (
    header_set_id TEXT NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,
    PRIMARY KEY (header_set_id, header_name)
);

CREATE INDEX IF NOT EXISTS idx_plugin_versions_ns ON plugin_versions(namespace_id, scope_id);
CREATE INDEX IF NOT EXISTS idx_credentials_ns ON credentials(namespace_id, scope_id);
CREATE INDEX IF NOT EXISTS idx_header_sets_ns ON header_sets(namespace_id, scope_id);
CREATE INDEX IF NOT EXISTS idx_access_logs_ns ON access_logs(namespace_id, scope_id);
CREATE INDEX IF NOT EXISTS idx_management_logs_ns ON management_logs(namespace_id, scope_id);
CREATE INDEX IF NOT EXISTS idx_tokens_ns ON tokens(namespace_id, scope_id);

CREATE TABLE IF NOT EXISTS used_nonces (
    namespace_id TEXT NOT NULL DEFAULT 'default',
    scope_id TEXT NOT NULL DEFAULT 'default',
    key_id TEXT NOT NULL,
    nonce_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE(namespace_id, scope_id, key_id, nonce_hash)
);

CREATE INDEX IF NOT EXISTS idx_used_nonces_expires ON used_nonces(expires_at);
";

pub async fn run_postgres_migrations(pool: &PgPool, schema: &str) -> Result<()> {
    tracing::debug!(schema, "Applying Postgres schema");

    let set_path = format!("CREATE SCHEMA IF NOT EXISTS {schema}; SET search_path TO {schema};");

    sqlx::raw_sql(&format!("{set_path}\n{POSTGRES_SCHEMA}"))
        .execute(pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Postgres schema creation failed");
            GapError::database(format!("Failed to run Postgres migrations: {}", e))
        })?;

    Ok(())
}

// ── Config KV ───────────────────────────────────────────────────

pub(crate) async fn pg_set_config(pool: &PgPool, key: &str, value: &[u8]) -> Result<()> {
    sqlx::query(
        "INSERT INTO config (key, value) VALUES ($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

pub(crate) async fn pg_get_config(pool: &PgPool, key: &str) -> Result<Option<Vec<u8>>> {
    let row = sqlx::query("SELECT value FROM config WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    match row {
        Some(r) => {
            let val: Vec<u8> = r.get("value");
            Ok(Some(val))
        }
        None => Ok(None),
    }
}

pub(crate) async fn pg_delete_config(pool: &PgPool, key: &str) -> Result<()> {
    sqlx::query("DELETE FROM config WHERE key = $1")
        .bind(key)
        .execute(pool)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

// ── Token CRUD ──────────────────────────────────────────────────

pub(crate) async fn pg_add_token(
    pool: &PgPool,
    token_value: &str,
    created_at: DateTime<Utc>,
    scopes: Option<&[TokenScope]>,
    ns: &str,
    scope: &str,
) -> Result<()> {
    let has_scopes = scopes.is_some();

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    sqlx::query(
        "INSERT INTO tokens (token_value, name, created_at, has_scopes, namespace_id, scope_id) \
         VALUES ($1, '', $2, $3, $4, $5) \
         ON CONFLICT (token_value) DO UPDATE SET \
         name = EXCLUDED.name, created_at = EXCLUDED.created_at, \
         has_scopes = EXCLUDED.has_scopes, namespace_id = EXCLUDED.namespace_id, \
         scope_id = EXCLUDED.scope_id",
    )
    .bind(token_value)
    .bind(created_at)
    .bind(has_scopes)
    .bind(ns)
    .bind(scope)
    .execute(&mut *tx)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    if let Some(scope_list) = scopes {
        for s in scope_list {
            let methods_json = s
                .methods
                .as_ref()
                .map(|m| serde_json::to_string(m).unwrap_or_default());
            let port = s.port.map(|p| p as i32);

            sqlx::query(
                "INSERT INTO token_scopes (token_value, host_pattern, port, path_pattern, methods) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(token_value)
            .bind(&s.host_pattern)
            .bind(port)
            .bind(&s.path_pattern)
            .bind(&methods_json)
            .execute(&mut *tx)
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        }
    }

    tx.commit()
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    Ok(())
}

pub(crate) async fn pg_get_token(
    pool: &PgPool,
    token_value: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<TokenMetadata>> {
    let row = sqlx::query(
        "SELECT created_at, has_scopes FROM tokens \
         WHERE token_value = $1 AND revoked_at IS NULL AND namespace_id = $2 AND scope_id = $3",
    )
    .bind(token_value)
    .bind(ns)
    .bind(scope)
    .fetch_optional(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    match row {
        Some(r) => {
            let created_at: DateTime<Utc> = r.get("created_at");
            let has_scopes: bool = r.get("has_scopes");

            let scopes = if has_scopes {
                Some(pg_get_token_scopes(pool, token_value).await?)
            } else {
                None
            };

            Ok(Some(TokenMetadata {
                created_at,
                scopes,
                revoked_at: None,
                namespace_id: ns.to_string(),
                scope_id: scope.to_string(),
            }))
        }
        None => Ok(None),
    }
}

async fn pg_get_token_scopes(pool: &PgPool, token_value: &str) -> Result<Vec<TokenScope>> {
    let rows = sqlx::query(
        "SELECT host_pattern, port, path_pattern, methods FROM token_scopes WHERE token_value = $1",
    )
    .bind(token_value)
    .fetch_all(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    let mut scopes = Vec::new();
    for row in rows {
        let host_pattern: String = row.get("host_pattern");
        let port: Option<i32> = row.get("port");
        let path_pattern: String = row.get("path_pattern");
        let methods_json: Option<String> = row.get("methods");

        let methods: Option<Vec<String>> =
            methods_json.and_then(|json| serde_json::from_str(&json).ok());

        scopes.push(TokenScope {
            host_pattern,
            port: port.map(|p| p as u16),
            path_pattern,
            methods,
        });
    }
    Ok(scopes)
}

pub(crate) async fn pg_list_tokens(
    pool: &PgPool,
    include_revoked: bool,
    ns: &str,
    scope: &str,
) -> Result<Vec<TokenEntry>> {
    let query = if include_revoked {
        "SELECT token_value, created_at, revoked_at, has_scopes FROM tokens \
         WHERE namespace_id = $1 AND scope_id = $2"
    } else {
        "SELECT token_value, created_at, revoked_at, has_scopes FROM tokens \
         WHERE revoked_at IS NULL AND namespace_id = $1 AND scope_id = $2"
    };

    let rows = sqlx::query(query)
        .bind(ns)
        .bind(scope)
        .fetch_all(pool)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    let mut result = Vec::new();
    for row in rows {
        let token_value: String = row.get("token_value");
        let created_at: DateTime<Utc> = row.get("created_at");
        let revoked_at: Option<DateTime<Utc>> = row.get("revoked_at");
        let has_scopes: bool = row.get("has_scopes");

        let scopes = if has_scopes {
            Some(pg_get_token_scopes(pool, &token_value).await?)
        } else {
            None
        };

        result.push(TokenEntry {
            token_value,
            created_at,
            scopes,
            revoked_at,
            namespace_id: ns.to_string(),
            scope_id: scope.to_string(),
        });
    }
    Ok(result)
}

pub(crate) async fn pg_revoke_token(
    pool: &PgPool,
    token_value: &str,
    ns: &str,
    scope: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE tokens SET revoked_at = $1 \
         WHERE token_value = $2 AND revoked_at IS NULL AND namespace_id = $3 AND scope_id = $4",
    )
    .bind(Utc::now())
    .bind(token_value)
    .bind(ns)
    .bind(scope)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

pub(crate) async fn pg_get_token_by_prefix(
    pool: &PgPool,
    prefix: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<String>> {
    let pattern = format!("{}%", prefix);
    let row = sqlx::query(
        "SELECT token_value FROM tokens \
         WHERE token_value LIKE $1 AND revoked_at IS NULL AND namespace_id = $2 AND scope_id = $3",
    )
    .bind(&pattern)
    .bind(ns)
    .bind(scope)
    .fetch_optional(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    match row {
        Some(r) => {
            let token_value: String = r.get("token_value");
            Ok(Some(token_value))
        }
        None => Ok(None),
    }
}

// ── Plugin CRUD ─────────────────────────────────────────────────

pub(crate) async fn pg_add_plugin(
    pool: &PgPool,
    plugin: &PluginEntry,
    source_code: &str,
    ns: &str,
    scope: &str,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let hosts_json =
        serde_json::to_string(&plugin.hosts).map_err(|e| GapError::database(e.to_string()))?;
    let schema_json = serde_json::to_string(&plugin.credential_schema)
        .map_err(|e| GapError::database(e.to_string()))?;

    let source_hash = format!("{:x}", Sha256::digest(source_code.as_bytes()));
    let now = Utc::now();
    let commit_sha = plugin.commit_sha.as_deref().unwrap_or("");

    sqlx::query(
        "INSERT INTO plugin_versions \
         (plugin_id, hosts, credential_schema, commit_sha, source_hash, source_code, \
          installed_at, deleted, dangerously_permit_http, weight, namespace_id, scope_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8, $9, $10, $11)",
    )
    .bind(&id)
    .bind(&hosts_json)
    .bind(&schema_json)
    .bind(commit_sha)
    .bind(&source_hash)
    .bind(source_code)
    .bind(now)
    .bind(plugin.dangerously_permit_http)
    .bind(plugin.weight)
    .bind(ns)
    .bind(scope)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    Ok(id)
}

pub(crate) async fn pg_get_plugin(
    pool: &PgPool,
    id: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<PluginEntry>> {
    let row = sqlx::query(
        "SELECT plugin_id, hosts, credential_schema, commit_sha, deleted, \
         dangerously_permit_http, weight, installed_at \
         FROM plugin_versions \
         WHERE plugin_id = $1 AND namespace_id = $2 AND scope_id = $3 \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(id)
    .bind(ns)
    .bind(scope)
    .fetch_optional(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    match row {
        Some(r) => {
            let deleted: bool = r.get("deleted");
            if deleted {
                return Ok(None);
            }
            Ok(Some(pg_row_to_plugin_entry(&r, ns, scope)?))
        }
        None => Ok(None),
    }
}

pub(crate) async fn pg_get_plugin_source(
    pool: &PgPool,
    id: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT source_code, deleted FROM plugin_versions \
         WHERE plugin_id = $1 AND namespace_id = $2 AND scope_id = $3 \
         ORDER BY id DESC LIMIT 1",
    )
    .bind(id)
    .bind(ns)
    .bind(scope)
    .fetch_optional(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    match row {
        Some(r) => {
            let deleted: bool = r.get("deleted");
            if deleted {
                return Ok(None);
            }
            let source: String = r.get("source_code");
            Ok(Some(source))
        }
        None => Ok(None),
    }
}

pub(crate) async fn pg_list_plugins(
    pool: &PgPool,
    ns: &str,
    scope: &str,
) -> Result<Vec<PluginEntry>> {
    let rows = sqlx::query(
        "SELECT pv.plugin_id, pv.hosts, pv.credential_schema, pv.commit_sha, \
         pv.dangerously_permit_http, pv.weight, pv.installed_at \
         FROM plugin_versions pv \
         INNER JOIN ( \
             SELECT plugin_id, MAX(id) as max_id \
             FROM plugin_versions \
             WHERE namespace_id = $1 AND scope_id = $2 \
             GROUP BY plugin_id \
         ) latest ON pv.id = latest.max_id \
         WHERE pv.deleted = FALSE AND pv.namespace_id = $1 AND pv.scope_id = $2",
    )
    .bind(ns)
    .bind(scope)
    .fetch_all(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    let mut result = Vec::new();
    for row in rows {
        result.push(pg_row_to_plugin_entry(&row, ns, scope)?);
    }
    Ok(result)
}

pub(crate) async fn pg_remove_plugin(
    pool: &PgPool,
    id: &str,
    ns: &str,
    scope: &str,
) -> Result<()> {
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO plugin_versions \
         (plugin_id, hosts, credential_schema, commit_sha, source_hash, source_code, \
          installed_at, deleted, namespace_id, scope_id) \
         VALUES ($1, '[]', '[]', '', '', '', $2, TRUE, $3, $4)",
    )
    .bind(id)
    .bind(now)
    .bind(ns)
    .bind(scope)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

pub(crate) async fn pg_get_plugin_version_by_hash(
    pool: &PgPool,
    source_hash: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<PluginVersion>> {
    let row = sqlx::query(
        "SELECT plugin_id, commit_sha, source_hash, source_code, installed_at \
         FROM plugin_versions \
         WHERE source_hash = $1 AND namespace_id = $2 AND scope_id = $3 \
         LIMIT 1",
    )
    .bind(source_hash)
    .bind(ns)
    .bind(scope)
    .fetch_optional(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    match row {
        Some(r) => {
            let plugin_id: String = r.get("plugin_id");
            let commit_sha_raw: String =
                r.get::<Option<String>, _>("commit_sha").unwrap_or_default();
            let source_hash_val: String = r.get("source_hash");
            let source_code: String = r.get("source_code");
            let installed_at: DateTime<Utc> = r.get("installed_at");

            let commit_sha = if commit_sha_raw.is_empty() {
                None
            } else {
                Some(commit_sha_raw)
            };

            Ok(Some(PluginVersion {
                plugin_id,
                commit_sha,
                source_hash: source_hash_val,
                source_code,
                installed_at,
            }))
        }
        None => Ok(None),
    }
}

pub(crate) async fn pg_update_plugin_weight(
    pool: &PgPool,
    id: &str,
    weight: i32,
    ns: &str,
    scope: &str,
) -> Result<()> {
    let result = sqlx::query(
        "UPDATE plugin_versions SET weight = $1 \
         WHERE id = (SELECT MAX(id) FROM plugin_versions \
         WHERE plugin_id = $2 AND deleted = FALSE AND namespace_id = $3 AND scope_id = $4)",
    )
    .bind(weight)
    .bind(id)
    .bind(ns)
    .bind(scope)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(GapError::database(format!("Plugin '{}' not found", id)));
    }
    Ok(())
}

/// Parse a Postgres row into a PluginEntry.
/// Expects columns: plugin_id, hosts, credential_schema, commit_sha,
///                   dangerously_permit_http, weight, installed_at
fn pg_row_to_plugin_entry(
    row: &sqlx::postgres::PgRow,
    ns: &str,
    scope: &str,
) -> Result<PluginEntry> {
    let id: String = row.get("plugin_id");
    let hosts_json: String = row.get("hosts");
    let schema_json: String = row.get("credential_schema");
    let commit_sha_raw: String = row.get::<Option<String>, _>("commit_sha").unwrap_or_default();

    let hosts: Vec<String> =
        serde_json::from_str(&hosts_json).map_err(|e| GapError::database(e.to_string()))?;
    let credential_schema: Vec<String> =
        serde_json::from_str(&schema_json).map_err(|e| GapError::database(e.to_string()))?;
    let commit_sha = if commit_sha_raw.is_empty() {
        None
    } else {
        Some(commit_sha_raw)
    };
    let dangerously_permit_http: bool = row.get("dangerously_permit_http");
    let weight: i32 = row.get("weight");
    let installed_at: Option<DateTime<Utc>> = row.get("installed_at");

    Ok(PluginEntry {
        id,
        source: None,
        hosts,
        credential_schema,
        commit_sha,
        dangerously_permit_http,
        weight,
        installed_at,
        namespace_id: ns.to_string(),
        scope_id: scope.to_string(),
    })
}

// ── Credential CRUD ─────────────────────────────────────────────

pub(crate) async fn pg_set_credential(
    pool: &PgPool,
    plugin_id: &str,
    field: &str,
    value: &str,
    ns: &str,
    scope: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO credentials (namespace_id, scope_id, plugin_id, field, value) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (namespace_id, scope_id, plugin_id, field) \
         DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(ns)
    .bind(scope)
    .bind(plugin_id)
    .bind(field)
    .bind(value)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

pub(crate) async fn pg_get_credential(
    pool: &PgPool,
    plugin_id: &str,
    field: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT value FROM credentials \
         WHERE plugin_id = $1 AND field = $2 AND namespace_id = $3 AND scope_id = $4",
    )
    .bind(plugin_id)
    .bind(field)
    .bind(ns)
    .bind(scope)
    .fetch_optional(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    match row {
        Some(r) => {
            let value: String = r.get("value");
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

pub(crate) async fn pg_get_plugin_credentials(
    pool: &PgPool,
    plugin_id: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<HashMap<String, String>>> {
    let rows = sqlx::query(
        "SELECT field, value FROM credentials \
         WHERE plugin_id = $1 AND namespace_id = $2 AND scope_id = $3",
    )
    .bind(plugin_id)
    .bind(ns)
    .bind(scope)
    .fetch_all(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    let mut map = HashMap::new();
    for row in rows {
        let field: String = row.get("field");
        let value: String = row.get("value");
        map.insert(field, value);
    }

    if map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(map))
    }
}

pub(crate) async fn pg_list_credentials(
    pool: &PgPool,
    ns: &str,
    scope: &str,
) -> Result<Vec<CredentialEntry>> {
    let rows = sqlx::query(
        "SELECT plugin_id, field FROM credentials \
         WHERE namespace_id = $1 AND scope_id = $2",
    )
    .bind(ns)
    .bind(scope)
    .fetch_all(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    let mut result = Vec::new();
    for row in rows {
        let plugin_id: String = row.get("plugin_id");
        let field: String = row.get("field");
        result.push(CredentialEntry {
            plugin_id,
            field,
            namespace_id: ns.to_string(),
            scope_id: scope.to_string(),
        });
    }
    Ok(result)
}

pub(crate) async fn pg_remove_credential(
    pool: &PgPool,
    plugin_id: &str,
    field: &str,
    ns: &str,
    scope: &str,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM credentials \
         WHERE plugin_id = $1 AND field = $2 AND namespace_id = $3 AND scope_id = $4",
    )
    .bind(plugin_id)
    .bind(field)
    .bind(ns)
    .bind(scope)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

// ── Activity Logging ────────────────────────────────────────────

pub(crate) async fn pg_log_activity(pool: &PgPool, entry: &ActivityEntry) -> Result<()> {
    sqlx::query(
        "INSERT INTO access_logs \
         (timestamp, request_id, method, url, agent_id, status, plugin_id, plugin_sha, \
          source_hash, request_headers, rejection_stage, rejection_reason, \
          namespace_id, scope_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(entry.timestamp)
    .bind(entry.request_id.as_deref().unwrap_or(""))
    .bind(&entry.method)
    .bind(&entry.url)
    .bind(entry.agent_id.as_deref().unwrap_or(""))
    .bind(entry.status as i32)
    .bind(entry.plugin_id.as_deref().unwrap_or(""))
    .bind(entry.plugin_sha.as_deref().unwrap_or(""))
    .bind(entry.source_hash.as_deref().unwrap_or(""))
    .bind(entry.request_headers.as_deref().unwrap_or(""))
    .bind(entry.rejection_stage.as_deref().unwrap_or(""))
    .bind(entry.rejection_reason.as_deref().unwrap_or(""))
    .bind(&entry.namespace_id)
    .bind(&entry.scope_id)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(format!("Failed to log activity: {}", e)))?;
    Ok(())
}

pub(crate) async fn pg_query_activity(
    pool: &PgPool,
    filter: &ActivityFilter,
) -> Result<Vec<ActivityEntry>> {
    let select = "SELECT timestamp, request_id, method, url, agent_id, status, plugin_id, \
                   plugin_sha, source_hash, request_headers, rejection_stage, rejection_reason, \
                   namespace_id, scope_id FROM access_logs";

    let mut conditions: Vec<String> = Vec::new();
    let mut args = PgArguments::default();
    let mut idx = 1u32;

    if let Some(ref domain) = filter.domain {
        conditions.push(format!("url LIKE ${}", idx));
        args.add(format!("%://{}%", domain))
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref path) = filter.path {
        conditions.push(format!("url LIKE ${}", idx));
        args.add(format!("%{}%", path))
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref plugin_id) = filter.plugin_id {
        conditions.push(format!("plugin_id = ${}", idx));
        args.add(plugin_id.clone())
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref agent) = filter.agent {
        conditions.push(format!("agent_id = ${}", idx));
        args.add(agent.clone())
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref method) = filter.method {
        conditions.push(format!("method = ${}", idx));
        args.add(method.clone())
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref since) = filter.since {
        conditions.push(format!("timestamp >= ${}", idx));
        args.add(*since)
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref request_id) = filter.request_id {
        conditions.push(format!("request_id = ${}", idx));
        args.add(request_id.clone())
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref namespace_id) = filter.namespace_id {
        conditions.push(format!("namespace_id = ${}", idx));
        args.add(namespace_id.clone())
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref scope_id) = filter.scope_id {
        conditions.push(format!("scope_id = ${}", idx));
        args.add(scope_id.clone())
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }

    let _ = idx;

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    let limit = filter.limit.unwrap_or(100);
    let query = format!(
        "{}{} ORDER BY id DESC LIMIT {}",
        select, where_clause, limit
    );

    let rows = sqlx::query_with(&query, args)
        .fetch_all(pool)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    pg_rows_to_activity(&rows)
}

fn empty_to_none(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn pg_rows_to_activity(rows: &[sqlx::postgres::PgRow]) -> Result<Vec<ActivityEntry>> {
    let mut result = Vec::new();
    for row in rows {
        let timestamp: DateTime<Utc> = row.get("timestamp");
        let request_id_raw: String = row.get("request_id");
        let method: String = row.get("method");
        let url: String = row.get("url");
        let agent_id_raw: String = row.get("agent_id");
        let status_i32: i32 = row.get("status");
        let plugin_id_raw: String = row.get("plugin_id");
        let plugin_sha_raw: String = row.get("plugin_sha");
        let source_hash_raw: String = row.get("source_hash");
        let request_headers_raw: String = row.get("request_headers");
        let rejection_stage_raw: String = row.get("rejection_stage");
        let rejection_reason_raw: String = row.get("rejection_reason");
        let namespace_id: String = row.get("namespace_id");
        let scope_id: String = row.get("scope_id");

        result.push(ActivityEntry {
            timestamp,
            request_id: empty_to_none(request_id_raw),
            method,
            url,
            agent_id: empty_to_none(agent_id_raw),
            status: status_i32 as u16,
            plugin_id: empty_to_none(plugin_id_raw),
            plugin_sha: empty_to_none(plugin_sha_raw),
            source_hash: empty_to_none(source_hash_raw),
            request_headers: empty_to_none(request_headers_raw),
            rejection_stage: empty_to_none(rejection_stage_raw),
            rejection_reason: empty_to_none(rejection_reason_raw),
            namespace_id,
            scope_id,
        });
    }
    Ok(result)
}

// ── Management Logging ──────────────────────────────────────────

pub(crate) async fn pg_log_management_event(
    pool: &PgPool,
    entry: &ManagementLogEntry,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO management_logs \
         (timestamp, operation, resource_type, resource_id, detail, success, error_message, \
          namespace_id, scope_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(entry.timestamp)
    .bind(&entry.operation)
    .bind(&entry.resource_type)
    .bind(entry.resource_id.as_deref().unwrap_or(""))
    .bind(entry.detail.as_deref().unwrap_or(""))
    .bind(entry.success)
    .bind(entry.error_message.as_deref().unwrap_or(""))
    .bind(&entry.namespace_id)
    .bind(&entry.scope_id)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(format!("Failed to log management event: {}", e)))?;
    Ok(())
}

pub(crate) async fn pg_query_management_log(
    pool: &PgPool,
    filter: &ManagementLogFilter,
) -> Result<Vec<ManagementLogEntry>> {
    let select = "SELECT timestamp, operation, resource_type, resource_id, detail, success, \
                   error_message, namespace_id, scope_id FROM management_logs";

    let mut conditions: Vec<String> = Vec::new();
    let mut args = PgArguments::default();
    let mut idx = 1u32;

    if let Some(ref operation) = filter.operation {
        conditions.push(format!("operation = ${}", idx));
        args.add(operation.clone())
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref resource_type) = filter.resource_type {
        conditions.push(format!("resource_type = ${}", idx));
        args.add(resource_type.clone())
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref resource_id) = filter.resource_id {
        conditions.push(format!("resource_id = ${}", idx));
        args.add(resource_id.clone())
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(success) = filter.success {
        conditions.push(format!("success = ${}", idx));
        args.add(success)
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref since) = filter.since {
        conditions.push(format!("timestamp >= ${}", idx));
        args.add(*since)
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref namespace_id) = filter.namespace_id {
        conditions.push(format!("namespace_id = ${}", idx));
        args.add(namespace_id.clone())
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(ref scope_id) = filter.scope_id {
        conditions.push(format!("scope_id = ${}", idx));
        args.add(scope_id.clone())
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }

    let _ = idx;

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    let limit = filter.limit.unwrap_or(100);
    let query = format!(
        "{}{} ORDER BY id DESC LIMIT {}",
        select, where_clause, limit
    );

    let rows = sqlx::query_with(&query, args)
        .fetch_all(pool)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    pg_rows_to_management_log(&rows)
}

fn pg_rows_to_management_log(rows: &[sqlx::postgres::PgRow]) -> Result<Vec<ManagementLogEntry>> {
    let mut result = Vec::new();
    for row in rows {
        let timestamp: DateTime<Utc> = row.get("timestamp");
        let operation: String = row.get("operation");
        let resource_type: String = row.get("resource_type");
        let resource_id_raw: String = row.get("resource_id");
        let detail_raw: String = row.get("detail");
        let success: bool = row.get("success");
        let error_message_raw: String = row.get("error_message");
        let namespace_id: String = row.get("namespace_id");
        let scope_id: String = row.get("scope_id");

        result.push(ManagementLogEntry {
            timestamp,
            operation,
            resource_type,
            resource_id: empty_to_none(resource_id_raw),
            detail: empty_to_none(detail_raw),
            success,
            error_message: empty_to_none(error_message_raw),
            namespace_id,
            scope_id,
        });
    }
    Ok(result)
}

// ── Request Details ─────────────────────────────────────────────

pub(crate) async fn pg_save_request_details(
    pool: &PgPool,
    details: &RequestDetails,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO request_details \
         (request_id, req_headers, req_body, transformed_url, transformed_headers, \
          transformed_body, response_status, response_headers, response_body, body_truncated) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (request_id) DO UPDATE SET \
         req_headers = EXCLUDED.req_headers, \
         req_body = EXCLUDED.req_body, \
         transformed_url = EXCLUDED.transformed_url, \
         transformed_headers = EXCLUDED.transformed_headers, \
         transformed_body = EXCLUDED.transformed_body, \
         response_status = EXCLUDED.response_status, \
         response_headers = EXCLUDED.response_headers, \
         response_body = EXCLUDED.response_body, \
         body_truncated = EXCLUDED.body_truncated",
    )
    .bind(&details.request_id)
    .bind(details.req_headers.as_deref().unwrap_or(""))
    .bind(details.req_body.as_deref().unwrap_or(&[]))
    .bind(details.transformed_url.as_deref().unwrap_or(""))
    .bind(details.transformed_headers.as_deref().unwrap_or(""))
    .bind(details.transformed_body.as_deref().unwrap_or(&[]))
    .bind(details.response_status.map(|s| s as i32).unwrap_or(0))
    .bind(details.response_headers.as_deref().unwrap_or(""))
    .bind(details.response_body.as_deref().unwrap_or(&[]))
    .bind(details.body_truncated)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(format!("Failed to save request details: {}", e)))?;
    Ok(())
}

pub(crate) async fn pg_get_request_details(
    pool: &PgPool,
    request_id: &str,
) -> Result<Option<RequestDetails>> {
    let row = sqlx::query(
        "SELECT request_id, req_headers, req_body, transformed_url, transformed_headers, \
         transformed_body, response_status, response_headers, response_body, body_truncated \
         FROM request_details WHERE request_id = $1",
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    match row {
        Some(r) => {
            fn empty_str_to_none(s: String) -> Option<String> {
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            }
            fn empty_blob_to_none(b: Vec<u8>) -> Option<Vec<u8>> {
                if b.is_empty() {
                    None
                } else {
                    Some(b)
                }
            }

            let rid: String = r.get("request_id");
            let req_headers_raw: String = r
                .get::<Option<String>, _>("req_headers")
                .unwrap_or_default();
            let req_body: Vec<u8> = r
                .get::<Option<Vec<u8>>, _>("req_body")
                .unwrap_or_default();
            let transformed_url_raw: String = r
                .get::<Option<String>, _>("transformed_url")
                .unwrap_or_default();
            let transformed_headers_raw: String = r
                .get::<Option<String>, _>("transformed_headers")
                .unwrap_or_default();
            let transformed_body: Vec<u8> = r
                .get::<Option<Vec<u8>>, _>("transformed_body")
                .unwrap_or_default();
            let response_status_raw: i32 = r
                .get::<Option<i32>, _>("response_status")
                .unwrap_or(0);
            let response_headers_raw: String = r
                .get::<Option<String>, _>("response_headers")
                .unwrap_or_default();
            let response_body: Vec<u8> = r
                .get::<Option<Vec<u8>>, _>("response_body")
                .unwrap_or_default();
            let body_truncated: bool = r
                .get::<Option<bool>, _>("body_truncated")
                .unwrap_or(false);

            Ok(Some(RequestDetails {
                request_id: rid,
                req_headers: empty_str_to_none(req_headers_raw),
                req_body: empty_blob_to_none(req_body),
                transformed_url: empty_str_to_none(transformed_url_raw),
                transformed_headers: empty_str_to_none(transformed_headers_raw),
                transformed_body: empty_blob_to_none(transformed_body),
                response_status: if response_status_raw == 0 {
                    None
                } else {
                    Some(response_status_raw as u16)
                },
                response_headers: empty_str_to_none(response_headers_raw),
                response_body: empty_blob_to_none(response_body),
                body_truncated,
            }))
        }
        None => Ok(None),
    }
}

// ── Header Set CRUD ─────────────────────────────────────────────

pub(crate) async fn pg_add_header_set(
    pool: &PgPool,
    match_patterns: &[String],
    weight: i32,
    ns: &str,
    scope: &str,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let patterns_json =
        serde_json::to_string(match_patterns).map_err(|e| GapError::database(e.to_string()))?;
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO header_sets \
         (id, match_patterns, weight, created_at, deleted, namespace_id, scope_id) \
         VALUES ($1, $2, $3, $4, FALSE, $5, $6)",
    )
    .bind(&id)
    .bind(&patterns_json)
    .bind(weight)
    .bind(now)
    .bind(ns)
    .bind(scope)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(id)
}

pub(crate) async fn pg_get_header_set(
    pool: &PgPool,
    id: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<HeaderSet>> {
    let row = sqlx::query(
        "SELECT id, match_patterns, weight, created_at FROM header_sets \
         WHERE id = $1 AND deleted = FALSE AND namespace_id = $2 AND scope_id = $3",
    )
    .bind(id)
    .bind(ns)
    .bind(scope)
    .fetch_optional(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    match row {
        Some(r) => Ok(Some(pg_row_to_header_set(&r, ns, scope)?)),
        None => Ok(None),
    }
}

pub(crate) async fn pg_list_header_sets(
    pool: &PgPool,
    ns: &str,
    scope: &str,
) -> Result<Vec<HeaderSet>> {
    let rows = sqlx::query(
        "SELECT id, match_patterns, weight, created_at FROM header_sets \
         WHERE deleted = FALSE AND namespace_id = $1 AND scope_id = $2 ORDER BY id",
    )
    .bind(ns)
    .bind(scope)
    .fetch_all(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    let mut result = Vec::new();
    for row in rows {
        result.push(pg_row_to_header_set(&row, ns, scope)?);
    }
    Ok(result)
}

pub(crate) async fn pg_update_header_set(
    pool: &PgPool,
    id: &str,
    match_patterns: Option<&[String]>,
    weight: Option<i32>,
    ns: &str,
    scope: &str,
) -> Result<()> {
    let mut sets: Vec<String> = Vec::new();
    let mut args = PgArguments::default();
    let mut idx = 1u32;

    if let Some(patterns) = match_patterns {
        let json =
            serde_json::to_string(patterns).map_err(|e| GapError::database(e.to_string()))?;
        sets.push(format!("match_patterns = ${}", idx));
        args.add(json)
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }
    if let Some(w) = weight {
        sets.push(format!("weight = ${}", idx));
        args.add(w)
            .map_err(|e| GapError::database(e.to_string()))?;
        idx += 1;
    }

    if sets.is_empty() {
        return Ok(());
    }

    let sql = format!(
        "UPDATE header_sets SET {} WHERE id = ${} AND deleted = FALSE \
         AND namespace_id = ${} AND scope_id = ${}",
        sets.join(", "),
        idx,
        idx + 1,
        idx + 2
    );
    args.add(id.to_string())
        .map_err(|e| GapError::database(e.to_string()))?;
    args.add(ns.to_string())
        .map_err(|e| GapError::database(e.to_string()))?;
    args.add(scope.to_string())
        .map_err(|e| GapError::database(e.to_string()))?;

    let result = sqlx::query_with(&sql, args)
        .execute(pool)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(GapError::database(format!(
            "Header set '{}' not found",
            id
        )));
    }
    Ok(())
}

pub(crate) async fn pg_remove_header_set(
    pool: &PgPool,
    id: &str,
    ns: &str,
    scope: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE header_sets SET deleted = TRUE \
         WHERE id = $1 AND deleted = FALSE AND namespace_id = $2 AND scope_id = $3",
    )
    .bind(id)
    .bind(ns)
    .bind(scope)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    sqlx::query("DELETE FROM header_set_headers WHERE header_set_id = $1")
        .bind(id)
        .execute(pool)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    Ok(())
}

pub(crate) async fn pg_set_header_set_header(
    pool: &PgPool,
    header_set_id: &str,
    header_name: &str,
    header_value: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO header_set_headers (header_set_id, header_name, header_value) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (header_set_id, header_name) \
         DO UPDATE SET header_value = EXCLUDED.header_value",
    )
    .bind(header_set_id)
    .bind(header_name)
    .bind(header_value)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

pub(crate) async fn pg_get_header_set_headers(
    pool: &PgPool,
    header_set_id: &str,
) -> Result<HashMap<String, String>> {
    let rows = sqlx::query(
        "SELECT header_name, header_value FROM header_set_headers WHERE header_set_id = $1",
    )
    .bind(header_set_id)
    .fetch_all(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    let mut map = HashMap::new();
    for row in rows {
        let name: String = row.get("header_name");
        let value: String = row.get("header_value");
        map.insert(name, value);
    }
    Ok(map)
}

pub(crate) async fn pg_list_header_set_header_names(
    pool: &PgPool,
    header_set_id: &str,
) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT header_name FROM header_set_headers WHERE header_set_id = $1")
        .bind(header_set_id)
        .fetch_all(pool)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    let mut result = Vec::new();
    for row in rows {
        let name: String = row.get("header_name");
        result.push(name);
    }
    Ok(result)
}

pub(crate) async fn pg_remove_header_set_header(
    pool: &PgPool,
    header_set_id: &str,
    header_name: &str,
) -> Result<()> {
    sqlx::query("DELETE FROM header_set_headers WHERE header_set_id = $1 AND header_name = $2")
        .bind(header_set_id)
        .bind(header_name)
        .execute(pool)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

// ── Namespace Discovery ─────────────────────────────────────────

pub(crate) async fn pg_list_distinct_namespaces(pool: &PgPool) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT DISTINCT namespace_id FROM tokens \
         UNION \
         SELECT DISTINCT namespace_id FROM plugin_versions WHERE deleted = FALSE",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    let mut result = Vec::new();
    for row in rows {
        let ns: String = row.get("namespace_id");
        result.push(ns);
    }
    result.sort();
    result.dedup();
    Ok(result)
}

pub(crate) async fn pg_list_namespace_scopes(
    pool: &PgPool,
    namespace_id: &str,
) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT DISTINCT scope_id FROM tokens WHERE namespace_id = $1 \
         UNION \
         SELECT DISTINCT scope_id FROM plugin_versions \
         WHERE namespace_id = $1 AND deleted = FALSE",
    )
    .bind(namespace_id)
    .fetch_all(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    let mut result = Vec::new();
    for row in rows {
        let scope: String = row.get("scope_id");
        result.push(scope);
    }
    result.sort();
    result.dedup();
    Ok(result)
}

pub(crate) async fn pg_get_scope_resource_counts(
    pool: &PgPool,
    ns: &str,
    scope: &str,
) -> Result<serde_json::Value> {
    let plugin_row = sqlx::query(
        "SELECT COUNT(*) as cnt FROM plugin_versions \
         WHERE namespace_id = $1 AND scope_id = $2 AND deleted = FALSE",
    )
    .bind(ns)
    .bind(scope)
    .fetch_one(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    let plugin_count: i64 = plugin_row.get("cnt");

    let token_row = sqlx::query(
        "SELECT COUNT(*) as cnt FROM tokens \
         WHERE namespace_id = $1 AND scope_id = $2 AND revoked_at IS NULL",
    )
    .bind(ns)
    .bind(scope)
    .fetch_one(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    let token_count: i64 = token_row.get("cnt");

    let header_set_row = sqlx::query(
        "SELECT COUNT(*) as cnt FROM header_sets \
         WHERE namespace_id = $1 AND scope_id = $2",
    )
    .bind(ns)
    .bind(scope)
    .fetch_one(pool)
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    let header_set_count: i64 = header_set_row.get("cnt");

    Ok(serde_json::json!({
        "plugins": plugin_count,
        "tokens": token_count,
        "header_sets": header_set_count,
    }))
}

// ── Nonce Store ─────────────────────────────────────────────────

/// Insert a nonce into the used_nonces table. Returns true if inserted (fresh), false if duplicate (replay).
pub(crate) async fn pg_check_and_insert_nonce(
    pool: &PgPool,
    namespace_id: &str,
    scope_id: &str,
    key_id: &str,
    nonce_hash: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool> {
    let result = sqlx::query(
        "INSERT INTO used_nonces (namespace_id, scope_id, key_id, nonce_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (namespace_id, scope_id, key_id, nonce_hash) DO NOTHING",
    )
    .bind(namespace_id)
    .bind(scope_id)
    .bind(key_id)
    .bind(nonce_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(|e| GapError::database(format!("Failed to check nonce: {}", e)))?;

    Ok(result.rows_affected() == 1)
}

/// Delete expired nonces.
pub(crate) async fn pg_cleanup_nonces(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM used_nonces WHERE expires_at < NOW()")
        .execute(pool)
        .await
        .map_err(|e| GapError::database(format!("Failed to cleanup nonces: {}", e)))?;

    Ok(result.rows_affected())
}

fn pg_row_to_header_set(
    row: &sqlx::postgres::PgRow,
    ns: &str,
    scope: &str,
) -> Result<HeaderSet> {
    let id: String = row.get("id");
    let patterns_json: String = row.get("match_patterns");
    let weight: i32 = row.get("weight");
    let created_at: DateTime<Utc> = row.get("created_at");

    let match_patterns: Vec<String> =
        serde_json::from_str(&patterns_json).map_err(|e| GapError::database(e.to_string()))?;

    Ok(HeaderSet {
        id,
        match_patterns,
        weight,
        created_at,
        namespace_id: ns.to_string(),
        scope_id: scope.to_string(),
    })
}
