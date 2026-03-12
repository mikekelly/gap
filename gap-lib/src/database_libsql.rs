//! LibSQL backend implementations for GapDatabase.
//!
//! Each `ls_*` function is a standalone async function that takes a
//! `&libsql::Connection` as its first parameter, mirroring the `pg_*`
//! pattern in `database_postgres.rs`.

use crate::error::{GapError, Result};
use crate::types::{
    ActivityEntry, CredentialEntry, HeaderSet, ManagementLogEntry, PluginEntry, PluginVersion,
    TokenEntry, TokenMetadata, TokenScope,
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

/// Schema DDL applied on every database open (idempotent via IF NOT EXISTS).
pub(crate) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    token_value TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    has_scopes INTEGER NOT NULL DEFAULT 0,
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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    request_id TEXT,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    agent_id TEXT,
    status INTEGER NOT NULL,
    plugin_id TEXT,
    plugin_sha TEXT,
    source_hash TEXT,
    request_headers TEXT,
    namespace_id TEXT NOT NULL DEFAULT 'default',
    scope_id TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_access_logs_url ON access_logs(url);

CREATE TABLE IF NOT EXISTS plugin_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_id TEXT NOT NULL,
    hosts TEXT NOT NULL DEFAULT '[]',
    credential_schema TEXT NOT NULL DEFAULT '[]',
    commit_sha TEXT,
    source_hash TEXT NOT NULL,
    source_code TEXT NOT NULL,
    installed_at TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    namespace_id TEXT NOT NULL DEFAULT 'default',
    scope_id TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_plugin_versions_plugin ON plugin_versions(plugin_id);
CREATE INDEX IF NOT EXISTS idx_plugin_versions_hash ON plugin_versions(source_hash);

CREATE TABLE IF NOT EXISTS management_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    operation TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    success INTEGER NOT NULL,
    error_message TEXT NOT NULL DEFAULT '',
    namespace_id TEXT NOT NULL DEFAULT 'default',
    scope_id TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_management_logs_timestamp ON management_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_management_logs_operation ON management_logs(operation);

CREATE TABLE IF NOT EXISTS request_details (
    request_id TEXT PRIMARY KEY,
    req_headers TEXT,
    req_body BLOB,
    transformed_url TEXT,
    transformed_headers TEXT,
    transformed_body BLOB,
    response_status INTEGER,
    response_headers TEXT,
    response_body BLOB,
    body_truncated INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS header_sets (
    id TEXT PRIMARY KEY,
    match_patterns TEXT NOT NULL DEFAULT '[]',
    weight INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
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
";

// ── Migrations ─────────────────────────────────────────────────────

pub(crate) async fn run_libsql_migrations(conn: &libsql::Connection) -> Result<()> {
    tracing::debug!("Applying database schema");
    conn.execute_batch(SCHEMA)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Schema creation failed");
            GapError::database(format!("Failed to run migrations: {}", e))
        })?;

    // Migration for existing DBs — ignore error if columns already exist
    let alter_migrations = [
        "ALTER TABLE access_logs ADD COLUMN plugin_id TEXT",
        "ALTER TABLE access_logs ADD COLUMN plugin_sha TEXT",
        "ALTER TABLE access_logs ADD COLUMN source_hash TEXT",
        "ALTER TABLE access_logs ADD COLUMN request_headers TEXT",
        "ALTER TABLE access_logs ADD COLUMN request_id TEXT",
        "ALTER TABLE plugin_versions ADD COLUMN hosts TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE plugin_versions ADD COLUMN credential_schema TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE plugin_versions ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE plugin_versions ADD COLUMN dangerously_permit_http INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE access_logs ADD COLUMN rejection_stage TEXT",
        "ALTER TABLE access_logs ADD COLUMN rejection_reason TEXT",
        "ALTER TABLE plugin_versions ADD COLUMN weight INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE tokens ADD COLUMN revoked_at TEXT",
        "ALTER TABLE tokens ADD COLUMN has_scopes INTEGER NOT NULL DEFAULT 0",
    ];

    for migration in &alter_migrations {
        match conn.execute(migration, ()).await {
            Ok(_) => tracing::debug!("Migration applied: {}", migration),
            Err(_) => tracing::debug!("Migration skipped (already applied): {}", migration),
        }
    }

    // Namespace mode columns — ignore errors if columns already exist
    let ns_tables = [
        "tokens",
        "credentials",
        "plugin_versions",
        "header_sets",
        "access_logs",
        "management_logs",
    ];
    for table in ns_tables {
        let _ = conn
            .execute(
                &format!(
                    "ALTER TABLE {} ADD COLUMN namespace_id TEXT NOT NULL DEFAULT 'default'",
                    table
                ),
                (),
            )
            .await;
        let _ = conn
            .execute(
                &format!(
                    "ALTER TABLE {} ADD COLUMN scope_id TEXT NOT NULL DEFAULT 'default'",
                    table
                ),
                (),
            )
            .await;
    }

    Ok(())
}

// ── Helper: row parsers ────────────────────────────────────────────

/// Query token_scopes for a given token value.
pub(crate) async fn get_token_scopes(
    conn: &libsql::Connection,
    token_value: &str,
) -> Result<Vec<TokenScope>> {
    let mut rows = conn
        .query(
            "SELECT host_pattern, port, path_pattern, methods FROM token_scopes WHERE token_value = ?1",
            libsql::params![token_value],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    let mut scopes = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let host_pattern: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        let port: Option<i64> = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
        let path_pattern: String = row.get(2).map_err(|e| GapError::database(e.to_string()))?;
        let methods_json: Option<String> =
            row.get(3).map_err(|e| GapError::database(e.to_string()))?;

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

/// Parse a `Row` into a `PluginEntry`.
///
/// Columns expected at positions 0-3: plugin_id, hosts, credential_schema, commit_sha.
/// The `dangerously_permit_http` column index varies by query and is passed explicitly.
/// Weight is at `permit_http_col + 1`, installed_at at `permit_http_col + 2`.
pub(crate) fn row_to_plugin_entry(
    row: &libsql::Row,
    permit_http_col: usize,
    ns: &str,
    scope: &str,
) -> Result<PluginEntry> {
    let id: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
    let hosts_json: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
    let schema_json: String = row.get(2).map_err(|e| GapError::database(e.to_string()))?;
    let commit_sha_raw: String = row.get(3).map_err(|e| GapError::database(e.to_string()))?;

    let hosts: Vec<String> =
        serde_json::from_str(&hosts_json).map_err(|e| GapError::database(e.to_string()))?;
    let credential_schema: Vec<String> =
        serde_json::from_str(&schema_json).map_err(|e| GapError::database(e.to_string()))?;
    let commit_sha = if commit_sha_raw.is_empty() {
        None
    } else {
        Some(commit_sha_raw)
    };
    let dangerously_permit_http: i64 = row.get(permit_http_col as i32).unwrap_or(0);

    let weight: i32 = row.get((permit_http_col + 1) as i32).unwrap_or(0);
    let installed_at_raw: String = row
        .get((permit_http_col + 2) as i32)
        .unwrap_or_default();
    let installed_at = if installed_at_raw.is_empty() {
        None
    } else {
        Some(
            DateTime::parse_from_rfc3339(&installed_at_raw)
                .map_err(|e| GapError::database(format!("Invalid installed_at: {}", e)))?
                .with_timezone(&Utc),
        )
    };

    Ok(PluginEntry {
        id,
        source: None,
        hosts,
        credential_schema,
        commit_sha,
        dangerously_permit_http: dangerously_permit_http != 0,
        weight,
        installed_at,
        namespace_id: ns.to_string(),
        scope_id: scope.to_string(),
    })
}

/// Helper: convert activity rows into `Vec<ActivityEntry>`.
///
/// Columns expected: timestamp, request_id, method, url, agent_id, status,
///                   plugin_id, plugin_sha, source_hash, request_headers,
///                   rejection_stage, rejection_reason, namespace_id, scope_id
pub(crate) async fn rows_to_activity(
    rows: &mut libsql::Rows,
) -> Result<Vec<ActivityEntry>> {
    let mut result = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let ts_str: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        let request_id_raw: String =
            row.get(1).map_err(|e| GapError::database(e.to_string()))?;
        let method: String = row.get(2).map_err(|e| GapError::database(e.to_string()))?;
        let url: String = row.get(3).map_err(|e| GapError::database(e.to_string()))?;
        let agent_id_raw: String =
            row.get(4).map_err(|e| GapError::database(e.to_string()))?;
        let status_i64: i64 = row.get(5).map_err(|e| GapError::database(e.to_string()))?;
        let plugin_id_raw: String =
            row.get(6).map_err(|e| GapError::database(e.to_string()))?;
        let plugin_sha_raw: String =
            row.get(7).map_err(|e| GapError::database(e.to_string()))?;
        let source_hash_raw: String =
            row.get(8).map_err(|e| GapError::database(e.to_string()))?;
        let request_headers_raw: String =
            row.get(9).map_err(|e| GapError::database(e.to_string()))?;
        let rejection_stage_raw: String =
            row.get(10).map_err(|e| GapError::database(e.to_string()))?;
        let rejection_reason_raw: String =
            row.get(11).map_err(|e| GapError::database(e.to_string()))?;
        let namespace_id: String =
            row.get(12).map_err(|e| GapError::database(e.to_string()))?;
        let scope_id: String =
            row.get(13).map_err(|e| GapError::database(e.to_string()))?;

        let timestamp = DateTime::parse_from_rfc3339(&ts_str)
            .map_err(|e| GapError::database(format!("Invalid timestamp: {}", e)))?
            .with_timezone(&Utc);

        fn empty_to_none(s: String) -> Option<String> {
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }

        result.push(ActivityEntry {
            timestamp,
            request_id: empty_to_none(request_id_raw),
            method,
            url,
            agent_id: empty_to_none(agent_id_raw),
            status: status_i64 as u16,
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

/// Helper: convert management_logs rows into `Vec<ManagementLogEntry>`.
///
/// Columns expected: timestamp, operation, resource_type, resource_id, detail,
///                   success, error_message, namespace_id, scope_id
pub(crate) async fn rows_to_management_log(
    rows: &mut libsql::Rows,
) -> Result<Vec<ManagementLogEntry>> {
    let mut result = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let ts_str: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        let operation: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
        let resource_type: String = row.get(2).map_err(|e| GapError::database(e.to_string()))?;
        let resource_id_raw: String =
            row.get(3).map_err(|e| GapError::database(e.to_string()))?;
        let detail_raw: String = row.get(4).map_err(|e| GapError::database(e.to_string()))?;
        let success_i64: i64 = row.get(5).map_err(|e| GapError::database(e.to_string()))?;
        let error_message_raw: String =
            row.get(6).map_err(|e| GapError::database(e.to_string()))?;
        let namespace_id: String = row.get(7).map_err(|e| GapError::database(e.to_string()))?;
        let scope_id: String = row.get(8).map_err(|e| GapError::database(e.to_string()))?;

        let timestamp = DateTime::parse_from_rfc3339(&ts_str)
            .map_err(|e| GapError::database(format!("Invalid timestamp: {}", e)))?
            .with_timezone(&Utc);

        fn empty_to_none(s: String) -> Option<String> {
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }

        result.push(ManagementLogEntry {
            timestamp,
            operation,
            resource_type,
            resource_id: empty_to_none(resource_id_raw),
            detail: empty_to_none(detail_raw),
            success: success_i64 != 0,
            error_message: empty_to_none(error_message_raw),
            namespace_id,
            scope_id,
        });
    }
    Ok(result)
}

/// Parse a row from header_sets into a HeaderSet.
/// Columns expected: id, match_patterns, weight, created_at.
pub(crate) fn row_to_header_set(
    row: &libsql::Row,
    ns: &str,
    scope: &str,
) -> Result<HeaderSet> {
    let id: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
    let patterns_json: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
    let weight: i32 = row.get(2).map_err(|e| GapError::database(e.to_string()))?;
    let created_at_str: String = row.get(3).map_err(|e| GapError::database(e.to_string()))?;

    let match_patterns: Vec<String> =
        serde_json::from_str(&patterns_json).map_err(|e| GapError::database(e.to_string()))?;
    let created_at = DateTime::parse_from_rfc3339(&created_at_str)
        .map_err(|e| GapError::database(format!("Invalid created_at: {}", e)))?
        .with_timezone(&Utc);

    Ok(HeaderSet {
        id,
        match_patterns,
        weight,
        created_at,
        namespace_id: ns.to_string(),
        scope_id: scope.to_string(),
    })
}

// ── Token CRUD ─────────────────────────────────────────────────────

pub(crate) async fn ls_add_token(
    conn: &libsql::Connection,
    token_value: &str,
    created_at: DateTime<Utc>,
    scopes: Option<&[TokenScope]>,
    ns: &str,
    scope: &str,
) -> Result<()> {
    let has_scopes: i64 = if scopes.is_some() { 1 } else { 0 };
    conn.execute(
        "INSERT OR REPLACE INTO tokens (token_value, name, created_at, has_scopes, namespace_id, scope_id) VALUES (?1, '', ?2, ?3, ?4, ?5)",
        libsql::params![token_value, created_at.to_rfc3339(), has_scopes, ns, scope],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    if let Some(scope_list) = scopes {
        for s in scope_list {
            let methods_json = s
                .methods
                .as_ref()
                .map(|m| serde_json::to_string(m).unwrap_or_default());
            let port = s.port.map(|p| p as i64);
            conn.execute(
                "INSERT INTO token_scopes (token_value, host_pattern, port, path_pattern, methods) VALUES (?1, ?2, ?3, ?4, ?5)",
                libsql::params![
                    token_value,
                    s.host_pattern.as_str(),
                    port,
                    s.path_pattern.as_str(),
                    methods_json
                ],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        }
    }

    Ok(())
}

pub(crate) async fn ls_get_token(
    conn: &libsql::Connection,
    token_value: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<TokenMetadata>> {
    let mut rows = conn
        .query(
            "SELECT created_at, has_scopes FROM tokens WHERE token_value = ?1 AND revoked_at IS NULL AND namespace_id = ?2 AND scope_id = ?3",
            libsql::params![token_value, ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let created_at_str: String =
            row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| GapError::database(format!("Invalid timestamp: {}", e)))?
            .with_timezone(&Utc);
        let has_scopes: i64 = row.get(1).map_err(|e| GapError::database(e.to_string()))?;

        let scopes = if has_scopes == 1 {
            Some(get_token_scopes(conn, token_value).await?)
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
    } else {
        Ok(None)
    }
}

pub(crate) async fn ls_list_tokens(
    conn: &libsql::Connection,
    include_revoked: bool,
    ns: &str,
    scope: &str,
) -> Result<Vec<TokenEntry>> {
    let query = if include_revoked {
        "SELECT token_value, created_at, revoked_at, has_scopes FROM tokens WHERE namespace_id = ?1 AND scope_id = ?2"
    } else {
        "SELECT token_value, created_at, revoked_at, has_scopes FROM tokens WHERE revoked_at IS NULL AND namespace_id = ?1 AND scope_id = ?2"
    };
    let mut rows = conn
        .query(query, libsql::params![ns, scope])
        .await
        .map_err(|e| GapError::database(e.to_string()))?;
    let mut result = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let token_value: String =
            row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        let created_at_str: String =
            row.get(1).map_err(|e| GapError::database(e.to_string()))?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| GapError::database(format!("Invalid timestamp: {}", e)))?
            .with_timezone(&Utc);
        let revoked_at_str: Option<String> =
            row.get(2).map_err(|e| GapError::database(e.to_string()))?;
        let revoked_at = revoked_at_str
            .map(|s| DateTime::parse_from_rfc3339(&s))
            .transpose()
            .map_err(|e| {
                GapError::database(format!("Invalid revoked_at timestamp: {}", e))
            })?
            .map(|dt| dt.with_timezone(&Utc));
        let has_scopes: i64 = row.get(3).map_err(|e| GapError::database(e.to_string()))?;

        let scopes = if has_scopes == 1 {
            Some(get_token_scopes(conn, &token_value).await?)
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

pub(crate) async fn ls_revoke_token(
    conn: &libsql::Connection,
    token_value: &str,
    ns: &str,
    scope: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE tokens SET revoked_at = ?2 WHERE token_value = ?1 AND revoked_at IS NULL AND namespace_id = ?3 AND scope_id = ?4",
        libsql::params![token_value, Utc::now().to_rfc3339(), ns, scope],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

pub(crate) async fn ls_get_token_by_prefix(
    conn: &libsql::Connection,
    prefix: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<String>> {
    let pattern = format!("{}%", prefix);
    let mut rows = conn
        .query(
            "SELECT token_value FROM tokens WHERE token_value LIKE ?1 AND revoked_at IS NULL AND namespace_id = ?2 AND scope_id = ?3",
            libsql::params![pattern, ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let token_value: String =
            row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        Ok(Some(token_value))
    } else {
        Ok(None)
    }
}

// ── Plugin CRUD ────────────────────────────────────────────────────

pub(crate) async fn ls_add_plugin(
    conn: &libsql::Connection,
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

    // Compute source hash
    let source_hash = format!("{:x}", Sha256::digest(source_code.as_bytes()));
    let now = Utc::now().to_rfc3339();

    let permit_http: i64 = if plugin.dangerously_permit_http {
        1
    } else {
        0
    };

    conn.execute(
        "INSERT INTO plugin_versions (plugin_id, hosts, credential_schema, commit_sha, source_hash, source_code, installed_at, deleted, dangerously_permit_http, weight, namespace_id, scope_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9, ?10, ?11)",
        libsql::params![
            id.as_str(),
            hosts_json,
            schema_json,
            plugin.commit_sha.as_deref().unwrap_or(""),
            source_hash,
            source_code,
            now,
            permit_http,
            plugin.weight,
            ns,
            scope
        ],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    Ok(id)
}

pub(crate) async fn ls_get_plugin(
    conn: &libsql::Connection,
    id: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<PluginEntry>> {
    let mut rows = conn
        .query(
            "SELECT plugin_id, hosts, credential_schema, commit_sha, deleted, dangerously_permit_http, weight, installed_at FROM plugin_versions WHERE plugin_id = ?1 AND namespace_id = ?2 AND scope_id = ?3 ORDER BY id DESC LIMIT 1",
            libsql::params![id, ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let deleted: i64 = row.get(4).map_err(|e| GapError::database(e.to_string()))?;
        if deleted != 0 {
            return Ok(None);
        }
        Ok(Some(row_to_plugin_entry(&row, 5, ns, scope)?))
    } else {
        Ok(None)
    }
}

pub(crate) async fn ls_get_plugin_source(
    conn: &libsql::Connection,
    id: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<String>> {
    let mut rows = conn
        .query(
            "SELECT source_code, deleted FROM plugin_versions WHERE plugin_id = ?1 AND namespace_id = ?2 AND scope_id = ?3 ORDER BY id DESC LIMIT 1",
            libsql::params![id, ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let deleted: i64 = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
        if deleted != 0 {
            return Ok(None);
        }
        let source: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        Ok(Some(source))
    } else {
        Ok(None)
    }
}

pub(crate) async fn ls_list_plugins(
    conn: &libsql::Connection,
    ns: &str,
    scope: &str,
) -> Result<Vec<PluginEntry>> {
    let mut rows = conn
        .query(
            "SELECT pv.plugin_id, pv.hosts, pv.credential_schema, pv.commit_sha, pv.dangerously_permit_http, pv.weight, pv.installed_at \
             FROM plugin_versions pv \
             INNER JOIN ( \
                 SELECT plugin_id, MAX(id) as max_id \
                 FROM plugin_versions \
                 WHERE namespace_id = ?1 AND scope_id = ?2 \
                 GROUP BY plugin_id \
             ) latest ON pv.id = latest.max_id \
             WHERE pv.deleted = 0 AND pv.namespace_id = ?1 AND pv.scope_id = ?2",
            libsql::params![ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;
    let mut result = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        result.push(row_to_plugin_entry(&row, 4, ns, scope)?);
    }
    Ok(result)
}

pub(crate) async fn ls_remove_plugin(
    conn: &libsql::Connection,
    id: &str,
    ns: &str,
    scope: &str,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO plugin_versions (plugin_id, hosts, credential_schema, commit_sha, source_hash, source_code, installed_at, deleted, namespace_id, scope_id) VALUES (?1, '[]', '[]', '', '', '', ?2, 1, ?3, ?4)",
        libsql::params![id, now, ns, scope],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

pub(crate) async fn ls_get_plugin_version_by_hash(
    conn: &libsql::Connection,
    source_hash: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<PluginVersion>> {
    let mut rows = conn
        .query(
            "SELECT plugin_id, commit_sha, source_hash, source_code, installed_at FROM plugin_versions WHERE source_hash = ?1 AND namespace_id = ?2 AND scope_id = ?3 LIMIT 1",
            libsql::params![source_hash, ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let plugin_id: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        let commit_sha_raw: String =
            row.get(1).map_err(|e| GapError::database(e.to_string()))?;
        let source_hash: String =
            row.get(2).map_err(|e| GapError::database(e.to_string()))?;
        let source_code: String =
            row.get(3).map_err(|e| GapError::database(e.to_string()))?;
        let installed_at_str: String =
            row.get(4).map_err(|e| GapError::database(e.to_string()))?;

        let commit_sha = if commit_sha_raw.is_empty() {
            None
        } else {
            Some(commit_sha_raw)
        };
        let installed_at = DateTime::parse_from_rfc3339(&installed_at_str)
            .map_err(|e| GapError::database(format!("Invalid timestamp: {}", e)))?
            .with_timezone(&Utc);

        Ok(Some(PluginVersion {
            plugin_id,
            commit_sha,
            source_hash,
            source_code,
            installed_at,
        }))
    } else {
        Ok(None)
    }
}

// ── Credential CRUD ────────────────────────────────────────────────

pub(crate) async fn ls_set_credential(
    conn: &libsql::Connection,
    plugin_id: &str,
    field: &str,
    value: &str,
    ns: &str,
    scope: &str,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO credentials (namespace_id, scope_id, plugin_id, field, value) VALUES (?1, ?2, ?3, ?4, ?5)",
        libsql::params![ns, scope, plugin_id, field, value],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

pub(crate) async fn ls_get_credential(
    conn: &libsql::Connection,
    plugin_id: &str,
    field: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<String>> {
    let mut rows = conn
        .query(
            "SELECT value FROM credentials WHERE plugin_id = ?1 AND field = ?2 AND namespace_id = ?3 AND scope_id = ?4",
            libsql::params![plugin_id, field, ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let value: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        Ok(Some(value))
    } else {
        Ok(None)
    }
}

pub(crate) async fn ls_get_plugin_credentials(
    conn: &libsql::Connection,
    plugin_id: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<HashMap<String, String>>> {
    let mut rows = conn
        .query(
            "SELECT field, value FROM credentials WHERE plugin_id = ?1 AND namespace_id = ?2 AND scope_id = ?3",
            libsql::params![plugin_id, ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    let mut map = HashMap::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let field: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        let value: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
        map.insert(field, value);
    }

    if map.is_empty() {
        Ok(None)
    } else {
        Ok(Some(map))
    }
}

pub(crate) async fn ls_list_credentials(
    conn: &libsql::Connection,
    ns: &str,
    scope: &str,
) -> Result<Vec<CredentialEntry>> {
    let mut rows = conn
        .query(
            "SELECT plugin_id, field FROM credentials WHERE namespace_id = ?1 AND scope_id = ?2",
            libsql::params![ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;
    let mut result = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let plugin_id: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        let field: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
        result.push(CredentialEntry {
            plugin_id,
            field,
            namespace_id: ns.to_string(),
            scope_id: scope.to_string(),
        });
    }
    Ok(result)
}

pub(crate) async fn ls_remove_credential(
    conn: &libsql::Connection,
    plugin_id: &str,
    field: &str,
    ns: &str,
    scope: &str,
) -> Result<()> {
    conn.execute(
        "DELETE FROM credentials WHERE plugin_id = ?1 AND field = ?2 AND namespace_id = ?3 AND scope_id = ?4",
        libsql::params![plugin_id, field, ns, scope],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

// ── Config KV ──────────────────────────────────────────────────────

pub(crate) async fn ls_set_config(
    conn: &libsql::Connection,
    key: &str,
    value: &[u8],
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
        libsql::params![key, libsql::Value::Blob(value.to_vec())],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

pub(crate) async fn ls_get_config(
    conn: &libsql::Connection,
    key: &str,
) -> Result<Option<Vec<u8>>> {
    let mut rows = conn
        .query(
            "SELECT value FROM config WHERE key = ?1",
            libsql::params![key],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let val = row
            .get_value(0)
            .map_err(|e| GapError::database(e.to_string()))?;
        match val {
            libsql::Value::Blob(b) => Ok(Some(b)),
            _ => Err(GapError::database("Expected blob value for config")),
        }
    } else {
        Ok(None)
    }
}

pub(crate) async fn ls_delete_config(
    conn: &libsql::Connection,
    key: &str,
) -> Result<()> {
    conn.execute(
        "DELETE FROM config WHERE key = ?1",
        libsql::params![key],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

// ── Activity Logging ───────────────────────────────────────────────

pub(crate) async fn ls_log_activity(
    conn: &libsql::Connection,
    entry: &ActivityEntry,
) -> Result<()> {
    conn.execute(
        "INSERT INTO access_logs (timestamp, request_id, method, url, agent_id, status, plugin_id, plugin_sha, source_hash, request_headers, rejection_stage, rejection_reason, namespace_id, scope_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        libsql::params![
            entry.timestamp.to_rfc3339(),
            entry.request_id.as_deref().unwrap_or(""),
            entry.method.as_str(),
            entry.url.as_str(),
            entry.agent_id.as_deref().unwrap_or(""),
            entry.status as i64,
            entry.plugin_id.as_deref().unwrap_or(""),
            entry.plugin_sha.as_deref().unwrap_or(""),
            entry.source_hash.as_deref().unwrap_or(""),
            entry.request_headers.as_deref().unwrap_or(""),
            entry.rejection_stage.as_deref().unwrap_or(""),
            entry.rejection_reason.as_deref().unwrap_or(""),
            entry.namespace_id.as_str(),
            entry.scope_id.as_str()
        ],
    )
    .await
    .map_err(|e| GapError::database(format!("Failed to log activity: {}", e)))?;
    Ok(())
}

pub(crate) async fn ls_query_activity(
    conn: &libsql::Connection,
    filter: &crate::types::ActivityFilter,
) -> Result<Vec<ActivityEntry>> {
    let select = "SELECT timestamp, request_id, method, url, agent_id, status, plugin_id, plugin_sha, source_hash, request_headers, rejection_stage, rejection_reason, namespace_id, scope_id FROM access_logs";

    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<libsql::Value> = Vec::new();
    let mut idx = 1u32;

    if let Some(ref domain) = filter.domain {
        conditions.push(format!("url LIKE ?{}", idx));
        params.push(libsql::Value::Text(format!("%://{}%", domain)));
        idx += 1;
    }
    if let Some(ref path) = filter.path {
        conditions.push(format!("url LIKE ?{}", idx));
        params.push(libsql::Value::Text(format!("%{}%", path)));
        idx += 1;
    }
    if let Some(ref plugin_id) = filter.plugin_id {
        conditions.push(format!("plugin_id = ?{}", idx));
        params.push(libsql::Value::Text(plugin_id.clone()));
        idx += 1;
    }
    if let Some(ref agent) = filter.agent {
        conditions.push(format!("agent_id = ?{}", idx));
        params.push(libsql::Value::Text(agent.clone()));
        idx += 1;
    }
    if let Some(ref method) = filter.method {
        conditions.push(format!("method = ?{}", idx));
        params.push(libsql::Value::Text(method.clone()));
        idx += 1;
    }
    if let Some(ref since) = filter.since {
        conditions.push(format!("timestamp >= ?{}", idx));
        params.push(libsql::Value::Text(since.to_rfc3339()));
        idx += 1;
    }
    if let Some(ref request_id) = filter.request_id {
        conditions.push(format!("request_id = ?{}", idx));
        params.push(libsql::Value::Text(request_id.clone()));
        idx += 1;
    }
    if let Some(ref namespace_id) = filter.namespace_id {
        conditions.push(format!("namespace_id = ?{}", idx));
        params.push(libsql::Value::Text(namespace_id.clone()));
        idx += 1;
    }
    if let Some(ref scope_id) = filter.scope_id {
        conditions.push(format!("scope_id = ?{}", idx));
        params.push(libsql::Value::Text(scope_id.clone()));
    }

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

    let mut rows = conn
        .query(&query, params)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;
    rows_to_activity(&mut rows).await
}

// ── Management Log ─────────────────────────────────────────────────

pub(crate) async fn ls_log_management_event(
    conn: &libsql::Connection,
    entry: &ManagementLogEntry,
) -> Result<()> {
    conn.execute(
        "INSERT INTO management_logs (timestamp, operation, resource_type, resource_id, detail, success, error_message, namespace_id, scope_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        libsql::params![
            entry.timestamp.to_rfc3339(),
            entry.operation.as_str(),
            entry.resource_type.as_str(),
            entry.resource_id.as_deref().unwrap_or(""),
            entry.detail.as_deref().unwrap_or(""),
            entry.success as i64,
            entry.error_message.as_deref().unwrap_or(""),
            entry.namespace_id.as_str(),
            entry.scope_id.as_str()
        ],
    )
    .await
    .map_err(|e| GapError::database(format!("Failed to log management event: {}", e)))?;
    Ok(())
}

pub(crate) async fn ls_query_management_log(
    conn: &libsql::Connection,
    filter: &crate::types::ManagementLogFilter,
) -> Result<Vec<ManagementLogEntry>> {
    let select = "SELECT timestamp, operation, resource_type, resource_id, detail, success, error_message, namespace_id, scope_id FROM management_logs";

    let mut conditions: Vec<String> = Vec::new();
    let mut params: Vec<libsql::Value> = Vec::new();
    let mut idx = 1u32;

    if let Some(ref operation) = filter.operation {
        conditions.push(format!("operation = ?{}", idx));
        params.push(libsql::Value::Text(operation.clone()));
        idx += 1;
    }
    if let Some(ref resource_type) = filter.resource_type {
        conditions.push(format!("resource_type = ?{}", idx));
        params.push(libsql::Value::Text(resource_type.clone()));
        idx += 1;
    }
    if let Some(ref resource_id) = filter.resource_id {
        conditions.push(format!("resource_id = ?{}", idx));
        params.push(libsql::Value::Text(resource_id.clone()));
        idx += 1;
    }
    if let Some(success) = filter.success {
        conditions.push(format!("success = ?{}", idx));
        params.push(libsql::Value::Integer(success as i64));
        idx += 1;
    }
    if let Some(ref since) = filter.since {
        conditions.push(format!("timestamp >= ?{}", idx));
        params.push(libsql::Value::Text(since.to_rfc3339()));
        idx += 1;
    }
    if let Some(ref namespace_id) = filter.namespace_id {
        conditions.push(format!("namespace_id = ?{}", idx));
        params.push(libsql::Value::Text(namespace_id.clone()));
        idx += 1;
    }
    if let Some(ref scope_id) = filter.scope_id {
        conditions.push(format!("scope_id = ?{}", idx));
        params.push(libsql::Value::Text(scope_id.clone()));
        idx += 1;
    }

    let _ = idx; // suppress unused warning

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

    let mut rows = conn
        .query(&query, params)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;
    rows_to_management_log(&mut rows).await
}

// ── Request Details ────────────────────────────────────────────────

pub(crate) async fn ls_save_request_details(
    conn: &libsql::Connection,
    details: &crate::types::RequestDetails,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO request_details (request_id, req_headers, req_body, transformed_url, transformed_headers, transformed_body, response_status, response_headers, response_body, body_truncated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        libsql::params![
            details.request_id.as_str(),
            details.req_headers.as_deref().unwrap_or(""),
            libsql::Value::Blob(details.req_body.clone().unwrap_or_default()),
            details.transformed_url.as_deref().unwrap_or(""),
            details.transformed_headers.as_deref().unwrap_or(""),
            libsql::Value::Blob(details.transformed_body.clone().unwrap_or_default()),
            details.response_status.map(|s| s as i64).unwrap_or(0),
            details.response_headers.as_deref().unwrap_or(""),
            libsql::Value::Blob(details.response_body.clone().unwrap_or_default()),
            if details.body_truncated { 1i64 } else { 0i64 }
        ],
    )
    .await
    .map_err(|e| GapError::database(format!("Failed to save request details: {}", e)))?;
    Ok(())
}

pub(crate) async fn ls_get_request_details(
    conn: &libsql::Connection,
    request_id: &str,
) -> Result<Option<crate::types::RequestDetails>> {
    let mut rows = conn
        .query(
            "SELECT request_id, req_headers, req_body, transformed_url, transformed_headers, transformed_body, response_status, response_headers, response_body, body_truncated FROM request_details WHERE request_id = ?1",
            libsql::params![request_id],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        fn empty_to_none(s: String) -> Option<String> {
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
        fn blob_from_value(val: libsql::Value) -> Vec<u8> {
            match val {
                libsql::Value::Blob(b) => b,
                _ => Vec::new(),
            }
        }

        let request_id: String =
            row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        let req_headers_raw: String =
            row.get(1).map_err(|e| GapError::database(e.to_string()))?;
        let req_body_val = row
            .get_value(2)
            .map_err(|e| GapError::database(e.to_string()))?;
        let transformed_url_raw: String =
            row.get(3).map_err(|e| GapError::database(e.to_string()))?;
        let transformed_headers_raw: String =
            row.get(4).map_err(|e| GapError::database(e.to_string()))?;
        let transformed_body_val = row
            .get_value(5)
            .map_err(|e| GapError::database(e.to_string()))?;
        let response_status_raw: i64 =
            row.get(6).map_err(|e| GapError::database(e.to_string()))?;
        let response_headers_raw: String =
            row.get(7).map_err(|e| GapError::database(e.to_string()))?;
        let response_body_val = row
            .get_value(8)
            .map_err(|e| GapError::database(e.to_string()))?;
        let body_truncated_raw: i64 =
            row.get(9).map_err(|e| GapError::database(e.to_string()))?;

        Ok(Some(crate::types::RequestDetails {
            request_id,
            req_headers: empty_to_none(req_headers_raw),
            req_body: empty_blob_to_none(blob_from_value(req_body_val)),
            transformed_url: empty_to_none(transformed_url_raw),
            transformed_headers: empty_to_none(transformed_headers_raw),
            transformed_body: empty_blob_to_none(blob_from_value(transformed_body_val)),
            response_status: if response_status_raw == 0 {
                None
            } else {
                Some(response_status_raw as u16)
            },
            response_headers: empty_to_none(response_headers_raw),
            response_body: empty_blob_to_none(blob_from_value(response_body_val)),
            body_truncated: body_truncated_raw != 0,
        }))
    } else {
        Ok(None)
    }
}

// ── Plugin Weight ──────────────────────────────────────────────────

pub(crate) async fn ls_update_plugin_weight(
    conn: &libsql::Connection,
    id: &str,
    weight: i32,
    ns: &str,
    scope: &str,
) -> Result<()> {
    let rows_affected = conn
        .execute(
            "UPDATE plugin_versions SET weight = ?1 WHERE id = (SELECT MAX(id) FROM plugin_versions WHERE plugin_id = ?2 AND deleted = 0 AND namespace_id = ?3 AND scope_id = ?4)",
            libsql::params![weight, id, ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if rows_affected == 0 {
        return Err(GapError::database(format!("Plugin '{}' not found", id)));
    }
    Ok(())
}

// ── Header Set CRUD ────────────────────────────────────────────────

pub(crate) async fn ls_add_header_set(
    conn: &libsql::Connection,
    match_patterns: &[String],
    weight: i32,
    ns: &str,
    scope: &str,
) -> Result<String> {
    let id = Uuid::new_v4().to_string();
    let patterns_json =
        serde_json::to_string(match_patterns).map_err(|e| GapError::database(e.to_string()))?;
    let now = Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO header_sets (id, match_patterns, weight, created_at, deleted, namespace_id, scope_id) VALUES (?1, ?2, ?3, ?4, 0, ?5, ?6)",
        libsql::params![id.as_str(), patterns_json, weight, now, ns, scope],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(id)
}

pub(crate) async fn ls_get_header_set(
    conn: &libsql::Connection,
    id: &str,
    ns: &str,
    scope: &str,
) -> Result<Option<HeaderSet>> {
    let mut rows = conn
        .query(
            "SELECT id, match_patterns, weight, created_at FROM header_sets WHERE id = ?1 AND deleted = 0 AND namespace_id = ?2 AND scope_id = ?3",
            libsql::params![id, ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        Ok(Some(row_to_header_set(&row, ns, scope)?))
    } else {
        Ok(None)
    }
}

pub(crate) async fn ls_list_header_sets(
    conn: &libsql::Connection,
    ns: &str,
    scope: &str,
) -> Result<Vec<HeaderSet>> {
    let mut rows = conn
        .query(
            "SELECT id, match_patterns, weight, created_at FROM header_sets WHERE deleted = 0 AND namespace_id = ?1 AND scope_id = ?2 ORDER BY id",
            libsql::params![ns, scope],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    let mut result = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        result.push(row_to_header_set(&row, ns, scope)?);
    }
    Ok(result)
}

pub(crate) async fn ls_update_header_set(
    conn: &libsql::Connection,
    id: &str,
    match_patterns: Option<&[String]>,
    weight: Option<i32>,
    ns: &str,
    scope: &str,
) -> Result<()> {
    let mut sets: Vec<String> = Vec::new();
    let mut params: Vec<libsql::Value> = Vec::new();
    let mut idx = 1u32;

    if let Some(patterns) = match_patterns {
        let json =
            serde_json::to_string(patterns).map_err(|e| GapError::database(e.to_string()))?;
        sets.push(format!("match_patterns = ?{}", idx));
        params.push(libsql::Value::Text(json));
        idx += 1;
    }
    if let Some(w) = weight {
        sets.push(format!("weight = ?{}", idx));
        params.push(libsql::Value::Integer(w as i64));
        idx += 1;
    }

    if sets.is_empty() {
        return Ok(()); // nothing to update
    }

    let sql = format!(
        "UPDATE header_sets SET {} WHERE id = ?{} AND deleted = 0 AND namespace_id = ?{} AND scope_id = ?{}",
        sets.join(", "),
        idx,
        idx + 1,
        idx + 2
    );
    params.push(libsql::Value::Text(id.to_string()));
    params.push(libsql::Value::Text(ns.to_string()));
    params.push(libsql::Value::Text(scope.to_string()));

    let rows_affected = conn
        .execute(&sql, params)
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    if rows_affected == 0 {
        return Err(GapError::database(format!(
            "Header set '{}' not found",
            id
        )));
    }
    Ok(())
}

pub(crate) async fn ls_remove_header_set(
    conn: &libsql::Connection,
    id: &str,
    ns: &str,
    scope: &str,
) -> Result<()> {
    conn.execute(
        "UPDATE header_sets SET deleted = 1 WHERE id = ?1 AND deleted = 0 AND namespace_id = ?2 AND scope_id = ?3",
        libsql::params![id, ns, scope],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    conn.execute(
        "DELETE FROM header_set_headers WHERE header_set_id = ?1",
        libsql::params![id],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;

    Ok(())
}

pub(crate) async fn ls_set_header_set_header(
    conn: &libsql::Connection,
    header_set_id: &str,
    header_name: &str,
    header_value: &str,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO header_set_headers (header_set_id, header_name, header_value) VALUES (?1, ?2, ?3)",
        libsql::params![header_set_id, header_name, header_value],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

pub(crate) async fn ls_get_header_set_headers(
    conn: &libsql::Connection,
    header_set_id: &str,
) -> Result<HashMap<String, String>> {
    let mut rows = conn
        .query(
            "SELECT header_name, header_value FROM header_set_headers WHERE header_set_id = ?1",
            libsql::params![header_set_id],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    let mut map = HashMap::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let name: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        let value: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
        map.insert(name, value);
    }
    Ok(map)
}

pub(crate) async fn ls_list_header_set_header_names(
    conn: &libsql::Connection,
    header_set_id: &str,
) -> Result<Vec<String>> {
    let mut rows = conn
        .query(
            "SELECT header_name FROM header_set_headers WHERE header_set_id = ?1",
            libsql::params![header_set_id],
        )
        .await
        .map_err(|e| GapError::database(e.to_string()))?;

    let mut result = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let name: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        result.push(name);
    }
    Ok(result)
}

pub(crate) async fn ls_remove_header_set_header(
    conn: &libsql::Connection,
    header_set_id: &str,
    header_name: &str,
) -> Result<()> {
    conn.execute(
        "DELETE FROM header_set_headers WHERE header_set_id = ?1 AND header_name = ?2",
        libsql::params![header_set_id, header_name],
    )
    .await
    .map_err(|e| GapError::database(e.to_string()))?;
    Ok(())
}

// ── Namespace discovery ────────────────────────────────────────────

pub(crate) async fn ls_list_distinct_namespaces(
    conn: &libsql::Connection,
) -> Result<Vec<String>> {
    let sql = "SELECT DISTINCT namespace_id FROM tokens \
               UNION \
               SELECT DISTINCT namespace_id FROM plugin_versions WHERE deleted = 0";
    let mut rows = conn
        .query(sql, ())
        .await
        .map_err(|e| GapError::database(e.to_string()))?;
    let mut result = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let ns: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        result.push(ns);
    }
    result.sort();
    result.dedup();
    Ok(result)
}

pub(crate) async fn ls_list_namespace_scopes(
    conn: &libsql::Connection,
    namespace_id: &str,
) -> Result<Vec<String>> {
    let sql = "SELECT DISTINCT scope_id FROM tokens WHERE namespace_id = ?1 \
               UNION \
               SELECT DISTINCT scope_id FROM plugin_versions WHERE namespace_id = ?1 AND deleted = 0";
    let mut rows = conn
        .query(sql, libsql::params![namespace_id])
        .await
        .map_err(|e| GapError::database(e.to_string()))?;
    let mut result = Vec::new();
    while let Some(row) = rows
        .next()
        .await
        .map_err(|e| GapError::database(e.to_string()))?
    {
        let scope: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        result.push(scope);
    }
    result.sort();
    result.dedup();
    Ok(result)
}

pub(crate) async fn ls_get_scope_resource_counts(
    conn: &libsql::Connection,
    ns: &str,
    scope: &str,
) -> Result<serde_json::Value> {
    let plugin_count: i64 = {
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM plugin_versions WHERE namespace_id = ?1 AND scope_id = ?2 AND deleted = 0",
                libsql::params![ns, scope],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .await
            .map_err(|e| GapError::database(e.to_string()))?
        {
            row.get(0).map_err(|e| GapError::database(e.to_string()))?
        } else {
            0
        }
    };
    let token_count: i64 = {
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM tokens WHERE namespace_id = ?1 AND scope_id = ?2 AND revoked_at IS NULL",
                libsql::params![ns, scope],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .await
            .map_err(|e| GapError::database(e.to_string()))?
        {
            row.get(0).map_err(|e| GapError::database(e.to_string()))?
        } else {
            0
        }
    };
    let header_set_count: i64 = {
        let mut rows = conn
            .query(
                "SELECT COUNT(*) FROM header_sets WHERE namespace_id = ?1 AND scope_id = ?2",
                libsql::params![ns, scope],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        if let Some(row) = rows
            .next()
            .await
            .map_err(|e| GapError::database(e.to_string()))?
        {
            row.get(0).map_err(|e| GapError::database(e.to_string()))?
        } else {
            0
        }
    };
    Ok(serde_json::json!({
        "plugins": plugin_count,
        "tokens": token_count,
        "header_sets": header_set_count,
    }))
}
