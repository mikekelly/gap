//! Embedded database for GAP persistent storage.
//!
//! This module provides `GapDatabase`, which dispatches to either a libSQL
//! backend (`database_libsql`) or a Postgres backend (`database_postgres`).

use crate::error::{GapError, Result};
use crate::types::{
    ActivityEntry, CredentialEntry, HeaderSet, ManagementLogEntry, PluginEntry, PluginVersion,
    TokenEntry, TokenMetadata, TokenScope,
};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

enum DbBackend {
    LibSql {
        #[allow(dead_code)]
        db: libsql::Database,
        conn: libsql::Connection,
    },
    #[allow(dead_code)]
    Postgres {
        pool: sqlx::PgPool,
    },
}

/// Embedded database for GAP persistent storage.
pub struct GapDatabase {
    inner: DbBackend,
}

impl GapDatabase {
    fn conn(&self) -> &libsql::Connection {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => conn,
            DbBackend::Postgres { .. } => panic!("conn() called on Postgres backend"),
        }
    }

    #[allow(dead_code)]
    fn pool(&self) -> &sqlx::PgPool {
        match &self.inner {
            DbBackend::Postgres { pool } => pool,
            DbBackend::LibSql { .. } => panic!("pool() called on LibSql backend"),
        }
    }

    // ── Constructors ────────────────────────────────────────────────

    /// Open an encrypted database at the given path.
    pub async fn open(path: &str, encryption_key: &[u8]) -> Result<Self> {
        let db = match libsql::Builder::new_local(path)
            .encryption_config(libsql::EncryptionConfig::new(
                libsql::Cipher::Aes256Cbc,
                bytes::Bytes::copy_from_slice(encryption_key),
            ))
            .build()
            .await
        {
            Ok(db) => db,
            Err(e) => {
                // Log file header to help diagnose encryption mismatches
                if let Ok(bytes) = std::fs::read(path) {
                    let header = &bytes[..16.min(bytes.len())];
                    let is_sqlite = header.starts_with(b"SQLite format 3\0");
                    tracing::error!(
                        path = %std::path::Path::new(path).display(),
                        header_hex = %hex::encode(header),
                        appears_unencrypted = is_sqlite,
                        error = %e,
                        "Database open failed — check encryption key"
                    );
                } else {
                    tracing::error!(
                        path = %std::path::Path::new(path).display(),
                        error = %e,
                        "Database open failed"
                    );
                }
                return Err(GapError::database(format!(
                    "Failed to open encrypted database: {}",
                    e
                )));
            }
        };
        let conn = db
            .connect()
            .map_err(|e| GapError::database(format!("Failed to connect: {}", e)))?;
        let instance = Self {
            inner: DbBackend::LibSql { db, conn },
        };
        crate::database_libsql::run_libsql_migrations(instance.conn()).await?;
        // Use execute_batch for PRAGMAs because encrypted libSQL returns rows from
        // journal_mode, which causes execute() to fail with "Execute returned rows".
        instance
            .conn()
            .execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
            .await
            .map_err(|e| GapError::database(format!("Failed to set PRAGMAs: {}", e)))?;
        Ok(instance)
    }

    /// Open an unencrypted database at the given path.
    pub async fn open_unencrypted(path: &str) -> Result<Self> {
        let db = match libsql::Builder::new_local(path).build().await {
            Ok(db) => db,
            Err(e) => {
                if let Ok(bytes) = std::fs::read(path) {
                    let header = &bytes[..16.min(bytes.len())];
                    let is_sqlite = header.starts_with(b"SQLite format 3\0");
                    tracing::error!(
                        path = %std::path::Path::new(path).display(),
                        header_hex = %hex::encode(header),
                        appears_unencrypted = is_sqlite,
                        error = %e,
                        "Database open failed"
                    );
                } else {
                    tracing::error!(
                        path = %std::path::Path::new(path).display(),
                        error = %e,
                        "Database open failed"
                    );
                }
                return Err(GapError::database(format!(
                    "Failed to open database: {}",
                    e
                )));
            }
        };
        let conn = db
            .connect()
            .map_err(|e| GapError::database(format!("Failed to connect: {}", e)))?;
        let instance = Self {
            inner: DbBackend::LibSql { db, conn },
        };
        crate::database_libsql::run_libsql_migrations(instance.conn()).await?;
        instance
            .conn()
            .execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
            .await
            .map_err(|e| GapError::database(format!("Failed to enable foreign keys: {}", e)))?;
        Ok(instance)
    }

    /// Open an in-memory database (for testing).
    pub async fn in_memory() -> Result<Self> {
        let db = libsql::Builder::new_local(":memory:")
            .build()
            .await
            .map_err(|e| {
                GapError::database(format!("Failed to open in-memory database: {}", e))
            })?;
        let conn = db
            .connect()
            .map_err(|e| GapError::database(format!("Failed to connect: {}", e)))?;
        let instance = Self {
            inner: DbBackend::LibSql { db, conn },
        };
        crate::database_libsql::run_libsql_migrations(instance.conn()).await?;
        // Skip WAL for in-memory, just set foreign keys
        instance
            .conn()
            .execute("PRAGMA foreign_keys = ON;", ())
            .await
            .map_err(|e| GapError::database(format!("Failed to enable foreign keys: {}", e)))?;
        Ok(instance)
    }

    /// Open a Postgres-backed database.
    pub async fn open_postgres(
        url: &str,
        schema: &str,
        max_connections: u32,
        min_connections: u32,
    ) -> Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(max_connections)
            .min_connections(min_connections)
            .connect(url)
            .await
            .map_err(|e| {
                GapError::database(format!("Failed to connect to Postgres: {}", e))
            })?;

        crate::database_postgres::run_postgres_migrations(&pool, schema).await?;

        Ok(Self {
            inner: DbBackend::Postgres { pool },
        })
    }

    // ── Token CRUD ──────────────────────────────────────────────────

    /// Add a token to the database.
    ///
    /// `scopes` controls access restrictions:
    /// - `None` -> unrestricted token (can access anything)
    /// - `Some(&[])` -> deny-all token (no access)
    /// - `Some(&[scope1, scope2])` -> restricted to matching scopes
    pub async fn add_token(
        &self,
        token_value: &str,
        created_at: DateTime<Utc>,
        scopes: Option<&[TokenScope]>,
        ns: &str,
        scope: &str,
    ) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_add_token(conn, token_value, created_at, scopes, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_add_token(pool, token_value, created_at, scopes, ns, scope).await
            }
        }
    }

    /// Get token metadata by token value.
    ///
    /// Returns `None` for revoked tokens or tokens that don't exist.
    pub async fn get_token(
        &self,
        token_value: &str,
        ns: &str,
        scope: &str,
    ) -> Result<Option<TokenMetadata>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_token(conn, token_value, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_token(pool, token_value, ns, scope).await
            }
        }
    }

    /// List tokens.
    ///
    /// When `include_revoked` is `false`, only active (non-revoked) tokens are returned.
    /// When `true`, all tokens are returned including revoked ones.
    pub async fn list_tokens(
        &self,
        include_revoked: bool,
        ns: &str,
        scope: &str,
    ) -> Result<Vec<TokenEntry>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_list_tokens(conn, include_revoked, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_list_tokens(pool, include_revoked, ns, scope).await
            }
        }
    }

    /// Soft-delete a token by setting its revoked_at timestamp.
    ///
    /// Revoked tokens are excluded from `get_token` and `list_tokens(false)`.
    pub async fn revoke_token(&self, token_value: &str, ns: &str, scope: &str) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_revoke_token(conn, token_value, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_revoke_token(pool, token_value, ns, scope).await
            }
        }
    }

    /// Find an active token by prefix match.
    ///
    /// Returns the full token value if exactly one active token matches.
    /// Returns `None` if no tokens match.
    pub async fn get_token_by_prefix(
        &self,
        prefix: &str,
        ns: &str,
        scope: &str,
    ) -> Result<Option<String>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_token_by_prefix(conn, prefix, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_token_by_prefix(pool, prefix, ns, scope).await
            }
        }
    }

    // ── Plugin CRUD ─────────────────────────────────────────────────
    //
    // All plugin state lives in the append-only `plugin_versions` table.
    // The "current" plugin is the latest non-deleted entry for a given ID.
    // "Deleting" a plugin appends a tombstone row (deleted=1).

    /// Add a plugin by appending a new entry to plugin_versions.
    /// Returns the generated UUID for the new plugin.
    pub async fn add_plugin(
        &self,
        plugin: &PluginEntry,
        source_code: &str,
        ns: &str,
        scope: &str,
    ) -> Result<String> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_add_plugin(conn, plugin, source_code, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_add_plugin(pool, plugin, source_code, ns, scope).await
            }
        }
    }

    /// Get a plugin entry by ID (latest version, None if deleted or absent).
    pub async fn get_plugin(
        &self,
        id: &str,
        ns: &str,
        scope: &str,
    ) -> Result<Option<PluginEntry>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_plugin(conn, id, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_plugin(pool, id, ns, scope).await
            }
        }
    }

    /// Get only the source code for a plugin (latest version, None if deleted or absent).
    pub async fn get_plugin_source(
        &self,
        id: &str,
        ns: &str,
        scope: &str,
    ) -> Result<Option<String>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_plugin_source(conn, id, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_plugin_source(pool, id, ns, scope).await
            }
        }
    }

    /// List all plugins (latest non-deleted version of each) within a namespace/scope.
    pub async fn list_plugins(&self, ns: &str, scope: &str) -> Result<Vec<PluginEntry>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_list_plugins(conn, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_list_plugins(pool, ns, scope).await
            }
        }
    }

    /// Remove a plugin by appending a tombstone. Does NOT delete credentials (preserves across reinstalls).
    pub async fn remove_plugin(&self, id: &str, ns: &str, scope: &str) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_remove_plugin(conn, id, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_remove_plugin(pool, id, ns, scope).await
            }
        }
    }

    /// Check whether a plugin exists (latest entry is non-deleted).
    pub async fn has_plugin(&self, id: &str, ns: &str, scope: &str) -> Result<bool> {
        Ok(self.get_plugin(id, ns, scope).await?.is_some())
    }

    /// Look up a plugin version by its source hash within a namespace/scope.
    pub async fn get_plugin_version_by_hash(
        &self,
        source_hash: &str,
        ns: &str,
        scope: &str,
    ) -> Result<Option<PluginVersion>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_plugin_version_by_hash(conn, source_hash, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_plugin_version_by_hash(pool, source_hash, ns, scope).await
            }
        }
    }

    // ── Credential CRUD ─────────────────────────────────────────────

    /// Set (upsert) a credential value.
    pub async fn set_credential(
        &self,
        plugin_id: &str,
        field: &str,
        value: &str,
        ns: &str,
        scope: &str,
    ) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_set_credential(conn, plugin_id, field, value, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_set_credential(pool, plugin_id, field, value, ns, scope).await
            }
        }
    }

    /// Get a single credential value.
    pub async fn get_credential(
        &self,
        plugin_id: &str,
        field: &str,
        ns: &str,
        scope: &str,
    ) -> Result<Option<String>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_credential(conn, plugin_id, field, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_credential(pool, plugin_id, field, ns, scope).await
            }
        }
    }

    /// Get all credentials for a plugin as a field->value map.
    pub async fn get_plugin_credentials(
        &self,
        plugin_id: &str,
        ns: &str,
        scope: &str,
    ) -> Result<Option<HashMap<String, String>>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_plugin_credentials(conn, plugin_id, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_plugin_credentials(pool, plugin_id, ns, scope).await
            }
        }
    }

    /// List all credentials as `CredentialEntry` (plugin_id + field, no value).
    pub async fn list_credentials(&self, ns: &str, scope: &str) -> Result<Vec<CredentialEntry>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_list_credentials(conn, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_list_credentials(pool, ns, scope).await
            }
        }
    }

    /// Remove a single credential.
    pub async fn remove_credential(
        &self,
        plugin_id: &str,
        field: &str,
        ns: &str,
        scope: &str,
    ) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_remove_credential(conn, plugin_id, field, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_remove_credential(pool, plugin_id, field, ns, scope).await
            }
        }
    }

    // ── Config KV ───────────────────────────────────────────────────

    /// Set a config value (blob).
    pub async fn set_config(&self, key: &str, value: &[u8]) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_set_config(conn, key, value).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_set_config(pool, key, value).await
            }
        }
    }

    /// Get a config value (blob).
    pub async fn get_config(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_config(conn, key).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_config(pool, key).await
            }
        }
    }

    /// Delete a config key.
    pub async fn delete_config(&self, key: &str) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_delete_config(conn, key).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_delete_config(pool, key).await
            }
        }
    }

    // ── Password Hash (convenience over config) ─────────────────────

    /// Store the admin password hash.
    pub async fn set_password_hash(&self, hash: &str) -> Result<()> {
        self.set_config("password_hash", hash.as_bytes()).await
    }

    /// Retrieve the admin password hash.
    pub async fn get_password_hash(&self) -> Result<Option<String>> {
        match self.get_config("password_hash").await? {
            Some(bytes) => {
                let s = String::from_utf8(bytes).map_err(|e| {
                    GapError::database(format!("Invalid password hash UTF-8: {}", e))
                })?;
                Ok(Some(s))
            }
            None => Ok(None),
        }
    }

    /// Check whether the server has been initialized (password hash exists).
    pub async fn is_initialized(&self) -> Result<bool> {
        Ok(self.get_password_hash().await?.is_some())
    }

    // ── Activity Logging ────────────────────────────────────────────

    /// Log an activity entry.
    pub async fn log_activity(&self, entry: &ActivityEntry) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_log_activity(conn, entry).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_log_activity(pool, entry).await
            }
        }
    }

    /// Get recent activity, ordered newest-first.
    pub async fn get_activity(&self, limit: Option<u32>) -> Result<Vec<ActivityEntry>> {
        let filter = crate::types::ActivityFilter {
            limit: limit.or(Some(100)),
            ..Default::default()
        };
        self.query_activity(&filter).await
    }

    /// Get activity entries since a given timestamp, newest-first.
    pub async fn get_activity_since(&self, since: DateTime<Utc>) -> Result<Vec<ActivityEntry>> {
        let filter = crate::types::ActivityFilter {
            since: Some(since),
            ..Default::default()
        };
        self.query_activity(&filter).await
    }

    /// Query activity logs with flexible filtering.
    ///
    /// All filter fields are optional. When not set, that filter is skipped.
    /// Results are ordered by id DESC (newest first). Default limit is 100.
    pub async fn query_activity(
        &self,
        filter: &crate::types::ActivityFilter,
    ) -> Result<Vec<ActivityEntry>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_query_activity(conn, filter).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_query_activity(pool, filter).await
            }
        }
    }

    /// Log a management audit event.
    pub async fn log_management_event(&self, entry: &ManagementLogEntry) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_log_management_event(conn, entry).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_log_management_event(pool, entry).await
            }
        }
    }

    /// Query management audit logs with flexible filtering.
    ///
    /// All filter fields are optional. When not set, that filter is skipped.
    /// Results are ordered by id DESC (newest first). Default limit is 100.
    pub async fn query_management_log(
        &self,
        filter: &crate::types::ManagementLogFilter,
    ) -> Result<Vec<ManagementLogEntry>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_query_management_log(conn, filter).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_query_management_log(pool, filter).await
            }
        }
    }

    /// Save detailed request/response data for a proxied request.
    pub async fn save_request_details(
        &self,
        details: &crate::types::RequestDetails,
    ) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_save_request_details(conn, details).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_save_request_details(pool, details).await
            }
        }
    }

    /// Get detailed request/response data for a specific request.
    pub async fn get_request_details(
        &self,
        request_id: &str,
    ) -> Result<Option<crate::types::RequestDetails>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_request_details(conn, request_id).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_request_details(pool, request_id).await
            }
        }
    }

    // ── Plugin Weight ──────────────────────────────────────────────

    /// Update the weight of the latest version of a plugin.
    pub async fn update_plugin_weight(
        &self,
        id: &str,
        weight: i32,
        ns: &str,
        scope: &str,
    ) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_update_plugin_weight(conn, id, weight, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_update_plugin_weight(pool, id, weight, ns, scope).await
            }
        }
    }

    // ── Header Set CRUD ────────────────────────────────────────────

    /// Add a header set with a generated UUID. Returns the new ID.
    pub async fn add_header_set(
        &self,
        match_patterns: &[String],
        weight: i32,
        ns: &str,
        scope: &str,
    ) -> Result<String> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_add_header_set(conn, match_patterns, weight, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_add_header_set(pool, match_patterns, weight, ns, scope).await
            }
        }
    }

    /// Get a header set by ID (None if deleted or absent).
    pub async fn get_header_set(
        &self,
        id: &str,
        ns: &str,
        scope: &str,
    ) -> Result<Option<HeaderSet>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_header_set(conn, id, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_header_set(pool, id, ns, scope).await
            }
        }
    }

    /// List all non-deleted header sets, ordered by id.
    pub async fn list_header_sets(&self, ns: &str, scope: &str) -> Result<Vec<HeaderSet>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_list_header_sets(conn, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_list_header_sets(pool, ns, scope).await
            }
        }
    }

    /// Update a header set (partial update). Error if not found.
    pub async fn update_header_set(
        &self,
        id: &str,
        match_patterns: Option<&[String]>,
        weight: Option<i32>,
        ns: &str,
        scope: &str,
    ) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_update_header_set(conn, id, match_patterns, weight, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_update_header_set(pool, id, match_patterns, weight, ns, scope).await
            }
        }
    }

    /// Soft-delete a header set and remove its headers.
    pub async fn remove_header_set(&self, id: &str, ns: &str, scope: &str) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_remove_header_set(conn, id, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_remove_header_set(pool, id, ns, scope).await
            }
        }
    }

    /// Set (upsert) a header in a header set.
    pub async fn set_header_set_header(
        &self,
        header_set_id: &str,
        header_name: &str,
        header_value: &str,
        _ns: &str,
        _scope: &str,
    ) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_set_header_set_header(conn, header_set_id, header_name, header_value).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_set_header_set_header(pool, header_set_id, header_name, header_value).await
            }
        }
    }

    /// Get all headers for a header set as a name->value map.
    pub async fn get_header_set_headers(
        &self,
        header_set_id: &str,
        _ns: &str,
        _scope: &str,
    ) -> Result<HashMap<String, String>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_header_set_headers(conn, header_set_id).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_header_set_headers(pool, header_set_id).await
            }
        }
    }

    /// List header names for a header set (names only, no values).
    pub async fn list_header_set_header_names(
        &self,
        header_set_id: &str,
        _ns: &str,
        _scope: &str,
    ) -> Result<Vec<String>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_list_header_set_header_names(conn, header_set_id).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_list_header_set_header_names(pool, header_set_id).await
            }
        }
    }

    /// Remove a single header from a header set.
    pub async fn remove_header_set_header(
        &self,
        header_set_id: &str,
        header_name: &str,
        _ns: &str,
        _scope: &str,
    ) -> Result<()> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_remove_header_set_header(conn, header_set_id, header_name).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_remove_header_set_header(pool, header_set_id, header_name).await
            }
        }
    }

    // ── Namespace discovery ─────────────────────────────────────────

    /// Return distinct namespace_ids that have tokens or active plugins.
    pub async fn list_distinct_namespaces(&self) -> Result<Vec<String>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_list_distinct_namespaces(conn).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_list_distinct_namespaces(pool).await
            }
        }
    }

    /// Return distinct scope_ids within a given namespace.
    pub async fn list_namespace_scopes(&self, namespace_id: &str) -> Result<Vec<String>> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_list_namespace_scopes(conn, namespace_id).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_list_namespace_scopes(pool, namespace_id).await
            }
        }
    }

    /// Return resource counts for a given namespace and scope.
    pub async fn get_scope_resource_counts(
        &self,
        ns: &str,
        scope: &str,
    ) -> Result<serde_json::Value> {
        match &self.inner {
            DbBackend::LibSql { conn, .. } => {
                crate::database_libsql::ls_get_scope_resource_counts(conn, ns, scope).await
            }
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_get_scope_resource_counts(pool, ns, scope).await
            }
        }
    }

    // ── Nonce Store ───────────────────────────────────────────────────

    /// Check and insert a nonce (for Postgres-backed nonce store).
    /// Panics if called on LibSql backend.
    pub async fn check_nonce(
        &self,
        namespace_id: &str,
        scope_id: &str,
        key_id: &str,
        nonce_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool> {
        match &self.inner {
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_check_and_insert_nonce(
                    pool,
                    namespace_id,
                    scope_id,
                    key_id,
                    nonce_hash,
                    expires_at,
                )
                .await
            }
            DbBackend::LibSql { .. } => panic!("check_nonce called on LibSql backend"),
        }
    }

    /// Cleanup expired nonces (for Postgres-backed nonce store).
    /// Panics if called on LibSql backend.
    pub async fn cleanup_nonces(&self) -> Result<u64> {
        match &self.inner {
            DbBackend::Postgres { pool } => {
                crate::database_postgres::pg_cleanup_nonces(pool).await
            }
            DbBackend::LibSql { .. } => panic!("cleanup_nonces called on LibSql backend"),
        }
    }
}

#[cfg(test)]
#[path = "database_tests.rs"]
mod tests;
