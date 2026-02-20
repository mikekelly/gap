//! Embedded libSQL database for GAP persistent storage
//!
//! Provides an async database layer backed by libSQL (a SQLite fork) for
//! storing tokens, plugins, credentials, config, and activity logs.

use crate::error::{GapError, Result};
use crate::types::{CredentialEntry, HeaderSet, PluginEntry, PluginVersion, TokenEntry, TokenMetadata};
use crate::types::{ActivityEntry, ManagementLogEntry};
use chrono::{DateTime, Utc};
use sha2::{Sha256, Digest};
use std::collections::HashMap;

/// Schema DDL applied on every database open (idempotent via IF NOT EXISTS).
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    token_value TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    plugin TEXT NOT NULL,
    field TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (plugin, field)
);

CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    request_id TEXT,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    agent_id TEXT,
    status INTEGER NOT NULL,
    plugin_name TEXT,
    plugin_sha TEXT,
    source_hash TEXT,
    request_headers TEXT
);

CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_access_logs_url ON access_logs(url);

CREATE TABLE IF NOT EXISTS plugin_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plugin_name TEXT NOT NULL,
    hosts TEXT NOT NULL DEFAULT '[]',
    credential_schema TEXT NOT NULL DEFAULT '[]',
    commit_sha TEXT,
    source_hash TEXT NOT NULL,
    source_code TEXT NOT NULL,
    installed_at TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_plugin_versions_plugin ON plugin_versions(plugin_name);
CREATE INDEX IF NOT EXISTS idx_plugin_versions_hash ON plugin_versions(source_hash);

CREATE TABLE IF NOT EXISTS management_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    operation TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    success INTEGER NOT NULL,
    error_message TEXT NOT NULL DEFAULT ''
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
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    match_patterns TEXT NOT NULL DEFAULT '[]',
    weight INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS header_set_headers (
    header_set_name TEXT NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,
    PRIMARY KEY (header_set_name, header_name)
);
";

/// Embedded libSQL database for GAP persistent storage.
///
/// Wraps a libSQL `Database` and `Connection`, providing typed CRUD
/// operations for tokens, plugins, credentials, config, and activity logs.
pub struct GapDatabase {
    // Kept alive so the connection remains valid for the database's lifetime.
    #[allow(dead_code)]
    db: libsql::Database,
    conn: libsql::Connection,
}

impl GapDatabase {
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
                return Err(GapError::database(format!("Failed to open encrypted database: {}", e)));
            }
        };
        let conn = db
            .connect()
            .map_err(|e| GapError::database(format!("Failed to connect: {}", e)))?;
        let instance = Self { db, conn };
        instance.run_migrations().await?;
        // Use execute_batch for PRAGMAs because encrypted libSQL returns rows from
        // journal_mode, which causes execute() to fail with "Execute returned rows".
        instance
            .conn
            .execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
            .await
            .map_err(|e| GapError::database(format!("Failed to set PRAGMAs: {}", e)))?;
        Ok(instance)
    }

    /// Open an unencrypted database at the given path.
    pub async fn open_unencrypted(path: &str) -> Result<Self> {
        let db = match libsql::Builder::new_local(path)
            .build()
            .await
        {
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
                return Err(GapError::database(format!("Failed to open database: {}", e)));
            }
        };
        let conn = db
            .connect()
            .map_err(|e| GapError::database(format!("Failed to connect: {}", e)))?;
        let instance = Self { db, conn };
        instance.run_migrations().await?;
        instance
            .conn
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
        let instance = Self { db, conn };
        instance.run_migrations().await?;
        // Skip WAL for in-memory, just set foreign keys
        instance
            .conn
            .execute("PRAGMA foreign_keys = ON;", ())
            .await
            .map_err(|e| GapError::database(format!("Failed to enable foreign keys: {}", e)))?;
        Ok(instance)
    }

    async fn run_migrations(&self) -> Result<()> {
        tracing::debug!("Applying database schema");
        self.conn
            .execute_batch(SCHEMA)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Schema creation failed");
                GapError::database(format!("Failed to run migrations: {}", e))
            })?;

        // Migration for existing DBs — ignore error if columns already exist
        let alter_migrations = [
            "ALTER TABLE access_logs ADD COLUMN plugin_name TEXT",
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
        ];

        for migration in &alter_migrations {
            match self.conn.execute(migration, ()).await {
                Ok(_) => tracing::debug!("Migration applied: {}", migration),
                Err(_) => tracing::debug!("Migration skipped (already applied): {}", migration),
            }
        }

        Ok(())
    }

    // ── Token CRUD ──────────────────────────────────────────────────

    /// Add a token to the database.
    pub async fn add_token(
        &self,
        token_value: &str,
        name: &str,
        created_at: DateTime<Utc>,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO tokens (token_value, name, created_at) VALUES (?1, ?2, ?3)",
                libsql::params![token_value, name, created_at.to_rfc3339()],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
    }

    /// Get token metadata by token value.
    pub async fn get_token(&self, token_value: &str) -> Result<Option<TokenMetadata>> {
        let mut rows = self
            .conn
            .query(
                "SELECT name, created_at FROM tokens WHERE token_value = ?1",
                libsql::params![token_value],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let name: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            let created_at_str: String =
                row.get(1).map_err(|e| GapError::database(e.to_string()))?;
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|e| GapError::database(format!("Invalid timestamp: {}", e)))?
                .with_timezone(&Utc);
            Ok(Some(TokenMetadata { name, created_at }))
        } else {
            Ok(None)
        }
    }

    /// List all tokens.
    pub async fn list_tokens(&self) -> Result<Vec<TokenEntry>> {
        let mut rows = self
            .conn
            .query("SELECT token_value, name, created_at FROM tokens", ())
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let token_value: String =
                row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            let name: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
            let created_at_str: String =
                row.get(2).map_err(|e| GapError::database(e.to_string()))?;
            let created_at = DateTime::parse_from_rfc3339(&created_at_str)
                .map_err(|e| GapError::database(format!("Invalid timestamp: {}", e)))?
                .with_timezone(&Utc);
            result.push(TokenEntry {
                token_value,
                name,
                created_at,
            });
        }
        Ok(result)
    }

    /// Remove a token by its value.
    pub async fn remove_token(&self, token_value: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM tokens WHERE token_value = ?1",
                libsql::params![token_value],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
    }

    // ── Plugin CRUD ─────────────────────────────────────────────────
    //
    // All plugin state lives in the append-only `plugin_versions` table.
    // The "current" plugin is the latest non-deleted entry for a given name.
    // "Deleting" a plugin appends a tombstone row (deleted=1).

    /// Add a plugin by appending a new entry to plugin_versions.
    pub async fn add_plugin(&self, plugin: &PluginEntry, source_code: &str) -> Result<()> {
        let hosts_json =
            serde_json::to_string(&plugin.hosts).map_err(|e| GapError::database(e.to_string()))?;
        let schema_json = serde_json::to_string(&plugin.credential_schema)
            .map_err(|e| GapError::database(e.to_string()))?;

        // Compute source hash
        let source_hash = format!("{:x}", Sha256::digest(source_code.as_bytes()));
        let now = Utc::now().to_rfc3339();

        let permit_http: i64 = if plugin.dangerously_permit_http { 1 } else { 0 };

        self.conn
            .execute(
                "INSERT INTO plugin_versions (plugin_name, hosts, credential_schema, commit_sha, source_hash, source_code, installed_at, deleted, dangerously_permit_http, weight) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8, ?9)",
                libsql::params![
                    plugin.name.as_str(),
                    hosts_json,
                    schema_json,
                    plugin.commit_sha.as_deref().unwrap_or(""),
                    source_hash,
                    source_code,
                    now,
                    permit_http,
                    plugin.weight
                ],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        Ok(())
    }

    /// Get a plugin entry by name (latest version, None if deleted or absent).
    pub async fn get_plugin(&self, name: &str) -> Result<Option<PluginEntry>> {
        // Get the absolute latest entry; if it's a tombstone, the plugin is "deleted".
        let mut rows = self
            .conn
            .query(
                "SELECT plugin_name, hosts, credential_schema, commit_sha, deleted, dangerously_permit_http, weight, installed_at FROM plugin_versions WHERE plugin_name = ?1 ORDER BY id DESC LIMIT 1",
                libsql::params![name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let deleted: i64 = row.get(4).map_err(|e| GapError::database(e.to_string()))?;
            if deleted != 0 {
                return Ok(None);
            }
            Ok(Some(self.row_to_plugin_entry(&row, 5)?))
        } else {
            Ok(None)
        }
    }

    /// Get only the source code for a plugin (latest version, None if deleted or absent).
    pub async fn get_plugin_source(&self, name: &str) -> Result<Option<String>> {
        // Get the absolute latest entry; if it's a tombstone, the plugin is "deleted".
        let mut rows = self
            .conn
            .query(
                "SELECT source_code, deleted FROM plugin_versions WHERE plugin_name = ?1 ORDER BY id DESC LIMIT 1",
                libsql::params![name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
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

    /// List all plugins (latest non-deleted version of each).
    pub async fn list_plugins(&self) -> Result<Vec<PluginEntry>> {
        let mut rows = self
            .conn
            .query(
                "SELECT pv.plugin_name, pv.hosts, pv.credential_schema, pv.commit_sha, pv.dangerously_permit_http, pv.weight, pv.installed_at \
                 FROM plugin_versions pv \
                 INNER JOIN ( \
                     SELECT plugin_name, MAX(id) as max_id \
                     FROM plugin_versions \
                     GROUP BY plugin_name \
                 ) latest ON pv.id = latest.max_id \
                 WHERE pv.deleted = 0",
                (),
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            result.push(self.row_to_plugin_entry(&row, 4)?);
        }
        Ok(result)
    }

    /// Remove a plugin by appending a tombstone. Does NOT delete credentials (preserves across reinstalls).
    pub async fn remove_plugin(&self, name: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO plugin_versions (plugin_name, hosts, credential_schema, commit_sha, source_hash, source_code, installed_at, deleted) VALUES (?1, '[]', '[]', '', '', '', ?2, 1)",
                libsql::params![name, now],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
    }

    /// Check whether a plugin exists (latest entry is non-deleted).
    pub async fn has_plugin(&self, name: &str) -> Result<bool> {
        Ok(self.get_plugin(name).await?.is_some())
    }

    /// Parse a `Row` into a `PluginEntry`.
    ///
    /// Columns expected at positions 0-3: plugin_name, hosts, credential_schema, commit_sha.
    /// The `dangerously_permit_http` column index varies by query and is passed explicitly.
    /// Weight is at `permit_http_col + 1`, installed_at at `permit_http_col + 2`.
    fn row_to_plugin_entry(&self, row: &libsql::Row, permit_http_col: usize) -> Result<PluginEntry> {
        let name: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
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
        let installed_at_raw: String = row.get((permit_http_col + 2) as i32).unwrap_or_default();
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
            name,
            hosts,
            credential_schema,
            commit_sha,
            dangerously_permit_http: dangerously_permit_http != 0,
            weight,
            installed_at,
        })
    }

    /// Look up a plugin version by its source hash.
    pub async fn get_plugin_version_by_hash(&self, source_hash: &str) -> Result<Option<PluginVersion>> {
        let mut rows = self
            .conn
            .query(
                "SELECT plugin_name, commit_sha, source_hash, source_code, installed_at FROM plugin_versions WHERE source_hash = ?1 LIMIT 1",
                libsql::params![source_hash],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let plugin_name: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            let commit_sha_raw: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
            let source_hash: String = row.get(2).map_err(|e| GapError::database(e.to_string()))?;
            let source_code: String = row.get(3).map_err(|e| GapError::database(e.to_string()))?;
            let installed_at_str: String = row.get(4).map_err(|e| GapError::database(e.to_string()))?;

            let commit_sha = if commit_sha_raw.is_empty() { None } else { Some(commit_sha_raw) };
            let installed_at = DateTime::parse_from_rfc3339(&installed_at_str)
                .map_err(|e| GapError::database(format!("Invalid timestamp: {}", e)))?
                .with_timezone(&Utc);

            Ok(Some(PluginVersion {
                plugin_name,
                commit_sha,
                source_hash,
                source_code,
                installed_at,
            }))
        } else {
            Ok(None)
        }
    }

    // ── Credential CRUD ─────────────────────────────────────────────

    /// Set (upsert) a credential value.
    pub async fn set_credential(&self, plugin: &str, field: &str, value: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO credentials (plugin, field, value) VALUES (?1, ?2, ?3)",
                libsql::params![plugin, field, value],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
    }

    /// Get a single credential value.
    pub async fn get_credential(&self, plugin: &str, field: &str) -> Result<Option<String>> {
        let mut rows = self
            .conn
            .query(
                "SELECT value FROM credentials WHERE plugin = ?1 AND field = ?2",
                libsql::params![plugin, field],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let value: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    /// Get all credentials for a plugin as a field->value map.
    pub async fn get_plugin_credentials(
        &self,
        plugin: &str,
    ) -> Result<Option<HashMap<String, String>>> {
        let mut rows = self
            .conn
            .query(
                "SELECT field, value FROM credentials WHERE plugin = ?1",
                libsql::params![plugin],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        let mut map = HashMap::new();
        while let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
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

    /// List all credentials as `CredentialEntry` (plugin + field, no value).
    pub async fn list_credentials(&self) -> Result<Vec<CredentialEntry>> {
        let mut rows = self
            .conn
            .query("SELECT plugin, field FROM credentials", ())
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let plugin: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            let field: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
            result.push(CredentialEntry { plugin, field });
        }
        Ok(result)
    }

    /// Remove a single credential.
    pub async fn remove_credential(&self, plugin: &str, field: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM credentials WHERE plugin = ?1 AND field = ?2",
                libsql::params![plugin, field],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
    }

    // ── Config KV ───────────────────────────────────────────────────

    /// Set a config value (blob).
    pub async fn set_config(&self, key: &str, value: &[u8]) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES (?1, ?2)",
                libsql::params![key, libsql::Value::Blob(value.to_vec())],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
    }

    /// Get a config value (blob).
    pub async fn get_config(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut rows = self
            .conn
            .query(
                "SELECT value FROM config WHERE key = ?1",
                libsql::params![key],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
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

    /// Delete a config key.
    pub async fn delete_config(&self, key: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM config WHERE key = ?1",
                libsql::params![key],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
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
                let s = String::from_utf8(bytes)
                    .map_err(|e| GapError::database(format!("Invalid password hash UTF-8: {}", e)))?;
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
        self.conn
            .execute(
                "INSERT INTO access_logs (timestamp, request_id, method, url, agent_id, status, plugin_name, plugin_sha, source_hash, request_headers, rejection_stage, rejection_reason) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                libsql::params![
                    entry.timestamp.to_rfc3339(),
                    entry.request_id.as_deref().unwrap_or(""),
                    entry.method.as_str(),
                    entry.url.as_str(),
                    entry.agent_id.as_deref().unwrap_or(""),
                    entry.status as i64,
                    entry.plugin_name.as_deref().unwrap_or(""),
                    entry.plugin_sha.as_deref().unwrap_or(""),
                    entry.source_hash.as_deref().unwrap_or(""),
                    entry.request_headers.as_deref().unwrap_or(""),
                    entry.rejection_stage.as_deref().unwrap_or(""),
                    entry.rejection_reason.as_deref().unwrap_or("")
                ],
            )
            .await
            .map_err(|e| GapError::database(format!("Failed to log activity: {}", e)))?;
        Ok(())
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
    pub async fn query_activity(&self, filter: &crate::types::ActivityFilter) -> Result<Vec<ActivityEntry>> {
        let select = "SELECT timestamp, request_id, method, url, agent_id, status, plugin_name, plugin_sha, source_hash, request_headers, rejection_stage, rejection_reason FROM access_logs";

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
        if let Some(ref plugin) = filter.plugin {
            conditions.push(format!("plugin_name = ?{}", idx));
            params.push(libsql::Value::Text(plugin.clone()));
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
            // idx += 1; // not needed, last param
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };

        let limit = filter.limit.unwrap_or(100);
        let query = format!("{}{} ORDER BY id DESC LIMIT {}", select, where_clause, limit);

        let mut rows = self
            .conn
            .query(&query, params)
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        self.rows_to_activity(&mut rows).await
    }

    /// Helper: convert activity rows into `Vec<ActivityEntry>`.
    ///
    /// Columns expected: timestamp, request_id, method, url, agent_id, status,
    ///                   plugin_name, plugin_sha, source_hash, request_headers,
    ///                   rejection_stage, rejection_reason
    async fn rows_to_activity(&self, rows: &mut libsql::Rows) -> Result<Vec<ActivityEntry>> {
        let mut result = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let ts_str: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            let request_id_raw: String =
                row.get(1).map_err(|e| GapError::database(e.to_string()))?;
            let method: String = row.get(2).map_err(|e| GapError::database(e.to_string()))?;
            let url: String = row.get(3).map_err(|e| GapError::database(e.to_string()))?;
            let agent_id_raw: String =
                row.get(4).map_err(|e| GapError::database(e.to_string()))?;
            let status_i64: i64 = row.get(5).map_err(|e| GapError::database(e.to_string()))?;
            let plugin_name_raw: String =
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

            let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                .map_err(|e| GapError::database(format!("Invalid timestamp: {}", e)))?
                .with_timezone(&Utc);

            fn empty_to_none(s: String) -> Option<String> {
                if s.is_empty() { None } else { Some(s) }
            }

            result.push(ActivityEntry {
                timestamp,
                request_id: empty_to_none(request_id_raw),
                method,
                url,
                agent_id: empty_to_none(agent_id_raw),
                status: status_i64 as u16,
                plugin_name: empty_to_none(plugin_name_raw),
                plugin_sha: empty_to_none(plugin_sha_raw),
                source_hash: empty_to_none(source_hash_raw),
                request_headers: empty_to_none(request_headers_raw),
                rejection_stage: empty_to_none(rejection_stage_raw),
                rejection_reason: empty_to_none(rejection_reason_raw),
            });
        }
        Ok(result)
    }

    /// Log a management audit event.
    pub async fn log_management_event(&self, entry: &ManagementLogEntry) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO management_logs (timestamp, operation, resource_type, resource_id, detail, success, error_message) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                libsql::params![
                    entry.timestamp.to_rfc3339(),
                    entry.operation.as_str(),
                    entry.resource_type.as_str(),
                    entry.resource_id.as_deref().unwrap_or(""),
                    entry.detail.as_deref().unwrap_or(""),
                    entry.success as i64,
                    entry.error_message.as_deref().unwrap_or("")
                ],
            )
            .await
            .map_err(|e| GapError::database(format!("Failed to log management event: {}", e)))?;
        Ok(())
    }

    /// Query management audit logs with flexible filtering.
    ///
    /// All filter fields are optional. When not set, that filter is skipped.
    /// Results are ordered by id DESC (newest first). Default limit is 100.
    pub async fn query_management_log(&self, filter: &crate::types::ManagementLogFilter) -> Result<Vec<ManagementLogEntry>> {
        let select = "SELECT timestamp, operation, resource_type, resource_id, detail, success, error_message FROM management_logs";

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

        let _ = idx; // suppress unused warning

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };

        let limit = filter.limit.unwrap_or(100);
        let query = format!("{}{} ORDER BY id DESC LIMIT {}", select, where_clause, limit);

        let mut rows = self
            .conn
            .query(&query, params)
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        self.rows_to_management_log(&mut rows).await
    }

    /// Helper: convert management_logs rows into `Vec<ManagementLogEntry>`.
    ///
    /// Columns expected: timestamp, operation, resource_type, resource_id, detail,
    ///                   success, error_message
    async fn rows_to_management_log(&self, rows: &mut libsql::Rows) -> Result<Vec<ManagementLogEntry>> {
        let mut result = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let ts_str: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            let operation: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
            let resource_type: String = row.get(2).map_err(|e| GapError::database(e.to_string()))?;
            let resource_id_raw: String = row.get(3).map_err(|e| GapError::database(e.to_string()))?;
            let detail_raw: String = row.get(4).map_err(|e| GapError::database(e.to_string()))?;
            let success_i64: i64 = row.get(5).map_err(|e| GapError::database(e.to_string()))?;
            let error_message_raw: String = row.get(6).map_err(|e| GapError::database(e.to_string()))?;

            let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                .map_err(|e| GapError::database(format!("Invalid timestamp: {}", e)))?
                .with_timezone(&Utc);

            fn empty_to_none(s: String) -> Option<String> {
                if s.is_empty() { None } else { Some(s) }
            }

            result.push(ManagementLogEntry {
                timestamp,
                operation,
                resource_type,
                resource_id: empty_to_none(resource_id_raw),
                detail: empty_to_none(detail_raw),
                success: success_i64 != 0,
                error_message: empty_to_none(error_message_raw),
            });
        }
        Ok(result)
    }

    /// Save detailed request/response data for a proxied request.
    pub async fn save_request_details(&self, details: &crate::types::RequestDetails) -> Result<()> {
        self.conn
            .execute(
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

    /// Get detailed request/response data for a specific request.
    pub async fn get_request_details(&self, request_id: &str) -> Result<Option<crate::types::RequestDetails>> {
        let mut rows = self
            .conn
            .query(
                "SELECT request_id, req_headers, req_body, transformed_url, transformed_headers, transformed_body, response_status, response_headers, response_body, body_truncated FROM request_details WHERE request_id = ?1",
                libsql::params![request_id],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            fn empty_to_none(s: String) -> Option<String> {
                if s.is_empty() { None } else { Some(s) }
            }
            fn empty_blob_to_none(b: Vec<u8>) -> Option<Vec<u8>> {
                if b.is_empty() { None } else { Some(b) }
            }
            fn blob_from_value(val: libsql::Value) -> Vec<u8> {
                match val {
                    libsql::Value::Blob(b) => b,
                    _ => Vec::new(),
                }
            }

            let request_id: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            let req_headers_raw: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
            let req_body_val = row.get_value(2).map_err(|e| GapError::database(e.to_string()))?;
            let transformed_url_raw: String = row.get(3).map_err(|e| GapError::database(e.to_string()))?;
            let transformed_headers_raw: String = row.get(4).map_err(|e| GapError::database(e.to_string()))?;
            let transformed_body_val = row.get_value(5).map_err(|e| GapError::database(e.to_string()))?;
            let response_status_raw: i64 = row.get(6).map_err(|e| GapError::database(e.to_string()))?;
            let response_headers_raw: String = row.get(7).map_err(|e| GapError::database(e.to_string()))?;
            let response_body_val = row.get_value(8).map_err(|e| GapError::database(e.to_string()))?;
            let body_truncated_raw: i64 = row.get(9).map_err(|e| GapError::database(e.to_string()))?;

            Ok(Some(crate::types::RequestDetails {
                request_id,
                req_headers: empty_to_none(req_headers_raw),
                req_body: empty_blob_to_none(blob_from_value(req_body_val)),
                transformed_url: empty_to_none(transformed_url_raw),
                transformed_headers: empty_to_none(transformed_headers_raw),
                transformed_body: empty_blob_to_none(blob_from_value(transformed_body_val)),
                response_status: if response_status_raw == 0 { None } else { Some(response_status_raw as u16) },
                response_headers: empty_to_none(response_headers_raw),
                response_body: empty_blob_to_none(blob_from_value(response_body_val)),
                body_truncated: body_truncated_raw != 0,
            }))
        } else {
            Ok(None)
        }
    }

    // ── Plugin Weight ──────────────────────────────────────────────

    /// Update the weight of the latest version of a plugin.
    pub async fn update_plugin_weight(&self, name: &str, weight: i32) -> Result<()> {
        let rows_affected = self
            .conn
            .execute(
                "UPDATE plugin_versions SET weight = ?1 WHERE id = (SELECT MAX(id) FROM plugin_versions WHERE plugin_name = ?2 AND deleted = 0)",
                libsql::params![weight, name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if rows_affected == 0 {
            return Err(GapError::database(format!("Plugin '{}' not found", name)));
        }
        Ok(())
    }

    // ── Header Set CRUD ────────────────────────────────────────────

    /// Add or re-activate a header set (idempotent upsert).
    pub async fn add_header_set(&self, name: &str, match_patterns: &[String], weight: i32) -> Result<()> {
        let patterns_json = serde_json::to_string(match_patterns)
            .map_err(|e| GapError::database(e.to_string()))?;
        let now = Utc::now().to_rfc3339();

        self.conn
            .execute(
                "INSERT INTO header_sets (name, match_patterns, weight, created_at, deleted) VALUES (?1, ?2, ?3, ?4, 0) ON CONFLICT(name) DO UPDATE SET match_patterns = ?2, weight = ?3, deleted = 0",
                libsql::params![name, patterns_json, weight, now],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
    }

    /// Get a header set by name (None if deleted or absent).
    pub async fn get_header_set(&self, name: &str) -> Result<Option<HeaderSet>> {
        let mut rows = self
            .conn
            .query(
                "SELECT name, match_patterns, weight, created_at FROM header_sets WHERE name = ?1 AND deleted = 0",
                libsql::params![name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            Ok(Some(self.row_to_header_set(&row)?))
        } else {
            Ok(None)
        }
    }

    /// List all non-deleted header sets, ordered by name.
    pub async fn list_header_sets(&self) -> Result<Vec<HeaderSet>> {
        let mut rows = self
            .conn
            .query(
                "SELECT name, match_patterns, weight, created_at FROM header_sets WHERE deleted = 0 ORDER BY name",
                (),
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        let mut result = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            result.push(self.row_to_header_set(&row)?);
        }
        Ok(result)
    }

    /// Update a header set (partial update). Error if not found.
    pub async fn update_header_set(
        &self,
        name: &str,
        match_patterns: Option<&[String]>,
        weight: Option<i32>,
    ) -> Result<()> {
        let mut sets: Vec<String> = Vec::new();
        let mut params: Vec<libsql::Value> = Vec::new();
        let mut idx = 1u32;

        if let Some(patterns) = match_patterns {
            let json = serde_json::to_string(patterns)
                .map_err(|e| GapError::database(e.to_string()))?;
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
            "UPDATE header_sets SET {} WHERE name = ?{} AND deleted = 0",
            sets.join(", "),
            idx
        );
        params.push(libsql::Value::Text(name.to_string()));

        let rows_affected = self
            .conn
            .execute(&sql, params)
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if rows_affected == 0 {
            return Err(GapError::database(format!("Header set '{}' not found", name)));
        }
        Ok(())
    }

    /// Soft-delete a header set and remove its headers.
    pub async fn remove_header_set(&self, name: &str) -> Result<()> {
        self.conn
            .execute(
                "UPDATE header_sets SET deleted = 1 WHERE name = ?1 AND deleted = 0",
                libsql::params![name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        self.conn
            .execute(
                "DELETE FROM header_set_headers WHERE header_set_name = ?1",
                libsql::params![name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        Ok(())
    }

    /// Set (upsert) a header in a header set.
    pub async fn set_header_set_header(
        &self,
        header_set_name: &str,
        header_name: &str,
        header_value: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO header_set_headers (header_set_name, header_name, header_value) VALUES (?1, ?2, ?3)",
                libsql::params![header_set_name, header_name, header_value],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
    }

    /// Get all headers for a header set as a name->value map.
    pub async fn get_header_set_headers(&self, header_set_name: &str) -> Result<HashMap<String, String>> {
        let mut rows = self
            .conn
            .query(
                "SELECT header_name, header_value FROM header_set_headers WHERE header_set_name = ?1",
                libsql::params![header_set_name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        let mut map = HashMap::new();
        while let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let name: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            let value: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
            map.insert(name, value);
        }
        Ok(map)
    }

    /// List header names for a header set (names only, no values).
    pub async fn list_header_set_header_names(&self, header_set_name: &str) -> Result<Vec<String>> {
        let mut rows = self
            .conn
            .query(
                "SELECT header_name FROM header_set_headers WHERE header_set_name = ?1",
                libsql::params![header_set_name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        let mut result = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let name: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            result.push(name);
        }
        Ok(result)
    }

    /// Remove a single header from a header set.
    pub async fn remove_header_set_header(&self, header_set_name: &str, header_name: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM header_set_headers WHERE header_set_name = ?1 AND header_name = ?2",
                libsql::params![header_set_name, header_name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
    }

    /// Parse a row from header_sets into a HeaderSet.
    /// Columns expected: name, match_patterns, weight, created_at.
    fn row_to_header_set(&self, row: &libsql::Row) -> Result<HeaderSet> {
        let name: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
        let patterns_json: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
        let weight: i32 = row.get(2).map_err(|e| GapError::database(e.to_string()))?;
        let created_at_str: String = row.get(3).map_err(|e| GapError::database(e.to_string()))?;

        let match_patterns: Vec<String> = serde_json::from_str(&patterns_json)
            .map_err(|e| GapError::database(e.to_string()))?;
        let created_at = DateTime::parse_from_rfc3339(&created_at_str)
            .map_err(|e| GapError::database(format!("Invalid created_at: {}", e)))?
            .with_timezone(&Utc);

        Ok(HeaderSet {
            name,
            match_patterns,
            weight,
            created_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    // ── Token CRUD ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_token_add_and_get() {
        let db = GapDatabase::in_memory().await.unwrap();
        let now = Utc::now();

        db.add_token("gap_abc123", "test-agent", now)
            .await
            .unwrap();

        let meta = db.get_token("gap_abc123").await.unwrap().unwrap();
        assert_eq!(meta.name, "test-agent");
        // Round-trip via RFC 3339 may lose sub-microsecond precision;
        // compare to the second.
        assert_eq!(
            meta.created_at.timestamp(),
            now.timestamp()
        );
    }

    #[tokio::test]
    async fn test_token_get_nonexistent() {
        let db = GapDatabase::in_memory().await.unwrap();
        assert!(db.get_token("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_token_list() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Empty initially
        assert_eq!(db.list_tokens().await.unwrap().len(), 0);

        let now = Utc::now();
        db.add_token("gap_t1", "token1", now).await.unwrap();
        db.add_token("gap_t2", "token2", now).await.unwrap();

        let tokens = db.list_tokens().await.unwrap();
        assert_eq!(tokens.len(), 2);
        let names: Vec<&str> = tokens.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"token1"));
        assert!(names.contains(&"token2"));
    }

    #[tokio::test]
    async fn test_token_remove() {
        let db = GapDatabase::in_memory().await.unwrap();
        let now = Utc::now();

        db.add_token("gap_t1", "token1", now).await.unwrap();
        db.add_token("gap_t2", "token2", now).await.unwrap();

        db.remove_token("gap_t1").await.unwrap();

        let tokens = db.list_tokens().await.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_value, "gap_t2");
    }

    // ── Plugin CRUD ─────────────────────────────────────────────────

    fn sample_plugin(name: &str) -> PluginEntry {
        PluginEntry {
            name: name.to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        }
    }

    #[tokio::test]
    async fn test_plugin_add_and_get() {
        let db = GapDatabase::in_memory().await.unwrap();
        let plugin = sample_plugin("exa");

        db.add_plugin(&plugin, "function transform() {}").await.unwrap();

        let got = db.get_plugin("exa").await.unwrap().unwrap();
        assert_eq!(got.name, "exa");
        assert_eq!(got.hosts, vec!["api.example.com"]);
        assert_eq!(got.credential_schema, vec!["api_key"]);
    }

    #[tokio::test]
    async fn test_plugin_get_source() {
        let db = GapDatabase::in_memory().await.unwrap();
        let plugin = sample_plugin("exa");

        db.add_plugin(&plugin, "// source code here")
            .await
            .unwrap();

        let src = db.get_plugin_source("exa").await.unwrap().unwrap();
        assert_eq!(src, "// source code here");
    }

    #[tokio::test]
    async fn test_plugin_get_nonexistent() {
        let db = GapDatabase::in_memory().await.unwrap();
        assert!(db.get_plugin("nope").await.unwrap().is_none());
        assert!(db.get_plugin_source("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_plugin_list() {
        let db = GapDatabase::in_memory().await.unwrap();

        assert_eq!(db.list_plugins().await.unwrap().len(), 0);

        db.add_plugin(&sample_plugin("exa"), "src1").await.unwrap();
        db.add_plugin(&sample_plugin("github"), "src2")
            .await
            .unwrap();

        let plugins = db.list_plugins().await.unwrap();
        assert_eq!(plugins.len(), 2);
    }

    #[tokio::test]
    async fn test_plugin_remove_preserves_credentials() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.add_plugin(&sample_plugin("exa"), "src").await.unwrap();
        db.set_credential("exa", "api_key", "secret")
            .await
            .unwrap();

        // Remove plugin
        db.remove_plugin("exa").await.unwrap();

        // Plugin is gone
        assert!(db.get_plugin("exa").await.unwrap().is_none());
        // Credentials are preserved
        let cred = db.get_credential("exa", "api_key").await.unwrap();
        assert_eq!(cred, Some("secret".to_string()));
    }

    #[tokio::test]
    async fn test_plugin_has() {
        let db = GapDatabase::in_memory().await.unwrap();
        assert!(!db.has_plugin("exa").await.unwrap());

        db.add_plugin(&sample_plugin("exa"), "src").await.unwrap();
        assert!(db.has_plugin("exa").await.unwrap());
    }

    #[tokio::test]
    async fn test_plugin_with_commit_sha() {
        let db = GapDatabase::in_memory().await.unwrap();
        let plugin = PluginEntry {
            name: "exa".to_string(),
            hosts: vec!["api.exa.ai".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: Some("abc1234".to_string()),
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        };

        db.add_plugin(&plugin, "src").await.unwrap();

        let got = db.get_plugin("exa").await.unwrap().unwrap();
        assert_eq!(got.commit_sha, Some("abc1234".to_string()));
    }

    // ── Credential CRUD ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_credential_set_and_get() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.set_credential("exa", "api_key", "secret")
            .await
            .unwrap();

        let val = db.get_credential("exa", "api_key").await.unwrap();
        assert_eq!(val, Some("secret".to_string()));
    }

    #[tokio::test]
    async fn test_credential_get_nonexistent() {
        let db = GapDatabase::in_memory().await.unwrap();
        assert!(db.get_credential("nope", "nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_credential_get_plugin_credentials() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.set_credential("exa", "api_key", "key-val")
            .await
            .unwrap();
        db.set_credential("exa", "secret", "secret-val")
            .await
            .unwrap();

        let creds = db.get_plugin_credentials("exa").await.unwrap().unwrap();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds.get("api_key").unwrap(), "key-val");
        assert_eq!(creds.get("secret").unwrap(), "secret-val");

        // Nonexistent plugin returns None
        assert!(db.get_plugin_credentials("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_credential_list() {
        let db = GapDatabase::in_memory().await.unwrap();

        assert_eq!(db.list_credentials().await.unwrap().len(), 0);

        db.set_credential("exa", "api_key", "v1").await.unwrap();
        db.set_credential("github", "token", "v2").await.unwrap();

        let creds = db.list_credentials().await.unwrap();
        assert_eq!(creds.len(), 2);
        assert!(creds.iter().any(|c| c.plugin == "exa" && c.field == "api_key"));
        assert!(creds.iter().any(|c| c.plugin == "github" && c.field == "token"));
    }

    #[tokio::test]
    async fn test_credential_remove() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.set_credential("exa", "api_key", "v1").await.unwrap();
        db.set_credential("exa", "secret", "v2").await.unwrap();

        db.remove_credential("exa", "api_key").await.unwrap();

        assert!(db.get_credential("exa", "api_key").await.unwrap().is_none());
        assert_eq!(
            db.get_credential("exa", "secret").await.unwrap(),
            Some("v2".to_string())
        );
    }

    // ── Config KV ───────────────────────────────────────────────────

    #[tokio::test]
    async fn test_config_set_get_delete() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Not found initially
        assert!(db.get_config("my_key").await.unwrap().is_none());

        // Set and get
        db.set_config("my_key", b"hello world").await.unwrap();
        let val = db.get_config("my_key").await.unwrap().unwrap();
        assert_eq!(val, b"hello world");

        // Overwrite
        db.set_config("my_key", b"updated").await.unwrap();
        let val = db.get_config("my_key").await.unwrap().unwrap();
        assert_eq!(val, b"updated");

        // Delete
        db.delete_config("my_key").await.unwrap();
        assert!(db.get_config("my_key").await.unwrap().is_none());
    }

    // ── Password Hash ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_password_hash() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Not initialized
        assert!(!db.is_initialized().await.unwrap());
        assert!(db.get_password_hash().await.unwrap().is_none());

        // Set hash
        db.set_password_hash("argon2$hash$here").await.unwrap();
        assert!(db.is_initialized().await.unwrap());
        assert_eq!(
            db.get_password_hash().await.unwrap(),
            Some("argon2$hash$here".to_string())
        );
    }

    // ── Activity ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_activity_log_and_get() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/users".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].method, "GET");
        assert_eq!(logs[0].url, "https://api.example.com/users");
        assert_eq!(logs[0].agent_id, Some("agent-1".to_string()));
        assert_eq!(logs[0].status, 200);
    }

    #[tokio::test]
    async fn test_activity_get_with_limit() {
        let db = GapDatabase::in_memory().await.unwrap();

        for i in 0..5 {
            let entry = ActivityEntry {
                timestamp: Utc::now() + Duration::seconds(i),
                request_id: None,
                method: "GET".to_string(),
                url: format!("https://api.example.com/{}", i),
                agent_id: None,
                status: 200,
                plugin_name: None,
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
            };
            db.log_activity(&entry).await.unwrap();
        }

        let logs = db.get_activity(Some(3)).await.unwrap();
        assert_eq!(logs.len(), 3);
        // Newest first
        assert!(logs[0].url.contains("/4"));
    }

    #[tokio::test]
    async fn test_activity_get_since() {
        let db = GapDatabase::in_memory().await.unwrap();

        let past = Utc::now() - Duration::hours(2);
        let recent = Utc::now() - Duration::minutes(30);
        let now = Utc::now();

        // Old entry
        db.log_activity(&ActivityEntry {
            timestamp: past,
            request_id: None,
            method: "GET".to_string(),
            url: "https://old.example.com".to_string(),
            agent_id: None,
            status: 200,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        })
        .await
        .unwrap();

        // Recent entry
        db.log_activity(&ActivityEntry {
            timestamp: now,
            request_id: None,
            method: "POST".to_string(),
            url: "https://new.example.com".to_string(),
            agent_id: Some("agent-2".to_string()),
            status: 201,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        })
        .await
        .unwrap();

        let logs = db.get_activity_since(recent).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].method, "POST");
    }

    #[tokio::test]
    async fn test_activity_no_agent_id() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "DELETE".to_string(),
            url: "https://api.example.com/resource".to_string(),
            agent_id: None,
            status: 204,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].agent_id, None);
    }

    #[tokio::test]
    async fn test_activity_with_plugin_info() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_name: Some("exa".to_string()),
            plugin_sha: Some("abc1234".to_string()),
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].plugin_name, Some("exa".to_string()));
        assert_eq!(logs[0].plugin_sha, Some("abc1234".to_string()));
    }

    #[tokio::test]
    async fn test_activity_with_no_plugin_info() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: None,
            status: 200,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].plugin_name, None);
        assert_eq!(logs[0].plugin_sha, None);
    }

    #[tokio::test]
    async fn test_activity_with_source_hash() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_name: Some("exa".to_string()),
            plugin_sha: Some("abc1234".to_string()),
            source_hash: Some("deadbeef1234".to_string()),
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].source_hash, Some("deadbeef1234".to_string()));
    }

    #[tokio::test]
    async fn test_activity_with_request_headers() {
        let db = GapDatabase::in_memory().await.unwrap();

        let headers_json = r#"{"Authorization":"Bearer [REDACTED]","Host":"api.example.com"}"#;
        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_name: Some("exa".to_string()),
            plugin_sha: None,
            source_hash: None,
            request_headers: Some(headers_json.to_string()),
            rejection_stage: None,
            rejection_reason: None,
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0].request_headers,
            Some(headers_json.to_string())
        );
    }

    #[tokio::test]
    async fn test_activity_without_request_headers() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: None,
            status: 200,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].request_headers, None);
    }

    // ── Filtered Activity Queries ──────────────────────────────────

    /// Helper: seed diverse activity entries for query_activity tests
    async fn seed_activity(db: &GapDatabase) {
        let entries = vec![
            ActivityEntry {
                timestamp: Utc::now() - Duration::seconds(5),
                request_id: Some("aaa0000000000001".to_string()),
                method: "GET".to_string(),
                url: "https://api.example.com/users".to_string(),
                agent_id: Some("agent-1".to_string()),
                status: 200,
                plugin_name: Some("exa".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
            },
            ActivityEntry {
                timestamp: Utc::now() - Duration::seconds(4),
                request_id: Some("aaa0000000000002".to_string()),
                method: "POST".to_string(),
                url: "https://api.example.com/data".to_string(),
                agent_id: Some("agent-1".to_string()),
                status: 201,
                plugin_name: Some("exa".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
            },
            ActivityEntry {
                timestamp: Utc::now() - Duration::seconds(3),
                request_id: Some("bbb0000000000003".to_string()),
                method: "GET".to_string(),
                url: "https://other.service.io/health".to_string(),
                agent_id: Some("agent-2".to_string()),
                status: 200,
                plugin_name: Some("github".to_string()),
                plugin_sha: None,
                source_hash: None,
                request_headers: None,
                rejection_stage: None,
                rejection_reason: None,
            },
            ActivityEntry {
                timestamp: Utc::now() - Duration::seconds(2),
                request_id: Some("ccc0000000000004".to_string()),
                method: "DELETE".to_string(),
                url: "https://api.example.com/items/42".to_string(),
                agent_id: Some("agent-2".to_string()),
                status: 204,
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

    #[tokio::test]
    async fn test_query_activity_empty_filter_returns_all() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter::default();
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 4);
        // Newest first (ORDER BY id DESC)
        assert_eq!(results[0].method, "DELETE");
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_domain() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            domain: Some("api.example.com".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 3); // 3 entries with api.example.com
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_plugin() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            plugin: Some("exa".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 2); // 2 entries with plugin "exa"
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_method() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            method: Some("GET".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 2); // 2 GET requests
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_agent() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            agent: Some("agent-2".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 2); // 2 entries from agent-2
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_request_id() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            request_id: Some("bbb0000000000003".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://other.service.io/health");
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_path() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            path: Some("/users".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://api.example.com/users");
    }

    #[tokio::test]
    async fn test_query_activity_combined_filters() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        // Filter by domain + method — should match only GET on api.example.com
        let filter = crate::types::ActivityFilter {
            domain: Some("api.example.com".to_string()),
            method: Some("GET".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://api.example.com/users");
    }

    #[tokio::test]
    async fn test_query_activity_with_limit() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            limit: Some(2),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_query_activity_filter_by_since() {
        let db = GapDatabase::in_memory().await.unwrap();

        let past = Utc::now() - Duration::hours(2);
        let recent = Utc::now() - Duration::minutes(5);

        // Old entry
        db.log_activity(&ActivityEntry {
            timestamp: past,
            request_id: None,
            method: "GET".to_string(),
            url: "https://old.example.com".to_string(),
            agent_id: None,
            status: 200,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        }).await.unwrap();

        // Recent entry
        db.log_activity(&ActivityEntry {
            timestamp: Utc::now(),
            request_id: None,
            method: "POST".to_string(),
            url: "https://new.example.com".to_string(),
            agent_id: None,
            status: 201,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        }).await.unwrap();

        let filter = crate::types::ActivityFilter {
            since: Some(recent),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].method, "POST");
    }

    #[tokio::test]
    async fn test_query_activity_request_id_stored_and_retrieved() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: Some("deadbeef12345678".to_string()),
            method: "GET".to_string(),
            url: "https://api.example.com/test".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: None,
            rejection_reason: None,
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].request_id, Some("deadbeef12345678".to_string()));
    }

    #[tokio::test]
    async fn test_query_activity_no_match_returns_empty() {
        let db = GapDatabase::in_memory().await.unwrap();
        seed_activity(&db).await;

        let filter = crate::types::ActivityFilter {
            plugin: Some("nonexistent".to_string()),
            ..Default::default()
        };
        let results = db.query_activity(&filter).await.unwrap();
        assert_eq!(results.len(), 0);
    }

    // ── Plugin Version History ──────────────────────────────────────

    #[tokio::test]
    async fn test_add_plugin_and_get_by_hash() {
        let db = GapDatabase::in_memory().await.unwrap();

        let source_code = "function transform() {}";
        let source_hash = format!("{:x}", sha2::Sha256::digest(source_code.as_bytes()));

        let plugin = PluginEntry {
            name: "my-plugin".to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: Some("abc1234".to_string()),
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&plugin, source_code).await.unwrap();

        let version = db.get_plugin_version_by_hash(&source_hash).await.unwrap();
        assert!(version.is_some());
        let version = version.unwrap();
        assert_eq!(version.plugin_name, "my-plugin");
        assert_eq!(version.commit_sha, Some("abc1234".to_string()));
        assert_eq!(version.source_hash, source_hash);
        assert_eq!(version.source_code, source_code);
    }

    #[tokio::test]
    async fn test_get_plugin_version_by_hash_not_found() {
        let db = GapDatabase::in_memory().await.unwrap();
        let result = db.get_plugin_version_by_hash("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_add_plugin_creates_version_entry() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin = sample_plugin("test-versioned");
        let source_code = "function transform() { return request; }";
        db.add_plugin(&plugin, source_code).await.unwrap();

        // Compute expected hash
        let expected_hash = format!("{:x}", sha2::Sha256::digest(source_code.as_bytes()));

        // Should be able to find the version by hash
        let version = db.get_plugin_version_by_hash(&expected_hash).await.unwrap();
        assert!(version.is_some());
        let version = version.unwrap();
        assert_eq!(version.plugin_name, "test-versioned");
        assert_eq!(version.source_code, source_code);
    }

    #[tokio::test]
    async fn test_plugin_versions_are_append_only() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin = sample_plugin("versioned-plugin");

        // Install v1
        let code_v1 = "// version 1";
        db.add_plugin(&plugin, code_v1).await.unwrap();

        // Install v2 (same plugin name, different code)
        let code_v2 = "// version 2";
        db.add_plugin(&plugin, code_v2).await.unwrap();

        // Both versions should exist
        let hash_v1 = format!("{:x}", sha2::Sha256::digest(code_v1.as_bytes()));
        let hash_v2 = format!("{:x}", sha2::Sha256::digest(code_v2.as_bytes()));

        let v1 = db.get_plugin_version_by_hash(&hash_v1).await.unwrap();
        let v2 = db.get_plugin_version_by_hash(&hash_v2).await.unwrap();
        assert!(v1.is_some());
        assert!(v2.is_some());
        assert_eq!(v1.unwrap().source_code, code_v1);
        assert_eq!(v2.unwrap().source_code, code_v2);
    }

    // ── Append-only tombstone behavior ─────────────────────────────

    #[tokio::test]
    async fn test_remove_plugin_creates_tombstone() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.add_plugin(&sample_plugin("exa"), "src").await.unwrap();
        db.remove_plugin("exa").await.unwrap();

        // Plugin should be invisible via get/has/list
        assert!(db.get_plugin("exa").await.unwrap().is_none());
        assert!(!db.has_plugin("exa").await.unwrap());
        assert_eq!(db.list_plugins().await.unwrap().len(), 0);
        assert!(db.get_plugin_source("exa").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_reinstall_after_delete() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Install, delete, reinstall
        db.add_plugin(&sample_plugin("exa"), "v1 src").await.unwrap();
        db.remove_plugin("exa").await.unwrap();
        assert!(db.get_plugin("exa").await.unwrap().is_none());

        db.add_plugin(&sample_plugin("exa"), "v2 src").await.unwrap();
        let got = db.get_plugin("exa").await.unwrap().unwrap();
        assert_eq!(got.name, "exa");

        let src = db.get_plugin_source("exa").await.unwrap().unwrap();
        assert_eq!(src, "v2 src");
    }

    #[tokio::test]
    async fn test_list_plugins_only_latest_non_deleted() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Install two plugins
        db.add_plugin(&sample_plugin("exa"), "src1").await.unwrap();
        db.add_plugin(&sample_plugin("github"), "src2").await.unwrap();

        // Delete one
        db.remove_plugin("exa").await.unwrap();

        let plugins = db.list_plugins().await.unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "github");
    }

    #[tokio::test]
    async fn test_update_plugin_shows_latest_version() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin_v1 = PluginEntry {
            name: "exa".to_string(),
            hosts: vec!["api.exa.ai".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: Some("aaa1111".to_string()),
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&plugin_v1, "v1 code").await.unwrap();

        let plugin_v2 = PluginEntry {
            name: "exa".to_string(),
            hosts: vec!["api.exa.ai".to_string(), "new.exa.ai".to_string()],
            credential_schema: vec!["api_key".to_string(), "secret".to_string()],
            commit_sha: Some("bbb2222".to_string()),
            dangerously_permit_http: false,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&plugin_v2, "v2 code").await.unwrap();

        // get_plugin should return v2 metadata
        let got = db.get_plugin("exa").await.unwrap().unwrap();
        assert_eq!(got.hosts, vec!["api.exa.ai", "new.exa.ai"]);
        assert_eq!(got.credential_schema, vec!["api_key", "secret"]);
        assert_eq!(got.commit_sha, Some("bbb2222".to_string()));

        // get_plugin_source should return v2 code
        let src = db.get_plugin_source("exa").await.unwrap().unwrap();
        assert_eq!(src, "v2 code");

        // list should still show only one entry for "exa"
        let plugins = db.list_plugins().await.unwrap();
        assert_eq!(plugins.len(), 1);
    }

    #[tokio::test]
    async fn test_dangerously_permit_http_stored_and_retrieved() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Plugin with dangerously_permit_http = true
        let plugin = PluginEntry {
            name: "http-plugin".to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
            dangerously_permit_http: true,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&plugin, "src").await.unwrap();

        let got = db.get_plugin("http-plugin").await.unwrap().unwrap();
        assert!(got.dangerously_permit_http, "dangerously_permit_http should be true");
    }

    #[tokio::test]
    async fn test_dangerously_permit_http_defaults_false() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Plugin without dangerously_permit_http (default false)
        let plugin = sample_plugin("safe-plugin");
        db.add_plugin(&plugin, "src").await.unwrap();

        let got = db.get_plugin("safe-plugin").await.unwrap().unwrap();
        assert!(!got.dangerously_permit_http, "dangerously_permit_http should default to false");
    }

    #[tokio::test]
    async fn test_dangerously_permit_http_in_list_plugins() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin = PluginEntry {
            name: "http-list-test".to_string(),
            hosts: vec!["api.example.com".to_string()],
            credential_schema: vec!["api_key".to_string()],
            commit_sha: None,
            dangerously_permit_http: true,
            weight: 0,
            installed_at: None,
        };
        db.add_plugin(&plugin, "src").await.unwrap();

        let plugins = db.list_plugins().await.unwrap();
        assert_eq!(plugins.len(), 1);
        assert!(plugins[0].dangerously_permit_http);
    }

    // ── Rejection Tracking ─────────────────────────────────────────

    #[tokio::test]
    async fn test_activity_with_rejection() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ActivityEntry {
            timestamp: Utc::now(),
            request_id: Some("rej001".to_string()),
            method: "GET".to_string(),
            url: "https://unknown.host.com/data".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 0,
            plugin_name: None,
            plugin_sha: None,
            source_hash: None,
            request_headers: None,
            rejection_stage: Some("no_matching_plugin".to_string()),
            rejection_reason: Some("Host 'unknown.host.com' has no matching plugin".to_string()),
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].status, 0);
        assert_eq!(logs[0].rejection_stage, Some("no_matching_plugin".to_string()));
        assert_eq!(logs[0].rejection_reason, Some("Host 'unknown.host.com' has no matching plugin".to_string()));
    }

    // ── Request Details ────────────────────────────────────────────

    #[tokio::test]
    async fn test_request_details_round_trip() {
        let db = GapDatabase::in_memory().await.unwrap();

        let details = crate::types::RequestDetails {
            request_id: "test-req-001".to_string(),
            req_headers: Some(r#"{"Host":"api.example.com","Accept":"*/*"}"#.to_string()),
            req_body: Some(b"request body here".to_vec()),
            transformed_url: Some("https://api.example.com/v2/data".to_string()),
            transformed_headers: Some(r#"{"Authorization":"Bearer [REDACTED]","Host":"api.example.com"}"#.to_string()),
            transformed_body: Some(b"transformed body".to_vec()),
            response_status: Some(200),
            response_headers: Some(r#"{"Content-Type":"application/json"}"#.to_string()),
            response_body: Some(b"{\"result\":\"ok\"}".to_vec()),
            body_truncated: false,
        };
        db.save_request_details(&details).await.unwrap();

        let got = db.get_request_details("test-req-001").await.unwrap().unwrap();
        assert_eq!(got.request_id, "test-req-001");
        assert_eq!(got.req_headers, details.req_headers);
        assert_eq!(got.req_body, details.req_body);
        assert_eq!(got.transformed_url, details.transformed_url);
        assert_eq!(got.transformed_headers, details.transformed_headers);
        assert_eq!(got.transformed_body, details.transformed_body);
        assert_eq!(got.response_status, Some(200));
        assert_eq!(got.response_headers, details.response_headers);
        assert_eq!(got.response_body, details.response_body);
        assert!(!got.body_truncated);
    }

    #[tokio::test]
    async fn test_request_details_not_found() {
        let db = GapDatabase::in_memory().await.unwrap();
        let result = db.get_request_details("nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_request_details_partial_data() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Only pre-transform data (e.g., rejected request)
        let details = crate::types::RequestDetails {
            request_id: "rejected-001".to_string(),
            req_headers: Some(r#"{"Host":"blocked.com"}"#.to_string()),
            req_body: None,
            transformed_url: None,
            transformed_headers: None,
            transformed_body: None,
            response_status: None,
            response_headers: None,
            response_body: None,
            body_truncated: false,
        };
        db.save_request_details(&details).await.unwrap();

        let got = db.get_request_details("rejected-001").await.unwrap().unwrap();
        assert_eq!(got.req_headers, Some(r#"{"Host":"blocked.com"}"#.to_string()));
        assert!(got.transformed_url.is_none());
        assert!(got.response_status.is_none());
    }

    #[tokio::test]
    async fn test_request_details_with_truncated_body() {
        let db = GapDatabase::in_memory().await.unwrap();

        let details = crate::types::RequestDetails {
            request_id: "truncated-001".to_string(),
            req_headers: None,
            req_body: Some(vec![0u8; 100]),
            transformed_url: None,
            transformed_headers: None,
            transformed_body: None,
            response_status: None,
            response_headers: None,
            response_body: None,
            body_truncated: true,
        };
        db.save_request_details(&details).await.unwrap();

        let got = db.get_request_details("truncated-001").await.unwrap().unwrap();
        assert!(got.body_truncated);
    }

    // ── Management Log ───────────────────────────────────────────────

    fn sample_management_entry(operation: &str, resource_type: &str) -> ManagementLogEntry {
        ManagementLogEntry {
            timestamp: Utc::now(),
            operation: operation.to_string(),
            resource_type: resource_type.to_string(),
            resource_id: None,
            detail: None,
            success: true,
            error_message: None,
        }
    }

    #[tokio::test]
    async fn test_management_log_round_trip() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ManagementLogEntry {
            timestamp: Utc::now(),
            operation: "token_create".to_string(),
            resource_type: "token".to_string(),
            resource_id: Some("tok_abc123".to_string()),
            detail: Some(r#"{"name":"my-token"}"#.to_string()),
            success: true,
            error_message: None,
        };
        db.log_management_event(&entry).await.unwrap();

        let logs = db.query_management_log(&crate::types::ManagementLogFilter::default()).await.unwrap();
        assert_eq!(logs.len(), 1);
        let got = &logs[0];
        assert_eq!(got.operation, "token_create");
        assert_eq!(got.resource_type, "token");
        assert_eq!(got.resource_id, Some("tok_abc123".to_string()));
        assert_eq!(got.detail, Some(r#"{"name":"my-token"}"#.to_string()));
        assert!(got.success);
        assert_eq!(got.error_message, None);
    }

    #[tokio::test]
    async fn test_management_log_round_trip_failure_entry() {
        let db = GapDatabase::in_memory().await.unwrap();

        let entry = ManagementLogEntry {
            timestamp: Utc::now(),
            operation: "plugin_install".to_string(),
            resource_type: "plugin".to_string(),
            resource_id: Some("exa".to_string()),
            detail: None,
            success: false,
            error_message: Some("Repository not found".to_string()),
        };
        db.log_management_event(&entry).await.unwrap();

        let logs = db.query_management_log(&crate::types::ManagementLogFilter::default()).await.unwrap();
        assert_eq!(logs.len(), 1);
        let got = &logs[0];
        assert!(!got.success);
        assert_eq!(got.error_message, Some("Repository not found".to_string()));
        assert_eq!(got.detail, None);
    }

    #[tokio::test]
    async fn test_management_log_filter_by_operation() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.log_management_event(&sample_management_entry("token_create", "token")).await.unwrap();
        db.log_management_event(&sample_management_entry("plugin_install", "plugin")).await.unwrap();
        db.log_management_event(&sample_management_entry("token_create", "token")).await.unwrap();

        let filter = crate::types::ManagementLogFilter {
            operation: Some("token_create".to_string()),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 2);
        assert!(logs.iter().all(|e| e.operation == "token_create"));
    }

    #[tokio::test]
    async fn test_management_log_filter_by_resource_type() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.log_management_event(&sample_management_entry("token_create", "token")).await.unwrap();
        db.log_management_event(&sample_management_entry("plugin_install", "plugin")).await.unwrap();
        db.log_management_event(&sample_management_entry("credential_set", "credential")).await.unwrap();

        let filter = crate::types::ManagementLogFilter {
            resource_type: Some("plugin".to_string()),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].operation, "plugin_install");
    }

    #[tokio::test]
    async fn test_management_log_filter_by_success() {
        let db = GapDatabase::in_memory().await.unwrap();

        let mut success_entry = sample_management_entry("token_create", "token");
        success_entry.success = true;
        db.log_management_event(&success_entry).await.unwrap();

        let mut failure_entry = sample_management_entry("plugin_install", "plugin");
        failure_entry.success = false;
        failure_entry.error_message = Some("network error".to_string());
        db.log_management_event(&failure_entry).await.unwrap();

        // Filter for successes only
        let filter = crate::types::ManagementLogFilter {
            success: Some(true),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert!(logs[0].success);
        assert_eq!(logs[0].operation, "token_create");

        // Filter for failures only
        let filter = crate::types::ManagementLogFilter {
            success: Some(false),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert!(!logs[0].success);
        assert_eq!(logs[0].operation, "plugin_install");
    }

    #[tokio::test]
    async fn test_management_log_filter_by_since() {
        let db = GapDatabase::in_memory().await.unwrap();

        let old_time = Utc::now() - Duration::hours(2);
        let cutoff = Utc::now() - Duration::minutes(30);
        let new_time = Utc::now();

        let mut old_entry = sample_management_entry("token_create", "token");
        old_entry.timestamp = old_time;
        db.log_management_event(&old_entry).await.unwrap();

        let mut new_entry = sample_management_entry("plugin_install", "plugin");
        new_entry.timestamp = new_time;
        db.log_management_event(&new_entry).await.unwrap();

        let filter = crate::types::ManagementLogFilter {
            since: Some(cutoff),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].operation, "plugin_install");
    }

    #[tokio::test]
    async fn test_management_log_limit() {
        let db = GapDatabase::in_memory().await.unwrap();

        for i in 0..3 {
            let mut entry = sample_management_entry("token_create", "token");
            entry.timestamp = Utc::now() + Duration::seconds(i);
            db.log_management_event(&entry).await.unwrap();
        }

        let filter = crate::types::ManagementLogFilter {
            limit: Some(2),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 2);
    }

    #[tokio::test]
    async fn test_management_log_empty_query_returns_all() {
        let db = GapDatabase::in_memory().await.unwrap();

        db.log_management_event(&sample_management_entry("token_create", "token")).await.unwrap();
        db.log_management_event(&sample_management_entry("plugin_install", "plugin")).await.unwrap();
        db.log_management_event(&sample_management_entry("credential_set", "credential")).await.unwrap();

        // Default filter with no constraints
        let logs = db.query_management_log(&crate::types::ManagementLogFilter::default()).await.unwrap();
        assert_eq!(logs.len(), 3);
    }

    #[tokio::test]
    async fn test_management_log_filter_by_resource_id() {
        let db = GapDatabase::in_memory().await.unwrap();

        let mut entry_a = sample_management_entry("token_create", "token");
        entry_a.resource_id = Some("tok_aaa".to_string());
        db.log_management_event(&entry_a).await.unwrap();

        let mut entry_b = sample_management_entry("token_delete", "token");
        entry_b.resource_id = Some("tok_bbb".to_string());
        db.log_management_event(&entry_b).await.unwrap();

        let filter = crate::types::ManagementLogFilter {
            resource_id: Some("tok_aaa".to_string()),
            ..Default::default()
        };
        let logs = db.query_management_log(&filter).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].resource_id, Some("tok_aaa".to_string()));
    }

    // ── Header Set CRUD ───────────────────────────────────────────

    #[tokio::test]
    async fn test_header_set_crud() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Create a header set
        db.add_header_set("my-headers", &["api.example.com".to_string()], 10)
            .await
            .unwrap();

        // Get it back
        let hs = db.get_header_set("my-headers").await.unwrap().unwrap();
        assert_eq!(hs.name, "my-headers");
        assert_eq!(hs.match_patterns, vec!["api.example.com".to_string()]);
        assert_eq!(hs.weight, 10);

        // List should contain it
        let all = db.list_header_sets().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].name, "my-headers");

        // Update patterns
        db.update_header_set(
            "my-headers",
            Some(&["api.example.com".to_string(), "*.example.org".to_string()]),
            None,
        )
        .await
        .unwrap();
        let hs = db.get_header_set("my-headers").await.unwrap().unwrap();
        assert_eq!(hs.match_patterns.len(), 2);

        // Update weight
        db.update_header_set("my-headers", None, Some(20))
            .await
            .unwrap();
        let hs = db.get_header_set("my-headers").await.unwrap().unwrap();
        assert_eq!(hs.weight, 20);

        // Soft delete
        db.remove_header_set("my-headers").await.unwrap();
        assert!(db.get_header_set("my-headers").await.unwrap().is_none());
        assert_eq!(db.list_header_sets().await.unwrap().len(), 0);

        // Re-create (upsert revives deleted set)
        db.add_header_set("my-headers", &["new.example.com".to_string()], 5)
            .await
            .unwrap();
        let hs = db.get_header_set("my-headers").await.unwrap().unwrap();
        assert_eq!(hs.match_patterns, vec!["new.example.com".to_string()]);
        assert_eq!(hs.weight, 5);
    }

    #[tokio::test]
    async fn test_header_set_headers() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Create a header set
        db.add_header_set("auth-headers", &["api.example.com".to_string()], 0)
            .await
            .unwrap();

        // Set some headers
        db.set_header_set_header("auth-headers", "Authorization", "Bearer token123")
            .await
            .unwrap();
        db.set_header_set_header("auth-headers", "X-Custom", "value1")
            .await
            .unwrap();

        // Get headers with values
        let headers = db.get_header_set_headers("auth-headers").await.unwrap();
        assert_eq!(headers.len(), 2);
        assert_eq!(headers.get("Authorization").unwrap(), "Bearer token123");
        assert_eq!(headers.get("X-Custom").unwrap(), "value1");

        // List header names
        let names = db
            .list_header_set_header_names("auth-headers")
            .await
            .unwrap();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"Authorization".to_string()));
        assert!(names.contains(&"X-Custom".to_string()));

        // Remove one header
        db.remove_header_set_header("auth-headers", "X-Custom")
            .await
            .unwrap();
        let names = db
            .list_header_set_header_names("auth-headers")
            .await
            .unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "Authorization");

        // Cascade on header set delete: removing the header set should also remove headers
        db.remove_header_set("auth-headers").await.unwrap();
        let headers = db.get_header_set_headers("auth-headers").await.unwrap();
        assert!(headers.is_empty());
    }

    #[tokio::test]
    async fn test_plugin_weight() {
        let db = GapDatabase::in_memory().await.unwrap();

        // Add plugin with default weight=0
        let plugin = sample_plugin("weighted-plugin");
        db.add_plugin(&plugin, "src").await.unwrap();

        let got = db.get_plugin("weighted-plugin").await.unwrap().unwrap();
        assert_eq!(got.weight, 0);

        // Update weight
        db.update_plugin_weight("weighted-plugin", 42).await.unwrap();

        // Verify via list_plugins
        let plugins = db.list_plugins().await.unwrap();
        let p = plugins.iter().find(|p| p.name == "weighted-plugin").unwrap();
        assert_eq!(p.weight, 42);
    }

    #[tokio::test]
    async fn test_plugin_installed_at() {
        let db = GapDatabase::in_memory().await.unwrap();

        let plugin = sample_plugin("timestamped-plugin");
        db.add_plugin(&plugin, "src").await.unwrap();

        let got = db.get_plugin("timestamped-plugin").await.unwrap().unwrap();
        assert!(
            got.installed_at.is_some(),
            "installed_at should be populated from DB"
        );
    }
}
