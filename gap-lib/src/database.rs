//! Embedded libSQL database for GAP persistent storage
//!
//! Provides an async database layer backed by libSQL (a SQLite fork) for
//! storing tokens, plugins, credentials, config, and activity logs.

use crate::error::{GapError, Result};
use crate::types::{CredentialEntry, PluginEntry, PluginVersion, TokenEntry, TokenMetadata};
use crate::types::ActivityEntry;
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
        let db = libsql::Builder::new_local(path)
            .encryption_config(libsql::EncryptionConfig::new(
                libsql::Cipher::Aes256Cbc,
                bytes::Bytes::copy_from_slice(encryption_key),
            ))
            .build()
            .await
            .map_err(|e| GapError::database(format!("Failed to open encrypted database: {}", e)))?;
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
        let db = libsql::Builder::new_local(path)
            .build()
            .await
            .map_err(|e| GapError::database(format!("Failed to open database: {}", e)))?;
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
        self.conn
            .execute_batch(SCHEMA)
            .await
            .map_err(|e| GapError::database(format!("Failed to run migrations: {}", e)))?;

        // Migration for existing DBs — ignore error if columns already exist
        let _ = self.conn.execute("ALTER TABLE access_logs ADD COLUMN plugin_name TEXT", ()).await;
        let _ = self.conn.execute("ALTER TABLE access_logs ADD COLUMN plugin_sha TEXT", ()).await;
        let _ = self.conn.execute("ALTER TABLE access_logs ADD COLUMN source_hash TEXT", ()).await;
        let _ = self.conn.execute("ALTER TABLE access_logs ADD COLUMN request_headers TEXT", ()).await;
        let _ = self.conn.execute("ALTER TABLE access_logs ADD COLUMN request_id TEXT", ()).await;

        // Migrate plugin_versions for append-only plugin storage
        let _ = self.conn.execute("ALTER TABLE plugin_versions ADD COLUMN hosts TEXT NOT NULL DEFAULT '[]'", ()).await;
        let _ = self.conn.execute("ALTER TABLE plugin_versions ADD COLUMN credential_schema TEXT NOT NULL DEFAULT '[]'", ()).await;
        let _ = self.conn.execute("ALTER TABLE plugin_versions ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0", ()).await;

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

        self.conn
            .execute(
                "INSERT INTO plugin_versions (plugin_name, hosts, credential_schema, commit_sha, source_hash, source_code, installed_at, deleted) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                libsql::params![
                    plugin.name.as_str(),
                    hosts_json,
                    schema_json,
                    plugin.commit_sha.as_deref().unwrap_or(""),
                    source_hash,
                    source_code,
                    now
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
                "SELECT plugin_name, hosts, credential_schema, commit_sha, deleted FROM plugin_versions WHERE plugin_name = ?1 ORDER BY id DESC LIMIT 1",
                libsql::params![name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let deleted: i64 = row.get(4).map_err(|e| GapError::database(e.to_string()))?;
            if deleted != 0 {
                return Ok(None);
            }
            Ok(Some(self.row_to_plugin_entry(&row)?))
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
                "SELECT pv.plugin_name, pv.hosts, pv.credential_schema, pv.commit_sha \
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
            result.push(self.row_to_plugin_entry(&row)?);
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

    /// Parse a `Row` (plugin_name, hosts, credential_schema, commit_sha) into a `PluginEntry`.
    fn row_to_plugin_entry(&self, row: &libsql::Row) -> Result<PluginEntry> {
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

        Ok(PluginEntry {
            name,
            hosts,
            credential_schema,
            commit_sha,
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
                "INSERT INTO access_logs (timestamp, request_id, method, url, agent_id, status, plugin_name, plugin_sha, source_hash, request_headers) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
                    entry.request_headers.as_deref().unwrap_or("")
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
        let select = "SELECT timestamp, request_id, method, url, agent_id, status, plugin_name, plugin_sha, source_hash, request_headers FROM access_logs";

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
    ///                   plugin_name, plugin_sha, source_hash, request_headers
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
            });
        }
        Ok(result)
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
        };
        db.add_plugin(&plugin_v1, "v1 code").await.unwrap();

        let plugin_v2 = PluginEntry {
            name: "exa".to_string(),
            hosts: vec!["api.exa.ai".to_string(), "new.exa.ai".to_string()],
            credential_schema: vec!["api_key".to_string(), "secret".to_string()],
            commit_sha: Some("bbb2222".to_string()),
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
}
