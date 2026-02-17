//! Embedded libSQL database for GAP persistent storage
//!
//! Provides an async database layer backed by libSQL (a SQLite fork) for
//! storing tokens, plugins, credentials, config, and activity logs.

use crate::error::{GapError, Result};
use crate::types::{CredentialEntry, PluginEntry, TokenEntry, TokenMetadata};
use crate::types::ActivityEntry;
use chrono::{DateTime, Utc};
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

CREATE TABLE IF NOT EXISTS plugins (
    name TEXT PRIMARY KEY,
    hosts TEXT NOT NULL,
    credential_schema TEXT NOT NULL,
    commit_sha TEXT,
    source_code TEXT NOT NULL
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
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    agent_id TEXT,
    status INTEGER NOT NULL,
    plugin_name TEXT,
    plugin_sha TEXT
);

CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_access_logs_url ON access_logs(url);
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

    /// Add (or replace) a plugin and its source code.
    pub async fn add_plugin(&self, plugin: &PluginEntry, source_code: &str) -> Result<()> {
        let hosts_json =
            serde_json::to_string(&plugin.hosts).map_err(|e| GapError::database(e.to_string()))?;
        let schema_json = serde_json::to_string(&plugin.credential_schema)
            .map_err(|e| GapError::database(e.to_string()))?;

        self.conn
            .execute(
                "INSERT OR REPLACE INTO plugins (name, hosts, credential_schema, commit_sha, source_code) VALUES (?1, ?2, ?3, ?4, ?5)",
                libsql::params![
                    plugin.name.as_str(),
                    hosts_json,
                    schema_json,
                    plugin.commit_sha.as_deref().unwrap_or(""),
                    source_code
                ],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
    }

    /// Get a plugin entry by name (without source code).
    pub async fn get_plugin(&self, name: &str) -> Result<Option<PluginEntry>> {
        let mut rows = self
            .conn
            .query(
                "SELECT name, hosts, credential_schema, commit_sha FROM plugins WHERE name = ?1",
                libsql::params![name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            Ok(Some(self.row_to_plugin_entry(&row)?))
        } else {
            Ok(None)
        }
    }

    /// Get only the source code for a plugin.
    pub async fn get_plugin_source(&self, name: &str) -> Result<Option<String>> {
        let mut rows = self
            .conn
            .query(
                "SELECT source_code FROM plugins WHERE name = ?1",
                libsql::params![name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;

        if let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let source: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            Ok(Some(source))
        } else {
            Ok(None)
        }
    }

    /// List all plugins (without source code).
    pub async fn list_plugins(&self) -> Result<Vec<PluginEntry>> {
        let mut rows = self
            .conn
            .query(
                "SELECT name, hosts, credential_schema, commit_sha FROM plugins",
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

    /// Remove a plugin by name. Does NOT delete credentials (preserves across reinstalls).
    pub async fn remove_plugin(&self, name: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM plugins WHERE name = ?1",
                libsql::params![name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        Ok(())
    }

    /// Check whether a plugin exists.
    pub async fn has_plugin(&self, name: &str) -> Result<bool> {
        let mut rows = self
            .conn
            .query(
                "SELECT 1 FROM plugins WHERE name = ?1",
                libsql::params![name],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        let exists = rows
            .next()
            .await
            .map_err(|e| GapError::database(e.to_string()))?
            .is_some();
        Ok(exists)
    }

    /// Parse a `Row` (name, hosts, credential_schema, commit_sha) into a `PluginEntry`.
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
                "INSERT INTO access_logs (timestamp, method, url, agent_id, status, plugin_name, plugin_sha) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                libsql::params![
                    entry.timestamp.to_rfc3339(),
                    entry.method.as_str(),
                    entry.url.as_str(),
                    entry.agent_id.as_deref().unwrap_or(""),
                    entry.status as i64,
                    entry.plugin_name.as_deref().unwrap_or(""),
                    entry.plugin_sha.as_deref().unwrap_or("")
                ],
            )
            .await
            .map_err(|e| GapError::database(format!("Failed to log activity: {}", e)))?;
        Ok(())
    }

    /// Get recent activity, ordered newest-first.
    pub async fn get_activity(&self, limit: Option<u32>) -> Result<Vec<ActivityEntry>> {
        let query = match limit {
            Some(n) => format!(
                "SELECT timestamp, method, url, agent_id, status, plugin_name, plugin_sha FROM access_logs ORDER BY timestamp DESC LIMIT {}",
                n
            ),
            None => "SELECT timestamp, method, url, agent_id, status, plugin_name, plugin_sha FROM access_logs ORDER BY timestamp DESC".to_string(),
        };
        let mut rows = self
            .conn
            .query(&query, ())
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        self.rows_to_activity(&mut rows).await
    }

    /// Get activity entries since a given timestamp, newest-first.
    pub async fn get_activity_since(&self, since: DateTime<Utc>) -> Result<Vec<ActivityEntry>> {
        let mut rows = self
            .conn
            .query(
                "SELECT timestamp, method, url, agent_id, status, plugin_name, plugin_sha FROM access_logs WHERE timestamp >= ?1 ORDER BY timestamp DESC",
                libsql::params![since.to_rfc3339()],
            )
            .await
            .map_err(|e| GapError::database(e.to_string()))?;
        self.rows_to_activity(&mut rows).await
    }

    /// Helper: convert activity rows into `Vec<ActivityEntry>`.
    async fn rows_to_activity(&self, rows: &mut libsql::Rows) -> Result<Vec<ActivityEntry>> {
        let mut result = Vec::new();
        while let Some(row) = rows.next().await.map_err(|e| GapError::database(e.to_string()))? {
            let ts_str: String = row.get(0).map_err(|e| GapError::database(e.to_string()))?;
            let method: String = row.get(1).map_err(|e| GapError::database(e.to_string()))?;
            let url: String = row.get(2).map_err(|e| GapError::database(e.to_string()))?;
            let agent_id_raw: String =
                row.get(3).map_err(|e| GapError::database(e.to_string()))?;
            let status_i64: i64 = row.get(4).map_err(|e| GapError::database(e.to_string()))?;
            let plugin_name_raw: String =
                row.get(5).map_err(|e| GapError::database(e.to_string()))?;
            let plugin_sha_raw: String =
                row.get(6).map_err(|e| GapError::database(e.to_string()))?;

            let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                .map_err(|e| GapError::database(format!("Invalid timestamp: {}", e)))?
                .with_timezone(&Utc);
            let agent_id = if agent_id_raw.is_empty() {
                None
            } else {
                Some(agent_id_raw)
            };
            let plugin_name = if plugin_name_raw.is_empty() {
                None
            } else {
                Some(plugin_name_raw)
            };
            let plugin_sha = if plugin_sha_raw.is_empty() {
                None
            } else {
                Some(plugin_sha_raw)
            };

            result.push(ActivityEntry {
                timestamp,
                method,
                url,
                agent_id,
                status: status_i64 as u16,
                plugin_name,
                plugin_sha,
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
            method: "GET".to_string(),
            url: "https://api.example.com/users".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_name: None,
            plugin_sha: None,
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
                method: "GET".to_string(),
                url: format!("https://api.example.com/{}", i),
                agent_id: None,
                status: 200,
                plugin_name: None,
                plugin_sha: None,
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
            method: "GET".to_string(),
            url: "https://old.example.com".to_string(),
            agent_id: None,
            status: 200,
            plugin_name: None,
            plugin_sha: None,
        })
        .await
        .unwrap();

        // Recent entry
        db.log_activity(&ActivityEntry {
            timestamp: now,
            method: "POST".to_string(),
            url: "https://new.example.com".to_string(),
            agent_id: Some("agent-2".to_string()),
            status: 201,
            plugin_name: None,
            plugin_sha: None,
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
            method: "DELETE".to_string(),
            url: "https://api.example.com/resource".to_string(),
            agent_id: None,
            status: 204,
            plugin_name: None,
            plugin_sha: None,
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
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: Some("agent-1".to_string()),
            status: 200,
            plugin_name: Some("exa".to_string()),
            plugin_sha: Some("abc1234".to_string()),
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
            method: "GET".to_string(),
            url: "https://api.example.com/data".to_string(),
            agent_id: None,
            status: 200,
            plugin_name: None,
            plugin_sha: None,
        };
        db.log_activity(&entry).await.unwrap();

        let logs = db.get_activity(None).await.unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].plugin_name, None);
        assert_eq!(logs[0].plugin_sha, None);
    }
}
