//! Centralized registry for tokens, plugins, and credentials
//!
//! The registry is the authoritative record of what exists in the system.
//! It's stored as a single JSON document in the SecretStore at key "_registry".
//! This solves the problem of listing items on platforms where enumeration is
//! difficult (e.g., macOS Keychain).
//!
//! The actual values (token strings, plugin code, credential values) are still
//! stored at their individual keys. The registry only tracks metadata.

use crate::{
    storage::SecretStore,
    AcpError, Result,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Token metadata (without the token value, which is used as the hash key)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenMetadata {
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// Token metadata entry in the registry (deprecated - kept for backwards compatibility in tests)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenEntry {
    pub token_value: String,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// Plugin metadata entry in the registry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginEntry {
    pub name: String,
    pub hosts: Vec<String>,
    pub credential_schema: Vec<String>,
}

/// Credential metadata entry in the registry (deprecated - kept for backwards compatibility in tests)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialEntry {
    pub plugin: String,
    pub field: String,
}

/// The complete registry data structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistryData {
    pub version: u32,
    /// Map of token value -> token metadata
    pub tokens: HashMap<String, TokenMetadata>,
    pub plugins: Vec<PluginEntry>,
    /// Map of plugin name -> (field name -> field value)
    pub credentials: HashMap<String, HashMap<String, String>>,
    /// Argon2 hash of the admin password (set during init)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
}

impl Default for RegistryData {
    fn default() -> Self {
        Self {
            version: 1,
            tokens: HashMap::new(),
            plugins: Vec::new(),
            credentials: HashMap::new(),
            password_hash: None,
        }
    }
}

/// Registry manager for centralized metadata storage
///
/// The Registry wraps a SecretStore and provides load/save operations
/// for the registry data. The registry is stored at key "_registry".
pub struct Registry {
    store: Arc<dyn SecretStore>,
}

impl Registry {
    /// Storage key for the registry
    const KEY: &'static str = "_registry";

    /// Create a new Registry with the given store
    pub fn new(store: Arc<dyn SecretStore>) -> Self {
        Self { store }
    }

    /// Load the registry from storage
    ///
    /// Returns an empty RegistryData if the registry doesn't exist yet.
    /// This is not an error - it's the expected state for a fresh installation.
    pub async fn load(&self) -> Result<RegistryData> {
        match self.store.get(Self::KEY).await? {
            Some(bytes) => {
                let data = serde_json::from_slice(&bytes).map_err(|e| {
                    AcpError::storage(format!("Failed to parse registry JSON: {}", e))
                })?;
                Ok(data)
            }
            None => {
                // Registry doesn't exist yet - return empty
                Ok(RegistryData::default())
            }
        }
    }

    /// Save the registry to storage
    ///
    /// Serializes the RegistryData to JSON and stores it at the registry key.
    pub async fn save(&self, data: &RegistryData) -> Result<()> {
        let bytes = serde_json::to_vec(data)
            .map_err(|e| AcpError::storage(format!("Failed to serialize registry: {}", e)))?;
        self.store.set(Self::KEY, &bytes).await
    }

    // Token CRUD operations

    /// Add a token to the registry (deprecated - use add_token_with_metadata)
    ///
    /// Loads the registry, adds the token to the tokens map, and saves.
    pub async fn add_token(&self, token: &TokenEntry) -> Result<()> {
        let metadata = TokenMetadata {
            name: token.name.clone(),
            created_at: token.created_at,
        };
        self.add_token_with_metadata(&token.token_value, &metadata).await
    }

    /// Add a token to the registry with metadata
    ///
    /// Loads the registry, adds the token to the tokens map, and saves.
    pub async fn add_token_with_metadata(&self, token_value: &str, metadata: &TokenMetadata) -> Result<()> {
        let mut data = self.load().await?;
        data.tokens.insert(token_value.to_string(), metadata.clone());
        self.save(&data).await
    }

    /// Remove a token from the registry by token value
    ///
    /// Loads the registry, removes the token with matching token_value, and saves.
    pub async fn remove_token(&self, token_value: &str) -> Result<()> {
        let mut data = self.load().await?;
        data.tokens.remove(token_value);
        self.save(&data).await
    }

    /// Get a token from the registry by token value (O(1) lookup)
    ///
    /// Returns the token metadata if found, None otherwise.
    pub async fn get_token(&self, token_value: &str) -> Result<Option<TokenMetadata>> {
        let data = self.load().await?;
        Ok(data.tokens.get(token_value).cloned())
    }

    /// List all tokens in the registry
    ///
    /// Returns the tokens vec from the loaded registry (converted from HashMap for backwards compatibility).
    pub async fn list_tokens(&self) -> Result<Vec<TokenEntry>> {
        let data = self.load().await?;
        let tokens = data.tokens.iter().map(|(token_value, metadata)| {
            TokenEntry {
                token_value: token_value.clone(),
                name: metadata.name.clone(),
                created_at: metadata.created_at,
            }
        }).collect();
        Ok(tokens)
    }

    // Plugin CRUD operations

    /// Add a plugin to the registry
    ///
    /// Loads the registry, adds the plugin to the plugins vec, and saves.
    pub async fn add_plugin(&self, plugin: &PluginEntry) -> Result<()> {
        let mut data = self.load().await?;
        data.plugins.push(plugin.clone());
        self.save(&data).await
    }

    /// Remove a plugin from the registry by name
    ///
    /// Loads the registry, removes the plugin with matching name, and saves.
    pub async fn remove_plugin(&self, name: &str) -> Result<()> {
        let mut data = self.load().await?;
        data.plugins.retain(|p| p.name != name);
        self.save(&data).await
    }

    /// List all plugins in the registry
    ///
    /// Returns the plugins vec from the loaded registry.
    pub async fn list_plugins(&self) -> Result<Vec<PluginEntry>> {
        let data = self.load().await?;
        Ok(data.plugins)
    }

    // Credential CRUD operations

    /// Add a credential to the registry (deprecated - use set_credential)
    ///
    /// Loads the registry, adds the credential to the credentials map, and saves.
    pub async fn add_credential(&self, credential: &CredentialEntry) -> Result<()> {
        // This is a metadata-only operation, so we can't set an actual value
        // For backwards compatibility, just ensure the plugin entry exists
        let mut data = self.load().await?;
        data.credentials.entry(credential.plugin.clone())
            .or_insert_with(HashMap::new);
        self.save(&data).await
    }

    /// Set a credential value in the registry
    ///
    /// Loads the registry, sets the credential value in the nested map, and saves.
    pub async fn set_credential(&self, plugin: &str, field: &str, value: &str) -> Result<()> {
        let mut data = self.load().await?;
        data.credentials
            .entry(plugin.to_string())
            .or_insert_with(HashMap::new)
            .insert(field.to_string(), value.to_string());
        self.save(&data).await
    }

    /// Remove a credential from the registry by plugin and field
    ///
    /// Loads the registry, removes the credential with matching plugin and field, and saves.
    pub async fn remove_credential(&self, plugin: &str, field: &str) -> Result<()> {
        let mut data = self.load().await?;
        if let Some(plugin_creds) = data.credentials.get_mut(plugin) {
            plugin_creds.remove(field);
            // Remove the plugin entry if it has no more credentials
            if plugin_creds.is_empty() {
                data.credentials.remove(plugin);
            }
        }
        self.save(&data).await
    }

    /// Get a credential value from the registry
    ///
    /// Returns the credential value if found, None otherwise.
    pub async fn get_credential(&self, plugin: &str, field: &str) -> Result<Option<String>> {
        let data = self.load().await?;
        Ok(data.credentials
            .get(plugin)
            .and_then(|fields| fields.get(field))
            .cloned())
    }

    /// Get all credentials for a plugin
    ///
    /// Returns a map of field name -> field value for the plugin, or None if plugin not found.
    pub async fn get_plugin_credentials(&self, plugin: &str) -> Result<Option<HashMap<String, String>>> {
        let data = self.load().await?;
        Ok(data.credentials.get(plugin).cloned())
    }

    /// List all credentials in the registry
    ///
    /// Returns the credentials vec from the loaded registry (converted from HashMap for backwards compatibility).
    pub async fn list_credentials(&self) -> Result<Vec<CredentialEntry>> {
        let data = self.load().await?;
        let mut creds = Vec::new();
        for (plugin, fields) in data.credentials.iter() {
            for field in fields.keys() {
                creds.push(CredentialEntry {
                    plugin: plugin.clone(),
                    field: field.clone(),
                });
            }
        }
        Ok(creds)
    }

    // Password hash operations

    /// Set the password hash in the registry
    ///
    /// Loads the registry, sets the password_hash field, and saves.
    pub async fn set_password_hash(&self, hash: &str) -> Result<()> {
        let mut data = self.load().await?;
        data.password_hash = Some(hash.to_string());
        self.save(&data).await
    }

    /// Get the password hash from the registry
    ///
    /// Returns None if no password has been set (server not initialized).
    pub async fn get_password_hash(&self) -> Result<Option<String>> {
        let data = self.load().await?;
        Ok(data.password_hash)
    }

    /// Check if the server has been initialized (password hash is set)
    pub async fn is_initialized(&self) -> Result<bool> {
        let data = self.load().await?;
        Ok(data.password_hash.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_data_serialization() {
        use std::collections::HashMap;

        let mut tokens = HashMap::new();
        tokens.insert(
            "acp_abc123".to_string(),
            TokenMetadata {
                name: "test-token".to_string(),
                created_at: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        );

        let mut credentials = HashMap::new();
        let mut exa_creds = HashMap::new();
        exa_creds.insert("api_key".to_string(), "test-value".to_string());
        credentials.insert("exa".to_string(), exa_creds);

        let data = RegistryData {
            version: 1,
            tokens,
            plugins: vec![PluginEntry {
                name: "exa".to_string(),
                hosts: vec!["api.exa.ai".to_string()],
                credential_schema: vec!["api_key".to_string()],
            }],
            credentials,
            password_hash: Some("argon2hash123".to_string()),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&data).expect("serialization should succeed");
        assert!(json.contains("\"version\":1"));
        assert!(json.contains("\"acp_abc123\""));
        assert!(json.contains("\"name\":\"exa\""));

        // Deserialize back
        let parsed: RegistryData =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.tokens.len(), 1);
        assert_eq!(parsed.tokens.get("acp_abc123").unwrap().name, "test-token");
        assert_eq!(parsed.plugins.len(), 1);
        assert_eq!(parsed.plugins[0].name, "exa");
        assert_eq!(parsed.credentials.len(), 1);
        assert_eq!(parsed.credentials.get("exa").unwrap().get("api_key").unwrap(), "test-value");
    }

    #[test]
    fn test_registry_data_empty() {
        let data = RegistryData::default();

        assert_eq!(data.version, 1);
        assert_eq!(data.tokens.len(), 0);
        assert_eq!(data.plugins.len(), 0);
        assert_eq!(data.credentials.len(), 0);

        // Should serialize/deserialize empty structures
        let json = serde_json::to_string(&data).expect("serialization should succeed");
        let parsed: RegistryData =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(parsed.version, 1);
    }

    #[test]
    fn test_token_entry_fields() {
        let token = TokenEntry {
            token_value: "acp_test123".to_string(),
            name: "my-agent".to_string(),
            created_at: Utc::now(),
        };

        assert_eq!(token.token_value, "acp_test123");
        assert_eq!(token.name, "my-agent");
    }

    #[test]
    fn test_plugin_entry_fields() {
        let plugin = PluginEntry {
            name: "aws-s3".to_string(),
            hosts: vec!["*.s3.amazonaws.com".to_string()],
            credential_schema: vec!["access_key".to_string(), "secret_key".to_string()],
        };

        assert_eq!(plugin.name, "aws-s3");
        assert_eq!(plugin.hosts.len(), 1);
        assert_eq!(plugin.credential_schema.len(), 2);
    }

    #[test]
    fn test_credential_entry_fields() {
        let cred = CredentialEntry {
            plugin: "exa".to_string(),
            field: "api_key".to_string(),
        };

        assert_eq!(cred.plugin, "exa");
        assert_eq!(cred.field, "api_key");
    }

    #[tokio::test]
    async fn test_registry_load_empty() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // Load when no registry exists yet - should return empty RegistryData
        let data = registry.load().await.expect("load should succeed");
        assert_eq!(data.version, 1);
        assert_eq!(data.tokens.len(), 0);
        assert_eq!(data.plugins.len(), 0);
        assert_eq!(data.credentials.len(), 0);
    }

    #[tokio::test]
    async fn test_registry_save_and_load() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // Create test data
        let mut tokens = HashMap::new();
        tokens.insert(
            "acp_test123".to_string(),
            TokenMetadata {
                name: "test-token".to_string(),
                created_at: Utc::now(),
            }
        );

        let mut credentials = HashMap::new();
        let mut exa_creds = HashMap::new();
        exa_creds.insert("api_key".to_string(), "secret".to_string());
        credentials.insert("exa".to_string(), exa_creds);

        let data = RegistryData {
            version: 1,
            tokens,
            plugins: vec![PluginEntry {
                name: "exa".to_string(),
                hosts: vec!["api.exa.ai".to_string()],
                credential_schema: vec!["api_key".to_string()],
            }],
            credentials,
            password_hash: None,
        };

        // Save
        registry
            .save(&data)
            .await
            .expect("save should succeed");

        // Load back
        let loaded = registry.load().await.expect("load should succeed");
        assert_eq!(loaded.version, data.version);
        assert_eq!(loaded.tokens.len(), 1);
        assert_eq!(loaded.tokens.get("acp_test123").unwrap().name, "test-token");
        assert_eq!(loaded.plugins.len(), 1);
        assert_eq!(loaded.plugins[0].name, "exa");
        assert_eq!(loaded.credentials.len(), 1);
        assert_eq!(loaded.credentials.get("exa").unwrap().get("api_key").unwrap(), "secret");
    }

    #[tokio::test]
    async fn test_registry_overwrite() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // Save initial data
        let mut tokens1 = HashMap::new();
        tokens1.insert(
            "acp_token1".to_string(),
            TokenMetadata {
                name: "first".to_string(),
                created_at: Utc::now(),
            }
        );

        let data1 = RegistryData {
            version: 1,
            tokens: tokens1,
            plugins: vec![],
            credentials: HashMap::new(),
            password_hash: None,
        };
        registry.save(&data1).await.expect("save should succeed");

        // Overwrite with new data
        let mut tokens2 = HashMap::new();
        tokens2.insert(
            "acp_token1".to_string(),
            TokenMetadata {
                name: "first".to_string(),
                created_at: Utc::now(),
            }
        );
        tokens2.insert(
            "acp_token2".to_string(),
            TokenMetadata {
                name: "second".to_string(),
                created_at: Utc::now(),
            }
        );

        let data2 = RegistryData {
            version: 1,
            tokens: tokens2,
            plugins: vec![],
            credentials: HashMap::new(),
            password_hash: None,
        };
        registry.save(&data2).await.expect("save should succeed");

        // Load and verify it was overwritten
        let loaded = registry.load().await.expect("load should succeed");
        assert_eq!(loaded.tokens.len(), 2);
        assert!(loaded.tokens.contains_key("acp_token2"));
        assert_eq!(loaded.tokens.get("acp_token2").unwrap().name, "second");
    }

    #[tokio::test]
    async fn test_registry_uses_correct_key() {
        use crate::storage::{FileStore, SecretStore};
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = Arc::new(
            FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore"),
        );
        let registry = Registry::new(store.clone());

        // Save some data
        let data = RegistryData::default();
        registry.save(&data).await.expect("save should succeed");

        // Verify it was stored at the correct key
        let raw_value = store
            .get("_registry")
            .await
            .expect("get should succeed")
            .expect("value should exist");

        // Verify it's valid JSON
        let parsed: RegistryData =
            serde_json::from_slice(&raw_value).expect("should deserialize");
        assert_eq!(parsed.version, 1);
    }

    // RED: Tests for token CRUD operations
    #[tokio::test]
    async fn test_add_token() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        let token = TokenEntry {
            token_value: "acp_abc123".to_string(),
            name: "test-token".to_string(),
            created_at: Utc::now(),
        };

        // Add token should succeed
        registry.add_token(&token).await.expect("add should succeed");

        // Verify token is in registry
        let tokens = registry.list_tokens().await.expect("list should succeed");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_value, "acp_abc123");
        assert_eq!(tokens[0].name, "test-token");
    }

    #[tokio::test]
    async fn test_remove_token() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // Add two tokens
        let token1 = TokenEntry {
            token_value: "acp_abc123".to_string(),
            name: "token1".to_string(),
            created_at: Utc::now(),
        };
        let token2 = TokenEntry {
            token_value: "acp_def456".to_string(),
            name: "token2".to_string(),
            created_at: Utc::now(),
        };
        registry.add_token(&token1).await.expect("add should succeed");
        registry.add_token(&token2).await.expect("add should succeed");

        // Remove first token by value
        registry
            .remove_token("acp_abc123")
            .await
            .expect("remove should succeed");

        // Verify only second token remains
        let tokens = registry.list_tokens().await.expect("list should succeed");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_value, "acp_def456");
    }

    #[tokio::test]
    async fn test_list_tokens() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // List should return empty on fresh registry
        let tokens = registry.list_tokens().await.expect("list should succeed");
        assert_eq!(tokens.len(), 0);

        // Add tokens
        let token1 = TokenEntry {
            token_value: "acp_abc123".to_string(),
            name: "token1".to_string(),
            created_at: Utc::now(),
        };
        let token2 = TokenEntry {
            token_value: "acp_def456".to_string(),
            name: "token2".to_string(),
            created_at: Utc::now(),
        };
        registry.add_token(&token1).await.expect("add should succeed");
        registry.add_token(&token2).await.expect("add should succeed");

        // List should return both
        let tokens = registry.list_tokens().await.expect("list should succeed");
        assert_eq!(tokens.len(), 2);
    }

    // RED: Tests for plugin CRUD operations
    #[tokio::test]
    async fn test_add_plugin() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        let plugin = PluginEntry {
            name: "exa".to_string(),
            hosts: vec!["api.exa.ai".to_string()],
            credential_schema: vec!["api_key".to_string()],
        };

        // Add plugin should succeed
        registry
            .add_plugin(&plugin)
            .await
            .expect("add should succeed");

        // Verify plugin is in registry
        let plugins = registry.list_plugins().await.expect("list should succeed");
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "exa");
        assert_eq!(plugins[0].hosts, vec!["api.exa.ai"]);
    }

    #[tokio::test]
    async fn test_remove_plugin() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // Add two plugins
        let plugin1 = PluginEntry {
            name: "exa".to_string(),
            hosts: vec!["api.exa.ai".to_string()],
            credential_schema: vec!["api_key".to_string()],
        };
        let plugin2 = PluginEntry {
            name: "github".to_string(),
            hosts: vec!["api.github.com".to_string()],
            credential_schema: vec!["token".to_string()],
        };
        registry
            .add_plugin(&plugin1)
            .await
            .expect("add should succeed");
        registry
            .add_plugin(&plugin2)
            .await
            .expect("add should succeed");

        // Remove first plugin
        registry
            .remove_plugin("exa")
            .await
            .expect("remove should succeed");

        // Verify only second plugin remains
        let plugins = registry.list_plugins().await.expect("list should succeed");
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "github");
    }

    #[tokio::test]
    async fn test_list_plugins() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // List should return empty on fresh registry
        let plugins = registry.list_plugins().await.expect("list should succeed");
        assert_eq!(plugins.len(), 0);

        // Add plugins
        let plugin1 = PluginEntry {
            name: "exa".to_string(),
            hosts: vec!["api.exa.ai".to_string()],
            credential_schema: vec!["api_key".to_string()],
        };
        let plugin2 = PluginEntry {
            name: "github".to_string(),
            hosts: vec!["api.github.com".to_string()],
            credential_schema: vec!["token".to_string()],
        };
        registry
            .add_plugin(&plugin1)
            .await
            .expect("add should succeed");
        registry
            .add_plugin(&plugin2)
            .await
            .expect("add should succeed");

        // List should return both
        let plugins = registry.list_plugins().await.expect("list should succeed");
        assert_eq!(plugins.len(), 2);
    }

    // RED: Tests for credential CRUD operations
    #[tokio::test]
    async fn test_add_credential() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // Set credential with actual value
        registry
            .set_credential("exa", "api_key", "test-value")
            .await
            .expect("set should succeed");

        // Verify credential is in registry
        let creds = registry
            .list_credentials()
            .await
            .expect("list should succeed");
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].plugin, "exa");
        assert_eq!(creds[0].field, "api_key");
    }

    #[tokio::test]
    async fn test_remove_credential() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // Set credentials with actual values
        registry
            .set_credential("exa", "api_key", "key-value")
            .await
            .expect("set should succeed");
        registry
            .set_credential("exa", "secret", "secret-value")
            .await
            .expect("set should succeed");
        registry
            .set_credential("github", "token", "token-value")
            .await
            .expect("set should succeed");

        // Remove exa api_key credential
        registry
            .remove_credential("exa", "api_key")
            .await
            .expect("remove should succeed");

        // Verify only exa/secret and github/token remain
        let creds = registry
            .list_credentials()
            .await
            .expect("list should succeed");
        assert_eq!(creds.len(), 2);
        assert!(creds.iter().any(|c| c.plugin == "exa" && c.field == "secret"));
        assert!(creds.iter().any(|c| c.plugin == "github" && c.field == "token"));
        assert!(!creds
            .iter()
            .any(|c| c.plugin == "exa" && c.field == "api_key"));
    }

    #[tokio::test]
    async fn test_list_credentials() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // List should return empty on fresh registry
        let creds = registry
            .list_credentials()
            .await
            .expect("list should succeed");
        assert_eq!(creds.len(), 0);

        // Set credentials with actual values
        registry
            .set_credential("exa", "api_key", "key-value")
            .await
            .expect("set should succeed");
        registry
            .set_credential("github", "token", "token-value")
            .await
            .expect("set should succeed");

        // List should return both
        let creds = registry
            .list_credentials()
            .await
            .expect("list should succeed");
        assert_eq!(creds.len(), 2);
    }

    // RED: Test that token value IS the ID (no separate id field)
    #[tokio::test]
    async fn test_token_entry_uses_value_as_key() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        let token = TokenEntry {
            token_value: "acp_test123".to_string(),
            name: "test-token".to_string(),
            created_at: Utc::now(),
        };

        // Add token
        registry.add_token(&token).await.expect("add should succeed");

        // Verify token is in registry
        let tokens = registry.list_tokens().await.expect("list should succeed");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_value, "acp_test123");
        assert_eq!(tokens[0].name, "test-token");
    }

    // RED: Test that remove_token works with value as key
    #[tokio::test]
    async fn test_remove_token_by_value() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // Add token
        let token = TokenEntry {
            token_value: "acp_test123".to_string(),
            name: "test-token".to_string(),
            created_at: Utc::now(),
        };
        registry.add_token(&token).await.expect("add should succeed");

        // Remove by value
        registry
            .remove_token("acp_test123")
            .await
            .expect("remove should succeed");

        // Verify token is gone
        let tokens = registry.list_tokens().await.expect("list should succeed");
        assert_eq!(tokens.len(), 0);
    }

    // RED: Test for new TokenMetadata struct (token_value becomes hash key)
    #[test]
    fn test_token_metadata_struct() {
        let metadata = TokenMetadata {
            name: "test-agent".to_string(),
            created_at: Utc::now(),
        };

        assert_eq!(metadata.name, "test-agent");
    }

    // RED: Test for HashMap-based tokens in RegistryData
    #[test]
    fn test_registry_data_with_hashmap_tokens() {
        use std::collections::HashMap;

        let mut tokens = HashMap::new();
        tokens.insert(
            "acp_abc123".to_string(),
            TokenMetadata {
                name: "test-token".to_string(),
                created_at: DateTime::parse_from_rfc3339("2024-01-15T10:30:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            }
        );

        let data = RegistryData {
            version: 1,
            tokens,
            plugins: vec![],
            credentials: HashMap::new(),
            password_hash: None,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&data).expect("serialization should succeed");
        assert!(json.contains("\"acp_abc123\""));
        assert!(json.contains("\"test-token\""));

        // Deserialize back
        let parsed: RegistryData =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.tokens.len(), 1);
        assert_eq!(parsed.tokens.get("acp_abc123").unwrap().name, "test-token");
    }

    // RED: Test for HashMap-based credentials in RegistryData
    #[test]
    fn test_registry_data_with_hashmap_credentials() {
        use std::collections::HashMap;

        let mut credentials = HashMap::new();
        let mut exa_creds = HashMap::new();
        exa_creds.insert("api_key".to_string(), "secret-value".to_string());
        credentials.insert("exa".to_string(), exa_creds);

        let data = RegistryData {
            version: 1,
            tokens: HashMap::new(),
            plugins: vec![],
            credentials,
            password_hash: None,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&data).expect("serialization should succeed");
        assert!(json.contains("\"exa\""));
        assert!(json.contains("\"api_key\""));
        assert!(json.contains("\"secret-value\""));

        // Deserialize back
        let parsed: RegistryData =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.credentials.len(), 1);
        assert_eq!(parsed.credentials.get("exa").unwrap().get("api_key").unwrap(), "secret-value");
    }

    // RED: Test for get_token O(1) lookup
    #[tokio::test]
    async fn test_get_token_lookup() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // Add a token
        let metadata = TokenMetadata {
            name: "test-agent".to_string(),
            created_at: Utc::now(),
        };
        registry.add_token_with_metadata("acp_abc123", &metadata)
            .await
            .expect("add should succeed");

        // Get token by value - should be O(1) lookup
        let result = registry.get_token("acp_abc123")
            .await
            .expect("get should succeed");
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "test-agent");

        // Get non-existent token
        let result = registry.get_token("acp_nonexistent")
            .await
            .expect("get should succeed");
        assert!(result.is_none());
    }

    // RED: Test for get_credential lookup
    #[tokio::test]
    async fn test_get_credential() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // Set a credential
        registry.set_credential("exa", "api_key", "secret-value")
            .await
            .expect("set should succeed");

        // Get credential
        let result = registry.get_credential("exa", "api_key")
            .await
            .expect("get should succeed");
        assert_eq!(result, Some("secret-value".to_string()));

        // Get non-existent credential
        let result = registry.get_credential("exa", "nonexistent")
            .await
            .expect("get should succeed");
        assert_eq!(result, None);
    }

    // RED: Test for get_plugin_credentials (all creds for a plugin)
    #[tokio::test]
    async fn test_get_plugin_credentials() {
        use crate::storage::FileStore;
        use std::sync::Arc;

        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let registry = Registry::new(Arc::new(store));

        // Set multiple credentials for a plugin
        registry.set_credential("exa", "api_key", "key-value")
            .await
            .expect("set should succeed");
        registry.set_credential("exa", "secret", "secret-value")
            .await
            .expect("set should succeed");

        // Get all credentials for the plugin
        let result = registry.get_plugin_credentials("exa")
            .await
            .expect("get should succeed");
        assert!(result.is_some());
        let creds = result.unwrap();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds.get("api_key").unwrap(), "key-value");
        assert_eq!(creds.get("secret").unwrap(), "secret-value");

        // Get credentials for non-existent plugin
        let result = registry.get_plugin_credentials("nonexistent")
            .await
            .expect("get should succeed");
        assert!(result.is_none());
    }
}
