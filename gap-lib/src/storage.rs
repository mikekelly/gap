//! Secure storage abstraction for secrets
//!
//! Provides a trait-based abstraction over platform-specific secret storage
//! mechanisms. Implementations include:
//! - FileStore: File-based storage with proper permissions (all platforms)
//! - KeychainStore: macOS Keychain integration (macOS only)
//!
//! The storage is used to persist:
//! - Plugin credentials (scoped by plugin name)
//! - Agent tokens
//! - CA private keys
//! - Password hashes

use crate::Result;
use async_trait::async_trait;
use std::path::PathBuf;

/// Trait for secure secret storage operations
///
/// All implementations must be async and support binary data.
/// Keys use namespacing with format: `type:name:key`
/// Examples: `credential:aws-s3:access_key`, `token:abc123`, `ca:private_key`
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Store a secret value
    ///
    /// # Arguments
    /// * `key` - Namespaced key (e.g., "credential:plugin:field")
    /// * `value` - Binary secret data
    async fn set(&self, key: &str, value: &[u8]) -> Result<()>;

    /// Retrieve a secret value
    ///
    /// Returns None if the key doesn't exist.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Delete a secret
    ///
    /// Returns Ok(()) even if the key doesn't exist (idempotent).
    async fn delete(&self, key: &str) -> Result<()>;

    /// Downcast to concrete type
    ///
    /// Enables type-specific operations like listing keys on FileStore.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// File-based secret storage implementation
///
/// Stores secrets as individual files in a directory with restrictive permissions.
/// Works on all platforms. Each secret is stored in a file named after its key
/// with directory separators encoded.
pub struct FileStore {
    base_path: PathBuf,
}

impl FileStore {
    /// Create a new FileStore at the given path
    ///
    /// The directory will be created if it doesn't exist, with mode 0700.
    pub async fn new(base_path: PathBuf) -> Result<Self> {
        tokio::fs::create_dir_all(&base_path).await?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&base_path, perms)?;
        }

        Ok(Self { base_path })
    }

    /// Convert a key to a safe filename using base64url encoding
    fn key_to_filename(&self, key: &str) -> PathBuf {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let encoded = URL_SAFE_NO_PAD.encode(key.as_bytes());
        self.base_path.join(encoded)
    }
}

#[async_trait]
impl SecretStore for FileStore {
    async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let path = self.key_to_filename(key);

        // Write to temp file first, then rename (atomic on Unix)
        let temp_path = path.with_extension("tmp");

        // Write and explicitly sync to ensure data is persisted
        let mut file = tokio::fs::File::create(&temp_path).await?;
        use tokio::io::AsyncWriteExt;
        file.write_all(value).await?;
        file.sync_all().await?;
        drop(file);

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&temp_path, perms)?;
        }

        tokio::fs::rename(&temp_path, &path).await?;

        // Sync directory to ensure rename is persisted
        #[cfg(unix)]
        {
            if let Some(parent) = path.parent() {
                if let Ok(dir) = tokio::fs::File::open(parent).await {
                    let _ = dir.sync_all().await;
                }
            }
        }

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let path = self.key_to_filename(key);

        match tokio::fs::read(&path).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.key_to_filename(key);

        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}


/// macOS Keychain secret storage implementation
///
/// Uses the macOS Keychain to securely store secrets.
/// Only available on macOS.
#[cfg(target_os = "macos")]
pub struct KeychainStore {
    service_name: String,
    access_group: Option<String>,
    use_data_protection: bool,
}

#[cfg(target_os = "macos")]
impl KeychainStore {
    /// Create a new KeychainStore with the given service name
    ///
    /// The service name is used as a namespace for all keychain items.
    /// Uses traditional keychain (with ACLs) by default.
    pub fn new(service_name: impl Into<String>) -> Result<Self> {
        Ok(Self {
            service_name: service_name.into(),
            access_group: None,
            use_data_protection: false,
        })
    }

    /// Create a new KeychainStore with an access group
    ///
    /// The access group allows keychain items to survive binary re-signing.
    /// Must be prefixed with Team ID (e.g., "3R44BTH39W.com.gap.secrets").
    /// Uses traditional keychain (with ACLs) by default.
    pub fn new_with_access_group(
        service_name: impl Into<String>,
        access_group: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            service_name: service_name.into(),
            access_group: Some(access_group.into()),
            use_data_protection: false,
        })
    }

    /// Create a new KeychainStore with Data Protection Keychain enabled
    ///
    /// Data Protection Keychain uses entitlement-based access instead of ACLs,
    /// eliminating password prompts. Requires:
    /// - macOS 10.15 (Catalina) or later
    /// - Properly signed binary with keychain-access-groups entitlement
    /// - Access group must match the entitlement
    ///
    /// This is a breaking change - existing keychain items won't be found.
    pub fn new_with_data_protection(
        service_name: impl Into<String>,
        access_group: impl Into<String>,
    ) -> Result<Self> {
        Ok(Self {
            service_name: service_name.into(),
            access_group: Some(access_group.into()),
            use_data_protection: true,
        })
    }
}

#[cfg(target_os = "macos")]
#[async_trait]
impl SecretStore for KeychainStore {
    async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        crate::keychain_impl::set_generic_password_with_access_group(
            &self.service_name,
            key,
            value,
            self.access_group.as_deref(),
            self.use_data_protection,
        )
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        crate::keychain_impl::get_generic_password_with_access_group(
            &self.service_name,
            key,
            self.access_group.as_deref(),
            self.use_data_protection,
        )
    }

    async fn delete(&self, key: &str) -> Result<()> {
        crate::keychain_impl::delete_generic_password_with_access_group(
            &self.service_name,
            key,
            self.access_group.as_deref(),
            self.use_data_protection,
        )
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Factory function to create the appropriate SecretStore implementation
///
/// On macOS, returns a KeychainStore by default. If `data_dir` is provided,
/// returns a FileStore instead (useful for containers/testing).
///
/// On other platforms, always returns a FileStore.
///
/// # Arguments
/// * `data_dir` - Optional directory for FileStore. If None on macOS, uses Keychain.
///   If None on other platforms, uses a default location.
pub async fn create_store(data_dir: Option<PathBuf>) -> Result<Box<dyn SecretStore>> {
    // Check for GAP_DATA_DIR environment variable first (useful for testing)
    if let Ok(env_path) = std::env::var("GAP_DATA_DIR") {
        let store = FileStore::new(PathBuf::from(env_path)).await?;
        return Ok(Box::new(store));
    }

    match data_dir {
        Some(path) => {
            // Explicit file storage requested
            let store = FileStore::new(path).await?;
            Ok(Box::new(store))
        }
        None => {
            // Platform-specific default
            #[cfg(target_os = "macos")]
            {
                // In test mode, use traditional keychain (Data Protection requires signed binary)
                #[cfg(test)]
                {
                    let service_name = format!("com.gap.test.{}", std::process::id());
                    let store = KeychainStore::new_with_access_group(
                        service_name,
                        "3R44BTH39W.com.gap.secrets",
                    )?;
                    return Ok(Box::new(store));
                }

                // In production, use Data Protection Keychain (no prompts when properly signed)
                // Access group must match application-identifier in entitlements
                #[cfg(not(test))]
                {
                    let service_name = "com.mikekelly.gap-server";
                    let store = KeychainStore::new_with_data_protection(
                        service_name,
                        "3R44BTH39W.com.mikekelly.gap-server",
                    )?;
                    return Ok(Box::new(store));
                }
            }

            #[cfg(not(target_os = "macos"))]
            {
                // Use default location: ~/.gap/secrets
                let home = std::env::var("HOME")
                    .or_else(|_| std::env::var("USERPROFILE"))
                    .map_err(|_| crate::GapError::storage("Cannot determine home directory"))?;
                let path = PathBuf::from(home).join(".gap").join("secrets");
                let store = FileStore::new(path).await?;
                Ok(Box::new(store))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper to verify SecretStore implementation
    async fn test_store_implementation<S: SecretStore>(store: S) {
        // Test set and get
        store
            .set("test:key1", b"value1")
            .await
            .expect("set should succeed");

        let value = store
            .get("test:key1")
            .await
            .expect("get should succeed")
            .expect("value should exist");
        assert_eq!(value, b"value1");

        // Test get non-existent key
        let missing = store
            .get("test:missing")
            .await
            .expect("get should succeed");
        assert!(missing.is_none(), "missing key should return None");

        // Test overwrite
        store
            .set("test:key1", b"value2")
            .await
            .expect("overwrite should succeed");
        let value = store
            .get("test:key1")
            .await
            .expect("get should succeed")
            .expect("value should exist");
        assert_eq!(value, b"value2");

        // Test binary data
        let binary_data = vec![0u8, 1, 2, 255, 128];
        store
            .set("test:binary", &binary_data)
            .await
            .expect("binary set should succeed");
        let retrieved = store
            .get("test:binary")
            .await
            .expect("get should succeed")
            .expect("value should exist");
        assert_eq!(retrieved, binary_data);

        // Test delete
        store
            .delete("test:key1")
            .await
            .expect("delete should succeed");
        let deleted = store
            .get("test:key1")
            .await
            .expect("get should succeed");
        assert!(deleted.is_none(), "deleted key should not exist");

        // Test delete idempotency
        store
            .delete("test:key1")
            .await
            .expect("second delete should succeed");

        // Cleanup
        store.delete("test:binary").await.ok();
    }

    #[tokio::test]
    async fn test_file_store() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");

        test_store_implementation(store).await;
    }

    #[tokio::test]
    async fn test_file_store_permissions() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let temp_dir = tempfile::tempdir().expect("create temp dir");
            let store = FileStore::new(temp_dir.path().to_path_buf())
                .await
                .expect("create FileStore");

            // Check directory permissions
            let metadata = std::fs::metadata(temp_dir.path()).expect("get metadata");
            let mode = metadata.permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "directory should have mode 0700");

            // Write a file and check permissions
            store
                .set("test:perm", b"value")
                .await
                .expect("set should succeed");

            let file_path = store.key_to_filename("test:perm");
            let file_metadata = std::fs::metadata(&file_path).expect("get file metadata");
            let file_mode = file_metadata.permissions().mode();
            assert_eq!(
                file_mode & 0o777,
                0o600,
                "file should have mode 0600"
            );

            store.delete("test:perm").await.ok();
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_keychain_store() {
        // Use a unique service name for testing
        let service_name = format!("com.gap.test.{}", std::process::id());
        let store = KeychainStore::new(&service_name).expect("create KeychainStore");

        // Test basic operations (not list, since KeychainStore.list() returns empty)
        store
            .set("test:key1", b"value1")
            .await
            .expect("set should succeed");

        let value = store
            .get("test:key1")
            .await
            .expect("get should succeed")
            .expect("value should exist");
        assert_eq!(value, b"value1");

        // Test get non-existent key
        let missing = store
            .get("test:missing")
            .await
            .expect("get should succeed");
        assert!(missing.is_none(), "missing key should return None");

        // Test overwrite
        store
            .set("test:key1", b"value2")
            .await
            .expect("overwrite should succeed");
        let value = store
            .get("test:key1")
            .await
            .expect("get should succeed")
            .expect("value should exist");
        assert_eq!(value, b"value2");

        // Test binary data
        let binary_data = vec![0u8, 1, 2, 255, 128];
        store
            .set("test:binary", &binary_data)
            .await
            .expect("binary set should succeed");
        let retrieved = store
            .get("test:binary")
            .await
            .expect("get should succeed")
            .expect("value should exist");
        assert_eq!(retrieved, binary_data);

        // Test delete
        store
            .delete("test:key1")
            .await
            .expect("delete should succeed");
        let deleted = store
            .get("test:key1")
            .await
            .expect("get should succeed");
        assert!(deleted.is_none(), "deleted key should not exist");

        // Test delete idempotency
        store
            .delete("test:key1")
            .await
            .expect("second delete should succeed");

        // Cleanup
        let _ = store.delete("test:binary").await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_keychain_store_with_access_group() {
        // Test that KeychainStore can be created with an access group
        let service_name = format!("com.gap.test.{}", std::process::id());
        let access_group = "3R44BTH39W.com.gap.secrets";

        let store = KeychainStore::new_with_access_group(&service_name, access_group)
            .expect("create KeychainStore with access group");

        // Verify the store has the access group set
        assert_eq!(store.access_group.as_deref(), Some(access_group));

        // Test operations with access group
        store
            .set("test:access_group", b"value1")
            .await
            .expect("set with access group should succeed");

        let value = store
            .get("test:access_group")
            .await
            .expect("get with access group should succeed")
            .expect("value should exist");
        assert_eq!(value, b"value1");

        // Cleanup
        let _ = store.delete("test:access_group").await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_create_store_uses_test_namespace_in_test_mode() {
        // Verify that create_store(None) uses test namespace when running in test mode
        // This prevents tests from interfering with production keychain

        // Unset GAP_DATA_DIR to ensure we get KeychainStore
        std::env::remove_var("GAP_DATA_DIR");

        let store = create_store(None)
            .await
            .expect("create_store should succeed");

        // Downcast to KeychainStore to verify service name
        let keychain_store = store
            .as_any()
            .downcast_ref::<KeychainStore>()
            .expect("Should be KeychainStore on macOS in test mode without data_dir");

        // Verify service name starts with test prefix
        assert!(
            keychain_store.service_name.starts_with("com.gap.test."),
            "Service name should use test namespace, got: {}",
            keychain_store.service_name
        );

        // Verify it contains the process ID
        let expected_suffix = std::process::id().to_string();
        assert!(
            keychain_store.service_name.ends_with(&expected_suffix),
            "Service name should include process ID, got: {}",
            keychain_store.service_name
        );

        // Test that we can actually use it without affecting production keychain
        store
            .set("test:isolation_check", b"test_value")
            .await
            .expect("set should succeed");

        let value = store
            .get("test:isolation_check")
            .await
            .expect("get should succeed")
            .expect("value should exist");
        assert_eq!(value, b"test_value");

        // Cleanup
        let _ = store.delete("test:isolation_check").await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_keychain_store_with_data_protection() {
        // Test that KeychainStore can be created with Data Protection Keychain enabled
        let service_name = format!("com.gap.test.{}", std::process::id());
        let access_group = "3R44BTH39W.com.gap.secrets";

        let store = KeychainStore::new_with_data_protection(&service_name, access_group)
            .expect("create KeychainStore with Data Protection Keychain");

        // Verify the store has the settings configured
        assert_eq!(store.access_group.as_deref(), Some(access_group));
        assert!(store.use_data_protection, "Data Protection should be enabled");

        // Note: We can't test actual operations here because Data Protection Keychain
        // requires the binary to be properly signed with entitlements. This will fail
        // in development/test environments with errSecMissingEntitlement (-34018).
        // The important verification is that the constructor works and sets the flag.
    }
}
