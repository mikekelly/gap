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

#[cfg(target_os = "macos")]
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
#[cfg(target_os = "macos")]
use rand::RngCore;

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

/// Hybrid encrypted file storage implementation (macOS only)
///
/// Stores credentials encrypted at rest in files, with the master encryption key
/// stored in the traditional macOS keychain. This approach:
/// - Uses traditional keychain (one-time prompt with "Always Allow" option)
/// - Encrypts all credential data with ChaCha20-Poly1305
/// - Stores encrypted data in files (avoids Data Protection Keychain complexity)
#[cfg(target_os = "macos")]
pub struct EncryptedFileStore {
    file_store: FileStore,
    keychain_service: String,
    keychain_account: String,
}

#[cfg(target_os = "macos")]
impl EncryptedFileStore {
    /// Create a new EncryptedFileStore
    ///
    /// # Arguments
    /// * `base_path` - Directory for encrypted credential files
    /// * `keychain_service` - Keychain service name for master key (e.g., "com.mikekelly.gap-server")
    /// * `keychain_account` - Keychain account name for master key (e.g., "master_key")
    pub async fn new(
        base_path: PathBuf,
        keychain_service: impl Into<String>,
        keychain_account: impl Into<String>,
    ) -> Result<Self> {
        let file_store = FileStore::new(base_path).await?;
        Ok(Self {
            file_store,
            keychain_service: keychain_service.into(),
            keychain_account: keychain_account.into(),
        })
    }

    /// Get or create the master encryption key from keychain
    ///
    /// If the key doesn't exist, generates 32 random bytes and stores in keychain.
    /// Uses traditional keychain (no access group, no data protection) for reliable
    /// "Always Allow" behavior.
    fn get_or_create_master_key(&self) -> Result<[u8; 32]> {
        // Try to get existing key from traditional keychain (no access group, no data protection)
        if let Some(key_bytes) = crate::keychain_impl::get_generic_password_with_access_group(
            &self.keychain_service,
            &self.keychain_account,
            None,  // No access group - traditional keychain
            false, // No data protection - traditional keychain
        )? {
            if key_bytes.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&key_bytes);
                return Ok(key);
            }
            // Key exists but wrong size - delete and regenerate
            crate::keychain_impl::delete_generic_password_with_access_group(
                &self.keychain_service,
                &self.keychain_account,
                None,
                false,
            )?;
        }

        // Generate new master key
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);

        // Store in traditional keychain
        crate::keychain_impl::set_generic_password_with_access_group(
            &self.keychain_service,
            &self.keychain_account,
            &key,
            None,  // No access group - traditional keychain
            false, // No data protection - traditional keychain
        )?;

        Ok(key)
    }

    /// Encrypt data using ChaCha20-Poly1305
    ///
    /// Output format: [12-byte nonce][ciphertext + 16-byte auth tag]
    fn encrypt(&self, plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key.into());

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| crate::GapError::storage(format!("Encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    /// Decrypt data using ChaCha20-Poly1305
    ///
    /// Input format: [12-byte nonce][ciphertext + 16-byte auth tag]
    fn decrypt(&self, encrypted: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        if encrypted.len() < 12 + 16 {
            // Minimum: 12-byte nonce + 16-byte auth tag
            return Err(crate::GapError::storage("Encrypted data too short"));
        }

        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(&encrypted[..12]);
        let ciphertext = &encrypted[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| crate::GapError::storage(format!("Decryption failed: {}", e)))
    }
}

#[cfg(target_os = "macos")]
#[async_trait]
impl SecretStore for EncryptedFileStore {
    async fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        let master_key = self.get_or_create_master_key()?;
        let encrypted = self.encrypt(value, &master_key)?;
        self.file_store.set(key, &encrypted).await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let encrypted = match self.file_store.get(key).await? {
            Some(data) => data,
            None => return Ok(None),
        };

        let master_key = self.get_or_create_master_key()?;
        let decrypted = self.decrypt(&encrypted, &master_key)?;
        Ok(Some(decrypted))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.file_store.delete(key).await
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Factory function to create the appropriate SecretStore implementation
///
/// On macOS, returns EncryptedFileStore by default (master key in traditional keychain,
/// credentials encrypted in files). If `data_dir` is provided, returns FileStore instead.
///
/// On other platforms, always returns a FileStore.
///
/// # Arguments
/// * `data_dir` - Optional directory for FileStore. If None on macOS, uses EncryptedFileStore.
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
                // In test mode, use EncryptedFileStore with test-specific keychain service
                #[cfg(test)]
                {
                    let temp_dir = std::env::temp_dir()
                        .join("gap-test")
                        .join(std::process::id().to_string());
                    let service_name = format!("com.gap.test.{}", std::process::id());
                    let store = EncryptedFileStore::new(
                        temp_dir,
                        service_name,
                        "master_key",
                    ).await?;
                    return Ok(Box::new(store));
                }

                // In production, use EncryptedFileStore with traditional keychain for master key
                // This avoids Data Protection Keychain complexity while keeping credentials encrypted
                #[cfg(not(test))]
                {
                    let home = std::env::var("HOME")
                        .map_err(|_| crate::GapError::storage("Cannot determine home directory"))?;
                    let data_path = PathBuf::from(home).join(".gap").join("secrets");
                    let store = EncryptedFileStore::new(
                        data_path,
                        "com.mikekelly.gap-server",
                        "master_key",
                    ).await?;
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
    async fn test_create_store_uses_encrypted_file_store_in_test_mode() {
        // Verify that create_store(None) uses EncryptedFileStore when running in test mode
        // This uses traditional keychain for master key + encrypted files for credentials

        // Unset GAP_DATA_DIR to ensure we get EncryptedFileStore
        std::env::remove_var("GAP_DATA_DIR");

        let store = create_store(None)
            .await
            .expect("create_store should succeed");

        // Downcast to EncryptedFileStore to verify it's the correct type
        let encrypted_store = store
            .as_any()
            .downcast_ref::<EncryptedFileStore>()
            .expect("Should be EncryptedFileStore on macOS in test mode without data_dir");

        // Verify keychain service name starts with test prefix
        assert!(
            encrypted_store.keychain_service.starts_with("com.gap.test."),
            "Keychain service should use test namespace, got: {}",
            encrypted_store.keychain_service
        );

        // Verify it contains the process ID
        let expected_suffix = std::process::id().to_string();
        assert!(
            encrypted_store.keychain_service.ends_with(&expected_suffix),
            "Keychain service should include process ID, got: {}",
            encrypted_store.keychain_service
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
        // Cleanup master key from keychain
        let _ = crate::keychain_impl::delete_generic_password_with_access_group(
            &encrypted_store.keychain_service,
            &encrypted_store.keychain_account,
            None,
            false,
        );
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

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_encrypted_file_store() {
        // Test EncryptedFileStore basic operations
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let service_name = format!("com.gap.test.encrypted.{}", std::process::id());

        let store = EncryptedFileStore::new(
            temp_dir.path().to_path_buf(),
            &service_name,
            "test_master_key",
        )
        .await
        .expect("create EncryptedFileStore");

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

        // Cleanup keychain
        let _ = crate::keychain_impl::delete_generic_password_with_access_group(
            &service_name,
            "test_master_key",
            None,
            false,
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_encrypted_file_store_data_is_encrypted_on_disk() {
        // Verify that data stored by EncryptedFileStore is actually encrypted
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let service_name = format!("com.gap.test.encrypted.disk.{}", std::process::id());

        let store = EncryptedFileStore::new(
            temp_dir.path().to_path_buf(),
            &service_name,
            "test_master_key",
        )
        .await
        .expect("create EncryptedFileStore");

        let plaintext = b"this is a secret value that should be encrypted";
        store
            .set("test:encrypted", plaintext)
            .await
            .expect("set should succeed");

        // Read the raw file contents
        let raw_store = FileStore::new(temp_dir.path().to_path_buf())
            .await
            .expect("create FileStore");
        let raw_data = raw_store
            .get("test:encrypted")
            .await
            .expect("get raw should succeed")
            .expect("raw data should exist");

        // Raw data should NOT equal plaintext (it should be encrypted)
        assert_ne!(
            raw_data.as_slice(),
            plaintext,
            "Data on disk should be encrypted, not plaintext"
        );

        // Raw data should be longer than plaintext (nonce + auth tag overhead)
        // 12-byte nonce + 16-byte auth tag = 28 bytes overhead
        assert!(
            raw_data.len() >= plaintext.len() + 28,
            "Encrypted data should include nonce and auth tag"
        );

        // But decrypted data should match original
        let decrypted = store
            .get("test:encrypted")
            .await
            .expect("get should succeed")
            .expect("value should exist");
        assert_eq!(decrypted.as_slice(), plaintext);

        // Cleanup
        let _ = crate::keychain_impl::delete_generic_password_with_access_group(
            &service_name,
            "test_master_key",
            None,
            false,
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_encrypted_file_store_master_key_persistence() {
        // Verify that master key persists in keychain across store instances
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let service_name = format!("com.gap.test.encrypted.persist.{}", std::process::id());

        // Create first store and set a value
        let store1 = EncryptedFileStore::new(
            temp_dir.path().to_path_buf(),
            &service_name,
            "test_master_key",
        )
        .await
        .expect("create first EncryptedFileStore");

        store1
            .set("test:persist", b"persistent_value")
            .await
            .expect("set should succeed");

        // Create second store (simulates restart) - should use same master key
        let store2 = EncryptedFileStore::new(
            temp_dir.path().to_path_buf(),
            &service_name,
            "test_master_key",
        )
        .await
        .expect("create second EncryptedFileStore");

        // Second store should be able to decrypt data from first store
        let value = store2
            .get("test:persist")
            .await
            .expect("get should succeed")
            .expect("value should exist");
        assert_eq!(value, b"persistent_value");

        // Cleanup
        let _ = crate::keychain_impl::delete_generic_password_with_access_group(
            &service_name,
            "test_master_key",
            None,
            false,
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_encrypted_file_store_uses_traditional_keychain() {
        // Verify that EncryptedFileStore uses traditional keychain (not Data Protection)
        // Traditional keychain allows "Always Allow" option
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let service_name = format!("com.gap.test.encrypted.trad.{}", std::process::id());

        let store = EncryptedFileStore::new(
            temp_dir.path().to_path_buf(),
            &service_name,
            "test_master_key",
        )
        .await
        .expect("create EncryptedFileStore");

        // Store something to trigger master key creation
        store
            .set("test:trigger", b"value")
            .await
            .expect("set should succeed");

        // Verify we can retrieve the master key from traditional keychain
        // (no access group, no data protection)
        let key_data = crate::keychain_impl::get_generic_password_with_access_group(
            &service_name,
            "test_master_key",
            None,  // No access group
            false, // Not data protection
        )
        .expect("get master key should succeed")
        .expect("master key should exist");

        assert_eq!(key_data.len(), 32, "Master key should be 32 bytes");

        // Cleanup
        let _ = crate::keychain_impl::delete_generic_password_with_access_group(
            &service_name,
            "test_master_key",
            None,
            false,
        );
    }
}
