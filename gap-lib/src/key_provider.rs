//! Encryption key providers for GapDatabase
//!
//! Provides pluggable key sources for database encryption:
//! - `EnvKeyProvider` reads hex-encoded key from GAP_ENCRYPTION_KEY env var
//! - `KeychainKeyProvider` (macOS only) stores/retrieves key in macOS keychain

use async_trait::async_trait;
use crate::Result;

/// Provides encryption key bytes for the database.
///
/// Implementations determine where the key comes from (environment, keychain, etc).
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Returns the encryption key bytes for the database.
    async fn get_key(&self) -> Result<Vec<u8>>;
}

/// Reads encryption key from `GAP_ENCRYPTION_KEY` env var (hex-encoded).
///
/// The env var must contain a valid hex string (e.g. 64 hex chars for a 32-byte key).
pub struct EnvKeyProvider;

#[async_trait]
impl KeyProvider for EnvKeyProvider {
    async fn get_key(&self) -> Result<Vec<u8>> {
        let hex_key = std::env::var("GAP_ENCRYPTION_KEY")
            .map_err(|_| crate::GapError::config("GAP_ENCRYPTION_KEY not set"))?;
        hex::decode(&hex_key)
            .map_err(|e| crate::GapError::config(format!("Invalid hex in GAP_ENCRYPTION_KEY: {e}")))
    }
}

/// Retrieves or generates an encryption key from the macOS keychain.
///
/// On first use, generates a random 32-byte key, stores it in the traditional
/// macOS keychain (service: "com.gap.db-encryption", account: "master-key"),
/// and returns it. Subsequent calls retrieve the stored key.
#[cfg(target_os = "macos")]
pub struct KeychainKeyProvider;

#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "com.gap.db-encryption";
#[cfg(target_os = "macos")]
const KEYCHAIN_ACCOUNT: &str = "master-key";

#[cfg(target_os = "macos")]
#[async_trait]
impl KeyProvider for KeychainKeyProvider {
    async fn get_key(&self) -> Result<Vec<u8>> {
        use crate::keychain_impl::{
            get_generic_password_with_access_group,
            set_generic_password_with_access_group,
        };

        // Try to retrieve existing key from keychain (traditional keychain, no access group)
        if let Some(key) = get_generic_password_with_access_group(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
            None,
            false,
        )? {
            tracing::info!("Retrieved database encryption key from keychain");
            return Ok(key);
        }

        // Not found: generate a random 32-byte key
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);

        // Store in keychain for next time
        set_generic_password_with_access_group(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
            &key,
            None,
            false,
        )?;
        tracing::info!("Generated and stored new database encryption key in keychain");

        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn env_key_provider_returns_decoded_hex() {
        // Set a known hex key (32 bytes = 64 hex chars)
        let key_bytes = [0xABu8; 32];
        let hex_key = hex::encode(&key_bytes);
        unsafe { std::env::set_var("GAP_ENCRYPTION_KEY", &hex_key) };

        let provider = EnvKeyProvider;
        let result = provider.get_key().await.unwrap();
        assert_eq!(result, key_bytes.to_vec());

        // Clean up
        unsafe { std::env::remove_var("GAP_ENCRYPTION_KEY") };
    }

    #[tokio::test]
    async fn env_key_provider_error_when_not_set() {
        unsafe { std::env::remove_var("GAP_ENCRYPTION_KEY") };

        let provider = EnvKeyProvider;
        let err = provider.get_key().await.unwrap_err();
        assert!(err.to_string().contains("GAP_ENCRYPTION_KEY not set"));
    }

    #[tokio::test]
    async fn env_key_provider_error_on_invalid_hex() {
        unsafe { std::env::set_var("GAP_ENCRYPTION_KEY", "not-valid-hex!@#") };

        let provider = EnvKeyProvider;
        let err = provider.get_key().await.unwrap_err();
        assert!(err.to_string().contains("Invalid hex"));

        // Clean up
        unsafe { std::env::remove_var("GAP_ENCRYPTION_KEY") };
    }

    #[tokio::test]
    async fn env_key_provider_handles_short_key() {
        // A short hex string is valid hex but only 2 bytes
        unsafe { std::env::set_var("GAP_ENCRYPTION_KEY", "abcd") };

        let provider = EnvKeyProvider;
        let result = provider.get_key().await.unwrap();
        assert_eq!(result, vec![0xAB, 0xCD]);

        // Clean up
        unsafe { std::env::remove_var("GAP_ENCRYPTION_KEY") };
    }

    /// Integration test: open an encrypted DB, write data, reopen with same key
    #[tokio::test]
    async fn encrypted_db_roundtrip() {
        use crate::database::GapDatabase;

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_encrypted.db");
        let db_path_str = db_path.to_str().unwrap();

        let key = vec![0x42u8; 32];

        // Open encrypted DB, write some data
        {
            let db = GapDatabase::open(db_path_str, &key).await.unwrap();
            db.set_config("test_key", b"test_value").await.unwrap();
        }

        // Reopen with same key, verify data persisted
        {
            let db = GapDatabase::open(db_path_str, &key).await.unwrap();
            let val = db.get_config("test_key").await.unwrap().unwrap();
            assert_eq!(val, b"test_value");
        }
    }

    /// Verify that opening an encrypted DB with the wrong key fails
    #[tokio::test]
    async fn encrypted_db_wrong_key_fails() {
        use crate::database::GapDatabase;

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test_wrong_key.db");
        let db_path_str = db_path.to_str().unwrap();

        // Create encrypted DB with key A
        let key_a = vec![0x42u8; 32];
        {
            let db = GapDatabase::open(db_path_str, &key_a).await.unwrap();
            db.set_config("secret", b"data").await.unwrap();
        }

        // Try to open with key B -- should fail
        let key_b = vec![0x99u8; 32];
        let result = GapDatabase::open(db_path_str, &key_b).await;
        assert!(result.is_err(), "Opening encrypted DB with wrong key should fail");
    }

    /// KeychainKeyProvider test is ignored by default because it requires macOS keychain access
    /// and may prompt for user interaction.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore]
    async fn keychain_key_provider_stores_and_retrieves() {
        use crate::keychain_impl::delete_generic_password_with_access_group;

        // Clean up any existing test key
        let _ = delete_generic_password_with_access_group(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
            None,
            false,
        );

        let provider = KeychainKeyProvider;

        // First call should generate and store a new key
        let key1 = provider.get_key().await.unwrap();
        assert_eq!(key1.len(), 32, "Generated key should be 32 bytes");

        // Second call should retrieve the same key
        let key2 = provider.get_key().await.unwrap();
        assert_eq!(key1, key2, "Subsequent calls should return the same key");

        // Clean up
        let _ = delete_generic_password_with_access_group(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
            None,
            false,
        );
    }
}
