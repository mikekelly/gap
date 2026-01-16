//! Password input and hashing utilities

use anyhow::{Context, Result};
use sha2::{Digest, Sha512};

/// Read password from stdin without echoing
pub fn read_password(prompt: &str) -> Result<String> {
    // Internal: GAP_PASSWORD env var for testing (undocumented)
    if let Ok(password) = std::env::var("GAP_PASSWORD") {
        return Ok(password);
    }
    rpassword::prompt_password(prompt).context("Failed to read password")
}

/// Read a secret value from stdin without echoing
pub fn read_secret(prompt: &str) -> Result<String> {
    // Internal: GAP_CREDENTIAL_VALUE env var for testing (undocumented)
    if let Ok(value) = std::env::var("GAP_CREDENTIAL_VALUE") {
        return Ok(value);
    }
    rpassword::prompt_password(prompt).context("Failed to read secret value")
}

/// Read password with confirmation
pub fn read_password_with_confirmation(prompt: &str) -> Result<String> {
    let password = read_password(prompt)?;
    let confirm = read_password("Confirm password: ")?;

    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    Ok(password)
}

/// Hash password using SHA512 for transmission to server
/// The server will then hash this with Argon2 for storage
pub fn hash_password(password: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn test_hash_password_deterministic() {
        let hash1 = hash_password("test123");
        let hash2 = hash_password("test123");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_password_different_inputs() {
        let hash1 = hash_password("password1");
        let hash2 = hash_password("password2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hash_password_sha512_length() {
        let hash = hash_password("test");
        // SHA512 produces 64 bytes = 128 hex characters
        assert_eq!(hash.len(), 128);
    }

    #[test]
    fn test_hash_password_hex_encoding() {
        let hash = hash_password("test");
        // Should only contain hex characters
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // Mutex to serialize tests that modify GAP_PASSWORD environment variable
    // Required because environment variables are process-global
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // Helper to ensure environment variable cleanup with RAII pattern
    struct EnvGuard(&'static str);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    #[test]
    fn test_read_password_from_env_variable() {
        // Lock to prevent parallel execution with other env var tests
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard("GAP_PASSWORD");

        let test_password = "testpass123";
        std::env::set_var("GAP_PASSWORD", test_password);

        // Should read from environment variable without prompting
        let result = read_password("Enter password: ");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_password);
    }

    #[test]
    fn test_read_password_env_empty_string() {
        // Lock to prevent parallel execution with other env var tests
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard("GAP_PASSWORD");

        // Even an empty password should work if explicitly set
        std::env::set_var("GAP_PASSWORD", "");

        let result = read_password("Enter password: ");

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }
}
