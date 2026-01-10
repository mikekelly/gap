//! Password input and hashing utilities

use anyhow::{Context, Result};
use sha2::{Digest, Sha512};

/// Read password from stdin without echoing
pub fn read_password(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("Failed to read password")
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
}
