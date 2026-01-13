import CryptoKit
import Foundation

/// Hashes a password using SHA512 with no salt.
///
/// This implementation matches the CLI's Rust implementation exactly:
/// ```rust
/// pub fn hash_password(password: &str) -> String {
///     let mut hasher = Sha512::new();
///     hasher.update(password.as_bytes());
///     hex::encode(hasher.finalize())
/// }
/// ```
///
/// - Parameter password: The plain text password to hash
/// - Returns: A 128-character lowercase hex string representing the SHA512 hash
///
/// # Security Note
/// SHA512 without salt is intentionally used here for simplicity and because
/// the proxy runs on localhost only. This hash is used to verify passwords
/// for the Management API, not for general password storage.
func hashPassword(_ password: String) -> String {
    let hash = SHA512.hash(data: Data(password.utf8))
    return hash.map { String(format: "%02x", $0) }.joined()
}
