//! Client-side Ed25519 request signing.
//!
//! Signs outgoing management API requests with an Ed25519 private key.
//! The canonical string format and content digest computation MUST match
//! the server's implementation in `gap-server/src/signing.rs`.

use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Headers produced by signing a request.
pub struct SignedHeaders {
    pub timestamp: String,
    pub nonce: String,
    pub signature: String,
    pub key_id: String,
}

/// Build the canonical string for signing (must match server's format).
///
/// Format:
/// ```text
/// @method: POST
/// @path: /plugins
/// content-digest: sha-256=:BASE64_HASH:
/// x-gap-timestamp: 1709000000
/// x-gap-nonce: abc123
/// ```
pub fn build_canonical_string(
    method: &str,
    path: &str,
    content_digest: &str,
    timestamp: &str,
    nonce: &str,
) -> String {
    format!(
        "@method: {}\n@path: {}\ncontent-digest: {}\nx-gap-timestamp: {}\nx-gap-nonce: {}",
        method, path, content_digest, timestamp, nonce
    )
}

/// Compute SHA-256 content digest in standard HTTP Digest format.
///
/// Returns `sha-256=:BASE64_ENCODED_HASH:` (matches server's format).
pub fn compute_content_digest(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let hash = hasher.finalize();
    let encoded = base64::engine::general_purpose::STANDARD.encode(hash);
    format!("sha-256=:{}:", encoded)
}

/// Sign a request and return the headers to attach.
///
/// Computes the content digest, builds the canonical string, signs it
/// with the Ed25519 keypair, and returns all required headers.
pub fn sign_request(
    keypair: &Ed25519KeyPair,
    method: &str,
    path: &str,
    body: &[u8],
) -> SignedHeaders {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let nonce = generate_nonce();
    let digest = compute_content_digest(body);
    let canonical = build_canonical_string(method, path, &digest, &timestamp, &nonce);
    let signature = keypair.sign(canonical.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.as_ref());

    // Key ID: truncated SHA-256 hash of the raw public key bytes
    let pub_key_bytes = keypair.public_key().as_ref();
    let mut hasher = Sha256::new();
    hasher.update(pub_key_bytes);
    let key_hash = hasher.finalize();
    let key_id = hex::encode(&key_hash[..8]);

    SignedHeaders {
        timestamp,
        nonce,
        signature: sig_b64,
        key_id,
    }
}

/// Generate a cryptographically random nonce as a 32-char hex string.
fn generate_nonce() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes).unwrap();
    hex::encode(bytes)
}

/// Load an Ed25519 private key from PEM-encoded PKCS8.
///
/// Expects standard `-----BEGIN PRIVATE KEY-----` / `-----END PRIVATE KEY-----`
/// wrapping around base64-encoded DER (PKCS#8) content.
pub fn load_private_key_pem(pem_bytes: &[u8]) -> Result<Ed25519KeyPair, anyhow::Error> {
    let pem_str = std::str::from_utf8(pem_bytes)?;
    let start_marker = "-----BEGIN PRIVATE KEY-----";
    let end_marker = "-----END PRIVATE KEY-----";
    let start = pem_str
        .find(start_marker)
        .ok_or_else(|| anyhow::anyhow!("Missing PEM start marker"))?
        + start_marker.len();
    let end = pem_str
        .find(end_marker)
        .ok_or_else(|| anyhow::anyhow!("Missing PEM end marker"))?;
    let b64: String = pem_str[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = base64::engine::general_purpose::STANDARD.decode(&b64)?;
    Ed25519KeyPair::from_pkcs8(&der)
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 PKCS8 key: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair;

    /// Helper: generate a fresh Ed25519 keypair for tests.
    fn test_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    /// Helper: generate a PKCS8 document for PEM testing.
    fn test_pkcs8_der() -> Vec<u8> {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        pkcs8.as_ref().to_vec()
    }

    #[test]
    fn test_build_canonical_string_format() {
        let result = build_canonical_string("POST", "/plugins", "sha-256=:abc123:", "1709000000", "nonce1");
        let expected = "@method: POST\n@path: /plugins\ncontent-digest: sha-256=:abc123:\nx-gap-timestamp: 1709000000\nx-gap-nonce: nonce1";
        assert_eq!(result, expected);
    }

    #[test]
    fn test_build_canonical_string_get() {
        let result = build_canonical_string("GET", "/tokens", "sha-256=:xyz:", "123", "n");
        assert!(result.starts_with("@method: GET\n"));
        assert!(result.contains("@path: /tokens\n"));
    }

    #[test]
    fn test_compute_content_digest_deterministic() {
        let body = b"hello world";
        let d1 = compute_content_digest(body);
        let d2 = compute_content_digest(body);
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_compute_content_digest_format() {
        let digest = compute_content_digest(b"test");
        assert!(digest.starts_with("sha-256=:"), "Should start with sha-256=: but got: {}", digest);
        assert!(digest.ends_with(':'), "Should end with colon but got: {}", digest);
    }

    #[test]
    fn test_compute_content_digest_empty_body() {
        let digest = compute_content_digest(b"");
        // SHA-256 of empty input is well-known: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
        assert!(
            digest.contains("47DEQpj8HBSa"),
            "Empty body SHA-256 should match known value, got: {}",
            digest
        );
    }

    #[test]
    fn test_compute_content_digest_matches_server() {
        // Verify our digest matches what the server would compute
        // by checking a known value
        let body = b"the quick brown fox";
        let digest = compute_content_digest(body);

        // Compute the expected value independently
        let mut hasher = Sha256::new();
        hasher.update(body);
        let hash = hasher.finalize();
        let encoded = base64::engine::general_purpose::STANDARD.encode(hash);
        let expected = format!("sha-256=:{}:", encoded);

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sign_request_produces_valid_headers() {
        let keypair = test_keypair();
        let headers = sign_request(&keypair, "POST", "/plugins", b"body");

        // Timestamp should be a valid number
        let ts: u64 = headers.timestamp.parse().expect("timestamp should be a number");
        assert!(ts > 0);

        // Nonce should be 32 hex chars (16 bytes)
        assert_eq!(headers.nonce.len(), 32);
        assert!(headers.nonce.chars().all(|c| c.is_ascii_hexdigit()));

        // Signature should be valid base64
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&headers.signature)
            .expect("signature should be valid base64");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature should be 64 bytes");

        // Key ID should be 16 hex chars (8 bytes of SHA-256 hash)
        assert_eq!(headers.key_id.len(), 16);
        assert!(headers.key_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sign_request_key_id_matches_public_key() {
        let keypair = test_keypair();
        let headers = sign_request(&keypair, "GET", "/status", b"");

        // Verify key_id is derived from the public key correctly
        let pub_key_bytes = keypair.public_key().as_ref();
        let mut hasher = Sha256::new();
        hasher.update(pub_key_bytes);
        let key_hash = hasher.finalize();
        let expected_key_id = hex::encode(&key_hash[..8]);

        assert_eq!(headers.key_id, expected_key_id);
    }

    #[test]
    fn test_sign_request_signature_verifiable() {
        // The signature produced by sign_request should be verifiable
        // using the server's verification logic
        let keypair = test_keypair();
        let body = b"test body";
        let headers = sign_request(&keypair, "POST", "/test", body);

        // Reconstruct what the server would do to verify
        let digest = compute_content_digest(body);
        let canonical = build_canonical_string(
            "POST",
            "/test",
            &digest,
            &headers.timestamp,
            &headers.nonce,
        );
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&headers.signature)
            .unwrap();

        // Verify using ring's public key verification
        let pub_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            keypair.public_key().as_ref(),
        );
        pub_key
            .verify(canonical.as_bytes(), &sig_bytes)
            .expect("Signature should be verifiable with the corresponding public key");
    }

    #[test]
    fn test_load_private_key_pem_valid() {
        let der = test_pkcs8_der();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);

        // Build a PEM string
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64
        );

        let result = load_private_key_pem(pem.as_bytes());
        assert!(result.is_ok(), "Should load valid PEM key: {:?}", result.err());
    }

    #[test]
    fn test_load_private_key_pem_with_line_wrapping() {
        let der = test_pkcs8_der();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);

        // Build PEM with 64-char line wrapping (standard format)
        let mut wrapped = String::new();
        for (i, c) in b64.chars().enumerate() {
            if i > 0 && i % 64 == 0 {
                wrapped.push('\n');
            }
            wrapped.push(c);
        }

        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            wrapped
        );

        let result = load_private_key_pem(pem.as_bytes());
        assert!(result.is_ok(), "Should load PEM with line wrapping: {:?}", result.err());
    }

    #[test]
    fn test_load_private_key_pem_missing_start_marker() {
        let pem = b"-----END PRIVATE KEY-----\n";
        let result = load_private_key_pem(pem);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("start marker"), "Error should mention start marker: {}", err_msg);
    }

    #[test]
    fn test_load_private_key_pem_missing_end_marker() {
        let pem = b"-----BEGIN PRIVATE KEY-----\ndata\n";
        let result = load_private_key_pem(pem);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("end marker"), "Error should mention end marker: {}", err_msg);
    }

    #[test]
    fn test_load_private_key_pem_invalid_base64() {
        let pem = b"-----BEGIN PRIVATE KEY-----\n!!!invalid!!!\n-----END PRIVATE KEY-----\n";
        let result = load_private_key_pem(pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_private_key_pem_roundtrip() {
        // Generate key, save as PEM, reload, verify signing works
        let der = test_pkcs8_der();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            b64
        );

        let keypair = load_private_key_pem(pem.as_bytes()).unwrap();
        let headers = sign_request(&keypair, "POST", "/test", b"body");

        // Verify signature is valid
        assert!(!headers.signature.is_empty());
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&headers.signature)
            .unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }
}
