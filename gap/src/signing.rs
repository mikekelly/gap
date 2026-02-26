//! Client-side Ed25519 request signing (RFC 9421 HTTP Message Signatures).
//!
//! Signs outgoing management API requests with an Ed25519 private key.
//! The signature base and content digest computation MUST match
//! the server's implementation in `gap-server/src/signing.rs`.

use base64::Engine;
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Headers produced by signing a request (RFC 9421 format).
pub struct SignedHeaders {
    pub content_digest: String,  // "sha-256=:BASE64:"
    pub signature_input: String, // "sig1=(...);created=...;nonce=...;keyid=...;alg=\"ed25519\""
    pub signature: String,       // "sig1=:BASE64:"
}

/// Build the RFC 9421 signature params string.
///
/// The covered components are always `("@method" "@path" "content-digest")`.
///
/// Returns a string like:
/// `("@method" "@path" "content-digest");created=1709000000;nonce="abc123";keyid="6a3b42c10443f618";alg="ed25519"`
pub fn build_signature_params(created: i64, nonce: &str, keyid: &str) -> String {
    format!(
        "(\"@method\" \"@path\" \"content-digest\");created={};nonce=\"{}\";keyid=\"{}\";alg=\"ed25519\"",
        created, nonce, keyid
    )
}

/// Build the RFC 9421 signature base (the string that gets signed).
///
/// Format:
/// ```text
/// "@method": POST
/// "@path": /plugins
/// "content-digest": sha-256=:BASE64:
/// "@signature-params": ("@method" "@path" "content-digest");created=...;nonce="...";keyid="...";alg="ed25519"
/// ```
///
/// Each line is `"component-name": value`, joined by `\n`.
pub fn build_signature_base(
    method: &str,
    path: &str,
    content_digest: &str,
    signature_params: &str,
) -> String {
    format!(
        "\"@method\": {}\n\"@path\": {}\n\"content-digest\": {}\n\"@signature-params\": {}",
        method, path, content_digest, signature_params
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
/// Computes the content digest, builds the RFC 9421 signature base, signs it
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
        .as_secs() as i64;
    let nonce = generate_nonce();
    let content_digest = compute_content_digest(body);

    // Key ID: truncated SHA-256 hash of raw public key bytes
    let pub_key_bytes = keypair.public_key().as_ref();
    let mut hasher = Sha256::new();
    hasher.update(pub_key_bytes);
    let key_hash = hasher.finalize();
    let key_id = hex::encode(&key_hash[..8]);

    let sig_params = build_signature_params(timestamp, &nonce, &key_id);
    let sig_base = build_signature_base(method, path, &content_digest, &sig_params);
    let signature = keypair.sign(sig_base.as_bytes());
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.as_ref());

    SignedHeaders {
        content_digest,
        signature_input: format!("sig1={}", sig_params),
        signature: format!("sig1=:{}:", sig_b64),
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
    fn test_build_signature_params() {
        let params = build_signature_params(1709000000, "abc123", "6a3b42c10443f618");
        assert_eq!(
            params,
            "(\"@method\" \"@path\" \"content-digest\");created=1709000000;nonce=\"abc123\";keyid=\"6a3b42c10443f618\";alg=\"ed25519\""
        );
    }

    #[test]
    fn test_build_signature_base() {
        let params = build_signature_params(1709000000, "abc123", "6a3b42c10443f618");
        let base = build_signature_base("POST", "/plugins", "sha-256=:dGVzdA==:", &params);
        let expected = "\"@method\": POST\n\"@path\": /plugins\n\"content-digest\": sha-256=:dGVzdA==:\n\"@signature-params\": (\"@method\" \"@path\" \"content-digest\");created=1709000000;nonce=\"abc123\";keyid=\"6a3b42c10443f618\";alg=\"ed25519\"";
        assert_eq!(base, expected);
    }

    #[test]
    fn test_build_signature_base_get() {
        let params = build_signature_params(123, "n", "keyabc");
        let base = build_signature_base("GET", "/tokens", "sha-256=:xyz:", &params);
        assert!(base.starts_with("\"@method\": GET\n"));
        assert!(base.contains("\"@path\": /tokens\n"));
        assert!(base.contains("\"content-digest\": sha-256=:xyz:\n"));
        assert!(base.contains("\"@signature-params\":"));
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

        // content_digest should have standard format
        assert!(headers.content_digest.starts_with("sha-256=:"));
        assert!(headers.content_digest.ends_with(':'));

        // signature_input should start with "sig1=("
        assert!(
            headers.signature_input.starts_with("sig1=("),
            "signature_input should start with sig1=(, got: {}",
            headers.signature_input
        );
        assert!(headers.signature_input.contains(";created="));
        assert!(headers.signature_input.contains(";nonce=\""));
        assert!(headers.signature_input.contains(";keyid=\""));
        assert!(headers.signature_input.contains(";alg=\"ed25519\""));

        // signature should be "sig1=:BASE64:"
        assert!(
            headers.signature.starts_with("sig1=:"),
            "signature should start with sig1=:, got: {}",
            headers.signature
        );
        assert!(
            headers.signature.ends_with(':'),
            "signature should end with :, got: {}",
            headers.signature
        );

        // Verify the inner base64 is valid and decodes to 64 bytes (Ed25519 sig)
        let inner = &headers.signature["sig1=:".len()..headers.signature.len() - 1];
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(inner)
            .expect("inner signature should be valid base64");
        assert_eq!(sig_bytes.len(), 64, "Ed25519 signature should be 64 bytes");
    }

    #[test]
    fn test_sign_request_key_id_matches_public_key() {
        let keypair = test_keypair();
        let headers = sign_request(&keypair, "GET", "/status", b"");

        // Verify key_id is embedded in signature_input and matches public key
        let pub_key_bytes = keypair.public_key().as_ref();
        let mut hasher = Sha256::new();
        hasher.update(pub_key_bytes);
        let key_hash = hasher.finalize();
        let expected_key_id = hex::encode(&key_hash[..8]);

        let keyid_needle = format!(";keyid=\"{}\"", expected_key_id);
        assert!(
            headers.signature_input.contains(&keyid_needle),
            "signature_input should contain keyid={}, got: {}",
            expected_key_id,
            headers.signature_input
        );
    }

    #[test]
    fn test_sign_request_signature_verifiable() {
        // The signature produced by sign_request should be verifiable
        // using the server's verification logic (RFC 9421 format)
        let keypair = test_keypair();
        let body = b"test body";
        let headers = sign_request(&keypair, "POST", "/test", body);

        // Parse signature_input to extract params
        let sig_params_str = headers
            .signature_input
            .strip_prefix("sig1=")
            .expect("should have sig1= prefix");

        // Reconstruct what the server would do to verify
        let digest = compute_content_digest(body);
        let sig_base = build_signature_base("POST", "/test", &digest, sig_params_str);

        // Extract raw signature bytes from "sig1=:BASE64:"
        let inner = &headers.signature["sig1=:".len()..headers.signature.len() - 1];
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(inner)
            .unwrap();

        // Verify using ring's public key verification
        let pub_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            keypair.public_key().as_ref(),
        );
        pub_key
            .verify(sig_base.as_bytes(), &sig_bytes)
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

        // Verify signature is in correct format and valid
        assert!(headers.signature.starts_with("sig1=:"));
        assert!(headers.signature.ends_with(':'));
        let inner = &headers.signature["sig1=:".len()..headers.signature.len() - 1];
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(inner)
            .unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }
}
