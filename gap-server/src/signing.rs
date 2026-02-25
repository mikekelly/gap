//! HTTP message signing verification module.
//!
//! Provides Ed25519-based request signature verification with nonce-based
//! replay protection and timestamp validation. Designed for verifying that
//! incoming API requests were signed by a trusted key holder.
//!
//! # Protocol
//!
//! Requests must include the following headers:
//! - `x-gap-timestamp`: Unix epoch seconds when the request was signed
//! - `x-gap-nonce`: Unique value per request (replay protection)
//! - `x-gap-signature`: Base64-encoded Ed25519 signature over the canonical string
//! - `x-gap-key-id` (optional): Identifies which public key to verify against
//!
//! The canonical string is built from the method, path, content digest, timestamp,
//! and nonce — each on its own line. The signature covers this canonical string.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use dashmap::DashMap;
use ring::signature::{self, UnparsedPublicKey};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Maximum allowed clock skew between request timestamp and server time (5 minutes).
const MAX_TIMESTAMP_SKEW_SECS: i64 = 300;

/// Configuration holding the public keys trusted for signature verification.
pub struct SigningConfig {
    /// (key_id, public_key) pairs used to verify request signatures.
    pub public_keys: Vec<(String, UnparsedPublicKey<Vec<u8>>)>,
}

/// Thread-safe cache of recently seen nonces for replay protection.
///
/// Nonces are stored with the time they were first seen. The `cleanup` method
/// can be called periodically to evict expired entries.
pub struct NonceCache {
    inner: DashMap<String, Instant>,
}

impl NonceCache {
    /// Creates a new empty nonce cache.
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Checks if a nonce is fresh (not previously seen) and records it.
    ///
    /// Returns `true` if the nonce was not in the cache (fresh).
    /// Returns `false` if the nonce was already present (replay).
    pub fn check_and_insert(&self, nonce: &str) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.inner.entry(nonce.to_string()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(v) => {
                v.insert(Instant::now());
                true
            }
        }
    }

    /// Removes nonce entries older than `max_age`.
    ///
    /// Should be called periodically to prevent unbounded memory growth.
    pub fn cleanup(&self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        self.inner.retain(|_, inserted| *inserted > cutoff);
    }
}

/// Builds the canonical string that is signed/verified.
///
/// Format (each component on its own line, joined by `\n`):
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

/// Computes the content digest of a request body.
///
/// Returns the digest in the standard HTTP Digest header format:
/// `sha-256=:BASE64_ENCODED_HASH:`
///
/// An empty body still produces a valid hash (the SHA-256 of empty input).
pub fn compute_content_digest(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let hash = hasher.finalize();
    let encoded = BASE64.encode(hash);
    format!("sha-256=:{}:", encoded)
}

/// Errors that can occur during request signature verification.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// A required header is missing from the request.
    #[error("Missing required header: {0}")]
    MissingHeader(String),

    /// The timestamp header could not be parsed as a Unix timestamp.
    #[error("Invalid timestamp")]
    InvalidTimestamp,

    /// The request timestamp is too far from the current server time.
    #[error("Request timestamp expired")]
    TimestampExpired,

    /// The nonce has been seen before (potential replay attack).
    #[error("Nonce already used")]
    NonceReplay,

    /// The signature could not be decoded from base64.
    #[error("Invalid signature encoding")]
    InvalidSignature,

    /// No trusted key could verify the signature.
    #[error("Signature verification failed")]
    VerificationFailed,
}

/// Verifies the Ed25519 signature on an incoming HTTP request.
///
/// # Verification steps
///
/// 1. Extract required headers (`x-gap-timestamp`, `x-gap-nonce`, `x-gap-signature`)
/// 2. Optionally extract `x-gap-key-id` to narrow key selection
/// 3. Validate timestamp is within the allowed skew window (5 minutes)
/// 4. Check nonce has not been seen before (replay protection)
/// 5. Compute content digest from the request body
/// 6. Build canonical string and verify signature against trusted keys
///
/// # Errors
///
/// Returns `SigningError` describing the specific verification failure.
pub fn verify_request_signature(
    method: &str,
    path: &str,
    body: &[u8],
    headers: &http::HeaderMap,
    config: &SigningConfig,
    nonce_cache: &NonceCache,
) -> Result<(), SigningError> {
    // 1. Extract required headers
    let timestamp = headers
        .get("x-gap-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| SigningError::MissingHeader("x-gap-timestamp".to_string()))?;

    let nonce = headers
        .get("x-gap-nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| SigningError::MissingHeader("x-gap-nonce".to_string()))?;

    let signature_b64 = headers
        .get("x-gap-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| SigningError::MissingHeader("x-gap-signature".to_string()))?;

    // 4. Optional key ID to narrow key selection
    let key_id = headers
        .get("x-gap-key-id")
        .and_then(|v| v.to_str().ok());

    // 5. Validate timestamp within allowed skew
    let ts: i64 = timestamp
        .parse()
        .map_err(|_| SigningError::InvalidTimestamp)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SigningError::InvalidTimestamp)?
        .as_secs() as i64;
    if (now - ts).abs() > MAX_TIMESTAMP_SKEW_SECS {
        return Err(SigningError::TimestampExpired);
    }

    // 6. Check nonce freshness
    if !nonce_cache.check_and_insert(nonce) {
        return Err(SigningError::NonceReplay);
    }

    // 7. Compute content digest
    let content_digest = compute_content_digest(body);

    // 8. Build canonical string
    let canonical = build_canonical_string(method, path, &content_digest, timestamp, nonce);

    // 9. Decode signature
    let signature_bytes = BASE64
        .decode(signature_b64)
        .map_err(|_| SigningError::InvalidSignature)?;

    // 10. Select keys to try
    let keys_to_try: Vec<&(String, UnparsedPublicKey<Vec<u8>>)> = if let Some(kid) = key_id {
        config
            .public_keys
            .iter()
            .filter(|(id, _)| id == kid)
            .collect()
    } else {
        config.public_keys.iter().collect()
    };

    if keys_to_try.is_empty() {
        return Err(SigningError::VerificationFailed);
    }

    // 11. Try each candidate key
    for (_, key) in &keys_to_try {
        if key.verify(canonical.as_bytes(), &signature_bytes).is_ok() {
            return Ok(());
        }
    }

    Err(SigningError::VerificationFailed)
}

/// Loads an Ed25519 public key from PEM-encoded bytes (SPKI/PKCS#8 format).
///
/// Returns a `(key_id, public_key)` tuple where `key_id` is a truncated hex hash
/// of the raw public key bytes, suitable for use as a stable identifier.
///
/// # PEM format
///
/// Expects standard `-----BEGIN PUBLIC KEY-----` / `-----END PUBLIC KEY-----`
/// wrapping around base64-encoded DER content. The DER content uses the SPKI
/// format with the Ed25519 OID, containing a 12-byte ASN.1 prefix
/// (`302a300506032b6570032100`) followed by the 32-byte raw public key.
pub fn load_public_key_pem(
    pem_bytes: &[u8],
) -> Result<(String, UnparsedPublicKey<Vec<u8>>), anyhow::Error> {
    let pem_str = std::str::from_utf8(pem_bytes)?;

    // Extract base64 content between PEM markers
    let begin_marker = "-----BEGIN PUBLIC KEY-----";
    let end_marker = "-----END PUBLIC KEY-----";

    let start = pem_str
        .find(begin_marker)
        .ok_or_else(|| anyhow::anyhow!("Missing PEM begin marker"))?
        + begin_marker.len();
    let end = pem_str
        .find(end_marker)
        .ok_or_else(|| anyhow::anyhow!("Missing PEM end marker"))?;

    let b64_content: String = pem_str[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = BASE64.decode(&b64_content)?;

    // Ed25519 SPKI DER prefix: 302a300506032b6570032100 (12 bytes)
    // Total DER length should be 44 bytes (12 prefix + 32 key)
    let expected_prefix: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    if der.len() != 44 {
        return Err(anyhow::anyhow!(
            "Unexpected DER length: expected 44, got {}",
            der.len()
        ));
    }
    if &der[..12] != expected_prefix.as_slice() {
        return Err(anyhow::anyhow!("Unexpected DER prefix for Ed25519 SPKI key"));
    }

    let raw_key = der[12..].to_vec();

    // Derive key_id from truncated SHA-256 hash of the raw public key
    let mut hasher = Sha256::new();
    hasher.update(&raw_key);
    let hash = hasher.finalize();
    let key_id = hash[..8]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let public_key = UnparsedPublicKey::new(&signature::ED25519, raw_key);

    Ok((key_id, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// Creates a test Ed25519 keypair, returning the keypair and raw public key bytes.
    fn test_keypair() -> (Ed25519KeyPair, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public_key = keypair.public_key().as_ref().to_vec();
        (keypair, public_key)
    }

    /// Helper to produce a base64-encoded Ed25519 signature for test requests.
    fn sign_request(
        keypair: &Ed25519KeyPair,
        method: &str,
        path: &str,
        body: &[u8],
        timestamp: i64,
        nonce: &str,
    ) -> String {
        let digest = compute_content_digest(body);
        let canonical =
            build_canonical_string(method, path, &digest, &timestamp.to_string(), nonce);
        let sig = keypair.sign(canonical.as_bytes());
        BASE64.encode(sig.as_ref())
    }

    /// Returns the current Unix timestamp as i64.
    fn now_ts() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Builds an `http::HeaderMap` with the standard signing headers.
    fn build_headers(timestamp: i64, nonce: &str, signature: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-gap-timestamp", timestamp.to_string().parse().unwrap());
        headers.insert("x-gap-nonce", nonce.parse().unwrap());
        headers.insert("x-gap-signature", signature.parse().unwrap());
        headers
    }

    /// Creates a `SigningConfig` from raw public key bytes.
    fn config_from_raw(public_key: &[u8]) -> SigningConfig {
        SigningConfig {
            public_keys: vec![(
                "test-key".to_string(),
                UnparsedPublicKey::new(&signature::ED25519, public_key.to_vec()),
            )],
        }
    }

    #[test]
    fn test_valid_signature() {
        let (keypair, pub_key) = test_keypair();
        let config = config_from_raw(&pub_key);
        let nonce_cache = NonceCache::new();

        let ts = now_ts();
        let body = b"hello world";
        let sig = sign_request(&keypair, "POST", "/plugins", body, ts, "nonce-1");
        let headers = build_headers(ts, "nonce-1", &sig);

        let result = verify_request_signature("POST", "/plugins", body, &headers, &config, &nonce_cache);
        assert!(result.is_ok(), "Valid signature should verify: {:?}", result);
    }

    #[test]
    fn test_expired_timestamp() {
        let (keypair, pub_key) = test_keypair();
        let config = config_from_raw(&pub_key);
        let nonce_cache = NonceCache::new();

        let ts = now_ts() - 600; // 10 minutes ago — well past the 5-minute window
        let body = b"payload";
        let sig = sign_request(&keypair, "POST", "/api", body, ts, "nonce-expired");
        let headers = build_headers(ts, "nonce-expired", &sig);

        let result = verify_request_signature("POST", "/api", body, &headers, &config, &nonce_cache);
        assert!(matches!(result, Err(SigningError::TimestampExpired)));
    }

    #[test]
    fn test_replayed_nonce() {
        let (keypair, pub_key) = test_keypair();
        let config = config_from_raw(&pub_key);
        let nonce_cache = NonceCache::new();

        let ts = now_ts();
        let body = b"data";
        let sig = sign_request(&keypair, "POST", "/test", body, ts, "same-nonce");
        let headers = build_headers(ts, "same-nonce", &sig);

        // First call should succeed
        let result = verify_request_signature("POST", "/test", body, &headers, &config, &nonce_cache);
        assert!(result.is_ok(), "First use of nonce should succeed");

        // Second call with same nonce should fail
        let ts2 = now_ts();
        let sig2 = sign_request(&keypair, "POST", "/test", body, ts2, "same-nonce");
        let headers2 = build_headers(ts2, "same-nonce", &sig2);
        let result2 =
            verify_request_signature("POST", "/test", body, &headers2, &config, &nonce_cache);
        assert!(matches!(result2, Err(SigningError::NonceReplay)));
    }

    #[test]
    fn test_wrong_key() {
        let (keypair_a, _pub_key_a) = test_keypair();
        let (_keypair_b, pub_key_b) = test_keypair();
        // Sign with keypair A but verify with keypair B's public key
        let config = config_from_raw(&pub_key_b);
        let nonce_cache = NonceCache::new();

        let ts = now_ts();
        let body = b"secret";
        let sig = sign_request(&keypair_a, "POST", "/path", body, ts, "nonce-wrong");
        let headers = build_headers(ts, "nonce-wrong", &sig);

        let result =
            verify_request_signature("POST", "/path", body, &headers, &config, &nonce_cache);
        assert!(matches!(result, Err(SigningError::VerificationFailed)));
    }

    #[test]
    fn test_missing_headers() {
        let (_keypair, pub_key) = test_keypair();
        let config = config_from_raw(&pub_key);

        // Missing x-gap-timestamp
        {
            let nonce_cache = NonceCache::new();
            let mut headers = http::HeaderMap::new();
            headers.insert("x-gap-nonce", "n".parse().unwrap());
            headers.insert("x-gap-signature", "sig".parse().unwrap());
            let result =
                verify_request_signature("GET", "/", b"", &headers, &config, &nonce_cache);
            assert!(
                matches!(result, Err(SigningError::MissingHeader(ref h)) if h == "x-gap-timestamp"),
                "Expected MissingHeader(x-gap-timestamp), got: {:?}",
                result
            );
        }

        // Missing x-gap-nonce
        {
            let nonce_cache = NonceCache::new();
            let mut headers = http::HeaderMap::new();
            headers.insert("x-gap-timestamp", "12345".parse().unwrap());
            headers.insert("x-gap-signature", "sig".parse().unwrap());
            let result =
                verify_request_signature("GET", "/", b"", &headers, &config, &nonce_cache);
            assert!(
                matches!(result, Err(SigningError::MissingHeader(ref h)) if h == "x-gap-nonce"),
                "Expected MissingHeader(x-gap-nonce), got: {:?}",
                result
            );
        }

        // Missing x-gap-signature
        {
            let nonce_cache = NonceCache::new();
            let mut headers = http::HeaderMap::new();
            headers.insert("x-gap-timestamp", now_ts().to_string().parse().unwrap());
            headers.insert("x-gap-nonce", "n".parse().unwrap());
            let result =
                verify_request_signature("GET", "/", b"", &headers, &config, &nonce_cache);
            assert!(
                matches!(result, Err(SigningError::MissingHeader(ref h)) if h == "x-gap-signature"),
                "Expected MissingHeader(x-gap-signature), got: {:?}",
                result
            );
        }
    }

    #[test]
    fn test_tampered_body() {
        let (keypair, pub_key) = test_keypair();
        let config = config_from_raw(&pub_key);
        let nonce_cache = NonceCache::new();

        let ts = now_ts();
        let original_body = b"original content";
        let tampered_body = b"tampered content";
        let sig = sign_request(&keypair, "PUT", "/resource", original_body, ts, "nonce-tamper");
        let headers = build_headers(ts, "nonce-tamper", &sig);

        // Verify with a different body than was signed
        let result = verify_request_signature(
            "PUT",
            "/resource",
            tampered_body,
            &headers,
            &config,
            &nonce_cache,
        );
        assert!(matches!(result, Err(SigningError::VerificationFailed)));
    }

    #[test]
    fn test_nonce_cache_cleanup() {
        let cache = NonceCache::new();

        // Insert a nonce
        assert!(cache.check_and_insert("old-nonce"));

        // Immediately after insert, nonce should be present
        assert!(!cache.check_and_insert("old-nonce"));

        // Cleanup with a zero-duration max_age — should remove everything
        cache.cleanup(Duration::from_secs(0));

        // After cleanup, the nonce should be accepted again
        assert!(
            cache.check_and_insert("old-nonce"),
            "Nonce should be accepted after cleanup"
        );
    }

    #[test]
    fn test_content_digest_deterministic() {
        let body = b"the quick brown fox";
        let d1 = compute_content_digest(body);
        let d2 = compute_content_digest(body);
        assert_eq!(d1, d2, "Same body must produce identical digests");
        assert!(d1.starts_with("sha-256=:"), "Digest should have standard prefix");
        assert!(d1.ends_with(':'), "Digest should end with colon");
    }

    #[test]
    fn test_content_digest_empty_body() {
        let digest = compute_content_digest(b"");
        assert!(digest.starts_with("sha-256=:"), "Empty body digest should have standard prefix");
        assert!(digest.ends_with(':'), "Empty body digest should end with colon");
        // SHA-256 of empty input is well-known:
        // 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
        assert!(
            digest.contains("47DEQpj8HBSa"),
            "Empty body SHA-256 should match known value, got: {}",
            digest
        );
    }
}
