//! HTTP message signing verification module (RFC 9421).
//!
//! Provides Ed25519-based request signature verification with nonce-based
//! replay protection and timestamp validation. Designed for verifying that
//! incoming API requests were signed by a trusted key holder.
//!
//! # Protocol
//!
//! Requests must include the following headers:
//! - `Signature-Input`: Structured field describing the signature parameters
//!   e.g. `sig1=("@method" "@path" "content-digest");created=1709000000;nonce="abc123";keyid="6a3b42c10443f618";alg="ed25519"`
//! - `Signature`: The base64-encoded Ed25519 signature
//!   e.g. `sig1=:BASE64SIGNATURE:`
//!
//! The signature base is built from the covered components and signature params,
//! per RFC 9421 format.

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

/// Builds the RFC 9421 signature params string.
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

/// Builds the RFC 9421 signature base (the string that gets signed).
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

/// Parses a `Signature-Input` header value.
///
/// Expects format: `sig1=("@method" "@path" "content-digest");created=N;nonce="...";keyid="...";alg="ed25519"`
///
/// Returns `(created_timestamp, nonce, keyid)`.
pub fn parse_signature_input(header_value: &str) -> Result<(i64, String, String), SigningError> {
    // Strip "sig1=" prefix
    let rest = header_value
        .strip_prefix("sig1=")
        .ok_or(SigningError::InvalidSignatureInput)?;

    // Verify covered components
    let expected_components = "(\"@method\" \"@path\" \"content-digest\")";
    let rest = rest
        .strip_prefix(expected_components)
        .ok_or(SigningError::InvalidSignatureInput)?;

    // Parse ;key=value parameters
    let mut created: Option<i64> = None;
    let mut nonce: Option<String> = None;
    let mut keyid: Option<String> = None;

    // Split on ';' — the rest starts with ';'
    for param in rest.split(';').skip(1) {
        let param = param.trim();
        if let Some(val) = param.strip_prefix("created=") {
            created = Some(
                val.parse::<i64>()
                    .map_err(|_| SigningError::InvalidSignatureInput)?,
            );
        } else if let Some(val) = param.strip_prefix("nonce=") {
            nonce = Some(parse_quoted_string(val)?);
        } else if let Some(val) = param.strip_prefix("keyid=") {
            keyid = Some(parse_quoted_string(val)?);
        } else if let Some(val) = param.strip_prefix("alg=") {
            // Validate but don't return — must be "ed25519"
            let alg = parse_quoted_string(val)?;
            if alg != "ed25519" {
                return Err(SigningError::InvalidSignatureInput);
            }
        }
    }

    let created = created.ok_or(SigningError::InvalidSignatureInput)?;
    let nonce = nonce.ok_or(SigningError::InvalidSignatureInput)?;
    let keyid = keyid.ok_or(SigningError::InvalidSignatureInput)?;

    Ok((created, nonce, keyid))
}

/// Parses a quoted string value like `"abc123"`, returning the inner content.
fn parse_quoted_string(s: &str) -> Result<String, SigningError> {
    let s = s.trim();
    if s.len() < 2 || !s.starts_with('"') || !s.ends_with('"') {
        return Err(SigningError::InvalidSignatureInput);
    }
    Ok(s[1..s.len() - 1].to_string())
}

/// Parses a `Signature` header value.
///
/// Expects format: `sig1=:BASE64SIGNATURE:`
///
/// Returns the raw decoded signature bytes.
pub fn parse_signature(header_value: &str) -> Result<Vec<u8>, SigningError> {
    // Strip "sig1=:" prefix
    let rest = header_value
        .strip_prefix("sig1=:")
        .ok_or(SigningError::InvalidSignature)?;

    // Strip trailing ":"
    let b64 = rest
        .strip_suffix(':')
        .ok_or(SigningError::InvalidSignature)?;

    BASE64
        .decode(b64)
        .map_err(|_| SigningError::InvalidSignature)
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

    /// The Signature-Input header is malformed or has unexpected format.
    #[error("Invalid Signature-Input header")]
    InvalidSignatureInput,

    /// The timestamp could not be parsed or is invalid.
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

/// Verifies the RFC 9421 Ed25519 signature on an incoming HTTP request.
///
/// # Verification steps
///
/// 1. Extract `Signature-Input` header and parse to get created, nonce, keyid
/// 2. Extract `Signature` header and decode the signature bytes
/// 3. Validate timestamp is within the allowed skew window (5 minutes)
/// 4. Check nonce has not been seen before (replay protection)
/// 5. Compute content digest from the request body
/// 6. Build signature base and verify signature against trusted keys
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
    // 1. Extract and parse Signature-Input header
    let sig_input_value = headers
        .get("signature-input")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| SigningError::MissingHeader("signature-input".to_string()))?;

    let (created, nonce, keyid) = parse_signature_input(sig_input_value)?;

    // 2. Extract and parse Signature header
    let sig_value = headers
        .get("signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| SigningError::MissingHeader("signature".to_string()))?;

    let signature_bytes = parse_signature(sig_value)?;

    // 3. Validate timestamp within allowed skew
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SigningError::InvalidTimestamp)?
        .as_secs() as i64;
    if (now - created).abs() > MAX_TIMESTAMP_SKEW_SECS {
        return Err(SigningError::TimestampExpired);
    }

    // 4. Check nonce freshness
    if !nonce_cache.check_and_insert(&nonce) {
        return Err(SigningError::NonceReplay);
    }

    // 5. Compute content digest
    let content_digest = compute_content_digest(body);

    // 6. Build signature base
    let sig_params = build_signature_params(created, &nonce, &keyid);
    let sig_base = build_signature_base(method, path, &content_digest, &sig_params);

    // 7. Select keys to try (filter by keyid)
    let keys_to_try: Vec<&(String, UnparsedPublicKey<Vec<u8>>)> = config
        .public_keys
        .iter()
        .filter(|(id, _)| id == &keyid)
        .collect();

    // If no keys match the keyid, try all keys as fallback
    let keys_to_try = if keys_to_try.is_empty() {
        config.public_keys.iter().collect()
    } else {
        keys_to_try
    };

    if keys_to_try.is_empty() {
        return Err(SigningError::VerificationFailed);
    }

    // 8. Try each candidate key
    for (_, key) in &keys_to_try {
        if key.verify(sig_base.as_bytes(), &signature_bytes).is_ok() {
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

    /// Derives the key_id from a keypair (truncated SHA-256 of public key bytes).
    fn derive_key_id(keypair: &Ed25519KeyPair) -> String {
        let pub_key_bytes = keypair.public_key().as_ref();
        let mut hasher = Sha256::new();
        hasher.update(pub_key_bytes);
        let key_hash = hasher.finalize();
        key_hash[..8]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }

    /// Helper to produce RFC 9421 signature headers for test requests.
    ///
    /// Returns `(signature_input_value, signature_value)`.
    fn sign_request(
        keypair: &Ed25519KeyPair,
        method: &str,
        path: &str,
        body: &[u8],
        timestamp: i64,
        nonce: &str,
    ) -> (String, String) {
        let digest = compute_content_digest(body);
        let key_id = derive_key_id(keypair);

        let sig_params = build_signature_params(timestamp, nonce, &key_id);
        let sig_base = build_signature_base(method, path, &digest, &sig_params);
        let sig = keypair.sign(sig_base.as_bytes());
        let sig_b64 = BASE64.encode(sig.as_ref());

        let signature_input = format!("sig1={}", sig_params);
        let signature = format!("sig1=:{}:", sig_b64);

        (signature_input, signature)
    }

    /// Returns the current Unix timestamp as i64.
    fn now_ts() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Builds an `http::HeaderMap` with RFC 9421 signing headers.
    fn build_headers(signature_input: &str, signature: &str) -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert("signature-input", signature_input.parse().unwrap());
        headers.insert("signature", signature.parse().unwrap());
        headers
    }

    /// Creates a `SigningConfig` from raw public key bytes with the proper derived key_id.
    fn config_from_keypair(keypair: &Ed25519KeyPair, pub_key: &[u8]) -> SigningConfig {
        let key_id = derive_key_id(keypair);
        SigningConfig {
            public_keys: vec![(
                key_id,
                UnparsedPublicKey::new(&signature::ED25519, pub_key.to_vec()),
            )],
        }
    }

    /// Creates a `SigningConfig` from raw public key bytes with an arbitrary key_id.
    fn config_from_raw(public_key: &[u8]) -> SigningConfig {
        SigningConfig {
            public_keys: vec![(
                "test-key".to_string(),
                UnparsedPublicKey::new(&signature::ED25519, public_key.to_vec()),
            )],
        }
    }

    // --- Unit tests for new parsing/building functions ---

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
    fn test_parse_signature_input_valid() {
        let input = "sig1=(\"@method\" \"@path\" \"content-digest\");created=1709000000;nonce=\"abc123\";keyid=\"6a3b42c10443f618\";alg=\"ed25519\"";
        let (created, nonce, keyid) = parse_signature_input(input).unwrap();
        assert_eq!(created, 1709000000);
        assert_eq!(nonce, "abc123");
        assert_eq!(keyid, "6a3b42c10443f618");
    }

    #[test]
    fn test_parse_signature_input_missing_sig1_prefix() {
        let input = "(\"@method\" \"@path\" \"content-digest\");created=1709000000;nonce=\"abc123\";keyid=\"key1\";alg=\"ed25519\"";
        assert!(matches!(
            parse_signature_input(input),
            Err(SigningError::InvalidSignatureInput)
        ));
    }

    #[test]
    fn test_parse_signature_input_wrong_components() {
        let input = "sig1=(\"@method\" \"@path\");created=1709000000;nonce=\"abc123\";keyid=\"key1\";alg=\"ed25519\"";
        assert!(matches!(
            parse_signature_input(input),
            Err(SigningError::InvalidSignatureInput)
        ));
    }

    #[test]
    fn test_parse_signature_input_missing_created() {
        let input = "sig1=(\"@method\" \"@path\" \"content-digest\");nonce=\"abc123\";keyid=\"key1\";alg=\"ed25519\"";
        assert!(matches!(
            parse_signature_input(input),
            Err(SigningError::InvalidSignatureInput)
        ));
    }

    #[test]
    fn test_parse_signature_input_wrong_alg() {
        let input = "sig1=(\"@method\" \"@path\" \"content-digest\");created=1709000000;nonce=\"abc123\";keyid=\"key1\";alg=\"rsa\"";
        assert!(matches!(
            parse_signature_input(input),
            Err(SigningError::InvalidSignatureInput)
        ));
    }

    #[test]
    fn test_parse_signature_valid() {
        // Use a known base64 value
        let sig_bytes = vec![1u8, 2, 3, 4, 5];
        let b64 = BASE64.encode(&sig_bytes);
        let header = format!("sig1=:{}:", b64);
        let parsed = parse_signature(&header).unwrap();
        assert_eq!(parsed, sig_bytes);
    }

    #[test]
    fn test_parse_signature_missing_prefix() {
        assert!(matches!(
            parse_signature("bad=:AQID:"),
            Err(SigningError::InvalidSignature)
        ));
    }

    #[test]
    fn test_parse_signature_missing_trailing_colon() {
        assert!(matches!(
            parse_signature("sig1=:AQID"),
            Err(SigningError::InvalidSignature)
        ));
    }

    // --- Integration tests for verify_request_signature ---

    #[test]
    fn test_valid_signature() {
        let (keypair, pub_key) = test_keypair();
        let config = config_from_keypair(&keypair, &pub_key);
        let nonce_cache = NonceCache::new();

        let ts = now_ts();
        let body = b"hello world";
        let (sig_input, sig) = sign_request(&keypair, "POST", "/plugins", body, ts, "nonce-1");
        let headers = build_headers(&sig_input, &sig);

        let result =
            verify_request_signature("POST", "/plugins", body, &headers, &config, &nonce_cache);
        assert!(result.is_ok(), "Valid signature should verify: {:?}", result);
    }

    #[test]
    fn test_valid_signature_keyid_fallback() {
        // When keyid doesn't match any config key_id, falls back to trying all keys
        let (keypair, pub_key) = test_keypair();
        let config = config_from_raw(&pub_key); // Uses "test-key" as key_id, won't match derived keyid
        let nonce_cache = NonceCache::new();

        let ts = now_ts();
        let body = b"hello world";
        let (sig_input, sig) = sign_request(&keypair, "POST", "/plugins", body, ts, "nonce-fb");
        let headers = build_headers(&sig_input, &sig);

        let result =
            verify_request_signature("POST", "/plugins", body, &headers, &config, &nonce_cache);
        assert!(
            result.is_ok(),
            "Valid signature should verify with keyid fallback: {:?}",
            result
        );
    }

    #[test]
    fn test_expired_timestamp() {
        let (keypair, pub_key) = test_keypair();
        let config = config_from_keypair(&keypair, &pub_key);
        let nonce_cache = NonceCache::new();

        let ts = now_ts() - 600; // 10 minutes ago — well past the 5-minute window
        let body = b"payload";
        let (sig_input, sig) = sign_request(&keypair, "POST", "/api", body, ts, "nonce-expired");
        let headers = build_headers(&sig_input, &sig);

        let result =
            verify_request_signature("POST", "/api", body, &headers, &config, &nonce_cache);
        assert!(matches!(result, Err(SigningError::TimestampExpired)));
    }

    #[test]
    fn test_replayed_nonce() {
        let (keypair, pub_key) = test_keypair();
        let config = config_from_keypair(&keypair, &pub_key);
        let nonce_cache = NonceCache::new();

        let ts = now_ts();
        let body = b"data";
        let (sig_input, sig) = sign_request(&keypair, "POST", "/test", body, ts, "same-nonce");
        let headers = build_headers(&sig_input, &sig);

        // First call should succeed
        let result =
            verify_request_signature("POST", "/test", body, &headers, &config, &nonce_cache);
        assert!(result.is_ok(), "First use of nonce should succeed");

        // Second call with same nonce should fail
        let ts2 = now_ts();
        let (sig_input2, sig2) =
            sign_request(&keypair, "POST", "/test", body, ts2, "same-nonce");
        let headers2 = build_headers(&sig_input2, &sig2);
        let result2 =
            verify_request_signature("POST", "/test", body, &headers2, &config, &nonce_cache);
        assert!(matches!(result2, Err(SigningError::NonceReplay)));
    }

    #[test]
    fn test_wrong_key() {
        let (keypair_a, _pub_key_a) = test_keypair();
        let (_keypair_b, pub_key_b) = test_keypair();
        // Sign with keypair A but verify with keypair B's public key
        let config = config_from_keypair(&_keypair_b, &pub_key_b);
        let nonce_cache = NonceCache::new();

        let ts = now_ts();
        let body = b"secret";
        let (sig_input, sig) =
            sign_request(&keypair_a, "POST", "/path", body, ts, "nonce-wrong");
        let headers = build_headers(&sig_input, &sig);

        let result =
            verify_request_signature("POST", "/path", body, &headers, &config, &nonce_cache);
        assert!(matches!(result, Err(SigningError::VerificationFailed)));
    }

    #[test]
    fn test_missing_headers() {
        let (_keypair, pub_key) = test_keypair();
        let config = config_from_raw(&pub_key);

        // Missing signature-input
        {
            let nonce_cache = NonceCache::new();
            let mut headers = http::HeaderMap::new();
            headers.insert("signature", "sig1=:AQID:".parse().unwrap());
            let result =
                verify_request_signature("GET", "/", b"", &headers, &config, &nonce_cache);
            assert!(
                matches!(result, Err(SigningError::MissingHeader(ref h)) if h == "signature-input"),
                "Expected MissingHeader(signature-input), got: {:?}",
                result
            );
        }

        // Missing signature
        {
            let nonce_cache = NonceCache::new();
            let mut headers = http::HeaderMap::new();
            headers.insert(
                "signature-input",
                "sig1=(\"@method\" \"@path\" \"content-digest\");created=12345;nonce=\"n\";keyid=\"k\";alg=\"ed25519\""
                    .parse()
                    .unwrap(),
            );
            let result =
                verify_request_signature("GET", "/", b"", &headers, &config, &nonce_cache);
            assert!(
                matches!(result, Err(SigningError::MissingHeader(ref h)) if h == "signature"),
                "Expected MissingHeader(signature), got: {:?}",
                result
            );
        }
    }

    #[test]
    fn test_tampered_body() {
        let (keypair, pub_key) = test_keypair();
        let config = config_from_keypair(&keypair, &pub_key);
        let nonce_cache = NonceCache::new();

        let ts = now_ts();
        let original_body = b"original content";
        let tampered_body = b"tampered content";
        let (sig_input, sig) =
            sign_request(&keypair, "PUT", "/resource", original_body, ts, "nonce-tamper");
        let headers = build_headers(&sig_input, &sig);

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
        assert!(
            d1.starts_with("sha-256=:"),
            "Digest should have standard prefix"
        );
        assert!(d1.ends_with(':'), "Digest should end with colon");
    }

    #[test]
    fn test_content_digest_empty_body() {
        let digest = compute_content_digest(b"");
        assert!(
            digest.starts_with("sha-256=:"),
            "Empty body digest should have standard prefix"
        );
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
