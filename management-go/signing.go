package gap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// WithSigningKey sets the Ed25519 private key used for HTTP request signing.
// When set, every request will include Ed25519 signature headers instead of
// passcode-based authentication. Mutually exclusive with WithPasscode
// conceptually — use one or the other.
func WithSigningKey(key ed25519.PrivateKey) Option {
	return func(c *Client) {
		c.signingKey = key
	}
}

// LoadSigningKey reads PEM-encoded PKCS8 Ed25519 private key bytes and returns
// the parsed key. Use with WithSigningKey:
//
//	pemBytes, err := os.ReadFile("key.pem")
//	key, err := gap.LoadSigningKey(pemBytes)
//	client := gap.NewClient(url, gap.WithSigningKey(key))
func LoadSigningKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s (expected PRIVATE KEY)", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not Ed25519 (got %T)", key)
	}
	return edKey, nil
}

// signRequest adds Ed25519 signature headers to an HTTP request.
// The signature format matches the gap-server's verification in signing.rs.
//
// Headers set:
//   - X-Gap-Timestamp: Unix seconds when the request was signed
//   - X-Gap-Nonce: random 32-char hex string (16 bytes)
//   - Content-Digest: sha-256=:BASE64:
//   - X-Gap-Signature: base64-encoded Ed25519 signature over canonical string
//   - X-Gap-Key-Id: truncated SHA-256 of raw public key bytes (16 hex chars)
func (c *Client) signRequest(req *http.Request, body []byte) error {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	nonce, err := generateNonce()
	if err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	contentDigest := computeContentDigest(body)
	canonical := buildCanonicalString(req.Method, req.URL.Path, contentDigest, timestamp, nonce)

	sig := ed25519.Sign(c.signingKey, []byte(canonical))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	pubKey := c.signingKey.Public().(ed25519.PublicKey)
	keyID := computeKeyID(pubKey)

	req.Header.Set("X-Gap-Timestamp", timestamp)
	req.Header.Set("X-Gap-Nonce", nonce)
	req.Header.Set("Content-Digest", contentDigest)
	req.Header.Set("X-Gap-Signature", sigB64)
	req.Header.Set("X-Gap-Key-Id", keyID)

	return nil
}

// buildCanonicalString constructs the string that is signed/verified.
// Format must match gap-server/src/signing.rs exactly:
//
//	@method: {METHOD}
//	@path: {PATH}
//	content-digest: {DIGEST}
//	x-gap-timestamp: {TIMESTAMP}
//	x-gap-nonce: {NONCE}
func buildCanonicalString(method, path, contentDigest, timestamp, nonce string) string {
	return fmt.Sprintf(
		"@method: %s\n@path: %s\ncontent-digest: %s\nx-gap-timestamp: %s\nx-gap-nonce: %s",
		method, path, contentDigest, timestamp, nonce,
	)
}

// computeContentDigest computes SHA-256 of body in the HTTP Digest format:
// sha-256=:BASE64_ENCODED_HASH:
// Matches gap-server/src/signing.rs compute_content_digest().
func computeContentDigest(body []byte) string {
	h := sha256.Sum256(body)
	encoded := base64.StdEncoding.EncodeToString(h[:])
	return "sha-256=:" + encoded + ":"
}

// computeKeyID derives a key identifier from an Ed25519 public key.
// Returns the first 8 bytes of SHA-256(raw_public_key_bytes) as hex (16 chars).
// Matches gap-server/src/signing.rs key_id derivation.
func computeKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256([]byte(pub))
	return hex.EncodeToString(h[:8])
}

// generateNonce produces a cryptographically random 32-character hex string (16 bytes).
func generateNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
