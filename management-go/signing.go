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

// signRequest adds RFC 9421 HTTP Message Signature headers to an HTTP request.
// The signature format matches the gap-server's verification in signing.rs.
//
// Headers set:
//   - Content-Digest: sha-256=:BASE64:
//   - Signature-Input: sig1=("@method" "@path" "content-digest");created=...;nonce="...";keyid="...";alg="ed25519"
//   - Signature: sig1=:BASE64SIGNATURE:
func (c *Client) signRequest(req *http.Request, body []byte) error {
	created := time.Now().Unix()

	nonce, err := generateNonce()
	if err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	contentDigest := computeContentDigest(body)

	pubKey := c.signingKey.Public().(ed25519.PublicKey)
	keyID := computeKeyID(pubKey)

	sigParams := buildSignatureParams(created, nonce, keyID)
	sigBase := buildSignatureBase(req.Method, req.URL.Path, contentDigest, sigParams)

	sig := ed25519.Sign(c.signingKey, []byte(sigBase))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	req.Header.Set("Content-Digest", contentDigest)
	req.Header.Set("Signature-Input", "sig1="+sigParams)
	req.Header.Set("Signature", "sig1=:"+sigB64+":")

	return nil
}

// buildSignatureParams constructs the RFC 9421 signature-params component.
// Format: ("@method" "@path" "content-digest");created=UNIX;nonce="HEX";keyid="HEX";alg="ed25519"
func buildSignatureParams(created int64, nonce, keyid string) string {
	return fmt.Sprintf(
		`("@method" "@path" "content-digest");created=%d;nonce="%s";keyid="%s";alg="ed25519"`,
		created, nonce, keyid,
	)
}

// buildSignatureBase constructs the RFC 9421 signature base string that is signed/verified.
// Format must match gap-server/src/signing.rs exactly:
//
//	"@method": METHOD
//	"@path": PATH
//	"content-digest": DIGEST
//	"@signature-params": PARAMS
func buildSignatureBase(method, path, contentDigest, signatureParams string) string {
	return fmt.Sprintf(
		"\"@method\": %s\n\"@path\": %s\n\"content-digest\": %s\n\"@signature-params\": %s",
		method, path, contentDigest, signatureParams,
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
