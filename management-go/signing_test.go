package gap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// generateTestKey creates a fresh Ed25519 keypair for testing.
func generateTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	return priv
}

// writePEMKey serializes an Ed25519 private key to PKCS8 PEM.
func writePEMKey(t *testing.T, key ed25519.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
}

func TestComputeContentDigest(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		body := []byte("hello world")
		d1 := computeContentDigest(body)
		d2 := computeContentDigest(body)
		if d1 != d2 {
			t.Errorf("digest not deterministic: %q != %q", d1, d2)
		}
	})

	t.Run("format", func(t *testing.T) {
		digest := computeContentDigest([]byte("test"))
		if digest[:9] != "sha-256=:" {
			t.Errorf("expected prefix sha-256=:, got %q", digest[:9])
		}
		if digest[len(digest)-1] != ':' {
			t.Errorf("expected trailing colon, got %q", digest)
		}
	})

	t.Run("empty body known value", func(t *testing.T) {
		digest := computeContentDigest([]byte{})
		// SHA-256 of empty input: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
		expected := "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
		if digest != expected {
			t.Errorf("empty body digest mismatch:\n  got:  %s\n  want: %s", digest, expected)
		}
	})

	t.Run("matches independent computation", func(t *testing.T) {
		body := []byte("the quick brown fox")
		digest := computeContentDigest(body)

		h := sha256.Sum256(body)
		expected := "sha-256=:" + base64.StdEncoding.EncodeToString(h[:]) + ":"
		if digest != expected {
			t.Errorf("digest mismatch:\n  got:  %s\n  want: %s", digest, expected)
		}
	})
}

func TestBuildCanonicalString(t *testing.T) {
	result := buildCanonicalString("POST", "/plugins", "sha-256=:abc123:", "1709000000", "nonce1")
	expected := "@method: POST\n@path: /plugins\ncontent-digest: sha-256=:abc123:\nx-gap-timestamp: 1709000000\nx-gap-nonce: nonce1"
	if result != expected {
		t.Errorf("canonical string mismatch:\n  got:  %q\n  want: %q", result, expected)
	}
}

func TestComputeKeyID(t *testing.T) {
	key := generateTestKey(t)
	pubKey := key.Public().(ed25519.PublicKey)
	keyID := computeKeyID(pubKey)

	// Should be 16 hex chars (8 bytes of SHA-256)
	if len(keyID) != 16 {
		t.Errorf("key ID length: got %d, want 16", len(keyID))
	}

	// Verify independently
	h := sha256.Sum256([]byte(pubKey))
	expected := hex.EncodeToString(h[:8])
	if keyID != expected {
		t.Errorf("key ID mismatch:\n  got:  %s\n  want: %s", keyID, expected)
	}
}

func TestSignRequest(t *testing.T) {
	key := generateTestKey(t)
	client := &Client{signingKey: key}

	req, _ := http.NewRequest("POST", "http://localhost/plugins", nil)
	body := []byte(`{"name":"test"}`)

	err := client.signRequest(req, body)
	if err != nil {
		t.Fatalf("signRequest failed: %v", err)
	}

	// Verify all headers are set
	ts := req.Header.Get("X-Gap-Timestamp")
	if ts == "" {
		t.Error("missing X-Gap-Timestamp header")
	}
	if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
		t.Errorf("X-Gap-Timestamp not a valid integer: %s", ts)
	}

	nonce := req.Header.Get("X-Gap-Nonce")
	if nonce == "" {
		t.Error("missing X-Gap-Nonce header")
	}
	if len(nonce) != 32 {
		t.Errorf("nonce length: got %d, want 32", len(nonce))
	}
	// Verify nonce is valid hex
	if _, err := hex.DecodeString(nonce); err != nil {
		t.Errorf("nonce is not valid hex: %s", nonce)
	}

	sig := req.Header.Get("X-Gap-Signature")
	if sig == "" {
		t.Error("missing X-Gap-Signature header")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Errorf("signature not valid base64: %v", err)
	}
	if len(sigBytes) != 64 {
		t.Errorf("signature length: got %d bytes, want 64", len(sigBytes))
	}

	keyID := req.Header.Get("X-Gap-Key-Id")
	if keyID == "" {
		t.Error("missing X-Gap-Key-Id header")
	}
	if len(keyID) != 16 {
		t.Errorf("key ID length: got %d, want 16", len(keyID))
	}

	digest := req.Header.Get("Content-Digest")
	if digest == "" {
		t.Error("missing Content-Digest header")
	}
}

func TestSignRequestSignatureVerifiable(t *testing.T) {
	key := generateTestKey(t)
	client := &Client{signingKey: key}

	req, _ := http.NewRequest("POST", "http://localhost/test", nil)
	body := []byte("test body")

	if err := client.signRequest(req, body); err != nil {
		t.Fatalf("signRequest failed: %v", err)
	}

	// Reconstruct what the Rust server does to verify
	ts := req.Header.Get("X-Gap-Timestamp")
	nonce := req.Header.Get("X-Gap-Nonce")
	sig := req.Header.Get("X-Gap-Signature")
	contentDigest := req.Header.Get("Content-Digest")

	canonical := buildCanonicalString("POST", "/test", contentDigest, ts, nonce)

	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}

	pubKey := key.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pubKey, []byte(canonical), sigBytes) {
		t.Error("signature should be verifiable with corresponding public key")
	}
}

func TestSignRequestEmptyBody(t *testing.T) {
	key := generateTestKey(t)
	client := &Client{signingKey: key}

	req, _ := http.NewRequest("GET", "http://localhost/status", nil)
	body := []byte{} // empty body for GET

	if err := client.signRequest(req, body); err != nil {
		t.Fatalf("signRequest failed: %v", err)
	}

	digest := req.Header.Get("Content-Digest")
	if digest == "" {
		t.Error("Content-Digest should be set even for empty body")
	}
	// Should contain SHA-256 of empty
	if digest != "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:" {
		t.Errorf("unexpected empty body digest: %s", digest)
	}
}

func TestLoadSigningKey(t *testing.T) {
	t.Run("valid PEM", func(t *testing.T) {
		key := generateTestKey(t)
		pemBytes := writePEMKey(t, key)

		loaded, err := LoadSigningKey(pemBytes)
		if err != nil {
			t.Fatalf("LoadSigningKey failed: %v", err)
		}

		// Loaded key should produce same public key
		if !loaded.Public().(ed25519.PublicKey).Equal(key.Public()) {
			t.Error("loaded key has different public key")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := LoadSigningKey([]byte("not a pem"))
		if err == nil {
			t.Error("expected error for invalid PEM")
		}
	})

	t.Run("wrong key type", func(t *testing.T) {
		// Create an RSA-like PEM block with wrong type
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: []byte("not a real key"),
		}
		pemBytes := pem.EncodeToMemory(block)
		_, err := LoadSigningKey(pemBytes)
		if err == nil {
			t.Error("expected error for wrong PEM type")
		}
	})

	t.Run("roundtrip sign and verify", func(t *testing.T) {
		key := generateTestKey(t)
		pemBytes := writePEMKey(t, key)

		loaded, err := LoadSigningKey(pemBytes)
		if err != nil {
			t.Fatalf("LoadSigningKey failed: %v", err)
		}

		// Use loaded key to sign, verify with original key's public
		msg := []byte("test message")
		sig := ed25519.Sign(loaded, msg)

		pubKey := key.Public().(ed25519.PublicKey)
		if !ed25519.Verify(pubKey, msg, sig) {
			t.Error("signature from loaded key should verify with original public key")
		}
	})
}

func TestWithSigningKey(t *testing.T) {
	key := generateTestKey(t)
	client := NewClient("http://localhost:9080", WithSigningKey(key))

	if client.signingKey == nil {
		t.Error("signingKey should be set after WithSigningKey")
	}
}

func TestDoRequestWithSigning(t *testing.T) {
	key := generateTestKey(t)

	// Set up a test server that records the request headers
	var receivedHeaders http.Header
	var receivedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		receivedPath = r.URL.Path
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, WithSigningKey(key))
	resp, err := client.doRequest(context.Background(), "POST", "/plugins", nil)
	if err != nil {
		t.Fatalf("doRequest failed: %v", err)
	}
	resp.Body.Close()

	if receivedPath != "/plugins" {
		t.Errorf("path: got %q, want /plugins", receivedPath)
	}

	// Verify signing headers were sent
	if receivedHeaders.Get("X-Gap-Timestamp") == "" {
		t.Error("missing X-Gap-Timestamp in sent request")
	}
	if receivedHeaders.Get("X-Gap-Nonce") == "" {
		t.Error("missing X-Gap-Nonce in sent request")
	}
	if receivedHeaders.Get("X-Gap-Signature") == "" {
		t.Error("missing X-Gap-Signature in sent request")
	}
	if receivedHeaders.Get("X-Gap-Key-Id") == "" {
		t.Error("missing X-Gap-Key-Id in sent request")
	}
	if receivedHeaders.Get("Content-Digest") == "" {
		t.Error("missing Content-Digest in sent request")
	}
}

func TestDoRequestWithSigningVerifiable(t *testing.T) {
	key := generateTestKey(t)
	pubKey := key.Public().(ed25519.PublicKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reconstruct and verify the signature server-side
		ts := r.Header.Get("X-Gap-Timestamp")
		nonce := r.Header.Get("X-Gap-Nonce")
		sig := r.Header.Get("X-Gap-Signature")
		contentDigest := r.Header.Get("Content-Digest")

		canonical := buildCanonicalString(r.Method, r.URL.Path, contentDigest, ts, nonce)
		sigBytes, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			http.Error(w, "bad sig encoding", 400)
			return
		}
		if !ed25519.Verify(pubKey, []byte(canonical), sigBytes) {
			http.Error(w, "signature verification failed", 401)
			return
		}

		// Also verify timestamp is recent
		tsInt, _ := strconv.ParseInt(ts, 10, 64)
		now := time.Now().Unix()
		if abs(now-tsInt) > 300 {
			http.Error(w, "timestamp expired", 401)
			return
		}

		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, WithSigningKey(key))
	resp, err := client.doRequest(context.Background(), "GET", "/status", nil)
	if err != nil {
		t.Fatalf("doRequest failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected 200 from verifying server, got %d", resp.StatusCode)
	}
}

func TestDoSSEWithSigning(t *testing.T) {
	key := generateTestKey(t)

	var receivedHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.Write([]byte("data: test\n\n"))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, WithSigningKey(key))
	resp, err := client.doSSE(context.Background(), "/activity/stream")
	if err != nil {
		t.Fatalf("doSSE failed: %v", err)
	}
	resp.Body.Close()

	// Verify signing headers were sent for SSE requests too
	if receivedHeaders.Get("X-Gap-Timestamp") == "" {
		t.Error("missing X-Gap-Timestamp in SSE request")
	}
	if receivedHeaders.Get("X-Gap-Signature") == "" {
		t.Error("missing X-Gap-Signature in SSE request")
	}
}

func TestDoRequestWithoutSigning(t *testing.T) {
	// Verify that without a signing key, no signing headers are sent
	var receivedHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := NewClient(srv.URL, WithPasscode("test-passcode"))
	resp, err := client.doRequest(context.Background(), "GET", "/status", nil)
	if err != nil {
		t.Fatalf("doRequest failed: %v", err)
	}
	resp.Body.Close()

	// No signing headers should be present
	if receivedHeaders.Get("X-Gap-Timestamp") != "" {
		t.Error("X-Gap-Timestamp should not be set without signing key")
	}
	if receivedHeaders.Get("X-Gap-Signature") != "" {
		t.Error("X-Gap-Signature should not be set without signing key")
	}
	// But Authorization should be present
	if receivedHeaders.Get("Authorization") == "" {
		t.Error("Authorization header should still be set with passcode")
	}
}

// abs returns the absolute value of an int64.
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
