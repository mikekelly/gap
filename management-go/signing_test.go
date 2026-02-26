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
	"strings"
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

func TestBuildSignatureParams(t *testing.T) {
	result := buildSignatureParams(1709000000, "nonce1", "6a3b42c10443f618")
	expected := `("@method" "@path" "content-digest");created=1709000000;nonce="nonce1";keyid="6a3b42c10443f618";alg="ed25519"`
	if result != expected {
		t.Errorf("signature params mismatch:\n  got:  %q\n  want: %q", result, expected)
	}
}

func TestBuildSignatureBase(t *testing.T) {
	params := buildSignatureParams(1709000000, "nonce1", "6a3b42c10443f618")
	result := buildSignatureBase("POST", "/plugins", "sha-256=:abc123:", params)
	expected := "\"@method\": POST\n\"@path\": /plugins\n\"content-digest\": sha-256=:abc123:\n\"@signature-params\": " + params
	if result != expected {
		t.Errorf("signature base mismatch:\n  got:  %q\n  want: %q", result, expected)
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

	// Verify Signature-Input is set and starts with sig1=(
	sigInput := req.Header.Get("Signature-Input")
	if sigInput == "" {
		t.Error("missing Signature-Input header")
	}
	if !strings.HasPrefix(sigInput, "sig1=(") {
		t.Errorf("Signature-Input should start with sig1=(, got %q", sigInput)
	}

	// Verify Signature is set, starts with sig1=: and ends with :
	sigHeader := req.Header.Get("Signature")
	if sigHeader == "" {
		t.Error("missing Signature header")
	}
	if !strings.HasPrefix(sigHeader, "sig1=:") {
		t.Errorf("Signature should start with sig1=:, got %q", sigHeader)
	}
	if sigHeader[len(sigHeader)-1] != ':' {
		t.Errorf("Signature should end with :, got %q", sigHeader)
	}

	// Extract and decode signature bytes, verify length is 64
	sigB64 := sigHeader[len("sig1=:"):]
	sigB64 = sigB64[:len(sigB64)-1]
	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Errorf("signature not valid base64: %v", err)
	}
	if len(sigBytes) != 64 {
		t.Errorf("signature length: got %d bytes, want 64", len(sigBytes))
	}

	// Verify Content-Digest is set
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

	// Extract signature from header
	sigHeader := req.Header.Get("Signature")
	// Strip "sig1=:" prefix and ":" suffix
	sigB64 := sigHeader[len("sig1=:"):]
	sigB64 = sigB64[:len(sigB64)-1]

	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}

	// Reconstruct what the server does to verify
	sigInput := req.Header.Get("Signature-Input")
	// Strip "sig1=" prefix to get params
	sigParams := sigInput[len("sig1="):]

	contentDigest := req.Header.Get("Content-Digest")
	sigBase := buildSignatureBase("POST", "/test", contentDigest, sigParams)

	pubKey := key.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pubKey, []byte(sigBase), sigBytes) {
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

	// Verify RFC 9421 signing headers were sent
	if receivedHeaders.Get("Signature-Input") == "" {
		t.Error("missing Signature-Input in sent request")
	}
	if receivedHeaders.Get("Signature") == "" {
		t.Error("missing Signature in sent request")
	}
	if receivedHeaders.Get("Content-Digest") == "" {
		t.Error("missing Content-Digest in sent request")
	}
}

func TestDoRequestWithSigningVerifiable(t *testing.T) {
	key := generateTestKey(t)
	pubKey := key.Public().(ed25519.PublicKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reconstruct and verify the RFC 9421 signature server-side
		sigInput := r.Header.Get("Signature-Input")
		sigHeader := r.Header.Get("Signature")
		contentDigest := r.Header.Get("Content-Digest")

		// Strip "sig1=" prefix from Signature-Input to get params
		sigParams := sigInput[len("sig1="):]

		// Build signature base
		sigBase := buildSignatureBase(r.Method, r.URL.Path, contentDigest, sigParams)

		// Strip "sig1=:" prefix and ":" suffix from Signature
		sigB64 := sigHeader[len("sig1=:") : len(sigHeader)-1]
		sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			http.Error(w, "bad sig encoding", 400)
			return
		}
		if !ed25519.Verify(pubKey, []byte(sigBase), sigBytes) {
			http.Error(w, "signature verification failed", 401)
			return
		}

		// Parse created from sigParams to check timestamp
		// Find ";created=" and extract the number
		createdIdx := strings.Index(sigParams, ";created=")
		if createdIdx < 0 {
			http.Error(w, "missing created", 400)
			return
		}
		rest := sigParams[createdIdx+len(";created="):]
		semicolonIdx := strings.Index(rest, ";")
		createdStr := rest
		if semicolonIdx >= 0 {
			createdStr = rest[:semicolonIdx]
		}
		tsInt, _ := strconv.ParseInt(createdStr, 10, 64)
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

	// Verify RFC 9421 signing headers were sent for SSE requests too
	if receivedHeaders.Get("Signature-Input") == "" {
		t.Error("missing Signature-Input in SSE request")
	}
	if receivedHeaders.Get("Signature") == "" {
		t.Error("missing Signature in SSE request")
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
	if receivedHeaders.Get("Signature-Input") != "" {
		t.Error("Signature-Input should not be set without signing key")
	}
	if receivedHeaders.Get("Signature") != "" {
		t.Error("Signature should not be set without signing key")
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
