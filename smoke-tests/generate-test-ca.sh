#!/bin/bash
# Generate a test CA cert+key for no-bootstrap mode testing.
# Outputs base64-encoded DER values suitable for GAP_CA_CERT_CHAIN/GAP_CA_KEY env vars.
set -e

FIXTURES_DIR="$(dirname "$0")/fixtures"
mkdir -p "$FIXTURES_DIR"

# Generate CA private key (ECDSA P-256 — same as rcgen default)
openssl ecparam -name prime256v1 -genkey -noout -out "$FIXTURES_DIR/test-ca.key"

# Generate self-signed CA certificate (10 years, matching GAP defaults)
openssl req -new -x509 -key "$FIXTURES_DIR/test-ca.key" -out "$FIXTURES_DIR/test-ca.crt" \
    -days 3650 -subj "/CN=GAP Test CA/O=GAP Testing" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# Convert to DER and base64 encode for env vars
openssl x509 -in "$FIXTURES_DIR/test-ca.crt" -outform DER | base64 | tr -d '\n' > "$FIXTURES_DIR/test-ca-cert.b64"
openssl pkcs8 -topk8 -nocrypt -in "$FIXTURES_DIR/test-ca.key" -outform DER | base64 | tr -d '\n' > "$FIXTURES_DIR/test-ca-key.b64"

# Also generate a random encryption key (32 bytes hex-encoded, matching GAP_ENCRYPTION_KEY format)
openssl rand -hex 32 > "$FIXTURES_DIR/test-encryption.key"

echo "Test fixtures generated in $FIXTURES_DIR/"
echo "  test-ca.crt          — CA certificate (PEM)"
echo "  test-ca.key          — CA private key (PEM)"
echo "  test-ca-cert.b64     — CA certificate (base64 DER for GAP_CA_CERT_CHAIN)"
echo "  test-ca-key.b64      — CA private key (base64 DER for GAP_CA_KEY)"
echo "  test-encryption.key  — Encryption key (hex for GAP_ENCRYPTION_KEY)"
