#!/bin/bash
# Generate test CA fixtures for no-bootstrap mode testing.
# Produces a root CA and an intermediate CA (signed by root) as PEM files.
set -e

FIXTURES_DIR="$(dirname "$0")/fixtures"
mkdir -p "$FIXTURES_DIR"

# --- Root CA ---
openssl ecparam -name prime256v1 -genkey -noout -out "$FIXTURES_DIR/test-root-ca.key"
openssl req -new -x509 -key "$FIXTURES_DIR/test-root-ca.key" -out "$FIXTURES_DIR/test-root-ca.crt" \
    -days 3650 -subj "/CN=GAP Test Root CA/O=GAP Testing" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# --- Intermediate CA (signed by root) ---
openssl ecparam -name prime256v1 -genkey -noout -out "$FIXTURES_DIR/test-intermediate-ec.key"

# Convert to PKCS#8 format (required by rcgen/rustls)
openssl pkcs8 -topk8 -nocrypt \
    -in "$FIXTURES_DIR/test-intermediate-ec.key" \
    -out "$FIXTURES_DIR/test-intermediate.key"

# Create CSR for intermediate
openssl req -new -key "$FIXTURES_DIR/test-intermediate.key" \
    -out "$FIXTURES_DIR/test-intermediate.csr" \
    -subj "/CN=GAP Test Intermediate CA/O=GAP Testing"

# Sign intermediate cert with root CA
openssl x509 -req -in "$FIXTURES_DIR/test-intermediate.csr" \
    -CA "$FIXTURES_DIR/test-root-ca.crt" -CAkey "$FIXTURES_DIR/test-root-ca.key" \
    -CAcreateserial -out "$FIXTURES_DIR/test-intermediate.crt" \
    -days 3650 \
    -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign")

# Create chain file (intermediate cert only — root is NOT included because
# clients already have it in their trust store)
cp "$FIXTURES_DIR/test-intermediate.crt" "$FIXTURES_DIR/test-intermediate-chain.pem"

# Encryption key (unchanged)
openssl rand -hex 32 > "$FIXTURES_DIR/test-encryption.key"

# Clean up temp files
rm -f "$FIXTURES_DIR/test-intermediate-ec.key" "$FIXTURES_DIR/test-intermediate.csr" "$FIXTURES_DIR"/*.srl

echo "Test fixtures generated in $FIXTURES_DIR/"
echo "  test-root-ca.crt             — Root CA certificate (PEM, for client trust)"
echo "  test-root-ca.key             — Root CA private key (PEM)"
echo "  test-intermediate.crt        — Intermediate CA certificate (PEM)"
echo "  test-intermediate.key        — Intermediate CA private key (PEM, PKCS#8)"
echo "  test-intermediate-chain.pem  — Chain file for GAP_CA_CERT_CHAIN"
echo "  test-encryption.key          — Encryption key (hex for GAP_ENCRYPTION_KEY)"
