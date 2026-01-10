#!/usr/bin/env bash
# Sign ACP binaries for macOS Keychain access
# Uses a self-signed certificate for local development

set -e

CERT_NAME="ACP Development"
KEYCHAIN_NAME="acp-signing.keychain"
KEYCHAIN_PASSWORD="acp-build"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    log_error "This script only runs on macOS"
    exit 1
fi

# Check if binaries exist
if [[ ! -f "target/release/acp-server" ]] || [[ ! -f "target/release/acp" ]]; then
    log_info "Building release binaries..."
    cargo build --release
fi

# Check if certificate already exists in default keychain
if security find-identity -v -p codesigning | grep -q "$CERT_NAME"; then
    log_info "Certificate '$CERT_NAME' already exists"
else
    log_info "Creating self-signed code signing certificate..."

    # Create temporary directory for cert generation
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT

    # Create certificate config
    cat > "$TEMP_DIR/cert.conf" <<EOF
[req]
distinguished_name = req_dn
prompt = no
[req_dn]
CN = $CERT_NAME
O = ACP Development
[codesign]
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
basicConstraints = critical, CA:false
EOF

    # Generate key and certificate
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$TEMP_DIR/key.pem" \
        -out "$TEMP_DIR/cert.pem" \
        -days 365 -nodes \
        -config "$TEMP_DIR/cert.conf" \
        -extensions codesign 2>/dev/null

    # Import private key and certificate separately
    log_info "Importing certificate to login keychain (you may be prompted for your login password)..."

    # Import the private key
    security import "$TEMP_DIR/key.pem" \
        -k ~/Library/Keychains/login.keychain-db \
        -T /usr/bin/codesign \
        -T /usr/bin/security || {
            log_error "Failed to import private key"
            exit 1
        }

    # Import the certificate
    security import "$TEMP_DIR/cert.pem" \
        -k ~/Library/Keychains/login.keychain-db \
        -T /usr/bin/codesign \
        -T /usr/bin/security || {
            log_error "Failed to import certificate"
            exit 1
        }

    # Trust the certificate for code signing
    log_warn "You may see a prompt to trust the certificate - click 'Always Trust'"
    security add-trusted-cert -d -r trustRoot -p codeSign "$TEMP_DIR/cert.pem" 2>/dev/null || true

    log_info "Certificate created and imported"
fi

# Sign the binaries
# Note: We don't use --options runtime (hardened runtime) because it requires
# all loaded libraries to have matching team IDs. Since we link against
# Homebrew's OpenSSL, this would fail. Hardened runtime is only needed for
# notarization/distribution - for local Keychain access, a basic signature works.
log_info "Signing acp-server..."
codesign --sign "$CERT_NAME" \
    --force \
    --timestamp=none \
    target/release/acp-server

log_info "Signing acp..."
codesign --sign "$CERT_NAME" \
    --force \
    --timestamp=none \
    target/release/acp

# Verify signatures
log_info "Verifying signatures..."
codesign --verify --verbose target/release/acp-server
codesign --verify --verbose target/release/acp

echo ""
log_info "Binaries signed successfully!"
echo ""
echo "Next steps:"
echo "  1. Run: ./target/release/acp-server --data-dir /tmp/acp-test"
echo "  2. If blocked by Gatekeeper:"
echo "     - Go to System Settings → Privacy & Security"
echo "     - Click 'Open Anyway' next to the blocked app message"
echo "  3. On first Keychain access, click 'Always Allow' when prompted"
echo ""
echo "After authorization, the binaries will have full Keychain access."
