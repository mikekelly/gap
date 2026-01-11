#!/usr/bin/env bash
# Sign ACP binaries for macOS Keychain access
# Default: Uses a self-signed certificate for local development
# Production: Uses Developer ID with hardened runtime (--production flag)

set -e

# Parse arguments
PRODUCTION_MODE=false
if [[ "$1" == "--production" ]]; then
    PRODUCTION_MODE=true
fi

# Certificate names
DEV_CERT_NAME="ACP Development"
PROD_CERT_NAME="Developer ID Application"
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

# Determine which certificate to use
if [[ "$PRODUCTION_MODE" == true ]]; then
    CERT_NAME="$PROD_CERT_NAME"
    log_info "Production mode: using Developer ID"

    # Check if Developer ID certificate exists
    if ! security find-identity -v -p codesigning | grep -q "$PROD_CERT_NAME"; then
        log_error "Developer ID certificate not found in keychain"
        log_error "Please install a valid Developer ID Application certificate"
        log_error "Visit: https://developer.apple.com/account/resources/certificates/list"
        exit 1
    fi

    log_info "Found Developer ID certificate"
else
    CERT_NAME="$DEV_CERT_NAME"
    log_info "Development mode: using self-signed certificate"

    # Check if certificate already exists in default keychain
    if security find-identity -v -p codesigning | grep -q "$DEV_CERT_NAME"; then
        log_info "Certificate '$DEV_CERT_NAME' already exists"
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
fi

# Sign the binaries
if [[ "$PRODUCTION_MODE" == true ]]; then
    log_info "Signing with hardened runtime and secure timestamp..."

    # Create entitlements file for Homebrew OpenSSL compatibility
    # The disable-library-validation entitlement allows loading libraries
    # with different Team IDs (like Homebrew's OpenSSL)
    # The keychain-access-groups entitlement ensures secrets survive binary re-signing
    ENTITLEMENTS_FILE=$(mktemp)
    cat > "$ENTITLEMENTS_FILE" <<ENTITLEMENTS
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>3R44BTH39W.com.acp.secrets</string>
    </array>
    <key>keychain-access-groups</key>
    <array>
        <string>3R44BTH39W.com.acp.secrets</string>
    </array>
</dict>
</plist>
ENTITLEMENTS

    log_info "Signing acp-server..."
    codesign --sign "$CERT_NAME" \
        --force \
        --options runtime \
        --timestamp \
        --entitlements "$ENTITLEMENTS_FILE" \
        target/release/acp-server

    log_info "Signing acp..."
    codesign --sign "$CERT_NAME" \
        --force \
        --options runtime \
        --timestamp \
        --entitlements "$ENTITLEMENTS_FILE" \
        target/release/acp

    rm -f "$ENTITLEMENTS_FILE"
else
    # Development mode: no hardened runtime
    # Note: We don't use --options runtime (hardened runtime) for development because it requires
    # all loaded libraries to have matching team IDs. Since we may link against
    # Homebrew's OpenSSL, this could fail. Hardened runtime is only needed for
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
fi

# Verify signatures
log_info "Verifying signatures..."
codesign --verify --verbose target/release/acp-server
codesign --verify --verbose target/release/acp

# Enhanced verification for production builds
if [[ "$PRODUCTION_MODE" == true ]]; then
    log_info "Performing detailed signature verification..."

    echo ""
    log_info "acp-server signature details:"
    codesign --display --verbose=4 target/release/acp-server

    echo ""
    log_info "acp signature details:"
    codesign --display --verbose=4 target/release/acp

    # Verify hardened runtime is enabled
    echo ""
    log_info "Verifying hardened runtime..."
    if codesign --display --verbose target/release/acp-server 2>&1 | grep -q "runtime"; then
        log_info "✓ Hardened runtime enabled on acp-server"
    else
        log_error "✗ Hardened runtime NOT enabled on acp-server"
        exit 1
    fi

    if codesign --display --verbose target/release/acp 2>&1 | grep -q "runtime"; then
        log_info "✓ Hardened runtime enabled on acp"
    else
        log_error "✗ Hardened runtime NOT enabled on acp"
        exit 1
    fi
fi

echo ""
log_info "Binaries signed successfully!"
echo ""

if [[ "$PRODUCTION_MODE" == true ]]; then
    echo "Production build signed with Developer ID and hardened runtime."
    echo ""
    echo "Next steps:"
    echo "  1. Notarize the binaries:"
    echo "     xcrun notarytool submit <archive.zip> --keychain-profile \"notarytool-profile\" --wait"
    echo "  2. Staple the notarization ticket:"
    echo "     xcrun stapler staple target/release/acp-server"
    echo "     xcrun stapler staple target/release/acp"
    echo "  3. Verify notarization:"
    echo "     spctl -a -v target/release/acp-server"
    echo ""
else
    echo "Development build signed with self-signed certificate."
    echo ""
    echo "Next steps:"
    echo "  1. Run: ./target/release/acp-server --data-dir /tmp/acp-test"
    echo "  2. If blocked by Gatekeeper:"
    echo "     - Go to System Settings → Privacy & Security"
    echo "     - Click 'Open Anyway' next to the blocked app message"
    echo "  3. On first Keychain access, click 'Always Allow' when prompted"
    echo ""
    echo "After authorization, the binaries will have full Keychain access."
fi
