#!/usr/bin/env bash
# Notarize macOS binaries with Apple
#
# This script submits signed binaries to Apple's notarization service and staples
# the notarization ticket to the binary. Required for distribution outside the App Store.
#
# REQUIREMENTS:
#   - Binary must be signed with Developer ID certificate (use --production flag with macos-sign.sh)
#   - Notarization credentials must be configured in keychain profile
#
# SETUP:
#   Create a keychain profile with your Apple ID credentials:
#   xcrun notarytool store-credentials "notarytool-profile" \
#     --apple-id "your-apple-id@example.com" \
#     --team-id "YOUR_TEAM_ID" \
#     --password "app-specific-password"
#
# USAGE:
#   # Using keychain profile from environment variable:
#   export NOTARIZE_KEYCHAIN_PROFILE="notarytool-profile"
#   ./macos-notarize.sh path/to/binary
#
#   # Using keychain profile from command line:
#   ./macos-notarize.sh path/to/binary --keychain-profile "notarytool-profile"
#
#   # Show this help:
#   ./macos-notarize.sh --help
#
# EXAMPLES:
#   # Notarize acp-server binary:
#   export NOTARIZE_KEYCHAIN_PROFILE="notarytool-profile"
#   ./macos-notarize.sh target/release/acp-server
#
#   # Notarize both ACP binaries:
#   for binary in target/release/acp target/release/acp-server; do
#     ./macos-notarize.sh "$binary" --keychain-profile "notarytool-profile"
#   done
#
# NOTES:
#   - Notarization typically takes 2-5 minutes
#   - The --wait flag keeps the script running until notarization completes
#   - Failed notarization will show Apple's detailed error response
#   - Successfully notarized binaries will have the ticket stapled
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Show usage
show_usage() {
    echo "Usage: $0 <binary-path> [--keychain-profile <profile-name>]"
    echo ""
    echo "Notarize a signed macOS binary with Apple's notarization service."
    echo ""
    echo "Arguments:"
    echo "  <binary-path>             Path to the signed binary to notarize"
    echo "  --keychain-profile NAME   Keychain profile with notarization credentials"
    echo "                            (can also be set via NOTARIZE_KEYCHAIN_PROFILE env var)"
    echo ""
    echo "Environment Variables:"
    echo "  NOTARIZE_KEYCHAIN_PROFILE  Default keychain profile name"
    echo ""
    echo "Examples:"
    echo "  export NOTARIZE_KEYCHAIN_PROFILE=\"notarytool-profile\""
    echo "  $0 target/release/acp-server"
    echo ""
    echo "  $0 target/release/acp --keychain-profile \"notarytool-profile\""
    echo ""
    exit 0
}

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    log_error "This script only runs on macOS"
    exit 1
fi

# Parse arguments
BINARY_PATH=""
KEYCHAIN_PROFILE="${NOTARIZE_KEYCHAIN_PROFILE:-}"

if [ $# -eq 0 ]; then
    show_usage
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --help|-h)
            show_usage
            ;;
        --keychain-profile)
            if [ -z "$2" ]; then
                log_error "--keychain-profile requires a profile name"
                exit 1
            fi
            KEYCHAIN_PROFILE="$2"
            shift 2
            ;;
        *)
            if [ -z "$BINARY_PATH" ]; then
                BINARY_PATH="$1"
                shift
            else
                log_error "Unexpected argument: $1"
                show_usage
            fi
            ;;
    esac
done

# Validate arguments
if [ -z "$BINARY_PATH" ]; then
    log_error "Binary path is required"
    show_usage
fi

if [ ! -f "$BINARY_PATH" ]; then
    log_error "Binary not found: $BINARY_PATH"
    exit 1
fi

if [ -z "$KEYCHAIN_PROFILE" ]; then
    log_error "Keychain profile not configured"
    log_error "Set NOTARIZE_KEYCHAIN_PROFILE environment variable or use --keychain-profile flag"
    log_error ""
    log_error "To create a keychain profile, run:"
    log_error "  xcrun notarytool store-credentials \"notarytool-profile\" \\"
    log_error "    --apple-id \"your-apple-id@example.com\" \\"
    log_error "    --team-id \"YOUR_TEAM_ID\" \\"
    log_error "    --password \"app-specific-password\""
    exit 1
fi

# Get absolute path to binary
BINARY_PATH=$(cd "$(dirname "$BINARY_PATH")" && pwd)/$(basename "$BINARY_PATH")
BINARY_NAME=$(basename "$BINARY_PATH")

log_info "Notarizing: $BINARY_PATH"
log_info "Keychain profile: $KEYCHAIN_PROFILE"
echo ""

# Create temporary directory for zip
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Create zip archive for notarization
ZIP_PATH="$TEMP_DIR/$BINARY_NAME.zip"
log_info "Creating zip archive..."
ditto -c -k --keepParent "$BINARY_PATH" "$ZIP_PATH"

if [ ! -f "$ZIP_PATH" ]; then
    log_error "Failed to create zip archive"
    exit 1
fi

log_info "Archive created: $ZIP_PATH"
log_info "Archive size: $(du -h "$ZIP_PATH" | cut -f1)"
echo ""

# Submit for notarization
log_info "Submitting to Apple notarization service..."
log_info "This may take 2-5 minutes. Please wait..."
echo ""

set +e
NOTARIZE_OUTPUT=$(xcrun notarytool submit "$ZIP_PATH" \
    --keychain-profile "$KEYCHAIN_PROFILE" \
    --wait 2>&1)
NOTARIZE_EXIT_CODE=$?
set -e

echo "$NOTARIZE_OUTPUT"
echo ""

# Check if notarization succeeded
if [ $NOTARIZE_EXIT_CODE -ne 0 ]; then
    log_error "Notarization failed (exit code: $NOTARIZE_EXIT_CODE)"
    log_error ""
    log_error "Apple's response is shown above."
    log_error ""
    log_error "Common issues:"
    log_error "  - Binary not signed with Developer ID certificate"
    log_error "  - Hardened runtime not enabled (use --production flag with macos-sign.sh)"
    log_error "  - Invalid keychain profile credentials"
    log_error "  - Team ID mismatch"
    exit 1
fi

# Check if notarization was accepted
if echo "$NOTARIZE_OUTPUT" | grep -q "status: Accepted"; then
    log_info "Notarization successful! Status: Accepted"
else
    log_error "Notarization did not complete successfully"
    log_error "Check Apple's response above for details"
    exit 1
fi

echo ""

# Staple the notarization ticket
log_info "Stapling notarization ticket to binary..."
set +e
STAPLE_OUTPUT=$(xcrun stapler staple "$BINARY_PATH" 2>&1)
STAPLE_EXIT_CODE=$?
set -e

echo "$STAPLE_OUTPUT"
echo ""

if [ $STAPLE_EXIT_CODE -ne 0 ]; then
    log_error "Failed to staple notarization ticket (exit code: $STAPLE_EXIT_CODE)"
    log_error "The binary was notarized successfully, but stapling failed"
    log_error "Users will still be able to run the binary if they have an internet connection"
    exit 1
fi

log_info "Notarization ticket stapled successfully!"
echo ""

# Verify the staple
log_info "Verifying stapled ticket..."
set +e
VALIDATE_OUTPUT=$(xcrun stapler validate "$BINARY_PATH" 2>&1)
VALIDATE_EXIT_CODE=$?
set -e

echo "$VALIDATE_OUTPUT"
echo ""

if [ $VALIDATE_EXIT_CODE -ne 0 ]; then
    log_warn "Staple validation returned non-zero exit code, but this may be normal"
fi

# Final success message
echo ""
log_info "========================================="
log_info "NOTARIZATION COMPLETE"
log_info "========================================="
echo ""
echo "Binary: $BINARY_PATH"
echo "Status: Notarized and stapled"
echo ""
echo "Next steps:"
echo "  1. Verify with Gatekeeper:"
echo "     spctl -a -vv -t install \"$BINARY_PATH\""
echo ""
echo "  2. Test on a clean macOS system:"
echo "     - Copy the binary to another Mac"
echo "     - Double-click or run from Terminal"
echo "     - Should run without Gatekeeper warnings"
echo ""
log_info "Binary is ready for distribution!"
