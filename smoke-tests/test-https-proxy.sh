#!/bin/bash
set -e

# HTTPS Proxy Smoke Test
# Tests the proxy's TLS layer using homebrew curl with OpenSSL

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log_info "====================================="
log_info "HTTPS Proxy Smoke Test"
log_info "====================================="
echo ""

# Check for homebrew curl
CURL="/opt/homebrew/opt/curl/bin/curl"
if [ ! -x "$CURL" ]; then
    log_error "Homebrew curl not found at $CURL"
    echo "Install with: brew install curl"
    exit 1
fi

# Verify it has OpenSSL (not LibreSSL)
log_step "Verifying homebrew curl has OpenSSL"
CURL_VERSION=$($CURL --version)
if echo "$CURL_VERSION" | grep -q "OpenSSL"; then
    SSL_VERSION=$(echo "$CURL_VERSION" | grep "OpenSSL" | head -1)
    log_success "Found: $SSL_VERSION"
else
    log_error "Homebrew curl must use OpenSSL, not LibreSSL"
    echo "$CURL_VERSION"
    exit 1
fi

# Binaries
GAP_BIN="$WORKSPACE_ROOT/target/release/gap"
GAP_SERVER_BIN="$WORKSPACE_ROOT/target/release/gap-server"

# Build if needed
if [ ! -x "$GAP_SERVER_BIN" ]; then
    log_step "Building release binaries"
    cd "$WORKSPACE_ROOT"
    if cargo build --release -p gap -p gap-server 2>&1 | tail -5; then
        log_success "Binaries built successfully"
    else
        log_error "Failed to build binaries"
        exit 1
    fi
fi

# Create temp directory
TEST_DIR=$(mktemp -d)
log_step "Created test directory: $TEST_DIR"

cleanup() {
    log_step "Cleanup: Stopping server and removing temp files"
    [ -n "$SERVER_PID" ] && kill $SERVER_PID 2>/dev/null || true
    rm -rf "$TEST_DIR"
    log_success "Cleanup complete"
}
trap cleanup EXIT

# Start server on unique ports
API_PORT=19180
PROXY_PORT=19543
log_step "Starting gap-server on ports API=$API_PORT PROXY=$PROXY_PORT"
$GAP_SERVER_BIN --data-dir "$TEST_DIR" --api-port $API_PORT --proxy-port $PROXY_PORT > "$TEST_DIR/server.log" 2>&1 &
SERVER_PID=$!
log_info "Server PID: $SERVER_PID"
sleep 2

# Check server started
if ! kill -0 $SERVER_PID 2>/dev/null; then
    log_error "Server failed to start:"
    cat "$TEST_DIR/server.log"
    exit 1
fi
log_success "Server started successfully"

# Initialize
log_step "Initializing server"
PASSWORD_HASH=$(echo -n "testpassword" | shasum -a 512 | awk '{print $1}')
$CURL -s -k -X POST https://localhost:$API_PORT/init \
    -H "Content-Type: application/json" \
    -d "{\"password_hash\": \"$PASSWORD_HASH\"}" > /dev/null
log_success "Server initialized"

# Get CA cert path
CA_CERT="$HOME/Library/Application Support/gap/ca.crt"
if [ ! -f "$CA_CERT" ]; then
    log_error "CA certificate not found at: $CA_CERT"
    exit 1
fi
log_success "CA certificate found: $CA_CERT"

# Create token
log_step "Creating authentication token"
TOKEN_RESPONSE=$($CURL -s -k -X POST https://localhost:$API_PORT/tokens \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $PASSWORD_HASH" \
    -d '{}')
TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
    log_error "Failed to create token"
    echo "Response: $TOKEN_RESPONSE"
    exit 1
fi
log_success "Token created: ${TOKEN:0:20}..."

# Test HTTPS proxy
log_step "Testing HTTPS proxy connection to example.com"
RESPONSE=$($CURL -s \
    --proxy-cacert "$CA_CERT" \
    -x https://localhost:$PROXY_PORT \
    --proxy-header "Proxy-Authorization: Bearer $TOKEN" \
    --cacert "$CA_CERT" \
    https://example.com/ 2>&1)

CURL_EXIT=$?

if [ $CURL_EXIT -ne 0 ]; then
    log_error "curl failed with exit code $CURL_EXIT"
    echo "Response: $RESPONSE"
    echo ""
    echo "Server log:"
    cat "$TEST_DIR/server.log"
    exit 1
fi

if echo "$RESPONSE" | grep -q "Example Domain"; then
    log_success "HTTPS proxy working correctly"
    echo ""
    log_info "====================================="
    log_info "ALL TESTS PASSED"
    log_info "====================================="
    echo ""
    echo "Summary:"
    echo "  ✓ Homebrew curl with OpenSSL verified"
    echo "  ✓ Server started and initialized"
    echo "  ✓ CA certificate generated"
    echo "  ✓ Authentication token created"
    echo "  ✓ HTTPS proxy successfully proxied request"
    echo ""
    log_success "HTTPS proxy smoke test completed successfully"
    exit 0
else
    log_error "Unexpected response from proxy"
    echo "Response: $RESPONSE"
    exit 1
fi
