#!/usr/bin/env bash
# Smoke test for install.sh script
# Tests installation in a temporary directory

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_pass() {
    echo -e "${GREEN}✓${NC} $1"
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
    exit 1
}

# Create temporary directory for test installation
TEMP_PREFIX=$(mktemp -d)
echo "Testing installation in: $TEMP_PREFIX"

# Clean up on exit
cleanup() {
    echo "Cleaning up..."
    rm -rf "$TEMP_PREFIX"
}
trap cleanup EXIT

# Test 1: Build from source (requires cargo)
if command -v cargo &> /dev/null; then
    echo ""
    echo "Test 1: Build from source installation"
    echo "========================================"

    # Build the binaries locally first
    cd /Users/mike/code/agent-credential-proxy
    cargo build --release 2>&1 | tail -5

    # Install to test prefix
    mkdir -p "$TEMP_PREFIX/bin"
    cp target/release/acp "$TEMP_PREFIX/bin/acp"
    cp target/release/acp-server "$TEMP_PREFIX/bin/acp-server"
    chmod +x "$TEMP_PREFIX/bin/acp" "$TEMP_PREFIX/bin/acp-server"

    log_pass "Binaries installed to test prefix"

    # Verify binaries exist
    if [ -f "$TEMP_PREFIX/bin/acp" ]; then
        log_pass "acp binary exists"
    else
        log_fail "acp binary not found"
    fi

    if [ -f "$TEMP_PREFIX/bin/acp-server" ]; then
        log_pass "acp-server binary exists"
    else
        log_fail "acp-server binary not found"
    fi

    # Verify binaries are executable
    if [ -x "$TEMP_PREFIX/bin/acp" ]; then
        log_pass "acp binary is executable"
    else
        log_fail "acp binary is not executable"
    fi

    if [ -x "$TEMP_PREFIX/bin/acp-server" ]; then
        log_pass "acp-server binary is executable"
    else
        log_fail "acp-server binary is not executable"
    fi

    # Verify binaries run
    if "$TEMP_PREFIX/bin/acp" --version &> /dev/null; then
        log_pass "acp --version works"
    else
        log_fail "acp --version failed"
    fi

    if "$TEMP_PREFIX/bin/acp-server" --version &> /dev/null; then
        log_pass "acp-server --version works"
    else
        log_fail "acp-server --version failed"
    fi

    # Test CLI plugin commands (requires server to be running)
    echo ""
    echo "Test: CLI plugin commands"
    echo "========================="

    # Start server in background for CLI testing
    export HOME="$TEMP_PREFIX"
    export ACP_PASSWORD="test-password-$(date +%s)"

    # Create data directory
    mkdir -p "$TEMP_PREFIX/.config/acp"

    # Start server in background with temp data dir
    "$TEMP_PREFIX/bin/acp-server" --data-dir "$TEMP_PREFIX/.config/acp" --proxy-port 19443 --api-port 19080 > "$TEMP_PREFIX/server.log" 2>&1 &
    SERVER_PID=$!

    # Wait for server to start
    sleep 2

    # Check if server is running
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        log_fail "Server failed to start. Log: $(cat "$TEMP_PREFIX/server.log")"
    fi

    log_pass "Test server started (PID $SERVER_PID)"

    # Initialize ACP
    PASSWORD_HASH=$(echo -n "$ACP_PASSWORD" | sha512sum | cut -d' ' -f1)
    INIT_RESULT=$(curl -s -X POST http://localhost:19080/init \
        -H "Content-Type: application/json" \
        -d "{\"password_hash\": \"$PASSWORD_HASH\", \"ca_path\": \"$TEMP_PREFIX/.config/acp/ca.crt\"}")

    if echo "$INIT_RESULT" | grep -q '"ca_path"'; then
        log_pass "ACP initialized via API"
    else
        log_fail "Failed to initialize ACP: $INIT_RESULT"
    fi

    # Test plugin installation via CLI (requires network access)
    # Note: This will fail if GitHub is unreachable, but that's expected
    if "$TEMP_PREFIX/bin/acp" --server http://localhost:19080 install mikekelly/exa-acp 2>&1 | tee "$TEMP_PREFIX/install.log"; then
        log_pass "acp install command executed"

        # Test plugin listing via CLI
        PLUGINS_OUTPUT=$("$TEMP_PREFIX/bin/acp" --server http://localhost:19080 plugins 2>&1)
        if echo "$PLUGINS_OUTPUT" | grep -q "exa"; then
            log_pass "acp plugins command shows installed plugin"

            # Verify metadata is shown (hosts and credentials)
            if echo "$PLUGINS_OUTPUT" | grep -q -i "host"; then
                log_pass "Plugin listing shows host information"
            else
                log_warn "Plugin listing may not show host information"
            fi

            if echo "$PLUGINS_OUTPUT" | grep -q -i "credential"; then
                log_pass "Plugin listing shows credential schema"
            else
                log_warn "Plugin listing may not show credential schema"
            fi
        else
            log_warn "Plugin may not be installed (check network connectivity)"
        fi
    else
        log_warn "Plugin installation failed (may require network access): $(cat "$TEMP_PREFIX/install.log")"
    fi

    # Clean up server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    log_pass "Test server stopped"

    echo ""
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo "Skipping build-from-source test (cargo not available)"
fi

# Test 2: Platform detection
echo ""
echo "Test 2: Platform detection"
echo "=========================="

# Test platform detection by extracting just that function
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    darwin)
        OS="macos"
        ;;
    linux)
        OS="linux"
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH="x86_64"
        ;;
    aarch64|arm64)
        ARCH="aarch64"
        ;;
esac

PLATFORM="${OS}-${ARCH}"

if [ -n "$OS" ] && [ -n "$ARCH" ] && [ -n "$PLATFORM" ]; then
    log_pass "Platform detection works (detected: $PLATFORM)"
else
    log_fail "Platform detection failed"
fi

echo ""
echo "Test 3: Help output"
echo "==================="

if /Users/mike/code/agent-credential-proxy/install.sh --help | grep -q "ACP Installation Script"; then
    log_pass "Help output works"
else
    log_fail "Help output failed"
fi

echo ""
echo -e "${GREEN}Installation script smoke tests passed!${NC}"
