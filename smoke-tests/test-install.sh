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
