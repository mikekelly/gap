#!/usr/bin/env bash
# Test script for macos-notarize.sh
# Verifies script behavior without actually calling Apple's notarization service

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_test() { echo -e "${YELLOW}[TEST]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOTARIZE_SCRIPT="$SCRIPT_DIR/macos-notarize.sh"

TESTS_PASSED=0
TESTS_FAILED=0

# Helper function to run a test
run_test() {
    local test_name="$1"
    local expected_exit_code="$2"
    shift 2
    local test_command=("$@")

    log_test "$test_name"

    set +e
    output=$("${test_command[@]}" 2>&1)
    actual_exit_code=$?
    set -e

    if [ "$actual_exit_code" -eq "$expected_exit_code" ]; then
        log_pass "$test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_fail "$test_name (expected exit code $expected_exit_code, got $actual_exit_code)"
        echo "$output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Helper to check if output contains expected text
check_output_contains() {
    local test_name="$1"
    local expected_text="$2"
    shift 2
    local test_command=("$@")

    log_test "$test_name"

    set +e
    output=$("${test_command[@]}" 2>&1)
    set -e

    if echo "$output" | grep -q "$expected_text"; then
        log_pass "$test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_fail "$test_name (expected text not found: '$expected_text')"
        echo "Output was:"
        echo "$output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

echo "Testing macos-notarize.sh"
echo "=========================="
echo ""

# Test 1: Script exists and is executable
log_test "Script exists and is executable"
if [ -f "$NOTARIZE_SCRIPT" ] && [ -x "$NOTARIZE_SCRIPT" ]; then
    log_pass "Script exists and is executable"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_fail "Script does not exist or is not executable"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 2: No arguments shows usage
check_output_contains "No arguments shows usage" "Usage:" bash "$NOTARIZE_SCRIPT"

# Test 3: --help shows usage
check_output_contains "--help shows usage" "Usage:" bash "$NOTARIZE_SCRIPT" --help

# Test 4: Missing binary file fails
run_test "Missing binary file fails" 1 bash "$NOTARIZE_SCRIPT" /nonexistent/binary

# Test 5: Script validates macOS (skip if not on macOS)
if [[ "$(uname)" != "Darwin" ]]; then
    log_test "Non-macOS system rejected (skipped - not on macOS)"
else
    # Create a test binary file
    TEMP_BINARY=$(mktemp)
    echo "fake binary" > "$TEMP_BINARY"
    chmod +x "$TEMP_BINARY"

    # Test 6: Missing keychain profile configuration fails
    unset NOTARIZE_KEYCHAIN_PROFILE
    run_test "Missing keychain profile fails" 1 bash "$NOTARIZE_SCRIPT" "$TEMP_BINARY"

    # Test 7: --keychain-profile flag is recognized
    check_output_contains "Keychain profile flag recognized" "notarize-profile" bash "$NOTARIZE_SCRIPT" "$TEMP_BINARY" --keychain-profile notarize-profile || true

    # Test 8: NOTARIZE_KEYCHAIN_PROFILE env var is recognized
    NOTARIZE_KEYCHAIN_PROFILE="test-profile" check_output_contains "Env var recognized" "test-profile" bash "$NOTARIZE_SCRIPT" "$TEMP_BINARY" || true

    # Cleanup
    rm -f "$TEMP_BINARY"
fi

# Summary
echo ""
echo "=========================="
echo "Test Results"
echo "=========================="
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    log_pass "All tests passed!"
    exit 0
else
    log_fail "Some tests failed"
    exit 1
fi
