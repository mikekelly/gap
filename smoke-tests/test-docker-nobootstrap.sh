#!/bin/bash
# Test GAP in no-bootstrap mode using Docker Compose
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"

# Generate fixtures if needed
if [ ! -f "$FIXTURES_DIR/test-ca-cert.b64" ]; then
    echo "Generating test CA fixtures..."
    "$SCRIPT_DIR/generate-test-ca.sh"
fi

# Export env vars for docker-compose
export GAP_CA_CERT="$(cat "$FIXTURES_DIR/test-ca-cert.b64")"
export GAP_CA_KEY="$(cat "$FIXTURES_DIR/test-ca-key.b64")"
export GAP_ENCRYPTION_KEY_NOBOOTSTRAP="$(cat "$FIXTURES_DIR/test-encryption.key")"

echo "=== Testing no-bootstrap mode (should succeed) ==="
cd "$PROJECT_DIR"
docker compose --profile nobootstrap --profile test-nobootstrap up --build --abort-on-container-exit --exit-code-from test-runner-nobootstrap

echo ""
echo "=== Testing no-bootstrap mode with missing vars (should fail) ==="
# The fail service has GAP_NO_BOOTSTRAP=true (Dockerfile default) but no env vars
# It should exit with a non-zero code
if docker compose --profile test-nobootstrap-fail up --build gap-server-nobootstrap-fail 2>&1 | grep -q "GAP_NO_BOOTSTRAP is set but"; then
    echo "PASS: Server correctly refused to start with missing env vars"
else
    # Check if container exited with non-zero
    EXIT_CODE=$(docker inspect gap-server-nobootstrap-fail --format='{{.State.ExitCode}}' 2>/dev/null || echo "unknown")
    if [ "$EXIT_CODE" != "0" ] && [ "$EXIT_CODE" != "unknown" ]; then
        echo "PASS: Server exited with code $EXIT_CODE (non-zero as expected)"
    else
        echo "FAIL: Server should have refused to start"
        exit 1
    fi
fi

echo ""
echo "=== All no-bootstrap Docker tests passed ==="
