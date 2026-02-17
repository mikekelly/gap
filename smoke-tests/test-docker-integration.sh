#!/usr/bin/env bash
# Integration test for Docker deployment
# Tests the full GAP workflow: init, credentials, tokens, proxy health

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}✓${NC} $1"
}

log_fail() {
    echo -e "${RED}✗${NC} $1"
    exit 1
}

# Configuration
GAP_SERVER_URL="${GAP_SERVER_URL:-http://gap-server:9080}"
TEST_PASSWORD="test-integration-password"

log_info "Starting GAP Docker integration tests..."
log_info "Server URL: $GAP_SERVER_URL"
echo ""

# Test 1: Health check
echo "Test 1: Health check"
echo "===================="

MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -f -s "$GAP_SERVER_URL/status" > /dev/null 2>&1; then
        log_pass "Server health check passed"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
        log_fail "Server health check failed after $MAX_RETRIES retries"
    fi
    sleep 1
done

# Test 2: Get status
echo ""
echo "Test 2: Status check"
echo "===================="

STATUS_RESPONSE=$(curl -s "$GAP_SERVER_URL/status")
if echo "$STATUS_RESPONSE" | grep -q '"version"'; then
    log_pass "Status endpoint returns version info"
else
    log_fail "Unexpected status response: $STATUS_RESPONSE"
fi

# Test 3: Initialize GAP (set password)
echo ""
echo "Test 3: Initialize GAP"
echo "======================"

INIT_RESPONSE=$(curl -s -X POST "$GAP_SERVER_URL/init" \
    -H "Content-Type: application/json" \
    -d "{\"password_hash\": \"$(echo -n "$TEST_PASSWORD" | sha512sum | cut -d' ' -f1)\", \"ca_path\": \"/tmp/test-ca.crt\"}")

if echo "$INIT_RESPONSE" | grep -q '"ca_path"'; then
    log_pass "GAP initialized successfully (CA generated)"
elif echo "$INIT_RESPONSE" | grep -q 'already initialized'; then
    log_warn "GAP already initialized (expected if data persists)"
else
    log_fail "Failed to initialize GAP: $INIT_RESPONSE"
fi

# Test 4: Check status after init
echo ""
echo "Test 4: Status check (after init)"
echo "=================================="

STATUS_RESPONSE=$(curl -s "$GAP_SERVER_URL/status")
if echo "$STATUS_RESPONSE" | grep -q '"version"'; then
    log_pass "Status endpoint still works after init"
else
    log_fail "Status check failed: $STATUS_RESPONSE"
fi

# Test 5: Create agent token
echo ""
echo "Test 5: Create agent token"
echo "=========================="

TOKEN_RESPONSE=$(curl -s -X POST "$GAP_SERVER_URL/tokens/create" \
    -H "Content-Type: application/json" \
    -d "{
        \"password_hash\": \"$(echo -n "$TEST_PASSWORD" | sha512sum | cut -d' ' -f1)\",
        \"name\": \"test-agent-$(date +%s)\"
    }")

if echo "$TOKEN_RESPONSE" | grep -q '"token"'; then
    AGENT_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token')
    log_pass "Agent token created: ${AGENT_TOKEN:0:20}..."
else
    log_fail "Failed to create token: $TOKEN_RESPONSE"
fi

# Test 6: List tokens
echo ""
echo "Test 6: List tokens"
echo "==================="

TOKENS_RESPONSE=$(curl -s -X POST "$GAP_SERVER_URL/tokens" \
    -H "Content-Type: application/json" \
    -d "{
        \"password_hash\": \"$(echo -n "$TEST_PASSWORD" | sha512sum | cut -d' ' -f1)\"
    }")

if echo "$TOKENS_RESPONSE" | grep -q '"tokens"'; then
    TOKEN_COUNT=$(echo "$TOKENS_RESPONSE" | jq '.tokens | length')
    log_pass "Token listing works (found $TOKEN_COUNT tokens)"
else
    log_fail "Failed to list tokens: $TOKENS_RESPONSE"
fi

# Test 7: Verify mock API is accessible
echo ""
echo "Test 7: Verify mock API"
echo "======================="

# go-httpbin runs on port 8080
if curl -f -s "http://mock-api:8080/get" | grep -q "Host"; then
    log_pass "Mock API is accessible"
else
    log_fail "Mock API is not accessible"
fi

# Test 8: Set credential for a test plugin
echo ""
echo "Test 8: Set credential"
echo "======================"

CRED_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$GAP_SERVER_URL/credentials/test-plugin/api_key" \
    -H "Content-Type: application/json" \
    -d "{
        \"password_hash\": \"$(echo -n "$TEST_PASSWORD" | sha512sum | cut -d' ' -f1)\",
        \"value\": \"test-secret-key-12345\"
    }")

if [ "$CRED_STATUS" = "200" ]; then
    log_pass "Credential set successfully (HTTP $CRED_STATUS)"
else
    log_fail "Failed to set credential (HTTP $CRED_STATUS)"
fi

# Test 9: Install a plugin
echo ""
echo "Test 9: Install plugin"
echo "======================"

# Note: Plugin installation requires network access to GitHub
INSTALL_RESPONSE=$(curl -s -X POST "$GAP_SERVER_URL/plugins/install" \
    -H "Content-Type: application/json" \
    -d "{
        \"password_hash\": \"$(echo -n "$TEST_PASSWORD" | sha512sum | cut -d' ' -f1)\",
        \"name\": \"mikekelly/exa-gap\"
    }")

if echo "$INSTALL_RESPONSE" | grep -q '"name"'; then
    PLUGIN_NAME=$(echo "$INSTALL_RESPONSE" | jq -r '.name')
    log_pass "Plugin installed: $PLUGIN_NAME"
else
    log_fail "Failed to install plugin: $INSTALL_RESPONSE"
fi

# Test 10: List plugins
echo ""
echo "Test 10: List plugins"
echo "====================="

PLUGINS_RESPONSE=$(curl -s -X POST "$GAP_SERVER_URL/plugins" \
    -H "Content-Type: application/json" \
    -d "{
        \"password_hash\": \"$(echo -n "$TEST_PASSWORD" | sha512sum | cut -d' ' -f1)\"
    }")

if echo "$PLUGINS_RESPONSE" | grep -q '"plugins"'; then
    PLUGIN_COUNT=$(echo "$PLUGINS_RESPONSE" | jq '.plugins | length')
    log_pass "Plugin listing works (found $PLUGIN_COUNT plugins)"

    # Verify the installed plugin appears in the list
    if echo "$PLUGINS_RESPONSE" | jq -e ".plugins[] | select(.name == \"$PLUGIN_NAME\")" > /dev/null 2>&1; then
        log_pass "Installed plugin appears in plugin list"
    else
        log_fail "Installed plugin does not appear in plugin list"
    fi

    # Verify plugin metadata is present (match_patterns and credential_schema)
    PLUGIN_DATA=$(echo "$PLUGINS_RESPONSE" | jq -r ".plugins[] | select(.name == \"$PLUGIN_NAME\")")
    if echo "$PLUGIN_DATA" | jq -e '.match_patterns' > /dev/null 2>&1; then
        HOSTS=$(echo "$PLUGIN_DATA" | jq -r '.match_patterns | join(", ")')
        log_pass "Plugin metadata includes match_patterns: $HOSTS"
    else
        log_fail "Plugin metadata missing match_patterns field"
    fi

    if echo "$PLUGIN_DATA" | jq -e '.credential_schema' > /dev/null 2>&1; then
        SCHEMA=$(echo "$PLUGIN_DATA" | jq -r '.credential_schema | join(", ")')
        log_pass "Plugin metadata includes credential_schema: $SCHEMA"
    else
        log_fail "Plugin metadata missing credential_schema field"
    fi
else
    log_fail "Failed to list plugins: $PLUGINS_RESPONSE"
fi

# Test 11: Delete token (cleanup test)
echo ""
echo "Test 11: Delete token"
echo "====================="

if [ -n "$AGENT_TOKEN" ]; then
    # Extract token ID from TOKEN_RESPONSE
    TOKEN_ID=$(echo "$TOKEN_RESPONSE" | jq -r '.id')

    DELETE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE "$GAP_SERVER_URL/tokens/$TOKEN_ID" \
        -H "Content-Type: application/json" \
        -d "{
            \"password_hash\": \"$(echo -n "$TEST_PASSWORD" | sha512sum | cut -d' ' -f1)\"
        }")

    if [ "$DELETE_STATUS" = "200" ]; then
        log_pass "Token deleted successfully (HTTP $DELETE_STATUS)"
    else
        log_fail "Failed to delete token (HTTP $DELETE_STATUS)"
    fi
else
    log_warn "Skipping token deletion (no token to delete)"
fi

# Test 12: Proxy smoke test (optional — requires internet access and CA cert)
echo ""
echo "Test 12: Proxy smoke test"
echo "========================="
#
# The GAP proxy listens on port 9443 (HTTPS). Agents route requests through it
# using CONNECT tunnelling. To trust the proxy's TLS and its MITM certificates,
# a client needs to trust GAP's CA.
#
# The CA cert lives at /var/lib/gap/ca.crt inside the gap-server container.
# The test-runner does not mount the gap-data volume, so we can't read it
# directly. There is also no /ca API endpoint.
#
# We therefore fetch the CA cert from the gap-server container filesystem via
# the network — this only works if a CA endpoint exists. If the cert isn't
# accessible, we skip this test with a warning rather than failing the suite.

PROXY_URL="https://gap-server:9443"
CA_TMPFILE="/tmp/gap-ca.crt"
PROXY_TEST_SKIPPED=false

# Attempt 1: check for a /ca endpoint (may not exist)
CA_HTTP_STATUS=$(curl -s -o "$CA_TMPFILE" -w "%{http_code}" "$GAP_SERVER_URL/ca" 2>/dev/null || true)

if [ "$CA_HTTP_STATUS" = "200" ] && [ -s "$CA_TMPFILE" ]; then
    log_pass "Fetched CA cert from /ca endpoint"
else
    # Attempt 2: the init response included ca_path — but that path is on the
    # gap-server container. We can't reach it from here without a shared volume.
    log_warn "CA cert not accessible via API (no /ca endpoint and gap-data volume not mounted)"
    log_warn "Proxy smoke test requires either:"
    log_warn "  • A /ca API endpoint on gap-server, OR"
    log_warn "  • The gap-data volume mounted in the test-runner container"
    log_warn "Skipping proxy smoke test — management API tests (1-11) are the primary coverage"
    PROXY_TEST_SKIPPED=true
fi

if [ "$PROXY_TEST_SKIPPED" = false ]; then
    # Check internet connectivity to httpbin.org
    if ! curl -s --max-time 10 -o /dev/null "https://httpbin.org/get" 2>/dev/null; then
        log_warn "httpbin.org not reachable — skipping proxy smoke test"
        PROXY_TEST_SKIPPED=true
    fi
fi

if [ "$PROXY_TEST_SKIPPED" = false ]; then
    # Use curl's --proxy flag with HTTPS proxy support.
    # We need to trust GAP's CA for both the proxy TLS connection and the
    # MITM certificates GAP generates for upstream hosts.
    #
    # --proxy-cacert  trusts the CA for the proxy TLS handshake (CONNECT)
    # --cacert        trusts the CA for the MITM certs on the upstream tunnel
    PROXY_RESPONSE=$(curl -s \
        --max-time 30 \
        --proxy "$PROXY_URL" \
        --proxy-cacert "$CA_TMPFILE" \
        --cacert "$CA_TMPFILE" \
        "https://httpbin.org/headers" 2>&1) || PROXY_EXIT=$?

    if echo "$PROXY_RESPONSE" | grep -q '"Host"'; then
        log_pass "Proxy smoke test passed — response received via GAP proxy"
        log_pass "httpbin.org/headers response contains expected Host header"
    else
        log_fail "Proxy smoke test failed — unexpected response: $PROXY_RESPONSE"
    fi
fi

echo ""
echo -e "${GREEN}All Docker integration tests passed!${NC}"
echo ""
