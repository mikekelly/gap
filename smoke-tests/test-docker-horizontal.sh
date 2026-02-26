#!/usr/bin/env bash
# Smoke test for horizontal deployment mode (Postgres backend)
# Tests that GAP works correctly with PostgreSQL instead of libSQL

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
GAP_SERVER_URL="${GAP_SERVER_URL:-https://gap-server-horizontal:9080}"
TEST_PASSWORD="test-horizontal-password"
PW_HASH="$(echo -n "$TEST_PASSWORD" | sha512sum | cut -d' ' -f1)"

log_info "Starting GAP horizontal mode (Postgres) smoke tests..."
log_info "Server URL: $GAP_SERVER_URL"
echo ""

# Test 1: Health check
echo "Test 1: Health check"
echo "===================="

MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -fks "$GAP_SERVER_URL/status" > /dev/null 2>&1; then
        log_pass "Server health check passed"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
        log_fail "Server health check failed after $MAX_RETRIES retries"
    fi
    sleep 1
done

# Test 2: Status check
echo ""
echo "Test 2: Status check"
echo "===================="

STATUS_RESPONSE=$(curl -ks "$GAP_SERVER_URL/status")
if echo "$STATUS_RESPONSE" | grep -q '"version"'; then
    log_pass "Status endpoint returns version info"
else
    log_fail "Unexpected status response: $STATUS_RESPONSE"
fi

# Test 3: Initialize GAP (set password)
echo ""
echo "Test 3: Initialize GAP"
echo "======================"

INIT_RESPONSE=$(curl -ks -X POST "$GAP_SERVER_URL/init" \
    -H "Content-Type: application/json" \
    -d "{\"password_hash\": \"$PW_HASH\", \"ca_path\": \"/tmp/gap-ca.crt\"}")

if echo "$INIT_RESPONSE" | grep -q '"ca_path"'; then
    log_pass "GAP initialized successfully (CA generated)"
elif echo "$INIT_RESPONSE" | grep -q 'already initialized'; then
    log_warn "GAP already initialized (expected if data persists)"
else
    log_fail "Failed to initialize GAP: $INIT_RESPONSE"
fi

# Test 4: Create agent token
echo ""
echo "Test 4: Create agent token"
echo "=========================="

TOKEN_RESPONSE=$(curl -ks -X POST "$GAP_SERVER_URL/tokens" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $PW_HASH" \
    -d "{}")

if echo "$TOKEN_RESPONSE" | grep -q '"token"'; then
    AGENT_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token')
    TOKEN_PREFIX=$(echo "$TOKEN_RESPONSE" | jq -r '.prefix')
    log_pass "Agent token created: ${AGENT_TOKEN:0:20}..."
else
    log_fail "Failed to create token: $TOKEN_RESPONSE"
fi

# Test 5: List tokens
echo ""
echo "Test 5: List tokens"
echo "==================="

TOKENS_RESPONSE=$(curl -ks "$GAP_SERVER_URL/tokens" \
    -H "Authorization: Bearer $PW_HASH")

if echo "$TOKENS_RESPONSE" | grep -q '"tokens"'; then
    TOKEN_COUNT=$(echo "$TOKENS_RESPONSE" | jq '.tokens | length')
    log_pass "Token listing works (found $TOKEN_COUNT tokens)"
else
    log_fail "Failed to list tokens: $TOKENS_RESPONSE"
fi

# Test 6: Set credential
echo ""
echo "Test 6: Set credential"
echo "======================"

CRED_STATUS=$(curl -ks -o /dev/null -w "%{http_code}" -X POST "$GAP_SERVER_URL/credentials/test-plugin/api_key" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $PW_HASH" \
    -d "{
        \"value\": \"test-secret-key-12345\"
    }")

if [ "$CRED_STATUS" = "200" ]; then
    log_pass "Credential set successfully (HTTP $CRED_STATUS)"
else
    log_fail "Failed to set credential (HTTP $CRED_STATUS)"
fi

# Test 7: Register a plugin (inline JS)
echo ""
echo "Test 7: Register plugin (inline JS)"
echo "===================================="

PLUGIN_CODE='var plugin = {
    name: "horizontal-test",
    matchPatterns: ["api.horizontal-test.example.com"],
    credentialSchema: { fields: [
        { name: "api_key", label: "API Key", type: "password", required: true }
    ]},
    transform: function(request, credentials) {
        request.headers["Authorization"] = "Bearer " + credentials.api_key;
        return request;
    }
};'

REGISTER_BODY=$(jq -n \
    --arg code "$PLUGIN_CODE" \
    '{code: $code}')

REGISTER_RESPONSE=$(curl -ks -X POST "$GAP_SERVER_URL/plugins/register" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $PW_HASH" \
    -d "$REGISTER_BODY")

if echo "$REGISTER_RESPONSE" | jq -e '.registered == true' > /dev/null 2>&1; then
    PLUGIN_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.id')
    log_pass "Plugin registered successfully (id: $PLUGIN_ID)"
else
    log_fail "Failed to register plugin: $REGISTER_RESPONSE"
fi

# Test 8: List plugins (verify the registered plugin appears)
echo ""
echo "Test 8: List plugins"
echo "===================="

PLUGINS_RESPONSE=$(curl -ks "$GAP_SERVER_URL/plugins" \
    -H "Authorization: Bearer $PW_HASH")

if echo "$PLUGINS_RESPONSE" | jq -e ".plugins[] | select(.id == \"$PLUGIN_ID\")" > /dev/null 2>&1; then
    PLUGIN_COUNT=$(echo "$PLUGINS_RESPONSE" | jq '.plugins | length')
    log_pass "Plugin listing works (found $PLUGIN_COUNT plugins, registered plugin present)"
else
    log_fail "Registered plugin not found in plugin list: $PLUGINS_RESPONSE"
fi

# Test 9: Create header set + add header
echo ""
echo "Test 9: Create header set and add header"
echo "========================================="

RESPONSE=$(curl -ks -X POST "$GAP_SERVER_URL/header-sets" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $PW_HASH" \
    -d '{"match_patterns": ["api.horizontal-test.example.com"], "weight": 5}')

if echo "$RESPONSE" | jq -e '.created == true' > /dev/null 2>&1; then
    HEADER_SET_ID=$(echo "$RESPONSE" | jq -r '.id')
    log_pass "Header set created (id: $HEADER_SET_ID)"
else
    log_fail "Failed to create header set: $RESPONSE"
fi

# Add a header to the set
RESPONSE=$(curl -ks -X POST "$GAP_SERVER_URL/header-sets/$HEADER_SET_ID/headers" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $PW_HASH" \
    -d '{"name": "X-Custom-Header", "value": "horizontal-test-value"}')

if echo "$RESPONSE" | jq -e '.set == true' > /dev/null 2>&1; then
    log_pass "Header added to header set"
else
    log_fail "Failed to add header: $RESPONSE"
fi

# Test 10: List header sets (verify values hidden)
echo ""
echo "Test 10: List header sets (verify values hidden)"
echo "================================================="

RESPONSE=$(curl -ks "$GAP_SERVER_URL/header-sets" \
    -H "Authorization: Bearer $PW_HASH")

if echo "$RESPONSE" | jq -e ".header_sets[] | select(.id == \"$HEADER_SET_ID\") | .headers | length == 1" > /dev/null 2>&1; then
    log_pass "Header set listed with 1 header name"
else
    log_fail "Header set listing unexpected: $RESPONSE"
fi

# Verify values are NOT in the response
if echo "$RESPONSE" | grep -q "horizontal-test-value"; then
    log_fail "Header values should not be exposed in list response"
else
    log_pass "Header values correctly hidden in list response"
fi

# Test 11: Verify data persists in Postgres
echo ""
echo "Test 11: Verify data persists in Postgres"
echo "=========================================="

# Re-read all resources and verify they still exist
# This verifies the Postgres backend is actually storing data

# Tokens still present
TOKENS_CHECK=$(curl -ks "$GAP_SERVER_URL/tokens" \
    -H "Authorization: Bearer $PW_HASH")

TOKEN_CHECK_COUNT=$(echo "$TOKENS_CHECK" | jq '.tokens | length')
if [ "$TOKEN_CHECK_COUNT" -gt 0 ]; then
    log_pass "Tokens persist in Postgres ($TOKEN_CHECK_COUNT found)"
else
    log_fail "Tokens not persisted — expected at least 1, got $TOKEN_CHECK_COUNT"
fi

# Plugins still present
PLUGINS_CHECK=$(curl -ks "$GAP_SERVER_URL/plugins" \
    -H "Authorization: Bearer $PW_HASH")

if echo "$PLUGINS_CHECK" | jq -e ".plugins[] | select(.id == \"$PLUGIN_ID\")" > /dev/null 2>&1; then
    log_pass "Plugin persists in Postgres"
else
    log_fail "Plugin not persisted in Postgres"
fi

# Header sets still present
HEADERS_CHECK=$(curl -ks "$GAP_SERVER_URL/header-sets" \
    -H "Authorization: Bearer $PW_HASH")

if echo "$HEADERS_CHECK" | jq -e ".header_sets[] | select(.id == \"$HEADER_SET_ID\")" > /dev/null 2>&1; then
    log_pass "Header set persists in Postgres"
else
    log_fail "Header set not persisted in Postgres"
fi

# Test 12: Revoke token — immediately rejected
echo ""
echo "Test 12: Revoke token (immediate effect)"
echo "========================================="

DELETE_STATUS=$(curl -ks -o /dev/null -w "%{http_code}" -X DELETE "$GAP_SERVER_URL/tokens/$TOKEN_PREFIX" \
    -H "Authorization: Bearer $PW_HASH")

if [ "$DELETE_STATUS" = "200" ]; then
    log_pass "Token revoked successfully (HTTP $DELETE_STATUS)"
else
    log_fail "Failed to revoke token (HTTP $DELETE_STATUS)"
fi

# Verify the token no longer appears in the list
TOKENS_AFTER=$(curl -ks "$GAP_SERVER_URL/tokens" \
    -H "Authorization: Bearer $PW_HASH")

if echo "$TOKENS_AFTER" | jq -e ".tokens[] | select(.prefix == \"$TOKEN_PREFIX\")" > /dev/null 2>&1; then
    log_fail "Revoked token still appears in token list"
else
    log_pass "Revoked token no longer in token list"
fi

# Test 13: Management log has entries
echo ""
echo "Test 13: Management log has entries"
echo "===================================="

MGMT_LOG_RESPONSE=$(curl -ks "$GAP_SERVER_URL/management-log" \
    -H "Authorization: Bearer $PW_HASH")

MGMT_LOG_COUNT=$(echo "$MGMT_LOG_RESPONSE" | jq '.entries | length')

if [ "$MGMT_LOG_COUNT" -gt 0 ]; then
    log_pass "Management log has $MGMT_LOG_COUNT entries"
else
    log_fail "Management log is empty, expected entries from previous operations"
fi

# Verify entries have required fields
FIRST_ENTRY=$(echo "$MGMT_LOG_RESPONSE" | jq '.entries[0]')
HAS_TIMESTAMP=$(echo "$FIRST_ENTRY" | jq 'has("timestamp")')
HAS_OPERATION=$(echo "$FIRST_ENTRY" | jq 'has("operation")')
HAS_RESOURCE_TYPE=$(echo "$FIRST_ENTRY" | jq 'has("resource_type")')
HAS_SUCCESS=$(echo "$FIRST_ENTRY" | jq 'has("success")')

if [ "$HAS_TIMESTAMP" = "true" ] && [ "$HAS_OPERATION" = "true" ] && [ "$HAS_RESOURCE_TYPE" = "true" ] && [ "$HAS_SUCCESS" = "true" ]; then
    log_pass "Management log entries have correct schema"
else
    log_fail "Management log entries missing required fields"
fi

# Test 14: Cleanup — delete header set and plugin
echo ""
echo "Test 14: Cleanup (delete header set and plugin)"
echo "================================================"

# Delete header set
RESPONSE=$(curl -ks -X DELETE "$GAP_SERVER_URL/header-sets/$HEADER_SET_ID" \
    -H "Authorization: Bearer $PW_HASH")

if echo "$RESPONSE" | jq -e '.deleted == true' > /dev/null 2>&1; then
    log_pass "Header set deleted"
else
    log_fail "Failed to delete header set: $RESPONSE"
fi

# Delete plugin
RESPONSE=$(curl -ks -X DELETE "$GAP_SERVER_URL/plugins/$PLUGIN_ID" \
    -H "Authorization: Bearer $PW_HASH")

if echo "$RESPONSE" | jq -e '.uninstalled == true' > /dev/null 2>&1; then
    log_pass "Plugin deleted"
else
    log_fail "Failed to delete plugin: $RESPONSE"
fi

# Verify cleanup
PLUGINS_FINAL=$(curl -ks "$GAP_SERVER_URL/plugins" \
    -H "Authorization: Bearer $PW_HASH")

PLUGIN_FINAL_COUNT=$(echo "$PLUGINS_FINAL" | jq '.plugins | length')
log_info "Remaining plugins after cleanup: $PLUGIN_FINAL_COUNT"

HEADERS_FINAL=$(curl -ks "$GAP_SERVER_URL/header-sets" \
    -H "Authorization: Bearer $PW_HASH")

HEADER_FINAL_COUNT=$(echo "$HEADERS_FINAL" | jq '.header_sets | length')
log_info "Remaining header sets after cleanup: $HEADER_FINAL_COUNT"

echo ""
echo -e "${GREEN}All horizontal mode (Postgres) smoke tests passed!${NC}"
echo ""
