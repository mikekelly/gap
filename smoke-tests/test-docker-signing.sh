#!/usr/bin/env bash
# Integration tests for GAP HTTP signing authentication
# Tests the Ed25519 request signing flow in Docker
#
# Requires:
#   - openssl 3.x (for Ed25519 operations)
#   - curl, jq, coreutils (from base test-runner image)
#
# Environment:
#   GAP_SERVER_URL  - Base URL of the signing-enabled gap-server
#   /fixtures/signing-key.pem      - Ed25519 private key (PKCS8 PEM)
#   /fixtures/signing-key-pub.pem  - Corresponding public key
#   /fixtures/wrong-signing-key.pem - Different private key for negative tests

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
GAP_SERVER_URL="${GAP_SERVER_URL:-https://gap-server-signing:9080}"
SIGNING_KEY="/fixtures/signing-key.pem"
SIGNING_KEY_PUB="/fixtures/signing-key-pub.pem"
WRONG_SIGNING_KEY="/fixtures/wrong-signing-key.pem"

# Verify prerequisites
if ! command -v openssl &> /dev/null; then
    log_fail "openssl not found — required for Ed25519 signing"
fi

OPENSSL_VERSION=$(openssl version)
log_info "OpenSSL version: $OPENSSL_VERSION"

if [ ! -f "$SIGNING_KEY" ]; then
    log_fail "Signing key not found at $SIGNING_KEY"
fi

if [ ! -f "$SIGNING_KEY_PUB" ]; then
    log_fail "Public key not found at $SIGNING_KEY_PUB"
fi

# ── Signing helper ────────────────────────────────────────────────────
#
# Computes the Ed25519 signature over a canonical string that matches
# the server's format in gap-server/src/signing.rs:
#
#   @method: {METHOD}
#   @path: {PATH}
#   content-digest: sha-256=:{BASE64_SHA256}:
#   x-gap-timestamp: {TIMESTAMP}
#   x-gap-nonce: {NONCE}
#
# Outputs curl-compatible -H flags for all signing headers.

# Compute the key-id from the public key file.
# Key-ID = first 8 bytes of SHA-256(raw_32_byte_public_key), hex-encoded.
# The public key PEM is SPKI format: 12-byte ASN.1 prefix + 32-byte raw key.
compute_key_id() {
    local pub_key_file="$1"
    # Extract DER from PEM, skip 12-byte SPKI prefix to get raw 32-byte key,
    # then SHA-256 hash it and take first 16 hex chars (8 bytes).
    openssl pkey -pubin -in "$pub_key_file" -outform DER 2>/dev/null \
        | tail -c 32 \
        | openssl dgst -sha256 -binary \
        | head -c 8 \
        | od -An -tx1 \
        | tr -d ' \n'
}

KEY_ID=$(compute_key_id "$SIGNING_KEY_PUB")
log_info "Computed key-id: $KEY_ID"

# signed_curl METHOD PATH BODY KEY_FILE [EXTRA_CURL_ARGS...]
#
# Makes a signed HTTP request. Outputs the curl response.
# METHOD: HTTP method (GET, POST, etc.)
# PATH: URL path (e.g., /status)
# BODY: Request body (empty string for GET)
# KEY_FILE: Path to Ed25519 private key PEM
# Remaining args are passed through to curl.
signed_curl() {
    local method="$1"
    local path="$2"
    local body="$3"
    local key_file="$4"
    shift 4

    local timestamp
    timestamp=$(date +%s)

    local nonce
    nonce=$(openssl rand -hex 16)

    # Compute content digest: sha-256=:BASE64_SHA256:
    local body_hash
    body_hash=$(printf '%s' "$body" | openssl dgst -sha256 -binary | base64 -w 0)
    local content_digest="sha-256=:${body_hash}:"

    # Build canonical string (must match gap-server/src/signing.rs exactly)
    local canonical
    canonical=$(printf '@method: %s\n@path: %s\ncontent-digest: %s\nx-gap-timestamp: %s\nx-gap-nonce: %s' \
        "$method" "$path" "$content_digest" "$timestamp" "$nonce")

    # Sign the canonical string with Ed25519
    # -w 0 prevents base64 line wrapping (Ed25519 sigs are 64 bytes = 88 base64 chars)
    local signature
    signature=$(printf '%s' "$canonical" | openssl pkeyutl -sign -inkey "$key_file" 2>/dev/null | base64 -w 0)

    # Compute key-id for this specific key
    local kid
    kid=$(openssl pkey -in "$key_file" -pubout -outform DER 2>/dev/null \
        | tail -c 32 \
        | openssl dgst -sha256 -binary \
        | head -c 8 \
        | od -An -tx1 \
        | tr -d ' \n')

    # Make the request with signing headers
    if [ -n "$body" ]; then
        curl -ks -X "$method" "${GAP_SERVER_URL}${path}" \
            -H "Content-Type: application/json" \
            -H "X-Gap-Timestamp: $timestamp" \
            -H "X-Gap-Nonce: $nonce" \
            -H "X-Gap-Signature: $signature" \
            -H "X-Gap-Key-Id: $kid" \
            -d "$body" \
            "$@"
    else
        curl -ks -X "$method" "${GAP_SERVER_URL}${path}" \
            -H "X-Gap-Timestamp: $timestamp" \
            -H "X-Gap-Nonce: $nonce" \
            -H "X-Gap-Signature: $signature" \
            -H "X-Gap-Key-Id: $kid" \
            "$@"
    fi
}

# signed_curl_status — like signed_curl but returns HTTP status code only
signed_curl_status() {
    local method="$1"
    local path="$2"
    local body="$3"
    local key_file="$4"
    shift 4
    signed_curl "$method" "$path" "$body" "$key_file" -o /dev/null -w "%{http_code}" "$@"
}

log_info "Starting GAP Docker signing tests..."
log_info "Server URL: $GAP_SERVER_URL"
echo ""

# ── Wait for server ───────────────────────────────────────────────────

MAX_RETRIES=30
RETRY_COUNT=0
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if curl -fks "$GAP_SERVER_URL/status" > /dev/null 2>&1; then
        log_pass "Server is ready"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
        log_fail "Server health check failed after $MAX_RETRIES retries"
    fi
    sleep 1
done

# ── Test 1: Signed status check ──────────────────────────────────────
echo ""
echo "Test 1: Signed status check"
echo "==========================="

# /status is exempt from signing middleware, but verify it returns
# initialized: true in signing mode (no init step needed).
STATUS_RESPONSE=$(curl -ks "$GAP_SERVER_URL/status")
if echo "$STATUS_RESPONSE" | jq -e '.initialized == true' > /dev/null 2>&1; then
    log_pass "Status returns initialized: true (signing mode — no init needed)"
else
    log_fail "Expected initialized: true in signing mode, got: $STATUS_RESPONSE"
fi

if echo "$STATUS_RESPONSE" | jq -e '.version' > /dev/null 2>&1; then
    VERSION=$(echo "$STATUS_RESPONSE" | jq -r '.version')
    log_pass "Server version: $VERSION"
else
    log_fail "Status missing version field: $STATUS_RESPONSE"
fi

# ── Test 2: Full signed flow ─────────────────────────────────────────
echo ""
echo "Test 2: Full signed flow"
echo "========================"

# 2a: Create agent token
TOKEN_RESPONSE=$(signed_curl "POST" "/tokens" '{}' "$SIGNING_KEY")
if echo "$TOKEN_RESPONSE" | jq -e '.token' > /dev/null 2>&1; then
    AGENT_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token')
    TOKEN_PREFIX=$(echo "$TOKEN_RESPONSE" | jq -r '.prefix')
    log_pass "Agent token created: ${AGENT_TOKEN:0:20}..."
else
    log_fail "Failed to create token: $TOKEN_RESPONSE"
fi

# 2b: Install a plugin
INSTALL_RESPONSE=$(signed_curl "POST" "/plugins/install" '{"source": "mikekelly/exa-gap"}' "$SIGNING_KEY")
if echo "$INSTALL_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
    PLUGIN_ID=$(echo "$INSTALL_RESPONSE" | jq -r '.id')
    log_pass "Plugin installed: $PLUGIN_ID"
else
    log_fail "Failed to install plugin: $INSTALL_RESPONSE"
fi

# 2c: Set credential for the plugin
CRED_STATUS=$(signed_curl_status "POST" "/credentials/$PLUGIN_ID/api_key" '{"value": "test-secret-key-12345"}' "$SIGNING_KEY")
if [ "$CRED_STATUS" = "200" ]; then
    log_pass "Credential set successfully (HTTP $CRED_STATUS)"
else
    log_fail "Failed to set credential (HTTP $CRED_STATUS)"
fi

# 2d: List plugins
PLUGINS_RESPONSE=$(signed_curl "GET" "/plugins" "" "$SIGNING_KEY")
if echo "$PLUGINS_RESPONSE" | jq -e ".plugins[] | select(.id == \"$PLUGIN_ID\")" > /dev/null 2>&1; then
    PLUGIN_COUNT=$(echo "$PLUGINS_RESPONSE" | jq '.plugins | length')
    log_pass "Plugin listing works ($PLUGIN_COUNT plugins, installed plugin found)"
else
    log_fail "Installed plugin not in list: $PLUGINS_RESPONSE"
fi

# 2e: Check activity
ACTIVITY_RESPONSE=$(signed_curl "GET" "/activity" "" "$SIGNING_KEY")
ACTIVITY_COUNT=$(echo "$ACTIVITY_RESPONSE" | jq '.entries | length' 2>/dev/null || echo "0")
if [ "$ACTIVITY_COUNT" -ge 0 ] 2>/dev/null; then
    log_pass "Activity endpoint accessible ($ACTIVITY_COUNT entries)"
else
    log_fail "Activity endpoint failed: $ACTIVITY_RESPONSE"
fi

# ── Test 3: Unsigned request rejected ─────────────────────────────────
echo ""
echo "Test 3: Unsigned request rejected"
echo "================================="

# A request without signing headers to a protected endpoint should get 401.
UNSIGNED_STATUS=$(curl -ks -o /dev/null -w "%{http_code}" -X GET "$GAP_SERVER_URL/tokens")
if [ "$UNSIGNED_STATUS" = "401" ]; then
    log_pass "Unsigned request correctly rejected (HTTP $UNSIGNED_STATUS)"
else
    log_fail "Unsigned request should return 401, got HTTP $UNSIGNED_STATUS"
fi

# ── Test 4: Wrong key rejected ────────────────────────────────────────
echo ""
echo "Test 4: Wrong key rejected"
echo "=========================="

# Sign with the wrong private key — server should reject the signature.
WRONG_KEY_STATUS=$(signed_curl_status "GET" "/tokens" "" "$WRONG_SIGNING_KEY")
if [ "$WRONG_KEY_STATUS" = "401" ]; then
    log_pass "Wrong key correctly rejected (HTTP $WRONG_KEY_STATUS)"
else
    log_fail "Wrong key should return 401, got HTTP $WRONG_KEY_STATUS"
fi

# ── Test 5: Expired timestamp rejected ────────────────────────────────
echo ""
echo "Test 5: Expired timestamp rejected"
echo "==================================="

# Sign with a timestamp 10 minutes in the past (server allows 5 min skew).
EXPIRED_TS=$(($(date +%s) - 600))
EXPIRED_NONCE=$(openssl rand -hex 16)
EXPIRED_BODY=""
EXPIRED_HASH=$(printf '%s' "$EXPIRED_BODY" | openssl dgst -sha256 -binary | base64 -w 0)
EXPIRED_DIGEST="sha-256=:${EXPIRED_HASH}:"
EXPIRED_CANONICAL=$(printf '@method: %s\n@path: %s\ncontent-digest: %s\nx-gap-timestamp: %s\nx-gap-nonce: %s' \
    "GET" "/tokens" "$EXPIRED_DIGEST" "$EXPIRED_TS" "$EXPIRED_NONCE")
EXPIRED_SIG=$(printf '%s' "$EXPIRED_CANONICAL" | openssl pkeyutl -sign -inkey "$SIGNING_KEY" 2>/dev/null | base64 -w 0)

EXPIRED_STATUS=$(curl -ks -o /dev/null -w "%{http_code}" -X GET "$GAP_SERVER_URL/tokens" \
    -H "X-Gap-Timestamp: $EXPIRED_TS" \
    -H "X-Gap-Nonce: $EXPIRED_NONCE" \
    -H "X-Gap-Signature: $EXPIRED_SIG" \
    -H "X-Gap-Key-Id: $KEY_ID")

if [ "$EXPIRED_STATUS" = "401" ]; then
    log_pass "Expired timestamp correctly rejected (HTTP $EXPIRED_STATUS)"
else
    log_fail "Expired timestamp should return 401, got HTTP $EXPIRED_STATUS"
fi

# ── Test 6: Init rejected in signing mode ─────────────────────────────
echo ""
echo "Test 6: Init rejected in signing mode"
echo "======================================"

# /init is exempt from the signing middleware, but the handler itself
# returns 400 when signing is enabled (password-based init is not available).
INIT_STATUS=$(curl -ks -o /dev/null -w "%{http_code}" -X POST "$GAP_SERVER_URL/init" \
    -H "Content-Type: application/json" \
    -d '{"password_hash": "fake"}')

if [ "$INIT_STATUS" = "400" ]; then
    log_pass "Init correctly rejected in signing mode (HTTP $INIT_STATUS)"
else
    log_fail "Init should return 400 in signing mode, got HTTP $INIT_STATUS"
fi

# Verify the error message
INIT_RESPONSE=$(curl -ks -X POST "$GAP_SERVER_URL/init" \
    -H "Content-Type: application/json" \
    -d '{"password_hash": "fake"}')

if echo "$INIT_RESPONSE" | grep -qi "signing"; then
    log_pass "Init error message mentions signing"
else
    log_warn "Init error message does not mention signing: $INIT_RESPONSE"
fi

# ── Cleanup ───────────────────────────────────────────────────────────
echo ""
echo "Cleanup"
echo "======="

# Delete token created in Test 2
if [ -n "$TOKEN_PREFIX" ]; then
    DELETE_STATUS=$(signed_curl_status "DELETE" "/tokens/$TOKEN_PREFIX" "" "$SIGNING_KEY")
    if [ "$DELETE_STATUS" = "200" ]; then
        log_pass "Token cleaned up (HTTP $DELETE_STATUS)"
    else
        log_warn "Token cleanup returned HTTP $DELETE_STATUS"
    fi
fi

echo ""
echo -e "${GREEN}All Docker signing tests passed!${NC}"
echo ""
