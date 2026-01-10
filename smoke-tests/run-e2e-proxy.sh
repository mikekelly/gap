#!/bin/bash
set -e

# E2E Proxy Smoke Test Runner
# Automates the manual test documented in e2e-proxy.md

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Setup
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

export ACP_BIN="$WORKSPACE_ROOT/target/release/acp"
export ACP_SERVER_BIN="$WORKSPACE_ROOT/target/release/acp-server"
export ACP_PASSWORD="testpass123"

# Create clean test directory
export TEST_DIR=$(mktemp -d)
log_step "Created test directory: $TEST_DIR"

# Cleanup function
cleanup() {
    log_step "Cleaning up..."
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
    log_success "Cleanup complete"
}
trap cleanup EXIT

# Phase 1: Server Setup

log_step "Phase 1.1: Starting server"
$ACP_SERVER_BIN --data-dir "$TEST_DIR" --api-port 9080 --proxy-port 9443 --log-level warn > "$TEST_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 3

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    log_error "Server failed to start"
    cat "$TEST_DIR/server.log"
    exit 1
fi
log_success "Server started (PID: $SERVER_PID)"

log_step "Phase 1.2: Initializing server"
# Export CA to test directory to avoid conflicts with other tests
export ACP_CA_PATH="$TEST_DIR/ca.crt"
if ! $ACP_BIN --server http://localhost:9080 init --ca-path "$ACP_CA_PATH" 2>&1 | tee "$TEST_DIR/init.log"; then
    log_error "Initialization failed"
    cat "$TEST_DIR/server.log"
    exit 1
fi
log_success "Server initialized"
log_step "CA certificate: $ACP_CA_PATH"

log_step "Phase 1.3: Verifying status"
$ACP_BIN --server http://localhost:9080 status
log_success "Status verified"

# Phase 2: Plugin & Credentials

log_step "Phase 2.1: Installing test plugin locally"
# Create a simple test plugin instead of installing from GitHub
cat > "$TEST_DIR/test-plugin.js" << 'EOF'
var plugin = {
    name: "test-echo",
    matchPatterns: ["echo.free.beeceptor.com"],
    credentialSchema: [],
    transform: function(request, credentials) {
        // Add a custom header to verify transformation
        request.headers["X-ACP-Test"] = "smoke-test-passed";
        request.headers["X-ACP-Timestamp"] = new Date().toISOString();
        return request;
    }
};
EOF

# Store plugin in data directory using FileStore format
mkdir -p "$TEST_DIR/plugins"
cp "$TEST_DIR/test-plugin.js" "$TEST_DIR/plugin:test-echo"
log_success "Test plugin created and stored"

log_step "Phase 2.2: Creating agent token"
TOKEN_OUTPUT=$($ACP_BIN --server http://localhost:9080 token create test-agent 2>&1)
echo "$TOKEN_OUTPUT"

# Extract token from output
export ACP_TOKEN=$(echo "$TOKEN_OUTPUT" | grep -o 'acp_[a-zA-Z0-9_-]*' || true)
if [ -z "$ACP_TOKEN" ]; then
    log_error "Failed to extract token from output"
    echo "$TOKEN_OUTPUT"
    exit 1
fi
log_success "Token created: ${ACP_TOKEN:0:15}..."

# Phase 3: Proxy Test

log_step "Phase 3.1: Creating test client"
cat > "$TEST_DIR/test-client.mjs" << 'EOFJS'
// Simple proxy test client
import https from 'https';
import http from 'http';
import tls from 'tls';
import fs from 'fs';

const token = process.env.ACP_TOKEN;
const caPath = process.env.ACP_CA_PATH;
const proxyHost = process.env.ACP_PROXY_HOST || 'localhost';
const proxyPort = process.env.ACP_PROXY_PORT || '9443';

if (!token) {
  console.error('Error: ACP_TOKEN required');
  process.exit(1);
}

// Load CA certificate
let ca;
try {
  ca = fs.readFileSync(caPath);
  console.log(`Loaded CA from: ${caPath}`);
} catch (e) {
  console.error(`Failed to load CA from ${caPath}:`, e.message);
  process.exit(1);
}

// Connect to proxy
const proxyReq = http.request({
  host: proxyHost,
  port: parseInt(proxyPort),
  method: 'CONNECT',
  path: 'echo.free.beeceptor.com:443',
  headers: {
    'Host': 'echo.free.beeceptor.com:443',
    'Proxy-Authorization': `Bearer ${token}`
  }
});

proxyReq.on('connect', (res, socket, head) => {
  console.log(`CONNECT response: ${res.statusCode}`);

  if (res.statusCode !== 200) {
    console.error(`Proxy rejected: ${res.statusCode} ${res.statusMessage}`);
    socket.destroy();
    process.exit(1);
  }

  // Establish TLS through tunnel
  const tlsSocket = tls.connect({
    socket: socket,
    servername: 'echo.free.beeceptor.com',
    ca: ca,
    rejectUnauthorized: true
  }, () => {
    console.log('TLS established through proxy');

    // Send HTTP request
    const request = [
      'GET / HTTP/1.1',
      'Host: echo.free.beeceptor.com',
      'Connection: close',
      '',
      ''
    ].join('\r\n');

    console.log('Sending test request...');
    tlsSocket.write(request);
  });

  let responseData = '';
  tlsSocket.on('data', (chunk) => {
    responseData += chunk.toString();
  });

  tlsSocket.on('end', () => {
    console.log('\n--- Response ---');

    // Parse response
    const headerEnd = responseData.indexOf('\r\n\r\n');
    const headers = responseData.substring(0, headerEnd);
    const statusLine = headers.split('\r\n')[0];

    console.log('Status:', statusLine);

    // Check for our custom headers in the echo response
    if (responseData.includes('X-ACP-Test') || responseData.includes('X-Acp-Test')) {
      console.log('\n✓ SUCCESS: Transform verified!');
      console.log('  - Proxy accepted token');
      console.log('  - TLS MITM worked');
      console.log('  - Plugin transformation executed');
      console.log('  - Custom header present in echo');
      process.exit(0);
    } else {
      console.log('\n✗ PARTIAL: Request succeeded but transform not verified');
      console.log('Response body preview:');
      console.log(responseData.substring(0, 1000));
      process.exit(1);
    }
  });

  tlsSocket.on('error', (err) => {
    console.error('TLS error:', err.message);
    process.exit(1);
  });
});

proxyReq.on('error', (err) => {
  console.error('Proxy error:', err.message);
  if (err.code === 'ECONNREFUSED') {
    console.error('Is ACP server running?');
  }
  process.exit(1);
});

proxyReq.end();
EOFJS
log_success "Test client created"

log_step "Phase 3.2: Running proxy test"
if node "$TEST_DIR/test-client.mjs"; then
    log_success "E2E smoke test PASSED!"
    echo ""
    echo "Summary:"
    echo "  ✓ Server initialization"
    echo "  ✓ Plugin installation"
    echo "  ✓ Token creation"
    echo "  ✓ Proxy authentication"
    echo "  ✓ TLS MITM"
    echo "  ✓ Plugin transformation"
    echo ""
    exit 0
else
    log_error "E2E smoke test FAILED"
    echo ""
    echo "Server logs:"
    cat "$TEST_DIR/server.log"
    exit 1
fi
