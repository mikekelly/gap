# End-to-End Proxy Smoke Test

Manual test to verify the complete ACP flow: agent makes request through proxy, credentials are injected, upstream API responds.

## Prerequisites

- Built binaries: `acp` and `acp-server`
- Valid Exa API key (get from https://exa.ai)
- Node.js installed (for test client)

## Test Environment Setup

```bash
# Build the binaries
cargo build --release

# Set up paths
export ACP_BIN=./target/release/acp
export ACP_SERVER_BIN=./target/release/acp-server
export ACP_PASSWORD=testpass123

# Create clean test directory
export TEST_DIR=$(mktemp -d)
echo "Test directory: $TEST_DIR"
```

---

## Phase 1: Server Setup

### 1.1 Start server

```bash
$ACP_SERVER_BIN --data-dir "$TEST_DIR" --api-port 9080 --proxy-port 9443 --log-level info &
SERVER_PID=$!
sleep 2
```

**Expected:**
- Server starts without error
- Logs show both API and proxy ports

### 1.2 Initialize

```bash
$ACP_BIN --server http://localhost:9080 init
```

**Expected:**
- Success message
- CA certificate path shown (e.g., `~/.config/acp/ca.crt`)

### 1.3 Verify status

```bash
$ACP_BIN --server http://localhost:9080 status
```

**Expected:**
- Version shown
- Proxy Port: 9443
- API Port: 9080

---

## Phase 2: Plugin & Credentials

### 2.1 Install Exa plugin

```bash
$ACP_BIN --server http://localhost:9080 install mikekelly/exa-acp
```

**Expected:**
- "Plugin 'mikekelly/exa-acp' installed successfully"
- Server log shows: `Installed plugin: mikekelly/exa-acp (matches: ["api.exa.ai"])`

### 2.2 Set Exa API key

```bash
$ACP_BIN --server http://localhost:9080 set mikekelly/exa-acp:apiKey
# Enter your Exa API key when prompted
```

**Expected:**
- "Saved mikekelly/exa-acp:apiKey"

### 2.3 Create agent token

```bash
$ACP_BIN --server http://localhost:9080 token create test-agent
```

**Expected:**
- Token displayed: `ACP_TOKEN=acp_...`
- Save this token for Phase 3

---

## Phase 3: Proxy Test with JavaScript Client

### 3.1 Create test client

Create `test-client.mjs`:

```javascript
// test-client.mjs
// Usage: ACP_TOKEN=acp_xxx node test-client.mjs

const token = process.env.ACP_TOKEN;
if (!token) {
  console.error('Error: ACP_TOKEN environment variable required');
  process.exit(1);
}

const proxyHost = process.env.ACP_PROXY_HOST || 'localhost';
const proxyPort = process.env.ACP_PROXY_PORT || '9443';

// Request body for Exa search
const body = JSON.stringify({
  query: "What is the capital of France?",
  numResults: 1
});

console.log('Making request to api.exa.ai through ACP proxy...');
console.log(`Proxy: ${proxyHost}:${proxyPort}`);

// Use Node's native fetch with HTTPS proxy
// Note: Node.js doesn't natively support HTTPS proxies with fetch
// We'll use the https module directly

import https from 'https';
import http from 'http';
import tls from 'tls';
import fs from 'fs';
import path from 'path';
import os from 'os';

// Load the ACP CA certificate
const caPath = process.env.ACP_CA_PATH || path.join(os.homedir(), '.config', 'acp', 'ca.crt');
let ca;
try {
  ca = fs.readFileSync(caPath);
  console.log(`Loaded CA from: ${caPath}`);
} catch (e) {
  console.error(`Failed to load CA certificate from ${caPath}`);
  console.error('Make sure ACP is initialized and CA exists');
  process.exit(1);
}

// Step 1: Connect to proxy with CONNECT method
const proxyReq = http.request({
  host: proxyHost,
  port: parseInt(proxyPort),
  method: 'CONNECT',
  path: 'api.exa.ai:443',
  headers: {
    'Host': 'api.exa.ai:443',
    'Proxy-Authorization': `Bearer ${token}`
  }
});

proxyReq.on('connect', (res, socket, head) => {
  console.log(`CONNECT response: ${res.statusCode}`);

  if (res.statusCode !== 200) {
    console.error(`Proxy rejected connection: ${res.statusCode}`);
    socket.destroy();
    process.exit(1);
  }

  // Step 2: Upgrade to TLS through the tunnel
  const tlsSocket = tls.connect({
    socket: socket,
    servername: 'api.exa.ai',
    ca: ca,  // Trust ACP's CA for MITM
    rejectUnauthorized: true
  }, () => {
    console.log('TLS connection established through proxy');

    // Step 3: Send HTTP request through TLS tunnel
    const request = [
      'POST /search HTTP/1.1',
      'Host: api.exa.ai',
      'Content-Type: application/json',
      `Content-Length: ${Buffer.byteLength(body)}`,
      'Connection: close',
      '',
      body
    ].join('\r\n');

    console.log('Sending request (without Authorization - proxy should add it)...');
    tlsSocket.write(request);
  });

  let responseData = '';
  tlsSocket.on('data', (chunk) => {
    responseData += chunk.toString();
  });

  tlsSocket.on('end', () => {
    console.log('\n--- Response from Exa ---');

    // Parse HTTP response
    const headerEnd = responseData.indexOf('\r\n\r\n');
    const headers = responseData.substring(0, headerEnd);
    const body = responseData.substring(headerEnd + 4);

    console.log('Headers:', headers.split('\r\n')[0]); // Status line

    try {
      const json = JSON.parse(body);
      console.log('Response body:', JSON.stringify(json, null, 2).substring(0, 500) + '...');

      if (json.results && json.results.length > 0) {
        console.log('\n SUCCESS: Received search results from Exa!');
        console.log('This proves:');
        console.log('  1. Proxy accepted our token');
        console.log('  2. TLS MITM worked (we trusted ACP CA)');
        console.log('  3. Plugin injected Authorization header');
        console.log('  4. Exa accepted the request and responded');
      } else if (json.error) {
        console.log('\n PARTIAL: Request reached Exa but got error:', json.error);
      }
    } catch (e) {
      console.log('Raw body:', body.substring(0, 500));
    }
  });

  tlsSocket.on('error', (err) => {
    console.error('TLS error:', err.message);
  });
});

proxyReq.on('error', (err) => {
  console.error('Proxy connection error:', err.message);
  if (err.code === 'ECONNREFUSED') {
    console.error('Is the ACP server running?');
  }
});

proxyReq.end();
```

### 3.2 Run the test

```bash
# Use the token from step 2.3
export ACP_TOKEN=acp_xxxxx  # Replace with actual token

node test-client.mjs
```

**Expected output:**
```
Making request to api.exa.ai through ACP proxy...
Proxy: localhost:9443
Loaded CA from: /Users/you/.config/acp/ca.crt
CONNECT response: 200
TLS connection established through proxy
Sending request (without Authorization - proxy should add it)...

--- Response from Exa ---
Headers: HTTP/1.1 200 OK
Response body: {"results":[...]...

SUCCESS: Received search results from Exa!
This proves:
  1. Proxy accepted our token
  2. TLS MITM worked (we trusted ACP CA)
  3. Plugin injected Authorization header
  4. Exa accepted the request and responded
```

---

## Phase 4: Cleanup

```bash
kill $SERVER_PID
rm -rf "$TEST_DIR"
```

---

## Failure Modes

| Symptom | Likely Cause |
|---------|--------------|
| CONNECT response: 407 | Invalid or missing token |
| CONNECT response: 502 | Proxy can't reach upstream |
| TLS error: self signed certificate | CA not trusted - check ACP_CA_PATH |
| TLS error: certificate unknown | Proxy not doing MITM correctly |
| Response: 401 Unauthorized | Plugin didn't inject Authorization header |
| Response: 403 Forbidden | API key invalid or plugin transform wrong |
| ECONNREFUSED | Server not running or wrong port |

---

## Test Results Template

| Step | Status | Notes |
|------|--------|-------|
| 1.1 Start server | | |
| 1.2 Initialize | | |
| 1.3 Verify status | | |
| 2.1 Install plugin | | |
| 2.2 Set API key | | |
| 2.3 Create token | | |
| 3.1 Create test client | | |
| 3.2 Run test | | |
| 4 Cleanup | | |

---

## Current Known Gaps

**As of the last audit, these pieces need implementation:**

1. **Proxy server not started** - `main.rs` only starts API, not ProxyServer
2. **No HTTP parsing in proxy** - proxy pipes bytes but doesn't parse/transform requests
3. **Credential set endpoint is TODO** - endpoint exists but doesn't store to SecretStore

These must be fixed before this smoke test will pass.
