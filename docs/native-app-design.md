# GAP - Generic Agent Proxy

A credential proxy that lets AI agents make authenticated API calls without exposing secrets.

## Overview

### Problem

AI agents need to call authenticated APIs (GitHub, Slack, etc.), but exposing credentials to agents is dangerous:
- Prompt injection can trick agents into leaking tokens
- Credentials in agent memory are vulnerable to exfiltration
- Even `echo $GITHUB_TOKEN` is a trivial attack

### Solution

A proxy server that intercepts HTTPS requests and injects credentials:
1. Agent connects to the proxy
2. Agent makes normal HTTPS requests (no credentials)
3. Proxy intercepts, injects credentials from secure storage
4. Upstream receives authenticated request

The agent never sees credentials—they're isolated in the proxy's secure storage.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AI Agent                                 │
│                  (Claude Code, Cursor, etc.)                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS via proxy (:9443)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      gap-server (Rust)                           │
│                                                                  │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│   │HTTPS Proxy  │  │ Management  │  │    Boa JS Runtime       │ │
│   │   :9443     │  │  API :9080  │  │    (plugins)            │ │
│   └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│          │                                      │                │
│          │         ┌────────────────────────────┘                │
│          │         │                                             │
│          ▼         ▼                                             │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │                   Secret Store                           │   │
│   │       ┌─────────────────┐   ┌─────────────────┐         │   │
│   │       │ macOS: Keychain │   │ Linux: File     │         │   │
│   │       └─────────────────┘   └─────────────────┘         │   │
│   └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
        │                         ▲
        │ HTTPS (with creds)      │ HTTP + admin token
        ▼                         │
┌───────────────────┐    ┌────────────────────────────────────────┐
│   Upstream API    │    │              gap (CLI)                  │
│   (api.exa.ai)    │    │                                        │
└───────────────────┘    │  gap status                            │
                         │  gap plugin install user/repo          │
                         │  gap service configure exa             │
                         │  gap token create claude-code          │
                         └────────────────────────────────────────┘
```

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Agent reads credentials from env/files | Credentials in secure storage, not filesystem |
| Agent accesses secure storage directly | macOS: Keychain ACL. Linux: different user owns secrets. |
| Agent attaches debugger to gap-server | macOS: SIP blocks debugging signed apps. Linux: different user. |
| Agent installs malicious plugin | Password required for install, entered interactively |
| Agent modifies existing plugin | Plugins in secure storage (Keychain / gap user's directory) |
| Malicious plugin exfiltrates creds | Boa sandbox blocks network/filesystem access |
| Plugin accesses other plugin's creds | Credential scoping - plugins only receive their own namespaced credentials |
| Plugin requests non-declared hosts | Proxy enforces plugin's declared `match` hosts |
| Unauthorized CLI access | Password required for all operations except `status` |
| Agent captures password from CLI | Password entered via secure input (no echo, not in history) |

### Secure Storage by Platform

| Platform | Mechanism | What's Stored | Isolation |
|----------|-----------|---------------|-----------|
| **macOS** | Keychain via `security-framework` | Password hash, CA key/cert, plugins, credentials, tokens, registry | OS-level Keychain protection |
| **Linux** | File (`/var/lib/gap/`) | Password hash, CA key/cert, plugins, credentials, tokens, registry | Unix permissions - files owned by running user, mode 0600 |
| **Docker** | File (`/var/lib/gap/`) | Password hash, CA key/cert, plugins, credentials, tokens, registry | Container isolation + volume encryption |

**Implementation:**
- `SecretStore` trait with `FileStore` and `KeychainStore` implementations
- `create_store()` factory selects platform-appropriate backend
- `TokenCache` provides invalidate-on-write caching over `SecretStore`
- `Registry` pattern for metadata (stored at key `_registry`)

**macOS:** Everything stored in system Keychain. Benefits:
- OS-level credential protection
- Survives app uninstall/reinstall
- Integration with macOS security model
- Agents running as your user cannot access Keychain entries without user approval

**Linux desktop:** Everything in `/var/lib/gap/` when running as systemd service:
- Files owned by `gap` system user
- Mode 0600 (owner read/write only)
- Agents running as your user cannot access `gap` user's files

**Linux container:** Everything in `/var/lib/gap/` (volume mount):
- Container runs as non-root user `gap` (UID 1000)
- Files have mode 0600
- Volume must be mounted (enforced at startup)
- Infrastructure provides encryption at rest

**Why no application-level encryption?**

If the decryption key is co-located (on disk or in env), encryption adds nothing meaningful. Real security comes from:
- macOS: Keychain ACLs tied to code signing
- Linux desktop: Unix user separation
- Container: Infrastructure encryption + container isolation

### Agent Authentication

Agents authenticate to the proxy using bearer tokens:
```
CONNECT api.exa.ai:443 HTTP/1.1
Proxy-Authorization: Bearer <agent-token>
```

- User generates tokens via CLI: `gap token create claude-code`
- Proxy validates token on each CONNECT request
- Enables per-agent audit logging

Token storage is out of scope—agents receive tokens via environment variables, project config, or other mechanisms.

### Credential Scoping

Plugins only receive credentials that were explicitly set for them. This prevents a malicious or compromised plugin from accessing credentials belonging to other plugins.

**Storage:** Credentials are namespaced by plugin name:
- `gap set mikekelly/exa-gap:apiKey` → stored as `credential:mikekelly/exa-gap:apiKey`
- `gap set aws-s3:secretAccessKey` → stored as `credential:aws-s3:secretAccessKey`

**At runtime:** When the proxy runs `plugin.transform(request, credentials)`, the `credentials` object only contains keys set for that specific plugin:

```javascript
// mikekelly/exa-gap plugin receives:
credentials = { apiKey: "..." }  // Only mikekelly/exa-gap:* values

// aws-s3 plugin receives:
credentials = { accessKeyId: "...", secretAccessKey: "...", region: "..." }  // Only aws-s3:* values
```

A plugin cannot access another plugin's credentials, even if it tries to request them via the `credentialSchema`.

### Management API Authentication

The CLI uses a **shared secret** (password) set during `gap init`. This password:
- Is stored in secure storage (Keychain on macOS, `gap` user's file on Linux)
- Is never written to user-accessible disk
- Must be entered interactively for protected operations
- Cannot be accessed by agents

```bash
# First-time setup (sets the password)
$ gap init
Password: ••••••••••••
Confirm:  ••••••••••••
✓ Server initialized

# Protected operations require password entry
$ gap plugins
Password: ••••••••••••
  mikekelly/exa-gap  (a1b2c3d4)  api.exa.ai

# Only status is unauthenticated
$ gap status
GAP running on :9443
```

## Plugin System

### Runtime: Boa

[Boa](https://boajs.dev/) is a JavaScript engine written in pure Rust:
- No C dependencies - simplifies cross-platform builds
- ES2022+ support
- Easy to embed and sandbox
- Rust memory safety guarantees

### Plugin Interface

```typescript
interface GAPPlugin {
  name: string;

  // Which hosts this plugin handles (ENFORCED by proxy)
  match: string[];  // e.g., ["api.exa.ai"]

  // Defines what credentials the plugin needs (drives CLI prompts)
  credentialSchema: {
    fields: {
      name: string;       // Key in credentials object
      label: string;      // Display name
      type: "text" | "password";
      required: boolean;
    }[];
  };

  // Transform request before sending upstream
  transform(request: GAPRequest, credentials: GAPCredentials): GAPRequest;
}

interface GAPRequest {
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array;
}

interface GAPCredentials {
  [key: string]: string;
}
```

### Plugin Examples

**Simple Bearer Token (Exa):**
```javascript
// plugins/exa.js
export default {
  name: "exa",
  match: ["api.exa.ai"],

  credentialSchema: {
    fields: [
      { name: "apiKey", label: "API Key", type: "password", required: true }
    ]
  },

  transform(request, credentials) {
    request.headers["Authorization"] = `Bearer ${credentials.apiKey}`;
    request.headers["Content-Type"] = "application/json";
    return request;
  }
};
```

**AWS Signature V4:**
```javascript
// plugins/aws-s3.js
export default {
  name: "aws-s3",
  match: ["s3.amazonaws.com", "*.s3.amazonaws.com"],

  credentialSchema: {
    fields: [
      { name: "accessKeyId", label: "Access Key ID", type: "text", required: true },
      { name: "secretAccessKey", label: "Secret Access Key", type: "password", required: true },
      { name: "region", label: "Region", type: "text", required: true }
    ]
  },

  transform(request, credentials) {
    const date = GAP.util.amzDate();
    const signature = GAP.crypto.signAwsV4(request, credentials, date);

    request.headers["Authorization"] = signature;
    request.headers["x-amz-date"] = date;
    request.headers["x-amz-content-sha256"] = GAP.crypto.sha256Hex(request.body || "");
    return request;
  }
};
```

### Runtime Globals

Plugins run with pre-loaded crypto libraries. No imports or bundling needed.

```javascript
globalThis.GAP = {
  crypto: {
    // Hashing (@noble/hashes, bundled)
    sha256: (data: string | Uint8Array) => Uint8Array,
    sha256Hex: (data: string | Uint8Array) => string,
    hmac: (hash: "sha256" | "sha512", key: Uint8Array, data: Uint8Array) => Uint8Array,

    // Signatures (@noble/curves, bundled)
    ecdsa: { sign, verify },
    ed25519: { sign, verify },

    // Convenience for common auth schemes
    signAwsV4: (request, credentials, date) => string,
  },

  util: {
    base64: { encode, decode },
    hex: { encode, decode },
    utf8: { encode, decode },
    now: () => number,          // Unix timestamp
    isoDate: () => string,      // "2024-01-15T10:30:00Z"
    amzDate: () => string,      // "20240115T103000Z"
  },

  log: (...args) => void,
};

globalThis.TextEncoder = TextEncoder;
globalThis.TextDecoder = TextDecoder;
globalThis.URL = URL;
globalThis.URLSearchParams = URLSearchParams;
```

### Sandbox Restrictions

**Blocked:**
- `fetch` / `XMLHttpRequest` - no network access
- `fs` / filesystem APIs - no file access
- `process` / `child_process` - no process spawning
- `eval` / `Function` constructor - no dynamic code execution
- `WebAssembly` - no WASM

Plugins only transform request objects. The Rust server makes all network requests.

## Proxy Server

### Protocol

Standard HTTP CONNECT proxy with bearer token authentication:

```
1. Agent: CONNECT api.exa.ai:443 HTTP/1.1
          Proxy-Authorization: Bearer <agent-token>
2. GAP:   HTTP/1.1 200 Connection Established
3. Agent: <TLS handshake with GAP>
4. Agent: POST /search HTTP/1.1
5. GAP:   <host check - is api.exa.ai in a plugin's match[]?>
6. GAP:   <load credentials scoped to matching plugin only>
7. GAP:   <run plugin.transform(request, scoped_credentials)>
8. GAP:   <TLS handshake with upstream>
9. GAP:   <forward request with injected credentials>
10. GAP:  <return response to agent>
```

### Host Enforcement

The proxy **only forwards requests to hosts declared in installed plugins**:

1. Each plugin declares `match: ["api.exa.ai"]`
2. On plugin install, user sees and approves the host list
3. At runtime, proxy rejects requests to non-matching hosts with 403

This prevents agents from using the proxy to reach arbitrary endpoints.

### TLS Handling

GAP performs MITM to inspect/modify HTTPS requests:

1. Agent connects to GAP proxy
2. GAP presents a certificate for the target host (signed by GAP's CA)
3. Agent validates certificate (must trust GAP's CA)
4. GAP establishes separate TLS connection to upstream
5. GAP can read/modify HTTP traffic between agent and upstream

**Certificate setup:**
- On first run, `gap-server init` generates a local CA
- CA private key stored in secure storage
- CA public cert written to `~/.config/gap/ca.crt` (or configurable path)
- Agent must trust this CA: `NODE_EXTRA_CA_CERTS=~/.config/gap/ca.crt`

### Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 9443 | HTTPS | Proxy - agents connect here |
| 9080 | HTTP | Management API - CLI connects here |

Both configurable via config file or flags.

## Management API

HTTP API for CLI (and future GUI).

**Base URL:** `http://127.0.0.1:9080` (default)

**Authentication:** Password is SHA512 hashed client-side before sending. Server verifies by comparing against stored Argon2 hash of the SHA512 hash.

```
# Unauthenticated
GET  /status                     → { version, uptime, proxy_port, api_port }

# All other endpoints require { password_hash: "..." } in request body
# CLI computes SHA512(password) and sends that
# Server verifies SHA512 hash against stored Argon2(SHA512(password))

GET  /plugins                    → [{ name, repo, match[], installed_at }]
POST /plugins                    → { repo, password_hash } → { name, match[] }
DELETE /plugins/:name            → { password_hash }

POST /credentials/:plugin/:key   → { value, password_hash }
DELETE /credentials/:plugin/:key → { password_hash }

GET  /tokens                     → [{ id, name, prefix, created_at }]
POST /tokens                     → { name, password_hash } → { id, name, token }
DELETE /tokens/:id               → { password_hash }

GET  /activity                   → [{ timestamp, token_id, method, host, path, status_code, duration_ms }]
```

## CLI

Single binary, same repo as server.

### Authentication Model

All commands except `status` require the shared secret (password) set during `gap init`:

```bash
$ gap plugins
Password: ••••••••••••
  mikekelly/exa-gap  (a1b2c3d4)  api.exa.ai
```

The password is:
- Entered via secure input (no echo, not in shell history)
- Verified against hash in secure storage
- Never stored on user-accessible disk

### Commands

```
# No password required
gap status                          Check if server is running

# Password required - Setup
gap init                            First-time setup (set password, generate CA)
                                    CA written to ~/.config/gap/ca.crt

# Password required - Plugins
gap plugins                         List installed plugins
gap install <user/repo>             Install plugin from GitHub (e.g., mikekelly/exa-gap)
gap uninstall <name>                Remove plugin

# Password required - Credentials
gap set <plugin>:<key>              Set credential (interactive value input)

# Password required - Agent Tokens
gap token                           Manage agent tokens (subcommand)
  gap token create <name>           Create new agent token
  gap token list                    List agent tokens (shows prefixes only)
  gap token delete <id>             Delete agent token

# Password required - Monitoring
gap activity                        View activity logs
```

### Plugin Naming

- `user/repo` - GitHub install (e.g., `mikekelly/exa-gap`)
- `alphanumeric` - Local install via `--name` (e.g., `myapi`)

The `/` distinguishes GitHub plugins from local plugins.

### Example Flows

```bash
# === FIRST-TIME SETUP ===
$ gap init
    _    ____ ____
   / \  / ___|  _ \
  / _ \| |   | |_) |
 / ___ \ |___|  __/
/_/   \_\____|_|

Password: ••••••••••••
Confirm:  ••••••••••••

✓ Server initialized
✓ CA certificate: ~/.config/gap/ca.crt

# Or with custom cert path
$ gap init --ca-path /path/to/ca.crt

# === INSTALL PLUGIN ===
$ gap install mikekelly/exa-gap

Fetching mikekelly/exa-gap...

  Plugin:  exa-gap
  Version: a1b2c3d4
  Hosts:   api.exa.ai

Password: ••••••••••••

✓ Installed mikekelly/exa-gap

Get your API key from: https://exa.ai/settings/api
Then run: gap set mikekelly/exa-gap:apiKey

# === SET CREDENTIAL ===
$ gap set mikekelly/exa-gap:apiKey

Value:    •••••••••••••••••••••
Password: ••••••••••••

✓ Saved mikekelly/exa-gap:apiKey

# === CREATE AGENT TOKEN ===
$ gap token create claude-code

Password: ••••••••••••

✓ Token created

Save this token - it won't be shown again.

  GAP_TOKEN=gap_a1b2c3d4e5f6...

Configure your agent:
  export HTTPS_PROXY=http://127.0.0.1:9443
  export NODE_EXTRA_CA_CERTS=~/.config/gap/ca.crt
  export GAP_TOKEN=<token above>
```

### Remote Server

```bash
# Override server location
$ gap --server http://192.168.1.100:9080 status

# Environment variable
$ GAP_SERVER=http://192.168.1.100:9080 gap status
```

Only `GAP_SERVER` can be set via environment. The password is always entered interactively.

## Installation

### macOS

```bash
# Install via Homebrew
brew tap mikekelly/gap
brew install gap-server

# Start as background service
brew services start gap-server

# Initialize (generates CA, sets password)
gap init

# Check status
gap status
```

**Manual installation:**
```bash
# Download binary (adjust version and arch as needed)
curl -LO https://github.com/mikekelly/agent-credential-proxy/releases/latest/download/gap-darwin-arm64.tar.gz
tar -xzf gap-darwin-arm64.tar.gz
sudo mv gap gap-server /usr/local/bin/

# Run server in background
gap-server &

# Initialize
gap init
```

### Linux

See the [README](../README.md#get-started-linux) for detailed Linux installation instructions.

**Quick summary:**
```bash
# Download installer script
curl -LO https://raw.githubusercontent.com/mikekelly/agent-credential-proxy/main/install.sh
chmod +x install.sh

# Run installer (downloads binaries, creates user, sets up systemd)
sudo ./install.sh

# Start the service
sudo systemctl start gap-server
sudo systemctl enable gap-server

# Initialize
gap init
```

**The installer:**
1. Detects architecture (x86_64 or aarch64)
2. Downloads binaries from GitHub releases OR builds from source
3. Creates 'gap' system user (no login shell)
4. Creates `/var/lib/gap/` with restricted permissions (0700)
5. Installs binaries to `/usr/local/bin/`
6. Creates systemd service file
7. Enables and starts the service

**Manual installation:**
```bash
# Create system user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin gap

# Create data directory
sudo mkdir -p /var/lib/gap
sudo chown gap:gap /var/lib/gap
sudo chmod 700 /var/lib/gap

# Download and install binaries
curl -LO https://github.com/mikekelly/agent-credential-proxy/releases/latest/download/gap-linux-amd64.tar.gz
tar -xzf gap-linux-amd64.tar.gz
sudo mv gap gap-server /usr/local/bin/

# Create systemd service
sudo tee /etc/systemd/system/gap-server.service > /dev/null <<EOF
[Unit]
Description=Agent Credential Proxy
After=network.target

[Service]
Type=simple
User=gap
Group=gap
Environment=GAP_DATA_DIR=/var/lib/gap
ExecStart=/usr/local/bin/gap-server
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/gap

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable --now gap-server

# Initialize (as your user, not root)
gap init
```

### Container

See the [README](../README.md#docker-for-containerized-agents) for detailed Docker instructions.

**Quick start:**
```bash
# Run with persistent volume (REQUIRED - will fail without it)
docker run -d \
  --name gap-server \
  -v gap-data:/var/lib/gap \
  -p 9443:9443 \
  -p 9080:9080 \
  mikekelly321/gap:latest

# Initialize (first time only)
docker exec -it gap-server gap init

# Or from host if gap CLI is installed
gap init
```

**Docker Compose (recommended):**
```yaml
services:
  gap-server:
    image: mikekelly321/gap:latest
    volumes:
      - gap-data:/var/lib/gap
    ports:
      - "9443:9443"
      - "9080:9080"
    networks:
      - agent-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9080/status"]
      interval: 10s
      timeout: 5s
      retries: 3

  # Your containerized agent
  my-agent:
    image: your-agent-image
    environment:
      - HTTP_PROXY=http://gap-server:9443
      - HTTPS_PROXY=http://gap-server:9443
    networks:
      - agent-network
    depends_on:
      gap-server:
        condition: service_healthy

volumes:
  gap-data:

networks:
  agent-network:
```

**Volume enforcement:**
- Container REQUIRES a volume mount for `/var/lib/gap`
- Without volume, secrets would be lost on container restart
- For testing only, bypass with: `GAP_ALLOW_EPHEMERAL=I-understand-secrets-will-be-lost`

**Security notes:**
- Runs as non-root user `gap` (UID 1000)
- All files have 0600 permissions
- Use infrastructure-level encryption in production (encrypted EBS, etc.)
- Only suitable when agents also run in containers (isolation boundary)

## Configuration

### Server Config

```yaml
# /var/lib/gap/config.yaml (Linux)
# ~/Library/Application Support/GAP/config.yaml (macOS)

proxy:
  host: 127.0.0.1
  port: 9443

api:
  host: 127.0.0.1
  port: 9080

tls:
  ca_cert: /var/lib/gap/ca.crt
  ca_key: keychain:gap-ca-key  # macOS; file path on Linux

secrets:
  # "keychain" on macOS, "file" on Linux
  store: keychain

logging:
  level: info
  requests: true  # Log request URLs (not bodies/credentials)

plugins:
  directory: /var/lib/gap/plugins
```

### File Locations

**macOS:**
```
~/.config/gap/
└── ca.crt                # CA cert (copy for agents to trust)

# Everything else in Keychain (not filesystem):
# Storage keys use Registry pattern with individual entries:
# - _registry                      # Central metadata (JSON)
# - password_hash                  # Argon2(SHA512(password))
# - ca_private_key                 # CA private key (PEM)
# - ca_certificate                 # CA public cert (PEM)
# - plugin:{name}                  # Plugin code (JS)
# - credential:{plugin}:{field}    # Individual credential fields
# - token:{id}                     # Agent tokens
```

**Linux (systemd service):**
```
~/.config/gap/
└── ca.crt                # CA cert (copy for agents to trust)

/var/lib/gap/             # Owned by gap:gap, mode 0600 per file
├── _registry             # Central metadata (JSON)
├── password_hash         # Argon2 hash
├── ca_private_key        # CA private key (PEM)
├── ca_certificate        # CA public cert (PEM)
├── plugin:{name}         # Individual plugin files
├── credential:{plugin}:{field}  # Individual credential files
└── token:{id}            # Individual token files

# Note: Individual files use base64url-encoded filenames
# File permissions: 0600 (owner read/write only)
```

**Docker:**
```
/var/lib/gap/             # Mounted volume (required)
├── _registry             # Central metadata (JSON)
├── password_hash
├── ca_private_key
├── ca_certificate
├── plugin:{name}
├── credential:{plugin}:{field}
└── token:{id}

# Run as non-root user 'gap' (UID 1000)
# Files have 0600 permissions
```

## Project Structure

```
agent-credential-proxy/
├── Cargo.toml                  # Workspace manifest
├── gap-lib/                    # Shared library
│   ├── src/
│   │   ├── lib.rs
│   │   ├── config.rs
│   │   ├── error.rs
│   │   ├── types.rs            # GAPRequest, GAPCredentials, etc.
│   │   ├── plugin_runtime.rs   # Boa integration
│   │   ├── secret_store.rs     # SecretStore trait
│   │   ├── file_store.rs       # File-based storage
│   │   ├── keychain_store.rs   # macOS Keychain (conditional)
│   │   ├── token_cache.rs      # Token caching layer
│   │   ├── registry.rs         # Metadata registry
│   │   └── certificate_authority.rs  # TLS CA
│   └── tests/
│       ├── integration_test.rs
│       └── e2e_integration_test.rs
├── gap-server/                 # Server binary
│   └── src/
│       ├── main.rs             # Server entrypoint
│       ├── proxy_server.rs     # MITM proxy
│       ├── management_api.rs   # REST API
│       ├── http_utils.rs       # HTTP parsing
│       ├── plugin_matcher.rs   # Host matching
│       └── proxy_transforms.rs # Transform pipeline
├── gap/                        # CLI binary
│   └── src/
│       ├── main.rs             # CLI entrypoint
│       └── commands/           # CLI subcommands
├── plugins/                    # Example plugins
│   └── test-api.js
├── smoke-tests/                # Installation tests
│   ├── test-install.sh
│   └── test-docker.sh
├── Dockerfile
├── Dockerfile.test-runner
└── docker-compose.yml
```

## Testing

### Unit and Integration Tests

```bash
# Run all tests (workspace-wide)
cargo test

# Run with ignored tests (requires manual interaction on macOS for Keychain)
cargo test -- --ignored

# Test specific crate
cargo test -p gap-lib
cargo test -p gap-server
cargo test -p gap

# Run with output
cargo test -- --nocapture
```

**Test organization:**
- Unit tests: Inline with source code (`#[cfg(test)]` modules)
- Integration tests: `gap-lib/tests/integration_test.rs` (plugin pipeline)
- E2E tests: `gap-lib/tests/e2e_integration_test.rs` (full server lifecycle)
- Test plugin: `plugins/test-api.js`

**Test suite status:** 120 tests, 117 passing, 3 ignored on macOS (Keychain prompts)

### Docker Integration Tests

```bash
# Run full integration test suite with Docker
docker compose --profile test up --build --abort-on-container-exit

# This runs:
# 1. gap-server (in container)
# 2. mock-api (httpbin for testing)
# 3. test-runner (bash script with API calls)
```

**Test coverage:**
- Server initialization
- Token creation and authentication
- Plugin installation
- Credential management
- Proxy requests with credential injection

### Smoke Tests

```bash
# Test installation script
./smoke-tests/test-install.sh

# Test Docker image
./smoke-tests/test-docker.sh
```

### Manual Testing

```bash
# Build and run server
cargo build --release
./target/release/gap-server &

# Initialize and configure
./target/release/gap init
./target/release/gap install mikekelly/exa-gap
./target/release/gap set mikekelly/exa-gap:apiKey
./target/release/gap token create test-agent

# Test with curl through proxy
curl -x http://127.0.0.1:9443 \
     --cacert ~/.config/gap/ca.crt \
     --proxy-header "Proxy-Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"query": "test", "numResults": 1}' \
     https://api.exa.ai/search
```

## Roadmap

### Phase 1: Core Platform (Completed)

**Status:** Shipped in v0.1.0

- MITM HTTPS proxy with TLS interception
- Boa JavaScript plugin runtime with sandboxing
- Secure credential storage (macOS Keychain, Linux file-based)
- Plugin system with host enforcement and credential scoping
- Management API (HTTP)
- CLI for all operations
- Docker support with volume enforcement
- Installation scripts for macOS and Linux

### Phase 2: Enhanced Usability (In Progress)

**Goal:** Make GAP easier to use and more discoverable

- [ ] **Native GUI applications**
  - macOS: Swift/SwiftUI menu bar app with Keychain integration
  - Linux: GTK4 system tray with libsecret
  - Windows: WinUI 3 with Credential Manager
- [ ] **Plugin marketplace**
  - Discover community plugins
  - Search and browse by API/service
  - One-click installation
- [ ] **Improved activity logging**
  - Real-time streaming (`gap activity --follow`)
  - Export to JSON/CSV
  - Filter by time range, agent, or host
- [ ] **Better documentation**
  - Video tutorials
  - Plugin authoring guide
  - Common integration patterns

### Phase 3: Enterprise Features (Planned)

**Goal:** Production-ready for teams and organizations

- [ ] **Multi-user support**
  - Per-user credential isolation
  - Team-shared credentials with RBAC
  - Audit logging per user
- [ ] **Policy engine**
  - Rate limiting (per-token, per-plugin, per-host)
  - Request filtering (block specific paths, methods)
  - Anomaly detection (unusual usage patterns)
  - Cost tracking (API quota management)
- [ ] **Enhanced security**
  - Plugin signing and verification
  - Mandatory 2FA for admin operations
  - Secret rotation automation
  - Hardware security module (HSM) integration
- [ ] **Audit & Compliance**
  - SIEM integration (Splunk, Datadog, etc.)
  - Immutable audit logs
  - Compliance reports (SOC2, GDPR)
- [ ] **OAuth & SSO flows**
  - Browser-based OAuth for services requiring it
  - SAML/OIDC for enterprise identity providers
  - Refresh token management

### Phase 4: Advanced Capabilities (Future)

**Goal:** Handle complex authentication and scaling

- [ ] **Windows support**
  - Native Windows Credential Manager storage
  - Windows installer (MSI)
  - PowerShell integration
- [ ] **Advanced authentication schemes**
  - Mutual TLS (mTLS)
  - JWT signing with rotation
  - Custom signature algorithms
- [ ] **High availability**
  - Clustered deployment
  - Credential replication
  - Load balancing
- [ ] **Developer experience**
  - Plugin testing framework
  - Mock mode for local development
  - Plugin debugging tools
  - TypeScript types for plugin development
- [ ] **Agent framework integrations**
  - LangChain plugin
  - AutoGPT integration
  - Claude Code configuration helper
  - Cursor integration

## Summary

### Current Status (v0.1.x)

GAP is production-ready for individual developers and small teams. The core platform is complete:

1. **Full isolation** - Credentials stored in OS-level secure storage (Keychain/files), never exposed to agents
2. **Password protection** - Interactive password input required for all admin operations
3. **Cross-platform** - macOS (Keychain), Linux (file-based), Docker (volume-based)
4. **Simple deployment** - Homebrew on macOS, installer script on Linux, Docker image on Docker Hub
5. **Simple plugins** - Plain JavaScript with pre-loaded crypto, no build step required
6. **Host enforcement** - Proxy only forwards to plugin-declared hosts
7. **Credential scoping** - Plugins only receive their own namespaced credentials
8. **CLI-first** - Full functionality via command line (GUI in roadmap)
9. **Remote capable** - Server can run locally or on remote host/container
10. **GitHub plugin installation** - Install community plugins directly from GitHub repos

### What's Missing

- Native GUI applications (CLI only)
- Real-time activity streaming (`--follow` flag)
- Windows support
- OAuth flows (only static credentials)
- Multi-user support
- Rate limiting and policy enforcement
- Plugin marketplace/discovery

### Key Decisions

| Decision | Rationale |
|----------|-----------|
| Rust | Memory safety, Boa JS engine, `security-framework` for Keychain |
| Everything in secure storage | Plugins, config, and credentials all protected from agent access |
| Password via interactive input | Never stored on user-accessible disk, not in shell history |
| File-based storage on Linux | Simple. Desktop: dedicated user. Container: infrastructure encryption. |
| No app-level encryption | Co-located key is security theater. Real isolation from user separation or infra. |
| `/var/lib/gap/` on Linux | FHS standard, same as PostgreSQL, Docker, Redis |
| `--data-dir` for containers | No install needed, infrastructure handles encryption |
| Boa JS runtime | Pure Rust, ES2022+, simple sandbox |
| Pre-loaded crypto globals | Plugin authors write plain JS, no bundling |
| Git SHA for plugin versions | Version ID + integrity checksum |
| `user/repo` vs `name` | Clear distinction between GitHub and local plugins |
| SHA512 hashing in transit | Password never sent in plaintext; hashed client-side before API calls |
| Credential scoping per-plugin | Plugins only receive credentials namespaced to them, preventing cross-plugin access |
