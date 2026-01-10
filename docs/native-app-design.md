# ACP - Agent Credential Proxy

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
│                      acp-server (Rust)                           │
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
│   Upstream API    │    │              acp (CLI)                  │
│   (api.exa.ai)    │    │                                        │
└───────────────────┘    │  acp status                            │
                         │  acp plugin install user/repo          │
                         │  acp service configure exa             │
                         │  acp token create claude-code          │
                         └────────────────────────────────────────┘
```

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Agent reads credentials from env/files | Credentials in secure storage, not filesystem |
| Agent accesses secure storage directly | macOS: Keychain ACL. Linux: different user owns secrets. |
| Agent attaches debugger to acp-server | macOS: SIP blocks debugging signed apps. Linux: different user. |
| Agent installs malicious plugin | Password required for install, entered interactively |
| Agent modifies existing plugin | Plugins in secure storage (Keychain / acp user's directory) |
| Malicious plugin exfiltrates creds | Boa sandbox blocks network/filesystem access |
| Plugin accesses other plugin's creds | Credential scoping - plugins only receive their own namespaced credentials |
| Plugin requests non-declared hosts | Proxy enforces plugin's declared `match` hosts |
| Unauthorized CLI access | Password required for all operations except `status` |
| Agent captures password from CLI | Password entered via secure input (no echo, not in history) |

### Secure Storage by Platform

| Platform | Mechanism | What's Stored | Isolation |
|----------|-----------|---------------|-----------|
| **macOS** | Keychain via `security-framework` | Password hash, CA key, plugins, config, credentials | Code signing ACLs - only signed ACP binary can read |
| **Linux** | File (`/var/lib/acp/`) | Password hash, CA key, plugins, config, credentials | Unix permissions - `acp:acp` user, mode 700 |

```rust
pub enum SecureStore {
    Keychain,  // macOS - everything in Keychain
    File,      // Linux - everything in /var/lib/acp/
}
```

**macOS:** Everything stored in Keychain, protected by code signing ACLs. Agents cannot:
- Read credentials
- Read or modify plugins
- Read or modify config
- Access the password hash

**Linux desktop:** Everything in `/var/lib/acp/`, owned by `acp` system user. Agents (running as your user) cannot access any of it.

**Linux container:** Everything in `--data-dir` (e.g., `/data`). Infrastructure provides encryption at rest. No dedicated user needed - container isolation is sufficient.

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

- User generates tokens via CLI: `acp token create claude-code`
- Proxy validates token on each CONNECT request
- Enables per-agent audit logging

Token storage is out of scope—agents receive tokens via environment variables, project config, or other mechanisms.

### Credential Scoping

Plugins only receive credentials that were explicitly set for them. This prevents a malicious or compromised plugin from accessing credentials belonging to other plugins.

**Storage:** Credentials are namespaced by plugin name:
- `acp set mikekelly/exa-acp:apiKey` → stored as `credential:mikekelly/exa-acp:apiKey`
- `acp set aws-s3:secretAccessKey` → stored as `credential:aws-s3:secretAccessKey`

**At runtime:** When the proxy runs `plugin.transform(request, credentials)`, the `credentials` object only contains keys set for that specific plugin:

```javascript
// mikekelly/exa-acp plugin receives:
credentials = { apiKey: "..." }  // Only mikekelly/exa-acp:* values

// aws-s3 plugin receives:
credentials = { accessKeyId: "...", secretAccessKey: "...", region: "..." }  // Only aws-s3:* values
```

A plugin cannot access another plugin's credentials, even if it tries to request them via the `credentialSchema`.

### Management API Authentication

The CLI uses a **shared secret** (password) set during `acp init`. This password:
- Is stored in secure storage (Keychain on macOS, `acp` user's file on Linux)
- Is never written to user-accessible disk
- Must be entered interactively for protected operations
- Cannot be accessed by agents

```bash
# First-time setup (sets the password)
$ acp init
Password: ••••••••••••
Confirm:  ••••••••••••
✓ Server initialized

# Protected operations require password entry
$ acp plugins
Password: ••••••••••••
  mikekelly/exa-acp  (a1b2c3d4)  api.exa.ai

# Only status is unauthenticated
$ acp status
ACP running on :9443
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
interface ACPPlugin {
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
  transform(request: ACPRequest, credentials: ACPCredentials): ACPRequest;
}

interface ACPRequest {
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array;
}

interface ACPCredentials {
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
    const date = ACP.util.amzDate();
    const signature = ACP.crypto.signAwsV4(request, credentials, date);

    request.headers["Authorization"] = signature;
    request.headers["x-amz-date"] = date;
    request.headers["x-amz-content-sha256"] = ACP.crypto.sha256Hex(request.body || "");
    return request;
  }
};
```

### Runtime Globals

Plugins run with pre-loaded crypto libraries. No imports or bundling needed.

```javascript
globalThis.ACP = {
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
2. ACP:   HTTP/1.1 200 Connection Established
3. Agent: <TLS handshake with ACP>
4. Agent: POST /search HTTP/1.1
5. ACP:   <host check - is api.exa.ai in a plugin's match[]?>
6. ACP:   <load credentials scoped to matching plugin only>
7. ACP:   <run plugin.transform(request, scoped_credentials)>
8. ACP:   <TLS handshake with upstream>
9. ACP:   <forward request with injected credentials>
10. ACP:  <return response to agent>
```

### Host Enforcement

The proxy **only forwards requests to hosts declared in installed plugins**:

1. Each plugin declares `match: ["api.exa.ai"]`
2. On plugin install, user sees and approves the host list
3. At runtime, proxy rejects requests to non-matching hosts with 403

This prevents agents from using the proxy to reach arbitrary endpoints.

### TLS Handling

ACP performs MITM to inspect/modify HTTPS requests:

1. Agent connects to ACP proxy
2. ACP presents a certificate for the target host (signed by ACP's CA)
3. Agent validates certificate (must trust ACP's CA)
4. ACP establishes separate TLS connection to upstream
5. ACP can read/modify HTTP traffic between agent and upstream

**Certificate setup:**
- On first run, `acp-server init` generates a local CA
- CA private key stored in secure storage
- CA public cert written to `~/.config/acp/ca.crt` (or configurable path)
- Agent must trust this CA: `NODE_EXTRA_CA_CERTS=~/.config/acp/ca.crt`

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

GET  /plugins                    → [{ name, sha, match[], installed_at }]
POST /plugins/install            → { url, password } → { name, sha, match[] } (preview)
POST /plugins/install/confirm    → { sha, password } → { ok }
DELETE /plugins/:name            → { password }

POST /credentials/:plugin/:key   → { value, password }
DELETE /credentials/:plugin/:key → { password }

GET  /tokens                     → [{ id, name, prefix, created_at }]
POST /tokens                     → { name, password } → { id, name, token }
DELETE /tokens/:id               → { password }

GET  /activity                   → [{ ts, agent, method, host, path, status, latency_ms }]
GET  /activity/stream            → SSE stream (requires password query param)
```

## CLI

Single binary, same repo as server.

### Authentication Model

All commands except `status` require the shared secret (password) set during `acp init`:

```bash
$ acp plugins
Password: ••••••••••••
  mikekelly/exa-acp  (a1b2c3d4)  api.exa.ai
```

The password is:
- Entered via secure input (no echo, not in shell history)
- Verified against hash in secure storage
- Never stored on user-accessible disk

### Commands

```
# No password required
acp status                          Check if server is running

# Password required - Setup
acp init [--ca-path <path>]         First-time setup (set password, generate CA)
                                    Default CA path: ~/.config/acp/ca.crt

# Password required - Plugins
acp plugins                         List installed plugins
acp install <name>                  Install bundled plugin (e.g., "exa")
acp uninstall <name>                Remove plugin

# Password required - Credentials
acp set <plugin>:<key>              Set credential (interactive value input)

# Password required - Agent Tokens
acp tokens                          List agent tokens (shows prefixes only)
acp token create <name>             Create new agent token
acp token revoke <id>               Revoke agent token

# Password required - Monitoring
acp activity                        Show recent activity
acp activity --follow               Stream activity in real-time
```

### Plugin Naming

- `user/repo` - GitHub install (e.g., `mikekelly/exa-acp`)
- `alphanumeric` - Local install via `--name` (e.g., `myapi`)

The `/` distinguishes GitHub plugins from local plugins.

### Example Flows

```bash
# === FIRST-TIME SETUP ===
$ acp init
    _    ____ ____
   / \  / ___|  _ \
  / _ \| |   | |_) |
 / ___ \ |___|  __/
/_/   \_\____|_|

Password: ••••••••••••
Confirm:  ••••••••••••

✓ Server initialized
✓ CA certificate: ~/.config/acp/ca.crt

# Or with custom cert path
$ acp init --ca-path /path/to/ca.crt

# === INSTALL PLUGIN ===
$ acp install mikekelly/exa-acp

Fetching mikekelly/exa-acp...

  Plugin:  exa-acp
  Version: a1b2c3d4
  Hosts:   api.exa.ai

Password: ••••••••••••

✓ Installed mikekelly/exa-acp

Get your API key from: https://exa.ai/settings/api
Then run: acp set mikekelly/exa-acp:apiKey

# === SET CREDENTIAL ===
$ acp set mikekelly/exa-acp:apiKey

Value:    •••••••••••••••••••••
Password: ••••••••••••

✓ Saved mikekelly/exa-acp:apiKey

# === CREATE AGENT TOKEN ===
$ acp token create claude-code

Password: ••••••••••••

✓ Token created

Save this token - it won't be shown again.

  ACP_TOKEN=acp_a1b2c3d4e5f6...

Configure your agent:
  export HTTPS_PROXY=http://127.0.0.1:9443
  export NODE_EXTRA_CA_CERTS=~/.config/acp/ca.crt
  export ACP_TOKEN=<token above>
```

### Remote Server

```bash
# Override server location
$ acp --server http://192.168.1.100:9080 status

# Environment variable
$ ACP_SERVER=http://192.168.1.100:9080 acp status
```

Only `ACP_SERVER` can be set via environment. The password is always entered interactively.

## Installation

### macOS

```bash
# Install via Homebrew (future)
brew install acp

# Or download binary
curl -L https://github.com/.../acp-darwin-arm64.tar.gz | tar xz
sudo mv acp acp-server /usr/local/bin/

# Initialize (generates CA, admin token, starts server)
acp-server init

# Server runs in foreground, or install as LaunchAgent
acp-server install  # Creates ~/Library/LaunchAgents/com.acp.server.plist
```

### Linux

```bash
# Download and install
curl -L https://github.com/.../acp-linux-amd64.tar.gz | tar xz
sudo ./install.sh

# install.sh does:
# 1. Creates 'acp' system user
# 2. Copies binaries to /usr/local/bin/
# 3. Creates /var/lib/acp/ owned by acp:acp
# 4. Installs systemd service
# 5. Runs 'acp-server init' as acp user
# 6. Prints admin token for user to save
```

**Manual installation:**
```bash
# Create system user
sudo useradd --system --no-create-home --shell /usr/sbin/nologin acp

# Create data directory
sudo mkdir -p /var/lib/acp
sudo chown acp:acp /var/lib/acp
sudo chmod 700 /var/lib/acp

# Install binaries
sudo cp acp acp-server /usr/local/bin/

# Initialize
sudo -u acp acp-server init --data-dir /var/lib/acp
# Save the admin token printed here!

# Install and start systemd service
sudo cp acp-server.service /etc/systemd/system/
sudo systemctl enable --now acp-server
```

### Container

No installation needed - just run the binary with `--data-dir`:

```dockerfile
FROM rust:alpine AS builder
# ... build ...

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/acp-server /usr/local/bin/

EXPOSE 9443 9080
VOLUME /data

ENTRYPOINT ["acp-server", "run", "--data-dir", "/data"]
```

```yaml
# docker-compose.yaml
services:
  acp:
    image: acp-server:latest
    ports:
      - "9443:9443"
      - "9080:9080"
    volumes:
      - acp-data:/data
    environment:
      - ACP_ADMIN_TOKEN=${ACP_ADMIN_TOKEN}

volumes:
  acp-data:
    # Use encrypted volume driver in production
```

**First run:**
```bash
# Initialize (generates CA, prints admin token)
docker run -v acp-data:/data acp-server init --data-dir /data
# Save the admin token!

# Run server
docker run -d -v acp-data:/data -p 9443:9443 -p 9080:9080 acp-server run --data-dir /data
```

For production, use infrastructure-level encryption (encrypted EBS, Kubernetes encrypted secrets, etc.).

## Configuration

### Server Config

```yaml
# /var/lib/acp/config.yaml (Linux)
# ~/Library/Application Support/ACP/config.yaml (macOS)

proxy:
  host: 127.0.0.1
  port: 9443

api:
  host: 127.0.0.1
  port: 9080

tls:
  ca_cert: /var/lib/acp/ca.crt
  ca_key: keychain:acp-ca-key  # macOS; file path on Linux

secrets:
  # "keychain" on macOS, "file" on Linux
  store: keychain

logging:
  level: info
  requests: true  # Log request URLs (not bodies/credentials)

plugins:
  directory: /var/lib/acp/plugins
```

### File Locations

**macOS:**
```
~/.config/acp/
└── ca.crt                # CA cert (copy for agents to trust)

# Everything else in Keychain (not filesystem):
# - acp:password-hash
# - acp:ca-private-key
# - acp:config
# - acp:plugin:<name>
# - acp:credential:<plugin>:<key>
# - acp:tokens
```

**Linux desktop:**
```
~/.config/acp/
└── ca.crt                # CA cert (copy for agents to trust)

/var/lib/acp/             # Owned by acp:acp, mode 700
├── password-hash         # Argon2 hash of password
├── config.yaml           # Server config
├── ca.key                # CA private key
├── ca.crt                # CA public cert
├── secrets.json          # Credentials
├── tokens.json           # Agent tokens
└── plugins/
    └── mikekelly/
        └── exa-acp.js
```

**Container:**
```
/data/                    # Mounted volume (--data-dir /data)
├── password-hash
├── config.yaml
├── ca.key
├── ca.crt
├── secrets.json
├── tokens.json
└── plugins/
```

## Project Structure

```
acp/
├── Cargo.toml
├── src/
│   ├── main.rs                 # CLI entrypoint
│   ├── bin/
│   │   └── acp-server.rs       # Server entrypoint
│   ├── cli/                    # CLI commands
│   │   ├── mod.rs
│   │   ├── status.rs
│   │   ├── plugin.rs
│   │   ├── service.rs
│   │   └── token.rs
│   ├── server/
│   │   ├── mod.rs
│   │   ├── proxy.rs            # HTTPS proxy
│   │   ├── api.rs              # Management API
│   │   └── tls.rs              # Certificate generation/signing
│   ├── plugins/
│   │   ├── mod.rs
│   │   ├── runtime.rs          # Boa integration
│   │   └── globals.rs          # ACP.crypto, ACP.util
│   ├── secrets/
│   │   ├── mod.rs              # SecretStore trait
│   │   ├── keychain.rs         # macOS (security-framework)
│   │   └── file.rs             # Linux (all environments)
│   └── runtime/
│       └── globals.js          # Bundled JS for ACP.* globals
├── plugins/                    # Bundled plugins
│   ├── exa.js
│   └── aws-s3.js
├── scripts/
│   └── install.sh              # Linux installer
└── tests/
    ├── docker-compose.yaml     # Integration tests
    └── ...
```

## Testing

### Local (macOS)

```bash
# Build and run server
cargo build --release
./target/release/acp-server init
./target/release/acp-server run

# In another terminal
./target/release/acp status
./target/release/acp plugin install example/exa-plugin
./target/release/acp service configure exa
./target/release/acp token create test-agent

# Test with curl through proxy
export HTTPS_PROXY=http://127.0.0.1:9443
export NODE_EXTRA_CA_CERTS=~/.config/acp/ca.crt
curl -H "Proxy-Authorization: Bearer <agent-token>" https://api.exa.ai/search
```

### Docker Compose (Integration)

```yaml
# tests/docker-compose.yaml
services:
  acp-server:
    build: ..
    environment:
      - ACP_MASTER_KEY=test-key-do-not-use-in-prod
      - ACP_ADMIN_TOKEN=test-admin-token
    ports:
      - "9443:9443"
      - "9080:9080"

  test-client:
    image: alpine:latest
    depends_on:
      - acp-server
    environment:
      - ACP_SERVER=http://acp-server:9080
      - ACP_ADMIN_TOKEN=test-admin-token
      - HTTPS_PROXY=http://acp-server:9443
    command: |
      sh -c "
        apk add --no-cache curl
        # Test management API
        acp --server http://acp-server:9080 status
        # Test proxy (would need real upstream or mock)
      "
```

```bash
# Run integration tests
cd tests
docker-compose up --build --abort-on-container-exit
```

### Clean Alpine (Installer Test)

```bash
# Test Linux installer in clean environment
docker run --rm -it -v $(pwd):/src alpine:latest sh -c "
  apk add --no-cache bash sudo
  cd /src
  ./scripts/install.sh
  acp-server status
"
```

## v2 Considerations (Future)

- **GUI**: Native menu bar app (Swift on macOS, tray on Windows/Linux)
- **Windows support**: Credential Manager adapter
- **OAuth flows**: Browser-based auth for services that require it
- **Policy engine**: Rate limiting, request filtering, anomaly detection
- **Audit log export**: SIEM integration for enterprise
- **Plugin signing**: Optional verification of plugin sources

## Summary

v1 provides:

1. **Full isolation** - Everything (plugins, config, credentials) in secure storage, not just secrets
2. **Password protection** - Shared secret required for all operations except `status`
3. **Cross-platform** - macOS (Keychain) and Linux (dedicated user or container)
4. **Simple deployment** - Container: just run with `--data-dir`. Desktop: installer script.
5. **Simple plugins** - Plain JavaScript with pre-loaded crypto, no build step
6. **Host enforcement** - Proxy only allows requests to plugin-declared hosts
7. **Credential scoping** - Plugins only receive credentials namespaced to them
8. **CLI-first** - Full functionality via command line, GUI deferred to v2
9. **Remote capable** - Server can run locally or on remote host/container

### Key Decisions

| Decision | Rationale |
|----------|-----------|
| Rust | Memory safety, Boa JS engine, `security-framework` for Keychain |
| Everything in secure storage | Plugins, config, and credentials all protected from agent access |
| Password via interactive input | Never stored on user-accessible disk, not in shell history |
| File-based storage on Linux | Simple. Desktop: dedicated user. Container: infrastructure encryption. |
| No app-level encryption | Co-located key is security theater. Real isolation from user separation or infra. |
| `/var/lib/acp/` on Linux | FHS standard, same as PostgreSQL, Docker, Redis |
| `--data-dir` for containers | No install needed, infrastructure handles encryption |
| Boa JS runtime | Pure Rust, ES2022+, simple sandbox |
| Pre-loaded crypto globals | Plugin authors write plain JS, no bundling |
| Git SHA for plugin versions | Version ID + integrity checksum |
| `user/repo` vs `name` | Clear distinction between GitHub and local plugins |
| SHA512 hashing in transit | Password never sent in plaintext; hashed client-side before API calls |
| Credential scoping per-plugin | Plugins only receive credentials namespaced to them, preventing cross-plugin access |
