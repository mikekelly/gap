<p align="center">
  <img src="gap_header.png" alt="GAP Header" width="100%">
</p>

# GAP (Gated Agent Proxy)

**Give AI agents secure access to your APIs - without sharing your credentials.**

## The Problem

AI agents need to call APIs on your behalf - search the web, access your cloud services, interact with third-party tools. But how do you give them access?

Today's approach is not ideal - agents are entrusted with access to API credentials.

## The Solution

GAP lets you grant agents authenticated API access without giving them your credentials.

Agents **opt in** by routing requests through the proxy. You give them a proxy token - not your API keys. When they make a request to an API you've authorized, GAP injects your credentials at the network layer. The agent never sees them.

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   AI Agent  │ ──── │     GAP     │ ──── │   Exa API   │
│             │      │  (proxy)    │      │             │
│  has: proxy │      │  has: your  │      │  sees: your │
│  token only │      │  API keys   │      │  API key    │
└─────────────┘      └─────────────┘      └─────────────┘
```

**Why this matters:**
- **Prompt injection can't leak credentials** - The agent doesn't have them. A malicious prompt can't trick the agent into revealing what it doesn't possess.
- **Credentials never leave your machine** - Stored in your OS keychain (macOS) or under a dedicated service user (Linux). The proxy injects them into requests on your behalf.
- **Stolen tokens are useless off-machine** - Prompt injection could exfiltrate a GAP token, but the proxy only listens on localhost. The token only works on your machine.
- **One-way credential flow** - Credentials go into GAP and never come back out. There's no API to retrieve them, no export function. The only path out is privilege escalation on your machine.
- **Scoped access** - Agents only get access to APIs you explicitly authorize via plugins
- **Works with any agent or software stack** - If it can use an HTTP proxy, it works with GAP
- **CLI protects secrets from shell history** - Credentials are entered via secure prompts, never as command arguments that could end up in shell logs (accessible to agents)

## Get Started

### macOS Quick Start

**Download the native app (recommended):**

1. Download `GAP.dmg` from the [latest GitHub release](https://github.com/mikekelly/gap/releases/latest)
2. Open the DMG and drag Gap to Applications
3. Launch Gap from Applications

Install a gap plugin for a given service (eg. Exa) and set credentials:
```bash
# Install a plugin (e.g. Exa search API)
gap install mikekelly/exa-gap

# Set your API key for the plugin
gap set mikekelly/exa-gap:apiKey
```

Assign a GAP token to an agent (eg. Claude Code)
```bash
gap token create my-agent
# outputs: gap_xxxxxxxxxxxx

cd /path/to/your/project

echo "GAP_TOKEN=gap_xxxxxxxxxxxx" >> .env
```

Install GAP enabled tools (eg. this GAP-enabled fork of exa-mcp-server):
```
claude mcp add exa -- npx -y exa-gapped-mcp
```

The agent can now talk to Exa without direct API credentials - GAP injects them automatically.

### Linux Quick Start

#### 1. Download and install binaries

```bash
# Download the latest release (adjust version and arch as needed)
curl -LO https://github.com/mikekelly/gap/releases/latest/download/gap-linux-amd64.tar.gz
tar -xzf gap-linux-amd64.tar.gz
sudo mv gap gap-server /usr/local/bin/
```

#### 2. Create a dedicated user and directories

```bash
# Create gap user (no login shell, no home directory)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin gap

# Create data directory with restricted permissions
sudo mkdir -p /var/lib/gap
sudo chown gap:gap /var/lib/gap
sudo chmod 700 /var/lib/gap
```

#### 3. Create systemd service

```bash
sudo tee /etc/systemd/system/gap-server.service > /dev/null <<EOF
[Unit]
Description=Gated Agent Proxy
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
```

#### 4. Start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable gap-server
sudo systemctl start gap-server

# Check status
sudo systemctl status gap-server
```

#### 5. Initialize and configure

```bash
# Initialize with a password
gap init

# Install a plugin
gap install mikekelly/exa-gap

# Set your API key
gap set mikekelly/exa-gap:apiKey

# Create a token for your agent
gap token create my-agent
```

#### 6. Use the proxy

```bash
# CA cert location varies by platform:
# - macOS: ~/Library/Application\ Support/gap/ca.crt
# - Linux: /var/lib/gap/ca.crt

curl -x https://localhost:9443 \
     --proxy-cacert ~/Library/Application\ Support/gap/ca.crt \
     --cacert ~/Library/Application\ Support/gap/ca.crt \
     --proxy-header "Proxy-Authorization: Bearer gap_xxxxxxxxxxxx" \
     -H "Content-Type: application/json" \
     -d '{"query": "latest AI news", "numResults": 3}' \
     https://api.exa.ai/search
```

> **Note:** On Linux, replace `~/Library/Application\ Support/gap/ca.crt` with `/var/lib/gap/ca.crt`

### Docker (for containerized agents)

> **Security note:** The Docker deployment is designed for environments where **agents also run in containers**. If your agent runs directly on the host machine, use the native macOS/Linux installation instead - a host-based agent could potentially access the Docker volume and read credentials directly, bypassing the proxy's protection.

The Docker image is ideal for:
- Sandboxed agent environments (agent and GAP both containerized)
- Kubernetes deployments
- CI/CD pipelines with ephemeral agents

#### Quick start

```bash
# Run with persistent storage (required)
docker run -d \
  --name gap-server \
  -v gap-data:/var/lib/gap \
  -p 9443:9443 \
  -p 9080:9080 \
  mikekelly321/gap:latest
```

#### Docker Compose (recommended for containerized agents)

```yaml
services:
  gap-server:
    image: mikekelly321/gap:latest
    volumes:
      - gap-data:/var/lib/gap
      # Export CA cert so agents can trust it
      - ./gap-ca.crt:/var/lib/gap/ca-export.crt:ro
    ports:
      - "9443:9443"
      - "9080:9080"
    networks:
      - agent-network

  my-agent:
    image: your-agent-image
    environment:
      # Proxy uses HTTPS, not HTTP
      - HTTPS_PROXY=https://gap-server:9443
      # Agent needs to trust GAP's CA for both proxy and MITM
      - NODE_EXTRA_CA_CERTS=/certs/ca.crt
      - GAP_TOKEN=${GAP_TOKEN}
    volumes:
      # Mount CA cert from host
      - ./gap-ca.crt:/certs/ca.crt:ro
    networks:
      - agent-network
    depends_on:
      - gap-server

volumes:
  gap-data:

networks:
  agent-network:
```

**Important notes:**
- The proxy now uses **HTTPS** on port 9443 (not HTTP)
- Agents must trust GAP's CA certificate for both the proxy TLS connection and HTTPS MITM
- Export the CA cert from the container: `docker cp gap-server:/var/lib/gap/ca.crt ./gap-ca.crt`
- This isolates credentials from the agent - the agent container cannot access the `gap-data` volume

#### Volume requirement

The container **requires** a volume mount for `/var/lib/gap`. Without it, secrets would be lost when the container stops:

```bash
# This will fail with a helpful error
docker run mikekelly321/gap:latest

# For testing only, you can bypass with:
docker run -e GAP_ALLOW_EPHEMERAL=I-understand-secrets-will-be-lost mikekelly321/gap:latest
```

### Build from Source

#### 1. Build and start the server

```bash
git clone https://github.com/mikekelly/gap.git
cd gap
cargo build --release

# Start the server
./target/release/gap-server &
```

#### 2. Initialize and install a plugin

```bash
# Initialize with a password (you'll need this for admin operations)
./target/release/gap init

# Install the Exa search plugin
./target/release/gap install mikekelly/exa-gap

# Set your Exa API key
./target/release/gap set "mikekelly/exa-gap:apiKey"
```

#### 3. Create an agent token

```bash
# Create a token that can use the Exa plugin
./target/release/gap token create my-agent --plugins mikekelly/exa-gap
```

This outputs a token like `gap_19ba8e89e25` - give this to your agent.

#### 4. Configure your agent to use the proxy

Point your agent's HTTP traffic through GAP:

```bash
# The proxy runs on localhost:9443
# Your agent needs to trust the CA certificate at:
#   macOS: ~/Library/Application Support/gap/ca.crt
#   Linux: /var/lib/gap/ca.crt

# Example with curl (macOS):
curl --proxy https://127.0.0.1:9443 \
     --proxy-cacert ~/Library/Application\ Support/gap/ca.crt \
     --cacert ~/Library/Application\ Support/gap/ca.crt \
     --proxy-header "Proxy-Authorization: Bearer gap_19ba8e89e25" \
     -X POST https://api.exa.ai/search \
     -H "Content-Type: application/json" \
     -d '{"query":"latest AI news","numResults":3}'
```

The agent sends the request without any API key - GAP injects it automatically.

## How It Works

1. **Agent makes request** through the proxy with its bearer token
2. **GAP authenticates** the agent and checks which plugins it can use
3. **Plugin matches** the target hostname (e.g., `api.exa.ai`)
4. **Credentials loaded** from secure storage (Keychain on macOS, service user on Linux)
5. **JavaScript transform** injects credentials into the request
6. **Request forwarded** to the actual API

### Security Model

Credentials are **write-only** and **stored outside your user context**:
- **macOS**: Stored in the system Keychain, isolated from user-space processes
- **Linux**: Stored with restricted permissions under a dedicated service user

There's no "get credential" API, no way to list credential values, no export function. The only way to use a credential is through the proxy - and the only way to extract one is privilege escalation to root/admin.

This is a fundamentally different security posture than giving credentials to an agent, where a single prompt injection could exfiltrate them to an attacker-controlled server.

**Agent tokens:** Tokens are for **tracking and audit**, not strong authentication. Any process that can read the token (other agents, scripts, humans with shell access) can use it. The real security boundary is the credential store - tokens just help you see which agent made which request.

**CLI attack surface:** When you use the CLI to manage credentials (`gap set`, `gap init`), you enter secrets interactively via secure terminal input (no echo, never stored). The CLI immediately hashes these with SHA512 before transmitting to the management API. The plaintext exists in the CLI process memory only briefly (milliseconds). Current transport from CLI to management API is HTTP on localhost. HTTPS using the existing `ca.crt` is on the roadmap for defense in depth. Remaining attack vectors all require host compromise: memory scraping during the brief plaintext window, or keylogger/terminal interception. These are edge cases requiring privilege escalation - and if an attacker has that level of access, they could access the credential store directly anyway.

Plugins are simple JavaScript:

```javascript
export default {
  name: "exa-gap",
  match: ["api.exa.ai"],

  credentialSchema: {
    fields: [
      { name: "apiKey", label: "API Key", type: "password", required: true }
    ]
  },

  transform(request, credentials) {
    request.headers["Authorization"] = `Bearer ${credentials.apiKey}`;
    return request;
  }
};
```

## Common Questions

**Q: Can a malicious agent steal my credentials?**

No. The agent never receives your credentials - they're injected at the network layer. Even a compromised agent can only make requests to APIs you've authorized, and you'll see the activity in your logs.

**Q: What if someone steals the agent token?**

Agent tokens control which APIs can be accessed, but not which credentials are used. A stolen token lets someone make requests on your behalf to authorized APIs - similar to API key theft, but scoped to specific services. You can revoke tokens instantly via `gap token delete`.

**Q: How is this different from giving my API keys to the agent?**

With GAP: credentials stay in secure storage, agent gets scoped access via token, you control which APIs, you can revoke instantly.

With direct API keys: credentials in chat logs, sent to LLM providers, vulnerable to prompt injection, no revocation without rotating keys everywhere.

**Q: Can I use this with Claude Code, Cursor, or other IDEs?**

Yes, if the IDE supports HTTPS proxy configuration. The proxy uses **HTTPS on port 9443** (not HTTP). Point it to `https://localhost:9443` and configure the IDE to trust GAP's CA certificate at:
- **macOS:** `~/Library/Application Support/gap/ca.crt`
- **Linux:** `/var/lib/gap/ca.crt`

Each IDE has different proxy settings - check their documentation.

**Note:** The proxy uses TLS 1.3 with post-quantum key exchange (X25519MLKEM768). macOS system curl (LibreSSL-based) may not be compatible; use an OpenSSL-based curl if needed.

**Q: Do I need to trust the agent framework?**

You need to trust it not to exfiltrate data it receives from APIs (like search results), but you don't need to trust it with your credentials. The agent never sees them.

## Project Status

**Core functionality complete:**
- MITM proxy with TLS interception
- JavaScript plugin system with credential injection
- Secure credential storage (macOS Keychain, Linux service user isolation)
- CLI for management
- Management API for programmatic control

## Roadmap

### Native GUI Applications

The CLI works, but managing credentials should be as easy as a password manager. We're building native desktop apps with:

- **Push-based approval** - get notified when agents request access tokens or trigger suspicious activity
- **Credential management** - add, remove, and rotate API keys through a familiar UI

| Platform | Status | Notes |
|----------|--------|-------|
| **macOS** | Available | Swift/SwiftUI menu bar app with Data Protection Keychain - see [macos-app](./macos-app/) |
| **Linux** | Planned | GTK4, libsecret integration, system tray |
| **Windows** | Planned | WinUI 3, Credential Manager integration |

### Coming Soon

- **HTTPS for CLI → proxy communication** - defense in depth using existing ca.crt to prevent network observers from seeing even hashed shared secrets
- **Linux distro packages** - .deb, .rpm, and other native packages for easier installation
- **Audit logging** - full trail of what credentials were used when
- **Policy plugins** - custom policies that can assess and block requests
- **Rate limiting policy** - prevent runaway agents from burning through quotas

## Contributing

Contributions welcome! See the codebase structure:

- `gap-lib/` - Core library (proxy, plugins, storage)
- `gap-server/` - Server daemon
- `gap/` - CLI tool

```bash
cargo test        # Run tests
cargo clippy      # Lint
```

## License

MIT
