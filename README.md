# Agent Credential Proxy (ACP)

**Give AI agents secure access to your APIs - without sharing your credentials.**

## The Problem

AI agents need to call APIs on your behalf - search the web, access your cloud services, interact with third-party tools. But how do you give them access?

Today's approach is not ideal - agents are entrusted with access to API credentials.

## The Solution

ACP lets you grant agents authenticated API access without giving them your credentials.

Agents **opt in** by routing requests through the proxy. You give them a proxy token - not your API keys. When they make a request to an API you've authorized, ACP injects your credentials at the network layer. The agent never sees them.

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   AI Agent  │ ──── │     ACP     │ ──── │   Exa API   │
│             │      │  (proxy)    │      │             │
│  has: proxy │      │  has: your  │      │  sees: your │
│  token only │      │  API keys   │      │  API key    │
└─────────────┘      └─────────────┘      └─────────────┘
```

**Why this matters:**
- **Prompt injection can't leak credentials** - The agent doesn't have them. A malicious prompt can't trick the agent into revealing what it doesn't possess.
- **Credentials never leave your machine** - Stored in your OS keychain (macOS) or encrypted files, injected at the network layer. The proxy only listens on localhost by default.
- **One-way credential flow** - Credentials go into ACP and never come back out. There's no API to retrieve them, no export function. The only path out is privilege escalation on your machine.
- **Scoped access** - Agents only get access to APIs you explicitly authorize via plugins
- **Works with any agent** - If it can use an HTTP proxy, it works with ACP

## Get Started

See [INSTALL.md](INSTALL.md) for detailed installation instructions, platform-specific guidance, and troubleshooting.

### macOS Quick Start

```bash
# Install via Homebrew
brew tap mikekelly/acp
brew install acp-server

# Start the background service
brew services start acp-server

# Initialize with a password (you'll need this for admin operations)
acp init

# Install a plugin (e.g. Exa search API)
acp install mikekelly/exa-acp

# Set your API key for the plugin
acp set mikekelly/exa-acp:apiKey

# Create a token for your agent
acp token create my-agent
# outputs: acp_xxxxxxxxxxxx
```

Now you and your agents can use this to make requests:

```bash
curl -x http://localhost:9443 \
     --cacert ~/.config/acp/ca.crt \
     --proxy-header "Proxy-Authorization: Bearer acp_xxxxxxxxxxxx" \
     -H "Content-Type: application/json" \
     -d '{"query": "latest AI news", "numResults": 3}' \
     https://api.exa.ai/search
```

The agent sends requests without service credentials - ACP injects them automatically.

### Linux Quick Start

#### 1. Download and install binaries

```bash
# Download the latest release (adjust version and arch as needed)
curl -LO https://github.com/mikekelly/acp/releases/latest/download/acp-linux-amd64.tar.gz
tar -xzf acp-linux-amd64.tar.gz
sudo mv acp acp-server /usr/local/bin/
```

#### 2. Create a dedicated user and directories

```bash
# Create acp user (no login shell, no home directory)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin acp

# Create data directory with restricted permissions
sudo mkdir -p /var/lib/acp
sudo chown acp:acp /var/lib/acp
sudo chmod 700 /var/lib/acp
```

#### 3. Create systemd service

```bash
sudo tee /etc/systemd/system/acp-server.service > /dev/null <<EOF
[Unit]
Description=Agent Credential Proxy
After=network.target

[Service]
Type=simple
User=acp
Group=acp
Environment=ACP_DATA_DIR=/var/lib/acp
ExecStart=/usr/local/bin/acp-server
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/acp

[Install]
WantedBy=multi-user.target
EOF
```

#### 4. Start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable acp-server
sudo systemctl start acp-server

# Check status
sudo systemctl status acp-server
```

#### 5. Initialize and configure

```bash
# Initialize with a password
acp init

# Install a plugin
acp install mikekelly/exa-acp

# Set your API key
acp set mikekelly/exa-acp:apiKey

# Create a token for your agent
acp token create my-agent
```

#### 6. Use the proxy

```bash
curl -x http://localhost:9443 \
     --cacert ~/.config/acp/ca.crt \
     --proxy-header "Proxy-Authorization: Bearer acp_xxxxxxxxxxxx" \
     -H "Content-Type: application/json" \
     -d '{"query": "latest AI news", "numResults": 3}' \
     https://api.exa.ai/search
```

### Docker (for containerized agents)

> **Security note:** The Docker deployment is designed for environments where **agents also run in containers**. If your agent runs directly on the host machine, use the native macOS/Linux installation instead - a host-based agent could potentially access the Docker volume and read credentials directly, bypassing the proxy's protection.

The Docker image is ideal for:
- Sandboxed agent environments (agent and ACP both containerized)
- Kubernetes deployments
- CI/CD pipelines with ephemeral agents

#### Quick start

```bash
# Run with persistent storage (required)
docker run -d \
  --name acp-server \
  -v acp-data:/var/lib/acp \
  -p 9443:9443 \
  -p 9080:9080 \
  mikekelly321/acp:latest
```

#### Docker Compose (recommended for containerized agents)

```yaml
services:
  acp-server:
    image: mikekelly321/acp:latest
    volumes:
      - acp-data:/var/lib/acp
    ports:
      - "9443:9443"
      - "9080:9080"
    networks:
      - agent-network

  my-agent:
    image: your-agent-image
    environment:
      - HTTP_PROXY=http://acp-server:9443
      - HTTPS_PROXY=http://acp-server:9443
    networks:
      - agent-network

volumes:
  acp-data:

networks:
  agent-network:
```

This isolates credentials from the agent - the agent container cannot access the `acp-data` volume.

#### Volume requirement

The container **requires** a volume mount for `/var/lib/acp`. Without it, secrets would be lost when the container stops:

```bash
# This will fail with a helpful error
docker run mikekelly321/acp:latest

# For testing only, you can bypass with:
docker run -e ACP_ALLOW_EPHEMERAL=I-understand-secrets-will-be-lost mikekelly321/acp:latest
```

### Build from Source

#### 1. Build and start the server

```bash
git clone https://github.com/mikekelly/agent-credential-proxy.git
cd agent-credential-proxy
cargo build --release

# Start the server
./target/release/acp-server &
```

#### 2. Initialize and install a plugin

```bash
# Initialize with a password (you'll need this for admin operations)
./target/release/acp init

# Install the Exa search plugin
./target/release/acp install mikekelly/exa-acp

# Set your Exa API key
./target/release/acp set "mikekelly/exa-acp:apiKey"
```

#### 3. Create an agent token

```bash
# Create a token that can use the Exa plugin
./target/release/acp token create my-agent --plugins mikekelly/exa-acp
```

This outputs a token like `acp_19ba8e89e25` - give this to your agent.

#### 4. Configure your agent to use the proxy

Point your agent's HTTP traffic through ACP:

```bash
# The proxy runs on localhost:9443
# Your agent needs to trust the CA certificate at ~/.config/acp/ca.crt

# Example with curl:
curl --proxy http://127.0.0.1:9443 \
     --cacert ~/.config/acp/ca.crt \
     --proxy-header "Proxy-Authorization: Bearer acp_19ba8e89e25" \
     -X POST https://api.exa.ai/search \
     -H "Content-Type: application/json" \
     -d '{"query":"latest AI news","numResults":3}'
```

The agent sends the request without any API key - ACP injects it automatically.

## How It Works

1. **Agent makes request** through the proxy with its bearer token
2. **ACP authenticates** the agent and checks which plugins it can use
3. **Plugin matches** the target hostname (e.g., `api.exa.ai`)
4. **Credentials loaded** from secure storage (Keychain on macOS, encrypted file on Linux)
5. **JavaScript transform** injects credentials into the request
6. **Request forwarded** to the actual API

### Security Model

Credentials are **write-only** and **stored outside your user context**:
- **macOS**: Stored in the system Keychain, isolated from user-space processes
- **Linux**: Stored with restricted permissions under a dedicated service user

There's no "get credential" API, no way to list credential values, no export function. The only way to use a credential is through the proxy - and the only way to extract one is privilege escalation to root/admin.

This is a fundamentally different security posture than giving credentials to an agent, where a single prompt injection could exfiltrate them to an attacker-controlled server.

**Agent tokens:** Tokens are for **tracking and audit**, not strong authentication. Any process that can read the token (other agents, scripts, humans with shell access) can use it. The real security boundary is the credential store - tokens just help you see which agent made which request.

Plugins are simple JavaScript:

```javascript
export default {
  name: "exa-acp",
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

Agent tokens control which APIs can be accessed, but not which credentials are used. A stolen token lets someone make requests on your behalf to authorized APIs - similar to API key theft, but scoped to specific services. You can revoke tokens instantly via `acp token delete`.

**Q: How is this different from giving my API keys to the agent?**

With ACP: credentials stay in secure storage, agent gets scoped access via token, you control which APIs, you can revoke instantly.

With direct API keys: credentials in chat logs, sent to LLM providers, vulnerable to prompt injection, no revocation without rotating keys everywhere.

**Q: Can I use this with Claude Code, Cursor, or other IDEs?**

Yes, if the IDE supports HTTP proxy configuration. Point it to `http://localhost:9443` and provide the CA certificate at `~/.config/acp/ca.crt`. Each IDE has different proxy settings - check their documentation.

**Q: Do I need to trust the agent framework?**

You need to trust it not to exfiltrate data it receives from APIs (like search results), but you don't need to trust it with your credentials. The agent never sees them.

## Project Status

**Core functionality complete:**
- MITM proxy with TLS interception
- JavaScript plugin system with credential injection
- Secure credential storage (macOS Keychain, encrypted files)
- CLI for management
- Management API for programmatic control

## Roadmap

### Native GUI Applications

The CLI works, but managing credentials should be as easy as a password manager. We're building native desktop apps with:

- **Push-based approval** - get notified when agents request access tokens or trigger suspicious activity
- **Credential management** - add, remove, and rotate API keys through a familiar UI

| Platform | Status | Notes |
|----------|--------|-------|
| **macOS** | Planned | Swift/SwiftUI, Keychain integration, menu bar app |
| **Linux** | Planned | GTK4, libsecret integration, system tray |
| **Windows** | Planned | WinUI 3, Credential Manager integration |

### Coming Soon

- **Linux distro packages** - .deb, .rpm, and other native packages for easier installation
- **Audit logging** - full trail of what credentials were used when
- **Policy plugins** - custom policies that can assess and block requests
- **Rate limiting policy** - prevent runaway agents from burning through quotas

## Contributing

Contributions welcome! See the codebase structure:

- `acp-lib/` - Core library (proxy, plugins, storage)
- `acp-server/` - Server daemon
- `acp/` - CLI tool

```bash
cargo test        # Run tests
cargo clippy      # Lint
```

## License

MIT
