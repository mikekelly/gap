# Agent Credential Proxy (ACP)

**Give AI agents secure access to your APIs - without sharing your credentials.**

## Get Started (macOS)

```bash
# Install via Homebrew
brew tap mikekelly/acp
brew install acp-server

# Start the background service
brew services start acp-server

# Initialize with a password (you'll need this for admin operations)
acp init

# Install a plugin (e.g., Exa search API)
acp install mikekelly/exa-acp

# Set your API key
acp set mikekelly/exa-acp:apiKey

# Create a token for your agent
acp token create my-agent
# outputs: acp_xxxxxxxxxxxx
```

Now configure your agent to use the proxy:

```bash
curl -x http://localhost:9443 \
     --cacert ~/.config/acp/ca.crt \
     --proxy-header "Proxy-Authorization: Bearer acp_xxxxxxxxxxxx" \
     -H "Content-Type: application/json" \
     -d '{"query": "latest AI news", "numResults": 3}' \
     https://api.exa.ai/search
```

The agent sends requests without credentials - ACP injects them automatically.

---

## The Problem

AI agents need to call APIs on your behalf - search the web, access your cloud services, interact with third-party tools. But how do you give them access?

Today's options are terrible:
- **Paste credentials into the agent** - Now your secrets live in chat logs, get sent to LLM providers, and could be extracted by prompt injection
- **Set up OAuth flows** - Complex, not supported by most agent frameworks, and still requires trusting the agent with tokens
- **Just don't use APIs** - Severely limits what agents can do for you

## The Solution

ACP sits between your AI agent and the internet as a transparent proxy. When the agent makes a request to an API you've authorized, ACP automatically injects your credentials - the agent never sees them.

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│   AI Agent  │ ──── │     ACP     │ ──── │   Exa API   │
│             │      │  (proxy)    │      │             │
│  "search    │      │  + injects  │      │  sees your  │
│   for X"    │      │  API key    │      │  API key    │
└─────────────┘      └─────────────┘      └─────────────┘
       │
       └── never sees your credentials
```

**Key benefits:**
- **One-way credential flow** - Credentials go into ACP and never come back out. There's no API to retrieve them, no way for an agent to extract them. The only path out is through privilege escalation on your machine.
- **Credentials never leave your machine** - They're stored in your OS keychain (macOS) or encrypted files, and injected at the network layer
- **Scoped access** - Agents only get access to APIs you explicitly authorize via plugins
- **Works with any agent** - If it can use an HTTP proxy, it works with ACP
- **Simple plugin system** - JavaScript transforms define how credentials are injected per API

## Build from Source

### 1. Build and start the server

```bash
git clone https://github.com/mikekelly/agent-credential-proxy.git
cd agent-credential-proxy
cargo build --release

# Start the server
./target/release/acp-server &
```

### 2. Initialize and install a plugin

```bash
# Initialize with a password (you'll need this for admin operations)
./target/release/acp init

# Install the Exa search plugin
./target/release/acp install mikekelly/exa-acp

# Set your Exa API key
./target/release/acp set "mikekelly/exa-acp:apiKey"
```

### 3. Create an agent token

```bash
# Create a token that can use the Exa plugin
./target/release/acp token create my-agent --plugins mikekelly/exa-acp
```

This outputs a token like `acp_19ba8e89e25` - give this to your agent.

### 4. Configure your agent to use the proxy

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

## Project Status

**Core functionality complete:**
- MITM proxy with TLS interception
- JavaScript plugin system with credential injection
- Secure credential storage (macOS Keychain, encrypted files)
- CLI for management
- Management API for programmatic control

## Roadmap

### Native GUI Applications

The CLI works, but managing credentials should be as easy as a password manager. We're building native desktop apps:

| Platform | Status | Notes |
|----------|--------|-------|
| **macOS** | Planned | Swift/SwiftUI, Keychain integration, menu bar app |
| **Linux** | Planned | GTK4, libsecret integration, system tray |
| **Windows** | Planned | WinUI 3, Credential Manager integration |

### Coming Soon

- **Plugin marketplace** - discover and install community plugins
- **Usage analytics** - see which APIs your agents are calling
- **Rate limiting** - prevent runaway agents from burning through quotas
- **Audit logging** - full trail of what credentials were used when

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
