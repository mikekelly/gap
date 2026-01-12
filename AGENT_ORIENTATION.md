# Agent Orientation

## What This Is
ACP (Agent Credential Proxy) lets AI agents access APIs without seeing your credentials. Agents route requests through the proxy with a token; ACP injects stored credentials and forwards to the API. The agent never sees the actual API keys.

**Security model:**
- Credentials stored in OS keychain (macOS) or under dedicated service user (Linux)
- No API to retrieve credentials - write-only storage
- Agent tokens are for audit/tracking only, not authentication
- Proxy listens on localhost - stolen tokens useless off-machine

## Structure
- **Cargo workspace** with 3 crates:
  - `acp-lib` - Shared library (types, errors)
  - `acp` - CLI binary
  - `acp-server` - Server binary
- `docs/` — Architecture decisions and documentation
- See `README.md` for quick start

## Commands
```bash
cargo build          # Build all workspace members
cargo test           # Run all tests
cargo clippy         # Lint
cargo run --bin acp  # Run CLI
cargo run --bin acp-server  # Run server
```

## Top 5 Critical Gotchas

1. **Wildcard matching is single-level only**: `*.s3.amazonaws.com` matches `bucket.s3.amazonaws.com` but rejects both `s3.amazonaws.com` (no subdomain) and `evil.com.s3.amazonaws.com` (multiple levels). This is a security feature.

2. **PluginRuntime is not Send**: Contains Boa engine with `Rc` types. In async Axum handlers, scope PluginRuntime operations in a block to ensure the runtime is dropped before any `.await` points. Enable `#[axum::debug_handler]` to see detailed Send/Sync errors.

3. **KeychainStore.list() limitation**: Returns empty vec due to security-framework API limitations. This is why we use the Registry pattern for metadata tracking. FileStore provides full list() functionality.

4. **git2 callbacks are not Send**: `RepoBuilder` with `RemoteCallbacks` closures is not `Send`. In async handlers, scope the entire git clone operation in a block to ensure all non-Send types are dropped before any `.await` points.

5. **PluginRuntime single-context limitation**: Loading a plugin overwrites the global `plugin` object in the JS context. Only the most recently loaded plugin's transform function can be executed. Plugin metadata is preserved for all loaded plugins.

## Detailed Reference Documentation

For comprehensive details, see:
- **[docs/reference/types.md](docs/reference/types.md)** - All core types, their purposes, and usage patterns
- **[docs/reference/architecture.md](docs/reference/architecture.md)** - System design, patterns, TLS infrastructure, proxy pipeline, Management API, CLI, plugin management, installation
- **[docs/reference/gotchas.md](docs/reference/gotchas.md)** - Complete list of 30+ implementation caveats with explanations

## Quick Type Reference

Key types you'll use frequently:
- `ACPRequest`, `ACPCredentials`, `ACPPlugin` - HTTP and plugin types
- `AgentToken` - Bearer token (`.token` is a field, not a method)
- `SecretStore` trait - Storage abstraction (`FileStore`, `KeychainStore`)
- `PluginRuntime` - Sandboxed Boa JS runtime for plugins
- `Registry` - Centralized metadata at key `"_registry"`
- `CertificateAuthority` - TLS CA for dynamic cert generation
- `ProxyServer` - MITM HTTPS proxy with agent auth

See [docs/reference/types.md](docs/reference/types.md) for full details.
