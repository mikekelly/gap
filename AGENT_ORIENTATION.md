# Agent Orientation

## Purpose
Agent credential proxy — manages credential access for AI agents.

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

## Core Types (acp-lib)
- `ACPRequest` - HTTP request with method, url, headers, body
- `ACPCredentials` - String key-value map for plugin credentials
- `ACPPlugin` - Plugin definition with host matching (supports wildcards like `*.s3.amazonaws.com`)
- `AgentToken` - Bearer token for agent authentication
- `Config` - Runtime configuration
- `AcpError` - Unified error type with context helpers
- `PluginRuntime` - Sandboxed Boa JS runtime with ACP.crypto, ACP.util, TextEncoder/TextDecoder
- `SecretStore` - Async trait for secure storage (FileStore, KeychainStore implementations)
- `FileStore` - File-based storage with 0600 permissions, base64url-encoded filenames
- `KeychainStore` - macOS Keychain integration (conditional compilation)
- `create_store()` - Factory for platform-appropriate storage
- `CertificateAuthority` - TLS CA for dynamic certificate generation (Phase 3)

## Patterns
- **Wildcard host matching**: `*.example.com` matches `sub.example.com` but NOT `a.b.example.com` (single-level only)
- **Builder pattern**: All types use `.with_*()` methods for fluent construction
- **Error context**: Use `AcpError::storage("msg")` rather than `AcpError::Storage("msg".to_string())`
- **TLS certificate caching**: Generated certificates cached by hostname with expiry; auto-cleanup on access

## TLS Infrastructure (rcgen 0.13)
- **CA generation**: `CertificateAuthority::generate()` creates self-signed CA valid for 10 years
- **Dynamic cert signing**: `ca.sign_for_hostname()` generates certs signed by CA (default 24h validity)
- **PEM/DER support**: CA exported/imported as PEM or DER; PEM used internally for storage
- **Certificate caching**: In-memory cache with expiry based on validity period
- **rcgen limitation**: Cannot reload `Certificate` from PEM/DER - must recreate CA params for signing

## Gotchas
- **Wildcard matching is single-level only**: The pattern `*.s3.amazonaws.com` matches `bucket.s3.amazonaws.com` but rejects both `s3.amazonaws.com` (no subdomain) and `evil.com.s3.amazonaws.com` (multiple levels)
- **Token serialization**: `AgentToken` uses `#[serde(skip_serializing)]` on the `token` field to prevent accidental exposure in JSON responses
- **Boa 0.19 API**: When using Boa engine, must import `JsArgs` trait for `.get_or_undefined()`, use `JsString::from()` for string literals in API calls, import `base64::Engine` trait for `.encode()` method on BASE64_STANDARD
- **KeychainStore.list() limitation**: Returns empty vec due to security-framework API limitations. FileStore provides full list() functionality.
- **Storage key encoding**: FileStore uses base64url encoding for filenames to handle colons and slashes in keys safely across filesystems
- **rcgen 0.13 signing**: To sign certificates, recreate CA `CertificateParams` with same DN/settings, call `self_signed(&ca_key_pair)` to get `Certificate` object, then use that to sign new certs with `params.signed_by(&key_pair, &ca_cert, &ca_key_pair)`
