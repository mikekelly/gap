# Architecture Reference

This document provides detailed technical reference for the GAP (Gated Agent Proxy) architecture.

## Patterns

### Wildcard Host Matching
- `*.example.com` matches `sub.example.com` but NOT `a.b.example.com` (single-level only)
- Pattern `*.s3.amazonaws.com` matches `bucket.s3.amazonaws.com` but rejects both `s3.amazonaws.com` (no subdomain) and `evil.com.s3.amazonaws.com` (multiple levels)

### Builder Pattern
All types use `.with_*()` methods for fluent construction.

### Error Context
Use `GapError::storage("msg")` rather than `GapError::Storage("msg".to_string())`.

### Registry Pattern
Centralized metadata storage at key "_registry" solves listing issues on platforms like macOS Keychain. Registry tracks what exists (metadata), while actual values remain at individual keys. `Registry.load()` returns empty `RegistryData` if not found (not an error).

### Credential Storage Pattern
Management API stores credentials as `credential:{plugin}:{field_name}` (e.g., `credential:exa:api_key`). ProxyServer loads ALL fields for a plugin by listing keys with prefix `credential:{plugin}:` and builds a `GAPCredentials` object.

### Token Storage Pattern
Tokens stored as `token:{token_value}` → `{name, created_at}` in SecretStore, enabling direct lookup by token value without caching layer.

### SecretStore Sharing
ProxyServer receives `Arc<dyn SecretStore>` from main.rs (same instance as Management API) to ensure consistent credential access.

## TLS Infrastructure

Uses rcgen 0.13 for certificate generation and management.

### CA Generation
- `CertificateAuthority::generate()` creates self-signed CA valid for 10 years
- CA exported/imported as PEM or DER; PEM used internally for storage

### Dynamic Certificate Signing
- `ca.sign_for_hostname(hostname, validity_opt)` generates certs signed by CA (default 24h validity)
- Returns `(Vec<u8>, Vec<u8>)` for cert and key in DER format
- Certificate caching: In-memory cache with expiry based on validity period

### Integration with rustls
- Use `CertificateDer::from(der_bytes)` and `PrivateKeyDer::try_from(der_bytes)` to convert DER bytes for rustls

### Limitations
- rcgen limitation: Cannot reload `Certificate` from PEM/DER - must recreate CA params for signing
- To sign certificates, recreate CA `CertificateParams` with same DN/settings, call `self_signed(&ca_key_pair)` to get `Certificate` object, then use that to sign new certs with `params.signed_by(&key_pair, &ca_cert, &ca_key_pair)`
- CA returns DER not PEM: `sign_for_hostname()` returns raw DER bytes, not PEM format

## Proxy Infrastructure

MITM proxy implementation with dual TLS and bidirectional streaming.

### Agent Authentication
- Bearer token validation via `Proxy-Authorization` header
- Returns 407 if invalid

### TLS Configuration
- **Agent-side TLS**: Uses dynamic certificate generation with CertificateAuthority for host-specific certs on-demand
- **Upstream TLS**: Uses webpki-roots for system CA trust (TLS_SERVER_ROOTS)
- Note: Use webpki-roots instead of rustls-native-certs for cross-platform consistency

### Transform Pipeline
1. Parse HTTP using `http_utils` module
2. Match host using `plugin_matcher`
3. Load credentials from SecretStore
4. Execute plugin transformation using `PluginRuntime`
5. Serialize modified HTTP
6. Forward to upstream

### Bidirectional Streaming
- Uses `tokio::io::copy` with `tokio::select!` for full-duplex proxying
- Implements HTTP CONNECT tunnel

## Management API

REST API for configuration and monitoring.

### Authentication
- Client sends `password_hash` (SHA512 of password) in request body
- Server verifies Argon2(SHA512(password))
- Verification uses `Argon2::default().verify_password()` with client's SHA512 hash against stored Argon2 hash

### Endpoints
- `/status` - No authentication required
- `/plugins` - List and manage plugins (requires auth)
- `/tokens` - Manage agent tokens (requires auth)
- `/credentials/:plugin/:key` - Manage plugin credentials (requires auth)
- `/activity` - View activity logs (requires auth)

### Token Management
- Full token value only returned on creation (via `token` field)
- List endpoint shows prefix only for security
- Token persistence: Stored in SecretStore with key `token:{token_value}` → `{name, created_at}` JSON

### State Management
- `ApiState` holds:
  - Server start time
  - Ports configuration
  - Password hash
  - Activity log
  - Shared `Arc<dyn SecretStore>`
- Shared storage ensures all endpoints use the same storage backend (respects --data-dir)

## CLI

Command-line interface for GAP management.

### Password Handling
- Uses `rpassword` crate for hidden password input (no echo)
- `GAP_PASSWORD` env var bypasses interactive prompt for testing/automation
- Client-side SHA512 hashing via `sha2` crate before sending to API

### HTTP Client
- Built with `reqwest` 0.12
- Handles JSON requests/responses
- Server URL configurable via `--server` flag (default: http://localhost:9080)

### Command Structure
- Uses clap derive macros with nested subcommands (e.g., `token create`)
- Returns exit code 1 on errors
- Prints errors to stderr

## Plugin Management

Handles plugin installation and lifecycle.

### Installation Flow
1. Uses git2 (0.19) to clone GitHub repos
2. `RepoBuilder` with credentials callback → clone
3. Read `plugin.js` from repository
4. Validate plugin structure
5. Store in SecretStore
6. Automatic cleanup via `tempfile::tempdir()` Drop

### Git2 Integration
- Must use `RepoBuilder` with `FetchOptions` and credentials callback even for public repos
- Direct `Repository::clone()` fails with auth error
- Clone failures return BAD_GATEWAY (502)
- Missing plugin.js returns BAD_REQUEST (400)

### Plugin Credential Schema
Supports two formats:
1. **Simple**: `credentialSchema: ["api_key", "secret"]`
2. **Rich**:
   ```javascript
   credentialSchema: {
     fields: [
       {name: "apiKey", label: "API Key", type: "password", required: true},
       // ...
     ]
   }
   ```
   The runtime extracts just the `name` field from the rich format for internal use.

### Important Notes
- git2 callbacks are not Send: Scope the entire git clone operation in a block to ensure all non-Send types are dropped before any `.await` points in async handlers
- Temp directory cleanup: `tempfile::tempdir()` automatically cleans up when it goes out of scope (RAII)

## Installation

Deployment options and configuration.

### Installation Script
- **install.sh**: Cross-platform (macOS/Linux, x86_64/aarch64)
- Supports build-from-source and binary download modes

### Docker
- **Dockerfile**: Multi-stage build with dependency caching layer
- Uses `rustlang/rust:nightly-slim` (required for edition2024 support)
- Runtime uses non-root user `gap` on Debian Bookworm
- Includes curl for healthcheck

### Docker Testing
- **Dockerfile.test-runner**: Test runner image with curl, jq, and coreutils
- **docker-compose.yml**: Complete test environment with GAP server, mock API, test-runner service (profile: test), and persistent volumes
- **smoke-tests/test-docker-integration.sh**: Integration tests covering init, token creation, credential management, and API access

### Configuration
- **Default ports**:
  - 9443: Proxy
  - 9080: Management API
  - 8080: Mock API (internal)
- **Data directory**:
  - Docker: `/var/lib/gap`
  - Host: `~/.config/gap/` or `$XDG_CONFIG_HOME/gap/`
- **Health check**: Management API `/status` endpoint

### Binaries
- Release binaries at `target/release/gap` and `target/release/gap-server`
- Size: 5-6MB each

### Important Notes
- Rust nightly required for Docker builds due to base64ct 1.8.2+ requiring edition2024 support
- Docker compose profiles: Test-runner uses profile `test`, only runs when invoked with `docker compose --profile test up`
- Docker healthcheck dependencies: Use `depends_on` with `condition: service_healthy` to ensure proper startup ordering
