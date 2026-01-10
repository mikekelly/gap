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
- `AgentToken` - Bearer token for agent authentication (token field is public for direct access)
- `Config` - Runtime configuration
- `AcpError` - Unified error type with context helpers (includes Network and Protocol variants)
- `PluginRuntime` - Sandboxed Boa JS runtime with ACP.crypto, ACP.util, ACP.log, TextEncoder/TextDecoder, URL/URLSearchParams
- `SecretStore` - Async trait for secure storage (FileStore, KeychainStore implementations)
- `FileStore` - File-based storage with 0600 permissions, base64url-encoded filenames
- `KeychainStore` - macOS Keychain integration (conditional compilation)
- `create_store()` - Factory for platform-appropriate storage
- `CertificateAuthority` - TLS CA for dynamic certificate generation (Phase 3)
- `ProxyServer` - MITM HTTPS proxy with agent authentication and bidirectional streaming (Phase 4)

## Patterns
- **Wildcard host matching**: `*.example.com` matches `sub.example.com` but NOT `a.b.example.com` (single-level only)
- **Builder pattern**: All types use `.with_*()` methods for fluent construction
- **Error context**: Use `AcpError::storage("msg")` rather than `AcpError::Storage("msg".to_string())`
- **TLS certificate caching**: Generated certificates cached by hostname with expiry; auto-cleanup on access

## TLS Infrastructure (rcgen 0.13)
- **CA generation**: `CertificateAuthority::generate()` creates self-signed CA valid for 10 years
- **Dynamic cert signing**: `ca.sign_for_hostname(hostname, validity_opt)` generates certs signed by CA (default 24h validity), returns `(Vec<u8>, Vec<u8>)` for cert and key in DER format
- **PEM/DER support**: CA exported/imported as PEM or DER; PEM used internally for storage
- **Certificate caching**: In-memory cache with expiry based on validity period
- **rcgen limitation**: Cannot reload `Certificate` from PEM/DER - must recreate CA params for signing
- **rustls integration**: Use `CertificateDer::from(der_bytes)` and `PrivateKeyDer::try_from(der_bytes)` to convert DER bytes for rustls

## Proxy Infrastructure (Phase 4)
- **MITM proxy**: Implements HTTP CONNECT tunnel with dual TLS (agent-side and upstream)
- **Agent authentication**: Bearer token validation via `Proxy-Authorization` header (returns 407 if invalid)
- **Dynamic cert generation**: Uses CertificateAuthority to generate host-specific certs on-demand
- **Upstream TLS**: Uses webpki-roots for system CA trust (TLS_SERVER_ROOTS)
- **Bidirectional streaming**: tokio::io::copy with tokio::select! for full-duplex proxying

## Management API (Phase 6)
- **Authentication**: Client sends `password_hash` (SHA512 of password) in request body; server verifies Argon2(SHA512(password))
- **Endpoints**: `/status` (no auth), `/plugins`, `/tokens`, `/credentials/:plugin/:key`, `/activity` (all require auth)
- **Token management**: Full token value only returned on creation (via `token` field); list endpoint shows prefix only
- **State management**: `ApiState` holds server start time, ports, password hash, tokens, and activity log

## CLI (Phase 7)
- **Password input**: Uses `rpassword` crate for hidden password input (no echo)
- **ACP_PASSWORD env var**: Set `ACP_PASSWORD` to bypass interactive password prompt for testing/automation
- **Password hashing**: Client-side SHA512 hashing via `sha2` crate before sending to API
- **HTTP client**: Built with `reqwest` 0.12, handles JSON requests/responses
- **Server URL**: Configurable via `--server` flag (default: http://localhost:9080)
- **Command structure**: Uses clap derive macros with nested subcommands (e.g., `token create`)
- **Error handling**: Returns exit code 1 on errors, prints to stderr

## Testing (Phase 8)
- **Integration tests**: Located in `acp-lib/tests/` for end-to-end testing
  - `integration_test.rs` - Plugin pipeline tests (FileStore → PluginRuntime → Transform)
  - `e2e_integration_test.rs` - Full system E2E tests (server → API → storage)
- **E2E test infrastructure**: `TestServer` helper spawns `acp-server` in subprocess with dynamic ports and temp directories
- **Bundled plugins**: Production-ready plugins in `plugins/` directory (`exa.js`, `aws-s3.js`)
- **Plugin testing**: Use `PluginRuntime::load_plugin_from_code()` to load plugins from files for testing (avoids SecretStore dependency)
- **Test suite**: 120 tests across all workspace crates (117 passing, 3 ignored on macOS)
- **Test organization**: Unit tests inline with source, integration tests in `tests/` directory
- **Platform differences**: Some E2E tests ignored on macOS due to Keychain requiring user interaction. Run with `--ignored` for manual testing.
- **Smoke tests**: Located in `smoke-tests/` directory for installation verification (`test-install.sh`, `test-docker.sh`)

## Plugin Management
- **Plugin installation**: Uses git2 (0.19) to clone GitHub repos instead of HTTP fetch
- **Installation flow**: `RepoBuilder` with credentials callback → clone → read `plugin.js` → validate → store → cleanup (automatic via tempfile Drop)
- **git2 credentials**: Must use `RepoBuilder` with `FetchOptions` and credentials callback even for public repos. Direct `Repository::clone()` fails with auth error.
- **Temp directory cleanup**: `tempfile::tempdir()` automatically cleans up when it goes out of scope (RAII)
- **Error mapping**: Clone failures return BAD_GATEWAY (502), missing plugin.js returns BAD_REQUEST (400)

## Installation (Phase 8.3)
- **install.sh**: Cross-platform installation script (macOS/Linux, x86_64/aarch64) with build-from-source and binary download support
- **Dockerfile**: Multi-stage build with dependency caching layer; runtime uses non-root user `acp` on Debian Bookworm
- **docker-compose.yml**: Complete test environment with ACP server, mock API (httpbin), and persistent volumes
- **Binaries**: Release binaries at `target/release/acp` and `target/release/acp-server` (5-6MB each)
- **Default ports**: 9443 (proxy), 9080 (management API)
- **Data directory**: `/var/lib/acp` in Docker, `~/.config/acp/` or `$XDG_CONFIG_HOME/acp/` on host systems
- **Health check**: Management API `/status` endpoint used for Docker health checks

## Gotchas
- **Wildcard matching is single-level only**: The pattern `*.s3.amazonaws.com` matches `bucket.s3.amazonaws.com` but rejects both `s3.amazonaws.com` (no subdomain) and `evil.com.s3.amazonaws.com` (multiple levels)
- **Token serialization**: `AgentToken` uses `#[serde(skip_serializing)]` on the `token` field to prevent accidental exposure in JSON responses
- **Token field access**: `AgentToken.token` is a public field (not a method) - access via `token.token.clone()` not `token.token()`
- **Boa 0.19 API**: When using Boa engine, must import `JsArgs` trait for `.get_or_undefined()`, use `JsString::from()` for string literals in API calls, import `base64::Engine` trait for `.encode()` method on BASE64_STANDARD
- **Boa closures with state**: `NativeFunction::from_fn_ptr()` only accepts pure function pointers, not closures that capture variables. To maintain state, use JavaScript globals or context properties instead. Example: Store logs in `__acp_logs` JavaScript array rather than Rust Rc<RefCell<Vec<String>>>
- **KeychainStore.list() limitation**: Returns empty vec due to security-framework API limitations. FileStore provides full list() functionality.
- **Storage key encoding**: FileStore uses base64url encoding for filenames to handle colons and slashes in keys safely across filesystems
- **rcgen 0.13 signing**: To sign certificates, recreate CA `CertificateParams` with same DN/settings, call `self_signed(&ca_key_pair)` to get `Certificate` object, then use that to sign new certs with `params.signed_by(&key_pair, &ca_cert, &ca_key_pair)`
- **CA returns DER not PEM**: `sign_for_hostname()` returns raw DER bytes `(Vec<u8>, Vec<u8>)` for certificate and key, not PEM format
- **rustls-native-certs vs webpki-roots**: Use webpki-roots (TLS_SERVER_ROOTS) for cross-platform system CA trust; rustls-native-certs has platform-specific quirks
- **Axum authentication**: Custom extractors using `FromRequest` with request body are complex in Axum 0.7. Simpler to use helper functions that take `Bytes` parameter and verify authentication manually in each handler.
- **Argon2 password hashing**: Client sends SHA512(password), server stores Argon2(SHA512(password)). Verification uses `Argon2::default().verify_password()` with client's SHA512 hash against stored Argon2 hash.
- **PluginRuntime single-context limitation**: Loading a plugin overwrites the global `plugin` object in the JS context. Only the most recently loaded plugin's transform function can be executed. Plugin metadata (name, patterns, schema) is preserved for all loaded plugins.
- **PluginRuntime loading methods**: Use `load_plugin(name, store)` to load from SecretStore (async), or `load_plugin_from_code(name, code)` to load from string (sync). Both cache the plugin for `execute_transform()`. Using `execute()` + `extract_plugin_metadata()` alone does NOT cache the plugin.
- **PluginRuntime timeout limitation**: `execute_transform_with_timeout()` cannot interrupt tight infinite loops in JavaScript (Boa limitation). It measures elapsed time after execution completes, so only catches slow operations that eventually finish.
- **Environment variable test isolation**: Tests modifying environment variables must use a static Mutex to serialize execution and an RAII guard to ensure cleanup, as env vars are process-global and tests run in parallel.
- **E2E test binary resolution**: Use `std::env::var("CARGO_BIN_EXE_acp-server")` with fallback to workspace-relative path for finding test binaries. The env var is only set when using `cargo test`, not `cargo build`.
- **E2E test keychain isolation (macOS)**: Tests using server init will trigger Keychain prompts on macOS. Mark with `#[cfg_attr(target_os = "macos", ignore = "reason")]` or set `HOME` env var to temp dir (doesn't fully prevent Keychain access).
- **portpicker for test isolation**: Use `portpicker` crate to get dynamic ports for test servers, avoiding port conflicts in parallel test execution.
- **PluginRuntime is not Send**: PluginRuntime contains Boa engine with `Rc` types, making it not `Send`. In async Axum handlers, scope PluginRuntime operations in a block to ensure the runtime is dropped before any `.await` points. Enable `axum = { version = "0.7", features = ["macros"] }` and use `#[axum::debug_handler]` to see detailed Send/Sync errors during development.
- **git2 callbacks are not Send**: `RepoBuilder` with `RemoteCallbacks` closures is not `Send`. In async handlers, scope the entire git clone operation (callbacks, fetch options, builder) in a block to ensure all non-Send types are dropped before any `.await` points.
