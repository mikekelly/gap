# Gotchas

This document contains important implementation caveats, limitations, and non-obvious behaviors you should be aware of when working with GAP.

## Pattern Matching

### Wildcard matching is single-level only
The pattern `*.s3.amazonaws.com` matches `bucket.s3.amazonaws.com` but rejects both `s3.amazonaws.com` (no subdomain) and `evil.com.s3.amazonaws.com` (multiple levels).

**Why:** Single-level matching provides security by preventing overly broad matches that could inadvertently expose credentials to unintended hosts.

## Storage & Keychain

### Keychain access groups
Use low-level SecItem* APIs for access group support. High-level `security_framework::passwords` API doesn't support access groups. See `keychain_impl.rs` for proper implementation using CFMutableDictionary and direct SecItem* calls. Access groups require Team ID prefix (e.g., "3R44BTH39W.com.gap.secrets").

**Why:** Access groups enable credential sharing between related apps on macOS/iOS, but require direct Core Foundation APIs to configure.

### KeychainStore.list() limitation
Returns empty vec due to security-framework API limitations. FileStore provides full list() functionality.

**Why:** macOS Keychain API doesn't provide reliable enumeration of all stored items. The Registry pattern works around this by maintaining metadata separately.

### Storage key encoding
FileStore uses base64url encoding for filenames to handle colons and slashes in keys safely across filesystems.

**Why:** Keys like `credential:plugin:field` or `token:abc123` contain characters that aren't safe in filenames on all platforms.

## Token Management

### Token serialization
`AgentToken` fully serializes including the `token` field (needed for storage). API responses use `TokenResponse` wrapper to control token exposure - only shown on creation.

**Why:** Storage needs the full token value, but API responses should only reveal it once for security.

### Token field access
`AgentToken.token` is a public field (not a method) - access via `token.token.clone()` not `token.token()`.

**Why:** Rust struct fields are accessed directly, not through getter methods. This is a common source of confusion for developers from other languages.

## JavaScript Runtime (Boa)

### Boa 0.19 API
When using Boa engine, must import `JsArgs` trait for `.get_or_undefined()`, use `JsString::from()` for string literals in API calls, import `base64::Engine` trait for `.encode()` method on BASE64_STANDARD.

**Why:** Rust trait methods are only available when the trait is in scope. Boa's API design requires explicit imports.

### Boa closures with state
`NativeFunction::from_fn_ptr()` only accepts pure function pointers, not closures that capture variables. To maintain state, use JavaScript globals or context properties instead. Example: Store logs in `__gap_logs` JavaScript array rather than Rust Rc<RefCell<Vec<String>>>.

**Why:** Function pointers have a different type than closures in Rust. Boa's FFI boundary requires stable function pointers.

## Plugin System

### PluginRuntime single-context limitation
Loading a plugin overwrites the global `plugin` object in the JS context. Only the most recently loaded plugin's transform function can be executed. Plugin metadata (name, patterns, schema) is preserved for all loaded plugins.

**Why:** Boa maintains a single JavaScript context per runtime. Each `load_plugin()` call replaces the global plugin object.

### PluginRuntime loading methods
Use `load_plugin(name, store)` to load from SecretStore (async), or `load_plugin_from_code(name, code)` to load from string (sync). Both cache the plugin for `execute_transform()`. Using `execute()` + `extract_plugin_metadata()` alone does NOT cache the plugin.

**Why:** Different loading paths serve different use cases - production uses SecretStore, tests use code strings.

### PluginRuntime timeout limitation
`execute_transform_with_timeout()` cannot interrupt tight infinite loops in JavaScript (Boa limitation). It measures elapsed time after execution completes, so only catches slow operations that eventually finish.

**Why:** Boa doesn't support preemptive interruption of JavaScript execution. True timeout requires cooperative yield points.

### PluginRuntime is not Send
PluginRuntime contains Boa engine with `Rc` types, making it not `Send`. In async Axum handlers, scope PluginRuntime operations in a block to ensure the runtime is dropped before any `.await` points. Enable `axum = { version = "0.7", features = ["macros"] }` and use `#[axum::debug_handler]` to see detailed Send/Sync errors during development.

**Why:** Boa uses reference-counted pointers (`Rc`) which are not thread-safe. Async functions must be `Send` to move between threads.

### Plugin credential schema formats
Supports two formats:
1. Simple: `credentialSchema: ["api_key", "secret"]`
2. Rich: `credentialSchema: { fields: [{name: "apiKey", label: "API Key", type: "password", required: true}, ...] }`

The runtime extracts just the `name` field from the rich format for internal use.

**Why:** The rich format supports UI generation for credential input, while simple format is easier for quick plugin authoring.

## TLS & Certificates

### rcgen 0.13 signing
To sign certificates, recreate CA `CertificateParams` with same DN/settings, call `self_signed(&ca_key_pair)` to get `Certificate` object, then use that to sign new certs with `params.signed_by(&key_pair, &ca_cert, &ca_key_pair)`.

**Why:** rcgen cannot reload `Certificate` from PEM/DER - must recreate CA params for signing operations.

### CA returns DER not PEM
`sign_for_hostname()` returns raw DER bytes `(Vec<u8>, Vec<u8>)` for certificate and key, not PEM format.

**Why:** DER is the canonical binary format. PEM is just base64-encoded DER with headers. rustls consumes DER directly.

### rustls-native-certs vs webpki-roots
Use webpki-roots (TLS_SERVER_ROOTS) for cross-platform system CA trust; rustls-native-certs has platform-specific quirks.

**Why:** webpki-roots provides a consistent, well-maintained set of root CAs that work identically across platforms.

## Async & Concurrency

### SecretStore trait with ?Sized
When working with trait objects (`&dyn SecretStore`), functions accepting generic `S: SecretStore` parameters need `+ ?Sized` bound to support unsized types. This applies to `parse_and_transform()`, `load_plugin_credentials()`, and `find_matching_plugin()`.

**Why:** Trait objects are dynamically-sized types. The `?Sized` bound allows both sized and unsized types.

### git2 callbacks are not Send
`RepoBuilder` with `RemoteCallbacks` closures is not `Send`. In async handlers, scope the entire git clone operation (callbacks, fetch options, builder) in a block to ensure all non-Send types are dropped before any `.await` points.

**Why:** git2's callback API uses non-thread-safe types. Must complete synchronously before yielding to async runtime.

## Authentication

### Axum authentication
Custom extractors using `FromRequest` with request body are complex in Axum 0.7. Simpler to use helper functions that take `Bytes` parameter and verify authentication manually in each handler.

**Why:** Axum 0.7's extractor API makes consuming the request body in an extractor difficult due to borrow checker constraints.

### Argon2 password hashing
Client sends SHA512(password), server stores Argon2(SHA512(password)). Verification uses `Argon2::default().verify_password()` with client's SHA512 hash against stored Argon2 hash.

**Why:** Double-hashing prevents plain-text password transmission while allowing Argon2's computational hardness on the server.

## Testing

### Environment variable test isolation
Tests modifying environment variables must use a static Mutex to serialize execution and an RAII guard to ensure cleanup, as env vars are process-global and tests run in parallel.

**Why:** Rust test harness runs tests in parallel. Environment variables are process-wide, so concurrent modification causes race conditions.

### E2E test binary resolution
Use `std::env::var("CARGO_BIN_EXE_gap-server")` with fallback to workspace-relative path for finding test binaries. The env var is only set when using `cargo test`, not `cargo build`.

**Why:** Cargo provides this env var during test execution to locate built binaries, but it's not available in all contexts.

### E2E test keychain isolation (macOS)
Tests using server init will trigger Keychain prompts on macOS. Mark with `#[cfg_attr(target_os = "macos", ignore = "reason")]` or set `HOME` env var to temp dir (doesn't fully prevent Keychain access).

**Why:** macOS Keychain access requires user interaction by default. CI/automated testing needs to avoid these prompts.

### portpicker for test isolation
Use `portpicker` crate to get dynamic ports for test servers, avoiding port conflicts in parallel test execution.

**Why:** Tests run concurrently may bind to the same port, causing flaky failures. Dynamic port allocation ensures isolation.

## Build & Deployment

### Rust nightly required for Docker builds
The Dockerfile uses `rustlang/rust:nightly-slim` because `base64ct` 1.8.2+ requires edition2024 support, which is not stabilized in Rust 1.83/1.84. Use nightly for Docker builds.

**Why:** Dependency constraints require Rust features not yet in stable. Nightly provides edition2024 support.

### Docker compose profiles
The test-runner service uses profile `test`, so it only runs when invoked with `docker compose --profile test up`. This prevents accidental test runs during normal compose up operations.

**Why:** Test services should be opt-in to avoid cluttering normal development workflows.

### Docker healthcheck dependencies
Use `depends_on` with `condition: service_healthy` to ensure test-runner waits for gap-server to be ready before running tests.

**Why:** Tests that run before services are ready will fail intermittently. Health checks provide proper startup synchronization.

## Related Documentation

- [Core Types](./types.md) - Detailed type reference
- [Architecture](./architecture.md) - System design and patterns
- [Agent Orientation](../AGENT_ORIENTATION.md) - Full developer guide
