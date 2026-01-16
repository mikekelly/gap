# Done

Shipped work - archive periodically.

## Rust Crate Rename: ACP → GAP (2026-01-16)
Renamed all Rust crates from ACP (Agent Credential Proxy) to GAP (Gated Agent Proxy) to avoid naming conflict with Agent Client Protocol (agentclientprotocol.com). Binary names updated: `acp` → `gap`, `acp-server` → `gap-server`.

**Changes:**
- Directories renamed via git mv: acp/ → gap/, acp-server/ → gap-server/, acp-lib/ → gap-lib/
- All Cargo.toml files updated with new crate names and workspace dependencies
- All imports updated: `use acp_lib::` → `use gap_lib::`
- Internal JS runtime prefixes updated: `__acp_native_*` → `__gap_native_*`, `__acp_logs` → `__gap_logs`
- Build verified: cargo build succeeds
- Tests verified: 40 tests passing

**Commit:** 745a9ba

## HTTPS Management API (2026-01-12)
Implemented TLS encryption for CLI → management API communication. Management API now serves HTTPS with certificates signed by the existing CA infrastructure. Includes support for configurable Subject Alternative Names (SANs) at init time and live certificate rotation without server restart.

**Features:**
- Management certificate generation during `gap init` with default SANs (localhost, 127.0.0.1, ::1)
- `--management-sans` flag for custom SANs in remote management scenarios
- Server serves HTTPS on management API port with certificate verification
- CLI configured with CA trust bundle for secure connections to `https://localhost:9080`
- `POST /v1/management-cert` endpoint for live certificate rotation
- `gap new-management-cert` CLI command to trigger cert regeneration
- Tests updated for HTTPS communication

**Commits:**
- 6915482: Add sign_server_cert method to CertificateAuthority
- a6ac124: Implement HTTPS server setup with rustls
- cb5ed8b: Add /init endpoint support for management_sans
- deb6293: Add CLI --management-sans flag to init command
- bb42e8b: Configure CLI HTTPS client with CA verification
- 504c4d1: Implement cert rotation endpoint
- d324f7f: Add new-management-cert CLI command
- 2b33e59: Update tests for HTTPS compatibility

## Registry Simplification
Converted tokens/credentials from arrays to HashMaps. Tokens now keyed by token value for O(1) lookup. Credentials stored as nested HashMap (plugin → field → value) directly in registry. Eliminated separate storage entries for tokens and credentials.

## Token/Plugin Simplification
Removed TokenCache abstraction, tokens now stored directly as `token:{token_value}` → `{name, created_at}` for direct lookup. Fixed plugin matching to properly find matching plugins.

## Homebrew Formula
Homebrew tap for macOS distribution via `brew tap mikekelly/gap`.

## Registry Refactor
Centralized registry for tokens, plugins, and credentials. Fixes KeychainStore listing on macOS.

## Phase 1: Foundation
Project skeleton with core types, error handling, Cargo workspace.

## Phase 2: Secure Storage
SecretStore trait + Keychain (macOS) + File (Linux) implementations.

## Phase 3: TLS Infrastructure
CA generation, dynamic cert signing for MITM proxy.

## Phase 4: Proxy Core
MITM proxy that forwards HTTPS requests with agent auth.

## Phase 5: Plugin Runtime
Boa JS engine with sandboxed globals for request transforms.

## Phase 6: Management API
HTTP API for CLI (plugins, credentials, tokens, activity).

## Phase 7: CLI
Full command-line interface with secure password input.

## Phase 8: Integration & Polish
Bundled plugins (Exa, AWS S3), e2e tests, install scripts, Docker support, README docs.
Remaining: plugin authoring guide.

## Docker Compose Test Runner
Docker Compose with `test-runner` service that validates the Dockerfile and runs 9 integration tests.
