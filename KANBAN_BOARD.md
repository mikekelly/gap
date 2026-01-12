# Project Kanban

## Ideas
<!-- Raw thoughts, not yet evaluated -->

- A fork of exa-mcp-server that relies on ACP proxy instead of env vars
- Drop-in wrappers for common http libraries that handle ACP proxying transparently (exa-mcp-server fork would be a good test candidate)
- Plugins that can initiate and handle OAuth dance when installed
- Plugin authoring guide documentation

## Designed
<!-- Has clear outcomes/spec -->
- HTTPS for CLI → proxy communication (defense in depth using existing ca.crt)

## Ready
<!-- Designed + planned, can be picked up -->

- macOS Native GUI: Menu bar app using existing management API (see docs/macos-improvements/macos-gui-plan.md)

## In Progress
<!-- Currently being worked on -->

- Registry Simplification: Convert tokens/credentials from arrays to hashes, store credential values inline, eliminate redundant storage entries (see docs/registry-refactor/plan.md)

## Done
<!-- Shipped — archive periodically -->

### Token/Plugin Simplification ✓
Removed TokenCache abstraction, tokens now stored directly as `token:{token_value}` → `{name, created_at}` for direct lookup. Fixed plugin matching to properly find matching plugins.

### Homebrew Formula ✓
Homebrew tap for macOS distribution via `brew tap mikekelly/acp`.

### Registry Refactor ✓
Centralized registry for tokens, plugins, and credentials. Fixes KeychainStore listing on macOS.

### Phase 1: Foundation ✓
Project skeleton with core types, error handling, Cargo workspace.

### Phase 2: Secure Storage ✓
SecretStore trait + Keychain (macOS) + File (Linux) implementations.

### Phase 3: TLS Infrastructure ✓
CA generation, dynamic cert signing for MITM proxy.

### Phase 4: Proxy Core ✓
MITM proxy that forwards HTTPS requests with agent auth.

### Phase 5: Plugin Runtime ✓
Boa JS engine with sandboxed globals for request transforms.

### Phase 6: Management API ✓
HTTP API for CLI (plugins, credentials, tokens, activity).

### Phase 7: CLI ✓
Full command-line interface with secure password input.

### Phase 8: Integration & Polish ✓
Bundled plugins (Exa, AWS S3), e2e tests, install scripts, Docker support, README docs.
Remaining: plugin authoring guide.

### Docker Compose Test Runner ✓
Docker Compose with `test-runner` service that validates the Dockerfile and runs 9 integration tests.

