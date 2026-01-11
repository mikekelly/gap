# Project Kanban

## Ideas
<!-- Raw thoughts, not yet evaluated -->

- Plugin authoring guide documentation

## Designed
<!-- Has clear outcomes/spec -->

## Ready
<!-- Designed + planned, can be picked up -->

## In Progress
<!-- Currently being worked on -->

## Done
<!-- Shipped — archive periodically -->

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

