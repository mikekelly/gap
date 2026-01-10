# Project Kanban

## Ideas
<!-- Raw thoughts, not yet evaluated -->

- Plugin authoring guide documentation
- Homebrew formula for macOS distribution

## Designed
<!-- Has clear outcomes/spec -->

## Ready
<!-- Designed + planned, can be picked up -->

### Registry Refactor
Centralized registry for tokens, plugins, and credentials. Fixes KeychainStore listing on macOS.
Plan: `docs/registry-refactor/plan.md`

## In Progress
<!-- Currently being worked on -->

## Done
<!-- Shipped — archive periodically -->

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

### Phase 8: Integration & Polish (partial) ✓
Bundled plugins (Exa, AWS S3), e2e tests, install scripts, Docker support, README docs.
Remaining: plugin authoring guide, Homebrew formula.

### Docker Compose Test Runner ✓
Docker Compose with `test-runner` service that validates the Dockerfile and runs 9 integration tests.

