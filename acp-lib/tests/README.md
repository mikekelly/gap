# Integration Tests

This directory contains integration tests for the Agent Credential Proxy system.

## Test Files

### `integration_test.rs`
Basic integration tests for the plugin pipeline:
- Full plugin pipeline (FileStore → PluginRuntime → Transform)
- Multiple plugin coexistence
- Complex credential schemas

### `e2e_integration_test.rs`
End-to-end integration tests for complete system flows:
- Server initialization
- Plugin installation
- Credential management
- Token lifecycle (create → list → revoke)
- Complete integration flow

## Running Tests

### All Tests
```bash
cargo test
```

### Integration Tests Only
```bash
cargo test --test integration_test
cargo test --test e2e_integration_test
```

### E2E Tests (including ignored)
On macOS, some tests require keychain access and are ignored by default. To run them:

```bash
cargo test --test e2e_integration_test -- --ignored --test-threads=1
```

**Note:** This will prompt for keychain access multiple times.

## Platform-Specific Behavior

### macOS
The following tests are ignored by default on macOS because they require keychain access:
- `test_server_initialization_flow`
- `test_token_management_flow`
- `test_complete_integration_flow`

These tests can be run with `--ignored` flag, but they will require manual approval
for keychain access in the macOS system dialog.

### Linux
All tests run without manual intervention.

## Test Architecture

### TestServer Helper
The E2E tests use a `TestServer` struct that:
- Spawns `acp-server` binary in a subprocess
- Uses dynamic ports to avoid conflicts
- Creates isolated temporary directories
- Automatically cleans up on drop

### Test Isolation
Each test:
- Uses a unique temporary directory
- Binds to dynamically allocated ports
- Runs in parallel (except keychain tests)
- Cleans up all resources on completion

## Coverage

The E2E tests verify:

1. **Server initialization flow**
   - Server starts successfully
   - Status endpoint works before and after init
   - Password hashing and storage

2. **Plugin installation flow**
   - Plugin code storage
   - Plugin loading via PluginRuntime
   - Metadata extraction

3. **Credential setting flow**
   - Credential storage in SecretStore
   - Retrieval and verification
   - List and delete operations

4. **Token management flow**
   - Token creation with unique IDs
   - Token listing (without exposing full token)
   - Token revocation

5. **Complete integration**
   - Full lifecycle: init → configure → create token
   - All components working together

## Manual Testing

For comprehensive testing including proxy functionality, see:
- `/smoke-tests/cli.md` - CLI smoke tests
- `/smoke-tests/test-init.exp` - Expect script for automated CLI testing

## Troubleshooting

### Tests timeout
Increase the timeout in the test code or check if the server binary is built:
```bash
cargo build --bin acp-server
```

### Keychain access denied (macOS)
The test is trying to access macOS Keychain. Either:
1. Run with `--ignored` and approve the access
2. Run only non-ignored tests (default behavior)

### Port conflicts
Tests use dynamic port allocation, but if you see bind errors:
```bash
# Kill any lingering test servers
pkill -f acp-server
```
