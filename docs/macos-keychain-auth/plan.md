# macOS Direct Keychain Authentication

## Overview

Eliminate the shared secret authentication on macOS by leveraging code signing. When both `acp` (CLI) and `acp-server` are signed with the same Apple Developer Team ID, they share access to the same Keychain items via access groups. This means:

- No password prompts for CLI operations
- No shared secret to hash and transmit
- OS-level identity verification via code signature
- Better UX without sacrificing security

## Current State

### CLI Auth Flow (today)
1. User runs `acp set plugin:apiKey`
2. CLI prompts for password (secure stdin, no echo)
3. CLI hashes password with SHA512
4. CLI sends hash to management API over HTTP
5. Server verifies against Argon2-hashed stored password
6. Server writes credential to Keychain

### Keychain Integration (today)
- Both CLI and server use `KeychainStore` with access group `3R44BTH39W.com.acp.secrets`
- Access controlled by code signature Team ID
- Server already reads/writes Keychain directly for proxy operations

### Problem
The CLI *already has* Keychain access (if signed correctly), but still goes through the password→API→server flow. This is unnecessary friction on macOS.

## Phase 1: macOS CLI Direct Keychain Access

### Objective
On macOS, the CLI writes credentials directly to Keychain, bypassing the management API for credential operations. For other operations (tokens, plugins), use Keychain-stored auth instead of user-entered password.

### Design

#### Credential Operations (Direct)
These bypass the management API entirely:

| Command | Current Flow | New Flow (macOS) |
|---------|--------------|------------------|
| `acp set plugin:key` | Prompt → API → Keychain | Prompt value → Keychain directly |
| `acp init` | Prompt password → API stores hash | Generate auth token → Keychain |

#### API Operations (Token-Based)
These still need the management API but use Keychain-stored auth:

| Command | Current Flow | New Flow (macOS) |
|---------|--------------|------------------|
| `acp token create` | Prompt password → API | Read auth token from Keychain → API |
| `acp install plugin` | Prompt password → API | Read auth token from Keychain → API |
| `acp activity` | Prompt password → API | Read auth token from Keychain → API |

#### Auth Token Mechanism
1. On `acp init` (or first run), generate a random 256-bit token
2. Store in Keychain under key `auth:api_token` with same access group
3. CLI reads this token for API requests (no user prompt)
4. Server verifies token matches stored value
5. If CLI can read the token, it's signed correctly → trusted

### Changes Required

#### acp-lib/src/storage.rs
- Add `get_local()` / `set_local()` methods that work without network
- Expose `KeychainStore` for direct CLI use

#### acp/src/commands/credentials.rs
- On macOS: create local `KeychainStore` instance
- Write credentials directly: `store.set("credential:plugin:key", value)`
- Skip API call entirely
- Update registry via API (metadata only, no auth needed for writes)

#### acp/src/commands/init.rs
- On macOS: generate auth token, store in Keychain
- Remove password prompt
- Just generate CA cert path if needed

#### acp/src/auth.rs
- Add `get_auth_token() -> Option<String>` for macOS
- Falls back to password prompt on Linux
- Used by API client for authenticated requests

#### acp-server/src/api.rs
- Accept auth token OR password hash for backwards compatibility
- New auth check: `verify_auth_token()` alongside existing password verification

### Platform Detection

```rust
#[cfg(target_os = "macos")]
fn authenticate() -> Result<String> {
    // Try to read auth token from Keychain
    let store = KeychainStore::new_with_access_group(...)?;
    if let Some(token) = store.get("auth:api_token").await? {
        return Ok(String::from_utf8(token)?);
    }
    // Fall back to password if token not found (first run)
    read_password_and_hash()
}

#[cfg(not(target_os = "macos"))]
fn authenticate() -> Result<String> {
    read_password_and_hash()
}
```

### Migration Path
1. Existing macOS users have password stored as Argon2 hash
2. On first CLI run after update, detect missing auth token
3. Prompt for password once to verify identity
4. Generate and store auth token
5. Future operations use token (no prompt)

### Testing

#### Unit Tests
- `KeychainStore` direct access from CLI context
- Auth token generation and retrieval
- Platform-conditional compilation

#### Integration Tests
- `acp set` writes to Keychain without API call (verify with `security` command)
- `acp token create` works with Keychain auth token
- Migration from password-based to token-based auth
- Linux still uses password flow (no regression)

### Documentation Updates
- README: Update macOS Quick Start (remove `acp init` password prompt mention)
- README: Note platform differences in auth model
- AGENT_ORIENTATION.md: Update CLI auth description

### Acceptance Criteria
- [ ] `acp set plugin:key` on macOS works without password prompt
- [ ] `acp token create` on macOS works without password prompt
- [ ] `acp init` on macOS only generates CA cert (no password)
- [ ] Linux behavior unchanged (password required)
- [ ] Existing macOS users can migrate with one password entry
- [ ] All existing tests pass
- [ ] New integration tests for direct Keychain access

---

## Phase 2: macOS Native GUI

### Objective
Build a native macOS menu bar app with:
- Direct Keychain access (same as Phase 1 CLI)
- Touch ID / password confirmation for sensitive operations
- Push notifications for agent activity
- Visual credential management

### Design

#### Technology Stack
- Swift / SwiftUI
- Same code signing (Team ID, access group)
- LocalAuthentication framework for Touch ID
- UserNotifications for alerts

#### Keychain Access
Identical to Phase 1 — signed with same Team ID, gets same Keychain items:
- Read/write credentials directly
- No management API needed for credential operations
- Share `3R44BTH39W.com.acp.secrets` access group

#### Server Communication
For operations requiring the server:
- Read auth token from Keychain (same as CLI)
- Call management API endpoints
- Or: embed XPC service for tighter integration

#### Touch ID Integration
```swift
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthentication,
                       localizedReason: "Authorize credential access") { success, error in
    if success {
        // Proceed with Keychain write
    }
}
```

Use for:
- Adding new credentials
- Deleting credentials
- Revoking agent tokens

Not required for:
- Viewing activity logs
- Viewing installed plugins
- Creating new agent tokens (low risk)

#### UI Components
1. **Menu Bar Icon**: Status indicator, quick access
2. **Credential Manager**: List, add, delete credentials per plugin
3. **Token Manager**: Create, revoke agent tokens
4. **Activity View**: Recent proxy requests, filterable
5. **Settings**: Proxy ports, notification preferences

### Changes Required

#### New Xcode Project
- `acp-gui/` directory
- SwiftUI app with menu bar presence
- Signed with same Developer ID

#### Shared Code (Rust → Swift)
Option A: Swift calls Rust via C FFI
- Expose `KeychainStore` as C API
- Swift wrapper around C functions

Option B: Pure Swift reimplementation
- Reimplement `KeychainStore` in Swift using Security framework
- Use same service name and access group
- Simpler, no FFI complexity

Recommendation: **Option B** — Swift has excellent Security framework support, and the Keychain logic is straightforward.

#### Management API Client
- Swift `URLSession` client for API calls
- Read auth token from Keychain
- JSON encoding/decoding for request/response

### Testing

#### Unit Tests
- Keychain read/write in Swift
- Auth token retrieval
- API client request formation

#### UI Tests
- Credential add flow with Touch ID
- Token creation and revocation
- Activity log display

#### Integration Tests
- GUI and CLI share Keychain state
- GUI-created credentials usable by proxy
- GUI-created tokens valid for agents

### Documentation Updates
- README: Add macOS GUI section
- Screenshots of key flows
- Download/install instructions

### Acceptance Criteria
- [ ] Menu bar app launches and shows status
- [ ] Can add credentials with Touch ID confirmation
- [ ] Can view and revoke agent tokens
- [ ] Activity log shows recent requests
- [ ] Credentials created in GUI work with proxy
- [ ] Tokens created in GUI work with agents
- [ ] App is notarized and distributable

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Keychain access denied due to signing mismatch | CLI can't auth | Clear error message, docs on signing requirements |
| Migration breaks existing setups | User locked out | Password fallback during migration period |
| GUI and CLI write conflicts | Data corruption | Keychain handles atomic access; registry updates are idempotent |
| Touch ID unavailable (older Macs) | Can't use GUI | Fall back to password confirmation |

## Open Questions

1. **Should `acp init` become optional on macOS?** If there's no password to set, init just generates the CA cert. Could auto-generate on first use instead.

2. **Registry updates for direct Keychain writes**: When CLI writes credential directly, should it still notify the server to update plugin metadata? Probably yes, for consistency.

3. **Homebrew formula changes**: Need to ensure Homebrew-installed binaries are signed. Currently handled by `macos-sign.sh` but may need Homebrew tap updates.

---

## Cache Invalidation Strategy

### The Problem

When CLI/GUI mutate Keychain directly (bypassing the server's API), the server's in-memory caches become stale.

### Cache Analysis

| Component | Location | Concern Level | Reason |
|-----------|----------|---------------|--------|
| **TokenCache** | `token_cache.rs` | **HIGH** | Caches all tokens in `RwLock<Option<HashMap>>`. Uses invalidate-on-write, but won't see external writes. |
| **Registry** | `registry.rs` | **LOW** | Always loads fresh from storage on each operation. No in-memory caching. |
| **PluginRuntime** | `plugin_runtime.rs` | **NONE** | New instance created per HTTP request. Cache is request-scoped. |
| **CertificateCache** | `tls.rs` | **NONE** | Only caches generated TLS certs by hostname. Not affected by credential/token changes. |

### Solution: Lightweight Invalidation Endpoint

Add a new unauthenticated endpoint that CLI/GUI call after direct mutations:

```
POST /invalidate
```

This endpoint:
1. Calls `token_cache.invalidate()` to clear the token cache
2. Returns 200 OK (no response body needed)
3. No authentication required — worst case is extra cache invalidations (harmless)

### Implementation

#### Server (acp-server/src/api.rs)
```rust
async fn invalidate_caches(State(state): State<ApiState>) -> StatusCode {
    state.token_cache.invalidate().await;
    StatusCode::OK
}

// Add route
.route("/invalidate", post(invalidate_caches))
```

#### CLI (after direct Keychain writes)
```rust
#[cfg(target_os = "macos")]
async fn notify_server_of_mutation() {
    // Best-effort notification - don't fail if server is down
    let _ = reqwest::Client::new()
        .post("http://127.0.0.1:9080/invalidate")
        .send()
        .await;
}
```

### Alternative Considered: File-Based Watch

Could touch a file after mutations and have server watch it with `notify` crate:
- Pro: No HTTP call needed
- Con: Adds filesystem dependency, more complex, cross-platform concerns

**Decision**: HTTP endpoint is simpler and sufficient for the use case.

### Testing Requirements

1. **Unit test**: Verify `/invalidate` clears TokenCache
2. **Integration test**: CLI creates token via direct Keychain → calls `/invalidate` → server sees new token
3. **Smoke test**: Full workflow with CLI, server, and proxy verifying cache coherence
4. **Negative test**: Server down when CLI calls `/invalidate` → CLI operation still succeeds (best-effort)

### Acceptance Criteria (Cache Invalidation)
- [ ] `/invalidate` endpoint exists and clears TokenCache
- [ ] CLI calls `/invalidate` after direct Keychain mutations
- [ ] GUI calls `/invalidate` after credential/token changes
- [ ] CLI/GUI don't fail if server is unreachable during invalidation
- [ ] Integration tests verify cache coherence across processes

---

## Implementation Order

### Phase 1 Tasks (CLI)
1. Add direct Keychain access to CLI (macOS only)
2. Implement auth token mechanism
3. Update `acp set` to bypass API on macOS
4. Update `acp init` to skip password on macOS
5. Add migration path for existing users
6. Update tests
7. Update documentation

### Phase 2 Tasks (GUI)
1. Create Xcode project structure
2. Implement Swift Keychain wrapper
3. Build menu bar presence
4. Implement credential management UI
5. Implement token management UI
6. Add Touch ID integration
7. Implement activity log view
8. Add push notifications
9. Set up notarization
10. Update documentation
