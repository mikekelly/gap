# macOS Improvements Plan

## Overview

Two improvements for macOS:
1. **Phase 1**: Simplify token storage and plugin matching (remove unnecessary complexity)
2. **Phase 2**: Native macOS GUI that provides a nicer interface to the existing management API

## Threat Model (Critical Context)

The shared secret exists to prevent **agents from modifying ACP configuration**:

| Actor | Can do | Cannot do |
|-------|--------|-----------|
| **Human at keyboard** | Enter shared secret via secure stdin | — |
| **Agent on machine** | Run CLI commands, read files | Provide shared secret (doesn't know it, can't intercept secure stdin) |

**The shared secret is a user presence check**, not an auth mechanism for storage access. Without it, an agent could:
- `acp install malicious-plugin` — exfiltrate data through rogue plugins
- `acp token create backdoor` — create tokens for unauthorized access
- `acp set plugin:credential` — overwrite credentials

The inconvenience of entering the password is a feature, not a bug.

---

## Phase 1: Simplify Token Storage and Plugin Matching

### Problem 1: Unnecessary Token Indirection

**Current state:**
- Tokens stored as `token:{id}` → `{ id, name, token_value, created_at }`
- TokenCache loads ALL tokens into HashMap keyed by token value
- Cache needed because lookup is by value but storage is by ID
- Cache creates complexity and potential staleness issues

**Better approach:**
- Store tokens as `token:{token_value}` → `{ name, created_at }`
- The token value IS the ID (no separate ID needed)
- Direct lookup: `store.get("token:acp_xxxx")` — one read, no cache
- Remove TokenCache entirely

### Problem 2: Inefficient Plugin Matching

**Current state** (`plugin_matcher.rs`):
```rust
for entry in plugin_entries {
    // For EVERY plugin on EVERY request:
    let plugin_code = store.get(&key).await?;           // Load code
    let mut runtime = PluginRuntime::new()?;            // Create JS runtime
    runtime.load_plugin_from_code(&entry.name, &code);  // Parse JavaScript
    if plugin.matches_host(host) { ... }                // Check match
}
```

This is O(N) JavaScript executions per request.

**Better approach:**
- Registry already stores `hosts` in `PluginEntry`
- Match against `PluginEntry.hosts` directly (cheap string matching)
- Only load plugin code for the ONE that matched
- One JS parse per request (for the matched plugin), not N

### Changes Required

#### Remove TokenCache
- Delete `acp-lib/src/token_cache.rs`
- Update `acp-lib/src/lib.rs` to remove export
- Update `acp-server/src/main.rs` to use Registry directly
- Update `acp-lib/src/proxy.rs` to look up tokens directly

#### Change Token Storage Schema
- Store: `token:{token_value}` → `{ name, created_at }`
- Update `acp-server/src/api.rs` token endpoints
- Update token validation in proxy to do direct lookup
- Migration: read old format, write new format on first access

#### Fix Plugin Matching
- Update `plugin_matcher.rs` to match against `PluginEntry.hosts`
- Only load plugin code after finding a match
- Remove unnecessary PluginRuntime creation for non-matches

### Testing

- All existing tests must pass
- Add test: direct token lookup by value
- Add test: plugin matching uses Registry metadata, not JS parsing
- Performance test: measure request latency before/after

### Acceptance Criteria
- [ ] TokenCache removed from codebase
- [ ] Tokens stored by value, not by separate ID
- [ ] Plugin matching uses Registry metadata for host matching
- [ ] Plugin code only loaded for matched plugin
- [ ] All existing tests pass
- [ ] No regression in proxy request handling

---

## Phase 2: macOS Native GUI

### Objective

Build a native macOS menu bar app that provides a visual interface to ACP. The GUI uses the **exact same management API as the CLI** — no special code paths.

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│  macOS GUI                                              │
│                                                         │
│  ┌─────────────────┐                                    │
│  │ On launch:      │                                    │
│  │ Prompt password │───┐                                │
│  │ SHA512 hash     │   │                                │
│  │ Store in memory │   │                                │
│  └─────────────────┘   │                                │
│                        ▼                                │
│  ┌─────────────────────────────────────┐                │
│  │ All operations use stored hash      │                │
│  │ POST /tokens    { password_hash }   │────────┐       │
│  │ POST /plugins   { password_hash }   │        │       │
│  │ POST /credentials { password_hash } │        │       │
│  └─────────────────────────────────────┘        │       │
│                                                 ▼       │
└─────────────────────────────────────────────────────────┘
                                                  │
                                    ┌─────────────▼───────┐
                                    │  Management API     │
                                    │  (acp-server:9080)  │
                                    │  Same as CLI uses   │
                                    └─────────────────────┘
```

### Why This Approach

| Consideration | Decision |
|---------------|----------|
| **Security** | Same user presence check as CLI. Agent can't provide password. |
| **Simplicity** | No special Keychain access, no cache invalidation, no new code paths. |
| **Consistency** | GUI and CLI use identical API. One implementation to maintain. |
| **Convenience** | Password entered once per session (GUI is long-running, unlike CLI). |

### User Presence Options

The GUI prompt for the shared secret could be:
1. **Plain password dialog** — same as CLI, but once per session
2. **Touch ID to unlock** — store password hash in Keychain, Touch ID to retrieve
3. **Touch ID per operation** — most secure, but more friction

Recommendation: Start with (1), consider (2) as enhancement. Touch ID for credential operations is a nice-to-have.

### Technology Stack

- Swift / SwiftUI
- Menu bar app (LSUIElement)
- URLSession for API calls
- UserNotifications for alerts (optional)

### UI Components

1. **Menu Bar Icon** — Status indicator, quick access dropdown
2. **Main Window**:
   - Credential Manager — add, view, delete credentials per plugin
   - Token Manager — create, revoke agent tokens
   - Plugin Manager — view installed plugins
   - Activity Log — recent proxy requests
3. **Password Prompt** — shown on launch and after idle timeout

### Implementation Tasks

1. Create Xcode project with menu bar app template
2. Implement password prompt dialog
3. Implement SHA512 hashing (matching CLI)
4. Implement API client (URLSession wrapper)
5. Build credential management UI
6. Build token management UI
7. Build plugin list UI
8. Build activity log view
9. Add idle timeout (re-prompt after X minutes)
10. Set up code signing and notarization
11. Update documentation

### Testing

- Unit tests for API client
- UI tests for main flows
- Integration test: GUI-created token works with proxy
- Security test: verify password hash matches CLI format

### Acceptance Criteria
- [ ] Menu bar app launches and prompts for password
- [ ] Can view, add, delete credentials
- [ ] Can view, create, revoke tokens
- [ ] Can view installed plugins
- [ ] Can view activity log
- [ ] Password re-prompted after idle timeout
- [ ] All operations use same API as CLI
- [ ] App is signed and notarized

---

## What This Plan Does NOT Do

Previous versions of this plan incorrectly proposed:
- ❌ Direct Keychain access from CLI/GUI bypassing the API
- ❌ Auth tokens stored in Keychain to replace shared secret
- ❌ Cache invalidation endpoints for cross-process coordination
- ❌ Code signing as an authentication mechanism

These were based on a misunderstanding of the threat model. The shared secret is not about Keychain access — it's about proving user presence to prevent agents from modifying ACP configuration.

---

## Implementation Order

### Phase 1 (Token/Plugin Cleanup)
1. Remove TokenCache, implement direct token lookup
2. Change token storage schema to key by value
3. Fix plugin matching to use Registry metadata
4. Update tests
5. Update AGENT_ORIENTATION.md

### Phase 2 (macOS GUI)
1. Create Xcode project
2. Implement password prompt + API client
3. Build credential management UI
4. Build token management UI
5. Build activity/plugin views
6. Add idle timeout
7. Set up signing/notarization
8. Update documentation

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Token schema migration breaks existing setups | Users locked out | Auto-migrate on first read, keep backwards compat temporarily |
| GUI idle timeout too aggressive | User annoyance | Make timeout configurable, default to reasonable value (15 min) |
| Password dialog vulnerable to accessibility automation | Agent could automate GUI | Touch ID enhancement addresses this; document the limitation |
