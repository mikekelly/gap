# macOS Native GUI

## Overview

Build a native macOS menu bar app that provides a visual interface to GAP. The GUI uses the **exact same management API as the CLI** — no special code paths.

## Threat Model (Critical Context)

The shared secret exists to prevent **agents from modifying GAP configuration**:

| Actor | Can do | Cannot do |
|-------|--------|-----------|
| **Human at keyboard** | Enter shared secret via secure stdin | — |
| **Agent on machine** | Run CLI commands, read files | Provide shared secret (doesn't know it, can't intercept secure stdin) |

**The shared secret is a user presence check**, not an auth mechanism for storage access. Without it, an agent could:
- `gap install malicious-plugin` — exfiltrate data through rogue plugins
- `gap token create backdoor` — create tokens for unauthorized access
- `gap set plugin:credential` — overwrite credentials

The GUI must preserve this security property.

---

## Architecture

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
                                    │  (gap-server:9080)  │
                                    │  Same as CLI uses   │
                                    └─────────────────────┘
```

---

## Why This Approach

| Consideration | Decision |
|---------------|----------|
| **Security** | Same user presence check as CLI. Agent can't provide password. |
| **Simplicity** | No special Keychain access, no cache invalidation, no new code paths. |
| **Consistency** | GUI and CLI use identical API. One implementation to maintain. |
| **Convenience** | Password entered once per session (GUI is long-running, unlike CLI). |

---

## User Presence Options

The GUI prompt for the shared secret could be:
1. **Plain password dialog** — same as CLI, but once per session
2. **Touch ID to unlock** — store password hash in Keychain, Touch ID to retrieve
3. **Touch ID per operation** — most secure, but more friction

Recommendation: Start with (1), consider (2) as enhancement.

Note: A password dialog is potentially vulnerable to accessibility automation (an agent could theoretically click buttons). Touch ID is immune to this. Document this limitation.

---

## Technology Stack

- Swift / SwiftUI
- Menu bar app (LSUIElement)
- URLSession for API calls
- UserNotifications for alerts (optional)

---

## UI Components

1. **Menu Bar Icon** — Status indicator, quick access dropdown
2. **Main Window**:
   - Credential Manager — add, view, delete credentials per plugin
   - Token Manager — create, revoke agent tokens
   - Plugin Manager — view installed plugins
   - Activity Log — recent proxy requests
3. **Password Prompt** — shown on launch

---

## Implementation Tasks

1. Create Xcode project with menu bar app template
2. Implement password prompt dialog
3. Implement SHA512 hashing (matching CLI implementation)
4. Implement API client (URLSession wrapper)
5. Build credential management UI
6. Build token management UI
7. Build plugin list UI
8. Build activity log view
10. Set up code signing and notarization
11. Update documentation

---

## Testing

- Unit tests for API client
- Unit tests for SHA512 hashing (must match CLI output)
- UI tests for main flows
- Integration test: GUI-created token works with proxy
- Integration test: GUI-created credential works with proxy
- Security test: verify password hash matches CLI format exactly

---

## Acceptance Criteria

- [ ] Menu bar app launches and prompts for password
- [ ] Can view, add, delete credentials
- [ ] Can view, create, revoke tokens
- [ ] Can view installed plugins
- [ ] Can view activity log
- [ ] All operations use same API as CLI
- [ ] Password hash format matches CLI exactly
- [ ] App is signed and notarized

---

## What This Plan Does NOT Do

Previous versions of this plan incorrectly proposed:
- ❌ Direct Keychain access from GUI bypassing the API
- ❌ Auth tokens stored in Keychain to replace shared secret
- ❌ Cache invalidation endpoints for cross-process coordination
- ❌ Code signing as an authentication mechanism

These were based on a misunderstanding of the threat model. The shared secret is not about Keychain access — it's about proving user presence to prevent agents from modifying GAP configuration.

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Password dialog vulnerable to accessibility automation | Agent could automate GUI | Touch ID enhancement addresses this; document the limitation |
| Hash implementation differs from CLI | Auth fails | Test hash output matches CLI exactly; share implementation if possible |
