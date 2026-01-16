# macOS GUI Implementation Plan

## Current State

The GAP project is a Rust workspace with three components:
- `gap-lib/` - Core library with types, registry, secret storage
- `gap-server/` - Server daemon exposing Management API on port 9080 (HTTPS)
- `gap/` - CLI tool that communicates with the Management API

The Management API already supports all operations the GUI needs. The GUI will be a pure API client.

## Blueprint

```
macos-gui/
├── GAP.xcodeproj/
├── GAP/
│   ├── GAPApp.swift              # App entry point, menu bar setup
│   ├── AppState.swift            # Global state (password hash, connection status)
│   ├── API/
│   │   ├── GAPClient.swift       # URLSession wrapper for Management API
│   │   ├── Models.swift          # Codable structs matching API responses
│   │   └── PasswordHash.swift    # SHA512 hashing (must match CLI exactly)
│   ├── Views/
│   │   ├── MenuBarView.swift     # Menu bar dropdown
│   │   ├── MainWindow.swift      # Main window with tab navigation
│   │   ├── PasswordPrompt.swift  # Modal password entry dialog
│   │   ├── CredentialsView.swift # Credential management UI
│   │   ├── TokensView.swift      # Token management UI
│   │   ├── PluginsView.swift     # Plugin list UI
│   │   └── ActivityView.swift    # Activity log view
│   ├── Resources/
│   │   └── Assets.xcassets/      # Menu bar icons
│   └── Info.plist
├── GAPTests/
│   ├── PasswordHashTests.swift   # Verify hash matches CLI output
│   └── GAPClientTests.swift      # API client unit tests
└── README.md
```

## API Endpoints Used

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/status` | GET | No | Check server connection |
| `/plugins` | POST | Yes | List installed plugins |
| `/plugins/install` | POST | Yes | Install plugin |
| `/plugins/:name/update` | POST | Yes | Update plugin |
| `/plugins/:name` | DELETE | Yes | Uninstall plugin |
| `/tokens` | POST | Yes | List tokens |
| `/tokens/create` | POST | Yes | Create token |
| `/tokens/:id` | DELETE | Yes | Revoke token |
| `/credentials/:plugin/:key` | POST | Yes | Set credential |
| `/credentials/:plugin/:key` | DELETE | Yes | Delete credential |
| `/activity` | POST | Yes | Get activity log |

All authenticated endpoints require `password_hash` in JSON body.

## Password Hashing

Must match CLI exactly:
```swift
import CryptoKit

func hashPassword(_ password: String) -> String {
    let hash = SHA512.hash(data: Data(password.utf8))
    return hash.map { String(format: "%02x", $0) }.joined()
}
```

- Input: UTF-8 encoded password
- Algorithm: SHA512, no salt, no iterations
- Output: 128-character lowercase hex string

## Phases

### Phase 1: Foundation (Sequential)
Create Xcode project, app structure, and core utilities.

1. **Create Xcode project** - Menu bar app template with LSUIElement
2. **Implement PasswordHash.swift** - SHA512 hashing with tests
3. **Implement API Models** - Codable structs for all API responses

### Phase 2: API Client (Sequential, depends on Phase 1)
Build the network layer.

4. **Implement GAPClient** - URLSession wrapper with:
   - Base URL configuration (https://localhost:9080)
   - TLS certificate trust (self-signed CA)
   - JSON encoding/decoding
   - Error handling

### Phase 3: App State & Password Flow (Sequential, depends on Phase 2)
Build the core app flow.

5. **Implement AppState** - Observable object holding:
   - Password hash (in memory)
   - Connection status
   - Current data (plugins, tokens, etc.)

6. **Implement PasswordPrompt** - Modal dialog:
   - Secure text field
   - Hash on submit
   - Verify against /status or first API call
   - Store hash in AppState

7. **Implement MenuBarView** - Status indicator and dropdown:
   - Connection status icon
   - Quick access to main window
   - Quit option

### Phase 4: Main UI (Parallel, depends on Phase 3)
Build the main window views. These can be developed in parallel.

8. **Implement MainWindow** - Tab-based navigation container

9. **Implement PluginsView**:
   - List installed plugins with names and patterns
   - Install button (text field for owner/repo)
   - Update and uninstall buttons per plugin

10. **Implement TokensView**:
    - List tokens with name, prefix, created date
    - Create button (text field for name)
    - Copy token on creation
    - Revoke button per token

11. **Implement CredentialsView**:
    - Grouped by plugin
    - Show credential keys (not values - write-only)
    - Set credential (plugin, key, value inputs)
    - Delete credential button

12. **Implement ActivityView**:
    - List of recent requests
    - Timestamp, method, URL, agent, status
    - Auto-refresh option

### Phase 5: Polish & Release (Sequential, depends on Phase 4)
13. **Menu bar icon assets** - Status icons for connected/disconnected
14. **Error handling UI** - Alert dialogs for API errors
15. **Code signing** - Developer ID certificate
16. **Notarization** - Apple notarization for distribution
17. **Documentation** - Update main README, add GUI-specific docs

## Parallel Opportunities

- Phase 4 views (8-12) can be developed in parallel once Phase 3 completes
- Password hashing tests can run alongside API client development
- Documentation can be written alongside Phase 5 polish work

## Risks

| Risk | Mitigation |
|------|------------|
| TLS trust for self-signed CA | Use URLSessionDelegate to trust the GAP CA certificate |
| Hash mismatch with CLI | Unit tests comparing Swift output to known CLI output |
| Menu bar app complexity | Use well-documented SwiftUI patterns for LSUIElement apps |
| Accessibility automation vulnerability | Document limitation; Touch ID enhancement can be added later |

## Acceptance Criteria

- [ ] App launches as menu bar icon (no dock icon)
- [ ] Password prompt shown on launch
- [ ] Password hash matches CLI output exactly
- [ ] Can connect to gap-server over HTTPS
- [ ] Can view installed plugins
- [ ] Can install/update/uninstall plugins
- [ ] Can view tokens (name, prefix, date)
- [ ] Can create tokens (shows full token once)
- [ ] Can revoke tokens
- [ ] Can set credentials per plugin
- [ ] Can delete credentials
- [ ] Can view activity log
- [ ] Error dialogs for API failures
- [ ] App is signed and notarized
