# ACP macOS GUI

Native macOS menu bar app for managing Agent Credential Proxy.

## Building

Requires Xcode command line tools (`xcode-select --install`).

### Build from CLI

```bash
# Build release
xcodebuild -project macos-gui/ACP.xcodeproj -scheme ACP -configuration Release \
  -derivedDataPath macos-gui/.build build

# Run
open macos-gui/.build/Build/Products/Release/ACP.app

# Clean
xcodebuild -project macos-gui/ACP.xcodeproj -scheme ACP clean
```

### Build from Xcode

Open `macos-gui/ACP.xcodeproj` and press Cmd+R.

## Architecture

The GUI uses the **same Management API as the CLI** - no special code paths.

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

## Project Structure

```
macos-gui/
├── ACP.xcodeproj/           # Xcode project
├── ACP/
│   ├── ACPApp.swift         # App entry, MenuBarExtra setup
│   ├── AppState.swift       # Global state (password hash, data)
│   ├── API/
│   │   ├── ACPClient.swift  # URLSession wrapper for Management API
│   │   ├── Models.swift     # Codable structs for API responses
│   │   └── PasswordHash.swift # SHA512 hashing (matches CLI)
│   ├── Views/
│   │   ├── MainWindow.swift # Tab navigation + all 4 views
│   │   ├── MenuBarView.swift # Menu bar dropdown
│   │   └── PasswordPrompt.swift # Password entry dialog
│   └── Resources/
│       └── Assets.xcassets/ # App icons
├── ACPTests/                # Unit tests
├── .build/                  # Build output (gitignored)
└── README.md
```

## Features

- **Menu Bar App**: Runs as menu bar icon (no dock icon)
- **Password Prompt**: Authenticates once per session
- **Plugin Management**: Install, update, uninstall plugins
- **Token Management**: Create, revoke agent tokens
- **Credential Management**: Set, delete credentials (write-only)
- **Activity Log**: View proxy requests with auto-refresh

## Password Hashing

The GUI hashes passwords identically to the CLI:

```swift
import CryptoKit

func hashPassword(_ password: String) -> String {
    let hash = SHA512.hash(data: Data(password.utf8))
    return hash.map { String(format: "%02x", $0) }.joined()
}
```

- Algorithm: SHA512, no salt, no iterations
- Output: 128-character lowercase hex string

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

## Self-Signed Certificate Trust

The GUI trusts self-signed certificates from localhost using a URLSessionDelegate:

```swift
class TrustDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge) async
                    -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        if challenge.protectionSpace.host == "localhost",
           let trust = challenge.protectionSpace.serverTrust {
            return (.useCredential, URLCredential(trust: trust))
        }
        return (.performDefaultHandling, nil)
    }
}
```

## Requirements

- macOS 13.0+
- Xcode 15+ (or command line tools)
- Running `acp-server` on localhost:9080

## Code Signing

For local development, the app signs with "Sign to Run Locally".

For distribution, configure a Developer ID certificate in Xcode and run:

```bash
xcodebuild -project macos-gui/ACP.xcodeproj -scheme ACP -configuration Release \
  CODE_SIGN_IDENTITY="Developer ID Application: Your Name" \
  -derivedDataPath macos-gui/.build build
```

Then notarize with `xcrun notarytool`.
