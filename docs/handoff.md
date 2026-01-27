# Handoff: macOS App Launch Failure Debugging

## 1. Current State

### Goal
Build a working macOS native app (DMG distribution) for GAP with proper signing, notarization, and automatic cleanup when users drag the app to trash.

### Where We Are
**Debugging** - The app builds and signs correctly, passes Gatekeeper verification, but fails to launch with error 163 "Launchd job spawn failed". We've exhausted standard troubleshooting and need to isolate whether the issue is the Login Items (SMAppService) feature.

### Codebase State
- **Broken**: The macOS app won't launch despite being properly signed and notarized
- Recent commits are good but untested in production due to launch failure
- The v0.5.1 release was created but may have the same issue

## 2. What's Been Done

### Key Decisions
1. **HTTPS proxy implemented** - Port 9443 now uses TLS (TLS 1.3 with PQ key exchange)
2. **Removed Homebrew distribution** - DMG from GitHub is primary macOS install method
3. **Developer ID signing** - Not App Store, distributed via GitHub releases
4. **Data Protection Keychain** - Eliminates keychain password prompts
5. **Removed provisioning profiles** - Development profiles conflicted with Developer ID signing

### Files Modified This Session
- `gap-server/src/main.rs` - Added periodic orphan detection (checks every 60s if binary deleted, cleans up launchd)
- `macos-app/sign-and-package.sh` - Developer ID signing, DMG signing, removed provisioning profile embedding
- `docs/RELEASING.md` - New consolidated release guide
- `docs/macos-distribution.md` - Trimmed to one-time setup only
- `AGENT_ORIENTATION.md` - Notarization docs
- `README.md` - Updated installation instructions (no Homebrew)

### Commits Made (recent)
```
e130d34 Add periodic self-check to detect and clean up orphaned gap-server process
8b7861e Release v0.5.1: Developer ID signing and release documentation
05073e7 Revert notarization docs to xcrun notarytool workflow
529ee8e Fix documentation drift: token list behavior and architecture
4d47183 Fix allowlist enforcement gap: proxy now rejects unauthorized hosts
```

### What We Tried for Launch Failure
1. Full system restart - didn't help
2. `sfltool resetbtm` - resets Background Task Management database
3. Removed provisioning profiles from bundle
4. Removed quarantine attributes (`xattr -cr`)
5. Fresh install from DMG
6. Different install locations (/Applications vs /tmp)
7. Running binary directly - exits with SIGKILL (137)

All attempts still result in error 163 "Launchd job spawn failed".

## 3. What's Pending

### Immediate Next Step
**Build a test version WITHOUT the Login Items feature** to isolate whether SMAppService is causing the issue:

1. Modify `macos-app/GAP-App/Sources/ServerManager.swift`:
   - Comment out or remove the `SMAppService.loginItem()` registration in `install()` function (around line 62-69)
   - Keep the LaunchAgent plist installation (that's separate)

2. Rebuild and test:
   ```bash
   cd macos-app
   ./build-dmg.sh
   ./sign-and-package.sh
   cp -R build/Gap.app /Applications/
   open /Applications/Gap.app
   ```

3. If it works without SMAppService:
   - The issue is Login Items registration
   - May need to investigate macOS Tahoe (26) specific requirements
   - Consider alternative approach (just LaunchAgent, no Login Item)

4. If it still fails:
   - Issue is elsewhere in the SwiftUI app
   - Compare with working apps like Stats.app or Docker.app

### Known Blockers
- Error 163 "Launchd job spawn failed" on every launch attempt
- May be macOS Tahoe (26) specific behavior
- May be corrupted user-level state that persists through reboot

## 4. Context for Next Agent

### Key Files to Read
1. `AGENT_ORIENTATION.md` - Project overview and gotchas
2. `macos-app/GAP-App/Sources/ServerManager.swift` - **THE FILE TO MODIFY** - contains SMAppService.loginItem() registration
3. `macos-app/GAP-App/Sources/GAPApp.swift` - Main SwiftUI app structure
4. `macos-app/sign-and-package.sh` - Signing process
5. `docs/RELEASING.md` - Release process

### Important Patterns
- The app has a Login Item helper at `Gap.app/Contents/Library/LoginItems/gap-server.app`
- The main app registers this helper via `SMAppService.loginItem(identifier:)` on install
- It also creates a LaunchAgent plist at `~/Library/LaunchAgents/com.mikekelly.gap-server.plist`
- The helper (gap-server) has orphan detection that cleans up when binary is deleted

### Gotchas
- **sfltool resetbtm requires auth** - Can't be automated, shows popup
- **Development provisioning profiles conflict with Developer ID** - Don't embed them
- **Error 163 = ECANCELED** - Generic "spawn failed" in launchd context
- **macOS system curl incompatible with TLS 1.3 PQ** - Use homebrew curl for HTTPS proxy testing

### User Preferences
- User delegates by default (see CLAUDE.md)
- Prefers minimal changes, KISS principle
- Wants clean UX - no password prompts, automatic cleanup on uninstall

## 5. Open Questions

1. **Is this macOS Tahoe (26) specific?** - The SMAppService behavior may have changed
2. **Is the user's BTM database corrupted beyond sfltool resetbtm?** - Might need different user account to test
3. **Do we need specific entitlements for Login Items in macOS 26?** - Compare with Docker.app which works

## Quick Test Commands

```bash
# Check current state
launchctl list | grep gap
sfltool dumpbtm | grep -i gap
ls ~/Library/LaunchAgents/*gap* 2>/dev/null

# Clean slate before testing
rm -rf /Applications/Gap.app
sfltool resetbtm  # Requires auth

# Build and install
cd macos-app
./build-dmg.sh
./sign-and-package.sh
cp -R build/Gap.app /Applications/
open /Applications/Gap.app

# Check launch failure
# Error 163 = "Launchd job spawn failed"
```

## The Key Change to Test

In `macos-app/GAP-App/Sources/ServerManager.swift`, the `install()` function (line 57-76):

```swift
func install() {
    // COMMENT OUT THIS SECTION to test without Login Items:
    // let service = SMAppService.loginItem(identifier: helperBundleID)
    // do {
    //     try service.register()
    //     NSLog("GAP: Registered login item")
    // } catch {
    //     NSLog("GAP: Failed to register login item: \(error)")
    // }

    // Keep this - LaunchAgent is separate from Login Items
    installLaunchAgent()

    // Keep this
    start()
}
```

If the app launches after commenting out the SMAppService code, the issue is isolated to Login Items registration.
