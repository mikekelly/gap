# macOS Packaging

## Objective

Package ACP for proper macOS distribution:
- Signed binaries (Developer ID)
- LaunchAgent for background execution
- Self-install/uninstall commands
- Keychain access prompt handled cleanly

## Current State

- Rust binaries built via Cargo
- Keychain integration working (`security-framework` crate)
- Self-signed dev signing script exists (`scripts/macos-sign.sh`)
- No LaunchAgent support
- No install/uninstall subcommands

## Blueprint

### Components

1. **LaunchAgent plist generation** - Template-based plist creation
2. **Install command** - `acp-server install` creates plist, loads service
3. **Uninstall command** - `acp-server uninstall` stops service, removes plist
4. **Status command** - `acp-server status` shows if running via launchd
5. **Production signing script** - Uses Developer ID, hardened runtime, notarization

### LaunchAgent Location

```
~/Library/LaunchAgents/com.acp.server.plist
```

User-level agent (no sudo required), runs after login, has access to user's Keychain.

### Plist Template

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.acp.server</string>
  <key>Program</key>
  <string>{binary_path}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{binary_path}</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log_dir}/acp-server.log</string>
  <key>StandardErrorPath</key>
  <string>{log_dir}/acp-server.err</string>
</dict>
</plist>
```

### CLI Interface

```bash
# Install as background service
acp-server install
# Output: Installed LaunchAgent to ~/Library/LaunchAgents/com.acp.server.plist
#         Service started. View logs: tail -f ~/.acp/logs/acp-server.log

# Check status
acp-server status
# Output: acp-server is running (pid 12345)
#    or:  acp-server is not running

# Uninstall
acp-server uninstall
# Output: Stopped acp-server
#         Removed ~/Library/LaunchAgents/com.acp.server.plist

# Uninstall including data
acp-server uninstall --purge
# Also removes ~/.acp/ directory (but not Keychain items)
```

## Phases

### Phase 1: LaunchAgent Support

Add install/uninstall/status commands to acp-server.

1. Add `launchd` module with plist generation
2. Add `install` subcommand
3. Add `uninstall` subcommand
4. Add `status` subcommand
5. Add integration tests

### Phase 2: Production Signing

Update signing for distribution.

1. Update `scripts/macos-sign.sh` for Developer ID
2. Add notarization script
3. Document signing process

### Phase 3: Polish

1. Update install.sh to optionally run `acp-server install`
2. Update README with macOS-specific instructions
3. Add smoke test for install/uninstall cycle

## Risks

- **Hardened runtime + OpenSSL**: Current script avoids this. Need to verify rustls-based build works with hardened runtime.
- **Keychain prompts during install**: First run will prompt for Keychain access. Document this.
- **Log rotation**: LaunchAgent logs grow unbounded. Consider newsyslog or manual rotation.

## Out of Scope

- pkg installer (can add later if needed)
- Homebrew formula (can add later)
- GUI/menu bar app (separate feature)
- Automatic updates
