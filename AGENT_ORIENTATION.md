# Agent Orientation

## What This Is
GAP (Gated Agent Proxy) lets AI agents access APIs without seeing your credentials. Agents route requests through the proxy with a token; GAP injects stored credentials and forwards to the API. The agent never sees the actual API keys.

**Security model:**
- Credentials encrypted at rest in files (macOS: `~/.gap/secrets`), with master encryption key in traditional macOS keychain
- No API to retrieve credentials - write-only storage
- Agent tokens are for audit/tracking only, not authentication
- Proxy listens on localhost - stolen tokens useless off-machine

## Structure
- **Cargo workspace** with 3 crates:
  - `gap-lib` - Shared library (types, errors)
  - `gap` - CLI binary
  - `gap-server` - Server binary
- `docs/` — Architecture decisions and documentation
- See `README.md` for quick start

## Commands
```bash
cargo build          # Build all workspace members
cargo test           # Run all tests
cargo clippy         # Lint
cargo run --bin gap  # Run CLI
cargo run --bin gap-server  # Run server
```

## Top 5 Critical Gotchas

1. **Wildcard matching is single-level only**: `*.s3.amazonaws.com` matches `bucket.s3.amazonaws.com` but rejects both `s3.amazonaws.com` (no subdomain) and `evil.com.s3.amazonaws.com` (multiple levels). This is a security feature.

2. **PluginRuntime is not Send**: Contains Boa engine with `Rc` types. In async Axum handlers, scope PluginRuntime operations in a block to ensure the runtime is dropped before any `.await` points. Enable `#[axum::debug_handler]` to see detailed Send/Sync errors.

3. **KeychainStore.list() limitation**: Returns empty vec due to security-framework API limitations. This is why we use the Registry pattern for metadata tracking. FileStore provides full list() functionality.

4. **git2 callbacks are not Send**: `RepoBuilder` with `RemoteCallbacks` closures is not `Send`. In async handlers, scope the entire git clone operation in a block to ensure all non-Send types are dropped before any `.await` points.

5. **PluginRuntime single-context limitation**: Loading a plugin overwrites the global `plugin` object in the JS context. Only the most recently loaded plugin's transform function can be executed. Plugin metadata is preserved for all loaded plugins.

## Hybrid Credential Storage (macOS)

**Architecture:** Master encryption key stored in traditional macOS keychain, credentials encrypted at rest in files (`~/.gap/secrets`).

**Why this approach:**
- Traditional keychain supports "Always Allow" (one-time prompt)
- Avoids Data Protection Keychain complexity (signing, entitlements, `-34018` errors)
- Credentials encrypted with ChaCha20-Poly1305

**Storage classes:**
- `EncryptedFileStore` - Production default on macOS (master key in keychain, encrypted files)
- `FileStore` - Plain file storage (use with `--data-dir` or `GAP_DATA_DIR`)
- `KeychainStore` - Direct keychain storage (legacy, not used by default)

**Breaking change:** Users migrating from previous versions that stored directly in keychain must re-initialize credentials.

## Detailed Reference Documentation

For comprehensive details, see:
- **[docs/reference/types.md](docs/reference/types.md)** - All core types, their purposes, and usage patterns
- **[docs/reference/architecture.md](docs/reference/architecture.md)** - System design, patterns, TLS infrastructure, proxy pipeline, Management API, CLI, plugin management, installation
- **[docs/reference/gotchas.md](docs/reference/gotchas.md)** - Complete list of 30+ implementation caveats with explanations

## macOS App & Releases

**Full release process:** See [docs/RELEASING.md](docs/RELEASING.md)

**Location:** `macos-app/` directory

**Quick build commands:**
```bash
cd macos-app
./build-dmg.sh              # Build unsigned app
./sign-and-package.sh       # Sign (requires manual keychain unlock)
```

**Manual steps (cannot be automated by agents):**
1. **Keychain unlock** - macOS prompts for password when accessing Developer ID certificate
2. **Notarization** - First-time setup requires Apple ID credentials (use `xcrun notarytool store-credentials`)
3. **Provisioning profiles** - Must be downloaded from Apple Developer portal first

**Testing signed builds:**
- Use `--data-dir` flag with unsigned dev builds to bypass keychain
- Smoke test: `./smoke-tests/test-https-proxy.sh`

**Entitlements architecture:**
- Main app (`GAP.app`): Minimal entitlements (just `app-sandbox=false`)
- Helper binary (`gap-server`): Minimal entitlements (no `keychain-access-groups` needed - uses traditional keychain)
- Entitlement files: `build/main.entitlements` and `build/helper.entitlements` (tracked in git)
- Signing must apply correct entitlements to each binary separately (inside-out order: helper first, then main app)

**Icon regeneration:**
- Source logo: `gap_logo.png` (1024x1024 PNG in project root)
- Script: `macos-app/regenerate-icons.sh` - regenerates all icon sizes from source
- App icons stored in: `macos-app/GAP-App/Sources/Assets.xcassets/AppIcon.appiconset/`
- Menu bar icon stored in: `macos-app/GAP-App/Sources/Assets.xcassets/MenuBarIcon.imageset/`
- Menu bar icon uses `template-rendering-intent: template` for automatic monochrome rendering
- After regenerating, must run `macos-app/build-dmg.sh` to rebuild the app
- Build script uses `xcrun actool` to compile icons into `AppIcon.icns` and `Assets.car`
- **Critical:** Always verify icon content visually, not just timestamps. Simply copying icon files doesn't update the built app - must run regenerate script to properly resize from source.
- **macOS icon caching:** After rebuilding with new icons, may need to clear system icon cache (`rm -rf /Library/Caches/com.apple.iconservices.store` and `killall Dock Finder`) or restart Mac.

**Common issues:**
- LibreSSL TLS error: macOS system curl incompatible with TLS 1.3 PQ key exchange; use homebrew curl
- Error 163 on launch: Incorrect entitlements on main app (keep minimal: just `app-sandbox=false`)
- Exit code 137 (SIGKILL): On modern macOS, Developer ID signed binaries require notarization to run. For local testing, use ad-hoc signing (`codesign --sign -`) instead of Developer ID signing.

## Quick Type Reference

Key types you'll use frequently:
- `GAPRequest`, `GAPCredentials`, `GAPPlugin` - HTTP and plugin types
- `AgentToken` - Bearer token (`.token` is a field, not a method)
- `SecretStore` trait - Storage abstraction (`EncryptedFileStore`, `FileStore`, `KeychainStore`)
- `PluginRuntime` - Sandboxed Boa JS runtime for plugins
- `Registry` - Centralized metadata at key `"_registry"`
- `CertificateAuthority` - TLS CA for dynamic cert generation
- `ProxyServer` - MITM HTTPS proxy with agent auth

See [docs/reference/types.md](docs/reference/types.md) for full details.
