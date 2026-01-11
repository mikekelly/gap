# macOS Distribution Guide

This document covers signing, notarizing, and distributing ACP binaries via Homebrew.

## Prerequisites

### Apple Developer Account
- Apple Developer Program membership ($99/year): https://developer.apple.com/programs/

### Developer ID Certificate
1. Go to https://developer.apple.com/account/resources/certificates/list
2. Click "+" → Select "Developer ID Application"
3. Create a Certificate Signing Request (CSR):
   - Open Keychain Access
   - Menu: Keychain Access → Certificate Assistant → Request a Certificate from a Certificate Authority
   - Enter your email, select "Saved to disk"
   - Save the `.certSigningRequest` file
4. Upload CSR to Apple, download the `.cer` file
5. Double-click to install (use **System** keychain, not iCloud)
6. Verify: `security find-identity -v -p codesigning | grep "Developer ID"`

### Notarization Credentials
1. Create app-specific password at https://appleid.apple.com (App-Specific Passwords → Generate)
2. Store credentials in keychain:
   ```bash
   xcrun notarytool store-credentials "notarytool-profile" \
     --apple-id "your-apple-id@example.com" \
     --team-id "YOUR_TEAM_ID" \
     --password "xxxx-xxxx-xxxx-xxxx"
   ```
3. Credentials are stored in `.env.local` (gitignored) for reference

## Release Process

### 1. Bump Version

Update the version in `Cargo.toml`:
```bash
# Edit Cargo.toml and change:
# [workspace.package]
# version = "0.1.1"  # <- increment this

# Verify the change
grep 'version = ' Cargo.toml
```

### 2. Build Release Binaries
```bash
cargo build --release

# Verify version is correct
./target/release/acp --version
./target/release/acp-server --version
```
Binaries are created at:
- `target/release/acp`
- `target/release/acp-server`

### 3. Sign with Developer ID
```bash
./scripts/macos-sign.sh --production
```

This script:
- Signs both binaries with Developer ID
- Enables hardened runtime (`--options runtime`)
- Adds secure timestamp (`--timestamp`)
- Adds `disable-library-validation` entitlement (required for Homebrew OpenSSL compatibility)
- Verifies signatures

**Important:** The `disable-library-validation` entitlement is required because:
- Hardened runtime prevents loading libraries with different Team IDs
- Homebrew's OpenSSL has a different (or no) Team ID
- Without this entitlement, users get: "mapping process and mapped file have different Team IDs"

### 4. Notarize with Apple
```bash
# Create zip and submit for notarization
cd target/release
zip ../../dist/acp-binaries.zip acp acp-server
cd ../..

xcrun notarytool submit dist/acp-binaries.zip \
  --keychain-profile "notarytool-profile" \
  --wait
```

This:
- Submits to Apple's notarization service
- Waits for approval (usually 2-5 minutes)
- Status should be "Accepted"

**Note:** Stapling only works for `.app`, `.pkg`, and `.dmg` files. Bare executables can't be stapled, but Gatekeeper will verify them online.

### 5. Package Release Tarball
```bash
cd target/release
tar -czvf ../../dist/acp-darwin-arm64.tar.gz acp acp-server
cd ../..
shasum -a 256 dist/acp-darwin-arm64.tar.gz
```

Record the SHA256 - you'll need it for the Homebrew formula.

### 6. Commit and Tag
```bash
git add Cargo.toml Cargo.lock
git commit -m "Bump version to X.Y.Z"
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin main
git push origin vX.Y.Z
```

### 7. Create GitHub Release
```bash
gh release create vX.Y.Z \
  --title "vX.Y.Z - Description" \
  --notes "Release notes here" \
  dist/acp-darwin-arm64.tar.gz
```

### 8. Update Homebrew Formula
Edit `~/code/homebrew-acp/Formula/acp-server.rb`:
- Update `version`
- Update `url` to point to new release
- Update `sha256` with the checksum from step 5

```bash
cd ~/code/homebrew-acp
git add Formula/acp-server.rb
git commit -m "Update to v0.1.0"
git push
```

## Homebrew Tap Structure

Repository: https://github.com/mikekelly/homebrew-acp

```
homebrew-acp/
├── README.md
└── Formula/
    └── acp-server.rb
```

### Formula Template
```ruby
class AcpServer < Formula
  desc "Agent Credential Proxy - secure credential management for AI agents"
  homepage "https://github.com/mikekelly/acp"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mikekelly/acp/releases/download/v0.1.0/acp-darwin-arm64.tar.gz"
      sha256 "SHA256_HERE"
    else
      odie "Intel Mac binary not yet available. Please build from source."
    end
  end

  def install
    bin.install "acp"
    bin.install "acp-server"
  end

  service do
    run [opt_bin/"acp-server"]
    keep_alive true
    log_path var/"log/acp-server.log"
    error_log_path var/"log/acp-server.err"
  end

  test do
    system "#{bin}/acp-server", "--version"
  end
end
```

## User Installation

```bash
brew tap mikekelly/acp
brew install acp-server

# Start as background service
brew services start acp-server

# Or run directly
acp-server
```

## Troubleshooting

### "Developer ID certificate not found"
Install your Developer ID certificate from Apple Developer Portal. Must be "Developer ID Application" (not "Apple Development").

### Error -25294 when importing certificate
The private key from your CSR isn't in the keychain. Either:
- The CSR was created on a different Mac
- The private key was deleted

Solution: Revoke the certificate and create a new one with a fresh CSR on this Mac.

### "different Team IDs" error when running binary
The binary needs the `disable-library-validation` entitlement. Re-sign with:
```bash
codesign --sign "Developer ID Application" \
  --force --options runtime --timestamp \
  --entitlements entitlements.plist \
  target/release/acp-server
```

Where `entitlements.plist` contains:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>
```

### Stapling fails with Error 73
This is expected for bare Mach-O executables. Stapling only works for `.app`, `.pkg`, and `.dmg` files. The binary is still notarized - Gatekeeper will verify online.

### SHA256 mismatch after reinstall
If you re-signed/re-notarized, you need to:
1. Re-create the tarball
2. Get new SHA256
3. Update GitHub release (delete old asset, upload new)
4. Update formula with new SHA256
5. Push formula changes

## Future Improvements

- **Static link OpenSSL**: Eliminates need for `disable-library-validation` entitlement
- **Intel Mac builds**: Add x86_64 binaries via cross-compilation or CI
- **Linux builds**: Add Linux binaries for Linuxbrew
- **Automated releases**: GitHub Actions workflow for build → sign → notarize → release
