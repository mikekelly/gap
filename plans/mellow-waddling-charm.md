# Plan: Hybrid Storage (Keychain Key + Encrypted Files)

## Problem
- Data Protection Keychain (DPK) with `keychain-access-groups` requires provisioning profile
- Provisioning profiles are incompatible with Developer ID distribution
- Plain file storage works but credentials are unencrypted at rest

## Solution
Store a master encryption key in **traditional keychain** (one prompt, "Always Allow"), encrypt all credentials before writing to `~/.gap/`.

## Implementation

### 1. Add `EncryptedFileStore` to `gap-lib/src/storage.rs`

New struct implementing existing `SecretStore` trait:

```rust
pub struct EncryptedFileStore {
    file_store: FileStore,           // Delegate file I/O
    keychain_service: String,        // "com.mikekelly.gap-server"
    keychain_account: String,        // "master_key"
}

impl EncryptedFileStore {
    pub async fn new(base_path: PathBuf) -> Result<Self>;

    // Get master key from keychain, or generate + store if first run
    fn get_or_create_master_key(&self) -> Result<[u8; 32]>;

    // ChaCha20-Poly1305: [nonce:12][ciphertext+tag]
    fn encrypt(&self, plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>>;
    fn decrypt(&self, ciphertext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>>;
}
```

### 2. Update `create_store()` factory in `storage.rs`

```rust
#[cfg(target_os = "macos")]
#[cfg(not(test))]
{
    // Use EncryptedFileStore for macOS production
    let path = /* ~/.gap/secrets */;
    let store = EncryptedFileStore::new(path).await?;
    return Ok(Box::new(store));
}
```

### 3. Add crypto dependency to `gap-lib/Cargo.toml`

```toml
chacha20poly1305 = "0.10"  # AEAD encryption
rand = "0.8"               # Key generation (may already exist)
```

### 4. Keychain interaction (uses existing `keychain_impl.rs`)

- Service: `com.mikekelly.gap-server`
- Account: `master_key`
- **No** `kSecAttrAccessGroup` (traditional keychain)
- **No** `kSecUseDataProtectionKeychain` (avoid entitlement issues)
- User sees ONE prompt on first run, clicks "Always Allow"

## Files to Modify

| File | Change |
|------|--------|
| `gap-lib/src/storage.rs` | Add `EncryptedFileStore`, update `create_store()` |
| `gap-lib/Cargo.toml` | Add `chacha20poly1305` dependency |
| `macos-app/build/helper.entitlements` | Remove `keychain-access-groups` (not needed for traditional keychain) |

## What Stays the Same

- `SecretStore` trait interface (no changes to consumers)
- `FileStore` (kept for Linux, containers, `--data-dir` flag)
- `KeychainStore` (kept for tests, can be removed later)
- `keychain_impl.rs` functions (reused for master key)

## Storage Format

**Encrypted file format:** `[nonce:12 bytes][ciphertext + auth tag]`

**File location:** `~/.gap/secrets/<base64url-encoded-key>`

**Master key:** 32 random bytes, stored in keychain as generic password

## UX Flow

1. User installs Gap.app, launches it
2. gap-server starts, calls `EncryptedFileStore::new()`
3. First run: generates master key, stores in keychain
4. macOS shows keychain prompt: "gap-server wants to use keychain"
5. User enters password, clicks **"Always Allow"**
6. Subsequent runs: master key retrieved silently (no prompt)
7. After app update (re-signing): one new prompt (expected, good security)

## Verification

1. **Build and sign:**
   ```bash
   cargo build --release -p gap-server
   cd macos-app && ./build-dmg.sh && ./sign-and-package.sh
   ```

2. **Clean install:**
   ```bash
   rm -rf /Applications/Gap.app ~/.gap
   security delete-generic-password -s "com.mikekelly.gap-server" -a "master_key" 2>/dev/null
   cp -R build/Gap.app /Applications/
   ```

3. **First launch (expect keychain prompt):**
   ```bash
   open /Applications/Gap.app
   # Click "Always Allow" when prompted
   ```

4. **Verify server running:**
   ```bash
   pgrep gap-server
   curl -s http://localhost:9080/status
   ```

5. **Verify encrypted storage:**
   ```bash
   ls ~/.gap/secrets/
   file ~/.gap/secrets/*  # Should show "data" not "ASCII text"
   ```

6. **Second launch (no prompt):**
   ```bash
   pkill gap-server
   open /Applications/Gap.app
   # No keychain prompt expected
   ```

7. **Notarize and test distributed version:**
   ```bash
   xcrun notarytool submit build/Gap Installer.dmg --keychain-profile "notarytool-profile" --wait
   xcrun stapler staple build/Gap Installer.dmg
   # Test on clean system or different user account
   ```
