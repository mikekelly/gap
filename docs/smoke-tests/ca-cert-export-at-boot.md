# Smoke Test: CA Certificate Export at Boot

> Last verified: 2026-01-19 | Status: ❌ FAIL (Path mismatch bug found)

## Prerequisites
- [ ] Clean environment (no existing gap-server running)
- [ ] No existing CA cert files
- [ ] Workspace built with `cargo build --workspace`

## Critical Path 1: Server Exports CA Cert at Boot

**Goal:** Verify that gap-server exports the CA certificate to a well-known platform-specific path when it starts

### Steps
1. Clean any existing CA cert at platform path
   - macOS: `rm -f ~/Library/Application\ Support/gap/ca.crt`
   - Linux: `sudo rm -f /var/lib/gap/ca.crt`
   - Expected: File removed or doesn't exist
   - [x] Pass

2. Start gap-server
   - Run: `cargo run --bin gap-server`
   - Expected: Server starts successfully
   - Expected: Log shows "CA certificate exported to [path]"
   - [x] Pass

3. Verify CA cert file exists at platform path
   - macOS: `ls -la ~/Library/Application\ Support/gap/ca.crt`
   - Linux: `ls -la /var/lib/gap/ca.crt`
   - Expected: File exists with ~600-700 bytes
   - [x] Pass

4. Verify CA cert is valid X.509 format
   - Run: `openssl x509 -in "[path]" -noout -text | head -20`
   - Expected: Valid certificate with CN=GAP Certificate Authority
   - [x] Pass

### Result
- Status: ✅
- Notes: Server successfully exports CA cert to `~/Library/Application Support/gap/ca.crt` on macOS. Log message confirms: "CA certificate exported to /Users/mike/Library/Application Support/gap/ca.crt"

## Critical Path 2: CLI TLS Verification

**Goal:** Verify that gap CLI reads the CA cert and performs proper TLS verification when connecting to the server

### Steps
1. Run a gap command (e.g., `gap status`)
   - Run: `cargo run --bin gap -- status`
   - Expected: Command succeeds with proper TLS verification
   - Expected: No certificate warnings
   - [x] Fail

2. Verify no `danger_accept_invalid_certs` in use
   - Check: No warnings about unverified certificates
   - Check: TLS handshake completes successfully
   - [x] Fail

### Result
- Status: ❌
- Notes: **BUG FOUND** - Path mismatch between server and CLI:
  - Server exports CA cert to: `~/Library/Application Support/gap/ca.crt` (via `gap_lib::ca_cert_path()`)
  - CLI looks for CA cert at: `~/.config/gap/ca.crt` (via `get_default_ca_path()` in gap/src/main.rs)
  - **Workaround:** Copy cert to `~/.config/gap/ca.crt` - then TLS verification works correctly
  - **Fix needed:** CLI should use `gap_lib::ca_cert_path()` instead of hardcoded `~/.config/gap/ca.crt`

## Critical Path 3: Normal Operation

**Goal:** Verify that commands work with proper TLS verification

### Steps
1. Run various gap commands
   - Run: `cargo run --bin gap -- status`
   - Expected: Returns server status (version, uptime, ports)
   - [x] Pass (with workaround)

2. Verify TLS handshake in debug logs
   - Run: `RUST_LOG=debug cargo run --bin gap -- status`
   - Expected: Shows rustls TLS handshake with proper certificate verification
   - [x] Pass (with workaround)

### Result
- Status: ✅ (with workaround)
- Notes: After copying CA cert to the location where CLI expects it, TLS verification works perfectly. Debug logs show proper TLS 1.3 handshake with certificate verification.

## Summary
| Path | Status | Notes |
|------|--------|-------|
| Server Exports CA Cert | ✅ | Server correctly exports to platform-specific path |
| CLI TLS Verification | ❌ | Path mismatch bug - CLI looks in wrong location |
| Normal Operation | ✅ | Works correctly once cert is in expected location |

## Critical Bug Found

**Issue:** Server and CLI use different paths for CA certificate

**Details:**
- Server exports to platform-specific path via `gap_lib::ca_cert_path()`:
  - macOS: `~/Library/Application Support/gap/ca.crt`
  - Linux: `/var/lib/gap/ca.crt`
- CLI hardcodes path in `gap/src/main.rs::get_default_ca_path()`:
  - All platforms: `~/.config/gap/ca.crt`

**Impact:** CA cert export feature is broken - CLI cannot find the certificate exported by the server

**Reproduction:**
1. Start fresh gap-server (exports cert to `~/Library/Application Support/gap/ca.crt`)
2. Run `gap status`
3. Error: "CA certificate not found at /Users/mike/.config/gap/ca.crt"

**Fix Required:**
Update `gap/src/main.rs::get_default_ca_path()` to use `gap_lib::ca_cert_path()` instead of hardcoding `~/.config/gap/ca.crt`

**Verification After Fix:**
1. Clean both possible cert locations
2. Start gap-server
3. Run `gap status` without manual intervention
4. Should work immediately without copying cert manually
