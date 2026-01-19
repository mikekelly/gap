# Smoke Test: CA Certificate Export at Boot

> Last verified: 2026-01-19 | Status: PASS

## Prerequisites
- [x] gap workspace built (`cargo build --workspace`)
- [x] No gap-server running on port 9080
- [x] macOS environment (test path: `~/Library/Application Support/gap/ca.crt`)

## Critical Path 1: Server Exports CA Cert at Boot

**Goal:** Verify gap-server creates CA certificate at correct platform-specific path on startup

### Steps
1. Remove any existing CA cert files
   - Expected: Clean slate for testing
   - [x] Pass

2. Start gap-server
   - Expected: Server starts, logs CA cert creation
   - [x] Pass - Server logged: "CA certificate exported to /Users/mike/Library/Application Support/gap/ca.crt"

3. Verify CA cert exists at `~/Library/Application Support/gap/ca.crt`
   - Expected: File exists and is a valid PEM certificate
   - [x] Pass - File exists (639 bytes), valid PEM format confirmed

### Result
- Status: PASS
- Notes: Server correctly exports CA cert to platform-specific path on boot. Old path (`~/.config/gap/ca.crt`) NOT used.

## Critical Path 2: CLI Finds and Trusts CA Cert

**Goal:** Verify CLI uses `gap_lib::ca_cert_path()` to find cert and establishes TLS trust

### Steps
1. Run `gap status` command (non-interactive alternative to `gap init`)
   - Expected: No "unverified cert" or TLS warnings
   - [x] Pass - Command completed successfully

2. Check status output for successful TLS handshake
   - Expected: Command completes without certificate errors
   - [x] Pass - Clean output showing server version, uptime, ports

3. Verify no TLS warnings in any command output
   - Expected: No certificate/TLS error messages
   - [x] Pass - No warnings found

### Result
- Status: PASS
- Notes: CLI successfully finds and trusts CA cert at new location. TLS handshake works correctly. Note: `gap init` requires interactive password input, so `gap status` was used to verify TLS operation.

## Critical Path 3: End-to-End Operation

**Goal:** Verify normal operations work with proper TLS verification

### Steps
1. Run `gap status` command
   - Expected: Command succeeds, shows server info
   - [x] Pass - Returned version 0.3.1, uptime, proxy port 9443, API port 9080

2. Check for any TLS/certificate warnings in output
   - Expected: Clean output, no warnings
   - [x] Pass - No certificate or TLS warnings detected

### Result
- Status: PASS
- Notes: End-to-end TLS operation verified. CLI successfully communicates with server using trusted CA cert.

## Summary
| Path | Status | Notes |
|------|--------|-------|
| Server exports cert at boot | PASS | Cert created at correct macOS path |
| CLI finds and trusts cert | PASS | TLS handshake successful, no warnings |
| End-to-end operation | PASS | Normal operations work with TLS verification |

## Known Issues
- None - all critical paths passed
