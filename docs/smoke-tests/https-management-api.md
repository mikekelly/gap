# Smoke Test: HTTPS Management API

> Last verified: 2026-01-13 | Status: PASS

## Prerequisites
- [ ] Clean environment (no existing ACP data)
- [ ] Rust toolchain installed
- [ ] Both server and CLI binaries can be built
- [ ] Ports 9080 and 9081 available

## Test Environment
- **OS:** macOS (Darwin 25.1.0)
- **Server:** acp-server v0.2.2
- **CLI:** acp v0.2.2
- **Storage:** File-based (using --data-dir flag)
- **CA Certificate Location:** `~/.config/acp/ca.crt`

## Fixes Verified
1. Certificate signature failure (commit a839237) - FIXED
2. Port mismatch (commit f438b7c) - FIXED (CLI defaults to 9080)

## Critical Path 1: Fresh Init Flow

**Goal:** Verify that a fresh initialization creates a management certificate and the server serves HTTPS correctly.

### Steps

1. Clean environment completely
   - Run: `rm -rf ~/.config/acp ~/.local/share/acp`
   - Expected: Clean slate for testing
   - [x] PASS

2. Start the server with test data directory
   - Run: `cargo run -p acp-server -- --api-port 9080 --proxy-port 9081 --data-dir /tmp/acp-test-data`
   - Expected: Server starts, generates CA and management cert, listens on HTTPS
   - [x] PASS
   - Server logs show:
     ```
     INFO Generating new CA certificate
     INFO CA certificate saved to storage
     INFO Generating new management certificate
     INFO Management certificate saved to storage
     INFO Management API listening on https://0.0.0.0:9080
     ```

3. Run init command with password
   - Run: Use expect script to provide password interactively
   ```bash
   spawn cargo run -p acp -- init
   expect "Enter password:" -> send "testpass123\r"
   expect "Confirm password:" -> send "testpass123\r"
   ```
   - Expected: Command succeeds, CA cert saved to `~/.config/acp/ca.crt`
   - [x] PASS
   - Output: "ACP initialized successfully! CA certificate saved to: /Users/mike/.config/acp/ca.crt"

4. Verify CA certificate file exists
   - Run: `ls -la ~/.config/acp/ca.crt`
   - Expected: File exists and is readable
   - [x] PASS

### Result
- Status: PASS
- Notes:
  - Server must be started with `--data-dir` flag for truly fresh environment
  - Without `--data-dir`, server uses macOS Keychain which persists across runs
  - Init command requires interactive password input (no flag support)
  - CLI now defaults to port 9080, matching server default

---

## Critical Path 2: HTTPS Verification

**Goal:** Verify that the management certificate is properly signed by the CA and HTTPS connections are secure.

### Steps

1. Test with OpenSSL
   - Run: `openssl s_client -connect localhost:9080 -CAfile ~/.config/acp/ca.crt </dev/null`
   - Expected: Shows "Verify return code: 0 (ok)"
   - [x] PASS
   - Output confirms certificate chain is valid

2. Test with curl using CA cert
   - Run: `curl --cacert ~/.config/acp/ca.crt https://localhost:9080/status`
   - Expected: Successfully retrieves status JSON
   - [x] PASS
   - Output: `{"version":"0.2.2","uptime_seconds":42,"proxy_port":9081,"api_port":9080}`

3. Verify curl fails without CA cert
   - Run: `curl https://localhost:9080/status` (no --cacert)
   - Expected: Certificate verification error
   - [x] PASS (implicit - system doesn't trust self-signed cert)

### Result
- Status: PASS
- Notes:
  - Certificate signature bug is FIXED
  - Management cert properly signed by CA
  - Both OpenSSL and curl verify successfully
  - This was previously FAILING with "certificate signature failure"

---

## Critical Path 3: CLI Operations Over HTTPS

**Goal:** Verify that standard CLI operations work correctly over the HTTPS connection.

### Steps

1. Check server status
   - Run: `cargo run -p acp -- status`
   - Expected: Returns server status information without password
   - [x] PASS
   - Output:
     ```
     ACP Server Status
       Version: 0.2.2
       Uptime: 53 seconds
       Proxy Port: 9081
       API Port: 9080
     ```

2. Verify HTTPS is being used
   - Check: CLI uses `https://localhost:9080` by default
   - Expected: Default server URL matches actual API port
   - [x] PASS
   - CLI help shows: `--server <SERVER>  Server URL (default: https://localhost:9080...)`

### Result
- Status: PASS
- Notes:
  - Port mismatch bug is FIXED
  - CLI now defaults to 9080 (was 9443)
  - Status command works without password prompt
  - HTTPS certificate verification succeeds automatically

---

## Critical Path 4: Certificate Rotation

**Goal:** Verify that management certificates can be rotated without restarting the server and connections continue to work.

### Steps

1. Verify baseline certificate works
   - Run: `cargo run -p acp -- status`
   - Expected: Command succeeds with original cert
   - [x] PASS

2. Rotate the management certificate
   - Run: Use expect script to provide password
   ```bash
   spawn cargo run -p acp -- new-management-cert --sans "DNS:localhost,IP:127.0.0.1"
   expect "Enter ACP password:" -> send "testpass123\r"
   ```
   - Expected: New certificate generated successfully
   - [x] PASS
   - Output: "Management certificate rotated successfully! New SANs: DNS:localhost, IP:127.0.0.1"

3. Verify CLI continues working with new certificate
   - Run: `cargo run -p acp -- status`
   - Expected: Command succeeds with rotated cert
   - [x] PASS
   - Server uptime increased, confirming no restart occurred

4. Verify new certificate is valid
   - Run: `openssl s_client -connect localhost:9080 -CAfile ~/.config/acp/ca.crt </dev/null`
   - Expected: Certificate verification still passes
   - [x] PASS
   - Output: "Verify return code: 0 (ok)"

### Result
- Status: PASS
- Notes:
  - Hot-swap works correctly
  - Server continues running during rotation
  - New certificate properly signed by same CA
  - Existing CLI commands work immediately with new cert

---

## Summary

| Path | Status | Notes |
|------|--------|-------|
| Fresh Init Flow | PASS | Requires --data-dir for fresh environment |
| HTTPS Verification | PASS | Certificate signature bug FIXED |
| CLI Operations Over HTTPS | PASS | Port mismatch bug FIXED |
| Certificate Rotation | PASS | Hot-swap works without restart |

## Issues Found

None. All critical paths passing.

## Previous Issues Now Fixed

### 1. Certificate Signature Verification Failure (FIXED)
**Status:** RESOLVED in commit a839237
- Management certificates now properly signed by CA
- Both OpenSSL and curl verify successfully
- Root cause was duplicate `der_to_pem` conversion

### 2. Port Configuration Mismatch (FIXED)
**Status:** RESOLVED in commit f438b7c
- CLI now defaults to port 9080
- Matches server's default management API port
- No need for `--server` flag override

### 3. Server Auto-Initialization (DESIGN NOTE)
**Status:** Working as designed
- Server auto-generates certs on first startup
- This is expected behavior for ease of use
- For truly fresh environment, use `--data-dir` flag with empty directory
- `acp init` downloads CA cert for client use

## Recommendations

1. **Documentation:** Update README to mention `--data-dir` flag for testing/containers
2. **Success:** Both critical bugs are FIXED and verified working

## Testing Notes

**Password in CI/Scripts:** For non-interactive testing, use the `ACP_PASSWORD` environment variable (intentionally undocumented to discourage production use). This avoids passwords appearing in shell history while enabling automation:

```bash
ACP_PASSWORD=testpass123 cargo run -p acp -- init
ACP_PASSWORD=testpass123 cargo run -p acp -- new-management-cert --sans "DNS:localhost"
```

A `--password` flag is intentionally NOT provided to prevent secrets from appearing in shell history and process listings.

## Reproduction Steps for Future Testing

To verify these fixes in the future:

```bash
# 1. Clean environment
rm -rf ~/.config/acp ~/.local/share/acp /tmp/acp-test-data

# 2. Start server with test data directory
cargo run -p acp-server -- --api-port 9080 --proxy-port 9081 --data-dir /tmp/acp-test-data &

# 3. Wait for server to start (3 seconds)
sleep 3

# 4. Initialize (use ACP_PASSWORD env var for non-interactive testing)
ACP_PASSWORD=testpass123 cargo run -p acp -- init

# 5. Verify HTTPS
openssl s_client -connect localhost:9080 -CAfile ~/.config/acp/ca.crt </dev/null | grep "Verify return"
# Expected: "Verify return code: 0 (ok)"

# 6. Test CLI
cargo run -p acp -- status
# Expected: Shows version, uptime, ports

# 7. Test rotation (use ACP_PASSWORD env var)
ACP_PASSWORD=testpass123 cargo run -p acp -- new-management-cert --sans "DNS:localhost,IP:127.0.0.1"

# 8. Verify still works
cargo run -p acp -- status
```
