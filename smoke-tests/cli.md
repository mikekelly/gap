# CLI Smoke Tests

Manual test script to verify CLI behavior against the v1 specification.

## Prerequisites

- Built binaries: `acp` and `acp-server`
- Clean state (no existing ACP data)
- Terminal with interactive input capability

## Test Environment Setup

```bash
# Build the binaries
cargo build --release

# Set up paths
export ACP_BIN=./target/release/acp
export ACP_SERVER_BIN=./target/release/acp-server

# For clean slate testing, remove existing data:
# macOS: security delete-generic-password -s "acp:*" (for each key)
# Linux: sudo rm -rf /var/lib/acp/
```

---

## 1. Status (Unauthenticated)

### 1.1 Status when server not running

**Steps:**
1. Ensure `acp-server` is not running
2. Run `$ACP_BIN status`

**Expected:**
- Exit code: non-zero
- Output indicates server is not running or unreachable

### 1.2 Status when server running

**Steps:**
1. Start server: `$ACP_SERVER_BIN &`
2. Run `$ACP_BIN status`

**Expected:**
- Exit code: 0
- Output shows: version, uptime, proxy port (9443), API port (9080)
- No password prompt

---

## 2. Initialization

### 2.1 First-time init

**Steps:**
1. Ensure clean state (no existing ACP data)
2. Run `$ACP_BIN init`
3. When prompted, enter password: `testpass123`
4. When prompted for confirmation, enter: `testpass123`

**Expected:**
- Password input is hidden (no echo)
- Success message: "Server initialized"
- CA certificate path shown (default: `~/.config/acp/ca.crt`)
- CA certificate file exists at shown path

### 2.2 Init with custom CA path

**Steps:**
1. Ensure clean state
2. Run `$ACP_BIN init --ca-path /tmp/test-ca.crt`
3. Enter and confirm password

**Expected:**
- CA certificate created at `/tmp/test-ca.crt`
- Success message references custom path

### 2.3 Init password mismatch

**Steps:**
1. Ensure clean state
2. Run `$ACP_BIN init`
3. Enter password: `password1`
4. Enter confirmation: `password2`

**Expected:**
- Error message about password mismatch
- No state changes made
- Can retry init

### 2.4 Re-init when already initialized

**Steps:**
1. Complete successful init
2. Run `$ACP_BIN init` again

**Expected:**
- Error or warning that ACP is already initialized
- Existing configuration preserved

---

## 3. Plugin Management

### 3.1 List plugins (empty)

**Steps:**
1. Ensure server initialized and running
2. Run `$ACP_BIN plugins`
3. Enter password when prompted

**Expected:**
- Empty list or message indicating no plugins installed
- Password input hidden

### 3.2 Install plugin from GitHub

**Steps:**
1. Run `$ACP_BIN install mikekelly/exa-acp`
2. Observe plugin preview showing:
   - Plugin name
   - Version (git SHA)
   - Hosts it will handle
3. Enter password when prompted

**Expected:**
- Fetches from GitHub
- Preview shown before password prompt
- Success message after password
- Guidance on next steps (e.g., "run: acp set mikekelly/exa-acp:apiKey")

### 3.3 List plugins (with installed plugin)

**Steps:**
1. After installing plugin
2. Run `$ACP_BIN plugins`
3. Enter password

**Expected:**
- Shows installed plugin with:
  - Name (e.g., `exa`)
  - Version/SHA
  - Matched hosts (e.g., `api.exa.ai`)

### 3.4 Uninstall plugin

**Steps:**
1. Ensure plugin installed
2. Run `$ACP_BIN uninstall mikekelly/exa-acp`
3. Enter password

**Expected:**
- Success message
- Plugin no longer appears in `acp plugins`

### 3.5 Install with wrong password

**Steps:**
1. Run `$ACP_BIN install mikekelly/exa-acp`
2. Enter wrong password

**Expected:**
- Authentication error
- Plugin not installed

---

## 4. Credential Management

### 4.1 Set credential

**Steps:**
1. Ensure plugin installed (e.g., `exa`)
2. Run `$ACP_BIN set exa:apiKey`
3. Enter credential value when prompted (hidden input)
4. Enter password when prompted

**Expected:**
- Value input is hidden (no echo)
- Password input is hidden
- Success message: "Saved exa:apiKey"

### 4.2 Set credential for namespaced plugin

**Steps:**
1. Install `mikekelly/exa-acp`
2. Run `$ACP_BIN set mikekelly/exa-acp:apiKey`
3. Enter value and password

**Expected:**
- Credential saved with full namespace
- Success message references full plugin name

### 4.3 Set credential for non-existent plugin

**Steps:**
1. Run `$ACP_BIN set nonexistent:key`
2. Enter value and password

**Expected:**
- Error: plugin not installed
- Or: warning that plugin doesn't exist

### 4.4 Overwrite existing credential

**Steps:**
1. Set credential: `$ACP_BIN set exa:apiKey` with value "old"
2. Set again: `$ACP_BIN set exa:apiKey` with value "new"

**Expected:**
- Both operations succeed
- New value overwrites old (verify via proxy test if possible)

---

## 5. Token Management

### 5.1 Create token

**Steps:**
1. Run `$ACP_BIN token create claude-code`
2. Enter password

**Expected:**
- Success message
- Token displayed ONCE: `ACP_TOKEN=acp_...`
- Configuration guidance shown:
  - `HTTPS_PROXY` setting
  - `NODE_EXTRA_CA_CERTS` setting
  - Token usage

### 5.2 List tokens

**Steps:**
1. Create one or more tokens
2. Run `$ACP_BIN token list`
3. Enter password

**Expected:**
- Lists tokens with:
  - ID
  - Name
  - Prefix (partial token for identification)
  - Created timestamp
- Full token NOT shown (only prefix)

### 5.3 Revoke token

**Steps:**
1. Create token and note its ID
2. Run `$ACP_BIN token revoke <id>`
3. Enter password

**Expected:**
- Success message
- Token no longer appears in `acp token list`

### 5.4 Create duplicate token name

**Steps:**
1. Run `$ACP_BIN token create myagent`
2. Run `$ACP_BIN token create myagent` again

**Expected:**
- Either: error about duplicate name
- Or: both created with same name but different IDs/tokens

---

## 6. Activity Monitoring

### 6.1 View activity (empty)

**Steps:**
1. Run `$ACP_BIN activity`
2. Enter password

**Expected:**
- Empty list or message indicating no activity

### 6.2 View activity (with requests)

**Steps:**
1. Make requests through proxy (see Proxy Tests section)
2. Run `$ACP_BIN activity`
3. Enter password

**Expected:**
- Shows recent requests with:
  - Timestamp
  - Agent (token name)
  - Method
  - Host
  - Path
  - Status code
  - Latency

### 6.3 Follow activity stream

> **Note:** Activity streaming (`--follow`) is not yet implemented. This test is for future functionality.

**Steps:**
1. Run `$ACP_BIN activity --follow`
2. Enter password
3. Make requests through proxy in another terminal

**Expected:**
- Initial output (if any history)
- New requests appear in real-time
- Ctrl+C terminates stream cleanly

---

## 7. Remote Server

### 7.1 Specify server via flag

**Steps:**
1. Run server on different port or host
2. Run `$ACP_BIN --server http://localhost:9080 status`

**Expected:**
- Connects to specified server
- Returns status

### 7.2 Specify server via environment

**Steps:**
1. Run `ACP_SERVER=http://localhost:9080 $ACP_BIN status`

**Expected:**
- Uses server from environment
- Returns status

### 7.3 Flag overrides environment

**Steps:**
1. Set `ACP_SERVER=http://wrong:9999`
2. Run `$ACP_BIN --server http://localhost:9080 status`

**Expected:**
- Uses flag value, ignores environment
- Returns status (not connection error)

---

## 8. Error Handling

### 8.1 Invalid command

**Steps:**
1. Run `$ACP_BIN notacommand`

**Expected:**
- Error message with usage help
- Non-zero exit code

### 8.2 Missing required argument

**Steps:**
1. Run `$ACP_BIN install` (without plugin name)

**Expected:**
- Error about missing argument
- Usage hint

### 8.3 Network error

**Steps:**
1. Stop server
2. Run `$ACP_BIN plugins`

**Expected:**
- Clear error about server unreachable
- Non-zero exit code

### 8.4 Ctrl+C during password entry

**Steps:**
1. Run `$ACP_BIN plugins`
2. Press Ctrl+C at password prompt

**Expected:**
- Clean exit
- No partial state changes

---

## 9. Security Verification

### 9.1 Password not in process list

**Steps:**
1. Run `$ACP_BIN plugins` in one terminal
2. In another terminal, run `ps aux | grep acp`
3. Enter password in first terminal

**Expected:**
- Password never visible in process arguments

### 9.2 Password not in shell history

**Steps:**
1. Run various `acp` commands requiring password
2. Check shell history (`history` command)

**Expected:**
- Commands visible in history
- Passwords NOT visible in history

### 9.3 Credentials not readable by agent

**Steps (macOS):**
1. Set a credential via `acp set`
2. Attempt to read from Keychain directly:
   ```bash
   security find-generic-password -s "acp:credential:exa:apiKey" -w
   ```

**Expected:**
- Access denied (requires code signing match)

**Steps (Linux):**
1. Set a credential via `acp set`
2. As regular user, attempt to read `/var/lib/acp/secrets.json`

**Expected:**
- Permission denied (owned by `acp` user)

---

## Test Results Template

| Test | Status | Notes |
|------|--------|-------|
| 1.1 Status when server not running | | |
| 1.2 Status when server running | | |
| 2.1 First-time init | | |
| 2.2 Init with custom CA path | | |
| 2.3 Init password mismatch | | |
| 2.4 Re-init when already initialized | | |
| 3.1 List plugins (empty) | | |
| 3.2 Install bundled plugin | | |
| 3.3 List plugins (with plugin) | | |
| 3.4 Install GitHub plugin | | |
| 3.5 Uninstall plugin | | |
| 3.6 Install with wrong password | | |
| 4.1 Set credential | | |
| 4.2 Set credential for namespaced plugin | | |
| 4.3 Set credential for non-existent plugin | | |
| 4.4 Overwrite existing credential | | |
| 5.1 Create token | | |
| 5.2 List tokens | | |
| 5.3 Revoke token | | |
| 5.4 Create duplicate token name | | |
| 6.1 View activity (empty) | | |
| 6.2 View activity (with requests) | | |
| 6.3 Follow activity stream | | |
| 7.1 Specify server via flag | | |
| 7.2 Specify server via environment | | |
| 7.3 Flag overrides environment | | |
| 8.1 Invalid command | | |
| 8.2 Missing required argument | | |
| 8.3 Network error | | |
| 8.4 Ctrl+C during password entry | | |
| 9.1 Password not in process list | | |
| 9.2 Password not in shell history | | |
| 9.3 Credentials not readable by agent | | |
