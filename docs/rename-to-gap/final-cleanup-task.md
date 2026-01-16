# Task: Final Comprehensive ACP → GAP Cleanup

## Objective
Fix ALL remaining acp/ACP references in active code and documentation.

## Context
Working directory: `/Users/mike/code/agent-credential-proxy`

Previous sweeps have fixed most references, but several files remain. This is the final cleanup to eliminate all acp/ACP references from the active codebase.

## Files with acp/ACP References

### Markdown documentation files (must fix):
1. `README.md` - multiple references
2. `docs/reference/architecture.md` - multiple references  
3. `docs/reference/types.md` - multiple references
4. `docs/reference/gotchas.md` - multiple references
5. `docs/smoke-tests/https-management-api.md` - MANY references (CLI commands, paths, versions)
6. `smoke-tests/cli.md` - keychain service names like "acp:credential:..."
7. `smoke-tests/e2e-proxy.md` - references
8. `smoke-tests/installation.md` - references

### Shell scripts (must fix):
1. `.env.local` - comment with acp binary names
2. `smoke-tests/run-e2e-proxy.sh`
3. `smoke-tests/test-docker.sh`
4. `smoke-tests/test-install.sh`
5. `smoke-tests/test-docker-integration.sh`
6. `smoke-tests/smoke-test.sh`
7. `scripts/macos-sign.sh`
8. `scripts/macos-notarize.sh`

### Binary/build artifacts (SKIP):
- `dist/acp-binaries.zip`
- `dist/acp-darwin-arm64.tar.gz`

### Historical/planning docs (SKIP):
- `DONE.md` - historical record
- `docs/rename-to-gap/*.md` - planning docs

## Replacement Rules

Apply these transformations consistently:

1. **Binary names:**
   - `acp` → `gap`
   - `acp-server` → `gap-server`
   - `acp-lib` → `gap-lib`

2. **Paths:**
   - `~/.config/acp` → `~/.config/gap`
   - `~/.local/share/acp` → `~/.local/share/gap`
   - `/tmp/acp-test-data` → `/tmp/gap-test-data`

3. **Keychain service names:**
   - `"acp:credential:..."` → `"gap:credential:..."`
   - `acp:` → `gap:` (as keychain prefix)

4. **Descriptive text:**
   - `ACP` → `GAP`
   - `Agent Credential Proxy` → `Gated Agent Proxy` or just `GAP`
   - `acp v0.2.2` → `gap v0.2.2` or just remove version

5. **Environment variables (already done in code, but may appear in docs):**
   - `ACP_*` → `GAP_*` (e.g., `ACP_TOKEN` → `GAP_TOKEN`)

6. **Log prefixes:**
   - `RUST_LOG=acp_server` → `RUST_LOG=gap_server`

7. **CA certificate paths:**
   - `~/.config/acp/ca.crt` → `~/.config/gap/ca.crt`

## Files to Work Through

Process each file systematically:

### Documentation Files
For each `.md` file, read and apply replacements:
- `README.md`
- `docs/reference/architecture.md`
- `docs/reference/types.md`
- `docs/reference/gotchas.md`
- `docs/smoke-tests/https-management-api.md` (this has the most - ~50+ references)
- `smoke-tests/cli.md`
- `smoke-tests/e2e-proxy.md`
- `smoke-tests/installation.md`

### Shell Scripts
For each `.sh` file and `.env*` file:
- `.env.local`
- `smoke-tests/run-e2e-proxy.sh`
- `smoke-tests/test-docker.sh`
- `smoke-tests/test-install.sh`
- `smoke-tests/test-docker-integration.sh`
- `smoke-tests/smoke-test.sh`
- `scripts/macos-sign.sh`
- `scripts/macos-notarize.sh`

## Verification

After all edits:
1. Run comprehensive grep to verify no acp/ACP remains:
   ```bash
   grep -ri "acp" /Users/mike/code/agent-credential-proxy \
     --exclude-dir=.git \
     --exclude-dir=target \
     --exclude-dir=docs/rename-to-gap \
     --exclude="DONE.md" \
     --exclude-dir=dist
   ```
   Expected: No matches (or only matches in binary files we skip)

2. Run tests to ensure nothing broke:
   ```bash
   cargo test
   ```
   Expected: All tests pass

## Success Criteria
- All active documentation and scripts updated
- No remaining acp/ACP references in active code/docs (excluding skipped files)
- All tests pass
- Changes committed

## Notes
- Use the Edit tool for each file (Read first, then Edit)
- Be thorough but surgical - don't change historical records or planning docs
- This is the FINAL cleanup - make it comprehensive
