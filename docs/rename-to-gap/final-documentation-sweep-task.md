# Task: Final Documentation Sweep for ACP → GAP Rename

## Context
We're completing the rename from "Agent Credential Proxy (ACP)" to "GAP (Generic Agent Proxy)". Phases 1-5 are complete. This is the final cleanup phase.

## Objective
Update all documentation and eliminate remaining ACP references from active code and docs.

## Success Criteria
1. All documentation files updated with GAP naming
2. No remaining ACP references in active code/docs (excluding docs/rename-to-gap/ planning materials)
3. All tests pass: `cargo test`
4. Changes committed

## Specific Tasks

### 1. README.md
- Update title from "Agent Credential Proxy (ACP)" to "GAP (Generic Agent Proxy)"
- Update all command examples (acp → gap, acp-server → gap-server)
- Update all references to ACP in prose
- Update brew tap references
- Update docker image references
- Update all paths containing "acp" (e.g., ~/.config/acp → ~/.config/gap)
- Update environment variables (ACP_TOKEN → GAP_TOKEN, etc.)

### 2. AGENT_ORIENTATION.md
- Line 4: "ACP injects stored credentials" → "GAP injects stored credentials"
- Line 51: Update `ACPRequest`, `ACPCredentials`, `ACPPlugin` type names

### 3. Documentation Files
Review and update all files in docs/ directory:
- docs/macos-distribution.md
- docs/native-app-design.md
- docs/token-plugin-simplification/plan.md
- docs/reference/types.md
- docs/reference/architecture.md
- docs/reference/gotchas.md
- docs/smoke-tests/https-management-api.md
- docs/macos-improvements/macos-gui-plan.md
- docs/macos-improvements/macos-gui-implementation-plan.md

**Exclude:** docs/rename-to-gap/ (historical planning context)

### 4. Comprehensive Sweep
Run grep to find ALL remaining ACP references:
```bash
grep -ri "acp" \
  --include="*.md" \
  --include="*.rs" \
  --include="*.swift" \
  --include="*.sh" \
  --include="*.yml" \
  --include="*.yaml" \
  --include="*.json" \
  --include="*.toml" \
  /Users/mike/code/agent-credential-proxy
```

Review each match:
- **Update** if it's an active reference (variable names, comments, prose)
- **Skip** if it's in:
  - docs/rename-to-gap/ (planning materials)
  - target/ (build artifacts)
  - .git/ (history)
  - Cargo.lock (generated)
  - Comments explaining the rename itself

### 5. Verification
```bash
cd /Users/mike/code/agent-credential-proxy
cargo test
```

### 6. Commit
Commit all changes with message describing the documentation sweep.

## Notes
- Be systematic: work through files in order
- Check both prose and code examples
- Environment variables should be uppercase (GAP_TOKEN, GAP_DATA_DIR, etc.)
- Binary names are lowercase (gap, gap-server)
- The project should feel like it was always called GAP, not like it was renamed
