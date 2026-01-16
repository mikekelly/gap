# Task: Comprehensive ACP → GAP Cleanup

## Objective
Fix ALL remaining acp/ACP references found in active code and documentation (excluding planning docs in docs/rename-to-gap/).

## Working Directory
`/Users/mike/code/agent-credential-proxy`

## Files to Fix

### 1. Variable/Function Names
- **gap-server/src/launchd.rs**
  - Line with `let acp_dir = get_gap_dir();` → rename variable to `gap_dir` (4 occurrences)
  - Test name `test_get_log_dir_returns_acp_logs` → `test_get_log_dir_returns_gap_logs`

### 2. Public Type Names (IMPORTANT - Breaking Change)
These are public API types used throughout the codebase:
- **gap-lib/src/types.rs**
  - `ACPRequest` → `GAPRequest` (struct + impl)
  - `ACPCredentials` → `GAPCredentials` (struct + impl)
  - `ACPPlugin` → `GAPPlugin` (struct + impl)

**Propagate type renames** to all files that use these types:
- gap-lib/src/lib.rs (pub use statement)
- gap-lib/src/proxy_transforms.rs
- gap-lib/src/plugin_matcher.rs
- gap-lib/src/plugin_runtime.rs (many occurrences)
- gap-lib/src/http_utils.rs
- gap-server/src/api.rs
- All test files using these types

### 3. Comments and Strings
- **Cargo.toml**: `authors = ["Agent Credential Proxy Contributors"]` → `["GAP Contributors"]`
- **gap/src/main.rs**:
  - Comment `//! ACP CLI - Agent Credential Proxy command-line interface` → `//! GAP CLI - Gated Agent Proxy command-line interface`
  - `about = "Agent Credential Proxy CLI"` → `about = "GAP CLI"`
- **gap-lib/src/types.rs**: `//! Core types for the Agent Credential Proxy` → `//! Core types for GAP`
- **gap-lib/src/error.rs**: `//! Error types for the Agent Credential Proxy` → `//! Error types for GAP`
- **gap-lib/src/lib.rs**: `/// Agent Credential Proxy - Shared Library` → `/// GAP - Shared Library`
- **gap-lib/src/tls.rs**: `"Agent Credential Proxy"` in DN fields (2 occurrences) → `"GAP"`
- **gap-lib/tests/README.md**: `Agent Credential Proxy system` → `GAP system`

### 4. Documentation Files
- **docs/native-app-design.md**: `Description=Agent Credential Proxy` → `Description=GAP`
- **docs/reference/architecture.md**: `ACP (Agent Credential Proxy)` → `GAP (Gated Agent Proxy)`

### 5. Install Script
- **install.sh**: Look for "ACP Installation Script" help text → "GAP Installation Script"
- **smoke-tests/test-install.sh**: Update the grep check for "ACP Installation Script" → "GAP Installation Script"

### 6. URLs (Keep as-is)
Do NOT change:
- GitHub repository URLs containing "agent-credential-proxy" (e.g., in Cargo.toml, install.sh)
- These reflect the actual repo name which hasn't changed

### 7. Skip These (Planning Docs)
- Everything in `docs/rename-to-gap/` - these are planning materials
- `DONE.md` - historical record

## Implementation Approach

1. **Start with type renames** - these are the most pervasive:
   - Rename struct definitions in gap-lib/src/types.rs
   - Update all references throughout codebase
   - Use replace_all=true for these

2. **Then variable/function names** - localized changes

3. **Then comments/strings** - cosmetic but important

4. **Run `cargo test` after each phase** to catch issues early

5. **Commit all changes** when tests pass

## Success Criteria
- All active code/docs updated (excluding planning docs and git history)
- `cargo test` passes
- All changes committed

## Notes
- The type renames (ACPRequest → GAPRequest, etc.) are breaking changes to the public API
- This is fine since the project is not yet at 1.0
- Be systematic - grep for each type name to ensure you get all occurrences
