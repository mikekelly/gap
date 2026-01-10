# Registry Refactor Plan

## Problem

The `SecretStore` trait currently has a `list(prefix)` method that enumerates all keys matching a prefix. This works for `FileStore` (directory listing) but fails for `KeychainStore` because macOS's security-framework crate doesn't easily expose `SecItemCopyMatching` for enumeration.

**Current behavior:**
- `FileStore.list()` — works correctly
- `KeychainStore.list()` — returns empty vec (stub)

**Impact:** On macOS with Keychain storage, these commands return empty results:
- `acp token list`
- `acp plugin list`
- `acp credential list`

The proxy still works (it loads by exact key), but management operations are broken.

## Solution

Introduce a **centralized registry** stored as a single item in `SecretStore`. The registry is the authoritative record of what tokens, plugins, and credentials exist. Listing operations read from the registry instead of enumerating storage keys.

```
SecretStore contents:
├── _registry              ← JSON manifest (authoritative list)
├── token:abc123           ← token value
├── token:def456           ← token value
├── plugin:exa             ← plugin JS code
├── credential:exa:api_key ← credential value
└── ...
```

## Design

### Registry Structure

Stored at key `_registry` as JSON:

```json
{
  "version": 1,
  "tokens": [
    {
      "id": "abc123",
      "name": "my-agent",
      "created_at": "2024-01-15T10:30:00Z",
      "prefix": "acp_abc123"
    }
  ],
  "plugins": [
    {
      "name": "exa",
      "hosts": ["api.exa.ai"],
      "credential_schema": ["api_key"]
    }
  ],
  "credentials": [
    {
      "plugin": "exa",
      "field": "api_key"
    }
  ]
}
```

### Operations

| Operation | Current | After Refactor |
|-----------|---------|----------------|
| List tokens | `store.list("token:")` | Read `_registry`, return `tokens` |
| List plugins | `store.list("plugin:")` | Read `_registry`, return `plugins` |
| List credentials | `store.list("credential:")` | Read `_registry`, return `credentials` |
| Create token | `store.set(key, value)` | `store.set(key, value)` then update `_registry` |
| Delete token | `store.delete(key)` | `store.delete(key)` then update `_registry` |
| Get token value | `store.get(key)` | `store.get(key)` — unchanged |
| Proxy credential lookup | `store.get(key)` | `store.get(key)` — unchanged |

### SecretStore Trait Changes

Remove the `list()` method entirely:

```rust
// Before
#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, AcpError>;
    async fn set(&self, key: &str, value: &str) -> Result<(), AcpError>;
    async fn delete(&self, key: &str) -> Result<(), AcpError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, AcpError>;  // REMOVE
}

// After
#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<String>, AcpError>;
    async fn set(&self, key: &str, value: &str) -> Result<(), AcpError>;
    async fn delete(&self, key: &str) -> Result<(), AcpError>;
}
```

### Registry Manager

New struct to handle registry operations:

```rust
pub struct Registry {
    store: Arc<dyn SecretStore>,
}

impl Registry {
    const KEY: &'static str = "_registry";

    pub async fn load(&self) -> Result<RegistryData, AcpError>;
    pub async fn save(&self, data: &RegistryData) -> Result<(), AcpError>;

    // Token operations
    pub async fn add_token(&self, token: &TokenEntry) -> Result<(), AcpError>;
    pub async fn remove_token(&self, id: &str) -> Result<(), AcpError>;
    pub async fn list_tokens(&self) -> Result<Vec<TokenEntry>, AcpError>;

    // Plugin operations
    pub async fn add_plugin(&self, plugin: &PluginEntry) -> Result<(), AcpError>;
    pub async fn remove_plugin(&self, name: &str) -> Result<(), AcpError>;
    pub async fn list_plugins(&self) -> Result<Vec<PluginEntry>, AcpError>;

    // Credential operations
    pub async fn add_credential(&self, cred: &CredentialEntry) -> Result<(), AcpError>;
    pub async fn remove_credential(&self, plugin: &str, field: &str) -> Result<(), AcpError>;
    pub async fn list_credentials(&self) -> Result<Vec<CredentialEntry>, AcpError>;
}
```

### Concurrency

Registry updates must be atomic to prevent races:

1. Read current registry
2. Modify in memory
3. Write back

For single-server deployment (current architecture), this is fine. If multi-process access is needed later, add optimistic locking via a version field.

## Implementation Phases

### Phase 1: Add Registry Infrastructure

1. Create `RegistryData` struct and JSON serialization in `acp-lib`
2. Create `Registry` struct with load/save methods
3. Add registry initialization to server startup (create empty if missing)
4. Add unit tests for Registry operations

**Files:**
- `acp-lib/src/registry.rs` (new)
- `acp-lib/src/lib.rs` (export Registry)

### Phase 2: Migrate Management API

1. Add `Registry` to `ApiState`
2. Update token endpoints to use Registry for listing, update registry on create/delete
3. Update plugin endpoints similarly
4. Update credential endpoints similarly
5. Remove calls to `store.list()` from API handlers

**Files:**
- `acp-server/src/api.rs`
- `acp-server/src/main.rs`

### Phase 3: Migrate Proxy

1. Update `load_plugin_credentials()` in proxy to use registry for plugin lookup
2. Verify proxy still works with exact-key lookups

**Files:**
- `acp-server/src/proxy_transforms.rs`

### Phase 4: Remove list() from SecretStore

1. Remove `list()` from `SecretStore` trait
2. Remove `list()` implementations from `FileStore` and `KeychainStore`
3. Update any remaining callers
4. Update tests

**Files:**
- `acp-lib/src/secret_store.rs`
- `acp-lib/src/file_store.rs`
- `acp-lib/src/keychain_store.rs`

### Phase 5: Migration for Existing Installations

For users with existing data (secrets but no registry):

1. On startup, if `_registry` doesn't exist but other keys do, build registry from existing keys
2. Use `FileStore.list()` internally just for migration (keep private method)
3. Or: require fresh init, document in release notes

Recommend option 1 for smooth upgrades.

## Testing

1. **Unit tests:** Registry CRUD operations
2. **Integration tests:** API endpoints return correct data from registry
3. **E2E tests:** Full flow with KeychainStore on macOS
4. **Migration test:** Existing FileStore data gets registry created

## Acceptance Criteria

- [ ] `acp token list` works identically on macOS (Keychain) and Linux (FileStore)
- [ ] `acp plugin list` works identically on both platforms
- [ ] `acp credential list` works identically on both platforms
- [ ] Proxy credential injection still works
- [ ] `SecretStore` trait no longer has `list()` method
- [ ] Existing installations migrate smoothly

## References

- `AGENT_ORIENTATION.md` — Current architecture overview
- `acp-lib/src/secret_store.rs` — SecretStore trait definition
- `acp-lib/src/keychain_store.rs` — KeychainStore implementation (see list() stub)
- `acp-server/src/api.rs` — Management API handlers
