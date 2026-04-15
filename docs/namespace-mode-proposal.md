# Namespace Mode and Scope Model for GAP

## Goal

Add namespace support without introducing split runtime behavior.

## Core Decision

Use one internal operating model for all deployments:

- Every management request resolves to an effective `(namespace_id, scope_id)`.
- If values are omitted, resolve to `"default"` / `"default"`.
- Store and enforce all policy state on that resolved tuple.

This keeps legacy compatibility while enabling strict namespace operation.

## Modes

### 1) Single-namespace mode (legacy-compatible)

- Existing API shape remains valid (no namespace/scope in path).
- Omitted namespace and scope transparently resolve to defaults.
- Behavior for existing users remains unchanged.

### 2) Namespace mode (strict)

- Canonical management API requires explicit namespace and scope.
- Unscoped management calls are rejected.
- Prevents accidental writes to implicit defaults in multi-namespace operation.

## API Contract

### Canonical (namespace mode)

```text
GET    /namespaces/{namespaceId}
POST   /namespaces/{namespaceId}/scopes/{scopeId}/tokens
POST   /namespaces/{namespaceId}/scopes/{scopeId}/plugins
PATCH  /namespaces/{namespaceId}/scopes/{scopeId}/plugins/{pluginId}/credentials
POST   /namespaces/{namespaceId}/scopes/{scopeId}/headers
```

### Compatibility aliases (single-namespace mode)

Legacy endpoints are mapped to canonical handlers with:

- `namespace_id = "default"`
- `scope_id = "default"`

The important implementation rule is: aliases and canonical routes must share the same handler path after resolution.

## Data Model Rule

All management state is keyed by `(namespace_id, scope_id, resource...)`.

No special-case tables or code paths for legacy mode.

## Security and Observability

- Management logs should always include resolved `namespace_id` and `scope_id` (including defaults).
- If request signing is enabled, canonical signature input should include resolved namespace and scope context.
- Namespace mode should fail closed on missing namespace/scope.

## Why This Shape

- Preserves backward compatibility.
- Avoids dual behavior and drift in enforcement logic.
- Makes strict namespace operation a configuration choice, not a forked architecture.
