# Project Kanban

## Doing
<!-- Currently being worked on -->
<!-- Auth exclusivity + management-go + signing E2E completed 2026-02-26 → DONE.md -->

## Ready
<!-- Designed + planned, can be picked up -->

### Rich request/response logging in activity
Each activity entry should capture three phases with headers (YAML-style) and body (truncated):
1. **Incoming request** — pre-transform headers + body as received from the client
2. **Transformed request** — post-transform headers + body sent to upstream (credentials scrubbed in display)
3. **Origin response** — status, headers, body returned by the upstream

**Storage:** Bodies can be large — need a truncation/cap strategy (e.g., store first N bytes, configurable). Consider separate `request_bodies` table to keep `access_logs` lean.

**Rejected requests:** Record requests that fail at each pipeline stage — not just successful proxied requests. Each entry should capture the rejection stage and reason:
- No auth token / invalid token
- No matching plugin (host not allowed)
- Missing credentials (plugin matched but unconfigured)
- HTTP blocked (`dangerously_permit_http` not set)
- Upstream error (TLS failure, timeout, connection refused)

This is critical for security auditing (rogue agent detection, unauthorized host access attempts) and debugging (why isn't my request going through?).

**macOS app UI:** Activity detail view with three collapsible sections. Headers in YAML-style key: value format. Body truncated to reasonable length with "Show full" expand button. Rejected requests should be visually distinct (e.g., red/orange status indicator) with the rejection reason prominently displayed.

### Store CA certs in database for audit trail
CA certs are currently only exported to disk (`~/Library/Application Support/gap/ca.crt`). Multiple server instances overwrite each other's cert at the same path. Store CA cert history in the database (append-only, like plugin_versions) so there's a full audit trail of every CA cert ever generated. Disk export remains for client consumption but the DB becomes the source of truth.

### Prevent multiple server instances / stale CA conflicts
On startup, if a CA cert already exists on disk, verify its private key matches the one in the database. If it doesn't match (another instance wrote a different CA), log a clear error and refuse to launch. This catches the multi-instance problem at the source — no lockfile needed, just a crypto check.

