# Horizontal Mode Spec: Shared PostgreSQL

## Purpose

Define GAP's **horizontal mode**: multiple GAP replicas sharing one PostgreSQL state store.

This is GAP-specific and deploys from GAP's own compose/manifests.

## Mode Definition

### Single mode (existing)

- One GAP process.
- Local libSQL/SQLite file (`gap.db`) in `data_dir`.
- File-level DB encryption via libSQL key.
- In-memory runtime caches are process-local.

### Horizontal mode (new)

- Two or more GAP replicas behind a load balancer.
- Shared PostgreSQL store for authoritative state.
- No correctness dependency on process-local caches.
- Any request can hit any replica and still behave consistently.

## What Must Be Shared Across Replicas

- Token lifecycle state (create/revoke/scope checks)
- Plugin/header/credential configuration
- Replay-protection nonce state
- Activity and management logs
- Bootstrap/config state that affects behavior

## Storage and Consistency Model

### Authoritative state: PostgreSQL

Postgres stores durable management and policy state:

- tokens / token scopes
- plugin versions
- credentials
- header sets
- activity and management logs
- request details
- password hash and bootstrap metadata

### Replay protection: PostgreSQL (v1)

Use a nonce table with unique constraints:

- table: `used_nonces`
- key: `(namespace_id, scope_id, key_id, nonce_hash)` unique
- columns include `created_at`, `expires_at`
- verification path uses atomic insert-once semantics (`INSERT ... ON CONFLICT DO NOTHING`)
- scheduled cleanup removes expired rows

This avoids cross-replica replay without adding Redis in this phase.

### Phase 0 cache policy (explicitly no auth cache)

In horizontal mode phase 0, correctness comes directly from Postgres with no process-local auth cache:

- Disable `TokenCache` for token/authz decisions.
- Disable in-memory `NonceCache` for replay decisions.
- Token checks read from Postgres on each request.
- Replay checks use Postgres nonce storage (`used_nonces`) only.

### Caches that remain enabled

- TLS certificate cache remains enabled (performance-only, not auth correctness).
- Plugin runtime behavior remains request-scoped with DB-backed plugin/credential reads.

### Future optimization pattern (phase 1+ if needed)

If metrics show Postgres lookup bottlenecks, introduce L1 token cache later using:

- cache-aside/read-through per process
- soft/hard TTL with bounded staleness
- DB-backed invalidation log tailing (`authz_events`)
- per-key singleflight/stampede protection

## Data Protection Assumptions in Horizontal Mode

Horizontal mode changes where "encryption at rest" is provided.

In single mode, libSQL file encryption protects local `gap.db`.
In horizontal mode, data-at-rest protection is provided by the Postgres deployment/platform instead.

### Phase 0 security model

1. GAP does not add per-field application-layer encryption for Postgres in phase 0.
2. Postgres/storage platform must provide encryption at rest (including backups/snapshots).
3. GAP-to-Postgres traffic must use TLS in non-local environments.
4. GAP must use dedicated DB identity/scope (least privilege).

### Security consequence (explicit)

- Secret handling is shifted from GAP's local DB encryption to infrastructure controls.
- This means DB admins/backup readers can access plaintext values unless app-layer encryption is added later.

### Sensitive persisted fields (awareness)

- credential values
- CA private key material stored in config
- any other persisted private key material

## Configuration Shape

Suggested mode switch:

- `GAP_DEPLOYMENT_MODE=single|horizontal`

Horizontal mode requires:

- `GAP_STATE_STORE=postgres`
- `GAP_POSTGRES_URL` (or host/port/user/password/database)
- `GAP_POSTGRES_SCHEMA` (default `gap`)
- `GAP_POSTGRES_POOL_MAX`, `GAP_POSTGRES_POOL_MIN`
- `GAP_POSTGRES_SSLMODE`
- `GAP_TOKEN_CACHE_MODE=off` (phase 0 default in horizontal mode)
- `GAP_NONCE_STORE=postgres`

## Phased Delivery

### Phase 0: local compose parity (required now)

Goal: one GAP container running in **horizontal mode** against Postgres.

Deliverables:

- Add Postgres service to GAP compose profile.
- GAP wired for `GAP_DEPLOYMENT_MODE=horizontal` + `GAP_STATE_STORE=postgres`.
- Startup fails if required horizontal-mode env vars are missing.
- Horizontal mode explicitly disables single-mode auth caches (`TokenCache`, in-memory `NonceCache`).
- Smoke test: create token/plugin/credential/header, restart GAP, verify persistence.
- Replay test: first signed nonce accepted, replayed nonce rejected.
- Security baseline check: Postgres TLS + DB-role isolation configured; infra encryption-at-rest assumption documented.
- No-cache correctness test: repeated requests and revoke flows are correct without in-memory auth cache.

### Phase 1: local multi-replica correctness

Goal: two GAP replicas in horizontal mode with shared Postgres.

Deliverables:

- Replica-aware GAP compose setup (2 `gap-server` instances + simple local LB or direct per-replica ports).
- Cross-replica tests:
  - token created via replica A works via replica B
  - token revoked via A is rejected via B
  - nonce used on A is rejected on B
  - logs from both replicas are visible via shared API queries

### Phase 2: operational hardening

Goal: production readiness.

Deliverables:

- runbook for Postgres outage/failover
- backup/restore procedure for GAP Postgres data
- metrics and alerts (DB pool saturation, slow queries, replay failures)
- migration/rollback procedure documentation
- data security runbook (DB access controls, TLS, encryption-at-rest expectations)

## Acceptance Criteria

1. GAP can run in explicit horizontal mode with Postgres and no local `gap.db` dependency for correctness.
2. Replay protection is correct across replicas using Postgres-only nonce storage.
3. Horizontal mode phase 0 clearly relies on Postgres/platform encryption-at-rest + TLS (not GAP field encryption).
4. Existing single mode (libSQL) remains supported.
5. Multi-replica compose tests demonstrate consistent behavior.
6. Horizontal mode phase 0 runs with `TokenCache` and in-memory `NonceCache` disabled.

## Deferred

1. Log offload to OpenSearch/ClickHouse can be evaluated after initial rollout.
