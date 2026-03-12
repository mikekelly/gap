# Horizontal Mode: Handoff Document

## Current State

### What we were working on
Implementing Phase 0 of the horizontal mode spec (`docs/horizontal-mode-postgres-spec.md`): a single GAP container running against PostgreSQL with auth caches disabled, proving correctness before multi-replica testing.

### Where we are
**Phase 0 is COMPLETE.** All 6 implementation phases shipped and tested. `bin/all-tests` passes (cargo workspace tests + Docker horizontal smoke tests). The work is ready to move from "Doing" to "Done" on the kanban board and the DONE.md entry should be written.

### Codebase state
Working. All 131 cargo tests pass. Docker horizontal smoke tests (14 tests, 21 assertions) pass. No known regressions.

## What's Been Done

### Implementation Phases (all complete)

| Phase | Commit | Description |
|-------|--------|-------------|
| 1 | `fff0206` | Restructure GapDatabase to `DbBackend` enum dispatch (LibSql variant only) |
| 2+3 | `492346f` | Add sqlx dependency, Postgres DDL schema, all ~40 query method implementations |
| 4 | `6659fa3` | Wire `DeploymentMode` enum, Postgres config parsing, `TokenCache::new_disabled()` |
| 5 | `ad0b613` | `NonceStore` enum (InMemory/Postgres), async `verify_request_signature`, nonce DB methods |
| 6 | `6bbdfe3` | Docker Compose horizontal profile, smoke test script |
| Fix | `5ee821e` | `bin/all-tests` script, fix plugin delete assertion in smoke test |

### Key Architecture Decisions

1. **Enum dispatch, not trait**: `DbBackend::LibSql | DbBackend::Postgres` inside `GapDatabase`. Zero consumer changes — every caller keeps using `Arc<GapDatabase>`. No boxing overhead. There will never be a third backend.

2. **Postgres implementations in separate module**: `database_postgres.rs` (~850 lines) contains all `pg_*()` functions. `database.rs` dispatches via match arms. This keeps the already-large `database.rs` manageable.

3. **NonceStore enum pattern**: Same enum dispatch as DbBackend — `NonceStore::InMemory(NonceCache) | Postgres { db }`. The `verify_request_signature` function became async to support Postgres nonce checks. Fails closed (treats as replay) if Postgres is unreachable.

4. **TokenCache disabled flag**: `TokenCache::new_disabled()` makes all cache operations no-ops. In horizontal mode, every token check hits Postgres directly.

5. **sqlx crate**: `sqlx` with `runtime-tokio`, `postgres`, `chrono` features. Raw SQL (no ORM), built-in connection pool (`PgPool`).

### Files Created or Modified

**New files:**
- `gap-lib/src/database_postgres.rs` — All Postgres method implementations + DDL schema
- `smoke-tests/test-docker-horizontal.sh` — 14-test horizontal smoke test
- `bin/all-tests` — Runs cargo tests + Docker horizontal smoke tests

**Modified files:**
- `gap-lib/src/database.rs` — `DbBackend` enum, dispatch arms on all ~40 methods, `open_postgres()` constructor, `check_nonce()`/`cleanup_nonces()` methods
- `gap-lib/src/lib.rs` — Added `pub mod database_postgres`
- `gap-lib/Cargo.toml` — Added sqlx, testcontainers dev-deps
- `gap-lib/src/proxy.rs` — `TokenCache` `disabled` field + `new_disabled()`
- `gap-server/src/main.rs` — `DeploymentMode` enum, deployment mode wiring, conditional DB/cache/nonce construction
- `gap-server/src/signing.rs` — `NonceStore` enum, async `verify_request_signature`
- `gap-server/src/api.rs` — `nonce_store` field (was `nonce_cache`), async signing call
- `docker-compose.yml` — postgres, gap-server-horizontal, test-runner-horizontal services

### Environment Variables (horizontal mode)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GAP_DEPLOYMENT_MODE` | Yes | `single` | Set to `horizontal` |
| `GAP_STATE_STORE` | Yes (horizontal) | — | Must be `postgres` |
| `GAP_POSTGRES_URL` | Yes (horizontal) | — | Postgres connection URL |
| `GAP_POSTGRES_SCHEMA` | No | `gap` | Schema name |
| `GAP_POSTGRES_POOL_MAX` | No | `20` | Max pool connections |
| `GAP_POSTGRES_POOL_MIN` | No | `2` | Min pool connections |

### Test Suite

- **Cargo**: 131 passed, 0 failed, 1 ignored (~12s)
- **Docker horizontal**: 14 tests, 21 assertions — health, CRUD, persistence, revocation, management log, cleanup
- **Run all**: `bin/all-tests` (or `bin/all-tests cargo` / `bin/all-tests docker`)

## What's Pending

### Immediate TODO (housekeeping)
1. **Move kanban card**: "Horizontal mode with shared PostgreSQL" should move from Ready to Done
2. **Write DONE.md entry**: Document what was shipped (similar to existing entries)
3. **KANBAN_BOARD.md has uncommitted changes**: Just the kanban board — no code changes pending

### Not Yet Done (Future Phases from the spec)

**Phase 1: Local multi-replica correctness** (spec section "Phase 1"):
- Two GAP replicas in horizontal mode with shared Postgres
- Cross-replica tests: token created on A works on B, revoked on A rejected on B, nonce used on A rejected on B
- Needs compose setup with 2 gap-server instances + load balancer or direct per-replica ports

**Phase 2: Operational hardening** (spec section "Phase 2"):
- Runbook for Postgres outage/failover
- Backup/restore procedures
- Metrics and alerts (pool saturation, slow queries, replay failures)
- Migration/rollback documentation

### Known Issues
- **No Postgres integration tests via testcontainers**: The plan included testcontainers-based Rust integration tests for Postgres methods. These weren't written — correctness is currently validated by the Docker smoke tests only. Adding Rust-level Postgres integration tests would improve confidence.
- **Nonce scoping uses defaults**: `verify_request_signature` passes `"default"/"default"` for namespace/scope to the nonce store. In namespace mode, nonces should ideally be scoped per namespace/scope. This is fine for Phase 0 since keyid already prevents cross-key collisions.
- **No `GAP_POSTGRES_SSLMODE` support**: The spec mentions this env var but it wasn't implemented. The `GAP_POSTGRES_URL` can include `?sslmode=require` as a query parameter, so it's not strictly needed.

## Context for Next Agent

### Key Files to Read
- `docs/horizontal-mode-postgres-spec.md` — The full spec (Phases 0-2)
- `gap-lib/src/database.rs` — Core file, ~3500 lines, has `DbBackend` enum + all dispatch
- `gap-lib/src/database_postgres.rs` — All Postgres implementations
- `gap-server/src/main.rs` — Deployment mode wiring (lines 20-31, 274-382)
- `gap-server/src/signing.rs` — `NonceStore` enum
- `docker-compose.yml` — Horizontal profile services
- `KANBAN_BOARD.md` — Project tracking

### Gotchas
- `database.rs` is ~3500 lines — agents run out of context reading it. Scope tightly, use line ranges.
- `pool()` on `GapDatabase` is `pub` (was `pub(crate)`, changed for nonce store access from gap-server).
- `conn()` and `pool()` panic if called on the wrong backend variant — this is intentional.
- Methods that delegate to other public methods (e.g., `set_password_hash` calls `set_config`) were NOT wrapped with dispatch arms since they already dispatch through the inner call.
- The Docker horizontal test doesn't use a volume mount for `/var/lib/gap` — `GAP_ALLOW_EPHEMERAL` bypasses the entrypoint check.

### User Preferences
- Delegate to agents per CLAUDE.md — orchestrate, don't implement directly
- All agents should use `model: opus` for this project
- User prefers scripts at `bin/` not project root
- Keep KANBAN_BOARD.md and DONE.md updated

## Open Questions
None blocking. Phase 0 is complete. The user can decide when/whether to pursue Phase 1 (multi-replica) and Phase 2 (operational hardening).
