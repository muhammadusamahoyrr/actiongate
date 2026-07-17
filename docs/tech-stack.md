# AI Control Plane — Final Technology Stack (V1)

Finalized at design Round 6. This is the buildable selection; architecture and rationale live in [plan.md](plan.md) (§20 for decisions, §1–19 for the design they serve).

---

## Core

| Layer | Selection | Notes |
|---|---|---|
| Language (both deployables) | **Go 1.24+** | Single static cross-compiled gateway binary; shared types across the grant-verification boundary |
| Database | **PostgreSQL 16+** | Tenant-homed per region; the only datastore in V1 |
| SQL access | **pgx v5 + sqlc** | Hand-written SQL (CAS, SKIP LOCKED, `ON CONFLICT`), compile-time checked; no ORM |
| Queue / workers / timers | **River** | The transactional outbox, worker leases, and timer subsystem in one library. Rule: `InsertTx()` inside the transition transaction only — the non-Tx insert is forbidden |
| Migrations | **Goose** | Versioned, transactional; River's migrations ship through the same path |
| Policy evaluation | **cel-go** | Condition evaluator inside an explicit ordered-rule structure (first-match, `matched_rule_id`). Re-evaluate Cedar when customers author policies directly |
| MCP | **Official Go MCP SDK** (`modelcontextprotocol/go-sdk`) | Fallback if gaps: `mark3labs/mcp-go` |
| Gateway | **Customer-side static Go binary** | InboundAdapter + ExecutionAdapter; executes only with a verified ExecutionGrant, local credentials never leave the customer |

## Protocol & Signing

| Layer | Selection | Notes |
|---|---|---|
| Gateway ↔ Control Plane | **ConnectRPC + Protobuf** (V1, not deferred) | Four unary RPCs: `Enroll`, `SubmitAction`, `GetActionStatus`, `ReportOutcome`. Plain HTTPS under the hood. Buf breaking-change detection in CI — the wire protocol is a permanent compatibility contract once customer gateways exist |
| Grant signing (hot path) | **Ed25519, in-process key** | Key sealed at rest via KMS envelope encryption; ~7-day rotation with overlap; detached signature over the exact serialized protobuf bytes. No KMS call per grant |
| Epoch signing (cold path) | **Direct KMS Sign** | ECDSA P-256 if the KMS lacks Ed25519. This is the "app can't forge history" boundary |
| Grant lifecycle | TTL ≤ 60 s, single-use | Enforced gateway-side (grant_id cache) and control-plane-side (duplicate-receipt rejection); control-plane clock authoritative |
| Audit chain hashing | **SHA-256 over a shared deterministic encoding** | One Go package (fixed field order, length-prefixed) used by Sealer and verifier. No JSON canonicalization on the chain |
| Fingerprinting | **RFC 8785 (JCS) canonical JSON** | For `request_fingerprint` only |
| Audit anchoring | **Deferred by decision** | `AnchorStore` interface + `anchored_at` field ship in V1 so enabling WORM anchoring (S3 Object Lock) later is config, not migration |

## Data & Isolation

| Layer | Selection | Notes |
|---|---|---|
| Tenant isolation | **tenant_id-first indexes + PostgreSQL RLS** | RLS policy on `app.tenant_id` GUC set per transaction — defense-in-depth against cross-tenant query bugs. No cross-tenant joins anywhere |
| IDs | **UUIDv7 via `google/uuid`**, app-generated | Index locality only — never an ordering guarantee (wall-clock skew); authoritative order is the Sealer-assigned sequence |
| Configuration | **koanf** (bootstrap config only) + **`ConfigurationSnapshot` table** | Snapshot table is INSERT-only with a `content_hash` per row, so `policy_version_evaluated` is verifiable against actual policy content |
| Schema discipline | Partition-ready from day one | Every unique constraint includes `tenant_id`; `action_state` narrow with `fillfactor=80`; partial indexes on hot states and unclaimed timers |

## Operations

| Layer | Selection | Notes |
|---|---|---|
| Logging | **slog** behind the `Logger` interface | |
| Metrics / tracing | **OpenTelemetry** behind `MetricsRecorder` / `Tracer` | Vendor-neutral, matching "no vendor names in business logic" |
| Notifications | **slack-go** behind `NotificationPort`; SMTP via std lib | Channel is delivery-only |
| Secrets | **Vault/KMS behind `CredentialProvider` interface** | Vendor-side credentials for SaaS-managed integrations only, in per-tenant runners |
| Testing | **Testcontainers-Go** | All SQL primitives (CAS, SKIP LOCKED, unique constraints, RLS) tested against real Postgres — never mocked |
| Release pipeline | **GoReleaser + Cosign + Syft + Trivy** | Cross-compiled signed binaries, KMS-backed signing, SBOM, vulnerability scan — signed artifacts are part of the product |
| Connection pooling | **pgxpool** per service | |

## Explicitly Rejected (do not re-add casually)

| Item | Reason |
|---|---|
| PgBouncer (V1) | Transaction-mode pooling breaks River's LISTEN/NOTIFY; pgxpool is sufficient at V1 scale |
| OpenFeature / runtime feature flags | A flag that changes enforcement behavior is an unaudited policy change; toggles must live inside `ConfigurationSnapshot` versioning |
| ORMs | The design's correctness lives in hand-written SQL |
| Temporal (V1) | Deferred backend behind the worker interfaces; Postgres + SKIP LOCKED is sufficient and keeps self-host to "one binary + Postgres + a signing key" |
| Cached allow-decisions in offline gateway | Offline gateway fails closed; offline tolerance is a future policy-semantics ADR, not an implementation shortcut |

## Performance Targets (SLOs)

| Metric | Target | Alert |
|---|---|---|
| Allow path submit→grant (server-side) | p50 ≤ 30 ms, p99 ≤ 150 ms | p99 breach sustained 5 min |
| Throughput per region/Postgres | 500 actions/s design point (~2k/s headroom before sharding) | queue-claim p99 > 1 s |
| Notification enqueue after decision | ≤ 1 s | — |
| Timer firing accuracy | within 5 s of `fire_at` | > 30 s drift |
| Sealer unsealed-tail age | 99% ≤ 30 s | page at 60 s |
| Bloat | `river_job` / `action_state` dead tuples < 20% | vacuum lag growing |

Pre-GA validation: load at 10× design point; chaos runs — kill workers mid-lease, kill the Sealer for 5 minutes, Postgres failover mid-transaction.

---

**Status: stack selection closed at Round 6.** Remaining choices are code-level and belong in pull requests, not design rounds.
