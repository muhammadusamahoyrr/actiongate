# actiongate

Out-of-process action firewall for coding agents (Claude Code / Cursor / Codex).
The control plane decides and records; the customer-side gateway executes with
local credentials, only ever under a signed ExecutionGrant.

Architecture and all design decisions: [docs/plan.md](docs/plan.md) (frozen
at Round 8). Stack rationale: [docs/tech-stack.md](docs/tech-stack.md).
Verification log: [VERIFICATION.md](VERIFICATION.md).

## Layout

```
proto/actiongate/v1/    Gateway <-> control-plane wire contract (4 unary RPCs).
                        The signature scheme signs serialized bytes exactly as
                        sent — see GrantEnvelope / ReceiptEnvelope.
migrations/             Goose migrations: core schema, append-only guards, RLS.
                        River's own tables: `river migrate-up` (see Makefile).
internal/domain/        States, transition table (plan §7), audit event
                        vocabulary (plan §5).
internal/transition/    THE transition primitive (plan §20.2.1): one Postgres
                        transaction = state CAS + audit append + effects.
                        Tested against real Postgres via Testcontainers.
internal/auditenc/      Deterministic event encoding + SHA-256 chaining, shared
                        by the Sealer and every verifier (plan §20.2.3). This
                        package is the published chain spec's reference impl.
internal/db/queries/    sqlc query sources.
cmd/controlplane/       Control-plane service (policy, approvals, audit, workers).
cmd/gateway/            Customer-side binary (MCP proxy + execution + hooks).
cmd/verify/             Standalone offline audit-chain verifier (also the WASM
                        build target later — plan §22).
```

## Prerequisites

Go 1.25+, Docker (for Testcontainers), `buf`, `goose`, `river` CLI, `sqlc`.

## First commands

```
make tidy       # resolve module graph
make test       # spins real Postgres in Docker, runs the transition suite
make proto      # buf generate (ConnectRPC + protobuf stubs into gen/)
make migrate    # goose up against $DATABASE_URL
make river      # river migrate-up against $DATABASE_URL
```

## Module name

The module is intentionally bare (`actiongate`) until a public home is chosen;
rename in `go.mod` + imports when publishing (recommended license: Apache-2.0,
plan §21.4).

## Implementation order (from plan Round 6/7)

1. `internal/transition` — green tests (this skeleton ships the suite).
2. Idempotent create path (`INSERT … ON CONFLICT DO NOTHING RETURNING` +
   fingerprint check, plan §8).
3. PolicyEngine (cel-go conditions inside ordered rule structure) + evaluation
   trace.
4. River workers: ExecutionCoordinator (grants), Notification (Slack), Timer.
5. Sealer with the snapshot-horizon watermark (plan §20.2.2 — do not simplify).
6. Gateway: enroll, MCP proxy auto-wrap, grant verification, receipts.
