# Foundation Verification Report

Date: 2026-07-17. Scope: reproducible green build of the repo skeleton — no
feature work. All commands below were executed natively (no Docker-in-Docker)
and re-run to green after fixes.

## Environment

| Component | Version |
|---|---|
| OS | Windows 11 Pro (10.0.26200) |
| Go | go1.26.5 windows/amd64 (native install; module requires go >= 1.25.0) |
| Docker | Docker Desktop 29.3.1 (required by Testcontainers) |
| gcc | MinGW-W64 16.1.0 (WinLibs, UCRT/POSIX) — required for `-race` on Windows (CGO) |
| make | GNU make (ezwinports) |
| golangci-lint | 2.12.2 |
| buf / sqlc | not installed natively — executed via official images `bufbuild/buf` and `sqlc/sqlc` |

## Commands and results

| Command | Result |
|---|---|
| `go version` | `go version go1.26.5 windows/amd64` |
| `make tidy` (`go mod tidy`) | PASS (exit 0) |
| `make test` (`go test ./... -count=1`) | **PASS** — `ok actiongate/internal/transition 18.1s`; real `postgres:16-alpine` spawned by Testcontainers |
| `go test ./... -count=1 -v` | **PASS** — all 6 transition subtests + all 6 auditenc tests |
| `go test -race ./... -count=1 -cover` | **PASS** — `auditenc 74.3%`, `transition 73.8%` coverage; no races |
| `go vet ./...` | PASS (0 findings) |
| `gofmt -l .` | clean |
| `golangci-lint run` | **0 issues** (errcheck, govet, ineffassign, staticcheck, unused, misspell, gosec) |
| `buf lint` / `buf generate` | PASS — ConnectRPC + protobuf stubs generated into `gen/` |
| `sqlc generate` | PASS — typed queries generated into `internal/db/dbgen/` |
| Migrations on PostgreSQL 16 | PASS — all 3 applied clean; **functionally verified**: audit DELETE/content-UPDATE rejected by trigger, sealer columns settable exactly once, `action_requests`/`configuration_snapshots` immutable, RLS isolates tenants for a non-superuser role |

Test names, verbatim:

```
TestTransitionPrimitive/happy_path_writes_state_and_audit_atomically
TestTransitionPrimitive/invalid_transition_rejected_before_any_write
TestTransitionPrimitive/version_conflict_loses_the_race,_writes_nothing
TestTransitionPrimitive/failed_effect_rolls_back_state_and_audit_together
TestTransitionPrimitive/audit_events_cannot_be_deleted_or_rewritten
TestTransitionPrimitive/invalid_attempt_is_recordable_as_a_security_signal
TestEncodeIsDeterministic
TestEncodeIsTimezoneIndependent
TestEveryFieldAffectsTheHash
TestFieldBoundariesCannotBeConfused
TestChainLinksEvents
TestRejectsPreEpochTimestamp
```

## Issues found and fixed during verification

1. `go.mod` was missing `connectrpc.com/connect` + `google.golang.org/protobuf`
   after first `buf generate` → fixed via `go mod tidy`. Rule going forward:
   **`make proto` must be followed by `make tidy`** (encoded in CI).
2. connect v1.20.0 requires Go >= 1.25 → module bumped `go 1.24` → `go 1.25.0`
   (README updated).
3. `gofmt` violations in `internal/domain/domain.go` and
   `internal/auditenc/encode_test.go` → formatted.
4. errcheck: 4 unchecked `tx.Rollback`/`Close` in deferred cleanup → explicit
   discards.
5. gosec G115 (integer conversions in `auditenc`) → real fixes, not
   suppressions: `Event.SequenceNumber` is now `uint64` (sealer-assigned,
   non-negative by contract); `Encode`/`ChainHash` now return an error and
   refuse oversized fields (`ErrFieldTooLarge`) and pre-epoch timestamps
   instead of silently truncating. Chain-spec layout is unchanged.
6. Docker-in-Docker test attempts (before native Go was installed) failed on
   Testcontainers port networking (`172.17.0.1` unreachable). Not a code bug;
   native runs and Linux CI are the supported paths.

## Coverage

| Package | Coverage | Notes |
|---|---|---|
| `internal/transition` | 73.8% | uncovered lines are error branches of `RecordInvalidAttempt`/diagnose paths |
| `internal/auditenc` | 74.3% | uncovered lines are per-field `ErrFieldTooLarge` branches |
| `internal/domain` | 0% (no test files) | exercised indirectly by the transition suite; direct table test is cheap future work |
| `cmd/*` | 0% | intentional stubs — print "not implemented", exit 1 |
| `gen/`, `internal/db/dbgen` | 0% | generated code, excluded from lint |

## Milestone: idempotent-create (2026-07-17, same day)

`internal/transition/create.go` implements the plan §8 intake path:
`IdempotencyKey` (tenant+session+native id, domain-separated SHA-256),
`Fingerprint` (length-prefixed, refuses oversized fields), and `Create` —
one transaction inserting `action_requests` under the unique-constraint
guard, the `Created` state row, and the `ActionCreated` event; key collision
with equal fingerprint returns the existing workflow (current state, for
resume), unequal fingerprint commits `IdempotencyConflict` and refuses.

Verified (all with `-race`, real Postgres): fresh create; exact retry returns
same workflow and writes nothing; retry resumes at current state; conflicting
content refused + audited + original untouched; distinct sessions get
distinct actions; 8-way concurrent create race resolves to exactly one
action/event; invalid JSON refused. `go vet` 0, `golangci-lint` 0,
`internal/transition` coverage 73.8% → 77.2%.

## Milestone: PolicyEngine (2026-07-17, same day)

`internal/policy` implements the plan §20.1 design: cel-go evaluates each
rule's condition inside an explicit ordered-rule structure (first match wins);
composition, precedence, and explanation live in Go, not the expression
language. `Engine.Compile` validates a whole `SnapshotConfig` at load time
(CEL syntax, boolean output type, unknown variables, duplicate/reserved rule
ids, unknown decisions) so a broken rule can never be discovered
mid-request. `Evaluate` is pure and returns the `Decision` with
`MatchedRuleID` and the ordered `Trace` (plan §22 explainability). Fail-closed
is enforced three ways: empty/unmatched → default deny, runtime CEL errors
fail the evaluation (never skipped as "no match"), invalid snapshots never
load. `Decision.ToState()` maps verdicts onto the §7 state machine.

Verified: 10 test functions (23 cases including table subtests) covering
first-match ordering, params inspection, default-deny, runtime-error
fail-closed, 8 compile-rejection classes, trace path correctness, 100-run
determinism, and the JSON round-trip of the stored snapshot shape.
`go vet` 0, `golangci-lint` 0, coverage 94.5%, `-race` clean. New
dependency: github.com/google/cel-go v0.29.2.

## Milestone: River workers & timers (2026-07-17, same day)

`internal/queue` wires River in as designed (plan §20.1): `InsertJobEffect`
is the only enqueue path and it runs inside the transition primitive's
transaction — the transactional-outbox guarantee is now code, and its
rollback behavior is tested (a failing sibling effect leaves zero
`river_job` rows). Timers are River scheduled jobs written atomically with
the thing that needs them (Round 5 fix 2): the approval-expiry test creates
the `approval_requests` row and its timer in the single PendingApproval
transition. Three workers ship: `ApprovalExpiryWorker`
(PendingApproval→Expired + `ApprovalExpired` + approval-row CAS, in the
§20.2.1 lock order), `OutcomeDeadlineWorker`
(ExecutionAuthorized/Executing→OutcomeUnknown + `OutcomeUnknown`), and
`DeliverApprovalWorker` behind the new `notify.Port` interface (delivery
only; `LogPort` for dev/test — Slack lands with the ApprovalService).
Timer race rule enforced and tested: a timer that fires after the workflow
moved on no-ops successfully; it never errors into River retries.
`transition.CurrentState` added as the exported read path.

Verified: 6 integration subtests against real Postgres with River's own
migrations applied — outbox rollback, approval expiry **end-to-end through a
running River client** (job fires, state Expired, event written, approval
row CAS'd to expired/v1), both no-op race cases, OutcomeUnknown marking, and
port delivery fidelity. `go vet` 0, `golangci-lint` 0 (one gosec G101
false positive on a test literal fixed by making the fixture dynamic),
`-race` clean. Coverage: queue 76.9%. Note: transition coverage reads
68.6% (was 77.2%) because `CurrentState` added untested error branches —
its happy path is exercised heavily by the queue suite.
Dependencies: github.com/riverqueue/river v0.40.0 + riverpgxv5 (GitHub
module paths — the riverqueue.com vanity path does not serve the driver).

## Milestone: Sealer & verifier (2026-07-17, same day)

`internal/seal` implements the §20.2.2 mechanism without simplification.
`Sealer.SealStream`: per-stream advisory lock on a dedicated connection →
safe watermark derived from the oldest running transaction's start time
(min `xact_start` from `pg_stat_activity`, minus the configurable safety
margin) → unsealed events at or below the watermark sealed in `ingest_seq`
order with authoritative contiguous sequence numbers → SHA-256 chain via the
shared `auditenc` package → epoch encoded (`AGEPOCH1` layout, now also in
`auditenc` as part of the published spec) and signed OUTSIDE the write
transaction (§20.2.1: no slow calls inside transactions) → sealing columns
set once (the trigger-enforced one-shot proven in foundation testing) +
`audit_epochs` row committed. Signing is behind the cold-path `Signer`
interface (KMS-shaped); `Ed25519Signer` is the dev/test implementation.
`SealAll` discovers streams (sealer role needs BYPASSRLS in production —
documented). `Verify` re-derives everything from stored data trusting only
public keys: contiguity, per-event hashes, epoch roots, epoch linkage,
signatures, plus the unsealed-tail count for the §20.3 SLO.

Verified (7 integration subtests, real Postgres, `-race`): end-to-end
seal+verify with contiguous 1..N sequences; second epoch links and continues
the sequence; **the watermark test** — an open uncommitted transaction
holding a low `ingest_seq` blocks sealing entirely (0 sealed), and after
commit the once-invisible event lands at sequence 1 inside the chain, never
omitted; tamper detection (guard trigger disabled by a "malicious DBA",
metadata rewritten, verifier attributes the exact event); unknown signing
key reported; unsealed tail reported; `SealAll` multi-stream discovery.
Also: `internal/testdb` extracted (three duplicated container-setup helpers
→ one), and `auditenc` gained epoch-encoding determinism tests (coverage
48.2% after epoch.go landed → 75.0%). `go vet` 0, `golangci-lint` 0.
Coverage: seal 72.4%.

## Milestone: ApprovalService (2026-07-17, same day)

`internal/approval` implements plan §9. Tokens: `agt1_` +
base64url(tenant_id ‖ 32 random bytes) + HMAC-SHA256 signature — minted by
the service, stored only as SHA-256 hashes, single-use, expiring; the tenant
rides inside the signed payload so Resolve scopes its lookup under RLS
without any cross-tenant read, and forged tokens die at the HMAC check
before touching the database. `Request` performs Evaluated→PendingApproval
with the approval row, token, expiry timer (River scheduled job), and
delivery job committing atomically with the `ApprovalRequested` event; the
approver comes from the classification `Router` (never the PolicyEngine).
`Resolve` applies the decision as one transaction in the §20.2.1 lock order:
action_state CAS, then token single-use mark, approval-row version CAS, and
the `ApprovalDecision` record; events are attested `operator:<id>`.

Verified (8 integration subtests, real Postgres, `-race`): request
atomicity including queued-job payload fidelity; refusal outside Evaluated;
approve and deny paths; token replay rejected without changing the outcome;
forged/garbage tokens rejected pre-DB; expired tokens rejected; and the
double-approval race — concurrent approve+deny with exactly one winner, the
final state matching the winner, and exactly one decision row. `go vet` 0,
`golangci-lint` 0, coverage 76.2%.

Known limitation (documented in code): the raw token transits
`river_job.args` until the delivery job completes and River's cleaner prunes
it; tightening (payload encryption or post-delivery scrub) is future work.

## Milestone: ExecutionCoordinator & Orchestrator (2026-07-17, same day)

`internal/grant`: hot-path ExecutionGrants — in-process Ed25519 signing over
the exact serialized proto bytes (no canonicalization anywhere on the
signature path); `Verify` checks signature-then-parse against pinned keys.
`params_hash` is the request fingerprint (plan §8 layer 2), binding the
grant to the exact submitted content. `internal/execution`: the Coordinator
performs Evaluated/Approved→ExecutionAuthorized with the grant signed
before the transaction opens, the stored envelope + outcome-deadline timer
committing atomically with the `ExecutionAuthorized` event; the
`AuthorizeWorker` services the approved path. `approval.Resolve` now
enqueues `authorize_execution` atomically with an approval — a crash
between "approved" and "grant issued" recovers through the queue.
`internal/orchestrator`: `Submit` = idempotent create → cached compiled
snapshot (immutable, keyed by tenant+version) → `PolicyEvaluated` with the
full trace → route to authorize / request-approval / deny; `Status` is the
poll/resume path carrying the grant envelope when authorized. Two contract
amendments made with recorded justification: `SubmitActionResponse` gained
the `authorized` oneof branch (the allow path must return the grant without
a second round trip), and the `ActionDenied` event type was added (the
primitive writes one event per transition; `PolicyEvaluated` already
belongs to Created→Evaluated).

Verified: 4 grant tests (round-trip, tampered-grant privilege escalation
rejected, unknown key, expiry) + 6 orchestrator integration subtests — the
allow path end-to-end with an externally verified grant and armed deadline
timer; deny with rule-named explanation and `ActionDenied` event; the full
approval loop (pending → token recovered from the delivery job → resolve →
authorize worker → Status delivers a verifying grant); retry-resumes
semantics; no-snapshot tenants failing closed; late authorize jobs
no-oping. Full gate: `go vet` 0, `golangci-lint` 0, 8 packages `-race`
green; orchestrator 80.3% coverage.

## Milestone: RPC surface & runnable control plane (2026-07-17, same day)

The control plane is now a runnable binary. `internal/server` binds the four
RPCs to the orchestrated core with zero workflow logic of its own: `Enroll`
(single-use enrollment tokens marked used atomically with gateway creation;
credentials stored hashed; response pins the control-plane grant key),
bearer-credential auth interceptor (tenant identity comes from the
credential lookup, never from request fields), `SubmitAction` /
`GetActionStatus` mapping orchestrator results onto the proto oneof shapes,
`ReportOutcome` verifying gateway-signed receipts (`grant.VerifyReceipt`,
same sign-exact-bytes rule) before `Coordinator.RecordOutcome` applies the
two gateway-attested transitions (ExecutionStarted with both gateway and
server timestamps, then the terminal event + `action_results` + grant
single-use consumption). A channel-agnostic `POST /approval/callback`
endpoint resolves approvals. `cmd/controlplane` wires koanf env config,
pgxpool, River migration + worker client, the Sealer loop, and graceful
shutdown; signing keys come from seeds (ephemeral + loud warning in dev).
Migration 00005 adds the auth-plane `gateways`/`enrollment_tokens` tables
(deliberately outside tenant RLS — lookups happen before a tenant context
exists; documented). V1 session note: `session_id` is gateway-chosen but
scoped by the authenticated gateway, so collisions cannot cross tenants or
gateways — a recorded deviation from "server-minted at connect".

Verified — 6 wire-level subtests driving a real Connect client over HTTP
against the full stack with live River workers: enrollment single-use;
unauthenticated rejection; the complete happy path (enroll → submit → grant
verifies against enrolled keys → signed receipt accepted → duplicate
receipt flagged → status shows Succeeded with outcome); deny with rule
explanation; the full approval loop over the wire (pending → callback
approve → background worker authorizes → polled grant verifies → failure
receipt recorded); and a receipt signed with the wrong key rejected.
Full gate: `go vet` 0, `golangci-lint` 0, 9 packages `-race` green.
Coverage: server 63.6% (RPC error branches), grant package reads 42%
in isolation because receipt paths are exercised by the server suite.

## Milestone: Gateway core & CLI (2026-07-17, same day)

`cmd/gateway` is now a real binary with the check/report core underneath.
`internal/fingerprint` was extracted as a leaf package (the derivations are
shared verbatim by intake and the gateway, and the customer binary must not
drag the DB layer in); the derivation-freeze test moved with it.
`internal/gateway`: `Enroll` generates the keypair locally (private key
never leaves the machine) and pins the control-plane keys; `State` persists
to a 0600 file with atomic replace; `Check` submits and resolves to
allowed/denied, polling through pending — and `acceptGrant` is the trust
boundary: signature against pinned keys, `params_hash` against a locally
recomputed fingerprint (`canonicalParams` reproduces the server's
structpb-roundtrip + sorted-key JSON byte-for-byte), action/tool identity,
and expiry, with any failure treated as no grant at all; `Report` signs the
outcome receipt and forgets the local grant. CLI contract for agent hooks:
`check` exits 0 authorized / 2 denied / 3 timeout / 1 error; `report` is
the PostToolUse half. `internal/servertest` extracted (full-stack harness
shared by server and gateway suites; server_test became an external test
package to break the import cycle).

Verified — 6 integration subtests against the full live stack: state file
round-trip with keys intact; **the closed loop** (check → grant verified
locally → report success → control plane lands `Succeeded`); denial with
rule id and no grant retained; **approval mid-poll** (Check blocks, a human
approves via the public callback, the poll picks up the authorized grant,
partial outcome reported); report refused locally without a checked grant;
and swapped pinned keys causing grant rejection (`ErrGrantBad`).
Full gate: `gofmt` clean, `go vet` 0, `golangci-lint` 0 (one gosec G304
fixed with `filepath.Clean`), 11 packages `-race` green. Note: `make test`
and CI now cap package parallelism at 4 — unbounded parallel Testcontainers
startups exhausted Docker once (orchestrator false failure, passed in
isolation and in the capped full run).

## Milestone: MCP proxy (2026-07-17, same day)

`internal/gateway/mcpproxy.go` implements the §21.2 auto-wrap enforcement
point on the official MCP Go SDK (v1.6.1): the proxy connects to the
downstream MCP server, mirrors its tools verbatim (paginated ListTools,
schemas passed through untouched), and serves the wrapped surface — every
tools/call routes through `Gateway.Check` first and forwards the raw
arguments only under a locally verified grant. Enforcement rules encoded:
denied, timed-out, or errored checks NEVER reach downstream (fail closed;
refusals return `IsError` results attributed to actiongate, so the agent
sees why); outcomes are reported from what downstream actually returned;
a failed receipt delivery is logged and left to the outcome-deadline timer
(OutcomeUnknown — the honest fallback). `Gateway.State.PendingReceipts` is
now mutex-guarded (the MCP server dispatches concurrently). CLI:
`gateway mcp [flags] -- CMD [ARGS...]` bridges agent stdio ↔ downstream
subprocess; all logging goes to stderr since stdout is the MCP channel.
One recorded gosec suppression (G204, with justification comment): running
the user's explicitly named downstream server command is this command's
entire purpose — the "fix" would delete the feature.

Verified — 4 integration subtests: a real MCP agent client ↔ proxy ↔ fake
downstream server over in-memory transports, with the live control plane
(and its River workers) behind the proxy. Tool mirroring; allowed call
executes downstream, returns its output unchanged, and lands `Succeeded`
in the control plane; **denied call returns an attributed refusal and the
downstream invocation counter proves it never executed**, landing `Denied`;
approval-gated call blocks inside `tools/call`, a human approves via the
public callback, and the call completes with the downstream executed once.
Full gate: `gofmt` clean, `go vet` 0, `golangci-lint` 0, 11 packages
`-race` green (gateway 72.1%).

## Milestone: verify CLI, Slack channel, admin commands (2026-07-17, same day)

The last three V1 pieces. `cmd/verify` is real: streams discovered or
specified, `seal.Verify` re-derivation per stream, JSON report lines, exit
0/1/2 — the moat demo in a binary (and the future WASM target).
`internal/admin` + `controlplane admin`: `create-tenant`, `set-policy`
(policy is compiled before storage — a broken snapshot cannot exist;
`content_hash` now stored properly), and `enroll-token` (raw shown once,
hash stored). The admin-minted token is proven compatible by a round-trip
test through the real Enroll RPC. `notify.SlackPort`: approval messages
with Approve/Deny buttons carrying the callback token, channel routing by
approver target with default fallback, and no-destination as an error, not
a silent drop. `/slack/interaction` on the server verifies Slack's signing
secret before anything else, maps the button to a decision, and resolves
with approver identity `slack:<user id>` — token single-use and CAS
semantics identical to every other resolution path.

Verified: 3 admin subtests + enrollment round-trip; 3 SlackPort subtests
against a captured fake Slack API (token appears in both buttons, routing,
fallback, error); and the wire test — a **signed Slack button click**
resolving a real pending approval end-to-end (forged signature → 403 with
nothing resolved; genuine signature → approval attested
`operator:slack:U-ALICE`, worker advances to ExecutionAuthorized).
Full gate: `gofmt` clean, `go vet` 0, `golangci-lint` 0 (one gosec taint
finding in a test fake fixed by not echoing input), 13 packages `-race`
green.

## Remaining limitations (honest list)

- All three binaries are real: `controlplane` (+ `admin` subcommands),
  `gateway` (hooks CLI + MCP proxy), `verify`. `gateway init` (automatic
  .mcp.json rewriting) is future convenience work on top of the working
  `mcp` mode; the browser/WASM verifier is a second build target of the
  finished verify core (V1.5 per plan §22).
- Slack delivery requires a bot token + signing secret via env; the
  channel map is default-channel-only in config for now (the `Channels`
  routing map exists in code).
- `-race` on Windows requires a MinGW gcc (documented above); Linux CI runs it
  without extra setup.
- buf/sqlc were verified via their official Docker images, not native CLIs.
- The repository is not yet under git (`git init` pending owner decision);
  the CI workflow activates once pushed to GitHub.
- Performance SLOs (plan §20.3) are untested — that requires the actual
  services, not the skeleton.
