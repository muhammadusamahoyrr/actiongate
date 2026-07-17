# AI Control Plane — V2 Architecture (Post Review Round 5: Structural Fixes)

This revision supersedes the V1 document. Rounds 1–4 hardened the domain model (immutability, fact-based audit, race hygiene) — all of that is preserved. Round 5 fixed the six structural issues that would have forced a rewrite: the synchronous spine, unowned time, the undrawn execution trust boundary, the hash chain in the hot path, client-derived idempotency identity, and policy pinning conflating attribution with enforcement. Product scope is unchanged: intercept, evaluate policy, request approval, execute or deny, immutable audit log.

---

## 1. Design Principles (why this shape)

1. **Audit records facts, never intentions.** An event is only written once the thing it describes has actually happened — and it records *who attested* it.
2. **Nothing is mutated, only appended.** `ActionRequest` is immutable from creation; every downstream step produces a new object.
3. **Every state transition is exactly one transaction.** New state + audit event + next work item commit atomically, or none of them do. No component ever "writes audit, then calls a service."
4. **Control plane decides; data plane executes.** Execution happens where the tools and credentials already live — the customer's side. The control plane issues signed grants and records outcomes; it never touches customer credentials for local tools.
5. **Time is owned.** Every deadline (approval expiry, outcome reconciliation) is a timer row created atomically with the thing that needs it, fired by a first-class worker — never an unowned cron job.
6. **Vendor names never appear in business logic.** MCP, Slack, Postgres, KMS are implementations behind interfaces, not the architecture.
7. **Fail closed by default**, with an explicit, auditable override for fail-open where a policy says so. Fail-closed means "the transition transaction must commit" — a single, well-understood failure mode.
8. **Uncertainty is a valid state.** "We don't know what happened" is recorded honestly, not rounded to success or failure — and it has a defined path to resolution.
9. **Policy can only tighten a pending action, never loosen it.** Pinned versions attribute decisions; the current version enforces them.

---

## 2. Topology — Two Deployables

```
CUSTOMER SIDE (data plane)                      VENDOR / SELF-HOST (control plane)
──────────────────────────                      ──────────────────────────────────
Claude / Cursor / Codex / custom agent
        │ native tool call
        ▼
┌─────────────────────────┐   ActionRequest    ┌──────────────────────────────────┐
│      Gateway            │ ────────────────►  │   ControlPlaneOrchestrator        │
│  (single binary)        │                    │   (workflow = durable state       │
│  • InboundAdapter       │   Completed(result)│    machine over Postgres;         │
│    translate() only     │ ◄──────────────── │    every transition is ONE txn:   │
│  • ExecutionAdapter     │   or Pending(id)   │    state CAS + audit event +      │
│    execute() only,      │                    │    outbox row)                    │
│    local credentials    │                    └──┬──────────┬──────────┬─────────┘
│    only                 │                       │          │          │
└───────────┬─────────────┘                       ▼          ▼          ▼
            │ signed ExecutionGrant        ┌───────────┐┌──────────┐┌─────────────┐
            │ (short-TTL, single-use,      │PolicyEngine││ Approval ││ AuditService │
            │  content-bound, KMS-signed)  │.evaluate() ││ Service  ││ .record()    │
            ▼                              └───────────┘└────┬─────┘└──────┬───────┘
   filesystem / shell / DB /                                 │             │
   email / local tool APIs                                   ▼             ▼
            │                                        ┌──────────────┐  AuditStore
            │ signed outcome receipt                 │ApprovalChannel│  (append-only;
            └────────────────────────────►           │(Slack/email/ │  epoch-sealed
                                                     │ webhook)     │  + KMS-signed
                                                     └──────────────┘  by background
                                                                       Sealer)
Workers (control plane, all claim work via outbox + SKIP LOCKED + leases):
  ExecutionCoordinatorWorker — issues grants, tracks outcome deadlines
  NotificationWorker         — delivers approval requests
  TimerWorker                — fires approval expiry, reconciliation deadlines
  Sealer                     — assigns audit sequence, hash-chains epochs, signs roots

SaaS-managed integrations only (cloud APIs the vendor executes on the tenant's
behalf): per-tenant isolated runners + vendor-side CredentialProvider. Never a
shared executor process across tenants.

Cross-cutting (used by everything, owned by nothing above):
  Clock.now() — testable time source
  MetricsRecorder / Tracer / Logger — observability interfaces
  ConfigurationSnapshot — immutable, versioned policy + config bundle
```

Self-host = run the control plane too. Identical code path; only the concrete
implementations behind `PolicyStore`, `AuditStore`, `SigningKey`, and
`ApprovalChannel` differ.

---

## 3. Component Responsibilities

| Component | Does | Never does |
|---|---|---|
| **Gateway / InboundAdapter** | Translates a native call (MCP; later HTTP/CLI) into an immutable `ActionRequest`; attaches the server-minted `session_id` to form the idempotency key | Decide policy, execute without a verified grant, hold control-plane secrets |
| **Gateway / ExecutionAdapter** | Verifies an `ExecutionGrant` signature, executes locally with the customer's own credentials, reports a signed outcome receipt | Execute without a valid unexpired grant, send credentials to the control plane, make policy decisions |
| **ControlPlaneOrchestrator** | Owns the durable state machine; performs every transition as one transaction (state CAS + audit event + outbox row); idempotency check | Evaluate policy itself, notify anyone itself, execute anything itself |
| **PolicyEngine** | `ActionRequest` + `ConfigurationSnapshot` → `PolicyDecision` (allow / deny / requires_approval + risk classification tag) | Know approvers, send notifications, execute, mutate state |
| **ApprovalService** | Resolves approver from classification; creates `ApprovalRequest` + its expiry timer atomically; **mints** callback tokens; resolves decisions via CAS on `version` | Know policy rules, know downstream tool details, execute |
| **ApprovalChannel** (impl of `NotificationPort`) | Delivers approval requests and relays responses. Delivery only | Mint tokens, contain business logic, decide outcomes |
| **AuditService** | Appends fact-based events (plain INSERT in the transition txn — no hash, no sequence) with `attested_by` provenance | Make decisions, retry anything, delete or modify past events |
| **Sealer** | Background, per tenant: assigns sequence numbers in commit order, computes the SHA-256 chain, closes epochs, signs epoch roots with a KMS key the app/DB roles cannot use, anchors roots externally | Sit in any request path, hold the ability to rewrite events |
| **TimerWorker** | Claims due `timers` rows (SKIP LOCKED + lease), emits workflow commands (ExpireApproval, ReconcileOutcome) | Contain business rules about *what* expiry means |
| **ExecutionCoordinatorWorker** | Claims `execute_action` outbox rows, issues `ExecutionGrant`s, records `ExecutionAuthorized`, sets the outcome deadline timer | Execute anything itself |
| **CredentialProvider** (vendor-side, SaaS integrations only) | Issues short-lived, action-scoped credentials for vendor-executed cloud integrations, inside per-tenant runners | Serve customer-local tools; cache credentials beyond the action |

---

## 4. Domain Model

All domain objects are immutable once created. Workflow position lives in `action_state`, mutated only by compare-and-swap; everything else progresses by creating new, linked records.

**ActionRequest** *(immutable, created once by InboundAdapter)*
- `id`, `tenant_id`, `agent_id`, `session_id` (server-minted at connect, authenticated), `idempotency_key` = hash(`tenant_id`, `session_id`, `native_request_id`), `request_fingerprint` = hash(`agent_id`, `tool_name`, canonical(`tool_params`)), `tool_name`, `tool_params` (original, untouched), `environment`, `correlation_id`, `policy_version_evaluated` (the `ConfigurationSnapshot` version at creation — audit attribution, see §10), `created_at`
- Internally shaped as `RequestContext` + `RequestedAction` (Round 4 decision, kept)

**ActionState** *(the one legitimately mutable row — CAS only)*
- `action_request_id` (PK), `state`, `version` (optimistic lock), `lease_owner` (nullable), `lease_expires_at` (nullable)

**OutboxItem** *(work to be done, written in the same txn as the transition that requires it)*
- `id`, `kind` (`deliver_notification` | `execute_action` | `fire_timer_command`), `subject_id`, `available_at`, `claimed_by`, `lease_expires_at`, `attempts`

**Timer** *(written atomically with the thing that needs it — an approval can never exist without its expiry)*
- `id`, `tenant_id`, `fire_at`, `kind` (`approval_expiry` | `outcome_deadline`), `subject_id`

**PolicyDecision** *(created by PolicyEngine; also created on revalidation — see §10)*
- `id`, `action_request_id`, `decision` (`allow|deny|requires_approval`), `risk_classification`, `matched_rule_id`, `policy_version` (the version that produced *this* decision), `evaluated_at`

**ApprovalRequest** — `id`, `action_request_id`, `approver_target` (resolved by ApprovalService), `status` (`pending|approved|denied|expired|cancelled`), `version` (CAS), `expires_at`, `created_at`

**ApprovalCallbackToken** *(minted by ApprovalService, delivered by ApprovalChannel)*
- `token` (HMAC-signed, random, single-use, expiring), `approval_request_id` (via lookup table, never embedded), `used_at` (nullable, set once)

**ApprovalDecision** — `approval_request_id`, `approver_id` (authenticated identity), `decision`, `reason`, `decided_at`

**ExecutionGrant** *(the control-plane→gateway authorization; the credential for local tools IS the grant)*
- `grant_id`, `action_request_id`, `content_hash` = hash(`tenant_id`, `action_request_id`, `tool_name`, hash(`tool_params`)), `expires_at` (short TTL), `single_use`, `signature` (control-plane KMS key). Gateway verifies signature + content hash + expiry before executing.

**RedactedActionInputs** — `action_request_id`, `redacted_params`, `created_at` (a copy, never a mutation)

**AuditEvent** *(append-only; hot path writes NO hash and NO sequence — the Sealer adds them)*
- `id` (UUIDv7), `tenant_id`, `stream_id`, `action_request_id`, `event_type`, `metadata`, `attested_by` (`control_plane` | `gateway:<id>` | `operator:<id>`), `decision_ref` (nullable), `redacted_inputs_ref` (nullable), `references`, `recorded_at`, plus Sealer-assigned: `sequence_number`, `previous_hash`, `event_hash`, `epoch_id`

**AuditEpoch** *(created by Sealer)*
- `epoch_id`, `tenant_id`, `stream_id`, `first_sequence`, `last_sequence`, `root_hash` (SHA-256), `prev_epoch_root`, `signature` (KMS), `anchored_at` (external anchor timestamp, nullable), `sealed_at`

**ActionResult** *(reported by the gateway with a signed receipt; recorded by control plane)*
- `action_request_id`, `status` (`succeeded|failed|partially_succeeded|outcome_unknown`), `output_ref`, `error` (nullable), `side_effects` (list, for partial success), `started_at` (gateway-attested), `completed_at` (nullable), `receipt_signature`

**ReconciliationResult** *(resolves an `outcome_unknown` — human-verified)*
- `action_request_id`, `operator_id`, `verified_outcome`, `evidence_ref`, `reconciled_at`

*(RiskAssessment intentionally not modeled — deferred to the risk-scoring phase.)*

---

## 5. Audit Event Vocabulary (facts only, with attestation)

```
ActionCreated                (control_plane)
PolicyEvaluated              (control_plane; carries decision + risk_classification + policy_version)
PolicyRevalidated            (control_plane; carries original + current versions and outcome — see §10)
ApprovalRequested            (control_plane)
ApprovalGranted              (control_plane; approver_id)
ApprovalDenied               (control_plane; approver_id)
ApprovalExpired              (control_plane; via TimerWorker)
ActionCancelled              (control_plane; requester or admin withdrawal)
ActionSupersededByPolicy     (control_plane; a stricter current policy denied a pending action)
ExecutionAuthorized          (control_plane; fact: a signed grant was issued)
ExecutionStarted             (gateway-attested; gateway timestamp + server received_at)
ExecutionSucceeded           (gateway-attested)
ExecutionFailed              (gateway-attested)
ExecutionPartiallySucceeded  (gateway-attested; side_effects list)
OutcomeUnknown               (control_plane; outcome deadline fired with no receipt)
OutcomeReconciled            (operator-attested; verified_outcome + evidence_ref)
IdempotencyConflict          (control_plane; same key, different fingerprint — see §8)
InvalidTransitionAttempted   (control_plane; security-relevant signal)
```

Nothing here describes a state the system merely intends to reach. The control plane records only what it did or received; execution facts are explicitly marked as gateway-attested rather than pretended to be first-hand knowledge — the honesty principle applied to distribution.

---

## 6. Durable Workflow: Transitions, Crash Recovery, Non-Atomic Execution

**The transition primitive.** Every state change is one Postgres transaction: CAS on `action_state.version` + audit event INSERT + outbox/timer INSERTs. If any part can't commit, nothing happened — fail-closed reduces to transactional atomicity. (This un-defers the transactional outbox from Round 4: it is the foundation, built in V1, not an ADR for later.)

**Workers and leases.** All background work (execution coordination, notification delivery, timer firing) is claimed from `outbox`/`timers` via `SELECT … FOR UPDATE SKIP LOCKED` with a lease (`claimed_by`, `lease_expires_at`). Crash recovery is uniform: an expired lease returns the work item. There is no bespoke per-failure recovery logic.

**Partial success:** the gateway reports `partially_succeeded` with a `side_effects` list of exactly what completed. Never rounded up or down.

**Unknown outcome:** when the ExecutionCoordinatorWorker issues a grant, the same transaction writes an `outcome_deadline` timer. If it fires with no receipt received, the workflow transitions to `OutcomeUnknown` (audited). A human resolves it via `OutcomeReconciled` with operator identity and evidence — the uncertainty is preserved in the log, but it is no longer a dead end.

**V1 does not adopt a workflow engine** (Temporal etc.) — Postgres + SKIP LOCKED is boring, sufficient at V1 scale, and keeps the self-host story to "run one binary + Postgres." Worker interfaces are shaped so a workflow-engine backend could replace the queue later if real scaling data demands it.

---

## 7. State Machine (enforced only by ControlPlaneOrchestrator, via CAS)

```
Created → Evaluated ─┬→ Denied                                      (terminal)
                     ├→ PendingApproval ─┬→ Approved → ExecutionAuthorized → Executing
                     │                   ├→ Denied                  (terminal)
                     │                   ├→ Expired                 (terminal)
                     │                   ├→ Cancelled               (terminal)
                     │                   └→ SupersededByPolicy      (terminal)
                     └→ ExecutionAuthorized (auto-allow) → Executing

Executing → Succeeded | Failed | PartiallySucceeded                 (terminal)
Executing → OutcomeUnknown → Reconciled                             (terminal)
```

| From | Allowed to |
|---|---|
| Created | Evaluated |
| Evaluated | PendingApproval, ExecutionAuthorized (auto-allow), Denied (auto-deny) |
| PendingApproval | Approved, Denied, Expired, Cancelled, SupersededByPolicy |
| Approved | ExecutionAuthorized, SupersededByPolicy (pre-grant revalidation — §10) |
| ExecutionAuthorized | Executing, OutcomeUnknown (grant issued, no receipt ever arrived) |
| Executing | Succeeded, Failed, PartiallySucceeded, OutcomeUnknown |
| OutcomeUnknown | Reconciled |
| Denied, Expired, Cancelled, SupersededByPolicy, Succeeded, Failed, PartiallySucceeded, Reconciled | *(terminal)* |

Any transition outside this table is rejected and logged as `InvalidTransitionAttempted` — a security-relevant signal, not just a bug report.

---

## 8. Idempotency and Duplicate Detection (layered)

**Layer 1 — key identity (exact retry collapse).** At connect, the control plane mints an authenticated, unguessable `session_id`. `idempotency_key = hash(tenant_id, session_id, native_request_id)` — native request IDs (e.g. MCP's) are only unique within a session, so they are never used alone, and client-claimed identity never forms the key by itself. Enforced by a DB unique constraint on `(tenant_id, idempotency_key)`.

**Layer 2 — fingerprint check (never leak another result).** `request_fingerprint = hash(agent_id, tool_name, canonical(params))` is stored with the key. On a key hit: fingerprint matches → return the existing workflow's status/result (safe retry, and how a `Pending` submission is resumed); fingerprint differs → reject with a conflict error and write `IdempotencyConflict`. A result is never returned for different content.

**Layer 3 — cross-session advisory dedup.** A crashed-and-restarted agent gets a new session and new request IDs, so keys cannot catch that retry. A configurable content-fingerprint window (default 10 min) flags repeats; policy decides warn / block / allow, and the approver sees "an identical action was approved N minutes ago." Advisory by design — identical actions are sometimes legitimately repeated.

---

## 9. Approval Flow Detail

1. `PolicyEngine` returns `requires_approval` + a `risk_classification` tag — never a specific approver.
2. `ApprovalService` resolves `approver_target` from the classification, and in **one transaction** creates the `ApprovalRequest` (`version = 0`), its `approval_expiry` timer, its callback token, and a `deliver_notification` outbox row.
3. `ApprovalService` mints the opaque, HMAC-signed, single-use, expiring callback token; `ApprovalChannel` only delivers it. The `request_id` is never exposed externally.
4. On response, resolution is compare-and-swap on `ApprovalRequest.version`: concurrent approvers → first write wins, second gets a conflict. Token `used_at` set on first use; replays rejected.
5. Approval grant triggers policy revalidation (§10) before the workflow advances.

**Agent-facing contract:** `handle()` returns `Completed(ActionResult)` on the auto-allow fast path, or `Pending(action_id, expires_at)`. The MCP gateway surfaces `Pending` as a structured tool result; the agent or user resumes via `get_action_status(action_id)` (or resubmits with the same key — same workflow). HTTP adapters additionally support webhooks. No connection is ever held open across a human approval.

---

## 10. Policy Binding: Pin for Attribution, Re-evaluate for Enforcement

- `ActionRequest.policy_version_evaluated` is set once at creation and never changes — it attributes the *original* decision in the audit trail.
- Enforcement re-checks the **current** `ConfigurationSnapshot` at two gates: approval grant, and immediately before issuing the `ExecutionGrant`. Outcomes:
  - Same or looser → proceed; write `PolicyRevalidated` with both versions. A looser current policy never takes effect on a pending action.
  - Stricter (now requires approval / higher tier) → re-enter `PendingApproval`, audited.
  - Now denied → `SupersededByPolicy` (terminal) + `ActionSupersededByPolicy` event.
- **Invariant: a later policy version can tighten a pending action's path, never loosen it; every decision event records the version that produced it.** An emergency deny shipped while a dangerous request awaits approval takes effect — the old design's biggest semantic hole. Audit clarity improves, because revalidations are themselves events.

---

## 11. Credentials and the ExecutionGrant Protocol

**Local tools (the V1 core case):** the credential *is* the grant. The control plane signs an `ExecutionGrant` (short-TTL, single-use, bound to the request's content hash) with a KMS key; the gateway verifies it and executes with the customer's own local credentials. Customer credentials never transit the vendor cloud, and the gateway can never execute without a control-plane decision — the trust boundary is the signature.

**SaaS-managed integrations (vendor executes a cloud API on the tenant's behalf):** vendor-side `CredentialProvider` issues short-lived, action-scoped credentials, and execution runs in per-tenant isolated runners (per-tenant queue, per-tenant sandbox) — never a shared executor process across tenants. `SecretsManager` in V1, Vault/KMS dynamic leasing later, behind the same interface.

---

## 12. Audit Integrity: Epoch Sealing (off the hot path, signed against insiders)

**Hot path:** the audit INSERT inside each transition transaction is a plain append — UUIDv7 id, `attested_by`, no sequence number, no hash. Per-tenant write serialization does not exist on the request path; fail-closed means only "the transaction must commit."

**Sealing:** a background Sealer, per tenant stream, every few seconds or N events: assigns contiguous `sequence_number`s in commit order, computes the SHA-256 hash chain, closes an **epoch**, signs the epoch root with a KMS key that the application and DB roles cannot use for anything else, and optionally anchors epoch roots externally (object-locked storage or a customer-fetchable digest).

**Verification:** `verify_chain` is incremental — verify sealed epochs from checkpoints; alert if the unsealed tail exceeds its bounded window (a monitored SLO, not a silent gap).

**Threat model, stated:** tamper-evident against anyone without the KMS signing key, *including a DB administrator* — rewriting history requires re-signing every subsequent epoch and overwriting external anchors, not an UPDATE statement.

**Distribution:** tenant is the sharding unit; each tenant's writes are homed to one region, preserving commit order without global coordination. A region failover starts a new epoch referencing the last anchored root — failovers are visible in the chain, not papered over.

**Latency budget (explicit):** the allow path adds p99 ≤ 150 ms and exactly one database round trip (idempotency check + decision + state + audit in one transaction).

---

## 13. Data Model Additions for Operations

Every table carries `created_by`, `updated_by` (where mutation is legitimate — `action_state`, `ApprovalRequest.status/version`, outbox/timer claims only), `schema_version`. **`deleted_at` (soft delete) applies only to Policy definitions.** It must never apply to `AuditEvent`, `AuditEpoch`, or `ActionRequest`, which are permanently append-only. Audit events are forward-compatible and never rewritten — schema changes add fields, never alter historical rows.

---

## 14. Cross-Cutting Interfaces

```
Clock.now() -> Timestamp
MetricsRecorder.increment(name, tags) / .observe(name, value, tags)
Tracer.startSpan(name) -> Span
Logger.log(level, message, structured_fields)
    // business logic never calls a logging/metrics/time library directly
```

---

## 15. Interfaces (final)

```
// Gateway (customer side)
InboundAdapter.translate(native_call, session) -> ActionRequest
ExecutionAdapter.execute(request: ActionRequest, grant: ExecutionGrant) -> SignedReceipt<ActionResult>
    // verifies grant signature + content hash + TTL before touching anything

// Control plane
ControlPlaneOrchestrator.handle(request: ActionRequest) -> Completed(ActionResult) | Pending(action_id, expires_at)
ControlPlaneOrchestrator.status(action_id) -> ActionStatus            // resume path for Pending
ControlPlaneOrchestrator.cancel(action_id, actor) -> void             // → Cancelled if still pending
ControlPlaneOrchestrator.reportOutcome(receipt: SignedReceipt<ActionResult>) -> void

PolicyEngine.evaluate(request: ActionRequest, config: ConfigurationSnapshot) -> PolicyDecision

ApprovalService.request(request: ActionRequest, decision: PolicyDecision) -> ApprovalRequest
    // one txn: request + expiry timer + token + notification outbox row
ApprovalService.resolve(callback_token, decision: "approved"|"denied", approver_id) -> ApprovalDecision
    // CAS on ApprovalRequest.version; token single-use

AuditService.record(event_type, action_request_id, attested_by, fields) -> AuditEvent
    // plain append inside the caller's transaction
AuditService.verify(tenant_id, stream_id) -> VerificationReport       // incremental, epoch-checkpointed

Sealer.sealPending(tenant_id, stream_id) -> AuditEpoch                // background only

ExecutionCoordinator.issueGrant(request: ActionRequest) -> ExecutionGrant
    // same txn: ExecutionAuthorized event + outcome_deadline timer

CredentialProvider.issue(request: ActionRequest) -> ScopedCredential  // SaaS-managed integrations only

TimerService.schedule(fire_at, kind, subject_id) -> Timer             // called inside owning txns only
NotificationPort.send(payload) -> void
ApprovalChannel extends NotificationPort
```

---

## 16. Failure Behavior

| Failure | Behavior |
|---|---|
| Notification/ApprovalChannel down | Request stays `PendingApproval`; outbox retries with backoff; fallback channel if configured; never silently auto-approve |
| AuditStore/Postgres unreachable | **Fail closed universally** — the transition transaction cannot commit, so nothing happened; agent receives an error, not a hang |
| PolicyEngine crash | Orchestrator rejects the call outright; never falls back to direct execution |
| Control-plane worker crash | Lease expires; work item is reclaimed by another worker — uniform recovery, no bespoke logic |
| Gateway crash mid-execution | Grant issued but no receipt: `outcome_deadline` timer fires → `OutcomeUnknown`, resolved by human `OutcomeReconciled` |
| Grant expires before gateway executes | Gateway rejects it locally; gateway re-requests; control plane re-issues after revalidation (§10) |
| Concurrent approval clicks | CAS on `ApprovalRequest.version` — second writer gets a conflict |
| Duplicate/retried ActionRequest | Key + fingerprint match → existing workflow returned; key match + fingerprint mismatch → conflict + `IdempotencyConflict` event |
| Approval timeout | TimerWorker fires → `Expired`; configurable default deny |
| Sealer lag beyond bounded window | Alert (SLO breach); hot path unaffected; events remain durably committed and sealable |
| Region failover | Tenant re-homed; new epoch fenced against last anchored root — visible in the chain |

---

## 17. Architecture Decision Records to write before implementation

1. Why an Adapter Layer split into Inbound/Execution — and why MCP is one implementation, not the product
2. **Why every state transition is one transaction (state + audit + outbox) — the transactional outbox as V1 foundation, not a deferred pattern**
3. **Why control plane and data plane are separate deployables, and why execution runs customer-side with signed ExecutionGrants (the trust boundary is the signature)**
4. **Why audit integrity uses background epoch sealing + KMS signing + external anchoring — including the explicit threat model ("tamper-evident against whom": DB admins included)**
5. Why audit events describe attested facts (`ExecutionAuthorized` vs gateway-attested `ExecutionStarted`), never intentions
6. Why fail-closed by default, with explicit per-policy override for fail-open
7. Why asynchronous approvals with a `Pending`/resume contract instead of held connections
8. **Why policy is pinned for attribution but re-evaluated for enforcement, with the monotone-tightening invariant**
9. **Why idempotency identity is server-minted (session_id) + fingerprint-guarded, never raw client request IDs**
10. Why ActionRequest and its params are immutable — redaction produces a copy, never a mutation
11. Why credentials for local tools never transit the vendor cloud, and SaaS integrations run in per-tenant runners
12. Why self-host and cloud deployments share the same code path
13. Why `OutcomeUnknown` is honest but resolvable (`Reconciled`), not a dead end
14. Why domain state is an append-only sequence of events, not mutable records — with `action_state` as the single CAS-guarded projection
15. **Why time-driven work (expiry, reconciliation) is a first-class subsystem written atomically with its subject, not cron jobs**

Deferred to ADR-only (not built in V1): retention/archive/compliance-export lifecycle; workflow-engine (Temporal) backend behind the worker interfaces; orchestrator decomposition (revisit if it exceeds ~300 lines or gains a second responsibility).

---

## 18. What Remains Deliberately Out of Scope for V1

Unchanged: role-based routing, risk scoring, dry-run, pattern-mined suggestions, dashboard, rollback engine, intent analysis, simulation sandbox, plugin SDK, reputation network — all postponed or removed per the MVP Scope Review. Five capabilities only: intercept, evaluate, approve, execute-or-deny, audit.

---

## 19. Final Assessment

V2 keeps everything Rounds 1–4 got right about the nouns — immutable objects, fact-based events, race hygiene — and fixes what they never stress-tested: the physics. Time now has an owner; crashes have one uniform recovery mechanism; the approval flow has an honest async contract instead of a synchronous signature wrapped around an hours-long process; the execution trust boundary is drawn (and drawn where the credentials already live); audit integrity has a stated threat model and is off the hot path; idempotency can't leak one caller's result to another; and an emergency policy change actually stops a pending dangerous action.

The honest remaining risks are unchanged: distribution (a correct product with no customers is still worth nothing), the enterprise self-host conversation (now materially easier: one binary + Postgres + a KMS key), and the class of bugs that only real traffic through a real gateway will surface — which is the right next step now.

**Status: architecture review is closed at Round 5.** Further correctness issues should surface through implementation and tests, not additional design rounds.

---

## 20. Technology Selection & Implementation Decisions (Round 6 — final)

### 20.1 Stack

| Layer | Selection | Status |
|---|---|---|
| Language (both deployables) | Go 1.24+ | Final |
| Database | PostgreSQL 16+ (tenant-homed per region) | Final |
| SQL access | pgx v5 + sqlc (hand-written SQL, compile-time checked) | Final |
| Queue / workers / timers | River (`InsertTx` only — never non-transactional insert) | Final |
| Migrations | Goose | Final |
| Policy evaluation | cel-go as condition evaluator inside an explicit ordered-rule structure | Final; re-evaluate Cedar the day customers author policies directly |
| MCP | Official Go MCP SDK (`modelcontextprotocol/go-sdk`) | Final |
| Gateway | Customer-side static Go binary (InboundAdapter + ExecutionAdapter) | Final |
| Gateway↔CP protocol | ConnectRPC + Protobuf, unary only (`Enroll`, `SubmitAction`, `GetActionStatus`, `ReportOutcome`); Buf breaking-change checks in CI | **V1, not later** — the wire protocol is the hardest thing to change once customer gateways exist, and grant signatures are bound to protobuf bytes |
| Signing — grants (hot path) | Ed25519 key in process memory, sealed at rest via KMS envelope; ~7-day rotation with overlap; detached signature over exact serialized protobuf bytes | Final |
| Signing — audit epochs (cold path) | Direct KMS Sign (ECDSA P-256 if KMS lacks Ed25519) | Final |
| Audit anchoring | `AnchorStore` interface + `anchored_at` field ship in V1; external WORM anchoring (S3 Object Lock) enabled later as config, not migration | Deferred by decision |
| Tenant isolation | tenant_id-first indexes everywhere + PostgreSQL RLS (`app.tenant_id` GUC per txn) as defense-in-depth; no cross-tenant joins ever | Final |
| Config | koanf (bootstrap config only); `ConfigurationSnapshot` = dedicated INSERT-only table with `content_hash` per row | Final |
| Logging / observability | slog behind `Logger`; OpenTelemetry behind `MetricsRecorder`/`Tracer` | Final |
| Notifications | slack-go behind `NotificationPort`; SMTP via std lib | Final |
| IDs | UUIDv7 via google/uuid, app-generated — for index locality only; **amends Round 4: UUIDv7 is NOT an ordering guarantee** (wall-clock skew); authoritative order is the Sealer-assigned sequence | Final |
| Testing | Testcontainers-Go — all SQL primitives (CAS, SKIP LOCKED, unique constraints, RLS) tested against real Postgres | Final |
| Release pipeline | GoReleaser + Cosign (KMS-backed signing) + Syft SBOM + Trivy scan — signed artifacts are part of the product | Final |
| Explicitly rejected | PgBouncer in V1 (breaks River LISTEN/NOTIFY under transaction pooling; use pgxpool), OpenFeature (a runtime flag that changes enforcement is an unaudited policy change — toggles must live inside ConfigurationSnapshot), ORMs, workflow engines (Temporal remains a deferred backend behind the worker interfaces) | — |

### 20.2 Implementation decisions locked before coding

1. **Transition transaction rules:** nothing slow inside the txn (policy eval, signature verification, KMS all happen before BEGIN); fixed lock order — `action_state` CAS first, then `approval_request`; READ COMMITTED everywhere; idempotency via `INSERT … ON CONFLICT DO NOTHING RETURNING`.
2. **Sealer watermark (correctness-critical):** `audit_events` carries a plain `bigserial ingest_seq` (ordering aid only). Per stream: advisory lock → compute safe watermark from the snapshot horizon (`pg_snapshot_xmin`, +2 s margin) → seal events below the watermark in `ingest_seq` order, assigning the authoritative contiguous sequence. Sealing past an in-flight transaction silently and permanently omits events from the chain — this mechanism is not optional.
3. **Audit chain hashing:** `event_hash = SHA-256(previous_hash || encode(event))` where `encode` is a purpose-built deterministic layout (fixed field order, length-prefixed) in ONE shared Go package used by Sealer and verifier. No JSON canonicalization on the chain. RFC 8785 (JCS) is used only for `request_fingerprint`.
4. **Grant lifecycle:** TTL ≤ 60 s; single-use enforced gateway-side (grant_id cache) and control-plane-side (duplicate-receipt rejection); control-plane clock authoritative for receipt acceptance. Offline gateway fails closed — no cached allow decisions in V1.
5. **Sealing cadence:** every 5 s or 1,000 events per stream; every epoch root signed.
6. **Schema stays partition-ready:** every unique constraint includes `tenant_id` (future partition key); `action_state` narrow with `fillfactor=80` for HOT updates; partial indexes on hot states and unclaimed timers.

### 20.3 Performance targets (SLOs)

| Metric | Target | Alert |
|---|---|---|
| Allow path submit→grant (server-side) | p50 ≤ 30 ms, p99 ≤ 150 ms | p99 breach sustained 5 min |
| Throughput per region/Postgres | 500 actions/s design point (~2k/s headroom before tenant-home sharding) | queue-claim p99 > 1 s |
| Notification enqueue after decision | ≤ 1 s | — |
| Timer firing accuracy | within 5 s of `fire_at` | > 30 s drift |
| Sealer unsealed-tail age | 99% ≤ 30 s | page at 60 s |
| Bloat | river_job / action_state dead tuples < 20% | vacuum lag growing |

Pre-GA validation: load at 10× design point; chaos runs — kill workers mid-lease, kill the Sealer for 5 min, Postgres failover mid-transaction.

**Status: stack selection is closed at Round 6.** Remaining choices are code-level and should be settled in pull requests, not design rounds.

---

## 21. Round 7 — Competitive Sharpening (post market review, July 2026)

Context: the "action layer" is now a named, funded category — Microsoft Agent Governance Toolkit (April 2026, in-process middleware, 5 SDKs, framework adapters), Microsoft Defender for AI Agents (Jan 2026), Fiddler "AI Control Plane," Galileo, APort/OAP open spec. The surviving thesis is narrower and real: **out-of-process enforcement for closed coding agents (Claude Code / Cursor / Codex), sold bottom-up to engineering teams, with audit attested by keys the vendor doesn't hold.** In-process toolkits categorically cannot reach closed agents — the MCP/tool boundary is the only interception point, and it is exactly what this design does.

### 21.1 Scope cuts (V1 narrows further)

- **Vendor-side execution deleted from V1**: no SaaS-managed integrations, no per-tenant runners, no vendor-side CredentialProvider. Local execution through the customer gateway only. Pitch becomes architectural: customer credentials never exist on the vendor side.
- **Slack-only approvals** (email/webhook stay behind `NotificationPort`, shipped on demand).
- **Single region** (tenant-homing stays designed and schema-ready, unbuilt).

### 21.2 Product additions (adoption is the feature)

1. **MCP proxy auto-wrap**: `gateway init` imports existing `.mcp.json` / Claude Code / Cursor config and re-points every MCP server through the gateway. Zero code changes — the anti-SDK adoption story.
2. **Agent-hooks InboundAdapter** (second adapter): Claude Code PreToolUse-style hooks route non-MCP actions (raw shell, file writes) through the same control plane. MCP alone misses half the dangerous surface of coding agents.
3. **Shadow mode**: observe-only (allow-all policy + full audit) as the default first-run experience; enforcement enabled after a week of real traffic. This is the existing allow path, not the cut dry-run feature.
4. **Policy starter packs** for the coding-agent vertical: prod-DB access, destructive shell classes, `git push --force`, deploys, package publishing, secrets-file reads.

### 21.3 Moat features (what incumbents structurally can't copy)

- **Open audit-chain spec + standalone `verify` CLI ship in V1.** The deterministic encoding and epoch format are published; any skeptic can verify their own export against the vendor-independent signing keys. Competitors' audit is attested by the process/vendor being audited.
- **OAP interop = watch, don't chase.** Adopt OAP-compatible decision receipts when a second real implementation ships; do not block V1 on a v1.0 spec.

### 21.4 Business decisions (recommended, owner: founder)

- **Open-core**: gateway + control-plane core Apache-2.0 (a closed security binary on dev machines won't earn bottom-up trust in 2026); paid = hosted control plane, SSO/SCIM, retention/compliance exports, multi-region.
- **Activation metric**: download → first real action approved in Slack < 15 minutes; onboarding designed backwards from it. New UX SLO: approval request visible in Slack ≤ 5 s after the agent asks.

### 21.5 Explicit non-goals (the incumbents' home turf)

No framework adapters. No OWASP-checklist coverage race. No agent mesh, marketplace, or agent-identity ambitions. No GRC dashboard. General "enterprise AI governance" positioning is a losing battlefield; §18's scope boundary is now a survival constraint, not hygiene.

**Status: Round 7 closes positioning and V1 scope. Next artifact is the repo skeleton (proto schema, core migrations, transition-primitive package), not another review round.**

---

## 22. Round 8 — Differentiation Review (feature triage before freeze)

Ten candidate features evaluated against one test: **does it cash in the architecture's determinism, or dilute it?** Accepted features exploit what the design already paid for (immutable requests, versioned snapshots, deterministic evaluation, shared verifier code). Rejected features would drift the product from deterministic enforcement toward probabilistic advisory — the incumbents' shape.

### Accepted

| Feature | Release | Placement |
|---|---|---|
| Delegation context (`parent_action_id` + chain context on `ActionRequest` and the gateway protocol) | **V1** | Protocol/schema field only — capture forever, build no graph engine. Hard to retrofit; trivial now |
| Explainable decisions (`evaluation_trace` on `PolicyDecision`: which rule, which conditions, what matched) | **V1** | Inside PolicyEngine output. Activation-critical: a blocked developer must see exactly why, or uninstalls |
| Decision memory — exact (`request_fingerprint` "identical action approved N min ago") | **V1** (already spec'd Round 6) | ApprovalService composes into notification payload |
| Decision memory — same (tool, matched_rule) approval history for the approver | V1.5 | Read-only query in ApprovalService. Never similarity/ML |
| Policy simulation/replay ("what would this policy have blocked in 30 days") | **V1.5 — highest-value item** | Read-only `SimulationService` reusing `PolicyEngine.evaluate()` over stored `ActionRequest`s + any `ConfigurationSnapshot`. The shadow-mode → enforcement conversion feature; structurally unavailable to in-process competitors (they retain no immutable request record). Constraint: replays stored `tool_params`, NOT `RedactedActionInputs` — params retention policy must account for this |
| Execution timeline — `gateway timeline <action-id>` CLI | V1.5 | Renders the audit event chain per action. Web version arrives only with the hosted (paid) control plane |
| Browser-based offline audit verifier | V1.5 | Same shared verification package compiled to WASM, static page, strictly offline — a verifier that phones home destroys the claim it proves |
| Vertical policy packs (Git, Docker, K8s, shell, DB) | **V1** (decided Round 7) | Named by capability, updated as signed, versioned pack releases the customer explicitly adopts |

### Rejected

| Feature | Why |
|---|---|
| Risk-scoring engine (0–100) in the decision path | Unexplainable, unreproducible-in-audit enforcement; if made deterministic+versioned it's just rules with extra steps. Fiddler/Galileo's home turf. Upgrades the Round 1 `RiskAssessment` deferral to a rejection. Advisory-to-humans is the only permissible future form |
| Multi-agent graph engine / mesh modeling | AGT "Agent Mesh" territory; §21.5 non-goal. The V1 delegation field preserves the option forever |
| Compliance-branded packs (SOC2, PCI) | GRC marketing motion, wrong buyer, and liability — implies attestations the product cannot deliver. Same rules ship under capability names |
| Security insights / trends dashboard | Already a §21.5 non-goal; the top-down CISO product Fiddler/Arthur/Galileo sell. Reporting only ever as post-PMF paid-tier pull |
| Threat-intel-driven policy updates | A vendor feed auto-changing customer enforcement is a supply-chain attack surface — the exact threat class the product defends against — and contradicts ConfigurationSnapshot semantics (every policy change is a deliberate, versioned, audited act). Defender's telemetry scale wins that game anyway. Only form allowed: signed pack releases, human-reviewed, adopted as normal snapshot versions |

**Feature test for all future proposals, recorded as principle #10: a feature must exploit the system's determinism (replay, explanation, verification), never dilute it (scoring, trends, auto-updates).**

**Status: architecture, stack, positioning, and V1/V1.5 feature line are FROZEN at Round 8. Implementation begins; changes now require evidence from running code or paying customers, not further review rounds.**
