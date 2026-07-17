-- Core schema. Design authority: plan.md.txt §4 (domain model), §20.2 (index
-- and transaction rules). Every unique constraint includes tenant_id — the
-- future partition/shard key. River's queue tables are managed separately by
-- `river migrate-up`.

-- +goose Up

create table configuration_snapshots (
    tenant_id    uuid        not null,
    version      bigint      not null,
    content      jsonb       not null,
    content_hash bytea       not null,
    created_by   text        not null,
    created_at   timestamptz not null default now(),
    primary key (tenant_id, version)
);

create table action_requests (
    id                       uuid primary key,
    tenant_id                uuid        not null,
    agent_id                 text        not null,
    session_id               uuid        not null,
    idempotency_key          bytea       not null,
    request_fingerprint      bytea       not null,
    tool_name                text        not null,
    tool_params              jsonb       not null,
    environment              text        not null,
    correlation_id           uuid,
    parent_action_id         uuid references action_requests (id),
    policy_version_evaluated bigint      not null,
    created_at               timestamptz not null,
    unique (tenant_id, idempotency_key),
    foreign key (tenant_id, policy_version_evaluated)
        references configuration_snapshots (tenant_id, version)
);

create index action_requests_fingerprint
    on action_requests (tenant_id, request_fingerprint, created_at);

-- The single legitimately mutable row per action; changed only via
-- compare-and-swap on version inside the transition primitive.
-- fillfactor 80 keeps CAS updates HOT (plan §20.2.6).
create table action_state (
    action_request_id uuid primary key references action_requests (id),
    tenant_id         uuid        not null,
    state             text        not null,
    version           integer     not null default 0,
    lease_owner       text,
    lease_expires_at  timestamptz,
    updated_at        timestamptz not null
) with (fillfactor = 80);

create index action_state_hot
    on action_state (tenant_id)
    where state in ('PendingApproval', 'ExecutionAuthorized', 'Executing');

create table policy_decisions (
    id                uuid primary key,
    tenant_id         uuid        not null,
    action_request_id uuid        not null references action_requests (id),
    decision          text        not null
        check (decision in ('allow', 'deny', 'requires_approval')),
    risk_classification text      not null,
    matched_rule_id   text        not null,
    evaluation_trace  jsonb       not null default '{}',
    policy_version    bigint      not null,
    evaluated_at      timestamptz not null
);

create index policy_decisions_action
    on policy_decisions (tenant_id, action_request_id);

create table approval_requests (
    id                uuid primary key,
    tenant_id         uuid        not null,
    action_request_id uuid        not null references action_requests (id),
    approver_target   text        not null,
    status            text        not null default 'pending'
        check (status in ('pending', 'approved', 'denied', 'expired', 'cancelled')),
    version           integer     not null default 0,
    expires_at        timestamptz not null,
    created_at        timestamptz not null
);

create index approval_requests_action
    on approval_requests (tenant_id, action_request_id);

-- Tokens are stored hashed; the raw HMAC-signed token exists only in the
-- delivered notification (plan §9).
create table approval_callback_tokens (
    token_hash          bytea primary key,
    tenant_id           uuid        not null,
    approval_request_id uuid        not null references approval_requests (id),
    expires_at          timestamptz not null,
    used_at             timestamptz
);

create table approval_decisions (
    id                  uuid primary key,
    tenant_id           uuid        not null,
    approval_request_id uuid        not null references approval_requests (id),
    approver_id         text        not null,
    decision            text        not null check (decision in ('approved', 'denied')),
    reason              text,
    decided_at          timestamptz not null
);

create table redacted_action_inputs (
    id                uuid primary key,
    tenant_id         uuid        not null,
    action_request_id uuid        not null references action_requests (id),
    redacted_params   jsonb       not null,
    created_at        timestamptz not null
);

create table execution_grants (
    grant_id          uuid primary key,
    tenant_id         uuid        not null,
    action_request_id uuid        not null references action_requests (id),
    params_hash       bytea       not null,
    key_id            text        not null,
    expires_at        timestamptz not null,
    issued_at         timestamptz not null,
    receipt_received_at timestamptz
);

create index execution_grants_outstanding
    on execution_grants (tenant_id, expires_at)
    where receipt_received_at is null;

create table action_results (
    action_request_id uuid primary key references action_requests (id),
    tenant_id         uuid        not null,
    status            text        not null
        check (status in ('succeeded', 'failed', 'partially_succeeded', 'outcome_unknown')),
    output_ref        text,
    error             text,
    side_effects      jsonb       not null default '[]',
    started_at        timestamptz,
    completed_at      timestamptz,
    receipt_signature bytea
);

create table reconciliation_results (
    action_request_id uuid primary key references action_requests (id),
    tenant_id         uuid        not null,
    operator_id       text        not null,
    verified_outcome  text        not null,
    evidence_ref      text,
    reconciled_at     timestamptz not null
);

-- Hot-path appends carry NO sequence_number/hash — the background Sealer
-- assigns them in ingest_seq order below a snapshot-horizon watermark
-- (plan §20.2.2). ingest_seq is a physical ordering aid, never the
-- tamper-evident sequence.
create table audit_events (
    id                  uuid primary key,
    tenant_id           uuid        not null,
    stream_id           uuid        not null,
    ingest_seq          bigint      generated always as identity,
    action_request_id   uuid references action_requests (id),
    event_type          text        not null,
    attested_by         text        not null,
    metadata            jsonb       not null default '{}',
    decision_ref        uuid,
    redacted_inputs_ref uuid,
    refs                jsonb,
    recorded_at         timestamptz not null,
    -- Sealer-assigned (each set exactly once, from null; enforced by trigger):
    sequence_number     bigint,
    previous_hash       bytea,
    event_hash          bytea,
    epoch_id            uuid
);

create unique index audit_events_stream_seq
    on audit_events (tenant_id, stream_id, sequence_number)
    where sequence_number is not null;

create index audit_events_stream_ingest
    on audit_events (tenant_id, stream_id, ingest_seq);

create index audit_events_unsealed
    on audit_events (tenant_id, stream_id, ingest_seq)
    where epoch_id is null;

create index audit_events_action
    on audit_events (tenant_id, action_request_id);

create table audit_epochs (
    epoch_id        uuid primary key,
    tenant_id       uuid        not null,
    stream_id       uuid        not null,
    first_sequence  bigint      not null,
    last_sequence   bigint      not null,
    root_hash       bytea       not null,
    prev_epoch_root bytea,
    signature       bytea       not null,
    key_id          text        not null,
    anchored_at     timestamptz,
    sealed_at       timestamptz not null,
    unique (tenant_id, stream_id, first_sequence)
);

-- +goose Down

drop table if exists audit_epochs;
drop table if exists audit_events;
drop table if exists reconciliation_results;
drop table if exists action_results;
drop table if exists execution_grants;
drop table if exists redacted_action_inputs;
drop table if exists approval_decisions;
drop table if exists approval_callback_tokens;
drop table if exists approval_requests;
drop table if exists policy_decisions;
drop table if exists action_state;
drop index if exists action_requests_fingerprint;
drop table if exists action_requests;
drop table if exists configuration_snapshots;
