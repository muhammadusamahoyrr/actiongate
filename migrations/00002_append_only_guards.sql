-- Append-only enforcement at the database layer (plan §12: stated explicitly
-- so no future contributor "helpfully" adds a delete path to the audit trail).

-- +goose Up

-- +goose StatementBegin
create function reject_mutation() returns trigger
language plpgsql as $$
begin
    raise exception '% is append-only; % is not permitted', tg_table_name, tg_op;
end;
$$;
-- +goose StatementEnd

create trigger action_requests_append_only
    before update or delete on action_requests
    for each row execute function reject_mutation();

create trigger configuration_snapshots_append_only
    before update or delete on configuration_snapshots
    for each row execute function reject_mutation();

-- Audit events: DELETE never; UPDATE only to set the sealing columns
-- (sequence_number, previous_hash, event_hash, epoch_id) exactly once,
-- with every content column bit-identical.
-- +goose StatementBegin
create function audit_events_guard() returns trigger
language plpgsql as $$
begin
    if tg_op = 'DELETE' then
        raise exception 'audit_events is append-only; DELETE is not permitted';
    end if;
    if old.sequence_number is not null then
        raise exception 'audit event % is sealed and immutable', old.id;
    end if;
    if new.id is distinct from old.id
        or new.tenant_id is distinct from old.tenant_id
        or new.stream_id is distinct from old.stream_id
        or new.ingest_seq is distinct from old.ingest_seq
        or new.action_request_id is distinct from old.action_request_id
        or new.event_type is distinct from old.event_type
        or new.attested_by is distinct from old.attested_by
        or new.metadata is distinct from old.metadata
        or new.decision_ref is distinct from old.decision_ref
        or new.redacted_inputs_ref is distinct from old.redacted_inputs_ref
        or new.refs is distinct from old.refs
        or new.recorded_at is distinct from old.recorded_at
    then
        raise exception 'audit event content is immutable; only sealing columns may be set';
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

create trigger audit_events_guard
    before update or delete on audit_events
    for each row execute function audit_events_guard();

-- +goose Down

drop trigger if exists audit_events_guard on audit_events;
drop function if exists audit_events_guard();
drop trigger if exists configuration_snapshots_append_only on configuration_snapshots;
drop trigger if exists action_requests_append_only on action_requests;
drop function if exists reject_mutation();
