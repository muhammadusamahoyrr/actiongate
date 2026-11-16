-- Sealed epochs are append-only, like the events they cover (audit H8).
-- Deleting the newest epochs used to leave a shorter chain that still
-- verified; now the database refuses, and verify also flags sealed events
-- whose epoch is gone. anchored_at stays writable once, from null, for an
-- external anchoring step; nothing else in an epoch row may change.

-- +goose Up

-- +goose StatementBegin
create function audit_epochs_guard() returns trigger
language plpgsql as $$
begin
    if tg_op = 'DELETE' then
        raise exception 'audit_epochs is append-only; DELETE is not permitted';
    end if;
    if old.anchored_at is not null
        or new.epoch_id is distinct from old.epoch_id
        or new.tenant_id is distinct from old.tenant_id
        or new.stream_id is distinct from old.stream_id
        or new.first_sequence is distinct from old.first_sequence
        or new.last_sequence is distinct from old.last_sequence
        or new.root_hash is distinct from old.root_hash
        or new.prev_epoch_root is distinct from old.prev_epoch_root
        or new.signature is distinct from old.signature
        or new.key_id is distinct from old.key_id
        or new.sealed_at is distinct from old.sealed_at
    then
        raise exception 'audit epoch % is immutable; only anchored_at may be set, once', old.epoch_id;
    end if;
    return new;
end;
$$;
-- +goose StatementEnd

create trigger audit_epochs_guard
    before update or delete on audit_epochs
    for each row execute function audit_epochs_guard();

create trigger audit_epochs_no_truncate
    before truncate on audit_epochs
    for each statement execute function reject_mutation();

create trigger audit_events_no_truncate
    before truncate on audit_events
    for each statement execute function reject_mutation();

-- +goose Down

drop trigger if exists audit_events_no_truncate on audit_events;
drop trigger if exists audit_epochs_no_truncate on audit_epochs;
drop trigger if exists audit_epochs_guard on audit_epochs;
drop function if exists audit_epochs_guard();
