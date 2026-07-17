-- The signed GrantEnvelope is stored verbatim: signatures cover the exact
-- serialized bytes (plan §20.2, sign-raw-bytes decision), so the envelope
-- can never be re-derived from row data — it must be kept.

-- +goose Up

alter table execution_grants add column grant_envelope bytea not null;

-- +goose Down

alter table execution_grants drop column grant_envelope;
