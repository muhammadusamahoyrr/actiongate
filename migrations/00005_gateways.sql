-- Gateway enrollment (plan §15: Enroll). These are auth-plane tables:
-- lookups happen BEFORE a tenant context exists (credential → tenant), so
-- they deliberately do not carry the tenant RLS policy. Secrets are stored
-- hashed only.

-- +goose Up

create table gateways (
    gateway_id      uuid primary key,
    tenant_id       uuid        not null,
    name            text        not null,
    public_key      bytea       not null, -- Ed25519, verifies outcome receipts
    credential_hash bytea       not null unique,
    created_at      timestamptz not null
);

create index gateways_tenant on gateways (tenant_id);

create table enrollment_tokens (
    token_hash bytea primary key,
    tenant_id  uuid        not null,
    expires_at timestamptz not null,
    used_at    timestamptz
);

-- +goose Down

drop table if exists enrollment_tokens;
drop table if exists gateways;
