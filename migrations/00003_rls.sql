-- Row-Level Security as defense-in-depth (plan §20.1): a query missing its
-- tenant_id predicate returns nothing instead of leaking across tenants.
-- The application sets `app.tenant_id` per transaction via
-- set_config('app.tenant_id', ..., true). The application role must NOT be
-- a superuser or table owner, or RLS is bypassed.

-- +goose Up

alter table configuration_snapshots  enable row level security;
alter table configuration_snapshots  force row level security;
alter table action_requests          enable row level security;
alter table action_requests          force row level security;
alter table action_state             enable row level security;
alter table action_state             force row level security;
alter table policy_decisions         enable row level security;
alter table policy_decisions         force row level security;
alter table approval_requests        enable row level security;
alter table approval_requests        force row level security;
alter table approval_callback_tokens enable row level security;
alter table approval_callback_tokens force row level security;
alter table approval_decisions       enable row level security;
alter table approval_decisions       force row level security;
alter table redacted_action_inputs   enable row level security;
alter table redacted_action_inputs   force row level security;
alter table execution_grants         enable row level security;
alter table execution_grants         force row level security;
alter table action_results           enable row level security;
alter table action_results           force row level security;
alter table reconciliation_results   enable row level security;
alter table reconciliation_results   force row level security;
alter table audit_events             enable row level security;
alter table audit_events             force row level security;
alter table audit_epochs             enable row level security;
alter table audit_epochs             force row level security;

create policy tenant_isolation on configuration_snapshots
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on action_requests
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on action_state
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on policy_decisions
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on approval_requests
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on approval_callback_tokens
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on approval_decisions
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on redacted_action_inputs
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on execution_grants
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on action_results
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on reconciliation_results
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on audit_events
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);
create policy tenant_isolation on audit_epochs
    using (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- +goose Down

drop policy if exists tenant_isolation on audit_epochs;
drop policy if exists tenant_isolation on audit_events;
drop policy if exists tenant_isolation on reconciliation_results;
drop policy if exists tenant_isolation on action_results;
drop policy if exists tenant_isolation on execution_grants;
drop policy if exists tenant_isolation on redacted_action_inputs;
drop policy if exists tenant_isolation on approval_decisions;
drop policy if exists tenant_isolation on approval_callback_tokens;
drop policy if exists tenant_isolation on approval_requests;
drop policy if exists tenant_isolation on policy_decisions;
drop policy if exists tenant_isolation on action_state;
drop policy if exists tenant_isolation on action_requests;
drop policy if exists tenant_isolation on configuration_snapshots;

alter table audit_epochs             disable row level security;
alter table audit_events             disable row level security;
alter table reconciliation_results   disable row level security;
alter table action_results           disable row level security;
alter table execution_grants         disable row level security;
alter table redacted_action_inputs   disable row level security;
alter table approval_decisions       disable row level security;
alter table approval_callback_tokens disable row level security;
alter table approval_requests        disable row level security;
alter table policy_decisions         disable row level security;
alter table action_state             disable row level security;
alter table action_requests          disable row level security;
alter table configuration_snapshots  disable row level security;
