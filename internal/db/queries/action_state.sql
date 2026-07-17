-- name: GetActionState :one
select action_request_id, tenant_id, state, version, lease_owner, lease_expires_at, updated_at
from action_state
where action_request_id = $1;

-- name: GetActionRequestByIdempotencyKey :one
select id, tenant_id, request_fingerprint, created_at
from action_requests
where tenant_id = $1 and idempotency_key = $2;

-- name: ListUnsealedAuditEvents :many
select id, tenant_id, stream_id, ingest_seq, action_request_id, event_type,
       attested_by, metadata, recorded_at
from audit_events
where tenant_id = $1 and stream_id = $2 and epoch_id is null and ingest_seq <= $3
order by ingest_seq;
