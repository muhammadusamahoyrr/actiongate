package transition

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"actiongate/internal/domain"
	"actiongate/internal/testdb"
)

// The suite runs against real Postgres: the primitives under test (CAS,
// unique constraints, trigger guards, transactional atomicity) do not exist
// in mocks (plan §20.1: Testing).

func setupPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return testdb.SetupPool(t)
}

type fixture struct {
	tenantID uuid.UUID
	actionID uuid.UUID
	streamID uuid.UUID
}

func createAction(t *testing.T, pool *pgxpool.Pool) fixture {
	t.Helper()
	ctx := context.Background()
	f := fixture{
		tenantID: uuid.New(),
		actionID: uuid.New(),
		streamID: uuid.New(),
	}
	now := time.Now().UTC()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin fixture tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	mustExec(t, tx,
		`insert into configuration_snapshots (tenant_id, version, content, content_hash, created_by)
		 values ($1, 1, '{}', '\x00', 'test')`,
		f.tenantID)
	mustExec(t, tx,
		`insert into action_requests
		    (id, tenant_id, agent_id, session_id, idempotency_key, request_fingerprint,
		     tool_name, tool_params, environment, policy_version_evaluated, created_at)
		 values ($1, $2, 'agent-1', $3, $4, $5, 'bash', '{}', 'test', 1, $6)`,
		f.actionID, f.tenantID, uuid.New(), f.actionID[:], f.actionID[:], now)
	mustExec(t, tx,
		`insert into action_state (action_request_id, tenant_id, state, version, updated_at)
		 values ($1, $2, $3, 0, $4)`,
		f.actionID, f.tenantID, string(domain.StateCreated), now)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit fixture: %v", err)
	}
	return f
}

func mustExec(t *testing.T, tx pgx.Tx, sqlText string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(context.Background(), sqlText, args...); err != nil {
		t.Fatalf("fixture exec: %v\nsql: %s", err, sqlText)
	}
}

func evaluatedEvent(streamID uuid.UUID) Event {
	return Event{
		StreamID:   streamID,
		Type:       domain.EventPolicyEvaluated,
		AttestedBy: domain.AttestedByControlPlane,
		Metadata:   map[string]any{"decision": "allow"},
	}
}

func TestTransitionPrimitive(t *testing.T) {
	pool := setupPool(t)
	ctx := context.Background()

	t.Run("happy path writes state and audit atomically", func(t *testing.T) {
		f := createAction(t, pool)
		err := Apply(ctx, pool, Request{
			TenantID: f.tenantID, ActionID: f.actionID,
			From: domain.StateCreated, To: domain.StateEvaluated,
			ExpectedVersion: 0,
			Event:           evaluatedEvent(f.streamID),
		})
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		assertState(t, pool, f, domain.StateEvaluated, 1)
		assertEventCount(t, pool, f, string(domain.EventPolicyEvaluated), 1)
	})

	t.Run("invalid transition rejected before any write", func(t *testing.T) {
		f := createAction(t, pool)
		err := Apply(ctx, pool, Request{
			TenantID: f.tenantID, ActionID: f.actionID,
			From: domain.StateCreated, To: domain.StateExecuting, // not in §7 table
			ExpectedVersion: 0,
			Event:           evaluatedEvent(f.streamID),
		})
		if !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("want ErrInvalidTransition, got %v", err)
		}
		assertState(t, pool, f, domain.StateCreated, 0)
		assertEventCount(t, pool, f, string(domain.EventPolicyEvaluated), 0)
	})

	t.Run("version conflict loses the race, writes nothing", func(t *testing.T) {
		f := createAction(t, pool)
		first := Apply(ctx, pool, Request{
			TenantID: f.tenantID, ActionID: f.actionID,
			From: domain.StateCreated, To: domain.StateEvaluated,
			ExpectedVersion: 0,
			Event:           evaluatedEvent(f.streamID),
		})
		if first != nil {
			t.Fatalf("first Apply: %v", first)
		}
		second := Apply(ctx, pool, Request{
			TenantID: f.tenantID, ActionID: f.actionID,
			From: domain.StateCreated, To: domain.StateEvaluated,
			ExpectedVersion: 0, // stale
			Event:           evaluatedEvent(f.streamID),
		})
		if !errors.Is(second, ErrInvalidTransition) && !errors.Is(second, ErrVersionConflict) {
			t.Fatalf("want conflict error, got %v", second)
		}
		assertState(t, pool, f, domain.StateEvaluated, 1)
		assertEventCount(t, pool, f, string(domain.EventPolicyEvaluated), 1)
	})

	t.Run("failed effect rolls back state and audit together", func(t *testing.T) {
		f := createAction(t, pool)
		boom := errors.New("effect failed")
		err := Apply(ctx, pool, Request{
			TenantID: f.tenantID, ActionID: f.actionID,
			From: domain.StateCreated, To: domain.StateEvaluated,
			ExpectedVersion: 0,
			Event:           evaluatedEvent(f.streamID),
			Effects: []Effect{
				func(ctx context.Context, tx pgx.Tx) error { return boom },
			},
		})
		if !errors.Is(err, boom) {
			t.Fatalf("want effect error, got %v", err)
		}
		assertState(t, pool, f, domain.StateCreated, 0)
		assertEventCount(t, pool, f, string(domain.EventPolicyEvaluated), 0)
	})

	t.Run("audit events cannot be deleted or rewritten", func(t *testing.T) {
		f := createAction(t, pool)
		if err := Apply(ctx, pool, Request{
			TenantID: f.tenantID, ActionID: f.actionID,
			From: domain.StateCreated, To: domain.StateEvaluated,
			ExpectedVersion: 0,
			Event:           evaluatedEvent(f.streamID),
		}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`delete from audit_events where tenant_id = $1`, f.tenantID); err == nil {
			t.Fatal("DELETE on audit_events succeeded; append-only guard missing")
		}
		if _, err := pool.Exec(ctx,
			`update audit_events set event_type = 'Tampered' where tenant_id = $1`,
			f.tenantID); err == nil {
			t.Fatal("content UPDATE on audit_events succeeded; immutability guard missing")
		}
	})

	t.Run("invalid attempt is recordable as a security signal", func(t *testing.T) {
		f := createAction(t, pool)
		err := RecordInvalidAttempt(ctx, pool, f.tenantID, f.actionID, f.streamID,
			domain.StateCreated, domain.StateExecuting)
		if err != nil {
			t.Fatalf("RecordInvalidAttempt: %v", err)
		}
		assertEventCount(t, pool, f, string(domain.EventInvalidTransitionAttempted), 1)
	})
}

func assertState(t *testing.T, pool *pgxpool.Pool, f fixture, want domain.State, wantVersion int32) {
	t.Helper()
	var state string
	var version int32
	err := pool.QueryRow(context.Background(),
		`select state, version from action_state where action_request_id = $1`,
		f.actionID).Scan(&state, &version)
	if err != nil {
		t.Fatalf("read action_state: %v", err)
	}
	if domain.State(state) != want || version != wantVersion {
		t.Fatalf("action_state = (%s, v%d), want (%s, v%d)", state, version, want, wantVersion)
	}
}

func assertEventCount(t *testing.T, pool *pgxpool.Pool, f fixture, eventType string, want int) {
	t.Helper()
	var got int
	err := pool.QueryRow(context.Background(),
		`select count(*) from audit_events
		  where tenant_id = $1 and action_request_id = $2 and event_type = $3`,
		f.tenantID, f.actionID, eventType).Scan(&got)
	if err != nil {
		t.Fatalf("count audit_events: %v", err)
	}
	if got != want {
		t.Fatalf("%s events = %d, want %d", eventType, got, want)
	}
}
