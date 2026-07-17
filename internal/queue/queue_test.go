package queue

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"

	"actiongate/internal/domain"
	"actiongate/internal/notify"
	"actiongate/internal/testdb"
	"actiongate/internal/transition"
)

func setupPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := testdb.SetupPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatalf("river migrate: %v", err)
	}
	return pool
}

type fixture struct {
	tenantID uuid.UUID
	actionID uuid.UUID
	streamID uuid.UUID
}

func createAction(t *testing.T, pool *pgxpool.Pool) fixture {
	t.Helper()
	ctx := context.Background()
	tenantID := uuid.New()
	if _, err := pool.Exec(ctx,
		`insert into configuration_snapshots (tenant_id, version, content, content_hash, created_by)
		 values ($1, 1, '{}', '\x00', 'test')`, tenantID); err != nil {
		t.Fatalf("tenant fixture: %v", err)
	}
	res, err := transition.Create(ctx, pool, transition.CreateRequest{
		TenantID:        tenantID,
		AgentID:         "agent-1",
		SessionID:       uuid.New(),
		NativeRequestID: "req-1",
		ToolName:        "bash",
		ToolParams:      []byte(`{"command":"ls"}`),
		Environment:     "test",
		PolicyVersion:   1,
		StreamID:        uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return fixture{tenantID: tenantID, actionID: res.ActionID,
		streamID: uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")}
}

func advance(t *testing.T, pool *pgxpool.Pool, f fixture, from, to domain.State, version int32, effects ...transition.Effect) {
	t.Helper()
	err := transition.Apply(context.Background(), pool, transition.Request{
		TenantID: f.tenantID, ActionID: f.actionID,
		From: from, To: to, ExpectedVersion: version,
		Event: transition.Event{
			StreamID:   f.streamID,
			Type:       domain.EventPolicyEvaluated,
			AttestedBy: domain.AttestedByControlPlane,
		},
		Effects: effects,
	})
	if err != nil {
		t.Fatalf("advance %s->%s: %v", from, to, err)
	}
}

func countJobs(t *testing.T, pool *pgxpool.Pool, kind string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`select count(*) from river_job where kind = $1`, kind).Scan(&n); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	return n
}

func countEvents(t *testing.T, pool *pgxpool.Pool, f fixture, eventType domain.EventType) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`select count(*) from audit_events
		  where tenant_id = $1 and action_request_id = $2 and event_type = $3`,
		f.tenantID, f.actionID, string(eventType)).Scan(&n); err != nil {
		t.Fatalf("count events: %v", err)
	}
	return n
}

func insertApprovalRow(f fixture, approvalID uuid.UUID, expiresAt time.Time) transition.Effect {
	return func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`insert into approval_requests
			    (id, tenant_id, action_request_id, approver_target, status, version, expires_at, created_at)
			 values ($1, $2, $3, 'team-lead', 'pending', 0, $4, now())`,
			approvalID, f.tenantID, f.actionID, expiresAt)
		return err
	}
}

func TestQueue(t *testing.T) {
	pool := setupPool(t)
	ctx := context.Background()

	insertClient, err := NewInsertOnlyClient(pool)
	if err != nil {
		t.Fatalf("insert-only client: %v", err)
	}

	t.Run("enqueue rolls back with the transition", func(t *testing.T) {
		f := createAction(t, pool)
		boom := errors.New("effect failed")
		err := transition.Apply(ctx, pool, transition.Request{
			TenantID: f.tenantID, ActionID: f.actionID,
			From: domain.StateCreated, To: domain.StateEvaluated, ExpectedVersion: 0,
			Event: transition.Event{
				StreamID: f.streamID, Type: domain.EventPolicyEvaluated,
				AttestedBy: domain.AttestedByControlPlane,
			},
			Effects: []transition.Effect{
				InsertJobEffect(insertClient, OutcomeDeadlineArgs{
					TenantID: f.tenantID, ActionID: f.actionID, StreamID: f.streamID,
				}, nil),
				func(ctx context.Context, tx pgx.Tx) error { return boom },
			},
		})
		if !errors.Is(err, boom) {
			t.Fatalf("want effect error, got %v", err)
		}
		if got := countJobs(t, pool, "outcome_deadline"); got != 0 {
			t.Fatalf("job survived a rolled-back transition: %d rows — outbox guarantee broken", got)
		}
	})

	t.Run("approval expiry fires end to end", func(t *testing.T) {
		f := createAction(t, pool)
		approvalID := uuid.New()
		advance(t, pool, f, domain.StateCreated, domain.StateEvaluated, 0)
		// The approval row and its expiry timer are created atomically with
		// the PendingApproval transition (plan round 5 fix 2).
		advance(t, pool, f, domain.StateEvaluated, domain.StatePendingApproval, 1,
			insertApprovalRow(f, approvalID, time.Now().Add(time.Second)),
			InsertJobEffect(insertClient, ApprovalExpiryArgs{
				TenantID: f.tenantID, ActionID: f.actionID,
				ApprovalRequestID: approvalID, StreamID: f.streamID,
			}, &river.InsertOpts{ScheduledAt: time.Now().Add(time.Second)}),
		)

		workers, err := NewWorkers(pool, notify.LogPort{})
		if err != nil {
			t.Fatalf("NewWorkers: %v", err)
		}
		client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
			Queues:  map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 2}},
			Workers: workers,
		})
		if err != nil {
			t.Fatalf("river client: %v", err)
		}
		if err := client.Start(ctx); err != nil {
			t.Fatalf("client start: %v", err)
		}
		defer func() { _ = client.Stop(ctx) }()

		deadline := time.Now().Add(30 * time.Second)
		for {
			state, _, err := transition.CurrentState(ctx, pool, f.tenantID, f.actionID)
			if err != nil {
				t.Fatalf("CurrentState: %v", err)
			}
			if state == domain.StateExpired {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("action never expired; still %s", state)
			}
			time.Sleep(200 * time.Millisecond)
		}

		if got := countEvents(t, pool, f, domain.EventApprovalExpired); got != 1 {
			t.Fatalf("ApprovalExpired events = %d, want 1", got)
		}
		var status string
		var version int32
		if err := pool.QueryRow(ctx,
			`select status, version from approval_requests where id = $1`,
			approvalID).Scan(&status, &version); err != nil {
			t.Fatalf("read approval: %v", err)
		}
		if status != "expired" || version != 1 {
			t.Fatalf("approval row = (%s, v%d), want (expired, v1)", status, version)
		}
	})

	t.Run("expiry no-ops when the approval was already resolved", func(t *testing.T) {
		f := createAction(t, pool)
		advance(t, pool, f, domain.StateCreated, domain.StateEvaluated, 0)
		w := &ApprovalExpiryWorker{Pool: pool}
		err := w.Work(ctx, &river.Job[ApprovalExpiryArgs]{Args: ApprovalExpiryArgs{
			TenantID: f.tenantID, ActionID: f.actionID,
			ApprovalRequestID: uuid.New(), StreamID: f.streamID,
		}})
		if err != nil {
			t.Fatalf("late timer must no-op, got %v", err)
		}
		if got := countEvents(t, pool, f, domain.EventApprovalExpired); got != 0 {
			t.Fatalf("no-op timer wrote %d events", got)
		}
	})

	t.Run("outcome deadline marks a silent execution unknown", func(t *testing.T) {
		f := createAction(t, pool)
		advance(t, pool, f, domain.StateCreated, domain.StateEvaluated, 0)
		advance(t, pool, f, domain.StateEvaluated, domain.StateExecutionAuthorized, 1)
		w := &OutcomeDeadlineWorker{Pool: pool}
		err := w.Work(ctx, &river.Job[OutcomeDeadlineArgs]{Args: OutcomeDeadlineArgs{
			TenantID: f.tenantID, ActionID: f.actionID, StreamID: f.streamID,
		}})
		if err != nil {
			t.Fatalf("Work: %v", err)
		}
		state, _, err := transition.CurrentState(ctx, pool, f.tenantID, f.actionID)
		if err != nil {
			t.Fatalf("CurrentState: %v", err)
		}
		if state != domain.StateOutcomeUnknown {
			t.Fatalf("state = %s, want OutcomeUnknown", state)
		}
		if got := countEvents(t, pool, f, domain.EventOutcomeUnknown); got != 1 {
			t.Fatalf("OutcomeUnknown events = %d, want 1", got)
		}
	})

	t.Run("outcome deadline no-ops when a receipt won the race", func(t *testing.T) {
		f := createAction(t, pool)
		advance(t, pool, f, domain.StateCreated, domain.StateEvaluated, 0)
		advance(t, pool, f, domain.StateEvaluated, domain.StateExecutionAuthorized, 1)
		advance(t, pool, f, domain.StateExecutionAuthorized, domain.StateExecuting, 2)
		advance(t, pool, f, domain.StateExecuting, domain.StateSucceeded, 3)
		w := &OutcomeDeadlineWorker{Pool: pool}
		err := w.Work(ctx, &river.Job[OutcomeDeadlineArgs]{Args: OutcomeDeadlineArgs{
			TenantID: f.tenantID, ActionID: f.actionID, StreamID: f.streamID,
		}})
		if err != nil {
			t.Fatalf("late deadline must no-op, got %v", err)
		}
		if got := countEvents(t, pool, f, domain.EventOutcomeUnknown); got != 0 {
			t.Fatalf("no-op deadline wrote %d events", got)
		}
	})

	t.Run("notification worker delivers through the port", func(t *testing.T) {
		rec := &recordingPort{}
		w := &DeliverApprovalWorker{Port: rec}
		args := DeliverApprovalArgs{
			TenantID: uuid.New(), ActionID: uuid.New(), ApprovalRequestID: uuid.New(),
			ApproverTarget: "team-lead", Title: "Approve rm -rf?", Body: "agent-1 wants bash",
			CallbackToken: "cb-" + uuid.NewString(),
		}
		if err := w.Work(ctx, &river.Job[DeliverApprovalArgs]{Args: args}); err != nil {
			t.Fatalf("Work: %v", err)
		}
		rec.mu.Lock()
		defer rec.mu.Unlock()
		if len(rec.sent) != 1 {
			t.Fatalf("messages sent = %d, want 1", len(rec.sent))
		}
		got := rec.sent[0]
		if got.ApproverTarget != "team-lead" || got.CallbackToken != args.CallbackToken ||
			got.ActionID != args.ActionID {
			t.Fatalf("message mangled in delivery: %+v", got)
		}
	})
}

type recordingPort struct {
	mu   sync.Mutex
	sent []notify.Message
}

func (p *recordingPort) Send(_ context.Context, msg notify.Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sent = append(p.sent, msg)
	return nil
}
