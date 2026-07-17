package transition

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"actiongate/internal/domain"
)

func createTenant(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	tenantID := uuid.New()
	_, err := pool.Exec(context.Background(),
		`insert into configuration_snapshots (tenant_id, version, content, content_hash, created_by)
		 values ($1, 1, '{}', '\x00', 'test')`,
		tenantID)
	if err != nil {
		t.Fatalf("create tenant fixture: %v", err)
	}
	return tenantID
}

func baseCreateRequest(tenantID uuid.UUID) CreateRequest {
	return CreateRequest{
		TenantID:        tenantID,
		AgentID:         "agent-1",
		SessionID:       uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		NativeRequestID: "mcp-req-1",
		ToolName:        "bash",
		ToolParams:      []byte(`{"command":"ls"}`),
		Environment:     "test",
		PolicyVersion:   1,
		StreamID:        uuid.MustParse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
	}
}

func countEvents(t *testing.T, pool *pgxpool.Pool, tenantID, actionID uuid.UUID, eventType domain.EventType) int {
	t.Helper()
	var n int
	err := pool.QueryRow(context.Background(),
		`select count(*) from audit_events
		  where tenant_id = $1 and action_request_id = $2 and event_type = $3`,
		tenantID, actionID, string(eventType)).Scan(&n)
	if err != nil {
		t.Fatalf("count events: %v", err)
	}
	return n
}

func TestIdempotentCreate(t *testing.T) {
	pool := setupPool(t)
	ctx := context.Background()

	t.Run("fresh create writes request, state, and event atomically", func(t *testing.T) {
		tenantID := createTenant(t, pool)
		res, err := Create(ctx, pool, baseCreateRequest(tenantID))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if !res.Created || res.State != domain.StateCreated || res.Version != 0 {
			t.Fatalf("unexpected result: %+v", res)
		}
		if got := countEvents(t, pool, tenantID, res.ActionID, domain.EventActionCreated); got != 1 {
			t.Fatalf("ActionCreated events = %d, want 1", got)
		}
	})

	t.Run("exact retry returns the same workflow, writes nothing", func(t *testing.T) {
		tenantID := createTenant(t, pool)
		first, err := Create(ctx, pool, baseCreateRequest(tenantID))
		if err != nil {
			t.Fatalf("first Create: %v", err)
		}
		second, err := Create(ctx, pool, baseCreateRequest(tenantID))
		if err != nil {
			t.Fatalf("retry Create: %v", err)
		}
		if second.Created {
			t.Fatal("retry reported Created=true")
		}
		if second.ActionID != first.ActionID {
			t.Fatalf("retry returned different action: %s vs %s", second.ActionID, first.ActionID)
		}
		if got := countEvents(t, pool, tenantID, first.ActionID, domain.EventActionCreated); got != 1 {
			t.Fatalf("ActionCreated events after retry = %d, want 1", got)
		}
	})

	t.Run("retry resumes at the workflow's current state, not Created", func(t *testing.T) {
		tenantID := createTenant(t, pool)
		first, err := Create(ctx, pool, baseCreateRequest(tenantID))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := Apply(ctx, pool, Request{
			TenantID: tenantID, ActionID: first.ActionID,
			From: domain.StateCreated, To: domain.StateEvaluated,
			ExpectedVersion: 0,
			Event: Event{
				StreamID:   baseCreateRequest(tenantID).StreamID,
				Type:       domain.EventPolicyEvaluated,
				AttestedBy: domain.AttestedByControlPlane,
			},
		}); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		retry, err := Create(ctx, pool, baseCreateRequest(tenantID))
		if err != nil {
			t.Fatalf("retry Create: %v", err)
		}
		if retry.State != domain.StateEvaluated || retry.Version != 1 {
			t.Fatalf("retry state = (%s, v%d), want (Evaluated, v1)", retry.State, retry.Version)
		}
	})

	t.Run("same key with different content is refused and audited", func(t *testing.T) {
		tenantID := createTenant(t, pool)
		first, err := Create(ctx, pool, baseCreateRequest(tenantID))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		altered := baseCreateRequest(tenantID)
		altered.ToolParams = []byte(`{"command":"rm -rf /"}`)
		_, err = Create(ctx, pool, altered)
		if !errors.Is(err, ErrIdempotencyConflict) {
			t.Fatalf("want ErrIdempotencyConflict, got %v", err)
		}
		if got := countEvents(t, pool, tenantID, first.ActionID, domain.EventIdempotencyConflict); got != 1 {
			t.Fatalf("IdempotencyConflict events = %d, want 1", got)
		}
		// The conflicting content must not have replaced the original.
		var storedTool string
		var storedParams []byte
		err = pool.QueryRow(ctx,
			`select tool_name, tool_params from action_requests where id = $1`,
			first.ActionID).Scan(&storedTool, &storedParams)
		if err != nil {
			t.Fatalf("read stored request: %v", err)
		}
		if string(storedParams) != `{"command": "ls"}` && string(storedParams) != `{"command":"ls"}` {
			t.Fatalf("stored params changed: %s", storedParams)
		}
	})

	t.Run("same native request id in different sessions creates distinct actions", func(t *testing.T) {
		tenantID := createTenant(t, pool)
		first, err := Create(ctx, pool, baseCreateRequest(tenantID))
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		otherSession := baseCreateRequest(tenantID)
		otherSession.SessionID = uuid.New()
		second, err := Create(ctx, pool, otherSession)
		if err != nil {
			t.Fatalf("Create in second session: %v", err)
		}
		if !second.Created || second.ActionID == first.ActionID {
			t.Fatalf("second session did not get a distinct action: %+v", second)
		}
	})

	t.Run("concurrent creates with the same key resolve to one action", func(t *testing.T) {
		tenantID := createTenant(t, pool)
		const racers = 8
		results := make([]CreateResult, racers)
		errs := make([]error, racers)
		var wg sync.WaitGroup
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i], errs[i] = Create(ctx, pool, baseCreateRequest(tenantID))
			}(i)
		}
		wg.Wait()

		created := 0
		for i := 0; i < racers; i++ {
			if errs[i] != nil {
				t.Fatalf("racer %d: %v", i, errs[i])
			}
			if results[i].Created {
				created++
			}
			if results[i].ActionID != results[0].ActionID {
				t.Fatalf("racers resolved to different actions: %s vs %s",
					results[i].ActionID, results[0].ActionID)
			}
		}
		if created != 1 {
			t.Fatalf("Created=true count = %d, want exactly 1", created)
		}
		if got := countEvents(t, pool, tenantID, results[0].ActionID, domain.EventActionCreated); got != 1 {
			t.Fatalf("ActionCreated events = %d, want 1", got)
		}
	})

	t.Run("invalid params JSON is refused before any write", func(t *testing.T) {
		tenantID := createTenant(t, pool)
		bad := baseCreateRequest(tenantID)
		bad.ToolParams = []byte(`{not json`)
		if _, err := Create(ctx, pool, bad); err == nil {
			t.Fatal("invalid JSON accepted")
		}
	})
}
