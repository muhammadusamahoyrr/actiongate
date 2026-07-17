// Package execution is the ExecutionCoordinator (plan §3): it turns an
// allow decision or a granted approval into a signed ExecutionGrant,
// recording ExecutionAuthorized and arming the outcome-deadline timer in
// the same transaction. It never executes anything itself.
package execution

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/muhammadusamahoyrr/actiongate/internal/domain"
	"github.com/muhammadusamahoyrr/actiongate/internal/grant"
	"github.com/muhammadusamahoyrr/actiongate/internal/queue"
	"github.com/muhammadusamahoyrr/actiongate/internal/transition"
)

const DefaultOutcomeDeadline = 5 * time.Minute

var ErrNotAuthorizable = errors.New("action is not in an authorizable state")

type Coordinator struct {
	Pool   *pgxpool.Pool
	Queue  *river.Client[pgx.Tx]
	Signer *grant.Signer
	// TTL bounds how long the gateway may hold the grant before executing
	// (plan §20.2.4: <= 60 s).
	TTL time.Duration
	// OutcomeDeadline bounds how long after authorization a missing receipt
	// becomes OutcomeUnknown (plan §6).
	OutcomeDeadline time.Duration
	Now             func() time.Time
}

func (c *Coordinator) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return grant.DefaultTTL
}

func (c *Coordinator) deadline() time.Duration {
	if c.OutcomeDeadline > 0 {
		return c.OutcomeDeadline
	}
	return DefaultOutcomeDeadline
}

func (c *Coordinator) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

type Authorized struct {
	GrantID       uuid.UUID
	EnvelopeBytes []byte
	ExpiresAt     time.Time
}

// Authorize performs Evaluated→ExecutionAuthorized (auto-allow) or
// Approved→ExecutionAuthorized. The grant is signed before the transaction
// opens (§20.2.1); the grant row and the outcome-deadline timer commit
// atomically with the ExecutionAuthorized event.
func (c *Coordinator) Authorize(ctx context.Context, tenantID, actionID, streamID uuid.UUID) (Authorized, error) {
	state, version, err := transition.CurrentState(ctx, c.Pool, tenantID, actionID)
	if err != nil {
		return Authorized{}, err
	}
	if state != domain.StateEvaluated && state != domain.StateApproved {
		return Authorized{}, fmt.Errorf("%w: %s", ErrNotAuthorizable, state)
	}

	var toolName string
	var fingerprint []byte
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return Authorized{}, fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		_ = tx.Rollback(ctx)
		return Authorized{}, fmt.Errorf("set tenant: %w", err)
	}
	err = tx.QueryRow(ctx,
		`select tool_name, request_fingerprint from action_requests where id = $1`,
		actionID).Scan(&toolName, &fingerprint)
	_ = tx.Rollback(ctx)
	if err != nil {
		return Authorized{}, fmt.Errorf("load action: %w", err)
	}

	grantID, err := uuid.NewV7()
	if err != nil {
		return Authorized{}, fmt.Errorf("uuidv7: %w", err)
	}
	now := c.now().UTC()
	expiresAt := now.Add(c.ttl())
	envelope, err := c.Signer.Issue(grant.IssueInput{
		GrantID: grantID, ActionID: actionID, TenantID: tenantID,
		ToolName: toolName, ParamsHash: fingerprint, ExpiresAt: expiresAt,
	})
	if err != nil {
		return Authorized{}, fmt.Errorf("issue grant: %w", err)
	}

	err = transition.Apply(ctx, c.Pool, transition.Request{
		TenantID:        tenantID,
		ActionID:        actionID,
		From:            state,
		To:              domain.StateExecutionAuthorized,
		ExpectedVersion: version,
		Event: transition.Event{
			StreamID:   streamID,
			Type:       domain.EventExecutionAuthorized,
			AttestedBy: domain.AttestedByControlPlane,
			Metadata: map[string]any{
				"grant_id":   grantID.String(),
				"key_id":     c.Signer.KeyID(),
				"expires_at": expiresAt.Format(time.RFC3339Nano),
			},
		},
		Effects: []transition.Effect{
			func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx,
					`insert into execution_grants
					    (grant_id, tenant_id, action_request_id, params_hash, key_id,
					     expires_at, issued_at, grant_envelope)
					 values ($1, $2, $3, $4, $5, $6, $7, $8)`,
					grantID, tenantID, actionID, fingerprint, c.Signer.KeyID(),
					expiresAt, now, envelope)
				return err
			},
			queue.InsertJobEffect(c.Queue, queue.OutcomeDeadlineArgs{
				TenantID: tenantID, ActionID: actionID, StreamID: streamID,
			}, &river.InsertOpts{ScheduledAt: now.Add(c.deadline())}),
		},
	})
	if err != nil {
		return Authorized{}, err
	}
	return Authorized{GrantID: grantID, EnvelopeBytes: envelope, ExpiresAt: expiresAt}, nil
}

// LatestEnvelope returns the newest unexpired grant envelope for an action —
// the GetActionStatus delivery path while the gateway polls.
func (c *Coordinator) LatestEnvelope(ctx context.Context, tenantID, actionID uuid.UUID) ([]byte, error) {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		return nil, fmt.Errorf("set tenant: %w", err)
	}
	var envelope []byte
	err = tx.QueryRow(ctx,
		`select grant_envelope from execution_grants
		  where tenant_id = $1 and action_request_id = $2 and expires_at > now()
		  order by issued_at desc limit 1`,
		tenantID, actionID).Scan(&envelope)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load envelope: %w", err)
	}
	return envelope, nil
}

// AuthorizeWorker services AuthorizeExecutionArgs from the approved path.
// Late or duplicate jobs no-op (the queue package's lost-race rule).
type AuthorizeWorker struct {
	river.WorkerDefaults[queue.AuthorizeExecutionArgs]
	Coordinator *Coordinator
}

func (w *AuthorizeWorker) Work(ctx context.Context, job *river.Job[queue.AuthorizeExecutionArgs]) error {
	a := job.Args
	_, err := w.Coordinator.Authorize(ctx, a.TenantID, a.ActionID, a.StreamID)
	if errors.Is(err, ErrNotAuthorizable) {
		return nil
	}
	return err
}

// RegisterWorker adds the AuthorizeWorker to a queue registry (kept here to
// avoid an import cycle with the queue package).
func RegisterWorker(workers *river.Workers, c *Coordinator) error {
	return river.AddWorkerSafely(workers, &AuthorizeWorker{Coordinator: c})
}
