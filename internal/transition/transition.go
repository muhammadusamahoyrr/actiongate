// Package transition implements the system's single write path for workflow
// state (plan §20.2.1): one Postgres transaction = state CAS + audit event
// append + effects (River job inserts, timer rows). If any part cannot
// commit, nothing happened — fail-closed reduces to transactional atomicity.
//
// Rules enforced here and by convention on callers:
//   - Nothing slow inside the transaction: policy evaluation, signature
//     verification, and KMS calls all happen before Apply is called.
//   - Fixed lock order: action_state is always CAS'd first; effects that
//     touch approval_requests run after it, inside the same transaction.
//   - Isolation is READ COMMITTED; the version column carries correctness.
package transition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"actiongate/internal/domain"
)

var (
	ErrInvalidTransition = errors.New("transition not permitted by state machine")
	ErrVersionConflict   = errors.New("action_state version conflict")
	ErrNotFound          = errors.New("action_state row not found")
)

// Event is the audit fact appended atomically with the state change.
type Event struct {
	StreamID   uuid.UUID
	Type       domain.EventType
	AttestedBy string
	Metadata   map[string]any
}

// Effect runs inside the transition's transaction, after the CAS and audit
// append. River job inserts (InsertTx) and timer rows are Effects.
type Effect func(ctx context.Context, tx pgx.Tx) error

type Request struct {
	TenantID        uuid.UUID
	ActionID        uuid.UUID
	From, To        domain.State
	ExpectedVersion int32
	Event           Event
	Effects         []Effect
	Now             func() time.Time // defaults to time.Now (plan §13: Clock)
}

// Apply performs one state transition atomically. On ErrInvalidTransition or
// ErrVersionConflict nothing is written; callers should then record the
// security signal via RecordInvalidAttempt in a fresh transaction.
func Apply(ctx context.Context, pool *pgxpool.Pool, req Request) error {
	if !domain.CanTransition(req.From, req.To) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, req.From, req.To)
	}
	now := time.Now
	if req.Now != nil {
		now = req.Now
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := setTenant(ctx, tx, req.TenantID); err != nil {
		return err
	}

	tag, err := tx.Exec(ctx,
		`update action_state
		    set state = $1, version = version + 1, updated_at = $2
		  where action_request_id = $3 and state = $4 and version = $5`,
		string(req.To), now().UTC(), req.ActionID, string(req.From), req.ExpectedVersion,
	)
	if err != nil {
		return fmt.Errorf("cas action_state: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return casFailure(ctx, tx, req)
	}

	if err := appendEvent(ctx, tx, req.TenantID, req.ActionID, req.Event, now().UTC()); err != nil {
		return err
	}

	for _, effect := range req.Effects {
		if err := effect(ctx, tx); err != nil {
			return fmt.Errorf("effect: %w", err)
		}
	}

	return tx.Commit(ctx)
}

// RecordInvalidAttempt appends the InvalidTransitionAttempted security signal
// (plan §7) in its own transaction, since the failed transition's transaction
// rolled back.
func RecordInvalidAttempt(ctx context.Context, pool *pgxpool.Pool, tenantID, actionID uuid.UUID, streamID uuid.UUID, from, to domain.State) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return err
	}
	ev := Event{
		StreamID:   streamID,
		Type:       domain.EventInvalidTransitionAttempted,
		AttestedBy: domain.AttestedByControlPlane,
		Metadata:   map[string]any{"from": string(from), "to": string(to)},
	}
	if err := appendEvent(ctx, tx, tenantID, actionID, ev, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CurrentState reads an action's workflow position. The version is the CAS
// token for a subsequent Apply; a conflict there means someone else moved
// the workflow first, which callers usually treat as losing a benign race.
func CurrentState(ctx context.Context, pool *pgxpool.Pool, tenantID, actionID uuid.UUID) (domain.State, int32, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setTenant(ctx, tx, tenantID); err != nil {
		return "", 0, err
	}
	var state string
	var version int32
	err = tx.QueryRow(ctx,
		`select state, version from action_state where action_request_id = $1`,
		actionID,
	).Scan(&state, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", 0, fmt.Errorf("%w: action %s", ErrNotFound, actionID)
	}
	if err != nil {
		return "", 0, fmt.Errorf("read action_state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", 0, fmt.Errorf("commit: %w", err)
	}
	return domain.State(state), version, nil
}

func setTenant(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	_, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String())
	if err != nil {
		return fmt.Errorf("set tenant: %w", err)
	}
	return nil
}

func appendEvent(ctx context.Context, tx pgx.Tx, tenantID, actionID uuid.UUID, ev Event, at time.Time) error {
	id, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("uuidv7: %w", err)
	}
	meta := ev.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	_, err = tx.Exec(ctx,
		`insert into audit_events
		    (id, tenant_id, stream_id, action_request_id, event_type, attested_by, metadata, recorded_at)
		 values ($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, tenantID, ev.StreamID, actionID, string(ev.Type), ev.AttestedBy, metaJSON, at,
	)
	if err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	return nil
}

func casFailure(ctx context.Context, tx pgx.Tx, req Request) error {
	var state string
	var version int32
	err := tx.QueryRow(ctx,
		`select state, version from action_state where action_request_id = $1`,
		req.ActionID,
	).Scan(&state, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: action %s", ErrNotFound, req.ActionID)
	}
	if err != nil {
		return fmt.Errorf("diagnose cas failure: %w", err)
	}
	if domain.State(state) != req.From {
		return fmt.Errorf("%w: expected %s, found %s", ErrInvalidTransition, req.From, state)
	}
	return fmt.Errorf("%w: expected version %d, found %d", ErrVersionConflict, req.ExpectedVersion, version)
}
