// Package queue wires River into the architecture (plan §20.1): River is the
// transactional outbox, the workers-with-leases, and the timer subsystem in
// one. The one rule that keeps it correct: jobs are ALWAYS enqueued with
// InsertTx inside the transition primitive's transaction — InsertJobEffect
// is the only enqueue path, and it deliberately does not expose a
// non-transactional variant.
//
// Timers (plan Round 5 fix 2) are River scheduled jobs written atomically
// with the thing that needs them: an ApprovalRequest is created in the same
// transaction as its ApprovalExpiryArgs job; a grant in the same transaction
// as its OutcomeDeadlineArgs job.
package queue

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"

	"actiongate/internal/transition"
)

// ApprovalExpiryArgs is the approval-deadline timer (plan §16: approval
// timeout → Expired, configurable default deny).
type ApprovalExpiryArgs struct {
	TenantID          uuid.UUID `json:"tenant_id"`
	ActionID          uuid.UUID `json:"action_id"`
	ApprovalRequestID uuid.UUID `json:"approval_request_id"`
	StreamID          uuid.UUID `json:"stream_id"`
}

func (ApprovalExpiryArgs) Kind() string { return "approval_expiry" }

// OutcomeDeadlineArgs is the reconciliation timer (plan §6): a grant with no
// reported outcome within the deadline becomes OutcomeUnknown.
type OutcomeDeadlineArgs struct {
	TenantID uuid.UUID `json:"tenant_id"`
	ActionID uuid.UUID `json:"action_id"`
	StreamID uuid.UUID `json:"stream_id"`
}

func (OutcomeDeadlineArgs) Kind() string { return "outcome_deadline" }

// AuthorizeExecutionArgs asks the ExecutionCoordinator to issue a grant for
// an approved action (Approved → ExecutionAuthorized). Enqueued atomically
// with the approval resolution so a crash between "approved" and "grant
// issued" recovers through the queue, never through luck.
type AuthorizeExecutionArgs struct {
	TenantID uuid.UUID `json:"tenant_id"`
	ActionID uuid.UUID `json:"action_id"`
	StreamID uuid.UUID `json:"stream_id"`
}

func (AuthorizeExecutionArgs) Kind() string { return "authorize_execution" }

// DeliverApprovalArgs carries an approval notification to the
// NotificationWorker. Fields mirror notify.Message: names and identifiers
// only, never raw params.
type DeliverApprovalArgs struct {
	TenantID          uuid.UUID `json:"tenant_id"`
	ActionID          uuid.UUID `json:"action_id"`
	ApprovalRequestID uuid.UUID `json:"approval_request_id"`
	ApproverTarget    string    `json:"approver_target"`
	Title             string    `json:"title"`
	Body              string    `json:"body"`
	CallbackToken     string    `json:"callback_token"`
}

func (DeliverApprovalArgs) Kind() string { return "deliver_approval" }

// Migrate applies River's own schema (river_job etc.). Run after Goose
// migrations at service start and in test setup.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return fmt.Errorf("river migrator: %w", err)
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("river migrate up: %w", err)
	}
	return nil
}

// InsertJobEffect enqueues a job inside the transition's transaction. This
// is the transactional-outbox guarantee: if the transition rolls back, the
// job never existed.
func InsertJobEffect(client *river.Client[pgx.Tx], args river.JobArgs, opts *river.InsertOpts) transition.Effect {
	return func(ctx context.Context, tx pgx.Tx) error {
		if _, err := client.InsertTx(ctx, tx, args, opts); err != nil {
			return fmt.Errorf("enqueue %s: %w", args.Kind(), err)
		}
		return nil
	}
}

// NewInsertOnlyClient creates a client that can enqueue via InsertJobEffect
// but runs no workers — the shape API handlers use.
func NewInsertOnlyClient(pool *pgxpool.Pool) (*river.Client[pgx.Tx], error) {
	return river.NewClient(riverpgxv5.New(pool), &river.Config{})
}
