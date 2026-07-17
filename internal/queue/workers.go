package queue

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"actiongate/internal/domain"
	"actiongate/internal/notify"
	"actiongate/internal/transition"
)

// Workers here follow one shared rule for timer races (plan §20.2.4): a
// timer that fires after the workflow already moved on has simply lost a
// benign race — it must no-op successfully, never error into River retries.
// Errors are reserved for real failures, where a retry can help.

type ApprovalExpiryWorker struct {
	river.WorkerDefaults[ApprovalExpiryArgs]
	Pool *pgxpool.Pool
}

func (w *ApprovalExpiryWorker) Work(ctx context.Context, job *river.Job[ApprovalExpiryArgs]) error {
	a := job.Args
	state, version, err := transition.CurrentState(ctx, w.Pool, a.TenantID, a.ActionID)
	if err != nil {
		return err
	}
	if state != domain.StatePendingApproval {
		return nil // resolved before the deadline — the timer lost, correctly
	}
	err = transition.Apply(ctx, w.Pool, transition.Request{
		TenantID:        a.TenantID,
		ActionID:        a.ActionID,
		From:            domain.StatePendingApproval,
		To:              domain.StateExpired,
		ExpectedVersion: version,
		Event: transition.Event{
			StreamID:   a.StreamID,
			Type:       domain.EventApprovalExpired,
			AttestedBy: domain.AttestedByControlPlane,
			Metadata:   map[string]any{"approval_request_id": a.ApprovalRequestID.String()},
		},
		Effects: []transition.Effect{expireApprovalRow(a.ApprovalRequestID)},
	})
	if isLostRace(err) {
		return nil
	}
	return err
}

// expireApprovalRow runs inside the transition transaction, after the
// action_state CAS — the fixed lock order from plan §20.2.1.
func expireApprovalRow(approvalRequestID uuid.UUID) transition.Effect {
	return func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`update approval_requests
			    set status = 'expired', version = version + 1
			  where id = $1 and status = 'pending'`,
			approvalRequestID,
		)
		if err != nil {
			return fmt.Errorf("expire approval: %w", err)
		}
		if tag.RowsAffected() != 1 {
			// The action was PendingApproval but its approval is not pending:
			// invariant breach, refuse the whole transition.
			return fmt.Errorf("approval %s not pending while action awaited approval", approvalRequestID)
		}
		return nil
	}
}

type OutcomeDeadlineWorker struct {
	river.WorkerDefaults[OutcomeDeadlineArgs]
	Pool *pgxpool.Pool
}

func (w *OutcomeDeadlineWorker) Work(ctx context.Context, job *river.Job[OutcomeDeadlineArgs]) error {
	a := job.Args
	state, version, err := transition.CurrentState(ctx, w.Pool, a.TenantID, a.ActionID)
	if err != nil {
		return err
	}
	if state != domain.StateExecutionAuthorized && state != domain.StateExecuting {
		return nil // a receipt arrived in time
	}
	err = transition.Apply(ctx, w.Pool, transition.Request{
		TenantID:        a.TenantID,
		ActionID:        a.ActionID,
		From:            state,
		To:              domain.StateOutcomeUnknown,
		ExpectedVersion: version,
		Event: transition.Event{
			StreamID:   a.StreamID,
			Type:       domain.EventOutcomeUnknown,
			AttestedBy: domain.AttestedByControlPlane,
			Metadata:   map[string]any{"reason": "no outcome receipt within deadline"},
		},
	})
	if isLostRace(err) {
		return nil
	}
	return err
}

type DeliverApprovalWorker struct {
	river.WorkerDefaults[DeliverApprovalArgs]
	Port notify.Port
}

func (w *DeliverApprovalWorker) Work(ctx context.Context, job *river.Job[DeliverApprovalArgs]) error {
	a := job.Args
	return w.Port.Send(ctx, notify.Message{
		TenantID:          a.TenantID,
		ActionID:          a.ActionID,
		ApprovalRequestID: a.ApprovalRequestID,
		ApproverTarget:    a.ApproverTarget,
		Title:             a.Title,
		Body:              a.Body,
		CallbackToken:     a.CallbackToken,
	})
}

// NewWorkers registers every worker; the control plane and tests share this
// single registry so a job kind can never exist without its worker.
func NewWorkers(pool *pgxpool.Pool, port notify.Port) (*river.Workers, error) {
	workers := river.NewWorkers()
	if err := river.AddWorkerSafely(workers, &ApprovalExpiryWorker{Pool: pool}); err != nil {
		return nil, err
	}
	if err := river.AddWorkerSafely(workers, &OutcomeDeadlineWorker{Pool: pool}); err != nil {
		return nil, err
	}
	if err := river.AddWorkerSafely(workers, &DeliverApprovalWorker{Port: port}); err != nil {
		return nil, err
	}
	return workers, nil
}

func isLostRace(err error) bool {
	return errors.Is(err, transition.ErrVersionConflict) ||
		errors.Is(err, transition.ErrInvalidTransition)
}
