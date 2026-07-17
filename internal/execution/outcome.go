package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	actiongatev1 "actiongate/gen/actiongate/v1"
	"actiongate/internal/domain"
	"actiongate/internal/transition"
)

var ErrUnknownGrant = errors.New("receipt references an unknown grant")

// RecordOutcome applies a verified gateway receipt: ExecutionAuthorized →
// Executing (ExecutionStarted) → terminal, both gateway-attested (plan §5).
// The two transitions are separate transactions; a crash between them
// leaves Executing, which the outcome-deadline timer resolves honestly.
// Returns (accepted, duplicate): a second receipt for the same grant is
// rejected as duplicate (single-use, plan §20.2.4); a receipt arriving
// after the deadline already marked OutcomeUnknown is not accepted — the
// operator reconciles with the receipt as evidence.
func (c *Coordinator) RecordOutcome(ctx context.Context, tenantID uuid.UUID, gatewayID string, receipt *actiongatev1.OutcomeReceipt) (accepted, duplicate bool, err error) {
	grantID, err := uuid.Parse(receipt.GetGrantId())
	if err != nil {
		return false, false, fmt.Errorf("grant_id: %w", err)
	}

	var actionID uuid.UUID
	var receiptReceivedAt *time.Time
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return false, false, fmt.Errorf("begin: %w", err)
	}
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		_ = tx.Rollback(ctx)
		return false, false, fmt.Errorf("set tenant: %w", err)
	}
	err = tx.QueryRow(ctx,
		`select action_request_id, receipt_received_at from execution_grants
		  where tenant_id = $1 and grant_id = $2`,
		tenantID, grantID).Scan(&actionID, &receiptReceivedAt)
	_ = tx.Rollback(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, ErrUnknownGrant
	}
	if err != nil {
		return false, false, fmt.Errorf("load grant: %w", err)
	}
	if receiptReceivedAt != nil {
		return false, true, nil
	}
	if receipt.GetActionId() != actionID.String() {
		return false, false, fmt.Errorf("receipt action %s does not match grant action %s", receipt.GetActionId(), actionID)
	}

	toState, eventType, err := outcomeMapping(receipt.GetStatus())
	if err != nil {
		return false, false, err
	}
	streamID, err := c.streamOf(ctx, tenantID, actionID)
	if err != nil {
		return false, false, err
	}
	attestedBy := domain.AttestedByGateway + ":" + gatewayID
	receivedAt := c.now().UTC()
	startedAt := receipt.GetStartedAt().AsTime()

	state, version, err := transition.CurrentState(ctx, c.Pool, tenantID, actionID)
	if err != nil {
		return false, false, err
	}
	if state == domain.StateExecutionAuthorized {
		err = transition.Apply(ctx, c.Pool, transition.Request{
			TenantID: tenantID, ActionID: actionID,
			From: domain.StateExecutionAuthorized, To: domain.StateExecuting,
			ExpectedVersion: version,
			Event: transition.Event{
				StreamID: streamID, Type: domain.EventExecutionStarted,
				AttestedBy: attestedBy,
				Metadata: map[string]any{
					"grant_id":           grantID.String(),
					"gateway_started_at": startedAt.UTC().Format(time.RFC3339Nano),
					"server_received_at": receivedAt.Format(time.RFC3339Nano),
				},
			},
		})
		if err != nil {
			return false, false, err
		}
		state, version = domain.StateExecuting, version+1
	}
	if state != domain.StateExecuting {
		// The deadline (or something else) resolved this action first; the
		// receipt cannot be recorded as a live fact anymore.
		return false, false, nil
	}

	sideEffects, err := json.Marshal(receipt.GetSideEffects())
	if err != nil {
		return false, false, fmt.Errorf("side effects: %w", err)
	}
	var completedAt *time.Time
	if receipt.GetCompletedAt() != nil {
		ts := receipt.GetCompletedAt().AsTime().UTC()
		completedAt = &ts
	}
	err = transition.Apply(ctx, c.Pool, transition.Request{
		TenantID: tenantID, ActionID: actionID,
		From: domain.StateExecuting, To: toState, ExpectedVersion: version,
		Event: transition.Event{
			StreamID: streamID, Type: eventType, AttestedBy: attestedBy,
			Metadata: map[string]any{
				"grant_id":     grantID.String(),
				"error":        receipt.GetError(),
				"output_ref":   receipt.GetOutputRef(),
				"side_effects": json.RawMessage(sideEffects),
			},
		},
		Effects: []transition.Effect{
			func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx,
					`insert into action_results
					    (action_request_id, tenant_id, status, output_ref, error,
					     side_effects, started_at, completed_at)
					 values ($1, $2, $3, $4, $5, $6, $7, $8)`,
					actionID, tenantID, statusString(receipt.GetStatus()),
					receipt.GetOutputRef(), nullable(receipt.GetError()),
					sideEffects, startedAt.UTC(), completedAt)
				return err
			},
			func(ctx context.Context, tx pgx.Tx) error {
				tag, err := tx.Exec(ctx,
					`update execution_grants set receipt_received_at = $1
					  where grant_id = $2 and receipt_received_at is null`,
					receivedAt, grantID)
				if err != nil {
					return fmt.Errorf("mark grant used: %w", err)
				}
				if tag.RowsAffected() != 1 {
					return fmt.Errorf("grant %s already consumed by a concurrent receipt", grantID)
				}
				return nil
			},
		},
	})
	if err != nil {
		if errors.Is(err, transition.ErrVersionConflict) || errors.Is(err, transition.ErrInvalidTransition) {
			return false, true, nil // a concurrent receipt won
		}
		return false, false, err
	}
	return true, false, nil
}

// Outcome returns the recorded result for terminal actions, nil otherwise.
func (c *Coordinator) Outcome(ctx context.Context, tenantID, actionID uuid.UUID) (*actiongatev1.ActionOutcome, error) {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		return nil, fmt.Errorf("set tenant: %w", err)
	}
	var status, outputRef string
	var errText *string
	err = tx.QueryRow(ctx,
		`select status, coalesce(output_ref, ''), error from action_results
		  where tenant_id = $1 and action_request_id = $2`,
		tenantID, actionID).Scan(&status, &outputRef, &errText)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load result: %w", err)
	}
	out := &actiongatev1.ActionOutcome{
		ActionId:  actionID.String(),
		Status:    statusEnum(status),
		OutputRef: outputRef,
	}
	if errText != nil {
		out.Error = *errText
	}
	return out, nil
}

func (c *Coordinator) streamOf(ctx context.Context, tenantID, actionID uuid.UUID) (uuid.UUID, error) {
	tx, err := c.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		return uuid.Nil, fmt.Errorf("set tenant: %w", err)
	}
	var streamID uuid.UUID
	err = tx.QueryRow(ctx,
		`select stream_id from audit_events
		  where tenant_id = $1 and action_request_id = $2
		  order by ingest_seq limit 1`,
		tenantID, actionID).Scan(&streamID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("resolve stream: %w", err)
	}
	return streamID, nil
}

func outcomeMapping(s actiongatev1.ExecutionStatus) (domain.State, domain.EventType, error) {
	switch s {
	case actiongatev1.ExecutionStatus_EXECUTION_STATUS_SUCCEEDED:
		return domain.StateSucceeded, domain.EventExecutionSucceeded, nil
	case actiongatev1.ExecutionStatus_EXECUTION_STATUS_FAILED:
		return domain.StateFailed, domain.EventExecutionFailed, nil
	case actiongatev1.ExecutionStatus_EXECUTION_STATUS_PARTIALLY_SUCCEEDED:
		return domain.StatePartiallySucceeded, domain.EventExecutionPartiallySucceeded, nil
	default:
		return "", "", fmt.Errorf("receipt status %s is not reportable by a gateway", s)
	}
}

func statusString(s actiongatev1.ExecutionStatus) string {
	switch s {
	case actiongatev1.ExecutionStatus_EXECUTION_STATUS_SUCCEEDED:
		return "succeeded"
	case actiongatev1.ExecutionStatus_EXECUTION_STATUS_FAILED:
		return "failed"
	case actiongatev1.ExecutionStatus_EXECUTION_STATUS_PARTIALLY_SUCCEEDED:
		return "partially_succeeded"
	default:
		return "outcome_unknown"
	}
}

func statusEnum(s string) actiongatev1.ExecutionStatus {
	switch s {
	case "succeeded":
		return actiongatev1.ExecutionStatus_EXECUTION_STATUS_SUCCEEDED
	case "failed":
		return actiongatev1.ExecutionStatus_EXECUTION_STATUS_FAILED
	case "partially_succeeded":
		return actiongatev1.ExecutionStatus_EXECUTION_STATUS_PARTIALLY_SUCCEEDED
	default:
		return actiongatev1.ExecutionStatus_EXECUTION_STATUS_OUTCOME_UNKNOWN
	}
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
