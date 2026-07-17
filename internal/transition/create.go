package transition

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"actiongate/internal/domain"
	"actiongate/internal/fingerprint"
)

// ErrIdempotencyConflict: the idempotency key matched an existing action but
// the request content differs. The existing action's result is never
// returned to the new caller (plan §8, layer 2).
var ErrIdempotencyConflict = errors.New("idempotency key reuse with different request content")

type CreateRequest struct {
	ActionID        uuid.UUID // zero value: a UUIDv7 is generated
	TenantID        uuid.UUID
	AgentID         string
	SessionID       uuid.UUID
	NativeRequestID string
	ToolName        string
	ToolParams      []byte // canonical JSON (JCS); stored verbatim, hashed verbatim
	Environment     string
	CorrelationID   *uuid.UUID
	ParentActionID  *uuid.UUID
	PolicyVersion   int64
	StreamID        uuid.UUID
	Now             func() time.Time
}

type CreateResult struct {
	ActionID uuid.UUID
	State    domain.State
	Version  int32
	// Created is false when an existing workflow was returned instead — the
	// caller resumes it (a safe retry), nothing was written.
	Created bool
}

// Create is the idempotent intake path (plan §8): in one transaction it
// inserts the immutable ActionRequest guarded by the (tenant_id,
// idempotency_key) unique constraint, the Created action_state row, and the
// ActionCreated audit event. On a key collision it compares fingerprints:
// equal content returns the existing workflow; different content records
// IdempotencyConflict and refuses.
func Create(ctx context.Context, pool *pgxpool.Pool, req CreateRequest) (CreateResult, error) {
	if !json.Valid(req.ToolParams) {
		return CreateResult{}, fmt.Errorf("tool_params is not valid JSON")
	}
	actionID := req.ActionID
	if actionID == uuid.Nil {
		var err error
		if actionID, err = uuid.NewV7(); err != nil {
			return CreateResult{}, fmt.Errorf("uuidv7: %w", err)
		}
	}
	now := time.Now
	if req.Now != nil {
		now = req.Now
	}
	key := fingerprint.IdempotencyKey(req.TenantID, req.SessionID, req.NativeRequestID)
	fp, err := fingerprint.Fingerprint(req.AgentID, req.ToolName, req.ToolParams)
	if err != nil {
		return CreateResult{}, err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return CreateResult{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := setTenant(ctx, tx, req.TenantID); err != nil {
		return CreateResult{}, err
	}

	createdAt := now().UTC()
	tag, err := tx.Exec(ctx,
		`insert into action_requests
		    (id, tenant_id, agent_id, session_id, idempotency_key, request_fingerprint,
		     tool_name, tool_params, environment, correlation_id, parent_action_id,
		     policy_version_evaluated, created_at)
		 values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 on conflict (tenant_id, idempotency_key) do nothing`,
		actionID, req.TenantID, req.AgentID, req.SessionID, key, fp,
		req.ToolName, req.ToolParams, req.Environment, req.CorrelationID,
		req.ParentActionID, req.PolicyVersion, createdAt,
	)
	if err != nil {
		return CreateResult{}, fmt.Errorf("insert action_request: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return resolveExisting(ctx, tx, req, key, fp, createdAt)
	}

	if _, err := tx.Exec(ctx,
		`insert into action_state (action_request_id, tenant_id, state, version, updated_at)
		 values ($1, $2, $3, 0, $4)`,
		actionID, req.TenantID, string(domain.StateCreated), createdAt,
	); err != nil {
		return CreateResult{}, fmt.Errorf("insert action_state: %w", err)
	}

	ev := Event{
		StreamID:   req.StreamID,
		Type:       domain.EventActionCreated,
		AttestedBy: domain.AttestedByControlPlane,
		Metadata: map[string]any{
			"agent_id":  req.AgentID,
			"tool_name": req.ToolName,
		},
	}
	if err := appendEvent(ctx, tx, req.TenantID, actionID, ev, createdAt); err != nil {
		return CreateResult{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return CreateResult{}, fmt.Errorf("commit: %w", err)
	}
	return CreateResult{ActionID: actionID, State: domain.StateCreated, Version: 0, Created: true}, nil
}

// resolveExisting handles the key-collision branch. Fingerprint match: the
// existing workflow's position is returned and nothing is written.
// Mismatch: the IdempotencyConflict security event is committed (metadata
// carries hashes and names only — never raw params) and the create refused.
func resolveExisting(ctx context.Context, tx pgx.Tx, req CreateRequest, key, fp []byte, at time.Time) (CreateResult, error) {
	var existingID uuid.UUID
	var existingFingerprint []byte
	err := tx.QueryRow(ctx,
		`select id, request_fingerprint from action_requests
		  where tenant_id = $1 and idempotency_key = $2`,
		req.TenantID, key,
	).Scan(&existingID, &existingFingerprint)
	if err != nil {
		return CreateResult{}, fmt.Errorf("load existing action: %w", err)
	}

	if !bytes.Equal(existingFingerprint, fp) {
		ev := Event{
			StreamID:   req.StreamID,
			Type:       domain.EventIdempotencyConflict,
			AttestedBy: domain.AttestedByControlPlane,
			Metadata: map[string]any{
				"attempted_agent_id":    req.AgentID,
				"attempted_tool_name":   req.ToolName,
				"attempted_fingerprint": hex.EncodeToString(fp),
			},
		}
		if err := appendEvent(ctx, tx, req.TenantID, existingID, ev, at); err != nil {
			return CreateResult{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return CreateResult{}, fmt.Errorf("commit conflict event: %w", err)
		}
		return CreateResult{}, fmt.Errorf("%w: action %s", ErrIdempotencyConflict, existingID)
	}

	var state string
	var version int32
	err = tx.QueryRow(ctx,
		`select state, version from action_state where action_request_id = $1`,
		existingID,
	).Scan(&state, &version)
	if err != nil {
		return CreateResult{}, fmt.Errorf("load existing state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return CreateResult{}, fmt.Errorf("commit: %w", err)
	}
	return CreateResult{
		ActionID: existingID,
		State:    domain.State(state),
		Version:  version,
		Created:  false,
	}, nil
}
