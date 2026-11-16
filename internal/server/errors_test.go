package server

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"connectrpc.com/connect"

	"github.com/muhammadusamahoyrr/actiongate/internal/orchestrator"
	"github.com/muhammadusamahoyrr/actiongate/internal/transition"
)

// Audit L2: callers get a fixed message or a reference; the details go to
// the operator's log.
func TestErrorsDoNotLeakInternals(t *testing.T) {
	var logged bytes.Buffer
	s := &Server{Logger: slog.New(slog.NewTextHandler(&logged, nil))}

	internal := s.internalError(errors.New(`ERROR: relation "approval_callback_tokens" does not exist (SQLSTATE 42P01)`))
	if connect.CodeOf(internal) != connect.CodeInternal {
		t.Errorf("code = %v, want internal", connect.CodeOf(internal))
	}
	msg := internal.Error()
	if strings.Contains(msg, "approval_callback_tokens") || !strings.Contains(msg, "ref ") {
		t.Errorf("caller sees %q; want only a reference", msg)
	}
	ref := msg[strings.LastIndex(msg, "ref ")+4 : len(msg)-1]
	if !strings.Contains(logged.String(), ref) || !strings.Contains(logged.String(), "approval_callback_tokens") {
		t.Errorf("log %q lacks the reference %q or the full error", logged.String(), ref)
	}

	policy := s.mapSubmitError(fmt.Errorf("%w: cel: no such key: params.secret_rule_input", orchestrator.ErrPolicyFailed))
	if strings.Contains(policy.Error(), "secret_rule_input") || !strings.Contains(policy.Error(), "fail closed") {
		t.Errorf("policy failure shown as %q", policy.Error())
	}
	if c := connect.CodeOf(s.mapSubmitError(fmt.Errorf("x: %w", transition.ErrIdempotencyConflict))); c != connect.CodeFailedPrecondition {
		t.Errorf("idempotency conflict code = %v", c)
	}
	if c := connect.CodeOf(s.mapSubmitError(fmt.Errorf("load: %w", transition.ErrNotFound))); c != connect.CodeNotFound {
		t.Errorf("not found code = %v", c)
	}
	if c := connect.CodeOf(s.mapSubmitError(errors.New("connection refused"))); c != connect.CodeInternal {
		t.Errorf("unknown error code = %v, want internal", c)
	}
}
