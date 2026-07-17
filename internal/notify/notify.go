// Package notify defines NotificationPort (plan §14): delivery only, no
// business logic, no outcome decisions. Slack, email, and webhooks are
// implementations; workers depend only on the interface.
package notify

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
)

// Message is an approval request rendered for a human. It carries names,
// identifiers, and the opaque callback token — never raw tool params
// (redaction is upstream, plan §4 RedactedActionInputs).
type Message struct {
	TenantID          uuid.UUID
	ActionID          uuid.UUID
	ApprovalRequestID uuid.UUID
	ApproverTarget    string
	Title             string
	Body              string
	CallbackToken     string
}

type Port interface {
	Send(ctx context.Context, msg Message) error
}

// LogPort is the development/test implementation: it "delivers" to the log.
type LogPort struct {
	Logger *slog.Logger
}

func (p LogPort) Send(_ context.Context, msg Message) error {
	logger := p.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("approval notification",
		"tenant_id", msg.TenantID,
		"action_id", msg.ActionID,
		"approval_request_id", msg.ApprovalRequestID,
		"approver_target", msg.ApproverTarget,
		"title", msg.Title,
	)
	return nil
}
