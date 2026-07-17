package server

import (
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/slack-go/slack"

	"actiongate/internal/approval"
)

// handleSlackInteraction resolves approvals from Slack button clicks. The
// request is authenticated twice: Slack's signing secret proves the payload
// came from Slack, and the button's value is the single-use HMAC callback
// token that proves it belongs to a real pending approval. The approver
// identity recorded is the Slack user id.
func (s *Server) handleSlackInteraction(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		http.Error(w, "body", http.StatusBadRequest)
		return
	}
	verifier, err := slack.NewSecretsVerifier(r.Header, s.SlackSigningSecret)
	if err != nil {
		http.Error(w, "signature", http.StatusForbidden)
		return
	}
	if _, err := verifier.Write(body); err != nil {
		http.Error(w, "signature", http.StatusForbidden)
		return
	}
	if err := verifier.Ensure(); err != nil {
		http.Error(w, "signature", http.StatusForbidden)
		return
	}

	// Slack sends application/x-www-form-urlencoded with a `payload` field.
	values, err := parseForm(body)
	if err != nil {
		http.Error(w, "form", http.StatusBadRequest)
		return
	}
	var cb slack.InteractionCallback
	if err := cb.UnmarshalJSON([]byte(values.Get("payload"))); err != nil {
		http.Error(w, "payload", http.StatusBadRequest)
		return
	}
	if len(cb.ActionCallback.BlockActions) == 0 {
		w.WriteHeader(http.StatusOK)
		return
	}
	action := cb.ActionCallback.BlockActions[0]
	var decision string
	switch action.ActionID {
	case "approve":
		decision = "approved"
	case "deny":
		decision = "denied"
	default:
		w.WriteHeader(http.StatusOK)
		return
	}
	approver := cb.User.ID
	if approver == "" {
		approver = cb.User.Name
	}

	res, err := s.Approvals.Resolve(r.Context(), action.Value, decision, "slack:"+approver, "via slack")
	switch {
	case err == nil:
		respondText(w, "Recorded: "+decision+" — action "+res.ActionID.String())
	case errors.Is(err, approval.ErrAlreadyResolved):
		respondText(w, "This request was already resolved.")
	case errors.Is(err, approval.ErrTokenExpired):
		respondText(w, "This approval expired before a decision was made.")
	case errors.Is(err, approval.ErrTokenInvalid):
		http.Error(w, "token", http.StatusForbidden)
	default:
		http.Error(w, "internal", http.StatusInternalServerError)
	}
}

func parseForm(body []byte) (url.Values, error) {
	return url.ParseQuery(string(body))
}

func respondText(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(text))
}
