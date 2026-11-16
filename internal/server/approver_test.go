package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Audit M5: the callback's approver_id is only a claim, so it is recorded
// under "callback:" and can never pass for a Slack-verified identity.
func TestCallbackApproverIsNamespaced(t *testing.T) {
	for in, want := range map[string]string{
		"alice":        "callback:alice",
		"  bob  ":      "callback:bob",
		"slack:U-BOSS": "callback:slack:U-BOSS",
		"":             "callback:unspecified",
	} {
		got, err := callbackApprover(in)
		if err != nil || got != want {
			t.Errorf("callbackApprover(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{strings.Repeat("x", 129), "line\nbreak", "nul\x00"} {
		if got, err := callbackApprover(bad); err == nil {
			t.Errorf("callbackApprover(%q) = %q, want an error", bad, got)
		}
	}
}

// With an approver list, a click from anyone else is refused before the
// approval is touched (Approvals is nil here: reaching it would panic).
func TestSlackClickFromUnlistedUserIsRefused(t *testing.T) {
	const secret = "signing-secret"
	s := &Server{SlackSigningSecret: secret, SlackApprovers: []string{"U-ALICE"}}

	payload := `{"type":"block_actions","user":{"id":"U-MALLORY","name":"alice"},` +
		`"actions":[{"type":"button","action_id":"approve","block_id":"actiongate_approval","value":"some-token"}]}`
	body := "payload=" + url.QueryEscape(payload)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + ts + ":" + body))

	req := httptest.NewRequest(http.MethodPost, "/slack/interaction", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	rec := httptest.NewRecorder()
	s.handleSlackInteraction(rec, req)

	out, _ := io.ReadAll(rec.Body)
	if rec.Code != http.StatusOK || !strings.Contains(string(out), "not on actiongate's approver list") {
		t.Errorf("unlisted Slack user: %d %q, want a refusal", rec.Code, out)
	}
}
