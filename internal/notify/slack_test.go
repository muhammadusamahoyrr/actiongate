package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/slack-go/slack"
)

type postedMessage struct {
	channel string
	blocks  string
}

func fakeSlack(t *testing.T) (*slack.Client, *[]postedMessage) {
	t.Helper()
	var posted []postedMessage
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "chat.postMessage") {
			t.Fatalf("unexpected slack call %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		posted = append(posted, postedMessage{
			channel: r.Form.Get("channel"),
			blocks:  r.Form.Get("blocks"),
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C-FAKE"}`))
	}))
	t.Cleanup(ts.Close)
	return slack.New("test-token", slack.OptionAPIURL(ts.URL+"/")), &posted
}

func sampleMessage(token string) Message {
	return Message{
		TenantID: uuid.New(), ActionID: uuid.New(), ApprovalRequestID: uuid.New(),
		ApproverTarget: "sre-oncall",
		Title:          "Approve rm -rf?", Body: "agent-1 wants bash",
		CallbackToken: token,
	}
}

func TestSlackPort(t *testing.T) {
	ctx := context.Background()

	t.Run("routes by approver target and embeds the token in both buttons", func(t *testing.T) {
		client, posted := fakeSlack(t)
		port := SlackPort{
			Client:         client,
			Channels:       map[string]string{"sre-oncall": "C-SRE"},
			DefaultChannel: "C-DEFAULT",
		}
		token := "cb-" + uuid.NewString()
		if err := port.Send(ctx, sampleMessage(token)); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if len(*posted) != 1 {
			t.Fatalf("posted %d messages", len(*posted))
		}
		got := (*posted)[0]
		if got.channel != "C-SRE" {
			t.Fatalf("channel = %s, want C-SRE", got.channel)
		}
		if n := strings.Count(got.blocks, token); n != 2 {
			t.Fatalf("token appears %d times in blocks, want 2 (approve + deny)", n)
		}
		var blocks []map[string]any
		if err := json.Unmarshal([]byte(got.blocks), &blocks); err != nil {
			t.Fatalf("blocks are not valid JSON: %v", err)
		}
		if !strings.Contains(got.blocks, `"approve"`) || !strings.Contains(got.blocks, `"deny"`) {
			t.Fatal("approve/deny action ids missing")
		}
	})

	t.Run("unknown target falls back to the default channel", func(t *testing.T) {
		client, posted := fakeSlack(t)
		port := SlackPort{Client: client, DefaultChannel: "C-DEFAULT"}
		msg := sampleMessage("cb-x")
		msg.ApproverTarget = "someone-unmapped"
		if err := port.Send(ctx, msg); err != nil {
			t.Fatalf("Send: %v", err)
		}
		if (*posted)[0].channel != "C-DEFAULT" {
			t.Fatalf("channel = %s, want C-DEFAULT", (*posted)[0].channel)
		}
	})

	t.Run("no channel at all is an error, not a silent drop", func(t *testing.T) {
		client, _ := fakeSlack(t)
		port := SlackPort{Client: client}
		if err := port.Send(ctx, sampleMessage("cb-y")); err == nil {
			t.Fatal("message with no destination did not error")
		}
	})
}
