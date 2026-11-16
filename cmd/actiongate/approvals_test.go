package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPickApproval(t *testing.T) {
	a := pendingApproval{ID: uuid.MustParse("019f2c00-0000-7000-8000-00000000aaaa")}
	b := pendingApproval{ID: uuid.MustParse("019f2c00-0000-7000-8000-00000000bbbb")}
	pending := []pendingApproval{a, b}

	if got, err := pickApproval(pending, shortID(a.ID)); err != nil || got.ID != a.ID {
		t.Errorf("by short id: %v %v", got.ID, err)
	}
	if got, err := pickApproval(pending, a.ID.String()); err != nil || got.ID != a.ID {
		t.Errorf("by full id: %v %v", got.ID, err)
	}
	if _, err := pickApproval(pending, "019f2c00"); err == nil || !strings.Contains(err.Error(), "matches 2") {
		t.Errorf("ambiguous prefix: err = %v", err)
	}
	if _, err := pickApproval(pending, "abc"); err == nil {
		t.Error("a prefix under 4 characters must be refused")
	}
	if _, err := pickApproval(pending, "ffffffff"); err == nil {
		t.Error("unknown id must be refused")
	}
}

// Under `go test` stdin is not a console, which is exactly an agent's
// situation: approve/deny must refuse before touching anything.
func TestApproveRefusesWithoutAConsole(t *testing.T) {
	if isInteractiveConsole() {
		t.Skip("test is running attached to a real console")
	}
	if code := approvalsResolve("approve", []string{"019f2c00aaaa"}); code == 0 {
		t.Error("approve ran without an interactive console")
	}
}

func TestPostCallbackSendsTheDecision(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/approval/callback" || r.Method != http.MethodPost {
			http.Error(w, "wrong endpoint", http.StatusNotFound)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := postCallback(srv.URL, "agt1_x", "approved", "local:alice", "looked fine"); err != nil {
		t.Fatal(err)
	}
	if got["token"] != "agt1_x" || got["decision"] != "approved" || got["approver_id"] != "local:alice" || got["reason"] != "looked fine" {
		t.Errorf("callback body = %v", got)
	}

	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"already resolved"}`, http.StatusConflict)
	}))
	defer refuse.Close()
	if err := postCallback(refuse.URL, "t", "approved", "a", ""); err == nil || !strings.Contains(err.Error(), "already resolved") {
		t.Errorf("refusal not surfaced: %v", err)
	}
}
