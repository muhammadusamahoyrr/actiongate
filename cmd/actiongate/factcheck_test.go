package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/muhammadusamahoyrr/actiongate/policies"
)

// The incident this guards against: protect applied a pack using
// facts.self_tamper while the running control plane was an older build,
// and every governed action on the machine failed closed.
func TestProtectRefusesPackTheControlPlaneCannotEvaluate(t *testing.T) {
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`)) // predates the facts field
	}))
	defer old.Close()
	err := checkControlPlaneKnowsFacts(context.Background(), old.URL, policies.ClaudeCode)
	if err == nil || !strings.Contains(err.Error(), "self_tamper") {
		t.Fatalf("old control plane: err = %v, want a refusal naming self_tamper", err)
	}

	current := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","facts":["destructive","inline_dynamic","opaque","secret_access","self_secret","self_tamper"]}`))
	}))
	defer current.Close()
	if err := checkControlPlaneKnowsFacts(context.Background(), current.URL, policies.ClaudeCode); err != nil {
		t.Errorf("current control plane: %v", err)
	}

	// Unreachable: nothing to compare against; warn and carry on.
	if err := checkControlPlaneKnowsFacts(context.Background(), "http://127.0.0.1:1", policies.ClaudeCode); err != nil {
		t.Errorf("unreachable control plane: %v", err)
	}
}
