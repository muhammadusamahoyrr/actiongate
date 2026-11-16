package main

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Audit M3: the request id is Claude Code's tool_use_id, so a retried hook
// for the same call maps to the same action. Unusable ids fall back to a
// fresh UUID rather than to a shared constant.
func TestRequestIDUsesToolUseID(t *testing.T) {
	if got := requestID("toolu_01AbCdEf"); got != "toolu_01AbCdEf" {
		t.Errorf("requestID(toolu_01AbCdEf) = %q", got)
	}
	for _, bad := range []string{"", strings.Repeat("a", 129), "has space", "tab\there", "nl\n", "café"} {
		got := requestID(bad)
		if _, err := uuid.Parse(got); err != nil {
			t.Errorf("requestID(%q) = %q, want a fresh UUID", bad, got)
		}
		if got == requestID(bad) {
			t.Errorf("requestID(%q) repeated %q; fallbacks must be unique", bad, got)
		}
	}
}
