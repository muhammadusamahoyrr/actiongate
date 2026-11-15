package preview

import (
	"strings"
	"testing"
)

// Audit H6: the approver must see what will run.
func TestBodyShowsTheCommandAndWhy(t *testing.T) {
	b := Body("Bash", "claude-code", "approve-destructive", "destructive",
		map[string]any{"command": "rm -rf ~"}, []string{"recursive delete (rm)"})
	for _, want := range []string{"rm -rf ~", "approve-destructive", "claude-code", "recursive delete (rm)"} {
		if !strings.Contains(b, want) {
			t.Errorf("body missing %q:\n%s", want, b)
		}
	}
	other := Body("Bash", "claude-code", "approve-destructive", "destructive",
		map[string]any{"command": "rm -rf node_modules"}, nil)
	if other == b {
		t.Error("rm -rf node_modules and rm -rf ~ render the same")
	}
}

func TestMaskHidesCredentials(t *testing.T) {
	for in, secret := range map[string]string{
		`curl -H "Authorization: Bearer abcdef1234567890" https://x`:        "abcdef1234567890",
		`export API_KEY=sk-live-0123456789abcdef`:                           "sk-live-0123456789abcdef",
		`psql postgres://ag:hunter2@localhost/db`:                           "hunter2",
		`mysql --password=s3cr3t-pw -u root`:                                "s3cr3t-pw",
		`git clone https://ghp_abcdefghijklmnopqrstuvwxyz0123@github.com/x`: "ghp_abcdefghijklmnopqrstuvwxyz0123",
		`aws configure set aws_access_key_id AKIAABCDEFGHIJKLMNOP`:          "AKIAABCDEFGHIJKLMNOP",
		`TOKEN="xoxb-1234567890-abcdefghij" ./post.sh`:                      "xoxb-1234567890-abcdefghij",
	} {
		got := Mask(in)
		if strings.Contains(got, secret) {
			t.Errorf("Mask(%q) = %q, still shows %q", in, got, secret)
		}
	}
	if got := Mask("rm -rf node_modules && go test ./..."); got != "rm -rf node_modules && go test ./..." {
		t.Errorf("ordinary command changed: %q", got)
	}
}

func TestActionBoundsAndSummarises(t *testing.T) {
	long := strings.Repeat("echo hi; ", 200)
	a := Action("Bash", map[string]any{"command": long})
	if len(a) > MaxCommand+60 || !strings.Contains(a, "more bytes not shown") {
		t.Errorf("long command not bounded with a note: %d bytes", len(a))
	}
	if got := Action("Write", map[string]any{"file_path": "/x/main.go", "content": "package main"}); got != "Write /x/main.go (12 bytes)" {
		t.Errorf("Write preview = %q", got)
	}
	got := Action("mcp__db__query", map[string]any{"sql": "select 1", "password": "pw123456", "_actiongate_scripts": "x"})
	if strings.Contains(got, "pw123456") || strings.Contains(got, "_actiongate") || !strings.Contains(got, "select 1") {
		t.Errorf("generic preview = %q", got)
	}
}
