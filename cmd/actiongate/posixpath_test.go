package main

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"/c/bin/ag-hook":      "'/c/bin/ag-hook'",
		"/c/a b/ag-hook":      "'/c/a b/ag-hook'",
		"/c/a&b(1)$x/ag-hook": "'/c/a&b(1)$x/ag-hook'",
		"/c/it's/ag-hook":     `'/c/it'\''s/ag-hook'`,
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

// The quoted form must reach the program as exactly one argument.
func TestShellQuoteRoundTrip(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no POSIX shell")
	}
	if runtime.GOOS == "windows" && !strings.Contains(strings.ToLower(sh), "git") {
		t.Skip("sh is not Git Bash")
	}
	for _, in := range []string{"a b", "a&b;c", "x$(y)`z`", "it's", `back\slash`} {
		out, err := exec.Command(sh, "-c", "printf %s "+shellQuote(in)).Output() //nolint:gosec // G204: the point is to run the quoted string through sh
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if string(out) != in {
			t.Errorf("round trip %q -> %q", in, out)
		}
	}
}
