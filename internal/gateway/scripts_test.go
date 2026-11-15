package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/muhammadusamahoyrr/actiongate/internal/facts"
)

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Audit H2 end to end on the gateway side: the agent writes a script, then
// runs it; the gateway attaches the text and the analyzer sees what it does.
func TestAttachScriptsCatchesWriteThenRun(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "cleanup.sh", "#!/bin/sh\nrm -rf ~\n")
	write(t, dir, "tools/gen.sh", "git push --force origin main\n")
	write(t, dir, "job.py", "print(open('.env').read())\n")
	write(t, dir, "package.json", `{"scripts":{"clean":"rm -rf /","prebuild":"echo hi","build":"go build ./..."}}`)

	for cmd, want := range map[string]func(facts.Facts) bool{
		"bash cleanup.sh":      func(f facts.Facts) bool { return f.Destructive },
		"./cleanup.sh":         func(f facts.Facts) bool { return f.Destructive },
		"cd tools && ./gen.sh": func(f facts.Facts) bool { return f.Destructive },
		"python3 job.py":       func(f facts.Facts) bool { return f.SecretAccess },
		"npm run clean":        func(f facts.Facts) bool { return f.Destructive },
		"npm run build":        func(f facts.Facts) bool { return !f.Destructive && !f.Opaque },
		"bash missing.sh":      func(f facts.Facts) bool { return f.Opaque }, // may be created by the same command
		"bash -c 'echo hi'":    func(f facts.Facts) bool { return !f.Opaque },
		`cd "$X" && bash a.sh`: func(f facts.Facts) bool { return f.Opaque },
		"ls && git status":     func(f facts.Facts) bool { return !f.Opaque && !f.Destructive },
		"bash cleanup.sh # hi": func(f facts.Facts) bool { return f.Destructive },
	} {
		params := AttachScripts(map[string]any{"command": cmd}, "Bash", dir)
		if f := facts.Derive("Bash", params); !want(f) {
			t.Errorf("%q: facts %+v (attached %v)", cmd, f, params[facts.ScriptsKey])
		}
	}
}

// Only the gateway may fill the scripts key: a value the caller sent (an
// agent controls MCP params) is discarded, even when the command runs
// nothing.
func TestAttachScriptsDiscardsCallerValue(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "x.sh", "rm -rf ~\n")
	forged := []any{map[string]any{"path": "x.sh", "via": "shell", "content": "echo harmless"}}

	got := AttachScripts(map[string]any{"command": "bash x.sh", facts.ScriptsKey: forged}, "Bash", dir)
	if f := facts.Derive("Bash", got); !f.Destructive {
		t.Errorf("forged script content was trusted: %+v", got[facts.ScriptsKey])
	}
	got = AttachScripts(map[string]any{"command": "ls", facts.ScriptsKey: forged}, "Bash", dir)
	if _, ok := got[facts.ScriptsKey]; ok {
		t.Error("caller-supplied scripts key survived a command that runs no script")
	}
}

func TestAttachScriptsLimits(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "big.sh", strings.Repeat("echo hi\n", (maxScriptBytes/8)+10))
	write(t, dir, "app", "\x7fELF\x00\x00binary")
	write(t, dir, "data.sh", "\x00\x01binary-via-shell")

	f := facts.Derive("Bash", AttachScripts(map[string]any{"command": "bash big.sh"}, "Bash", dir))
	if !f.Opaque {
		t.Error("a script over the size limit must be opaque")
	}
	params := AttachScripts(map[string]any{"command": "./app --serve"}, "Bash", dir)
	if _, ok := params[facts.ScriptsKey]; ok {
		t.Error("a compiled program run by path should be skipped, not attached")
	}
	f = facts.Derive("Bash", AttachScripts(map[string]any{"command": "bash data.sh"}, "Bash", dir))
	if !f.Opaque {
		t.Error("binary content handed to a shell must be opaque")
	}
	// The original params are not mutated.
	in := map[string]any{"command": "bash big.sh"}
	_ = AttachScripts(in, "Bash", dir)
	if _, ok := in[facts.ScriptsKey]; ok {
		t.Error("AttachScripts mutated its input")
	}
}
