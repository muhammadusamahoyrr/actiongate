package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The managed hook keeps the organisation's own policy and hooks, replaces
// a previous actiongate entry, and runs ag-hook -locked.
func TestInstallManagedHookMergesAndLocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ClaudeCode", "managed-settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	org := `{"permissions":{"deny":["Read(./.env)"]},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/opt/org/audit"}]}]}}`
	if err := os.WriteFile(path, []byte(org), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := managedHookCommand("/opt/actiongate/ag-hook")
	for range 2 { // idempotent
		if err := installManagedHook(path, cmd, defaultMatcher, false); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["permissions"]; !ok {
		t.Error("organisation permissions were dropped")
	}
	if _, ok := got["allowManagedHooksOnly"]; ok {
		t.Error("allowManagedHooksOnly set without -exclusive")
	}
	pre := got["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("PreToolUse entries = %d, want org hook + ours", len(pre))
	}
	c, ok := managedHookInstalled(path)
	if !ok || !strings.HasSuffix(c, " -locked") {
		t.Errorf("managed hook command = %q, %v; want ag-hook -locked", c, ok)
	}
	start := got["hooks"].(map[string]any)["SessionStart"].([]any)
	warn := start[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"].(string)
	if !strings.Contains(warn, "-locked") || !strings.HasSuffix(warn, "-warn") {
		t.Errorf("SessionStart command = %q", warn)
	}
}

func TestInstallManagedHookExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := installManagedHook(path, managedHookCommand("/x/ag-hook"), defaultMatcher, true); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Clean(path))
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["allowManagedHooksOnly"] != true {
		t.Errorf("allowManagedHooksOnly = %v, want true", got["allowManagedHooksOnly"])
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o644 {
			t.Errorf("managed settings mode = %v, want 0644 (users must read it)", fi.Mode().Perm())
		}
	}
}

// Removing (empty command) drops only actiongate's entries, and leaves a
// missing file missing.
func TestInstallHookRemove(t *testing.T) {
	dir := t.TempDir()
	if _, err := installHook(dir, "", defaultMatcher); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude", "settings.local.json")); !os.IsNotExist(err) {
		t.Error("remove created a settings file")
	}
	if _, err := installHook(dir, "'/c/bin/ag-hook.exe'", defaultMatcher); err != nil {
		t.Fatal(err)
	}
	p, err := installHook(dir, "", defaultMatcher)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Clean(p))
	if _, ok := ourPreToolUseCommand(raw); ok {
		t.Errorf("actiongate hook still present after remove: %s", raw)
	}
}

func TestInstallBinariesCopiesAndVerifies(t *testing.T) {
	src, dst := t.TempDir(), filepath.Join(t.TempDir(), "actiongate")
	for _, b := range managedBinaries {
		if err := os.WriteFile(filepath.Join(src, exeName(b)), []byte("binary "+b), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	agHook, err := installBinaries(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	if agHook != filepath.Join(dst, exeName("ag-hook")) {
		t.Errorf("ag-hook path = %s", agHook)
	}
	for _, b := range managedBinaries {
		got, err := os.ReadFile(filepath.Join(dst, exeName(b))) //nolint:gosec // G304: test temp dir
		if err != nil || string(got) != "binary "+b {
			t.Errorf("%s = %q, %v", b, got, err)
		}
	}
	if _, err := installBinaries(t.TempDir(), dst); err == nil {
		t.Error("missing source binaries should fail")
	}
}

// A managed hook whose files the current user can write is reported as a
// failure: it looks protected and is not. (In a temp dir everything is
// writable, so this exercises exactly that path.)
func TestHookProtectionFlagsWritableManagedFiles(t *testing.T) {
	if isElevated() {
		t.Skip("doctor defers the writability check when elevated")
	}
	dir := t.TempDir()
	settings := filepath.Join(dir, "managed-settings.json")
	if ok, mark, _ := hookProtection(settings); !ok || mark != "!" {
		t.Errorf("no managed hook: ok=%v mark=%q, want warning only", ok, mark)
	}
	// The binary named in the command, not a default path, is checked.
	bin := filepath.Join(dir, "elsewhere", exeName("ag-hook"))
	if err := os.MkdirAll(filepath.Dir(bin), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installManagedHook(settings, managedHookCommand(bin), defaultMatcher, false); err != nil {
		t.Fatal(err)
	}
	if ok, mark, msg := hookProtection(settings); ok || mark != "✖" {
		t.Errorf("writable managed files: ok=%v mark=%q msg=%q, want failure", ok, mark, msg)
	}
	// A managed hook without -locked is a failure too.
	if err := installManagedHook(settings, bashHookCommand(bin), defaultMatcher, false); err != nil {
		t.Fatal(err)
	}
	if ok, _, msg := hookProtection(settings); ok || !strings.Contains(msg, "-locked") {
		t.Errorf("unlocked managed hook: ok=%v msg=%q, want -locked failure", ok, msg)
	}
}

func TestHookBinaryFromCommand(t *testing.T) {
	want := filepath.FromSlash("/opt/action gate/ag-hook")
	in := "'/opt/action gate/ag-hook' -locked"
	if runtime.GOOS == "windows" {
		want = `C:\PROGRA~1\actiongate\ag-hook.exe`
		in = "'/c/PROGRA~1/actiongate/ag-hook.exe' -locked"
	}
	if got, err := hookBinaryFromCommand(in); err != nil || got != want {
		t.Errorf("hookBinaryFromCommand(%q) = %q, %v; want %q", in, got, err, want)
	}
	if got, err := hookBinaryFromCommand(shellQuote("/opt/it's/ag-hook") + " -locked"); err != nil || filepath.ToSlash(got) != "/opt/it's/ag-hook" {
		t.Errorf("escaped quote: %q, %v", got, err)
	}
	if _, err := hookBinaryFromCommand("/bin/ag-hook"); err == nil {
		t.Error("unquoted command should not parse")
	}
}

func TestCheckInstallDirRejectsUserDir(t *testing.T) {
	if err := checkInstallDir(t.TempDir()); err == nil {
		t.Error("a user-owned temp dir must be refused as an install dir")
	}
}
