package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallHookPreservesSettingsAndBacksUpOnce(t *testing.T) {
	dir := t.TempDir()
	settingsDir := filepath.Join(dir, ".claude")
	if err := os.MkdirAll(settingsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(settingsDir, "settings.local.json")
	orig := []byte(`{"permissions":{"allow":["Bash(ls:*)"]}}`)
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatal(err)
	}

	for range 2 { // idempotent; the backup keeps the ORIGINAL
		if _, err := installHook(dir, "/c/ag-hook", "Bash"); err != nil {
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
		t.Error("user permissions were dropped")
	}
	hooks := got["hooks"].(map[string]any)
	if n := len(hooks["PreToolUse"].([]any)); n != 1 {
		t.Errorf("PreToolUse entries = %d, want 1", n)
	}
	backup, err := os.ReadFile(filepath.Clean(path + ".bak-actiongate"))
	if err != nil || string(backup) != string(orig) {
		t.Errorf("backup = %q, %v; want the original", backup, err)
	}
	if left, _ := filepath.Glob(path + ".*.tmp"); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func TestInstallHookCreatesFile(t *testing.T) {
	dir := t.TempDir()
	path, err := installHook(dir, "/c/ag-hook", "Bash")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".bak-actiongate"); !os.IsNotExist(err) {
		t.Error("backup created for a file that did not exist")
	}
}
