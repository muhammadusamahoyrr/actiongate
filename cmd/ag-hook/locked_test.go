package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// Hook settings can set env vars for the hook process. Locked, ag-hook must
// not let them redirect the gateway binary, the agent identity, or the
// gateway state.
func TestLockedIgnoresEnvOverrides(t *testing.T) {
	fake := t.TempDir()
	t.Setenv("AG_HOOK_GATEWAY", filepath.Join(fake, "noop"))
	t.Setenv("AG_HOOK_AGENT", "trusted-agent")
	t.Setenv("APPDATA", fake)         // windows
	t.Setenv("XDG_CONFIG_HOME", fake) // linux
	t.Setenv("HOME", fake)            // darwin / linux fallback

	locked = false
	if gw, _ := gatewayPath(); gw != filepath.Join(fake, "noop") {
		t.Fatalf("unlocked: AG_HOOK_GATEWAY should apply (operator escape hatch), got %s", gw)
	}

	locked = true
	defer func() { locked = false }()
	if gw, _ := gatewayPath(); strings.HasPrefix(gw, fake) {
		t.Errorf("locked: gateway path %s follows AG_HOOK_GATEWAY", gw)
	}
	if a := overridable("AG_HOOK_AGENT", "claude-code"); a != "claude-code" {
		t.Errorf("locked: agent id = %q, want claude-code", a)
	}
	state, err := profileStatePath()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(state, fake) {
		t.Errorf("locked: state path %s follows the environment", state)
	}
	if filepath.Base(state) != "gateway.json" || filepath.Base(filepath.Dir(state)) != "actiongate" {
		t.Errorf("state path %s, want .../actiongate/gateway.json", state)
	}
}
