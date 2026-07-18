package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/admin"
	"github.com/muhammadusamahoyrr/actiongate/internal/gateway"
	"github.com/muhammadusamahoyrr/actiongate/policies"
)

const (
	defaultMatcher  = "Read|Edit|Write|NotebookEdit|Bash|Grep"
	hookTimeoutSecs = 360 // must outlive the gateway's approval wait (5m)
)

// cmdProtect installs enforcement for an agent. Only claude-code exists so
// far: a PreToolUse hook merged into the project's Claude Code settings
// (never clobbering what's there) plus the claude-code policy pack applied
// to the tenant.
func cmdProtect(args []string) int {
	if len(args) < 1 || args[0] != "claude-code" {
		fmt.Fprintln(os.Stderr, "usage: actiongate protect claude-code [-project DIR]")
		return 1
	}
	fs := flag.NewFlagSet("protect", flag.ContinueOnError)
	project := fs.String("project", ".", "project directory whose Claude Code settings get the hook")
	matcher := fs.String("matcher", defaultMatcher, "tool-name matcher for the PreToolUse hook")
	pack := fs.String("pack", "claude-code", "starter policy pack: "+strings.Join(policies.Names(), "|"))
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	ctx := context.Background()

	packJSON, ok := policies.Pack(*pack)
	if !ok {
		fmt.Fprintf(os.Stderr, "protect: unknown pack %q (have: %s)\n", *pack, strings.Join(policies.Names(), ", "))
		return 1
	}

	projectDir, err := filepath.Abs(*project)
	if err != nil {
		fmt.Fprintln(os.Stderr, "protect:", err)
		return 1
	}
	if info, err := os.Stat(projectDir); err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "protect: %s is not a directory\n", projectDir)
		return 1
	}

	// An enrolled gateway is a prerequisite — the hook is a dead end without it.
	statePath, err := gateway.DefaultStatePath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "protect:", err)
		return 1
	}
	state, err := gateway.LoadState(statePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "protect: gateway not enrolled — run `actiongate up` first")
		return 1
	}

	hookPath, err := findAgHook()
	if err != nil {
		fmt.Fprintln(os.Stderr, "protect:", err)
		return 1
	}

	if err := ensurePolicyPack(ctx, *pack, packJSON); err != nil {
		fmt.Fprintln(os.Stderr, "protect: policy pack:", err)
		return 1
	}

	settingsPath, err := installHook(projectDir, bashHookCommand(hookPath), *matcher)
	if err != nil {
		fmt.Fprintln(os.Stderr, "protect: hook:", err)
		return 1
	}
	fmt.Printf("• hook installed: %s\n", settingsPath)

	if !healthy(ctx, state.ServerURL) {
		fmt.Printf(`
⚠ the control plane at %s is not answering. The hook fails CLOSED:
  governed tools in this project are blocked until you run 'actiongate up'.
`, state.ServerURL)
	}

	fmt.Printf(`
%s is now governed. Try it — start Claude Code in that project and ask:

    read my .env

The read should be blocked with a 🛑 and the rule name. Destructive shell
commands (rm -rf, git push --force, DROP TABLE …) will pause for approval.

To uninstall: remove the actiongate entry from the "hooks" section of
%s (a backup was written next to it on first install).
`, projectDir, settingsPath)
	return 0
}

// findAgHook expects the ag-hook binary to sit next to this one (both are
// built into bin/ together, and ag-hook finds gateway the same way).
func findAgHook() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	name := "ag-hook"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	p := filepath.Join(filepath.Dir(self), name)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("%s not found — run `go build -o bin/ ./cmd/...` so all binaries sit together", p)
	}
	return p, nil
}

// ensurePolicyPack applies the chosen embedded pack to the local dev
// tenant unless the tenant's newest snapshot is already exactly this
// content. Without a dev config (custom deployment), policy stays whatever
// the operator set — we don't guess at other people's control planes.
func ensurePolicyPack(ctx context.Context, packName string, packJSON []byte) error {
	cfgPath, err := devConfigPath()
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Clean(cfgPath))
	if os.IsNotExist(err) {
		fmt.Println("• policy pack: skipped (no local dev config — apply policies/claude-code.json via `controlplane admin set-policy`)")
		return nil
	} else if err != nil {
		return err
	}
	var cfg devConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("corrupt dev config %s: %w", cfgPath, err)
	}
	if cfg.TenantID == "" || cfg.DatabaseURL == "" {
		return fmt.Errorf("dev config incomplete — run `actiongate up` first")
	}
	tenantID, err := uuid.Parse(cfg.TenantID)
	if err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	want := sha256.Sum256(packJSON)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("database unreachable — run `actiongate up` first: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		return err
	}
	var current []byte
	err = tx.QueryRow(ctx,
		`select content_hash from configuration_snapshots
		 where tenant_id = $1 order by version desc limit 1`,
		tenantID).Scan(&current)
	if err == nil && string(current) == string(want[:]) {
		fmt.Printf("• policy pack: %s (already active)\n", packName)
		return nil
	}
	_ = tx.Rollback(ctx)

	version, err := admin.SetPolicy(ctx, pool, tenantID, packJSON)
	if err != nil {
		return err
	}
	fmt.Printf("• policy pack: %s applied (version %d)\n", packName, version)
	return nil
}

// installHook merges the PreToolUse entry into the project's
// .claude/settings.local.json, preserving everything else in the file.
// Re-running replaces any previous actiongate entry (idempotent).
func installHook(projectDir, command, matcher string) (string, error) {
	settingsDir := filepath.Join(projectDir, ".claude")
	settingsPath := filepath.Join(settingsDir, "settings.local.json")

	settings := map[string]any{}
	raw, err := os.ReadFile(filepath.Clean(settingsPath))
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &settings); err != nil {
			return "", fmt.Errorf("%s exists but is not valid JSON — fix or remove it: %w", settingsPath, err)
		}
		backup := settingsPath + ".bak-actiongate"
		if _, err := os.Stat(backup); os.IsNotExist(err) {
			// #nosec G703 -- the project directory is the user's explicit
			// argument; writing the settings backup inside it is the feature.
			if err := os.WriteFile(backup, raw, 0o600); err != nil {
				return "", fmt.Errorf("backup: %w", err)
			}
		}
	case os.IsNotExist(err):
		if err := os.MkdirAll(settingsDir, 0o750); err != nil {
			return "", err
		}
	default:
		return "", err
	}

	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		hooks = map[string]any{}
		settings["hooks"] = hooks
	}
	pre, _ := hooks["PreToolUse"].([]any)
	kept := make([]any, 0, len(pre)+1)
	for _, entry := range pre {
		if !hookEntryIsOurs(entry) {
			kept = append(kept, entry)
		}
	}
	kept = append(kept, map[string]any{
		"matcher": matcher,
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": command,
			"timeout": hookTimeoutSecs,
		}},
	})
	hooks["PreToolUse"] = kept

	// SessionStart warning: if the control plane is down, say so loudly at
	// session start instead of letting governed tools fail closed
	// mysteriously mid-conversation.
	start, _ := hooks["SessionStart"].([]any)
	keptStart := make([]any, 0, len(start)+1)
	for _, entry := range start {
		if !hookEntryIsOurs(entry) {
			keptStart = append(keptStart, entry)
		}
	}
	keptStart = append(keptStart, map[string]any{
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": command + " -warn",
			"timeout": 10,
		}},
	})
	hooks["SessionStart"] = keptStart

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return "", err
	}
	tmp := settingsPath + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return "", err
	}
	return settingsPath, os.Rename(tmp, settingsPath)
}

func hookEntryIsOurs(entry any) bool {
	m, ok := entry.(map[string]any)
	if !ok {
		return false
	}
	inner, _ := m["hooks"].([]any)
	for _, h := range inner {
		hm, ok := h.(map[string]any)
		if !ok {
			continue
		}
		if cmd, _ := hm["command"].(string); strings.Contains(cmd, "ag-hook") {
			return true
		}
	}
	return false
}
