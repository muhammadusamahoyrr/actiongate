package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/admin"
	"github.com/muhammadusamahoyrr/actiongate/internal/fsutil"
	"github.com/muhammadusamahoyrr/actiongate/internal/gateway"
	"github.com/muhammadusamahoyrr/actiongate/policies"
)

const (
	defaultMatcher  = "Read|Edit|MultiEdit|Write|NotebookEdit|Bash|PowerShell|Grep"
	hookTimeoutSecs = 360 // must outlive the gateway's approval wait (5m)
)

// cmdProtect installs enforcement for an agent. Only claude-code exists so
// far: a PreToolUse hook merged into the project's Claude Code settings
// (never clobbering what's there) plus the claude-code policy pack applied
// to the tenant.
func cmdProtect(args []string) int {
	if len(args) < 1 || args[0] != "claude-code" {
		fmt.Fprintln(os.Stderr, "usage: actiongate protect claude-code [-project DIR] | -managed [-install-dir DIR] [-exclusive]")
		return 1
	}
	fs := flag.NewFlagSet("protect", flag.ContinueOnError)
	project := fs.String("project", ".", "project directory whose Claude Code settings get the hook")
	matcher := fs.String("matcher", defaultMatcher, "tool-name matcher for the PreToolUse hook")
	pack := fs.String("pack", "claude-code", "starter policy pack: "+strings.Join(policies.Names(), "|"))
	managed := fs.Bool("managed", false, "admin: install the hook machine-wide in Claude Code's managed settings, where the agent cannot remove it")
	installDir := fs.String("install-dir", defaultInstallDir(), "with -managed: admin-only directory to copy ag-hook and gateway into")
	exclusive := fs.Bool("exclusive", false, "with -managed: also set allowManagedHooksOnly (blocks every non-managed hook)")
	if err := fs.Parse(args[1:]); err != nil {
		return 1
	}
	ctx := context.Background()
	if *managed {
		return protectManaged(*installDir, *matcher, *exclusive)
	}

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

	// With a managed hook in place, a project hook would only run every
	// check twice (two approval prompts). Remove ours instead of adding it.
	if cmd, ok := managedHookInstalled(managedSettingsPath()); ok {
		settingsPath, err := installHook(projectDir, "", *matcher)
		if err != nil {
			fmt.Fprintln(os.Stderr, "protect: hook:", err)
			return 1
		}
		fmt.Printf("• managed hook already governs every project (%s)\n", cmd)
		fmt.Printf("• no project hook needed; removed any actiongate entry from %s\n", settingsPath)
		fmt.Printf("• policy pack %q applied — done\n", *pack)
		return 0
	}

	settingsPath, err := installHook(projectDir, bashHookCommand(hookPath), *matcher)
	if err != nil {
		fmt.Fprintln(os.Stderr, "protect: hook:", err)
		return 1
	}
	fmt.Printf("• hook installed: %s\n", settingsPath)
	fmt.Println("  (project-level: an agent can edit this file. For a hook it cannot remove, run")
	fmt.Println("   `actiongate protect claude-code -managed` once as administrator.)")

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
//
// Claude Code writes this file too (e.g. when the user picks "always
// allow"), and an advisory lock cannot coordinate with it. So the merge is
// optimistic: just before writing, the file is read again, and if it
// changed since the merge started, the merge is redone on the new content.
// That shrinks the lost-update window from the whole merge to the instant
// between the final read and the rename.
//
// An empty command removes actiongate's entries and adds none.
func installHook(projectDir, command, matcher string) (string, error) {
	settingsPath := filepath.Join(projectDir, ".claude", "settings.local.json")
	return settingsPath, updateHookFile(settingsPath, command, matcher, 0o600, nil)
}

// updateHookFile is installHook for any Claude Code settings file: perm is
// the mode of a newly created file, and set holds extra top-level keys to
// write (e.g. allowManagedHooksOnly in managed settings).
func updateHookFile(settingsPath, command, matcher string, perm os.FileMode, set map[string]any) error {
	settingsDir := filepath.Dir(settingsPath)
	const attempts = 5
	for range attempts {
		raw, err := os.ReadFile(filepath.Clean(settingsPath))
		exists := err == nil
		switch {
		case exists:
			if err := backupSettings(settingsPath, raw); err != nil {
				return err
			}
		case os.IsNotExist(err):
			if command == "" && len(set) == 0 {
				return nil // removing from a file that does not exist
			}
			if err := os.MkdirAll(settingsDir, 0o755); err != nil { //nolint:gosec // G301: Claude Code (the user) must read settings dirs
				return err
			}
		default:
			return err
		}

		out, err := mergeHookSettings(settingsPath, raw, exists, command, matcher, set)
		if err != nil {
			return err
		}

		again, err := os.ReadFile(filepath.Clean(settingsPath))
		if exists != (err == nil) || (err != nil && !os.IsNotExist(err)) || !bytes.Equal(raw, again) {
			continue // someone else wrote the file meanwhile: merge again
		}
		// The settings file is the user's: keep its mode and, if it is a
		// symlink (dotfiles repos), write through the link instead of
		// replacing it.
		return fsutil.UpdateFileAtomic(settingsPath, out, perm)
	}
	return fmt.Errorf("%s kept changing while actiongate was updating it (is Claude Code writing it?) — retry", settingsPath)
}

// backupSettings keeps the user's original settings once, the first time
// actiongate touches them. O_EXCL makes "only if no backup yet" atomic, and
// a failed write removes the partial backup so the next run retries.
func backupSettings(settingsPath string, raw []byte) error {
	backup := settingsPath + ".bak-actiongate"
	// #nosec G304 G703 -- the project directory is the user's explicit
	// argument; writing the settings backup inside it is the feature.
	f, err := os.OpenFile(filepath.Clean(backup), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	_, werr := f.Write(raw)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(backup)
		return fmt.Errorf("backup: %w", errors.Join(werr, cerr))
	}
	return nil
}

// mergeHookSettings returns raw (the current settings, if exists) with
// actiongate's hook entries replaced, as the bytes to write.
func mergeHookSettings(settingsPath string, raw []byte, exists bool, command, matcher string, set map[string]any) ([]byte, error) {
	settings := map[string]any{}
	if exists {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return nil, fmt.Errorf("%s exists but is not valid JSON — fix or remove it: %w", settingsPath, err)
		}
	}
	for k, v := range set {
		settings[k] = v
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
	if command != "" { // "" removes actiongate's entries only
		kept = append(kept, map[string]any{
			"matcher": matcher,
			"hooks": []any{map[string]any{
				"type":    "command",
				"command": command,
				"timeout": hookTimeoutSecs,
			}},
		})
	}
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
	if command != "" {
		keptStart = append(keptStart, map[string]any{
			"hooks": []any{map[string]any{
				"type":    "command",
				"command": command + " -warn",
				"timeout": 10,
			}},
		})
	}
	hooks["SessionStart"] = keptStart

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// ourPreToolUseCommand finds actiongate's PreToolUse hook command in a
// settings file's JSON.
func ourPreToolUseCommand(raw []byte) (string, bool) {
	var settings map[string]any
	if json.Unmarshal(raw, &settings) != nil {
		return "", false
	}
	hooks, _ := settings["hooks"].(map[string]any)
	pre, _ := hooks["PreToolUse"].([]any)
	for _, entry := range pre {
		if !hookEntryIsOurs(entry) {
			continue
		}
		inner, _ := entry.(map[string]any)["hooks"].([]any)
		for _, h := range inner {
			if hm, ok := h.(map[string]any); ok {
				if cmd, _ := hm["command"].(string); strings.Contains(cmd, "ag-hook") {
					return cmd, true
				}
			}
		}
	}
	return "", false
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
