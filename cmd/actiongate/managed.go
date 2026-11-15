package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/muhammadusamahoyrr/actiongate/internal/fsutil"
)

// Managed install: the project-level hook lives in a file the governed
// agent can edit (and Claude Code applies hook edits live), and ag-hook
// lives in a directory the agent can write. `protect -managed` moves both
// out of the agent's reach:
//
//   - the hook goes into Claude Code's managed settings, an admin-owned
//     file whose hooks user/project/local settings cannot remove, and that
//     a user-level "disableAllHooks" cannot switch off;
//   - ag-hook and gateway are copied into an admin-owned install directory,
//     so the hook command cannot be swapped for a no-op;
//   - the hook runs ag-hook -locked, which ignores the env overrides a
//     settings file could inject (see cmd/ag-hook).
//
// This holds against an agent running as a standard user. An agent running
// as a local administrator can edit the managed file too.

// managedSettingsPath is where Claude Code reads file-based managed
// settings. (Windows no longer reads the legacy C:\ProgramData path.)
func managedSettingsPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(programFiles(), "ClaudeCode", "managed-settings.json")
	case "darwin":
		return "/Library/Application Support/ClaudeCode/managed-settings.json"
	default:
		return "/etc/claude-code/managed-settings.json"
	}
}

// defaultInstallDir is the admin-owned directory the binaries are copied
// into. Program Files and /usr/local/lib are writable only by
// administrators by default.
func defaultInstallDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(programFiles(), "actiongate")
	}
	return "/usr/local/lib/actiongate"
}

func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// managedBinaries are copied together: ag-hook runs its sibling gateway.
var managedBinaries = []string{"ag-hook", "gateway"}

// installBinaries copies the binaries from srcDir into dstDir and checks
// each copy byte-for-byte. Returns the installed ag-hook path.
func installBinaries(srcDir, dstDir string) (string, error) {
	if err := os.MkdirAll(dstDir, 0o755); err != nil { //nolint:gosec // G301: users must be able to run the hook
		return "", fmt.Errorf("create %s: %w", dstDir, err)
	}
	for _, b := range managedBinaries {
		src := filepath.Join(srcDir, exeName(b))
		dst := filepath.Join(dstDir, exeName(b))
		raw, err := os.ReadFile(filepath.Clean(src))
		if err != nil {
			return "", fmt.Errorf("%s: %w — build all binaries into one directory first", src, err)
		}
		if err := fsutil.WriteFileAtomic(dst, raw, 0o755); err != nil {
			if runtime.GOOS == "windows" && errors.Is(err, os.ErrPermission) {
				return "", fmt.Errorf("%w — if a Claude Code session is running the old copy, close it and retry", err)
			}
			return "", err
		}
		if err := sameContent(src, dst); err != nil {
			return "", err
		}
	}
	return filepath.Join(dstDir, exeName("ag-hook")), nil
}

func sameContent(a, b string) error {
	ha, err := fileSHA256(a)
	if err != nil {
		return err
	}
	hb, err := fileSHA256(b)
	if err != nil {
		return err
	}
	if !bytes.Equal(ha, hb) {
		return fmt.Errorf("installed %s does not match %s", b, a)
	}
	return nil
}

func fileSHA256(p string) ([]byte, error) {
	f, err := os.Open(filepath.Clean(p))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// protectManaged is `actiongate protect claude-code -managed`: the admin
// half of the install. It touches only admin-owned locations, never the
// user's gateway state or tenant — under UAC on a standard account the
// elevated process may be a different admin user with a different profile.
// The user then runs plain `actiongate protect claude-code` for the policy
// pack, which sees the managed hook and skips the project one.
func protectManaged(installDir, matcher string, exclusive bool) int {
	if !isElevated() {
		fmt.Fprintf(os.Stderr, "protect -managed: needs administrator rights — %s.\n", elevateHint)
		return 1
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "protect -managed:", err)
		return 1
	}
	installDir, err = filepath.Abs(installDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "protect -managed:", err)
		return 1
	}
	agHook, err := installBinaries(filepath.Dir(self), installDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "protect -managed: install binaries:", err)
		return 1
	}
	fmt.Printf("• installed %s into %s (admin-only)\n", managedBinaries, installDir)

	settingsPath := managedSettingsPath()
	command := managedHookCommand(agHook)
	if err := installManagedHook(settingsPath, command, matcher, exclusive); err != nil {
		fmt.Fprintln(os.Stderr, "protect -managed: managed settings:", err)
		return 1
	}
	fmt.Printf("• managed hook written: %s\n    %s\n", settingsPath, command)
	if exclusive {
		fmt.Println("• allowManagedHooksOnly: user, project, local and plugin hooks are now blocked")
	}

	fmt.Print(`
Every Claude Code session on this machine is now governed by a hook that
user, project and local settings cannot remove, running binaries the agent
cannot replace. It takes effect in running sessions too.

Next, as your normal (non-admin) user:

    actiongate protect claude-code -project <dir>

applies the policy pack and removes the now-redundant project hook.

Limits: an agent running as an administrator can still edit managed
settings, and gateway.json (enrollment + receipts) stays in your profile,
guarded by the self_tamper rule rather than file permissions.
`)
	return 0
}

// managedHookCommand is the hook command for an installed ag-hook.
func managedHookCommand(agHook string) string {
	return bashHookCommand(agHook) + " -locked"
}

// installManagedHook merges actiongate's hook into the managed settings
// file. Other keys and other hooks in it (the organisation's own policy)
// are kept. exclusive also sets allowManagedHooksOnly, which blocks every
// user, project, local and plugin hook — stricter, and disruptive if you
// rely on other hooks.
func installManagedHook(settingsPath, command, matcher string, exclusive bool) error {
	var set map[string]any
	if exclusive {
		set = map[string]any{"allowManagedHooksOnly": true}
	}
	// 0644: Claude Code runs as the user and must read it; only admins
	// can write it, which is the point.
	return updateHookFile(settingsPath, command, matcher, 0o644, set)
}

// managedHookInstalled reports whether the managed settings carry an
// actiongate PreToolUse hook, and which command it runs.
func managedHookInstalled(settingsPath string) (string, bool) {
	raw, err := os.ReadFile(filepath.Clean(settingsPath))
	if err != nil {
		return "", false
	}
	return ourPreToolUseCommand(raw)
}

// writableByCurrentUser reports whether this process can open p for
// writing — i.e. whether the agent, running as this user, could replace it.
// Opening for write does not modify the file.
func writableByCurrentUser(p string) bool {
	f, err := os.OpenFile(filepath.Clean(p), os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
