package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/dbruntime"
	"github.com/muhammadusamahoyrr/actiongate/internal/health"
)

// version is the ActionGate binary version. Overridable at build time via
// -ldflags "-X main.version=...".
var version = "dev"

// cmdDoctor runs an end-to-end health check and prints a human-readable report,
// exiting non-zero if anything is unhealthy. It is the single command to reach
// for when "it doesn't work".
func cmdDoctor(_ []string) int {
	path, err := devConfigPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "actiongate doctor:", err)
		return 1
	}
	cfg, err := loadDevConfigAt(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "actiongate doctor:", err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Printf("ActionGate %s\n\n", version)

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open database pool:", err)
		return 1
	}
	defer pool.Close()

	rep := health.Check(ctx, pool, health.Options{
		Version:     version,
		TenantID:    cfg.TenantID,
		EpochKeyIDs: append([]string{cfg.epochKeyID()}, cfg.EpochRetiredKeyIDs...),
	})

	ok := true
	line := func(name string, c dbruntime.ComponentHealth) {
		ok = ok && c.Healthy
		fmt.Printf("%s %-16s %s\n", mark(c.Healthy), name, c.Message)
	}
	line("Database", rep.Database)
	line("Schema", rep.Schema)
	line("Tenant", rep.Tenant)
	line("Signing keys", rep.Keys)
	line("Sealer", rep.Sealer)

	// The control plane is a separate process; report it directly so a running
	// service whose HTTP endpoint is not answering is diagnosed here.
	cpHealthy := healthy(ctx, cfg.ServerURL)
	cpMsg := "answering at " + cfg.ServerURL
	if !cpHealthy {
		cpMsg = "not answering at " + cfg.ServerURL + " — hooked projects fail closed"
	}
	ok = ok && cpHealthy
	fmt.Printf("%s %-16s %s\n", mark(cpHealthy), "Control plane", cpMsg)

	hookOK, hookMark, hookMsg := hookProtection(managedSettingsPath())
	ok = ok && hookOK
	fmt.Printf("%s %-16s %s\n", hookMark, "Hook", hookMsg)

	fmt.Println()
	if ok {
		fmt.Println("Everything healthy.")
		return 0
	}
	fmt.Println("Some checks failed — see the ✖ lines above.")
	return 1
}

// hookProtection reports how tamper-resistant the hook install is. A
// project-level hook is a warning (it works, but the agent can edit it);
// a managed hook whose files this user can write is a failure, because it
// looks protected and is not.
//
// It checks what the hook really runs (the binary named in the managed
// command and the gateway beside it, not a default path), and the
// directories holding them and the settings file plus their parents:
// whoever can create files in a directory can rename a file away and put
// their own in its place.
func hookProtection(settingsPath string) (ok bool, mark, msg string) {
	cmd, present := managedHookInstalled(settingsPath)
	if !present {
		return true, "!", "project-level only — the agent can edit it; run `actiongate protect claude-code -managed` as administrator"
	}
	if isElevated() {
		return true, "!", "managed hook present (run doctor as your normal user to check the files are out of its reach)"
	}
	agHook, err := hookBinaryFromCommand(cmd)
	if err != nil {
		return false, "✖", "managed hook command not understood (" + err.Error() + "): " + cmd
	}
	if !strings.Contains(cmd, "-locked") {
		return false, "✖", "managed hook does not run ag-hook -locked — env overrides could redirect it; re-run protect -managed"
	}
	binDir := filepath.Dir(agHook)
	for _, p := range []string{settingsPath, agHook, filepath.Join(binDir, exeName("gateway"))} {
		if writableByCurrentUser(p) {
			return false, "✖", "managed hook present, but " + p + " is writable by you — the agent could replace it"
		}
	}
	for _, d := range []string{filepath.Dir(settingsPath), binDir, filepath.Dir(filepath.Dir(settingsPath)), filepath.Dir(binDir)} {
		if canCreateIn(d) {
			return false, "✖", "managed hook present, but you can create files in " + d + " — the agent could swap the files"
		}
	}
	return true, "✔", "managed (admin-only): " + settingsPath
}

// hookBinaryFromCommand recovers the ag-hook path from a hook command as
// bashHookCommand renders it: single-quoted, POSIX-style ('/c/…' on
// Windows), followed by flags.
func hookBinaryFromCommand(cmd string) (string, error) {
	cmd = strings.TrimSpace(cmd)
	if !strings.HasPrefix(cmd, "'") {
		return "", errors.New("expected a single-quoted path")
	}
	var b strings.Builder
	for i := 1; i < len(cmd); i++ {
		if cmd[i] != '\'' {
			b.WriteByte(cmd[i])
			continue
		}
		if strings.HasPrefix(cmd[i:], `'\''`) { // shellQuote's escaped quote
			b.WriteByte('\'')
			i += 3
			continue
		}
		p := b.String()
		if runtime.GOOS == "windows" && len(p) > 2 && p[0] == '/' && p[2] == '/' {
			p = strings.ToUpper(p[1:2]) + ":" + p[2:]
		}
		return filepath.FromSlash(p), nil
	}
	return "", errors.New("unterminated quote")
}

// canCreateIn reports whether this user can create a file in dir (it
// creates and removes a temp file to find out).
func canCreateIn(dir string) bool {
	f, err := os.CreateTemp(dir, ".actiongate-doctor-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

func mark(ok bool) string {
	if ok {
		return "✔"
	}
	return "✖"
}
