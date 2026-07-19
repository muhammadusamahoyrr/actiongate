package dbruntime

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
)

// pgVersion is the exact PostgreSQL patch version bundled (Step 1). It must match
// the binaries produced by the prime step and is used in the cache path.
const pgVersion = "18.3.0"

// pgHBAContents is the hardened access-control policy: authenticated
// (scram-sha-256) loopback only, no trust.
const pgHBAContents = `# Managed by ActionGate (dbruntime). Authenticated loopback only — no trust.
local   all   all                  scram-sha-256
host    all   all   127.0.0.1/32   scram-sha-256
host    all   all   ::1/128        scram-sha-256
`

// defaultBinariesPath is a per-user cache location for the extracted binaries,
// shared across clusters so extraction happens once.
func defaultBinariesPath() string {
	cache, err := os.UserCacheDir()
	if err != nil || cache == "" {
		cache = os.TempDir()
	}
	return filepath.Join(cache, "actiongate", "pg-"+pgVersion)
}

// exe adds the .exe suffix on Windows so os.Stat (which, unlike exec, does not
// auto-append it) can find the real binary.
func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func (e *Embedded) pgCtlBin() string  { return filepath.Join(e.cfg.BinariesPath, "bin", exe("pg_ctl")) }
func (e *Embedded) initdbBin() string { return filepath.Join(e.cfg.BinariesPath, "bin", exe("initdb")) }

// adminDSN is a connection string to the built-in `postgres` database, used for
// CREATE DATABASE (which cannot run against the target database itself).
func (e *Embedded) adminDSN() string {
	return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%d/postgres?sslmode=disable",
		e.cfg.Username, e.cfg.Password, e.cfg.Port)
}

var primeMu sync.Mutex

// ensureBinaries makes sure Postgres binaries exist at binPath/bin, extracting
// them once via a throwaway embedded-postgres start if absent. This reuses the
// library's proven per-platform binary sourcing while the runtime owns the real
// cluster lifecycle. Offline once the archive is cached.
func ensureBinaries(binPath string, startTimeout time.Duration) error {
	primeMu.Lock()
	defer primeMu.Unlock()

	if _, err := os.Stat(filepath.Join(binPath, "bin", exe("pg_ctl"))); err == nil {
		return nil
	}
	if err := os.MkdirAll(binPath, 0o755); err != nil {
		return fmt.Errorf("dbruntime: create binaries dir: %w", err)
	}
	tmp, err := os.MkdirTemp("", "ag-pgprime-*")
	if err != nil {
		return fmt.Errorf("dbruntime: prime temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	port, err := probeFreePort()
	if err != nil {
		return err
	}
	if startTimeout < 30*time.Second {
		startTimeout = 90 * time.Second
	}
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V18).
		Port(port).
		BinariesPath(binPath).
		RuntimePath(filepath.Join(tmp, "rt")).
		DataPath(filepath.Join(tmp, "data")).
		Username("prime").
		Password("prime").
		StartTimeout(startTimeout).
		Logger(io.Discard))
	if err := pg.Start(); err != nil {
		return fmt.Errorf("dbruntime: prime binaries: %w", err)
	}
	if err := pg.Stop(); err != nil {
		return fmt.Errorf("dbruntime: prime binaries (stop): %w", err)
	}
	return nil
}

// runInitdb initializes a fresh cluster with the builtin C.UTF-8 locale provider
// (deterministic and identical across platforms) and scram-sha-256 auth.
func (e *Embedded) runInitdb(ctx context.Context) error {
	pw, err := os.CreateTemp("", "ag-pwfile-*")
	if err != nil {
		return fmt.Errorf("create pwfile: %w", err)
	}
	pwPath := pw.Name()
	defer func() { _ = os.Remove(pwPath) }()
	if _, err := pw.WriteString(e.cfg.Password); err != nil {
		_ = pw.Close()
		return fmt.Errorf("write pwfile: %w", err)
	}
	if err := pw.Close(); err != nil {
		return fmt.Errorf("close pwfile: %w", err)
	}

	args := []string{
		"-A", "scram-sha-256",
		"-U", e.cfg.Username,
		"-D", e.cfg.DataPath,
		"--pwfile=" + pwPath,
		"--encoding=UTF8",
		"--locale-provider=builtin",
		"--builtin-locale=C.UTF-8",
		"--no-instructions",
	}
	return e.runTool(ctx, "initdb", e.initdbBin(), args)
}

// createAppDatabase creates the application database, which inherits the
// cluster's builtin C.UTF-8 locale. No-op when the target is `postgres` itself.
func (e *Embedded) createAppDatabase(ctx context.Context) error {
	if e.cfg.Database == "postgres" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(cctx, e.adminDSN())
	if err != nil {
		return fmt.Errorf("dbruntime: connect to create app database: %w", err)
	}
	defer func() { _ = conn.Close(cctx) }()

	stmt := fmt.Sprintf("CREATE DATABASE %s", pgx.Identifier{e.cfg.Database}.Sanitize())
	if _, err := conn.Exec(cctx, stmt); err != nil {
		// 42P04 = duplicate_database: tolerate a pre-existing database.
		if !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("dbruntime: create app database: %w", err)
		}
	}
	return nil
}

// pgctlStart boots the cluster and waits for it to accept connections.
//
// The server log is redirected with -l and this process's stdio is left at the
// null device. Assigning a pipe (e.g. MultiWriter) here deadlocks on Windows:
// the long-lived postgres child inherits the pipe, so it never reaches EOF and
// cmd.Run blocks forever. Short-lived tools (initdb, pg_ctl stop) are safe.
func (e *Embedded) pgctlStart(ctx context.Context) error {
	logPath := filepath.Join(filepath.Dir(e.cfg.DataPath), "postgres.log")
	opts := encodeStartOptions(e.cfg.Port, e.startParams())

	cctx, cancel := context.WithTimeout(ctx, e.cfg.StartTimeout)
	defer cancel()
	// #nosec G204 -- our own extracted tool; args are built here.
	cmd := exec.CommandContext(cctx, e.pgCtlBin(),
		"start", "-w", "-l", logPath, "-D", e.cfg.DataPath, "-o", opts)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pg_ctl start failed: %w\n%s", err, tailFile(logPath, 4096))
	}
	return nil
}

// tailFile returns up to the last n bytes of a file, for diagnostics.
func tailFile(path string, n int64) string {
	f, err := os.Open(path) //nolint:gosec // our own log path
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err == nil && fi.Size() > n {
		_, _ = f.Seek(-n, io.SeekEnd)
	}
	b, _ := io.ReadAll(f)
	return strings.TrimSpace(string(b))
}

// pgctlStop stops the cluster. Fast performs a clean checkpoint (warm next
// start); Immediate skips it (forcing WAL recovery next start) and is logged.
func (e *Embedded) pgctlStop(ctx context.Context, mode ShutdownMode) error {
	m := "fast"
	if mode == ShutdownImmediate {
		m = "immediate"
		_, _ = io.WriteString(e.cfg.Logger,
			"dbruntime: WARNING immediate shutdown — next start will run WAL crash recovery\n")
	}
	return e.runTool(ctx, "pg_ctl stop", e.pgCtlBin(),
		[]string{"stop", "-w", "-m", m, "-D", e.cfg.DataPath})
}

// startParams are the hardened GUCs plus any caller overrides.
func (e *Embedded) startParams() map[string]string {
	// listen_addresses=localhost binds both loopback addresses (127.0.0.1 + ::1),
	// never an external interface.
	params := map[string]string{"listen_addresses": "localhost"}
	for k, v := range e.cfg.ExtraParams {
		params[k] = v
	}
	return params
}

// encodeStartOptions renders the `-o` argument for pg_ctl (mirrors the library's
// own encoding, incl. the double-quoting Windows CMD requires).
func encodeStartOptions(port uint32, params map[string]string) string {
	opts := []string{fmt.Sprintf("-p %d", port)}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic order
	for _, k := range keys {
		opts = append(opts, fmt.Sprintf("-c %s=\"%s\"", k, params[k]))
	}
	return strings.Join(opts, " ")
}

// runTool runs a Postgres CLI tool, bounding it by StartTimeout and capturing
// output for diagnostics on failure.
func (e *Embedded) runTool(ctx context.Context, label, bin string, args []string) error {
	cctx, cancel := context.WithTimeout(ctx, e.cfg.StartTimeout)
	defer cancel()

	var buf bytes.Buffer
	// #nosec G204 -- bin is our own extracted Postgres tool; args are built here.
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Stdout = io.MultiWriter(&buf, e.cfg.Logger)
	cmd.Stderr = io.MultiWriter(&buf, e.cfg.Logger)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w\n%s", label, err, strings.TrimSpace(buf.String()))
	}
	return nil
}

// writePgHBA writes the hardened pg_hba.conf into a cluster's data directory.
func writePgHBA(dataPath string) error {
	if err := os.WriteFile(filepath.Join(dataPath, "pg_hba.conf"), []byte(pgHBAContents), 0o600); err != nil {
		return fmt.Errorf("dbruntime: write pg_hba.conf: %w", err)
	}
	return nil
}

// hardenAuth ensures pg_hba.conf is scram-sha-256-only and reloads if it changed.
// Fresh clusters already have the hardened file (written at init); this is the
// safety net for existing clusters whose pg_hba may predate hardening.
func (e *Embedded) hardenAuth(ctx context.Context) error {
	hba := filepath.Join(e.cfg.DataPath, "pg_hba.conf")
	existing, err := os.ReadFile(hba) //nolint:gosec // path derived from our own DataPath
	if err != nil {
		return fmt.Errorf("dbruntime: read pg_hba.conf: %w", err)
	}
	if string(existing) == pgHBAContents {
		return nil
	}
	if err := writePgHBA(e.cfg.DataPath); err != nil {
		return err
	}

	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(cctx, e.dsn)
	if err != nil {
		return fmt.Errorf("dbruntime: connect to reload pg_hba: %w", err)
	}
	defer func() { _ = conn.Close(cctx) }()
	if _, err := conn.Exec(cctx, "SELECT pg_reload_conf()"); err != nil {
		return fmt.Errorf("dbruntime: reload pg_hba: %w", err)
	}
	return nil
}
