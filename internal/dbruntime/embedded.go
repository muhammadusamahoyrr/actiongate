package dbruntime

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
)

// Config configures an Embedded runtime.
type Config struct {
	// DataPath is the PERSISTENT cluster directory (survives restarts).
	DataPath string
	// RuntimePath is the EPHEMERAL extracted-binaries directory. The embedded
	// library erases and recreates it on every Start, so it must not equal
	// DataPath. If empty, the library derives one.
	RuntimePath string
	// BinariesPath points at pre-vendored Postgres binaries. When set and
	// BinariesPath/bin exists, nothing is downloaded (offline install). When
	// empty, binaries are fetched once and cached.
	BinariesPath string
	// Port is the TCP port to listen on. When 0, the runtime probes a free port
	// at New() and exposes it via Port(); the caller persists it (e.g. to
	// dev.json.db_port).
	Port uint32
	// Database, Username, Password are the cluster's initial credentials. The
	// password is stored SCRAM-hashed at init (PG18 default) and must stay stable
	// across restarts of a persistent DataPath. Use GeneratePassword for a strong
	// one and persist it alongside DataPath.
	Database string
	Username string
	Password string
	// Version is the ActionGate binary version, surfaced in HealthReport.Version.
	Version string
	// StartTimeout bounds a cold start (initdb + first boot). Defaults to 90s,
	// floored at 30s, to tolerate corporate AV scanning each extracted file.
	StartTimeout time.Duration
	// Logger receives the embedded Postgres process output. Defaults to
	// io.Discard.
	Logger io.Writer
	// ExtraParams are extra postgresql GUCs passed as `-c key=value` at start.
	// Primarily an override/testing seam (e.g. forcing fsync=off to exercise the
	// durability guard). They merge over the runtime's own hardening params.
	ExtraParams map[string]string
}

// Embedded is a DatabaseRuntime backed by an embedded PostgreSQL cluster.
type Embedded struct {
	cfg Config
	dsn string

	mu      sync.Mutex
	pg      *embeddedpostgres.EmbeddedPostgres
	running bool
}

// compile-time check that Embedded satisfies the interface.
var _ DatabaseRuntime = (*Embedded)(nil)

// New builds an Embedded runtime from cfg. It does not start Postgres.
func New(cfg Config) (*Embedded, error) {
	if cfg.DataPath == "" {
		return nil, errors.New("dbruntime: DataPath is required")
	}
	if cfg.Port == 0 {
		p, err := probeFreePort()
		if err != nil {
			return nil, fmt.Errorf("dbruntime: probe free port: %w", err)
		}
		cfg.Port = p
	}
	if cfg.Database == "" {
		cfg.Database = "actiongate"
	}
	if cfg.Username == "" {
		cfg.Username = "ag"
	}
	if cfg.Password == "" {
		cfg.Password = "ag"
	}
	if cfg.StartTimeout < 30*time.Second {
		cfg.StartTimeout = 90 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = io.Discard
	}

	dsn := fmt.Sprintf("postgres://%s:%s@127.0.0.1:%d/%s?sslmode=disable",
		cfg.Username, cfg.Password, cfg.Port, cfg.Database)

	return &Embedded{cfg: cfg, dsn: dsn}, nil
}

// GeneratePassword returns a URL-safe random 32-byte password for a new cluster.
func GeneratePassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("dbruntime: generate password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// probeFreePort asks the OS for an unused TCP port on loopback. There is a small
// window between closing the listener and Postgres binding; acceptable because a
// persistent DataPath keeps the same port on later starts.
func probeFreePort() (uint32, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return uint32(l.Addr().(*net.TCPAddr).Port), nil
}

func (e *Embedded) build() *embeddedpostgres.EmbeddedPostgres {
	// listen_addresses=localhost binds both loopback addresses (127.0.0.1 + ::1),
	// never an external interface, and avoids the v4/v6 resolution mismatch the
	// library's own host=localhost connections would otherwise hit.
	params := map[string]string{"listen_addresses": "localhost"}
	for k, v := range e.cfg.ExtraParams {
		params[k] = v
	}

	pc := embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.V18).
		Port(e.cfg.Port).
		Database(e.cfg.Database).
		Username(e.cfg.Username).
		Password(e.cfg.Password).
		DataPath(e.cfg.DataPath).
		StartTimeout(e.cfg.StartTimeout).
		StartParameters(params).
		Logger(e.cfg.Logger)
	if e.cfg.RuntimePath != "" {
		pc = pc.RuntimePath(e.cfg.RuntimePath)
	}
	if e.cfg.BinariesPath != "" {
		pc = pc.BinariesPath(e.cfg.BinariesPath)
	}
	return embeddedpostgres.NewDatabase(pc)
}

// DSN returns the connection string for the cluster.
func (e *Embedded) DSN() string { return e.dsn }

// Port returns the TCP port the cluster listens on (resolved if it was probed).
func (e *Embedded) Port() uint32 { return e.cfg.Port }

// Start brings the cluster up, hardens local auth to scram-sha-256, and refuses
// to run if durability GUCs are unsafe. A fresh cluster is initialized only when
// DataPath holds none; an existing DataPath is reused (data persists).
func (e *Embedded) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return nil
	}
	// Classify before starting: if a cluster already exists and fails to boot
	// (e.g. WAL recovery could not complete), we must surface a restore-directed
	// error and never let anything reinitialize over the audit history.
	state := ClassifyCluster(e.cfg.DataPath)
	pg := e.build()
	if err := runCtx(ctx, pg.Start); err != nil {
		if state == ClusterPresent {
			return &ClusterError{Path: e.cfg.DataPath, Err: err}
		}
		return fmt.Errorf("dbruntime: start embedded postgres: %w", err)
	}
	e.pg = pg
	e.running = true

	// Defense in depth on the on-disk cluster (initdb already restricts, but the
	// service may run as a broader account). Best-effort.
	_ = hardenDataDirPerms(e.cfg.DataPath)

	// Upgrade the library's default `password` auth to scram-sha-256 (no trust
	// anywhere) and reload.
	if err := e.hardenAuth(ctx); err != nil {
		e.stopLocked(ctx)
		return err
	}

	// The "survives a power-cord pull" guarantee is unenforceable without these.
	if err := e.checkDurability(ctx); err != nil {
		e.stopLocked(ctx)
		return err
	}
	return nil
}

// Stop shuts the cluster down. In M2 both modes perform the library's graceful
// stop; M4 differentiates fast vs immediate via pg_ctl.
func (e *Embedded) Stop(ctx context.Context, _ ShutdownMode) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopLocked(ctx)
}

// stopLocked stops the cluster; the caller must hold e.mu.
func (e *Embedded) stopLocked(ctx context.Context) error {
	if !e.running || e.pg == nil {
		return nil
	}
	if err := runCtx(ctx, e.pg.Stop); err != nil {
		return fmt.Errorf("dbruntime: stop embedded postgres: %w", err)
	}
	e.pg = nil
	e.running = false
	return nil
}

// Health probes the running cluster with a SELECT 1. A down database is
// reported in the HealthReport, not as an error.
func (e *Embedded) Health(ctx context.Context) (HealthReport, error) {
	rep := HealthReport{Version: e.cfg.Version}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, e.dsn)
	if err != nil {
		rep.Database = ComponentHealth{Healthy: false, Message: fmt.Sprintf("cannot connect: %v", err)}
		return rep, nil
	}
	defer func() { _ = conn.Close(ctx) }()

	var one int
	if err := conn.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
		rep.Database = ComponentHealth{Healthy: false, Message: fmt.Sprintf("query failed: %v", err)}
		return rep, nil
	}
	rep.Database = ComponentHealth{Healthy: true, Message: "ok"}
	return rep, nil
}

// pgHBAContents is the hardened access-control policy: authenticated
// (scram-sha-256) loopback only, no trust.
const pgHBAContents = `# Managed by ActionGate (dbruntime). Authenticated loopback only — no trust.
local   all   all                  scram-sha-256
host    all   all   127.0.0.1/32   scram-sha-256
host    all   all   ::1/128        scram-sha-256
`

// hardenAuth overwrites pg_hba.conf with scram-sha-256-only rules and reloads.
// The role password is already SCRAM-hashed at init (PG18 default), so scram
// authentication succeeds with the same password.
func (e *Embedded) hardenAuth(ctx context.Context) error {
	hba := filepath.Join(e.cfg.DataPath, "pg_hba.conf")
	existing, err := os.ReadFile(hba) //nolint:gosec // path derived from our own DataPath
	if err != nil {
		return fmt.Errorf("dbruntime: read pg_hba.conf: %w", err)
	}
	if string(existing) == pgHBAContents {
		return nil // already hardened (persistent DataPath, later start)
	}
	if err := os.WriteFile(hba, []byte(pgHBAContents), 0o600); err != nil {
		return fmt.Errorf("dbruntime: write pg_hba.conf: %w", err)
	}

	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(cctx, e.dsn) // pre-reload auth is still `password`
	if err != nil {
		return fmt.Errorf("dbruntime: connect to reload pg_hba: %w", err)
	}
	defer func() { _ = conn.Close(cctx) }()
	if _, err := conn.Exec(cctx, "SELECT pg_reload_conf()"); err != nil {
		return fmt.Errorf("dbruntime: reload pg_hba: %w", err)
	}
	return nil
}

// checkDurability refuses to run if a GUC that the tamper-evident audit log
// depends on for crash survival has been weakened.
func (e *Embedded) checkDurability(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(cctx, e.dsn)
	if err != nil {
		return fmt.Errorf("dbruntime: connect for durability guard: %w", err)
	}
	defer func() { _ = conn.Close(cctx) }()

	for _, g := range []string{"fsync", "synchronous_commit", "full_page_writes"} {
		var val string
		if err := conn.QueryRow(cctx, "SHOW "+g).Scan(&val); err != nil {
			return fmt.Errorf("dbruntime: durability guard: read %s: %w", g, err)
		}
		if val != "on" {
			return fmt.Errorf("dbruntime: durability guard: %s=%q, refusing to run (want on)", g, val)
		}
	}
	return nil
}

// runCtx runs a blocking library call while honoring ctx cancellation. If ctx is
// cancelled the call is abandoned (it finishes in the background); M4's
// self-owned lifecycle removes this compromise.
func runCtx(ctx context.Context, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}
