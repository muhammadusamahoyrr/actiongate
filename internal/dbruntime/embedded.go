package dbruntime

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Config configures an Embedded runtime.
type Config struct {
	// DataPath is the PERSISTENT cluster directory (survives restarts).
	DataPath string
	// RuntimePath is only used while priming (extracting) the Postgres binaries;
	// the owned lifecycle no longer keeps a per-start runtime dir. If empty, a
	// temp dir is used during priming.
	RuntimePath string
	// BinariesPath is where the Postgres binaries live. If empty, a per-user
	// cache location is used. When BinariesPath/bin/pg_ctl is absent the binaries
	// are extracted there once (offline if the archive is already cached).
	BinariesPath string
	// Port is the TCP port to listen on. When 0, the runtime probes a free port
	// at New() and exposes it via Port(); the caller persists it.
	Port uint32
	// Database, Username, Password are the cluster's credentials. The password is
	// stored SCRAM-hashed at initdb and must stay stable across restarts of a
	// persistent DataPath. Use GeneratePassword for a strong one.
	Database string
	Username string
	Password string
	// Version is the ActionGate binary version, surfaced in HealthReport.Version.
	Version string
	// StartTimeout bounds a cold start (initdb + first boot). Defaults to 90s,
	// floored at 30s, to tolerate corporate AV scanning each extracted file.
	StartTimeout time.Duration
	// Logger receives Postgres/tooling process output. Defaults to io.Discard.
	Logger io.Writer
	// ExtraParams are extra postgresql GUCs passed as `-c key=value` at start.
	// Primarily an override/testing seam (e.g. forcing fsync=off to exercise the
	// durability guard). They merge over the runtime's own hardening params.
	ExtraParams map[string]string
}

// Embedded is a DatabaseRuntime backed by an embedded PostgreSQL cluster whose
// initdb/pg_ctl lifecycle the runtime owns directly.
type Embedded struct {
	cfg Config
	dsn string

	mu      sync.Mutex
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
	if cfg.BinariesPath == "" {
		cfg.BinariesPath = defaultBinariesPath()
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

// DSN returns the connection string for the cluster's application database.
func (e *Embedded) DSN() string { return e.dsn }

// Port returns the TCP port the cluster listens on (resolved if it was probed).
func (e *Embedded) Port() uint32 { return e.cfg.Port }

// Start ensures binaries, initializes a fresh cluster (with builtin C.UTF-8
// locale and scram auth) only when DataPath holds none, boots via pg_ctl,
// hardens local auth, and refuses to run if durability GUCs are unsafe. An
// existing cluster that will not boot yields a *ClusterError and is never
// reinitialized.
func (e *Embedded) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return nil
	}

	if err := ensureBinaries(e.cfg.BinariesPath, e.cfg.StartTimeout); err != nil {
		return err
	}

	state := ClassifyCluster(e.cfg.DataPath)
	if state == ClusterAbsent {
		if err := e.runInitdb(ctx); err != nil {
			return fmt.Errorf("dbruntime: initdb: %w", err)
		}
		_ = hardenDataDirPerms(e.cfg.DataPath) // before first boot; best-effort
		if err := writePgHBA(e.cfg.DataPath); err != nil {
			return err
		}
	}

	if err := e.pgctlStart(ctx); err != nil {
		if state == ClusterPresent {
			return &ClusterError{Path: e.cfg.DataPath, Err: err}
		}
		return fmt.Errorf("dbruntime: start postgres: %w", err)
	}
	e.running = true

	if state == ClusterAbsent {
		if err := e.createAppDatabase(ctx); err != nil {
			e.stopLocked(ctx)
			return err
		}
	}

	// Safety net for existing clusters whose pg_hba may predate hardening.
	if err := e.hardenAuth(ctx); err != nil {
		e.stopLocked(ctx)
		return err
	}
	if err := e.checkDurability(ctx); err != nil {
		e.stopLocked(ctx)
		return err
	}
	return nil
}

// Stop shuts the cluster down: ShutdownFast is a clean checkpoint (warm next
// start); ShutdownImmediate skips the checkpoint (WAL recovery next start).
func (e *Embedded) Stop(ctx context.Context, mode ShutdownMode) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopLockedMode(ctx, mode)
}

// stopLocked stops the cluster with a fast shutdown; the caller must hold e.mu.
func (e *Embedded) stopLocked(ctx context.Context) {
	_ = e.stopLockedMode(ctx, ShutdownFast)
}

func (e *Embedded) stopLockedMode(ctx context.Context, mode ShutdownMode) error {
	if !e.running {
		return nil
	}
	if err := e.pgctlStop(ctx, mode); err != nil {
		return fmt.Errorf("dbruntime: stop postgres: %w", err)
	}
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
