package dbruntime

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// freePort asks the OS for an unused TCP port. There is a small race between
// closing the listener and Postgres binding, acceptable for a test. M2 replaces
// this with init-time probing inside the runtime.
func freePort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve free port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return uint32(l.Addr().(*net.TCPAddr).Port)
}

// newTestRuntime builds an Embedded runtime on a persistent DataPath under the
// test's temp dir, with an ephemeral runtime dir alongside it.
func newTestRuntime(t *testing.T, dataPath string) *Embedded {
	t.Helper()
	rt, err := New(Config{
		DataPath:     dataPath,
		RuntimePath:  filepath.Join(t.TempDir(), "pgruntime"),
		Port:         freePort(t),
		Version:      "test",
		StartTimeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return rt
}

// TestPersistence is the Step 3 "first test": start -> write a row -> stop ->
// start -> the row is still there. Proves DataPath persists across restarts with
// no Docker involved.
func TestPersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("downloads and runs a real Postgres; skipped in -short")
	}
	ctx := context.Background()
	dataPath := filepath.Join(t.TempDir(), "pgdata")

	// --- first boot: fresh cluster, write a row -------------------------------
	rt := newTestRuntime(t, dataPath)
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("first Start: %v", err)
	}

	rep, err := rt.Health(ctx)
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !rep.Database.Healthy {
		t.Fatalf("expected healthy database, got %q", rep.Database.Message)
	}
	if rep.Version != "test" {
		t.Fatalf("HealthReport.Version = %q, want %q", rep.Version, "test")
	}

	execSQL(t, ctx, rt.DSN(), `CREATE TABLE survivors (id int primary key, note text)`)
	execSQL(t, ctx, rt.DSN(), `INSERT INTO survivors (id, note) VALUES (1, 'i persist')`)

	if err := rt.Stop(ctx, ShutdownFast); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	// --- second boot: SAME DataPath, row must still be there ------------------
	rt2 := newTestRuntime(t, dataPath)
	if err := rt2.Start(ctx); err != nil {
		t.Fatalf("second Start: %v", err)
	}
	t.Cleanup(func() { _ = rt2.Stop(context.Background(), ShutdownFast) })

	note := queryString(t, ctx, rt2.DSN(), `SELECT note FROM survivors WHERE id = 1`)
	if note != "i persist" {
		t.Fatalf("row did not survive restart: got %q", note)
	}
}

// TestHealthReportsDownState checks that Health on a runtime that was never
// started reports the database as unhealthy with a diagnostic message rather
// than returning an error.
func TestHealthReportsDownState(t *testing.T) {
	rt, err := New(Config{
		DataPath: filepath.Join(t.TempDir(), "pgdata"),
		Port:     freePort(t),
		Version:  "test",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rep, err := rt.Health(context.Background())
	if err != nil {
		t.Fatalf("Health returned error, want report: %v", err)
	}
	if rep.Database.Healthy {
		t.Fatal("expected Database.Healthy == false for a stopped runtime")
	}
	if rep.Database.Message == "" {
		t.Fatal("expected a diagnostic message on the down database")
	}
}

func execSQL(t *testing.T, ctx context.Context, dsn, sql string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, sql); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func queryString(t *testing.T, ctx context.Context, dsn, sql string) string {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var s string
	if err := conn.QueryRow(ctx, sql).Scan(&s); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	return s
}
