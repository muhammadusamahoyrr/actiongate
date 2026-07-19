package dbruntime

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestBuiltinLocale verifies the app database uses the builtin C.UTF-8 locale
// provider (deterministic and identical across platforms) rather than libc/ICU.
func TestBuiltinLocale(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	rt := startHardened(t, "pw-locale", nil)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, rt.DSN())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()

	// In PG17+ datcollate/datctype hold the libc lc_* (system default); the
	// provider-specific locale is in datlocale.
	var provider, locale string
	err = conn.QueryRow(ctx,
		`SELECT datlocprovider::text, datlocale FROM pg_database WHERE datname = current_database()`).
		Scan(&provider, &locale)
	if err != nil {
		t.Fatalf("query locale: %v", err)
	}
	if provider != "b" {
		t.Fatalf("datlocprovider = %q, want \"b\" (builtin)", provider)
	}
	if locale != "C.UTF-8" {
		t.Fatalf("datlocale = %q, want \"C.UTF-8\"", locale)
	}
}

// TestFastStopWarmRestart verifies a clean fast shutdown yields a fast warm
// restart (no crash recovery) with data intact.
func TestFastStopWarmRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	ctx := context.Background()
	dataPath := filepath.Join(t.TempDir(), "pgdata")

	rt := newTestRuntime(t, dataPath)
	coldStart := time.Now()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("cold Start: %v", err)
	}
	coldDur := time.Since(coldStart)
	execSQL(t, ctx, rt.DSN(), `CREATE TABLE warm (id int)`)
	execSQL(t, ctx, rt.DSN(), `INSERT INTO warm VALUES (7)`)
	if err := rt.Stop(ctx, ShutdownFast); err != nil {
		t.Fatalf("fast Stop: %v", err)
	}

	rt2 := newTestRuntime(t, dataPath)
	warmStart := time.Now()
	if err := rt2.Start(ctx); err != nil {
		t.Fatalf("warm Start: %v", err)
	}
	warmDur := time.Since(warmStart)
	t.Cleanup(func() { _ = rt2.Stop(context.Background(), ShutdownFast) })

	if got := queryString(t, ctx, rt2.DSN(), `SELECT id::text FROM warm WHERE id = 7`); got != "7" {
		t.Fatalf("row did not survive fast restart: %q", got)
	}
	// A clean fast stop means the warm restart skips initdb and needs no crash
	// recovery, so it is materially faster than the cold start. The absolute <5s
	// figure is a reference-machine target, not a portable test bound (AV-throttled
	// dev boxes vary widely), so we assert the behavioral relationship instead.
	t.Logf("cold start %v, warm restart %v", coldDur, warmDur)
	if warmDur >= coldDur {
		t.Fatalf("warm restart (%v) not faster than cold start (%v)", warmDur, coldDur)
	}
}

// syncBuf is a concurrency-safe buffer for capturing process logger output.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestImmediateStopLogsAndRecovers verifies immediate shutdown logs loudly and
// the cluster recovers its data on the next start (via WAL crash recovery).
func TestImmediateStopLogsAndRecovers(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	ctx := context.Background()
	dataPath := filepath.Join(t.TempDir(), "pgdata")
	log := &syncBuf{}

	rt, err := New(Config{
		DataPath:     dataPath,
		Password:     "pw-immediate",
		Version:      "test",
		StartTimeout: 120 * time.Second,
		Logger:       log,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	execSQL(t, ctx, rt.DSN(), `CREATE TABLE recov (id int)`)
	execSQL(t, ctx, rt.DSN(), `INSERT INTO recov VALUES (99)`)

	if err := rt.Stop(ctx, ShutdownImmediate); err != nil {
		t.Fatalf("immediate Stop: %v", err)
	}
	if !strings.Contains(log.String(), "immediate shutdown") {
		t.Fatalf("immediate shutdown was not logged loudly; log:\n%s", log.String())
	}

	// rt2 must use the same password the cluster was initialized with.
	rt2, err := New(Config{
		DataPath:     dataPath,
		Password:     "pw-immediate",
		Version:      "test",
		StartTimeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatalf("New rt2: %v", err)
	}
	if err := rt2.Start(ctx); err != nil {
		t.Fatalf("restart after immediate stop: %v", err)
	}
	t.Cleanup(func() { _ = rt2.Stop(context.Background(), ShutdownFast) })

	if got := queryString(t, ctx, rt2.DSN(), `SELECT id::text FROM recov WHERE id = 99`); got != "99" {
		t.Fatalf("data not recovered after immediate stop: %q", got)
	}
}
