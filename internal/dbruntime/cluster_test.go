package dbruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestClassifyCluster checks the PG_VERSION-based fresh/existing detection. No
// Postgres process needed.
func TestClassifyCluster(t *testing.T) {
	dir := t.TempDir()
	if got := ClassifyCluster(dir); got != ClusterAbsent {
		t.Fatalf("empty dir: got %v, want absent", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "PG_VERSION"), []byte("18\n"), 0o600); err != nil {
		t.Fatalf("write PG_VERSION: %v", err)
	}
	if got := ClassifyCluster(dir); got != ClusterPresent {
		t.Fatalf("dir with PG_VERSION: got %v, want present", got)
	}
}

// TestFreshInitFullOrder verifies Initialize runs MigrateSchema then Provision
// on a fresh cluster, and on a second run migrates again but does NOT re-provision.
func TestFreshInitFullOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	rt := startHardened(t, "pw-init-order", nil)
	ctx := context.Background()

	var order []string
	steps := InitSteps{
		MigrateSchema: func(context.Context) error { order = append(order, "migrate"); return nil },
		Provision:     func(context.Context) error { order = append(order, "provision"); return nil },
	}

	// Fresh: migrate then provision.
	if err := Initialize(ctx, rt.DSN(), "v1.0.0", "v1.0.0", steps); err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	if len(order) != 2 || order[0] != "migrate" || order[1] != "provision" {
		t.Fatalf("fresh init order = %v, want [migrate provision]", order)
	}

	// Second run: migrate again, no re-provision.
	order = nil
	if err := Initialize(ctx, rt.DSN(), "v1.0.0", "v1.0.0", steps); err != nil {
		t.Fatalf("second Initialize: %v", err)
	}
	if len(order) != 1 || order[0] != "migrate" {
		t.Fatalf("second init order = %v, want [migrate] only", order)
	}
}

// TestOldBinaryRefused verifies an older binary is refused against a database
// that records a newer minimum, before any migration runs.
func TestOldBinaryRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	rt := startHardened(t, "pw-oldbin", nil)
	ctx := context.Background()

	// Fresh init records min binary v2.0.0.
	if err := Initialize(ctx, rt.DSN(), "v2.0.0", "v2.0.0", InitSteps{}); err != nil {
		t.Fatalf("seed Initialize: %v", err)
	}

	// An older binary must be refused, and must not migrate.
	migrated := false
	steps := InitSteps{MigrateSchema: func(context.Context) error { migrated = true; return nil }}
	err := Initialize(ctx, rt.DSN(), "v1.5.0", "v1.5.0", steps)
	if err == nil {
		t.Fatal("expected refusal for older binary, got nil")
	}
	if !strings.Contains(err.Error(), "v2.0.0") {
		t.Fatalf("error should name required version v2.0.0, got: %v", err)
	}
	if migrated {
		t.Fatal("MigrateSchema ran despite incompatible binary")
	}
}

// TestAdvisoryLockSerializesMigrations verifies two concurrent lock holders never
// overlap.
func TestAdvisoryLockSerializesMigrations(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	rt := startHardened(t, "pw-advlock", nil)
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, rt.DSN())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	var active, maxActive, ran int32
	work := func(context.Context) error {
		n := atomic.AddInt32(&active, 1)
		for {
			m := atomic.LoadInt32(&maxActive)
			if n <= m || atomic.CompareAndSwapInt32(&maxActive, m, n) {
				break
			}
		}
		time.Sleep(150 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		atomic.AddInt32(&ran, 1)
		return nil
	}

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := WithMigrationLock(ctx, pool, work); err != nil {
				t.Errorf("WithMigrationLock: %v", err)
			}
		}()
	}
	wg.Wait()

	if ran != 2 {
		t.Fatalf("expected both to run, ran=%d", ran)
	}
	if maxActive != 1 {
		t.Fatalf("lock did not serialize: max concurrent holders = %d", maxActive)
	}
}

// TestCorruptClusterFailsLoud verifies that an existing-but-unstartable cluster
// yields a ClusterError (never a reinit) and leaves PG_VERSION intact.
func TestCorruptClusterFailsLoud(t *testing.T) {
	if testing.Short() {
		t.Skip("extracts Postgres binaries; skipped in -short")
	}
	dataPath := filepath.Join(t.TempDir(), "pgdata")
	if err := os.MkdirAll(dataPath, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Look like a valid v18 cluster to the library, but with no real cluster
	// files behind it — the server will fail to start.
	pgv := filepath.Join(dataPath, "PG_VERSION")
	if err := os.WriteFile(pgv, []byte("18\n"), 0o600); err != nil {
		t.Fatalf("write PG_VERSION: %v", err)
	}

	rt, err := New(Config{
		DataPath:     dataPath,
		RuntimePath:  filepath.Join(t.TempDir(), "pgruntime"),
		Password:     "pw",
		Version:      "test",
		StartTimeout: 45 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = rt.Start(context.Background())
	if err == nil {
		_ = rt.Stop(context.Background(), ShutdownFast)
		t.Fatal("expected start to fail on a corrupt existing cluster")
	}
	var ce *ClusterError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ClusterError, got %T: %v", err, err)
	}
	if _, statErr := os.Stat(pgv); statErr != nil {
		t.Fatalf("PG_VERSION was removed — runtime must not reinitialize: %v", statErr)
	}
}
