package dbruntime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// startHardened builds and starts a runtime with the given password and extra
// params on a probed free port, registering cleanup. Returns the started runtime.
func startHardened(t *testing.T, password string, extra map[string]string) *Embedded {
	t.Helper()
	rt, err := New(Config{
		DataPath:     filepath.Join(t.TempDir(), "pgdata"),
		RuntimePath:  filepath.Join(t.TempDir(), "pgruntime"),
		Port:         0, // probe
		Password:     password,
		Version:      "test",
		StartTimeout: 120 * time.Second,
		ExtraParams:  extra,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = rt.Stop(context.Background(), ShutdownFast) })
	return rt
}

// TestRejectsUnauthenticated confirms the hardened cluster requires a password
// (no trust): a wrong password is rejected while the right one connects.
func TestRejectsUnauthenticated(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	const pw = "s3cret-correct-horse"
	rt := startHardened(t, pw, nil)
	ctx := context.Background()

	// Right password works.
	if _, err := rt.Health(ctx); err != nil {
		t.Fatalf("Health with correct password: %v", err)
	}
	if rep, _ := rt.Health(ctx); !rep.Database.Healthy {
		t.Fatalf("expected healthy with correct password: %q", rep.Database.Message)
	}

	// Wrong password is rejected.
	badDSN := fmt.Sprintf("postgres://ag:%s@127.0.0.1:%d/actiongate?sslmode=disable",
		"the-wrong-password", rt.Port())
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if conn, err := pgx.Connect(cctx, badDSN); err == nil {
		_ = conn.Close(cctx)
		t.Fatal("connection with wrong password succeeded — auth not enforced")
	}
}

// TestHardenedPgHBA asserts pg_hba.conf ends up scram-sha-256-only, with no
// trust and no cleartext password method.
func TestHardenedPgHBA(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	rt := startHardened(t, "pw-for-hba-test", nil)

	hba, err := os.ReadFile(filepath.Join(rt.cfg.DataPath, "pg_hba.conf"))
	if err != nil {
		t.Fatalf("read pg_hba.conf: %v", err)
	}
	got := string(hba)
	if got != pgHBAContents {
		t.Fatalf("pg_hba.conf not hardened as expected:\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasSuffix(line, "scram-sha-256") {
			t.Fatalf("non-scram auth rule present: %q", line)
		}
	}
}

// TestFsyncOffRefused confirms the durability guard aborts startup when fsync is
// forced off.
func TestFsyncOffRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	rt, err := New(Config{
		DataPath:     filepath.Join(t.TempDir(), "pgdata"),
		RuntimePath:  filepath.Join(t.TempDir(), "pgruntime"),
		Password:     "pw",
		Version:      "test",
		StartTimeout: 120 * time.Second,
		ExtraParams:  map[string]string{"fsync": "off"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = rt.Start(context.Background())
	if err == nil {
		_ = rt.Stop(context.Background(), ShutdownFast)
		t.Fatal("Start succeeded with fsync=off — durability guard did not fire")
	}
	if !strings.Contains(err.Error(), "fsync") {
		t.Fatalf("error should name fsync, got: %v", err)
	}
}

// TestProbesFreePortNoCollision confirms two Port==0 runtimes come up on
// distinct probed ports without colliding.
func TestProbesFreePortNoCollision(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	rt1 := startHardened(t, "pw1", nil)
	rt2 := startHardened(t, "pw2", nil)

	if rt1.Port() == 0 || rt2.Port() == 0 {
		t.Fatalf("expected non-zero probed ports, got %d and %d", rt1.Port(), rt2.Port())
	}
	if rt1.Port() == rt2.Port() {
		t.Fatalf("both runtimes probed the same port %d", rt1.Port())
	}
	for _, rt := range []*Embedded{rt1, rt2} {
		if rep, _ := rt.Health(context.Background()); !rep.Database.Healthy {
			t.Fatalf("runtime on port %d unhealthy: %q", rt.Port(), rep.Database.Message)
		}
	}
}
