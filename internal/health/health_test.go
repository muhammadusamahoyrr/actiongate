package health

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/muhammadusamahoyrr/actiongate/internal/dbruntime"
	"github.com/muhammadusamahoyrr/actiongate/migrations"
)

const testTenant = "2f871fa3-8397-413f-a1e1-a4ed8f123190"

// startDB boots an embedded cluster for the test and returns a pool plus its DSN.
func startDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	rt, err := dbruntime.New(dbruntime.Config{
		DataPath:     filepath.Join(t.TempDir(), "pgdata"),
		Password:     "pw-health",
		Version:      "test",
		StartTimeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatalf("dbruntime.New: %v", err)
	}
	if err := rt.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = rt.Stop(context.Background(), dbruntime.ShutdownFast) })

	pool, err := pgxpool.New(context.Background(), rt.DSN())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool, rt.DSN()
}

func applyMigrations(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	if err := goose.UpContext(context.Background(), db, "."); err != nil {
		t.Fatalf("goose up: %v", err)
	}
}

// TestCheckNamesFailingComponent: a database with no schema reports Database
// healthy but Schema failing, with a diagnostic message.
func TestCheckNamesFailingComponent(t *testing.T) {
	pool, _ := startDB(t)
	rep := Check(context.Background(), pool, Options{Version: "test"})

	if !rep.Database.Healthy {
		t.Fatalf("database should be reachable: %q", rep.Database.Message)
	}
	if rep.Schema.Healthy {
		t.Fatal("schema should be unhealthy before migrations")
	}
	if rep.Schema.Message == "" {
		t.Fatal("schema failure should carry a message")
	}
	if AllHealthy(rep) {
		t.Fatal("AllHealthy must be false when a component fails")
	}
}

// TestCheckAllHealthy: after migrations plus a provisioned tenant and a sealed
// epoch, every component is healthy.
func TestCheckAllHealthy(t *testing.T) {
	pool, dsn := startDB(t)
	applyMigrations(t, dsn)
	seedTenant(t, pool)
	seedEpoch(t, pool, "epoch-1")

	rep := Check(context.Background(), pool, Options{
		Version:     "test",
		TenantID:    testTenant,
		EpochKeyIDs: []string{"epoch-1"},
	})
	if !AllHealthy(rep) {
		t.Fatalf("expected all healthy, got: db=%+v schema=%+v tenant=%+v keys=%+v sealer=%+v",
			rep.Database, rep.Schema, rep.Tenant, rep.Keys, rep.Sealer)
	}
}

// TestCheckKeysUnknownKey: an epoch signed by a key outside the configured set
// fails the Keys component.
func TestCheckKeysUnknownKey(t *testing.T) {
	pool, dsn := startDB(t)
	applyMigrations(t, dsn)
	seedTenant(t, pool)
	seedEpoch(t, pool, "rogue-key")

	rep := Check(context.Background(), pool, Options{
		TenantID:    testTenant,
		EpochKeyIDs: []string{"epoch-1"},
	})
	if rep.Keys.Healthy {
		t.Fatal("Keys should fail when an epoch is signed by an unknown key")
	}
}

func seedTenant(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	err := withTenant(context.Background(), pool, testTenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO configuration_snapshots (tenant_id, version, content, content_hash, created_by)
			 VALUES ($1, 1, '{}'::jsonb, '\x00', 'test')`, testTenant)
		return err
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
}

func seedEpoch(t *testing.T, pool *pgxpool.Pool, keyID string) {
	t.Helper()
	err := withTenant(context.Background(), pool, testTenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO audit_epochs
			   (epoch_id, tenant_id, stream_id, first_sequence, last_sequence,
			    root_hash, signature, key_id, sealed_at)
			 VALUES (gen_random_uuid(), $1, gen_random_uuid(), 1, 1,
			    '\x00', '\x00', $2, now())`, testTenant, keyID)
		return err
	})
	if err != nil {
		t.Fatalf("seed epoch: %v", err)
	}
}
