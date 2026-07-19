package server_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/muhammadusamahoyrr/actiongate/internal/dbruntime"
	"github.com/muhammadusamahoyrr/actiongate/internal/server"
	"github.com/muhammadusamahoyrr/actiongate/migrations"
)

// TestHealthzReflectsSealer drives /healthz against a real (embedded) database
// and asserts the response carries the composite component report — including
// the sealer — while keeping a 200 liveness status. Uses the embedded runtime,
// so it needs no Docker.
func TestHealthzReflectsSealer(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	ctx := context.Background()

	rt, err := dbruntime.New(dbruntime.Config{
		DataPath:     filepath.Join(t.TempDir(), "pgdata"),
		Password:     "pw-healthz",
		Version:      "test",
		StartTimeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatalf("dbruntime.New: %v", err)
	}
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = rt.Stop(context.Background(), dbruntime.ShutdownFast) })

	// Apply the schema.
	db, err := sql.Open("pgx", rt.DSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	if err := goose.UpContext(ctx, db, "."); err != nil {
		t.Fatalf("goose up: %v", err)
	}
	_ = db.Close()

	pool, err := pgxpool.New(ctx, rt.DSN())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	// Provision a tenant so the Tenant component is healthy.
	if _, err := pool.Exec(ctx,
		`INSERT INTO configuration_snapshots (tenant_id, version, content, content_hash, created_by)
		 VALUES (gen_random_uuid(), 1, '{}'::jsonb, '\x00', 'test')`); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	srv := &server.Server{Pool: pool, Version: "test", EpochKeyIDs: []string{"epoch-1"}}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (database reachable)", resp.StatusCode)
	}

	var body struct {
		Status   string `json:"status"`
		Database struct {
			Healthy bool `json:"healthy"`
		} `json:"database"`
		Tenant struct {
			Healthy bool `json:"healthy"`
		} `json:"tenant"`
		SigningKeys struct {
			Healthy bool `json:"healthy"`
		} `json:"signing_keys"`
		Sealer struct {
			Healthy bool   `json:"healthy"`
			Message string `json:"message"`
		} `json:"sealer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if body.Status != "ok" {
		t.Fatalf("status = %q, want ok", body.Status)
	}
	if !body.Database.Healthy {
		t.Fatal("database component should be healthy")
	}
	if !body.Tenant.Healthy {
		t.Fatal("tenant component should be healthy (snapshot seeded)")
	}
	if !body.SigningKeys.Healthy {
		t.Fatal("signing keys component should be healthy (epoch-1 configured)")
	}
	// The point of this test: the sealer component is present and reflected.
	if !body.Sealer.Healthy {
		t.Fatalf("sealer component should be healthy on a fresh stack: %q", body.Sealer.Message)
	}
	if body.Sealer.Message == "" {
		t.Fatal("sealer component should carry a message")
	}
}
