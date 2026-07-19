// Package testdb provides the shared integration-test database: a real
// postgres:18-alpine container with the repo's Goose migrations applied.
// Only ever imported from _test files.
package testdb

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/muhammadusamahoyrr/actiongate/migrations"
)

// SetupPool starts a Postgres 18 container, applies all Goose migrations,
// and returns a pgxpool. Cleanup is registered on t.
func SetupPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	pgc, err := tcpostgres.Run(ctx, "postgres:18-alpine",
		tcpostgres.WithDatabase("actiongate"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { _ = pgc.Terminate(context.Background()) })

	dsn, err := pgc.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}

	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open for migrations: %v", err)
	}
	defer func() { _ = sqldb.Close() }()
	// Use the embedded migrations FS (like `actiongate up`), so tests never
	// depend on the process working directory. goose.SetBaseFS is global state;
	// setting it here keeps it consistent with the embedded-runtime test helpers
	// that also set it, avoiding cross-test interference within a package.
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("goose dialect: %v", err)
	}
	if err := goose.Up(sqldb, "."); err != nil {
		t.Fatalf("goose up: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
