package dbroles_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/muhammadusamahoyrr/actiongate/internal/admin"
	"github.com/muhammadusamahoyrr/actiongate/internal/dbroles"
	"github.com/muhammadusamahoyrr/actiongate/internal/dbruntime"
	"github.com/muhammadusamahoyrr/actiongate/internal/queue"
	"github.com/muhammadusamahoyrr/actiongate/migrations"
	"github.com/muhammadusamahoyrr/actiongate/policies"
)

// Audit C4: with the bootstrap superuser as the app role, tenant isolation
// and the append-only guarantees were inactive in every shipped mode, and
// no test exercised RLS as a non-owner. These tests do.
func TestRolesEnforceRLSAndAppendOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	ctx := context.Background()
	rt, err := dbruntime.New(dbruntime.Config{
		DataPath:     filepath.Join(t.TempDir(), "pgdata"),
		Password:     "pw-owner",
		Version:      "test",
		StartTimeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Stop(context.Background(), dbruntime.ShutdownFast) })

	owner := mustPool(t, rt.DSN())
	migrate(t, rt.DSN())
	if err := queue.Migrate(ctx, owner); err != nil {
		t.Fatalf("river migrate: %v", err)
	}
	tenant, err := admin.CreateTenant(ctx, owner, policies.ClaudeCode)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 { // idempotent
		if err := dbroles.Ensure(ctx, owner, "pw-app", "pw-sealer"); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
	}

	app := mustPool(t, mustDSN(t, rt.DSN(), dbroles.AppRole, "pw-app"))
	sealer := mustPool(t, mustDSN(t, rt.DSN(), dbroles.SealerRole, "pw-sealer"))

	for name, p := range map[string]*pgxpool.Pool{"app": app, "sealer": sealer} {
		var super bool
		if err := p.QueryRow(ctx, `select rolsuper from pg_roles where rolname = current_user`).Scan(&super); err != nil || super {
			t.Errorf("%s role: superuser=%v err=%v, want a non-superuser", name, super, err)
		}
		// Neither can switch the append-only triggers off.
		if _, err := p.Exec(ctx, `alter table audit_events disable trigger all`); err == nil {
			t.Errorf("%s role disabled the audit triggers", name)
		}
		if _, err := p.Exec(ctx, `set session_replication_role = replica`); err == nil {
			t.Errorf("%s role set session_replication_role (skips triggers)", name)
		}
	}

	// RLS binds the app role: no tenant set → no rows; tenant set → its rows.
	if !seesNothing(app, `select count(*) from configuration_snapshots`) {
		t.Error("app role saw snapshots with no tenant set")
	}
	if n := count(t, app, `select count(*) from configuration_snapshots`, tenant.String()); n == 0 {
		t.Error("app role saw no snapshots for its own tenant")
	}
	// The sealer must see audit events across tenants (BYPASSRLS).
	if _, err := owner.Exec(ctx,
		`insert into audit_events (id, tenant_id, stream_id, event_type, attested_by, metadata, recorded_at)
		 values (gen_random_uuid(), $1, gen_random_uuid(), 'ActionCreated', 'control_plane', '{}', now())`, tenant); err != nil {
		t.Fatalf("seed audit event: %v", err)
	}
	if n := count(t, sealer, `select count(*) from audit_events`, ""); n == 0 {
		t.Error("sealer role saw no audit events across tenants")
	}
	if !seesNothing(app, `select count(*) from audit_events`) {
		t.Error("app role saw audit events with no tenant set")
	}

	// Append-only holds for the app role even inside its own tenant.
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenant.String())
	_, err = tx.Exec(ctx, `update configuration_snapshots set created_by = 'mallory'`)
	_ = tx.Rollback(ctx)
	if err == nil {
		t.Error("app role rewrote an append-only snapshot")
	}

	// The audit trail (audit H8): the app may append events, and nothing
	// else. Each statement runs in its own tenant-scoped transaction.
	inTenant := func(q string) error {
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenant.String()); err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(ctx, q)
		return err
	}
	if err := inTenant(`insert into audit_events (id, tenant_id, stream_id, event_type, attested_by, metadata, recorded_at)
		values (gen_random_uuid(), current_setting('app.tenant_id')::uuid, gen_random_uuid(), 'ActionCreated', 'control_plane', '{}', now())`); err != nil {
		t.Errorf("app role cannot append an audit event: %v", err)
	}
	for _, q := range []string{
		`delete from audit_epochs`,
		`update audit_epochs set anchored_at = now()`,
		`insert into audit_epochs (epoch_id, tenant_id, stream_id, first_sequence, last_sequence, root_hash, signature, key_id, sealed_at)
		 values (gen_random_uuid(), current_setting('app.tenant_id')::uuid, gen_random_uuid(), 1, 1, '\x00', '\x00', 'k', now())`,
		`update audit_events set event_hash = '\x00'`,
		`delete from audit_events`,
	} {
		if err := inTenant(q); err == nil {
			t.Errorf("app role was allowed: %s", q)
		}
	}
	// Even the owner cannot delete or truncate sealed epochs: the guard
	// triggers refuse, and only a superuser disabling them gets past.
	if _, err := owner.Exec(ctx,
		`insert into audit_epochs (epoch_id, tenant_id, stream_id, first_sequence, last_sequence, root_hash, signature, key_id, sealed_at)
		 values (gen_random_uuid(), $1, gen_random_uuid(), 1, 1, '\x00', '\x00', 'k', now())`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `update audit_epochs set anchored_at = now()`); err != nil {
		t.Errorf("setting anchored_at once was refused: %v", err)
	}
	for _, q := range []string{
		`delete from audit_epochs`,
		`update audit_epochs set root_hash = '\x01'`,
		`update audit_epochs set anchored_at = now()`, // only once
		`truncate audit_epochs`,
		`truncate audit_events cascade`,
	} {
		if _, err := owner.Exec(ctx, q); err == nil {
			t.Errorf("owner was allowed: %s", q)
		}
	}

	// Neither role owns anything: an owner could attach triggers that a
	// later superuser migration would run. Ownership handed out by hand is
	// reclaimed at the next Ensure.
	if _, err := owner.Exec(ctx, `alter table river_job owner to ag_app`); err != nil {
		t.Fatal(err)
	}
	if err := dbroles.Ensure(ctx, owner, "pw-app", "pw-sealer"); err != nil {
		t.Fatal(err)
	}
	var owned int
	if err := owner.QueryRow(ctx,
		`select count(*) from pg_tables where schemaname = 'public' and tableowner in ('ag_app', 'ag_sealer')`).Scan(&owned); err != nil {
		t.Fatal(err)
	}
	if owned != 0 {
		t.Errorf("%d tables owned by a least-privilege role, want 0", owned)
	}

	// Migration bookkeeping is read-only to the app.
	if n := count(t, app, `select count(*) from goose_db_version`, ""); n == 0 {
		t.Error("app role cannot read the schema version (health check needs it)")
	}
	if _, err := app.Exec(ctx, `delete from goose_db_version`); err == nil {
		t.Error("app role deleted migration history")
	}

	// The sealer can do exactly its job: read the audit tables and set the
	// seal columns. Nothing else.
	for _, q := range []string{
		`select count(*) from configuration_snapshots`,
		`select count(*) from action_requests`,
		`update audit_events set metadata = '{}'::jsonb`,
		`insert into configuration_snapshots (tenant_id, version, content, content_hash, created_by) values (gen_random_uuid(), 99, '{}', '\x00', 'x')`,
	} {
		if _, err := sealer.Exec(ctx, q); err == nil {
			t.Errorf("sealer role was allowed: %s", q)
		}
	}
	if n := count(t, sealer, `select count(*) from audit_events`, ""); n < 0 {
		t.Error("sealer cannot read audit_events")
	}

	// A role someone promoted by hand is demoted again at the next Ensure.
	if _, err := owner.Exec(ctx, `alter role ag_app superuser bypassrls`); err != nil {
		t.Fatal(err)
	}
	if err := dbroles.Ensure(ctx, owner, "pw-app", "pw-sealer"); err != nil {
		t.Fatal(err)
	}
	var super, bypass bool
	if err := owner.QueryRow(ctx, `select rolsuper, rolbypassrls from pg_roles where rolname = 'ag_app'`).Scan(&super, &bypass); err != nil || super || bypass {
		t.Errorf("after Ensure: ag_app superuser=%v bypassrls=%v err=%v, want both false", super, bypass, err)
	}
}

func TestEnsureRefusesNonSuperuser(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	ctx := context.Background()
	rt, err := dbruntime.New(dbruntime.Config{
		DataPath: filepath.Join(t.TempDir(), "pgdata"), Password: "pw-owner", Version: "test", StartTimeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Stop(context.Background(), dbruntime.ShutdownFast) })
	owner := mustPool(t, rt.DSN())
	migrate(t, rt.DSN())
	if err := dbroles.Ensure(ctx, owner, "pw-app", "pw-sealer"); err != nil {
		t.Fatal(err)
	}
	app := mustPool(t, mustDSN(t, rt.DSN(), dbroles.AppRole, "pw-app"))
	err = dbroles.Ensure(ctx, app, "x", "y")
	if !dbroles.IsInsufficientPrivilege(err) {
		t.Errorf("Ensure as the app role: err = %v, want insufficient privilege", err)
	}
}

func TestDSNSwapsOnlyTheCredentials(t *testing.T) {
	got, err := dbroles.DSN("postgres://ag:secret@127.0.0.1:5433/actiongate?sslmode=disable", "ag_app", "p@ss/w:rd")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, "postgres://ag_app:") || !strings.HasSuffix(got, "@127.0.0.1:5433/actiongate?sslmode=disable") || strings.Contains(got, "secret") {
		t.Errorf("DSN = %q", got)
	}
	if _, err := dbroles.DSN("mysql://x@y/z", "a", "b"); err == nil {
		t.Error("non-postgres URL should be refused")
	}
}

func mustPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func mustDSN(t *testing.T, owner, role, pw string) string {
	t.Helper()
	d, err := dbroles.DSN(owner, role, pw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func migrate(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpContext(context.Background(), db, "."); err != nil {
		t.Fatalf("goose up: %v", err)
	}
}

// seesNothing reports whether a count query with no tenant set returns 0
// rows or fails. Both mean RLS held: on a pooled connection that earlier
// set a tenant, app.tenant_id reads back as ” and the policy's cast
// errors instead of returning nothing — closed either way.
func seesNothing(p *pgxpool.Pool, q string) bool {
	var n int
	if err := p.QueryRow(context.Background(), q).Scan(&n); err != nil {
		return true
	}
	return n == 0
}

func count(t *testing.T, p *pgxpool.Pool, q, tenant string) int {
	t.Helper()
	ctx := context.Background()
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if tenant != "" {
		if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenant); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := tx.QueryRow(ctx, q).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}
