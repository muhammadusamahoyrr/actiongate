// Package dbroles provisions the least-privilege database roles the control
// plane runs as (audit C4).
//
// Row-level security and the append-only triggers only bind a role that is
// neither a superuser nor the tables' owner: a superuser bypasses RLS even
// with FORCE ROW LEVEL SECURITY and can disable triggers. So the bootstrap
// role (the cluster's superuser, which owns the schema and runs
// migrations) is kept for migrations and administration, and the running
// control plane uses:
//
//   - AppRole: NOSUPERUSER NOBYPASSRLS. Every request path runs as it, so a
//     query missing its tenant predicate returns nothing, and the
//     append-only triggers cannot be switched off.
//   - SealerRole: NOSUPERUSER BYPASSRLS. The sealer must discover unsealed
//     streams across every tenant; it can read past RLS but, not being
//     superuser or owner, still cannot disable the triggers.
//
// Neither role owns anything (an owner can attach triggers that a later
// superuser migration would run). River's index-rebuild maintenance, which
// needs ownership, is switched off in the control plane
// (ReindexerIndexNames: []string{}).
package dbroles

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	AppRole    = "ag_app"
	SealerRole = "ag_sealer"
)

// ErrInsufficientPrivilege: the connecting role cannot create roles (an
// external database where actiongate is not the administrator).
var ErrInsufficientPrivilege = errors.New("cannot create roles: connect as a superuser (or a role with CREATEROLE) to provision them")

// Ensure creates or repairs both roles and their grants. It is idempotent
// and must run, as the owning superuser, after every migration (schema and
// queue) so new tables are covered. Passwords are applied on every run, so
// rotating one in the config takes effect at the next start.
func Ensure(ctx context.Context, owner *pgxpool.Pool, appPassword, sealerPassword string) error {
	if appPassword == "" || sealerPassword == "" {
		return errors.New("dbroles: both role passwords are required")
	}
	var super bool
	if err := owner.QueryRow(ctx, `select rolsuper from pg_roles where rolname = current_user`).Scan(&super); err != nil {
		return fmt.Errorf("dbroles: inspect current role: %w", err)
	}
	if !super {
		return ErrInsufficientPrivilege
	}

	tx, err := owner.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	roles := []struct {
		name, password, bypass string
	}{
		{AppRole, appPassword, "NOBYPASSRLS"},
		{SealerRole, sealerPassword, "BYPASSRLS"},
	}
	for _, r := range roles {
		id := pgx.Identifier{r.name}.Sanitize()
		var exists bool
		if err := tx.QueryRow(ctx, `select exists(select 1 from pg_roles where rolname = $1)`, r.name).Scan(&exists); err != nil {
			return err
		}
		verb := "ALTER"
		if !exists {
			verb = "CREATE"
		}
		// Attributes are (re)asserted every time, so a role someone made a
		// superuser by hand is demoted again.
		stmt := fmt.Sprintf(`%s ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION %s PASSWORD %s`,
			verb, id, r.bypass, quoteLiteral(r.password))
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("dbroles: %s role %s: %w", strings.ToLower(verb), r.name, err)
		}
	}

	app := pgx.Identifier{AppRole}.Sanitize()
	sealer := pgx.Identifier{SealerRole}.Sanitize()
	both := app + ", " + sealer
	db := pgx.Identifier{currentDB(ctx, tx)}.Sanitize()

	// Neither role owns anything: an owner can attach triggers that would
	// run as the superuser during a later migration. Ownership granted by
	// an earlier version is handed back to the migrating owner.
	if err := reclaimOwnership(ctx, tx); err != nil {
		return err
	}

	grants := []string{
		// Nobody but the owner may create objects in the schema the
		// superuser's migrations resolve names in (search_path hijack).
		`REVOKE CREATE ON SCHEMA public FROM PUBLIC`,
		`GRANT CONNECT ON DATABASE ` + db + ` TO ` + both,
		`GRANT USAGE ON SCHEMA public TO ` + both,

		// Start from nothing each run so the grants converge, including
		// revoking default privileges an earlier version set.
		`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ` + both,
		`REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM ` + both,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM ` + both,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM ` + both,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM ` + both,

		// App role: DML on the application and queue tables. Ensure runs
		// after every migration, so new tables are covered without
		// default privileges (which would also cover future admin tables).
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + app,
		`GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO ` + app,
		`GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ` + app,
		// The audit trail is append-only for the app: it writes events and
		// reads epochs (health), and never changes or removes either.
		// Sealing is the sealer's job.
		`REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM ` + app,
		`REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON audit_epochs FROM ` + app,

		// Sealer: exactly what sealing does — read the audit tables, set the
		// four seal columns on events, insert epochs.
		`GRANT SELECT ON audit_events, audit_epochs TO ` + sealer,
		`GRANT UPDATE (sequence_number, previous_hash, event_hash, epoch_id) ON audit_events TO ` + sealer,
		`GRANT INSERT ON audit_epochs TO ` + sealer,
	}
	for _, g := range grants {
		if _, err := tx.Exec(ctx, g); err != nil {
			return fmt.Errorf("dbroles: %s: %w", g, err)
		}
	}
	// Migration bookkeeping is read-only to the app (the health check reads
	// the schema version; nothing in the request path may change it).
	for _, t := range adminTables {
		var exists bool
		if err := tx.QueryRow(ctx, `select to_regclass($1) is not null`, "public."+t).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			continue
		}
		id := pgx.Identifier{t}.Sanitize()
		if _, err := tx.Exec(ctx, `REVOKE ALL ON `+id+` FROM `+both); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `GRANT SELECT ON `+id+` TO `+app); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// adminTables are migration bookkeeping, not application data.
var adminTables = []string{"goose_db_version", "actiongate_meta", "river_migration"}

// reclaimOwnership hands any table or sequence owned by one of the roles
// back to the current (owning, migrating) user.
func reclaimOwnership(ctx context.Context, tx pgx.Tx) error {
	rows, err := tx.Query(ctx,
		`select c.relname from pg_class c
		   join pg_namespace n on n.oid = c.relnamespace
		   join pg_roles r on r.oid = c.relowner
		  where n.nspname = 'public' and c.relkind in ('r', 'p', 'S') and r.rolname = any($1)`,
		[]string{AppRole, SealerRole})
	if err != nil {
		return err
	}
	var owned []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return err
		}
		owned = append(owned, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range owned {
		if _, err := tx.Exec(ctx, `ALTER TABLE `+pgx.Identifier{t}.Sanitize()+` OWNER TO CURRENT_USER`); err != nil {
			return fmt.Errorf("dbroles: reclaim %s: %w", t, err)
		}
	}
	return nil
}

func currentDB(ctx context.Context, tx pgx.Tx) string {
	var db string
	_ = tx.QueryRow(ctx, `select current_database()`).Scan(&db)
	return db
}

// quoteLiteral renders s as a SQL string literal. Role DDL takes no bind
// parameters; standard_conforming_strings (on by default since PG 9.1)
// makes doubling quotes sufficient.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// DSN returns ownerDSN with the user and password replaced: the same host,
// port, database and options, connecting as role.
func DSN(ownerDSN, role, password string) (string, error) {
	u, err := url.Parse(ownerDSN)
	if err != nil {
		return "", fmt.Errorf("dbroles: parse database URL: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return "", fmt.Errorf("dbroles: database URL must be postgres://, got %q", u.Scheme)
	}
	u.User = url.UserPassword(role, password)
	return u.String(), nil
}

// IsInsufficientPrivilege reports a permission error from the server.
func IsInsufficientPrivilege(err error) bool {
	var pgErr *pgconn.PgError
	return errors.Is(err, ErrInsufficientPrivilege) || errors.As(err, &pgErr) && pgErr.Code == "42501"
}
