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
// The River queue tables (river_*) carry no tenant data and no RLS; AppRole
// owns them because River's maintenance (index rebuilds) needs ownership.
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

	both := pgx.Identifier{AppRole}.Sanitize() + ", " + pgx.Identifier{SealerRole}.Sanitize()
	grants := []string{
		`GRANT CONNECT ON DATABASE ` + pgx.Identifier{currentDB(ctx, tx)}.Sanitize() + ` TO ` + both,
		`GRANT USAGE ON SCHEMA public TO ` + both,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ` + both,
		`GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO ` + both,
		`GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ` + both,
		// Tables the owner creates later (new migrations) are covered too.
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ` + both,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO ` + both,
		`ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO ` + both,
	}
	for _, g := range grants {
		if _, err := tx.Exec(ctx, g); err != nil {
			return fmt.Errorf("dbroles: %s: %w", g, err)
		}
	}

	// River's queue tables: owned by the app role (its maintenance rebuilds
	// indexes, which needs ownership). They hold no tenant data and no RLS.
	rows, err := tx.Query(ctx,
		`select tablename from pg_tables
		  where schemaname = 'public' and tablename like 'river\_%' and tableowner <> $1`, AppRole)
	if err != nil {
		return err
	}
	var riverTables []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			return err
		}
		riverTables = append(riverTables, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range riverTables {
		if _, err := tx.Exec(ctx, `ALTER TABLE `+pgx.Identifier{t}.Sanitize()+` OWNER TO `+pgx.Identifier{AppRole}.Sanitize()); err != nil {
			return fmt.Errorf("dbroles: own %s: %w", t, err)
		}
	}
	return tx.Commit(ctx)
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
