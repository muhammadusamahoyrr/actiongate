package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/muhammadusamahoyrr/actiongate/internal/admin"
	"github.com/muhammadusamahoyrr/actiongate/internal/controlplane"
	"github.com/muhammadusamahoyrr/actiongate/internal/gateway"
	"github.com/muhammadusamahoyrr/actiongate/migrations"
	"github.com/muhammadusamahoyrr/actiongate/policies"
)

const dbContainerName = "actiongate-db"

// cmdUp is the one-command bootstrap: Postgres up, schema migrated, tenant
// provisioned with the claude-code starter pack, local gateway enrolled, a
// self-test action round-tripped, and the control plane left running in the
// foreground. Safe to re-run: every step is check-then-create.
func cmdUp(args []string) int {
	fs := flag.NewFlagSet("up", flag.ContinueOnError)
	dbURLFlag := fs.String("db-url", "", "override the Postgres URL (default: managed docker container)")
	if err := fs.Parse(args); err != nil {
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, cfgPath, err := loadOrInitDevConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "up:", err)
		return 1
	}
	if *dbURLFlag != "" && *dbURLFlag != cfg.DatabaseURL {
		cfg.DatabaseURL = *dbURLFlag
		if err := saveDevConfig(cfg, cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "up:", err)
			return 1
		}
	}
	fmt.Printf("• config: %s\n", cfgPath)

	if err := ensurePostgres(ctx, cfg.DatabaseURL); err != nil {
		fmt.Fprintln(os.Stderr, "up: postgres:", err)
		return 1
	}
	fmt.Println("• postgres: ready")

	if err := migrate(ctx, cfg.DatabaseURL); err != nil {
		fmt.Fprintln(os.Stderr, "up: migrate:", err)
		return 1
	}
	fmt.Println("• migrations: applied")

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "up: connect:", err)
		return 1
	}
	defer pool.Close()

	created, err := ensureTenant(ctx, pool, cfg, cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "up: tenant:", err)
		return 1
	}
	if created {
		fmt.Printf("• tenant: %s (claude-code starter policy)\n", cfg.TenantID)
	} else {
		fmt.Printf("• tenant: %s\n", cfg.TenantID)
	}

	// If a control plane is already answering on our address (a second
	// `actiongate up`, or one running as a service), reuse it instead of
	// fighting over the port.
	alreadyRunning := healthy(ctx, cfg.ServerURL)
	errCh := make(chan error, 1)
	if alreadyRunning {
		fmt.Println("• control plane: already running — reusing it")
	} else {
		go func() { errCh <- runControlPlane(ctx, cfg, nil) }()
		if err := waitHealthy(ctx, cfg.ServerURL, errCh); err != nil {
			fmt.Fprintln(os.Stderr, "up: control plane:", err)
			return 1
		}
		fmt.Printf("• control plane: listening on %s\n", cfg.ServerURL)
	}

	gw, statePath, err := ensureEnrolled(ctx, pool, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "up: enroll:", err)
		return 1
	}
	fmt.Printf("• gateway: enrolled (%s)\n", statePath)

	if err := selfTest(ctx, gw, statePath); err != nil {
		fmt.Fprintln(os.Stderr, "up: self-test:", err)
		return 1
	}
	fmt.Println("• self-test: action allowed, executed, and audited end-to-end")

	epochPub, err := cfg.epochPublicKeyB64()
	if err != nil {
		fmt.Fprintln(os.Stderr, "up:", err)
		return 1
	}
	fmt.Printf(`
actiongate is up.

  Next step — protect a project (run inside the project directory):
      actiongate protect claude-code

  Verify the audit trail any time:
      verify -database-url "%s" -tenant %s -key epoch-1=%s

  Approvals: without Slack configured, pending actions are approved via
  POST %s/approval/callback (see README "Try it", step 6).
%s`, cfg.DatabaseURL, cfg.TenantID, epochPub, cfg.ServerURL, serviceHint())

	if alreadyRunning {
		return 0
	}
	fmt.Println("\nControl plane running — leave this window open. Ctrl+C stops it")
	fmt.Println("(while it is down, hooked projects fail closed: governed tools are blocked).")
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "up: control plane:", err)
			return 1
		}
	case <-ctx.Done():
		<-errCh // let the server shut down cleanly
	}
	return 0
}

func runControlPlane(ctx context.Context, cfg *devConfig, log *slog.Logger) error {
	grantSeed, err := cfg.seed(cfg.GrantKeySeed)
	if err != nil {
		return err
	}
	epochSeed, err := cfg.seed(cfg.EpochKeySeed)
	if err != nil {
		return err
	}
	return controlplane.Run(ctx, controlplane.Config{
		Logger:             log,
		DatabaseURL:        cfg.DatabaseURL,
		Listen:             cfg.Listen,
		TokenSecret:        cfg.TokenSecret,
		GrantKeySeed:       grantSeed,
		EpochKeySeed:       epochSeed,
		SlackBotToken:      firstNonEmpty(cfg.SlackBotToken, os.Getenv("AG_SLACK_BOT_TOKEN")),
		SlackSigningSecret: firstNonEmpty(cfg.SlackSigningSecret, os.Getenv("AG_SLACK_SIGNING_SECRET")),
		SlackChannel:       firstNonEmpty(cfg.SlackChannel, os.Getenv("AG_SLACK_CHANNEL")),
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ensurePostgres connects, and if that fails manages the actiongate-db
// docker container (start it if it exists, create it otherwise), then waits
// for the database to answer.
func ensurePostgres(ctx context.Context, dbURL string) error {
	if pingOnce(ctx, dbURL) == nil {
		return nil
	}
	u, err := url.Parse(dbURL)
	if err != nil || !strings.HasPrefix(u.Host, "localhost") {
		return fmt.Errorf("cannot reach %s and it is not a local database this command manages", dbURL)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("database unreachable and docker is not installed — start Postgres yourself or install Docker Desktop")
	}

	exists := exec.CommandContext(ctx, "docker", "inspect", dbContainerName).Run() == nil
	if exists {
		if out, err := exec.CommandContext(ctx, "docker", "start", dbContainerName).CombinedOutput(); err != nil {
			return fmt.Errorf("docker start %s: %v: %s", dbContainerName, err, out)
		}
		// Best-effort: make the container survive reboots from now on.
		_ = exec.CommandContext(ctx, "docker", "update", "--restart", "unless-stopped", dbContainerName).Run()
	} else {
		pass, _ := u.User.Password()
		args := []string{
			"run", "-d", "--name", dbContainerName,
			"--restart", "unless-stopped",
			"-e", "POSTGRES_USER=" + u.User.Username(),
			"-e", "POSTGRES_PASSWORD=" + pass,
			"-e", "POSTGRES_DB=" + strings.TrimPrefix(u.Path, "/"),
			"-p", "5432:5432",
			"postgres:16-alpine",
		}
		// #nosec G204 -- args are built from the user's own database URL to
		// manage their local dev container; that is this command's job.
		if out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("docker run: %v: %s", err, out)
		}
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if pingOnce(ctx, dbURL) == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("database did not become ready within 60s")
}

func pingOnce(ctx context.Context, dbURL string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	return pool.Ping(ctx)
}

func migrate(ctx context.Context, dbURL string) error {
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.UpContext(ctx, db, ".")
}

// ensureTenant makes cfg.TenantID exist in this database with at least one
// policy snapshot. A recorded tenant missing from the database (fresh
// volume) is re-provisioned under the same id so enrolled state stays
// coherent. Returns whether anything was created.
func ensureTenant(ctx context.Context, pool *pgxpool.Pool, cfg *devConfig, cfgPath string) (bool, error) {
	if cfg.TenantID == "" {
		id, err := admin.CreateTenant(ctx, pool, policies.ClaudeCode)
		if err != nil {
			return false, err
		}
		cfg.TenantID = id.String()
		return true, saveDevConfig(cfg, cfgPath)
	}
	tenantID, err := uuid.Parse(cfg.TenantID)
	if err != nil {
		return false, fmt.Errorf("corrupt tenant id in dev config: %w", err)
	}
	var exists bool
	tx, err := pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		return false, err
	}
	if err := tx.QueryRow(ctx,
		`select exists(select 1 from configuration_snapshots where tenant_id = $1)`,
		tenantID).Scan(&exists); err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	if _, err := admin.SetPolicy(ctx, pool, tenantID, policies.ClaudeCode); err != nil {
		return false, err
	}
	return true, nil
}

func healthy(ctx context.Context, serverURL string) bool {
	reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, serverURL+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}

func waitHealthy(ctx context.Context, serverURL string, errCh <-chan error) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			return fmt.Errorf("exited during startup: %w", err)
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		if healthy(ctx, serverURL) {
			return nil
		}
	}
	return errors.New("not healthy within 30s")
}

// ensureEnrolled returns a gateway enrolled against this control plane,
// enrolling (or re-enrolling after a database reset) when needed. A state
// file pointing at a different server is never overwritten.
func ensureEnrolled(ctx context.Context, pool *pgxpool.Pool, cfg *devConfig) (*gateway.Gateway, string, error) {
	statePath, err := gateway.DefaultStatePath()
	if err != nil {
		return nil, "", err
	}
	state, err := gateway.LoadState(statePath)
	switch {
	case err == nil && state.ServerURL == cfg.ServerURL && state.TenantID == cfg.TenantID:
		if enrolledInDB(ctx, pool, state.GatewayID) {
			return &gateway.Gateway{State: state}, statePath, nil
		}
		// Database was reset since enrollment — fall through and re-enroll.
	case err == nil && state.ServerURL != cfg.ServerURL:
		return nil, "", fmt.Errorf(
			"%s is enrolled against %s, not %s — move that file aside if you want a local dev enrollment",
			statePath, state.ServerURL, cfg.ServerURL)
	case err != nil && !os.IsNotExist(err):
		return nil, "", err
	}

	tenantID, err := uuid.Parse(cfg.TenantID)
	if err != nil {
		return nil, "", err
	}
	token, err := admin.NewEnrollmentToken(ctx, pool, tenantID, time.Hour)
	if err != nil {
		return nil, "", err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "local"
	}
	state, err = gateway.Enroll(ctx, nil, cfg.ServerURL, token, host)
	if err != nil {
		return nil, "", err
	}
	if err := state.Save(statePath); err != nil {
		return nil, "", err
	}
	return &gateway.Gateway{State: state}, statePath, nil
}

func enrolledInDB(ctx context.Context, pool *pgxpool.Pool, gatewayID string) bool {
	id, err := uuid.Parse(gatewayID)
	if err != nil {
		return false
	}
	var exists bool
	if err := pool.QueryRow(ctx,
		`select exists(select 1 from gateways where id = $1)`, id).Scan(&exists); err != nil {
		return false
	}
	return exists
}

// selfTest round-trips one benign action through the full stack: submit,
// receive and locally verify a grant, report the outcome. Denial is also a
// healthy result (a strict policy is still a working policy).
func selfTest(ctx context.Context, gw *gateway.Gateway, statePath string) error {
	res, err := gw.Check(ctx, gateway.CheckInput{
		AgentID:         "actiongate-up",
		SessionID:       uuid.NewString(),
		NativeRequestID: uuid.NewString(),
		ToolName:        "actiongate_selftest",
		Params:          map[string]any{"purpose": "up health check"},
		Environment:     "default",
		Wait:            15 * time.Second,
	})
	if saveErr := gw.State.Save(statePath); saveErr != nil {
		return saveErr
	}
	switch {
	case err == nil:
		if _, err := gw.Report(ctx, gateway.ReportInput{ActionID: res.ActionID, Status: "success"}); err != nil {
			return fmt.Errorf("outcome report failed: %w", err)
		}
		return gw.State.Save(statePath)
	case errors.Is(err, gateway.ErrDenied):
		fmt.Printf("  (self-test denied by rule %q — policy is enforcing, stack is healthy)\n", res.RuleID)
		return nil
	default:
		return err
	}
}
