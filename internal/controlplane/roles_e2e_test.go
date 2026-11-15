package controlplane_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/muhammadusamahoyrr/actiongate/internal/admin"
	"github.com/muhammadusamahoyrr/actiongate/internal/controlplane"
	"github.com/muhammadusamahoyrr/actiongate/internal/dbroles"
	"github.com/muhammadusamahoyrr/actiongate/internal/dbruntime"
	"github.com/muhammadusamahoyrr/actiongate/internal/gateway"
	"github.com/muhammadusamahoyrr/actiongate/internal/queue"
	"github.com/muhammadusamahoyrr/actiongate/migrations"
	"github.com/muhammadusamahoyrr/actiongate/policies"
)

// Audit C4, end to end and without Docker: the real control plane runs as
// the RLS-bound app role with the sealer on its own role, a gateway
// enrolls, an action is decided, executed and reported, and the sealer
// seals the audit chain across tenants.
func TestControlPlaneRunsAsLeastPrivilegeRoles(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	// Owner: migrations, roles, tenant (what `actiongate up` does).
	sqldb, err := sql.Open("pgx", rt.DSN())
	if err != nil {
		t.Fatal(err)
	}
	goose.SetBaseFS(migrations.FS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpContext(ctx, sqldb, "."); err != nil {
		t.Fatal(err)
	}
	_ = sqldb.Close()
	owner, err := pgxpool.New(ctx, rt.DSN())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := queue.Migrate(ctx, owner); err != nil {
		t.Fatal(err)
	}
	if err := dbroles.Ensure(ctx, owner, "pw-app", "pw-sealer"); err != nil {
		t.Fatal(err)
	}
	tenant, err := admin.CreateTenant(ctx, owner, policies.ClaudeCode)
	if err != nil {
		t.Fatal(err)
	}
	appDSN, _ := dbroles.DSN(rt.DSN(), dbroles.AppRole, "pw-app")
	sealerDSN, _ := dbroles.DSN(rt.DSN(), dbroles.SealerRole, "pw-sealer")

	addr := freeAddr(t)
	errCh := make(chan error, 1)
	go func() {
		errCh <- controlplane.Run(ctx, controlplane.Config{
			DatabaseURL: appDSN, SealerDatabaseURL: sealerDSN, SkipQueueMigrate: true,
			Listen: addr, TokenSecret: randomString(t, 32),
			GrantKeySeed: randomBytes(t, 32), EpochKeySeed: randomBytes(t, 32),
		})
	}()
	serverURL := "http://" + addr
	waitHealthy(t, serverURL, errCh)

	token, err := admin.NewEnrollmentToken(ctx, owner, tenant, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	state, err := gateway.Enroll(ctx, nil, serverURL, token, "roles-e2e")
	if err != nil {
		t.Fatalf("enroll as app role: %v", err)
	}
	gw := &gateway.Gateway{State: state}
	res, err := gw.Check(ctx, gateway.CheckInput{
		AgentID: "e2e", SessionID: uuid.NewString(), NativeRequestID: uuid.NewString(),
		ToolName: "Bash", Params: map[string]any{"command": "ls"}, Environment: "default", Wait: 15 * time.Second,
	})
	if err != nil {
		t.Fatalf("check as app role: %v", err)
	}
	if _, err := gw.Report(ctx, gateway.ReportInput{ActionID: res.ActionID, Status: "success"}); err != nil {
		t.Fatalf("report as app role: %v", err)
	}
	// A secret read is denied by the built-in rule under the app role too.
	if _, err := gw.Check(ctx, gateway.CheckInput{
		AgentID: "e2e", SessionID: uuid.NewString(), NativeRequestID: uuid.NewString(),
		ToolName: "Read", Params: map[string]any{"file_path": "/home/x/.config/actiongate/dev.json"}, Environment: "default", Wait: 15 * time.Second,
	}); err == nil {
		t.Error("reading actiongate's dev.json was allowed")
	}

	// Write-then-run (audit H2): a script the agent wrote is read by the
	// gateway, carried to the control plane, and judged there — rm -rf ~
	// inside it needs approval, which nobody gives here, so it times out.
	scriptDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(scriptDir, "cleanup.sh"), []byte("#!/bin/sh\nrm -rf ~\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = gw.Check(ctx, gateway.CheckInput{
		AgentID: "e2e", SessionID: uuid.NewString(), NativeRequestID: uuid.NewString(),
		ToolName: "Bash", Params: map[string]any{"command": "bash cleanup.sh"}, Environment: "default",
		Wait: 2 * time.Second, Cwd: scriptDir,
	})
	if !errors.Is(err, gateway.ErrTimedOut) {
		t.Errorf("bash cleanup.sh (rm -rf ~ inside): err = %v, want it held for approval (timed out)", err)
	}

	// The sealer (its own BYPASSRLS role) seals the chain.
	deadline := time.Now().Add(45 * time.Second)
	for {
		var epochs int
		if err := owner.QueryRow(ctx, `select count(*) from audit_epochs where tenant_id = $1`, tenant).Scan(&epochs); err != nil {
			t.Fatal(err)
		}
		if epochs > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sealer running as ag_sealer sealed no epoch within 45s")
		}
		select {
		case err := <-errCh:
			t.Fatalf("control plane exited: %v", err)
		case <-time.After(time.Second):
		}
	}
	cancel()
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

func waitHealthy(t *testing.T, url string, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("control plane exited early: %v", err)
		default:
		}
		if resp, err := http.Get(url + "/healthz"); err == nil { //nolint:gosec,noctx // test loopback URL
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("control plane never became healthy")
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func randomString(t *testing.T, n int) string {
	return fmt.Sprintf("%x", randomBytes(t, n))
}
