package controlplane_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/muhammadusamahoyrr/actiongate/internal/admin"
	"github.com/muhammadusamahoyrr/actiongate/internal/approval"
	"github.com/muhammadusamahoyrr/actiongate/internal/controlplane"
	"github.com/muhammadusamahoyrr/actiongate/internal/dbroles"
	"github.com/muhammadusamahoyrr/actiongate/internal/dbruntime"
	"github.com/muhammadusamahoyrr/actiongate/internal/domain"
	"github.com/muhammadusamahoyrr/actiongate/internal/gateway"
	"github.com/muhammadusamahoyrr/actiongate/internal/queue"
	"github.com/muhammadusamahoyrr/actiongate/internal/seal"
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
	tokenSecret := randomString(t, 32)
	epochSeed := randomBytes(t, 32)
	errCh := make(chan error, 1)
	go func() {
		errCh <- controlplane.Run(ctx, controlplane.Config{
			DatabaseURL: appDSN, SealerDatabaseURL: sealerDSN, SkipQueueMigrate: true,
			Listen: addr, TokenSecret: tokenSecret,
			GrantKeySeed: randomBytes(t, 32), EpochKeySeed: epochSeed,
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

	// Audit H6/H10: a held action's approval message shows the command,
	// and a local approval through the callback (token re-derived from the
	// secret, as `actiongate approvals approve` does) is recorded.
	held, err := gw.Check(ctx, gateway.CheckInput{
		AgentID: "e2e", SessionID: uuid.NewString(), NativeRequestID: uuid.NewString(),
		ToolName: "Bash", Params: map[string]any{"command": "rm -rf ./build-cache"}, Environment: "default",
		Wait: time.Second,
	})
	if !errors.Is(err, gateway.ErrTimedOut) {
		t.Fatalf("rm -rf: err = %v, want held for approval", err)
	}
	var approvalID uuid.UUID
	var body string
	deadlineA := time.Now().Add(15 * time.Second)
	for {
		err := owner.QueryRow(ctx,
			`select (args->>'approval_request_id')::uuid, args->>'body' from river_job
			  where kind = 'deliver_approval' and args->>'action_id' = $1`, held.ActionID).Scan(&approvalID, &body)
		if err == nil {
			break
		}
		if time.Now().After(deadlineA) {
			t.Fatalf("no approval delivery job for the held action: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(body, "rm -rf ./build-cache") {
		t.Errorf("approval body does not show the command:\n%s", body)
	}
	cbToken, err := (&approval.Service{TokenSecret: []byte(tokenSecret)}).CallbackToken(tenant, approvalID)
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := json.Marshal(map[string]string{"token": cbToken, "decision": "approved", "approver_id": "local:tester"})
	resp, err := http.Post(serverURL+"/approval/callback", "application/json", bytes.NewReader(cb)) //nolint:gosec,noctx // test loopback URL
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("local approval via callback: %s", resp.Status)
	}
	var status string
	if err := owner.QueryRow(ctx, `select status from approval_requests where id = $1`, approvalID).Scan(&status); err != nil || status != "approved" {
		t.Errorf("approval status = %q, %v; want approved", status, err)
	}

	// The sealer (its own BYPASSRLS role) seals the chain, up to and
	// including the first action's ActionCreated event.
	deadline := time.Now().Add(45 * time.Second)
	for {
		var sealed bool
		if err := owner.QueryRow(ctx,
			`select exists (select 1 from audit_events
			                 where action_request_id = $1 and event_type = 'ActionCreated' and epoch_id is not null)`,
			res.ActionID).Scan(&sealed); err != nil {
			t.Fatal(err)
		}
		if sealed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sealer running as ag_sealer did not seal the action within 45s")
		}
		select {
		case err := <-errCh:
			t.Fatalf("control plane exited: %v", err)
		case <-time.After(time.Second):
		}
	}
	cancel()
	<-errCh // the sealer has stopped; the chain is now still

	verifyAuditCoverage(t, owner, tenant, epochSeed, uuid.MustParse(res.ActionID))
}

// verifyAuditCoverage checks the sealed chain end to end, then tampers
// with it the way a database administrator could and checks that verify
// notices: the policy change is sealed (M9), each request is bound by its
// fingerprint (H7), and deleting epochs is detected (H8).
func verifyAuditCoverage(t *testing.T, owner *pgxpool.Pool, tenant uuid.UUID, epochSeed []byte, actionID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	_, pub, err := seal.NewEd25519SignerFromSeed("epoch-1", epochSeed)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"epoch-1": pub}
	stream := domain.StreamFor(tenant)
	report, err := seal.Verify(ctx, owner, tenant, stream, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() || report.RequestsChecked == 0 || report.Head == nil {
		t.Fatalf("clean chain: %+v", report)
	}
	var policyEvents int
	if err := owner.QueryRow(ctx,
		`select count(*) from audit_events
		  where tenant_id = $1 and stream_id = $2 and event_type = 'PolicyChanged' and epoch_id is not null`,
		tenant, stream).Scan(&policyEvents); err != nil || policyEvents != 1 {
		t.Errorf("sealed PolicyChanged events = %d (%v), want 1", policyEvents, err)
	}
	head := *report.Head

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	hasProblem := func(r seal.Report, substr string) bool {
		for _, p := range r.Problems {
			if strings.Contains(p, substr) {
				return true
			}
		}
		return false
	}

	// H7: rewrite what the agent asked for, past the append-only trigger.
	exec(`alter table action_requests disable trigger action_requests_append_only`)
	exec(`update action_requests set tool_params = '{"command":"rm -rf /"}' where id = $1`, actionID)
	exec(`alter table action_requests enable trigger action_requests_append_only`)
	if report, err = seal.Verify(ctx, owner, tenant, stream, keys); err != nil {
		t.Fatal(err)
	}
	if !hasProblem(report, "does not match its sealed fingerprint") {
		t.Errorf("rewritten request params were not detected: %v", report.Problems)
	}

	// H8: cut the chain back by deleting its newest epoch.
	exec(`alter table audit_epochs disable trigger audit_epochs_guard`)
	exec(`delete from audit_epochs where tenant_id = $1 and stream_id = $2 and last_sequence = $3`, tenant, stream, head.LastSequence)
	exec(`alter table audit_epochs enable trigger audit_epochs_guard`)
	if report, err = seal.Verify(ctx, owner, tenant, stream, keys); err != nil {
		t.Fatal(err)
	}
	if !hasProblem(report, "belong to no epoch") {
		t.Errorf("deleted epoch was not detected: %v", report.Problems)
	}
	if report.Contains(head) {
		t.Error("chain still contains the deleted head; a checkpoint would not catch the cut")
	}
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
