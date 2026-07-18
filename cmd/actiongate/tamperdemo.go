package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/seal"
)

const tamperDemoDB = "actiongate_tamperdemo"

// cmdTamperDemo stages the moat claim live on a throwaway database: real
// events sealed by the real Sealer verify clean; a "malicious DBA" edit
// (guard trigger disabled, one row rewritten) flips verification to false
// and names the exact event. The live audit chain is never touched — a
// tampered chain stays broken forever, which is the whole point.
func cmdTamperDemo(args []string) int {
	fs := flag.NewFlagSet("tamper-demo", flag.ContinueOnError)
	dbURLFlag := fs.String("db-url", "", "Postgres URL (default: the dev config's database server)")
	keep := fs.Bool("keep", false, "keep the scratch database afterwards")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	ctx := context.Background()

	baseURL := *dbURLFlag
	if baseURL == "" {
		cfgPath, err := devConfigPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "tamper-demo:", err)
			return 1
		}
		cfg, err := loadDevConfigAt(cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "tamper-demo: no database to borrow — run `actiongate up` first or pass -db-url:", err)
			return 1
		}
		baseURL = cfg.DatabaseURL
	}
	if err := runTamperDemo(ctx, baseURL, *keep); err != nil {
		fmt.Fprintln(os.Stderr, "tamper-demo:", err)
		return 1
	}
	return 0
}

func swapDatabase(rawURL, dbName string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	u.Path = "/" + dbName
	return u.String(), nil
}

func runTamperDemo(ctx context.Context, baseURL string, keep bool) error {
	adminURL, err := swapDatabase(baseURL, "postgres")
	if err != nil {
		return err
	}
	demoURL, err := swapDatabase(baseURL, tamperDemoDB)
	if err != nil {
		return err
	}

	fmt.Printf("Scratch database %q — your real audit chain is not touched.\n\n", tamperDemoDB)
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		return err
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `drop database if exists `+tamperDemoDB+` with (force)`); err != nil {
		return fmt.Errorf("drop old scratch db: %w", err)
	}
	if _, err := admin.Exec(ctx, `create database `+tamperDemoDB); err != nil {
		return fmt.Errorf("create scratch db: %w", err)
	}
	dropIt := func() {
		if keep {
			fmt.Printf("\n(scratch database kept: %s)\n", demoURL)
			return
		}
		if _, err := admin.Exec(context.Background(), `drop database if exists `+tamperDemoDB+` with (force)`); err == nil {
			fmt.Println("\nScratch database dropped. Your real chain never changed.")
		}
	}
	defer dropIt()

	if err := migrate(ctx, demoURL); err != nil {
		return err
	}
	pool, err := pgxpool.New(ctx, demoURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	// ACT 1 — a normal history, sealed by the real Sealer.
	fmt.Println("ACT 1 — five audit events are written and sealed into a signed epoch.")
	tenantID, streamID := uuid.New(), uuid.New()
	past := time.Now().Add(-5 * time.Second)
	var victim uuid.UUID
	for i, eventType := range []string{
		"ActionCreated", "PolicyEvaluated", "ApprovalRequested", "ApprovalGranted", "ExecutionSucceeded",
	} {
		id := uuid.New()
		meta := `{"demo": true}`
		if eventType == "ApprovalGranted" {
			victim = id
			meta = `{"approver_id": "alice", "reason": "reviewed and safe"}`
		}
		if _, err := pool.Exec(ctx,
			`insert into audit_events
			    (id, tenant_id, stream_id, event_type, attested_by, metadata, recorded_at)
			 values ($1, $2, $3, $4, 'control_plane', $5, $6)`,
			id, tenantID, streamID, eventType, meta, past.Add(time.Duration(i)*time.Millisecond).UTC()); err != nil {
			return fmt.Errorf("insert %s: %w", eventType, err)
		}
	}
	signer, pub, err := seal.NewEd25519Signer("demo-epoch")
	if err != nil {
		return err
	}
	sealer := &seal.Sealer{Pool: pool, Signer: signer}
	if _, err := sealer.SealStream(ctx, tenantID, streamID); err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	keys := map[string]ed25519.PublicKey{"demo-epoch": pub}

	report, err := seal.Verify(ctx, pool, tenantID, streamID, keys)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	printReport("verify (before tampering)", report)
	if !report.OK() {
		return fmt.Errorf("fresh chain failed verification — demo aborted")
	}

	// ACT 2 — the attack the triggers cannot stop: a DBA disables them.
	fmt.Println("\nACT 2 — a malicious DBA disables the append-only guard and rewrites")
	fmt.Println("the ApprovalGranted event: approver \"alice\" becomes \"attacker\".")
	if _, err := pool.Exec(ctx, `alter table audit_events disable trigger audit_events_guard`); err != nil {
		return fmt.Errorf("disable trigger: %w", err)
	}
	if _, err := pool.Exec(ctx,
		`update audit_events set metadata = '{"approver_id": "attacker", "reason": "nothing to see here"}'
		 where id = $1`, victim); err != nil {
		return fmt.Errorf("tamper: %w", err)
	}
	if _, err := pool.Exec(ctx, `alter table audit_events enable trigger audit_events_guard`); err != nil {
		return fmt.Errorf("re-enable trigger: %w", err)
	}
	fmt.Println("The database accepted the edit. Triggers, permissions, and the")
	fmt.Println("application all failed to prevent it.")

	// ACT 3 — the math does not.
	fmt.Println("\nACT 3 — re-run verification. It re-derives every hash and signature")
	fmt.Println("from raw rows, trusting nothing but the public key:")
	report, err = seal.Verify(ctx, pool, tenantID, streamID, keys)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	printReport("verify (after tampering)", report)
	if report.OK() {
		return fmt.Errorf("tampering was NOT detected — this is a bug, please report it")
	}
	fmt.Printf("\nThe edit was caught and attributed (victim event %s).\n", victim)
	fmt.Println("Rewriting history without the signing key is detectable, always.")
	return nil
}

func printReport(label string, r seal.Report) {
	out, _ := json.Marshal(map[string]any{
		"ok": r.OK(), "epochs": r.Epochs, "events_sealed": r.EventsSealed,
		"unsealed_tail": r.UnsealedTail, "problems": r.Problems,
	})
	fmt.Printf("  %s:\n  %s\n", label, string(out))
}
