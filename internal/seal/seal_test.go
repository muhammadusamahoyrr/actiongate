package seal

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/testdb"
)

func newSealer(t *testing.T, pool *pgxpool.Pool, margin time.Duration) (*Sealer, map[string]ed25519.PublicKey) {
	t.Helper()
	signer, pub, err := NewEd25519Signer("test-key-1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return &Sealer{Pool: pool, Signer: signer, SafetyMargin: margin},
		map[string]ed25519.PublicKey{"test-key-1": pub}
}

// insertEvent appends a hot-path event directly (no action reference —
// audit_events.action_request_id is nullable by schema).
func insertEvent(t *testing.T, pool *pgxpool.Pool, tenantID, streamID uuid.UUID, eventType string, recordedAt time.Time) uuid.UUID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuidv7: %v", err)
	}
	_, err = pool.Exec(context.Background(),
		`insert into audit_events
		    (id, tenant_id, stream_id, event_type, attested_by, metadata, recorded_at)
		 values ($1, $2, $3, $4, 'control_plane', '{"n": 1}', $5)`,
		id, tenantID, streamID, eventType, recordedAt.UTC())
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	return id
}

func mustVerify(t *testing.T, pool *pgxpool.Pool, tenantID, streamID uuid.UUID, keys map[string]ed25519.PublicKey) Report {
	t.Helper()
	report, err := Verify(context.Background(), pool, tenantID, streamID, keys)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return report
}

func TestSealer(t *testing.T) {
	pool := testdb.SetupPool(t)
	ctx := context.Background()

	t.Run("seals a stream and the chain verifies end to end", func(t *testing.T) {
		sealer, keys := newSealer(t, pool, 200*time.Millisecond)
		tenantID, streamID := uuid.New(), uuid.New()
		past := time.Now().Add(-5 * time.Second)
		for i := 0; i < 5; i++ {
			insertEvent(t, pool, tenantID, streamID, "ActionCreated", past.Add(time.Duration(i)*time.Millisecond))
		}
		n, err := sealer.SealStream(ctx, tenantID, streamID)
		if err != nil {
			t.Fatalf("SealStream: %v", err)
		}
		if n != 5 {
			t.Fatalf("sealed %d events, want 5", n)
		}
		report := mustVerify(t, pool, tenantID, streamID, keys)
		if !report.OK() || report.Epochs != 1 || report.EventsSealed != 5 || report.UnsealedTail != 0 {
			t.Fatalf("bad report: %+v", report)
		}
		// Sequences must be the contiguous authoritative 1..5.
		var minSeq, maxSeq int64
		if err := pool.QueryRow(ctx,
			`select min(sequence_number), max(sequence_number) from audit_events
			  where tenant_id = $1 and stream_id = $2`, tenantID, streamID).Scan(&minSeq, &maxSeq); err != nil {
			t.Fatalf("read sequences: %v", err)
		}
		if minSeq != 1 || maxSeq != 5 {
			t.Fatalf("sequences [%d..%d], want [1..5]", minSeq, maxSeq)
		}
	})

	t.Run("second epoch links to the first and continues the sequence", func(t *testing.T) {
		sealer, keys := newSealer(t, pool, 200*time.Millisecond)
		tenantID, streamID := uuid.New(), uuid.New()
		past := time.Now().Add(-5 * time.Second)
		for i := 0; i < 3; i++ {
			insertEvent(t, pool, tenantID, streamID, "ActionCreated", past.Add(time.Duration(i)*time.Millisecond))
		}
		if _, err := sealer.SealStream(ctx, tenantID, streamID); err != nil {
			t.Fatalf("first seal: %v", err)
		}
		for i := 0; i < 2; i++ {
			insertEvent(t, pool, tenantID, streamID, "PolicyEvaluated", past.Add(time.Duration(10+i)*time.Millisecond))
		}
		n, err := sealer.SealStream(ctx, tenantID, streamID)
		if err != nil {
			t.Fatalf("second seal: %v", err)
		}
		if n != 2 {
			t.Fatalf("second epoch sealed %d, want 2", n)
		}
		report := mustVerify(t, pool, tenantID, streamID, keys)
		if !report.OK() || report.Epochs != 2 || report.EventsSealed != 5 {
			t.Fatalf("bad report: %+v", report)
		}
	})

	t.Run("watermark never seals past an in-flight transaction", func(t *testing.T) {
		sealer, keys := newSealer(t, pool, 300*time.Millisecond)
		tenantID, streamID := uuid.New(), uuid.New()

		// An open transaction inserts an event and stays uncommitted: its
		// event is invisible but holds a low ingest_seq.
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		inFlightID, err := uuid.NewV7()
		if err != nil {
			t.Fatalf("uuidv7: %v", err)
		}
		if _, err := tx.Exec(ctx,
			`insert into audit_events
			    (id, tenant_id, stream_id, event_type, attested_by, metadata, recorded_at)
			 values ($1, $2, $3, 'ActionCreated', 'control_plane', '{}', now())`,
			inFlightID, tenantID, streamID); err != nil {
			t.Fatalf("in-flight insert: %v", err)
		}

		// Committed events arrive after the open transaction began.
		insertEvent(t, pool, tenantID, streamID, "PolicyEvaluated", time.Now())
		insertEvent(t, pool, tenantID, streamID, "PolicyEvaluated", time.Now())

		n, err := sealer.SealStream(ctx, tenantID, streamID)
		if err != nil {
			t.Fatalf("SealStream with in-flight txn: %v", err)
		}
		if n != 0 {
			t.Fatalf("sealed %d events past an in-flight transaction — the §20.2.2 failure mode", n)
		}

		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit in-flight: %v", err)
		}
		time.Sleep(500 * time.Millisecond) // let the margin pass

		n, err = sealer.SealStream(ctx, tenantID, streamID)
		if err != nil {
			t.Fatalf("SealStream after commit: %v", err)
		}
		if n != 3 {
			t.Fatalf("sealed %d events after commit, want all 3", n)
		}
		report := mustVerify(t, pool, tenantID, streamID, keys)
		if !report.OK() || report.EventsSealed != 3 {
			t.Fatalf("bad report: %+v", report)
		}
		// The once-invisible event must be inside the chain, not lost.
		var seq int64
		if err := pool.QueryRow(ctx,
			`select sequence_number from audit_events where id = $1`, inFlightID).Scan(&seq); err != nil {
			t.Fatalf("read in-flight event: %v", err)
		}
		if seq != 1 {
			t.Fatalf("in-flight event got sequence %d, want 1 (lowest ingest_seq)", seq)
		}
	})

	t.Run("verification detects tampering the triggers would have blocked", func(t *testing.T) {
		sealer, keys := newSealer(t, pool, 200*time.Millisecond)
		tenantID, streamID := uuid.New(), uuid.New()
		victim := insertEvent(t, pool, tenantID, streamID, "ApprovalGranted", time.Now().Add(-5*time.Second))
		insertEvent(t, pool, tenantID, streamID, "ExecutionAuthorized", time.Now().Add(-5*time.Second))
		if _, err := sealer.SealStream(ctx, tenantID, streamID); err != nil {
			t.Fatalf("seal: %v", err)
		}

		// A malicious DBA disables the guard and rewrites history.
		if _, err := pool.Exec(ctx, `alter table audit_events disable trigger audit_events_guard`); err != nil {
			t.Fatalf("disable trigger: %v", err)
		}
		if _, err := pool.Exec(ctx,
			`update audit_events set metadata = '{"n": 666}' where id = $1`, victim); err != nil {
			t.Fatalf("tamper: %v", err)
		}
		if _, err := pool.Exec(ctx, `alter table audit_events enable trigger audit_events_guard`); err != nil {
			t.Fatalf("re-enable trigger: %v", err)
		}

		report := mustVerify(t, pool, tenantID, streamID, keys)
		if report.OK() {
			t.Fatal("tampered stream verified clean")
		}
		found := false
		for _, p := range report.Problems {
			if strings.Contains(p, "tampered or corrupted") {
				found = true
			}
		}
		if !found {
			t.Fatalf("tampering not attributed: %v", report.Problems)
		}
	})

	t.Run("unknown signing key is reported", func(t *testing.T) {
		sealer, _ := newSealer(t, pool, 200*time.Millisecond)
		tenantID, streamID := uuid.New(), uuid.New()
		insertEvent(t, pool, tenantID, streamID, "ActionCreated", time.Now().Add(-5*time.Second))
		if _, err := sealer.SealStream(ctx, tenantID, streamID); err != nil {
			t.Fatalf("seal: %v", err)
		}
		report := mustVerify(t, pool, tenantID, streamID, map[string]ed25519.PublicKey{})
		if report.OK() {
			t.Fatal("epoch signed by an unknown key verified clean")
		}
	})

	t.Run("unsealed tail is reported, not hidden", func(t *testing.T) {
		sealer, keys := newSealer(t, pool, 200*time.Millisecond)
		tenantID, streamID := uuid.New(), uuid.New()
		insertEvent(t, pool, tenantID, streamID, "ActionCreated", time.Now().Add(-5*time.Second))
		if _, err := sealer.SealStream(ctx, tenantID, streamID); err != nil {
			t.Fatalf("seal: %v", err)
		}
		// A fresh event inside the safety margin stays unsealed for now.
		insertEvent(t, pool, tenantID, streamID, "PolicyEvaluated", time.Now())
		report := mustVerify(t, pool, tenantID, streamID, keys)
		if !report.OK() || report.UnsealedTail != 1 {
			t.Fatalf("bad report: %+v", report)
		}
	})

	t.Run("SealAll discovers and seals every stream", func(t *testing.T) {
		sealer, keys := newSealer(t, pool, 200*time.Millisecond)
		tenantA, streamA := uuid.New(), uuid.New()
		tenantB, streamB := uuid.New(), uuid.New()
		insertEvent(t, pool, tenantA, streamA, "ActionCreated", time.Now().Add(-5*time.Second))
		insertEvent(t, pool, tenantB, streamB, "ActionCreated", time.Now().Add(-5*time.Second))
		n, err := sealer.SealAll(ctx)
		if err != nil {
			t.Fatalf("SealAll: %v", err)
		}
		if n < 2 {
			t.Fatalf("SealAll sealed %d, want at least the 2 new events", n)
		}
		for _, s := range []struct{ tenant, stream uuid.UUID }{{tenantA, streamA}, {tenantB, streamB}} {
			if r := mustVerify(t, pool, s.tenant, s.stream, keys); !r.OK() {
				t.Fatalf("stream %s/%s: %+v", s.tenant, s.stream, r)
			}
		}
	})
}
