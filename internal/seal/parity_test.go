package seal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/muhammadusamahoyrr/actiongate/internal/dbruntime"
	"github.com/muhammadusamahoyrr/actiongate/internal/testdb"
	"github.com/muhammadusamahoyrr/actiongate/migrations"
)

// parityFixture is a fully-deterministic audit history: fixed ids, types, and
// timestamps, so sealing it produces a byte-identical root hash on any correct
// PostgreSQL backend. This is what protects the "check the math, not our word"
// pitch from silent drift between the Docker and embedded deployment modes.
type parityFixture struct {
	tenant uuid.UUID
	stream uuid.UUID
	events []parityEvent
	keys   map[string]ed25519.PublicKey
	signer Signer
}

type parityEvent struct {
	id  uuid.UUID
	typ string
	at  time.Time
}

func newParityFixture(t *testing.T) parityFixture {
	t.Helper()
	// Fixed seed → deterministic signing key, identical for both backends.
	signer, pub, err := NewEd25519SignerFromSeed("epoch-1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	base := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ids := []string{
		"00000000-0000-7000-8000-000000000001",
		"00000000-0000-7000-8000-000000000002",
		"00000000-0000-7000-8000-000000000003",
	}
	types := []string{"ActionCreated", "PolicyEvaluated", "ActionExecuted"}
	evs := make([]parityEvent, len(ids))
	for i := range ids {
		evs[i] = parityEvent{
			id:  uuid.MustParse(ids[i]),
			typ: types[i],
			at:  base.Add(time.Duration(i) * time.Second),
		}
	}
	return parityFixture{
		tenant: uuid.MustParse("2f871fa3-8397-413f-a1e1-a4ed8f123190"),
		stream: uuid.MustParse("11111111-2222-3333-4444-555555555555"),
		events: evs,
		keys:   map[string]ed25519.PublicKey{"epoch-1": pub},
		signer: signer,
	}
}

// sealFixture inserts the fixture into an already-migrated pool, seals it, and
// returns the epoch root hash and the verify report.
func (fx parityFixture) sealAndVerify(t *testing.T, pool *pgxpool.Pool) ([]byte, Report) {
	t.Helper()
	ctx := context.Background()
	for _, e := range fx.events {
		if _, err := pool.Exec(ctx,
			`insert into audit_events
			    (id, tenant_id, stream_id, event_type, attested_by, metadata, recorded_at)
			 values ($1, $2, $3, $4, 'control_plane', '{"n": 1}', $5)`,
			e.id, fx.tenant, fx.stream, e.typ, e.at); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}
	sealer := &Sealer{Pool: pool, Signer: fx.signer, SafetyMargin: 0}
	if _, err := sealer.SealStream(ctx, fx.tenant, fx.stream); err != nil {
		t.Fatalf("SealStream: %v", err)
	}
	var root []byte
	if err := pool.QueryRow(ctx,
		`select root_hash from audit_epochs where tenant_id = $1 and stream_id = $2`,
		fx.tenant, fx.stream).Scan(&root); err != nil {
		t.Fatalf("read root hash: %v", err)
	}
	report, err := Verify(ctx, pool, fx.tenant, fx.stream, fx.keys)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return root, report
}

func sameReport(a, b Report) bool {
	return a.OK() == b.OK() && a.Epochs == b.Epochs &&
		a.EventsSealed == b.EventsSealed && a.UnsealedTail == b.UnsealedTail
}

// startEmbeddedPool boots an embedded PG18 cluster, applies migrations, and
// returns a pool. No Docker.
func startEmbeddedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	rt, err := dbruntime.New(dbruntime.Config{
		DataPath:     filepath.Join(t.TempDir(), "pgdata"),
		Password:     "pw-parity",
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
	return pool
}

// TestVerifyDeterministicAcrossClusters seals the same fixture on two
// independent embedded clusters and asserts a byte-identical root hash and an
// identical verify report. This proves the sealing/verify math is deterministic
// — the property the Docker-vs-embedded parity check depends on. Runs without
// Docker.
func TestVerifyDeterministicAcrossClusters(t *testing.T) {
	if testing.Short() {
		t.Skip("runs real Postgres; skipped in -short")
	}
	fx := newParityFixture(t)

	root1, rep1 := fx.sealAndVerify(t, startEmbeddedPool(t))
	root2, rep2 := fx.sealAndVerify(t, startEmbeddedPool(t))

	if !rep1.OK() || !rep2.OK() {
		t.Fatalf("reports not OK: %+v / %+v", rep1, rep2)
	}
	if !bytes.Equal(root1, root2) {
		t.Fatalf("root hash differs across clusters:\n%x\n%x", root1, root2)
	}
	if !sameReport(rep1, rep2) {
		t.Fatalf("verify reports differ: %+v vs %+v", rep1, rep2)
	}
}

// TestVerifyParityDockerVsEmbedded is the deployment-mode parity guard: the same
// audit history sealed on Docker Postgres and on the embedded runtime must yield
// a byte-identical root hash and identical verify output. It needs the Docker
// daemon, so it is opt-in via AG_RUN_DOCKER_PARITY (set in CI).
func TestVerifyParityDockerVsEmbedded(t *testing.T) {
	if testing.Short() {
		t.Skip("runs real Postgres; skipped in -short")
	}
	if os.Getenv("AG_RUN_DOCKER_PARITY") == "" {
		t.Skip("set AG_RUN_DOCKER_PARITY=1 (needs Docker) to run the Docker-vs-embedded parity check")
	}
	fx := newParityFixture(t)

	embRoot, embRep := fx.sealAndVerify(t, startEmbeddedPool(t))
	dockRoot, dockRep := fx.sealAndVerify(t, testdb.SetupPool(t))

	if !embRep.OK() || !dockRep.OK() {
		t.Fatalf("reports not OK: embedded=%+v docker=%+v", embRep, dockRep)
	}
	if !bytes.Equal(embRoot, dockRoot) {
		t.Fatalf("root hash differs between embedded and docker:\n%x\n%x", embRoot, dockRoot)
	}
	if !sameReport(embRep, dockRep) {
		t.Fatalf("verify reports differ: embedded=%+v docker=%+v", embRep, dockRep)
	}
}
