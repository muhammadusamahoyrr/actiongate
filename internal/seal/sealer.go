// Package seal implements the background Sealer (plan §20.2.2). Hot-path
// audit writes are plain appends; the Sealer assigns the authoritative
// contiguous sequence numbers, computes the SHA-256 chain, and closes
// signed epochs — off the request path.
//
// The watermark mechanism is correctness-critical and deliberately not
// simplified: sealing must never pass an in-flight transaction whose event
// would land below the sealed frontier, or that event is silently and
// permanently omitted from the chain. The safe frontier is derived from the
// oldest running transaction's start time: ingest_seq values are allocated
// in wall-clock order at insert, and every running transaction started at or
// after min(xact_start), so any visible event recorded before
// min(xact_start) − safety margin can no longer gain a predecessor.
package seal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"actiongate/internal/auditenc"
)

const (
	DefaultSafetyMargin = 2 * time.Second
	DefaultMaxBatch     = 1000
	DefaultInterval     = 5 * time.Second
)

type Sealer struct {
	Pool   *pgxpool.Pool
	Signer Signer
	// SafetyMargin absorbs the skew between an event's Go-computed
	// recorded_at and its ingest_seq allocation inside the same statement.
	SafetyMargin time.Duration
	MaxBatch     int
	Now          func() time.Time
}

func (s *Sealer) margin() time.Duration {
	if s.SafetyMargin > 0 {
		return s.SafetyMargin
	}
	return DefaultSafetyMargin
}

func (s *Sealer) maxBatch() int {
	if s.MaxBatch > 0 {
		return s.MaxBatch
	}
	return DefaultMaxBatch
}

func (s *Sealer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Run seals every stream with unsealed events on a fixed cadence (plan
// §20.2.5: every 5 s or 1,000 events per stream) until ctx is done.
func (s *Sealer) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := s.SealAll(ctx); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
		}
	}
}

// SealAll discovers streams with unsealed events and seals each. The
// discovery query crosses tenants: the sealer's role needs BYPASSRLS (it is
// a control-plane internal component, plan §3).
func (s *Sealer) SealAll(ctx context.Context) (int, error) {
	rows, err := s.Pool.Query(ctx,
		`select distinct tenant_id, stream_id from audit_events where epoch_id is null`)
	if err != nil {
		return 0, fmt.Errorf("discover streams: %w", err)
	}
	type stream struct{ tenant, stream uuid.UUID }
	var streams []stream
	for rows.Next() {
		var st stream
		if err := rows.Scan(&st.tenant, &st.stream); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan stream: %w", err)
		}
		streams = append(streams, st)
	}
	rows.Close()
	if rows.Err() != nil {
		return 0, fmt.Errorf("discover streams: %w", rows.Err())
	}

	total := 0
	for _, st := range streams {
		n, err := s.SealStream(ctx, st.tenant, st.stream)
		if err != nil {
			return total, fmt.Errorf("seal %s/%s: %w", st.tenant, st.stream, err)
		}
		total += n
	}
	return total, nil
}

type pendingEvent struct {
	id              uuid.UUID
	actionRequestID *uuid.UUID
	eventType       string
	attestedBy      string
	metadataText    []byte
	recordedAt      time.Time
	ingestSeq       int64
}

// SealStream seals one epoch for one stream, returning how many events were
// sealed (0 when nothing is safely sealable yet). The whole operation runs
// on a single connection holding a per-stream advisory lock; the only
// slow-capable step — signing — happens outside the write transaction.
func (s *Sealer) SealStream(ctx context.Context, tenantID, streamID uuid.UUID) (int, error) {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()

	lockKey := tenantID.String() + ":" + streamID.String()
	if _, err := conn.Exec(ctx,
		`select pg_advisory_lock(hashtextextended($1, 42))`, lockKey); err != nil {
		return 0, fmt.Errorf("advisory lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, `select pg_advisory_unlock(hashtextextended($1, 42))`, lockKey)
	}()

	// Safe frontier: only events recorded before every currently running
	// transaction began (minus the margin) can be sealed — see package doc.
	var watermark int64
	err = conn.QueryRow(ctx,
		`with horizon as (
		    select least(
		        coalesce((select min(xact_start) from pg_stat_activity
		                   where xact_start is not null and pid <> pg_backend_pid()),
		                 now()),
		        now()) - $3::interval as t_old
		 )
		 select coalesce(max(e.ingest_seq), 0)
		   from audit_events e, horizon h
		  where e.tenant_id = $1 and e.stream_id = $2
		    and e.epoch_id is null and e.recorded_at < h.t_old`,
		tenantID, streamID, s.margin().String(),
	).Scan(&watermark)
	if err != nil {
		return 0, fmt.Errorf("compute watermark: %w", err)
	}
	if watermark == 0 {
		return 0, nil
	}

	rows, err := conn.Query(ctx,
		`select id, action_request_id, event_type, attested_by, metadata::text,
		        recorded_at, ingest_seq
		   from audit_events
		  where tenant_id = $1 and stream_id = $2
		    and epoch_id is null and ingest_seq <= $3
		  order by ingest_seq
		  limit $4`,
		tenantID, streamID, watermark, s.maxBatch())
	if err != nil {
		return 0, fmt.Errorf("load unsealed: %w", err)
	}
	var pending []pendingEvent
	for rows.Next() {
		var e pendingEvent
		if err := rows.Scan(&e.id, &e.actionRequestID, &e.eventType, &e.attestedBy,
			&e.metadataText, &e.recordedAt, &e.ingestSeq); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan event: %w", err)
		}
		pending = append(pending, e)
	}
	rows.Close()
	if rows.Err() != nil {
		return 0, fmt.Errorf("load unsealed: %w", rows.Err())
	}
	if len(pending) == 0 {
		return 0, nil
	}

	prevSeq, prevHash, prevEpochRoot, err := s.chainTail(ctx, conn, tenantID, streamID)
	if err != nil {
		return 0, err
	}

	sealedAt := s.now().UTC()
	epochID, err := uuid.NewV7()
	if err != nil {
		return 0, fmt.Errorf("uuidv7: %w", err)
	}

	type sealedEvent struct {
		id       uuid.UUID
		seq      uint64
		prevHash []byte
		hash     []byte
	}
	sealed := make([]sealedEvent, 0, len(pending))
	hash := prevHash
	seq := prevSeq
	for _, e := range pending {
		seq++
		actionRef := ""
		if e.actionRequestID != nil {
			actionRef = e.actionRequestID.String()
		}
		next, err := auditenc.ChainHash(hash, auditenc.Event{
			ID:              e.id,
			TenantID:        tenantID,
			StreamID:        streamID,
			SequenceNumber:  seq,
			Type:            e.eventType,
			AttestedBy:      e.attestedBy,
			ActionRequestID: actionRef,
			MetadataJCS:     e.metadataText,
			RecordedAt:      e.recordedAt,
		})
		if err != nil {
			return 0, fmt.Errorf("chain event %s: %w", e.id, err)
		}
		sealed = append(sealed, sealedEvent{id: e.id, seq: seq, prevHash: hash, hash: next})
		hash = next
	}

	epoch := auditenc.Epoch{
		EpochID:       epochID,
		TenantID:      tenantID,
		StreamID:      streamID,
		FirstSequence: sealed[0].seq,
		LastSequence:  sealed[len(sealed)-1].seq,
		RootHash:      hash,
		PrevEpochRoot: prevEpochRoot,
		SealedAt:      sealedAt,
	}
	message, err := auditenc.EncodeEpoch(epoch)
	if err != nil {
		return 0, fmt.Errorf("encode epoch: %w", err)
	}
	signature, err := s.Signer.Sign(ctx, message)
	if err != nil {
		return 0, fmt.Errorf("sign epoch: %w", err)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, e := range sealed {
		tag, err := tx.Exec(ctx,
			`update audit_events
			    set sequence_number = $1, previous_hash = $2, event_hash = $3, epoch_id = $4
			  where id = $5 and epoch_id is null`,
			e.seq, e.prevHash, e.hash, epochID, e.id)
		if err != nil {
			return 0, fmt.Errorf("seal event %s: %w", e.id, err)
		}
		if tag.RowsAffected() != 1 {
			return 0, fmt.Errorf("event %s vanished or was sealed concurrently despite the advisory lock", e.id)
		}
	}
	if _, err := tx.Exec(ctx,
		`insert into audit_epochs
		    (epoch_id, tenant_id, stream_id, first_sequence, last_sequence,
		     root_hash, prev_epoch_root, signature, key_id, sealed_at)
		 values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		epochID, tenantID, streamID, epoch.FirstSequence, epoch.LastSequence,
		epoch.RootHash, epoch.PrevEpochRoot, signature, s.Signer.KeyID(), sealedAt,
	); err != nil {
		return 0, fmt.Errorf("insert epoch: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return len(sealed), nil
}

// chainTail loads where the chain left off: the last sealed sequence, its
// event hash, and the previous epoch's root. A fresh stream starts at
// sequence 0 with the genesis hash.
func (s *Sealer) chainTail(ctx context.Context, conn *pgxpool.Conn, tenantID, streamID uuid.UUID) (uint64, []byte, []byte, error) {
	var lastSeq uint64
	var rootHash []byte
	err := conn.QueryRow(ctx,
		`select last_sequence, root_hash from audit_epochs
		  where tenant_id = $1 and stream_id = $2
		  order by last_sequence desc limit 1`,
		tenantID, streamID).Scan(&lastSeq, &rootHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, auditenc.GenesisHash, nil, nil
	}
	if err != nil {
		return 0, nil, nil, fmt.Errorf("load chain tail: %w", err)
	}
	var lastHash []byte
	err = conn.QueryRow(ctx,
		`select event_hash from audit_events
		  where tenant_id = $1 and stream_id = $2 and sequence_number = $3`,
		tenantID, streamID, lastSeq).Scan(&lastHash)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("load last sealed event: %w", err)
	}
	return lastSeq, lastHash, rootHash, nil
}
