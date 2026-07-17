package seal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"actiongate/internal/auditenc"
)

// Report is the outcome of an independent chain verification. OK means every
// epoch's signature verified, every hash re-derived identically, and the
// sequence is contiguous with no gaps. UnsealedTail is informational — a
// bounded tail is normal, a growing one is the §20.3 SLO alert.
type Report struct {
	Epochs       int
	EventsSealed int
	UnsealedTail int
	Problems     []string
}

func (r Report) OK() bool { return len(r.Problems) == 0 }

// Verify re-derives a stream's chain from the stored events — exactly what a
// skeptic would do from an export. It trusts nothing but the public keys:
// sequence contiguity, per-event hashes, epoch roots, epoch linkage, and
// signatures are all recomputed.
func Verify(ctx context.Context, pool *pgxpool.Pool, tenantID, streamID uuid.UUID, publicKeys map[string]ed25519.PublicKey) (Report, error) {
	var report Report
	problem := func(format string, args ...any) {
		report.Problems = append(report.Problems, fmt.Sprintf(format, args...))
	}

	type epochRow struct {
		epoch     auditenc.Epoch
		signature []byte
		keyID     string
	}
	rows, err := pool.Query(ctx,
		`select epoch_id, first_sequence, last_sequence, root_hash, prev_epoch_root,
		        signature, key_id, sealed_at
		   from audit_epochs
		  where tenant_id = $1 and stream_id = $2
		  order by first_sequence`,
		tenantID, streamID)
	if err != nil {
		return report, fmt.Errorf("load epochs: %w", err)
	}
	var epochs []epochRow
	for rows.Next() {
		var er epochRow
		var sealedAt time.Time
		if err := rows.Scan(&er.epoch.EpochID, &er.epoch.FirstSequence, &er.epoch.LastSequence,
			&er.epoch.RootHash, &er.epoch.PrevEpochRoot, &er.signature, &er.keyID, &sealedAt); err != nil {
			rows.Close()
			return report, fmt.Errorf("scan epoch: %w", err)
		}
		er.epoch.TenantID = tenantID
		er.epoch.StreamID = streamID
		er.epoch.SealedAt = sealedAt
		epochs = append(epochs, er)
	}
	rows.Close()
	if rows.Err() != nil {
		return report, fmt.Errorf("load epochs: %w", rows.Err())
	}
	report.Epochs = len(epochs)

	hash := auditenc.GenesisHash
	var prevRoot []byte
	var prevLastSeq uint64
	for _, er := range epochs {
		e := er.epoch
		if e.FirstSequence != prevLastSeq+1 {
			problem("epoch %s: first_sequence %d, want %d (gap or overlap)",
				e.EpochID, e.FirstSequence, prevLastSeq+1)
		}
		if !bytes.Equal(e.PrevEpochRoot, prevRoot) {
			problem("epoch %s: prev_epoch_root does not link to the previous epoch", e.EpochID)
		}

		message, err := auditenc.EncodeEpoch(e)
		if err != nil {
			return report, fmt.Errorf("encode epoch %s: %w", e.EpochID, err)
		}
		pub, ok := publicKeys[er.keyID]
		if !ok {
			problem("epoch %s: unknown signing key %q", e.EpochID, er.keyID)
		} else if !ed25519.Verify(pub, message, er.signature) {
			problem("epoch %s: signature does not verify", e.EpochID)
		}

		evRows, err := pool.Query(ctx,
			`select id, action_request_id, event_type, attested_by, metadata::text,
			        recorded_at, sequence_number, previous_hash, event_hash
			   from audit_events
			  where tenant_id = $1 and stream_id = $2 and epoch_id = $3
			  order by sequence_number`,
			tenantID, streamID, e.EpochID)
		if err != nil {
			return report, fmt.Errorf("load epoch %s events: %w", e.EpochID, err)
		}
		expectSeq := e.FirstSequence
		for evRows.Next() {
			var id uuid.UUID
			var actionRequestID *uuid.UUID
			var eventType, attestedBy string
			var metadataText []byte
			var recordedAt time.Time
			var seq uint64
			var storedPrev, storedHash []byte
			if err := evRows.Scan(&id, &actionRequestID, &eventType, &attestedBy,
				&metadataText, &recordedAt, &seq, &storedPrev, &storedHash); err != nil {
				evRows.Close()
				return report, fmt.Errorf("scan event: %w", err)
			}
			if seq != expectSeq {
				problem("event %s: sequence %d, want %d", id, seq, expectSeq)
			}
			expectSeq++
			if !bytes.Equal(storedPrev, hash) {
				problem("event %s (seq %d): previous_hash does not match the chain", id, seq)
			}
			actionRef := ""
			if actionRequestID != nil {
				actionRef = actionRequestID.String()
			}
			derived, err := auditenc.ChainHash(hash, auditenc.Event{
				ID: id, TenantID: tenantID, StreamID: streamID,
				SequenceNumber: seq, Type: eventType, AttestedBy: attestedBy,
				ActionRequestID: actionRef, MetadataJCS: metadataText, RecordedAt: recordedAt,
			})
			if err != nil {
				evRows.Close()
				return report, fmt.Errorf("re-derive event %s: %w", id, err)
			}
			if !bytes.Equal(derived, storedHash) {
				problem("event %s (seq %d): content does not match its recorded hash — tampered or corrupted", id, seq)
			}
			hash = storedHash
			report.EventsSealed++
		}
		evRows.Close()
		if evRows.Err() != nil {
			return report, fmt.Errorf("load epoch %s events: %w", e.EpochID, evRows.Err())
		}
		if expectSeq != e.LastSequence+1 {
			problem("epoch %s: contains events up to %d, header claims %d",
				e.EpochID, expectSeq-1, e.LastSequence)
		}
		if !bytes.Equal(hash, e.RootHash) {
			problem("epoch %s: re-derived root does not match the signed root", e.EpochID)
		}
		prevRoot = e.RootHash
		prevLastSeq = e.LastSequence
	}

	if err := pool.QueryRow(ctx,
		`select count(*) from audit_events
		  where tenant_id = $1 and stream_id = $2 and epoch_id is null`,
		tenantID, streamID).Scan(&report.UnsealedTail); err != nil {
		return report, fmt.Errorf("count unsealed tail: %w", err)
	}
	return report, nil
}
