package seal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/auditenc"
	"github.com/muhammadusamahoyrr/actiongate/internal/domain"
	"github.com/muhammadusamahoyrr/actiongate/internal/fingerprint"
)

// Report is the outcome of an independent chain verification. OK means every
// epoch's signature verified, every hash re-derived identically, and the
// sequence is contiguous with no gaps. UnsealedTail is informational — a
// bounded tail is normal, a growing one is the §20.3 SLO alert.
type Report struct {
	Epochs       int
	EventsSealed int
	UnsealedTail int
	// RequestsChecked counts sealed ActionCreated events whose recorded
	// request fingerprint was re-derived from the stored request (audit
	// H7). Events written before the fingerprint was recorded are skipped.
	RequestsChecked int
	// Head is the last sealed epoch, nil when nothing is sealed yet. Saved
	// somewhere the database cannot reach (verify -checkpoint), it lets a
	// later run detect a chain cut back below it (audit H8).
	Head     *Head
	Problems []string

	heads map[uint64]string // last_sequence -> root hash (hex) of every epoch
}

// Head identifies one point of a sealed chain: an epoch's last sequence
// and its signed root hash.
type Head struct {
	LastSequence uint64 `json:"last_sequence"`
	RootHash     string `json:"root_hash"` // hex
}

// Contains reports whether the verified chain still has an epoch ending at
// h with the same root, that is, whether h is still part of its history.
func (r Report) Contains(h Head) bool {
	root, ok := r.heads[h.LastSequence]
	return ok && root == h.RootHash
}

func (r Report) OK() bool { return len(r.Problems) == 0 }

// Verify re-derives a stream's chain from the stored events — exactly what a
// skeptic would do from an export. It trusts nothing but the public keys:
// sequence contiguity, per-event hashes, epoch roots, epoch linkage, and
// signatures are all recomputed.
func Verify(ctx context.Context, pool *pgxpool.Pool, tenantID, streamID uuid.UUID, publicKeys map[string]ed25519.PublicKey) (Report, error) {
	report := Report{heads: map[uint64]string{}}
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
		root := hex.EncodeToString(e.RootHash)
		report.heads[e.LastSequence] = root
		report.Head = &Head{LastSequence: e.LastSequence, RootHash: root}
	}

	// Audit H8: an event that was sealed points at its epoch. If that epoch
	// row is gone, epochs were deleted to cut the chain back.
	var orphaned int
	if err := pool.QueryRow(ctx,
		`select count(*) from audit_events e
		  where e.tenant_id = $1 and e.stream_id = $2 and e.epoch_id is not null
		    and not exists (select 1 from audit_epochs p
		                     where p.epoch_id = e.epoch_id and p.tenant_id = $1 and p.stream_id = $2)`,
		tenantID, streamID).Scan(&orphaned); err != nil {
		return report, fmt.Errorf("count orphaned events: %w", err)
	}
	if orphaned > 0 {
		problem("%d sealed events belong to no epoch: epochs were deleted (chain truncated)", orphaned)
	}

	if err := verifyRequests(ctx, pool, tenantID, streamID, &report, problem); err != nil {
		return report, err
	}

	if err := pool.QueryRow(ctx,
		`select count(*) from audit_events
		  where tenant_id = $1 and stream_id = $2 and epoch_id is null`,
		tenantID, streamID).Scan(&report.UnsealedTail); err != nil {
		return report, fmt.Errorf("count unsealed tail: %w", err)
	}
	return report, nil
}

// verifyRequests re-derives each sealed ActionCreated event's request
// fingerprint from the stored action request (audit H7). The event's
// metadata is covered by the chain, so a stored request whose agent, tool
// or params were changed after the fact no longer matches it.
func verifyRequests(ctx context.Context, pool *pgxpool.Pool, tenantID, streamID uuid.UUID, report *Report, problem func(string, ...any)) error {
	rows, err := pool.Query(ctx,
		`select e.id, e.metadata->>'request_fingerprint', a.id, a.agent_id, a.tool_name,
		        a.tool_params::text, a.request_fingerprint
		   from audit_events e
		   left join action_requests a on a.id = e.action_request_id
		  where e.tenant_id = $1 and e.stream_id = $2 and e.event_type = $3
		    and e.epoch_id is not null
		    and e.metadata->>'request_fingerprint' is not null`,
		tenantID, streamID, string(domain.EventActionCreated))
	if err != nil {
		return fmt.Errorf("load action requests: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var eventID uuid.UUID
		var sealedHex string
		var actionID *uuid.UUID
		var agentID, toolName, params *string
		var storedFP []byte
		if err := rows.Scan(&eventID, &sealedHex, &actionID, &agentID, &toolName, &params, &storedFP); err != nil {
			return fmt.Errorf("scan action request: %w", err)
		}
		report.RequestsChecked++
		if actionID == nil {
			problem("event %s: its action request is missing", eventID)
			continue
		}
		canonical, err := canonicalJSON([]byte(*params))
		if err != nil {
			problem("action %s: stored params are not valid JSON: %v", *actionID, err)
			continue
		}
		derived, err := fingerprint.Fingerprint(*agentID, *toolName, canonical)
		if err != nil {
			return err
		}
		if hex.EncodeToString(derived) != sealedHex {
			problem("action %s: stored request does not match its sealed fingerprint (agent, tool or params changed)", *actionID)
		} else if !bytes.Equal(derived, storedFP) {
			problem("action %s: request_fingerprint column does not match the request", *actionID)
		}
	}
	return rows.Err()
}

// canonicalJSON re-encodes params the way the control plane did before
// fingerprinting: decoded into Go values (numbers as float64) and
// re-marshalled with sorted keys.
func canonicalJSON(raw []byte) ([]byte, error) {
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	if v == nil {
		v = map[string]any{}
	}
	return json.Marshal(v)
}
