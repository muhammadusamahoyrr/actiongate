// Package auditenc is the deterministic audit-event encoding and hash chain
// (plan §20.2.3). It is shared by the Sealer and every verifier — including
// cmd/verify and its future WASM build — and doubles as the reference
// implementation of the published chain spec. No JSON canonicalization is
// used anywhere on the chain: fields are encoded in fixed order with
// big-endian uint32 length prefixes.
//
// Layout (version 1), in exactly this order, each variable field
// length-prefixed:
//
//	"AGCHAIN1" | id | tenant_id | stream_id | sequence_number(8B, no prefix) |
//	event_type | attested_by | action_request_id ("" if null) |
//	metadata (JCS bytes as stored) | recorded_at (unix micros, 8B, no prefix)
//
// event_hash = SHA-256(previous_hash || Encode(event)); the first event of a
// stream uses 32 zero bytes as previous_hash. Epoch roots chain over event
// hashes; see the Sealer.
package auditenc

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
)

const magic = "AGCHAIN1"

// ErrFieldTooLarge is returned when a variable-length field exceeds the
// uint32 length prefix. Postgres caps jsonb well below this; hitting it
// means corruption, and the encoder must refuse rather than truncate.
var ErrFieldTooLarge = errors.New("auditenc: field exceeds 4GiB encoding limit")

// ErrPreEpochTimestamp: timestamps before the Unix epoch cannot appear in
// honestly recorded events and are refused rather than wrapped.
var ErrPreEpochTimestamp = errors.New("auditenc: timestamp predates the Unix epoch")

var GenesisHash = make([]byte, sha256.Size)

type Event struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	StreamID uuid.UUID
	// Sealer-assigned, monotonic within (tenant, stream); never negative.
	SequenceNumber  uint64
	Type            string
	AttestedBy      string
	ActionRequestID string // empty when the event has no action reference
	MetadataJCS     []byte
	RecordedAt      time.Time
}

func Encode(e Event) ([]byte, error) {
	buf := make([]byte, 0, 256)
	buf = append(buf, magic...)
	var err error
	if buf, err = appendField(buf, e.ID[:]); err != nil {
		return nil, err
	}
	if buf, err = appendField(buf, e.TenantID[:]); err != nil {
		return nil, err
	}
	if buf, err = appendField(buf, e.StreamID[:]); err != nil {
		return nil, err
	}
	buf = appendUint64(buf, e.SequenceNumber)
	if buf, err = appendField(buf, []byte(e.Type)); err != nil {
		return nil, err
	}
	if buf, err = appendField(buf, []byte(e.AttestedBy)); err != nil {
		return nil, err
	}
	if buf, err = appendField(buf, []byte(e.ActionRequestID)); err != nil {
		return nil, err
	}
	if buf, err = appendField(buf, e.MetadataJCS); err != nil {
		return nil, err
	}
	recordedAt := e.RecordedAt.UTC().UnixMicro()
	if recordedAt < 0 {
		return nil, fmt.Errorf("recorded_at %v: %w", e.RecordedAt, ErrPreEpochTimestamp)
	}
	buf = appendUint64(buf, uint64(recordedAt))
	return buf, nil
}

func ChainHash(previousHash []byte, e Event) ([]byte, error) {
	encoded, err := Encode(e)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(previousHash)
	h.Write(encoded)
	return h.Sum(nil), nil
}

func appendUint64(buf []byte, v uint64) []byte {
	return binary.BigEndian.AppendUint64(buf, v)
}

func appendField(buf, field []byte) ([]byte, error) {
	n := uint64(len(field))
	if n > math.MaxUint32 {
		return nil, ErrFieldTooLarge
	}
	buf = binary.BigEndian.AppendUint32(buf, uint32(n))
	return append(buf, field...), nil
}
