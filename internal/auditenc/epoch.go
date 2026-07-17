package auditenc

import (
	"time"

	"github.com/google/uuid"
)

// Epoch is the sealed-epoch summary whose encoding is signed (plan §20.1:
// epoch roots are the cold-path, KMS-signed integrity anchor). Layout
// (version 1), fixed order, fixed-width fields raw, variable fields
// length-prefixed:
//
//	"AGEPOCH1" | epoch_id | tenant_id | stream_id |
//	first_sequence(8B) | last_sequence(8B) | root_hash | prev_epoch_root
//	("" for the first epoch) | sealed_at (unix micros, 8B)
type Epoch struct {
	EpochID       uuid.UUID
	TenantID      uuid.UUID
	StreamID      uuid.UUID
	FirstSequence uint64
	LastSequence  uint64
	RootHash      []byte
	PrevEpochRoot []byte // nil for the first epoch of a stream
	SealedAt      time.Time
}

const epochMagic = "AGEPOCH1"

func EncodeEpoch(e Epoch) ([]byte, error) {
	buf := make([]byte, 0, 192)
	buf = append(buf, epochMagic...)
	var err error
	if buf, err = appendField(buf, e.EpochID[:]); err != nil {
		return nil, err
	}
	if buf, err = appendField(buf, e.TenantID[:]); err != nil {
		return nil, err
	}
	if buf, err = appendField(buf, e.StreamID[:]); err != nil {
		return nil, err
	}
	buf = appendUint64(buf, e.FirstSequence)
	buf = appendUint64(buf, e.LastSequence)
	if buf, err = appendField(buf, e.RootHash); err != nil {
		return nil, err
	}
	if buf, err = appendField(buf, e.PrevEpochRoot); err != nil {
		return nil, err
	}
	sealedAt := e.SealedAt.UTC().UnixMicro()
	if sealedAt < 0 {
		return nil, ErrPreEpochTimestamp
	}
	buf = appendUint64(buf, uint64(sealedAt))
	return buf, nil
}
