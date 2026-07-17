// Package fingerprint holds the request identity derivations (plan §8),
// shared verbatim by the control plane (intake) and the gateway (grant
// params_hash verification). The derivations are frozen: changing the
// output breaks every key in customer databases and every outstanding
// grant.
package fingerprint

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"math"

	"github.com/google/uuid"
)

// ErrFieldTooLarge: a fingerprint input exceeded the uint32 length prefix.
// The wire protocol bounds inputs far below this; hitting it means upstream
// corruption, and hashing truncated content would be a collision vector —
// refuse instead.
var ErrFieldTooLarge = errors.New("fingerprint field exceeds 4GiB encoding limit")

// IdempotencyKey derives the layer-1 dedup identity. session_id is scoped by
// the authenticated gateway; the client-supplied native request ID is never
// used alone. Tenant and session are fixed-width, so only the trailing
// variable field needs no delimiter.
func IdempotencyKey(tenantID, sessionID uuid.UUID, nativeRequestID string) []byte {
	h := sha256.New()
	h.Write([]byte("AGKEY1"))
	h.Write(tenantID[:])
	h.Write(sessionID[:])
	h.Write([]byte(nativeRequestID))
	return h.Sum(nil)
}

// Fingerprint derives the layer-2 content identity over canonical params
// bytes. Canonicalization is the caller's job; this function hashes exactly
// what it is given.
func Fingerprint(agentID, toolName string, canonicalParams []byte) ([]byte, error) {
	h := sha256.New()
	h.Write([]byte("AGFPR1"))
	for _, field := range [][]byte{[]byte(agentID), []byte(toolName), canonicalParams} {
		if err := writeLenPrefixed(h, field); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

func writeLenPrefixed(h hash.Hash, field []byte) error {
	n := uint64(len(field))
	if n > math.MaxUint32 {
		return ErrFieldTooLarge
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(n))
	h.Write(lenBuf[:])
	h.Write(field)
	return nil
}
