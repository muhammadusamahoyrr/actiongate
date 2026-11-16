package approval

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/google/uuid"
)

// Callback tokens (plan §9, round 4): HMAC-signed, single-use, expiring, and
// opaque — the approval_request_id is never embedded; the database maps
// token→request. Only the SHA-256 of the token is stored.
//
// The raw token is never stored anywhere (audit C5): it is DERIVED from the
// token secret and the approval request id, so the delivery worker
// re-derives it at send time and the queued job carries ids only. Reading
// the database (approval_callback_tokens, river_job) yields no usable
// token; producing one needs the token secret, exactly as forging one does.
//
// Format: "agt1_" + base64url(tenant_id[16] || seed[32]) + "." +
// base64url(HMAC-SHA256(secret, "AGTOK1" || payload)), with
// seed = HMAC-SHA256(secret, "AGTOKSEED1" || approval_request_id). The
// tenant id rides inside the signed payload so Resolve can scope its
// lookup under RLS without a cross-tenant read.

var ErrTokenInvalid = errors.New("callback token invalid")

const tokenPrefix = "agt1_"

// mintToken derives the callback token for one approval request. It is
// deterministic, so the delivery worker can re-derive it instead of the
// token being stored.
func mintToken(secret []byte, tenantID, approvalID uuid.UUID) (token string, tokenHash []byte, err error) {
	if len(secret) < 32 {
		return "", nil, errors.New("token secret must be at least 32 bytes")
	}
	if approvalID == uuid.Nil {
		return "", nil, errors.New("token: approval request id is required")
	}
	payload := make([]byte, 0, 16+32)
	payload = append(payload, tenantID[:]...)
	seed := hmac.New(sha256.New, secret)
	seed.Write([]byte("AGTOKSEED1"))
	seed.Write(approvalID[:])
	payload = seed.Sum(payload)
	mac := tokenMAC(secret, payload)
	token = tokenPrefix +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// parseToken authenticates the token's HMAC and returns the embedded tenant
// and the storage hash. Forged or mangled tokens are rejected here, before
// any database work.
func parseToken(secret []byte, token string) (tenantID uuid.UUID, tokenHash []byte, err error) {
	rest, ok := strings.CutPrefix(token, tokenPrefix)
	if !ok {
		return uuid.Nil, nil, ErrTokenInvalid
	}
	payloadPart, macPart, ok := strings.Cut(rest, ".")
	if !ok {
		return uuid.Nil, nil, ErrTokenInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadPart)
	if err != nil || len(payload) != 16+32 {
		return uuid.Nil, nil, ErrTokenInvalid
	}
	mac, err := base64.RawURLEncoding.DecodeString(macPart)
	if err != nil {
		return uuid.Nil, nil, ErrTokenInvalid
	}
	if !hmac.Equal(mac, tokenMAC(secret, payload)) {
		return uuid.Nil, nil, ErrTokenInvalid
	}
	copy(tenantID[:], payload[:16])
	sum := sha256.Sum256([]byte(token))
	return tenantID, sum[:], nil
}

func tokenMAC(secret, payload []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("AGTOK1"))
	m.Write(payload)
	return m.Sum(nil)
}
