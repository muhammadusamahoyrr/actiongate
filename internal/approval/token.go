package approval

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Callback tokens (plan §9, round 4): HMAC-signed, single-use, expiring, and
// opaque — the approval_request_id is never embedded; the database maps
// token→request. Only the SHA-256 of the token is stored; the raw token
// exists in the delivered notification (and transiently in the queued
// delivery job — a documented V1 limitation).
//
// Format: "agt1_" + base64url(tenant_id[16] || random[32]) + "." +
// base64url(HMAC-SHA256(secret, "AGTOK1" || payload)). The tenant id rides
// inside the signed payload so Resolve can scope its lookup under RLS
// without a cross-tenant read.

var ErrTokenInvalid = errors.New("callback token invalid")

const tokenPrefix = "agt1_"

func mintToken(secret []byte, tenantID uuid.UUID) (token string, tokenHash []byte, err error) {
	payload := make([]byte, 16+32)
	copy(payload, tenantID[:])
	if _, err := rand.Read(payload[16:]); err != nil {
		return "", nil, fmt.Errorf("token randomness: %w", err)
	}
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
