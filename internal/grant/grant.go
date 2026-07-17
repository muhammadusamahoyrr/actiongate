// Package grant issues and verifies ExecutionGrants (plan §11): the
// hot-path credential. Signing uses an in-process Ed25519 key (sealed at
// rest via KMS envelope in production — never a per-grant KMS call, plan
// §20.1) and covers the exact serialized grant bytes; verifiers check the
// signature FIRST and only then unmarshal. There is deliberately no
// canonicalization step anywhere on this path.
package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	actiongatev1 "github.com/muhammadusamahoyrr/actiongate/gen/actiongate/v1"
)

const (
	Algorithm  = "ed25519"
	DefaultTTL = 60 * time.Second // plan §20.2.4
)

var (
	ErrBadSignature = errors.New("grant signature does not verify")
	ErrUnknownKey   = errors.New("grant signed by unknown key")
	ErrExpired      = errors.New("grant expired")
)

// Signer is the hot-path signer. The private key lives in process memory by
// design; rotation with overlapping validity is handled by key_id.
type Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

func NewSigner(keyID string) (*Signer, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	return &Signer{keyID: keyID, priv: priv}, pub, nil
}

// NewSignerFromSeed derives the key from a 32-byte seed (KMS-unsealed at
// boot in production) so grants stay verifiable across restarts.
func NewSignerFromSeed(keyID string, seed []byte) (*Signer, ed25519.PublicKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Signer{keyID: keyID, priv: priv}, priv.Public().(ed25519.PublicKey), nil
}

func (s *Signer) KeyID() string { return s.keyID }

type IssueInput struct {
	GrantID    uuid.UUID
	ActionID   uuid.UUID
	TenantID   uuid.UUID
	ToolName   string
	ParamsHash []byte // the request_fingerprint (plan §8 layer 2)
	ExpiresAt  time.Time
}

// Issue builds, serializes, and signs a grant, returning the serialized
// GrantEnvelope — the exact bytes to store and transmit.
func (s *Signer) Issue(in IssueInput) ([]byte, error) {
	grantBytes, err := proto.Marshal(&actiongatev1.ExecutionGrant{
		GrantId:    in.GrantID.String(),
		ActionId:   in.ActionID.String(),
		TenantId:   in.TenantID.String(),
		ToolName:   in.ToolName,
		ParamsHash: in.ParamsHash,
		ExpiresAt:  timestamppb.New(in.ExpiresAt.UTC()),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal grant: %w", err)
	}
	envelope, err := proto.Marshal(&actiongatev1.GrantEnvelope{
		GrantBytes: grantBytes,
		Signature:  ed25519.Sign(s.priv, grantBytes),
		KeyId:      s.keyID,
		Algorithm:  Algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return envelope, nil
}

// Verify authenticates a serialized envelope against the pinned public keys
// and returns the grant. Signature first, parse second; expiry is checked
// against the caller's clock (the control plane's clock stays authoritative
// for receipt acceptance).
func Verify(envelopeBytes []byte, keys map[string]ed25519.PublicKey, now time.Time) (*actiongatev1.ExecutionGrant, error) {
	var envelope actiongatev1.GrantEnvelope
	if err := proto.Unmarshal(envelopeBytes, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	pub, ok := keys[envelope.GetKeyId()]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownKey, envelope.GetKeyId())
	}
	if envelope.GetAlgorithm() != Algorithm {
		return nil, fmt.Errorf("%w: algorithm %q", ErrBadSignature, envelope.GetAlgorithm())
	}
	if !ed25519.Verify(pub, envelope.GetGrantBytes(), envelope.GetSignature()) {
		return nil, ErrBadSignature
	}
	var g actiongatev1.ExecutionGrant
	if err := proto.Unmarshal(envelope.GetGrantBytes(), &g); err != nil {
		return nil, fmt.Errorf("unmarshal grant: %w", err)
	}
	if now.After(g.GetExpiresAt().AsTime()) {
		return nil, ErrExpired
	}
	return &g, nil
}
