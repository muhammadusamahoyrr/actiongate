package seal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// Signer is the cold-path epoch signing interface (plan §20.1): implemented
// by direct KMS Sign in production so the application and DB roles never
// hold the key that vouches for history. Signing happens outside any
// database transaction — KMS latency must never sit inside one (§20.2.1).
type Signer interface {
	KeyID() string
	Sign(ctx context.Context, message []byte) ([]byte, error)
}

// Ed25519Signer holds the key in process memory — the development and test
// implementation. Production epochs use a KMS-backed Signer.
type Ed25519Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

func NewEd25519Signer(keyID string) (*Ed25519Signer, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	return &Ed25519Signer{keyID: keyID, priv: priv}, pub, nil
}

// NewEd25519SignerFromSeed derives the epoch key from a 32-byte seed so
// epochs stay verifiable across restarts (production uses direct KMS Sign
// behind the same interface instead).
func NewEd25519SignerFromSeed(keyID string, seed []byte) (*Ed25519Signer, ed25519.PublicKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Ed25519Signer{keyID: keyID, priv: priv}, priv.Public().(ed25519.PublicKey), nil
}

func (s *Ed25519Signer) KeyID() string { return s.keyID }

func (s *Ed25519Signer) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, message), nil
}
