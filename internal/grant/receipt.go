package grant

import (
	"crypto/ed25519"
	"fmt"

	"google.golang.org/protobuf/proto"

	actiongatev1 "github.com/muhammadusamahoyrr/actiongate/gen/actiongate/v1"
)

// Receipts are the gateway-signed half of the protocol: outcome facts the
// control plane records as gateway-attested (plan §5). Same signing rule as
// grants — the signature covers the exact serialized receipt bytes, and
// verifiers check the signature before parsing.

// SignReceipt serializes and signs a receipt with the gateway's key,
// returning the marshaled ReceiptEnvelope. Used by the gateway binary and
// by tests standing in for one.
func SignReceipt(priv ed25519.PrivateKey, keyID string, receipt *actiongatev1.OutcomeReceipt) ([]byte, error) {
	receiptBytes, err := proto.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("marshal receipt: %w", err)
	}
	envelope, err := proto.Marshal(&actiongatev1.ReceiptEnvelope{
		ReceiptBytes: receiptBytes,
		Signature:    ed25519.Sign(priv, receiptBytes),
		KeyId:        keyID,
		Algorithm:    Algorithm,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return envelope, nil
}

// VerifyReceipt authenticates a serialized ReceiptEnvelope against the
// enrolled gateway's public key.
func VerifyReceipt(envelopeBytes []byte, pub ed25519.PublicKey) (*actiongatev1.OutcomeReceipt, error) {
	var envelope actiongatev1.ReceiptEnvelope
	if err := proto.Unmarshal(envelopeBytes, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}
	if envelope.GetAlgorithm() != Algorithm {
		return nil, fmt.Errorf("%w: algorithm %q", ErrBadSignature, envelope.GetAlgorithm())
	}
	if !ed25519.Verify(pub, envelope.GetReceiptBytes(), envelope.GetSignature()) {
		return nil, ErrBadSignature
	}
	var receipt actiongatev1.OutcomeReceipt
	if err := proto.Unmarshal(envelope.GetReceiptBytes(), &receipt); err != nil {
		return nil, fmt.Errorf("unmarshal receipt: %w", err)
	}
	return &receipt, nil
}
