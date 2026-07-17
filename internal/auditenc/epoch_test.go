package auditenc

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func sampleEpoch() Epoch {
	return Epoch{
		EpochID:       uuid.MustParse("01912345-6789-7abc-8def-0123456789ab"),
		TenantID:      uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		StreamID:      uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		FirstSequence: 1,
		LastSequence:  5,
		RootHash:      bytes.Repeat([]byte{0xab}, sha256.Size),
		PrevEpochRoot: nil,
		SealedAt:      time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
	}
}

func TestEncodeEpochIsDeterministic(t *testing.T) {
	a, err := EncodeEpoch(sampleEpoch())
	if err != nil {
		t.Fatalf("EncodeEpoch: %v", err)
	}
	b, err := EncodeEpoch(sampleEpoch())
	if err != nil {
		t.Fatalf("EncodeEpoch: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("identical epochs encoded to different bytes")
	}
	if !bytes.HasPrefix(a, []byte("AGEPOCH1")) {
		t.Fatal("encoding does not start with the epoch magic")
	}
}

func TestEveryEpochFieldAffectsTheEncoding(t *testing.T) {
	base, err := EncodeEpoch(sampleEpoch())
	if err != nil {
		t.Fatalf("EncodeEpoch: %v", err)
	}
	mutations := map[string]func(*Epoch){
		"epoch_id":        func(e *Epoch) { e.EpochID = uuid.New() },
		"tenant":          func(e *Epoch) { e.TenantID = uuid.New() },
		"stream":          func(e *Epoch) { e.StreamID = uuid.New() },
		"first_sequence":  func(e *Epoch) { e.FirstSequence++ },
		"last_sequence":   func(e *Epoch) { e.LastSequence++ },
		"root_hash":       func(e *Epoch) { e.RootHash = bytes.Repeat([]byte{0xcd}, sha256.Size) },
		"prev_epoch_root": func(e *Epoch) { e.PrevEpochRoot = bytes.Repeat([]byte{0xef}, sha256.Size) },
		"sealed_at":       func(e *Epoch) { e.SealedAt = e.SealedAt.Add(time.Microsecond) },
	}
	for name, mutate := range mutations {
		e := sampleEpoch()
		mutate(&e)
		got, err := EncodeEpoch(e)
		if err != nil {
			t.Fatalf("EncodeEpoch(%s): %v", name, err)
		}
		if bytes.Equal(got, base) {
			t.Fatalf("mutating %q did not change the encoding — signature would not cover it", name)
		}
	}
}

func TestEncodeEpochRejectsPreEpochSealedAt(t *testing.T) {
	e := sampleEpoch()
	e.SealedAt = time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := EncodeEpoch(e); !errors.Is(err, ErrPreEpochTimestamp) {
		t.Fatalf("want ErrPreEpochTimestamp, got %v", err)
	}
}
