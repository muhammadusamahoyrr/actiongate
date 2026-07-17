package auditenc

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
)

func sampleEvent() Event {
	return Event{
		ID:              uuid.MustParse("01912345-6789-7abc-8def-0123456789ab"),
		TenantID:        uuid.MustParse("11111111-1111-1111-1111-111111111111"),
		StreamID:        uuid.MustParse("22222222-2222-2222-2222-222222222222"),
		SequenceNumber:  42,
		Type:            "PolicyEvaluated",
		AttestedBy:      "control_plane",
		ActionRequestID: "33333333-3333-3333-3333-333333333333",
		MetadataJCS:     []byte(`{"decision":"allow"}`),
		RecordedAt:      time.Date(2026, 7, 17, 12, 0, 0, 123456000, time.UTC),
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	a, err := Encode(sampleEvent())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	b, err := Encode(sampleEvent())
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("identical events encoded to different bytes")
	}
	if !bytes.HasPrefix(a, []byte("AGCHAIN1")) {
		t.Fatal("encoding does not start with the version magic")
	}
}

func TestEncodeIsTimezoneIndependent(t *testing.T) {
	e1 := sampleEvent()
	e2 := sampleEvent()
	e2.RecordedAt = e2.RecordedAt.In(time.FixedZone("PKT", 5*3600))
	a, err := Encode(e1)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	b, err := Encode(e2)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same instant in different zones encoded differently")
	}
}

func TestEveryFieldAffectsTheHash(t *testing.T) {
	base, err := ChainHash(GenesisHash, sampleEvent())
	if err != nil {
		t.Fatalf("ChainHash: %v", err)
	}
	mutations := map[string]func(*Event){
		"id":            func(e *Event) { e.ID = uuid.New() },
		"tenant":        func(e *Event) { e.TenantID = uuid.New() },
		"stream":        func(e *Event) { e.StreamID = uuid.New() },
		"sequence":      func(e *Event) { e.SequenceNumber++ },
		"type":          func(e *Event) { e.Type = "Tampered" },
		"attested_by":   func(e *Event) { e.AttestedBy = "attacker" },
		"action_ref":    func(e *Event) { e.ActionRequestID = "" },
		"metadata":      func(e *Event) { e.MetadataJCS = []byte(`{"decision":"deny"}`) },
		"recorded_at":   func(e *Event) { e.RecordedAt = e.RecordedAt.Add(time.Microsecond) },
		"previous_hash": nil,
	}
	for name, mutate := range mutations {
		e := sampleEvent()
		prev := GenesisHash
		if mutate == nil {
			prev = bytes.Repeat([]byte{0xff}, sha256.Size)
		} else {
			mutate(&e)
		}
		h, err := ChainHash(prev, e)
		if err != nil {
			t.Fatalf("ChainHash(%s): %v", name, err)
		}
		if bytes.Equal(h, base) {
			t.Fatalf("mutating %q did not change the chain hash", name)
		}
	}
}

func TestFieldBoundariesCannotBeConfused(t *testing.T) {
	// "ab" + "c" must not hash like "a" + "bc" — the length prefixes must
	// make field boundaries unambiguous.
	e1 := sampleEvent()
	e1.Type = "ab"
	e1.AttestedBy = "c"
	e2 := sampleEvent()
	e2.Type = "a"
	e2.AttestedBy = "bc"
	a, err := Encode(e1)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	b, err := Encode(e2)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("field boundary ambiguity: shifted content encoded identically")
	}
}

func TestChainLinksEvents(t *testing.T) {
	first := sampleEvent()
	second := sampleEvent()
	second.SequenceNumber = 43
	h1, err := ChainHash(GenesisHash, first)
	if err != nil {
		t.Fatalf("ChainHash: %v", err)
	}
	h2, err := ChainHash(h1, second)
	if err != nil {
		t.Fatalf("ChainHash: %v", err)
	}
	// Re-derive independently, as a verifier would.
	v1, _ := ChainHash(GenesisHash, first)
	v2, _ := ChainHash(v1, second)
	if !bytes.Equal(h2, v2) {
		t.Fatal("verifier re-derivation diverged from sealer chain")
	}
}

func TestRejectsPreEpochTimestamp(t *testing.T) {
	e := sampleEvent()
	e.RecordedAt = time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := Encode(e); err == nil {
		t.Fatal("pre-epoch timestamp must be rejected, not silently encoded")
	}
}
