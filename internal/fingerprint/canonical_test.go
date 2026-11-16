package fingerprint

import (
	"encoding/json"
	"math"
	"testing"
)

// Negative zero must encode as 0 wherever it sits: jsonb stores it as 0,
// and verify re-derives the fingerprint from what jsonb returns.
func TestCanonicalParamsDropsNegativeZero(t *testing.T) {
	negZero := math.Copysign(0, -1)
	intake, err := CanonicalParams(map[string]any{
		"n": negZero, "list": []any{negZero, 1.5}, "obj": map[string]any{"z": negZero},
	})
	if err != nil {
		t.Fatal(err)
	}
	// What verify sees: the same params after a jsonb round trip.
	var stored map[string]any
	if err := json.Unmarshal([]byte(`{"list": [0, 1.5], "n": 0, "obj": {"z": 0}}`), &stored); err != nil {
		t.Fatal(err)
	}
	readBack, err := CanonicalParams(stored)
	if err != nil {
		t.Fatal(err)
	}
	if string(intake) != string(readBack) {
		t.Errorf("intake %s != read back %s", intake, readBack)
	}
}

// Every value other than negative zero encodes exactly as encoding/json
// always did, so existing fingerprints, grants and idempotency keys keep
// matching.
func TestCanonicalParamsUnchangedOtherwise(t *testing.T) {
	params := map[string]any{
		"command": "rm -rf ./build <&>", "n": 1e21, "small": 1e-7, "zero": 0.0,
		"neg": -2.5, "list": []any{"a", true, nil}, "obj": map[string]any{"b": 1.0, "a": "x "},
	}
	want, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CanonicalParams(params)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("CanonicalParams = %s, want %s", got, want)
	}
	if empty, _ := CanonicalParams(nil); string(empty) != "{}" {
		t.Errorf("nil params = %s, want {}", empty)
	}
}
