package fingerprint

import (
	"testing"

	"github.com/google/uuid"
)

func TestDerivations(t *testing.T) {
	tenant := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	session := uuid.MustParse("22222222-2222-2222-2222-222222222222")

	k1 := IdempotencyKey(tenant, session, "req-1")
	k2 := IdempotencyKey(tenant, session, "req-1")
	if string(k1) != string(k2) {
		t.Fatal("idempotency key is not deterministic")
	}
	if string(IdempotencyKey(tenant, uuid.New(), "req-1")) == string(k1) {
		t.Fatal("session does not affect the key — cross-session collision (plan §8)")
	}
	if string(IdempotencyKey(tenant, session, "req-2")) == string(k1) {
		t.Fatal("native request id does not affect the key")
	}

	f1, err := Fingerprint("agent", "bash", []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	f2, err := Fingerprint("agent", "bash", []byte(`{"a":2}`))
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if string(f1) == string(f2) {
		t.Fatal("params do not affect the fingerprint")
	}
	// "ab"+"c" vs "a"+"bc": length prefixes must keep field boundaries
	// unambiguous.
	fa, _ := Fingerprint("ab", "c", []byte(`{}`))
	fb, _ := Fingerprint("a", "bc", []byte(`{}`))
	if string(fa) == string(fb) {
		t.Fatal("fingerprint field boundary ambiguity")
	}
	// The derivation is frozen: if the output ever changes, existing keys in
	// customer databases break.
	if len(f1) != 32 || len(k1) != 32 {
		t.Fatal("derivation output is not SHA-256 sized")
	}
}
