package approval

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

var testSecret = []byte("test-secret-32-bytes-minimum-ok!")

// Audit C5: the token is derived, so the delivery worker can re-create it
// and nothing has to store it. Derivation must be stable per approval,
// distinct across approvals, tenants and secrets, and still parse.
func TestMintTokenIsDerivedAndUnique(t *testing.T) {
	tenant, approval := uuid.New(), uuid.New()
	a, hashA, err := mintToken(testSecret, tenant, approval)
	if err != nil {
		t.Fatal(err)
	}
	b, hashB, err := mintToken(testSecret, tenant, approval)
	if err != nil || a != b || string(hashA) != string(hashB) {
		t.Fatalf("same approval minted different tokens: %q vs %q (%v)", a, b, err)
	}
	if !strings.HasPrefix(a, tokenPrefix) {
		t.Fatalf("token format: %q", a)
	}
	for name, other := range map[string]func() (string, []byte, error){
		"another approval": func() (string, []byte, error) { return mintToken(testSecret, tenant, uuid.New()) },
		"another tenant":   func() (string, []byte, error) { return mintToken(testSecret, uuid.New(), approval) },
		"another secret": func() (string, []byte, error) {
			return mintToken([]byte("another-secret-32-bytes-long-ok!"), tenant, approval)
		},
	} {
		if c, _, err := other(); err != nil || c == a {
			t.Errorf("%s: token %q equals the original (err %v)", name, c, err)
		}
	}

	gotTenant, gotHash, err := parseToken(testSecret, a)
	if err != nil || gotTenant != tenant || string(gotHash) != string(hashA) {
		t.Fatalf("parseToken = %s, %v; want %s", gotTenant, err, tenant)
	}
	// A different secret cannot validate it (so DB read access alone,
	// without the token secret, yields nothing usable).
	if _, _, err := parseToken([]byte("another-secret-32-bytes-long-ok!"), a); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("token validated under another secret: %v", err)
	}
}

func TestMintTokenRejectsBadInput(t *testing.T) {
	if _, _, err := mintToken([]byte("short"), uuid.New(), uuid.New()); err == nil {
		t.Error("short secret accepted")
	}
	if _, _, err := mintToken(testSecret, uuid.New(), uuid.Nil); err == nil {
		t.Error("nil approval id accepted")
	}
}
