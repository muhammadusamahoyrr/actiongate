package grant

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	actiongatev1 "actiongate/gen/actiongate/v1"
)

func issue(t *testing.T) ([]byte, map[string]ed25519.PublicKey, IssueInput) {
	t.Helper()
	signer, pub, err := NewSigner("hot-1")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	in := IssueInput{
		GrantID:    uuid.New(),
		ActionID:   uuid.New(),
		TenantID:   uuid.New(),
		ToolName:   "bash",
		ParamsHash: []byte("fingerprint-32-bytes-goes-here!!"),
		ExpiresAt:  time.Now().Add(time.Minute),
	}
	envelope, err := signer.Issue(in)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return envelope, map[string]ed25519.PublicKey{"hot-1": pub}, in
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	envelope, keys, in := issue(t)
	g, err := Verify(envelope, keys, time.Now())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if g.GetGrantId() != in.GrantID.String() || g.GetToolName() != "bash" ||
		string(g.GetParamsHash()) != string(in.ParamsHash) {
		t.Fatalf("grant fields mangled: %+v", g)
	}
}

func TestTamperedGrantBytesRejected(t *testing.T) {
	envelope, keys, _ := issue(t)
	var env actiongatev1.GrantEnvelope
	if err := proto.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var g actiongatev1.ExecutionGrant
	if err := proto.Unmarshal(env.GetGrantBytes(), &g); err != nil {
		t.Fatalf("unmarshal grant: %v", err)
	}
	g.ToolName = "rm" // privilege escalation attempt
	swapped, err := proto.Marshal(&g)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	env.GrantBytes = swapped
	forged, err := proto.Marshal(&env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if _, err := Verify(forged, keys, time.Now()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	envelope, _, _ := issue(t)
	_, otherPub, _ := NewSigner("other")
	keys := map[string]ed25519.PublicKey{"other": otherPub}
	if _, err := Verify(envelope, keys, time.Now()); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("want ErrUnknownKey, got %v", err)
	}
}

func TestExpiredGrantRejected(t *testing.T) {
	envelope, keys, in := issue(t)
	if _, err := Verify(envelope, keys, in.ExpiresAt.Add(time.Second)); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}
