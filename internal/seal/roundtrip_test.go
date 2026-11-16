package seal

import (
	"context"
	"math"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/muhammadusamahoyrr/actiongate/internal/fingerprint"
)

// The request fingerprint is computed at intake from the params as the
// server encodes them, and re-derived by verify from what Postgres jsonb
// hands back. Any value whose encoding does not survive that round trip
// makes verify report a genuine request as tampered (negative zero was
// one). Rather than list edge cases by hand, this pushes thousands of
// generated params through real Postgres and requires byte equality.
func TestFingerprintSurvivesJSONBRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	pool := startEmbeddedPool(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `create table rt (id int primary key, p jsonb not null)`); err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(20261116)) //nolint:gosec // deterministic test data
	const cases = 3000
	intake := make([][]byte, cases)
	for i := range intake {
		// What the server does: the wire Struct, AsMap, then canonical.
		st, err := structpb.NewStruct(genObject(rng, 0))
		if err != nil {
			t.Fatalf("case %d: struct: %v", i, err)
		}
		if intake[i], err = fingerprint.CanonicalParams(st.AsMap()); err != nil {
			t.Fatalf("case %d: canonical: %v", i, err)
		}
		if _, err := pool.Exec(ctx, `insert into rt (id, p) values ($1, $2)`, i, intake[i]); err != nil {
			t.Fatalf("case %d: insert %s: %v", i, intake[i], err)
		}
	}

	rows, err := pool.Query(ctx, `select id, p::text from rt order by id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	mismatches := 0
	for rows.Next() {
		var id int
		var stored string
		if err := rows.Scan(&id, &stored); err != nil {
			t.Fatal(err)
		}
		got, err := canonicalJSON([]byte(stored)) // what verify does
		if err != nil {
			t.Fatalf("case %d: re-canonicalize %s: %v", id, stored, err)
		}
		if string(got) != string(intake[id]) {
			mismatches++
			if mismatches <= 5 {
				t.Errorf("case %d: intake %s\n  stored %s\n  verify %s", id, intake[id], stored, got)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if mismatches > 0 {
		t.Fatalf("%d of %d params do not survive the jsonb round trip", mismatches, cases)
	}
}

func genObject(rng *rand.Rand, depth int) map[string]any {
	m := map[string]any{}
	for n := rng.Intn(5) + 1; n > 0; n-- {
		m[genString(rng)] = genValue(rng, depth+1)
	}
	return m
}

func genValue(rng *rand.Rand, depth int) any {
	kinds := 6
	if depth > 3 {
		kinds = 4 // no deeper containers
	}
	switch rng.Intn(kinds) {
	case 0:
		return genString(rng)
	case 1:
		return genNumber(rng)
	case 2:
		return rng.Intn(2) == 0
	case 3:
		return nil
	case 4:
		list := make([]any, rng.Intn(4))
		for i := range list {
			list[i] = genValue(rng, depth+1)
		}
		return list
	default:
		return genObject(rng, depth)
	}
}

// genNumber favours the values encoders disagree on.
func genNumber(rng *rand.Rand) float64 {
	special := []float64{
		0, math.Copysign(0, -1), 1, -1, 0.1, 1e21, 1e-7, 1e-6, 1e20, 123456789012345678,
		math.MaxFloat64, math.SmallestNonzeroFloat64, -math.MaxFloat64, 9007199254740993,
		math.Nextafter(1, 2), 5e-324, 1.7976931348623157e308, 100, 1e300, -1e-300,
	}
	switch rng.Intn(3) {
	case 0:
		return special[rng.Intn(len(special))]
	case 1:
		return float64(rng.Int63n(1<<62)) * float64(1-2*rng.Intn(2))
	default:
		return math.Float64frombits(rng.Uint64()&^(0x7ff<<52) | uint64(rng.Intn(0x7fe)+1)<<52) // finite
	}
}

// genString mixes ASCII, escapes JSON must handle, and non-ASCII runes.
// NUL is left out: Postgres jsonb cannot store U+0000 at all (see
// TestJSONBRejectsNUL).
func genString(rng *rand.Rand) string {
	pool := []string{
		"a", "Z", "0", " ", "\"", "\\", "/", "<", ">", "&", "\t", "\n", "\r", "\x01", "\x1f", "\x7f",
		string(rune(0xe9)), string(rune(0xdf)), string(rune(0x4e2d)), string(rune(0x1f600)),
		string(rune(0x2028)), string(rune(0x2029)), string(rune(0xfeff)), string(rune(0xfffd)),
		string(rune(0x10ffff)), "rm -rf ~", "$HOME",
	}
	var b strings.Builder
	for n := rng.Intn(8); n > 0; n-- {
		b.WriteString(pool[rng.Intn(len(pool))])
	}
	if !utf8.ValidString(b.String()) {
		panic("generated invalid UTF-8")
	}
	return b.String()
}

// Records a limit rather than a bug in the fingerprint: jsonb refuses
// U+0000, so a tool call whose params contain a NUL character cannot be
// stored and fails closed (the action is refused, never run unchecked).
func TestJSONBRejectsNUL(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	pool := startEmbeddedPool(t)
	params, err := fingerprint.CanonicalParams(map[string]any{"content": "a\x00b"})
	if err != nil {
		t.Fatal(err)
	}
	var out string
	err = pool.QueryRow(context.Background(), `select $1::jsonb::text`, params).Scan(&out)
	if err == nil {
		t.Fatalf("jsonb stored a NUL (%s); the fail-closed note above is stale", out)
	}
}
