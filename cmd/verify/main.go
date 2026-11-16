// Standalone offline audit-chain verifier (plan §21.3): re-derives every
// hash and signature from stored data using the same internal/auditenc
// package the Sealer uses, trusting nothing but the supplied public keys.
// Also the future WASM build target (plan §22). Exit codes: 0 every stream
// verified, 1 problems found, 2 operational error.
//
//	verify -database-url URL -tenant ID [-stream ID]
//	       -key KEYID=BASE64PUB [-key ...] [-checkpoint FILE]
//
// With -checkpoint, each stream's last sealed epoch is compared with the
// one recorded in FILE by the previous run, and FILE is updated when every
// stream verifies. Keep FILE where the database host cannot write it: it
// is what detects a chain cut back by someone able to delete epochs.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/muhammadusamahoyrr/actiongate/internal/seal"
)

type keyFlags map[string]ed25519.PublicKey

func (k keyFlags) String() string { return fmt.Sprintf("%d keys", len(k)) }

func (k keyFlags) Set(v string) error {
	id, encoded, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("want KEYID=BASE64PUB, got %q", v)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("key %q is not a base64 ed25519 public key", id)
	}
	k[id] = ed25519.PublicKey(raw)
	return nil
}

func main() {
	os.Exit(run())
}

func run() int {
	keys := keyFlags{}
	databaseURL := flag.String("database-url", os.Getenv("AG_DATABASE_URL"), "Postgres URL (or AG_DATABASE_URL)")
	tenantFlag := flag.String("tenant", "", "tenant id (required)")
	streamFlag := flag.String("stream", "", "stream id (default: every stream of the tenant)")
	flag.Var(keys, "key", "epoch signing key as KEYID=BASE64PUB (repeatable)")
	checkpointPath := flag.String("checkpoint", "", "file holding each stream's last verified head; compared, then updated when all streams verify")
	flag.Parse()

	if *databaseURL == "" || *tenantFlag == "" || len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "verify: -database-url, -tenant, and at least one -key are required")
		return 2
	}
	tenantID, err := uuid.Parse(*tenantFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify: -tenant:", err)
		return 2
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, *databaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify: connect:", err)
		return 2
	}
	defer pool.Close()

	var streams []uuid.UUID
	if *streamFlag != "" {
		streamID, err := uuid.Parse(*streamFlag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify: -stream:", err)
			return 2
		}
		streams = []uuid.UUID{streamID}
	} else {
		rows, err := pool.Query(ctx,
			`select distinct stream_id from audit_events where tenant_id = $1`, tenantID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "verify: discover streams:", err)
			return 2
		}
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				fmt.Fprintln(os.Stderr, "verify:", err)
				return 2
			}
			streams = append(streams, id)
		}
		rows.Close()
		if rows.Err() != nil {
			fmt.Fprintln(os.Stderr, "verify:", rows.Err())
			return 2
		}
	}
	var cp checkpoint
	if *checkpointPath != "" {
		if cp, err = loadCheckpoint(*checkpointPath, tenantID); err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			return 2
		}
		// A stream the checkpoint knows must still exist, even if every
		// one of its events is gone.
		if *streamFlag == "" {
			seen := map[string]bool{}
			for _, s := range streams {
				seen[s.String()] = true
			}
			for s := range cp.Streams {
				if id, err := uuid.Parse(s); err == nil && !seen[s] {
					streams = append(streams, id)
				}
			}
		}
	}
	if len(streams) == 0 {
		fmt.Fprintln(os.Stderr, "verify: tenant has no audit streams")
		return 2
	}

	failed := false
	for _, streamID := range streams {
		report, err := seal.Verify(ctx, pool, tenantID, streamID, keys)
		if err != nil {
			fmt.Fprintf(os.Stderr, "verify: stream %s: %v\n", streamID, err)
			return 2
		}
		if *checkpointPath != "" {
			checkAgainst(cp, streamID, &report)
			if report.Head != nil {
				cp.Streams[streamID.String()] = *report.Head
			}
		}
		out, _ := json.Marshal(map[string]any{
			"stream":           streamID.String(),
			"ok":               report.OK(),
			"epochs":           report.Epochs,
			"events_sealed":    report.EventsSealed,
			"unsealed_tail":    report.UnsealedTail,
			"requests_checked": report.RequestsChecked,
			"head":             report.Head,
			"problems":         report.Problems,
		})
		fmt.Println(string(out))
		if !report.OK() {
			failed = true
		}
	}
	if failed {
		return 1 // the checkpoint is only advanced past a clean run
	}
	if *checkpointPath != "" {
		if err := cp.save(*checkpointPath); err != nil {
			fmt.Fprintln(os.Stderr, "verify: save checkpoint:", err)
			return 2
		}
	}
	return 0
}
