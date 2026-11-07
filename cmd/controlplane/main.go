// The control-plane service (plan §2): env-configured entry point over the
// shared internal/controlplane assembly. Goose migrations run via
// `make migrate` (or `actiongate up`) before start; River's own schema is
// applied at boot.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"

	"github.com/muhammadusamahoyrr/actiongate/internal/controlplane"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "admin" {
		os.Exit(runAdmin(os.Args[2:]))
	}
	if err := run(); err != nil {
		slog.Error("control plane exited", "error", err)
		os.Exit(1)
	}
}

func run() error {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	k := koanf.New(".")
	if err := k.Load(env.Provider("AG_", ".", func(s string) string {
		return strings.ToLower(strings.TrimPrefix(s, "AG_"))
	}), nil); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	if k.String("database_url") == "" {
		return errors.New("AG_DATABASE_URL is required")
	}
	if len(k.String("token_secret")) < 32 {
		return errors.New("AG_TOKEN_SECRET must be at least 32 bytes")
	}
	grantSeed, err := seedFromConfig(k.String("grant_key_seed"), "grant")
	if err != nil {
		return err
	}
	epochSeed, err := seedFromConfig(k.String("epoch_key_seed"), "epoch")
	if err != nil {
		return err
	}

	return controlplane.Run(ctx, controlplane.Config{
		DatabaseURL:        k.String("database_url"),
		Listen:             k.String("listen"),
		TokenSecret:        k.String("token_secret"),
		GrantKeySeed:       grantSeed,
		EpochKeySeed:       epochSeed,
		ApproverDefault:    k.String("approver_default"),
		SlackBotToken:      k.String("slack_bot_token"),
		SlackSigningSecret: k.String("slack_signing_secret"),
		SlackChannel:       k.String("slack_channel"),
	})
}

// seedFromConfig decodes a base64 32-byte seed, or generates an ephemeral
// one with a loud warning — fine for development, wrong for production,
// where restarts would orphan every outstanding grant and sealed epoch.
// The seed itself is never logged: anyone holding it could forge grants
// and re-sign the audit chain. Only the public key is shown.
func seedFromConfig(encoded, name string) ([]byte, error) {
	if encoded != "" {
		seed, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("%s key seed: %w", name, err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s key seed: want %d bytes, got %d", name, ed25519.SeedSize, len(seed))
		}
		return seed, nil
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("randomness: %w", err)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	slog.Warn("ephemeral signing key generated — set the seed to survive restarts",
		"key", name, "public_key_b64", base64.StdEncoding.EncodeToString(pub))
	return seed, nil
}
