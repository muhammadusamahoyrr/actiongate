// The control-plane service (plan §2): ConnectRPC surface, River workers,
// and the Sealer loop in one deployable. Goose migrations run via
// `make migrate` before start; River's own schema is applied at boot.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/v2"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/slack-go/slack"

	"github.com/muhammadusamahoyrr/actiongate/internal/approval"
	"github.com/muhammadusamahoyrr/actiongate/internal/execution"
	"github.com/muhammadusamahoyrr/actiongate/internal/grant"
	"github.com/muhammadusamahoyrr/actiongate/internal/notify"
	"github.com/muhammadusamahoyrr/actiongate/internal/orchestrator"
	"github.com/muhammadusamahoyrr/actiongate/internal/policy"
	"github.com/muhammadusamahoyrr/actiongate/internal/queue"
	"github.com/muhammadusamahoyrr/actiongate/internal/seal"
	"github.com/muhammadusamahoyrr/actiongate/internal/server"
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

	databaseURL := k.String("database_url")
	if databaseURL == "" {
		return errors.New("AG_DATABASE_URL is required")
	}
	listen := k.String("listen")
	if listen == "" {
		listen = ":8091"
	}
	tokenSecret := k.String("token_secret")
	if len(tokenSecret) < 32 {
		return errors.New("AG_TOKEN_SECRET must be at least 32 bytes")
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	if err := queue.Migrate(ctx, pool); err != nil {
		return err
	}

	grantSeed, err := seedFromConfig(k.String("grant_key_seed"), "grant")
	if err != nil {
		return err
	}
	grantSigner, grantPub, err := grant.NewSignerFromSeed("grant-1", grantSeed)
	if err != nil {
		return fmt.Errorf("grant signer: %w", err)
	}
	epochSeed, err := seedFromConfig(k.String("epoch_key_seed"), "epoch")
	if err != nil {
		return err
	}
	epochSigner, _, err := seal.NewEd25519SignerFromSeed("epoch-1", epochSeed)
	if err != nil {
		return fmt.Errorf("epoch signer: %w", err)
	}

	insertClient, err := queue.NewInsertOnlyClient(pool)
	if err != nil {
		return fmt.Errorf("river insert client: %w", err)
	}
	coordinator := &execution.Coordinator{Pool: pool, Queue: insertClient, Signer: grantSigner}
	approvals := &approval.Service{
		Pool: pool, Queue: insertClient,
		TokenSecret: []byte(tokenSecret),
		Router:      approval.Router{Default: k.String("approver_default")},
	}
	if approvals.Router.Default == "" {
		approvals.Router.Default = "team-lead"
	}
	engine, err := policy.NewEngine()
	if err != nil {
		return fmt.Errorf("policy engine: %w", err)
	}
	orch := &orchestrator.Orchestrator{
		Pool: pool, Engine: engine, Approvals: approvals, Coordinator: coordinator,
	}

	var port notify.Port = notify.LogPort{}
	if slackToken := k.String("slack_bot_token"); slackToken != "" {
		port = notify.SlackPort{
			Client:         slack.New(slackToken),
			DefaultChannel: k.String("slack_channel"),
		}
		slog.Info("slack notifications enabled", "default_channel", k.String("slack_channel"))
	}
	workers, err := queue.NewWorkers(pool, port)
	if err != nil {
		return fmt.Errorf("workers: %w", err)
	}
	if err := execution.RegisterWorker(workers, coordinator); err != nil {
		return fmt.Errorf("authorize worker: %w", err)
	}
	workerClient, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:  map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 10}},
		Workers: workers,
	})
	if err != nil {
		return fmt.Errorf("river client: %w", err)
	}
	if err := workerClient.Start(ctx); err != nil {
		return fmt.Errorf("river start: %w", err)
	}
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = workerClient.Stop(stopCtx)
	}()

	sealer := &seal.Sealer{Pool: pool, Signer: epochSigner}
	go func() {
		if err := sealer.Run(ctx, seal.DefaultInterval); err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("sealer stopped", "error", err)
		}
	}()

	srv := &server.Server{
		Pool: pool, Orchestrator: orch, Approvals: approvals, Coordinator: coordinator,
		GrantKeyID: grantSigner.KeyID(), GrantPublicKey: grantPub,
		SlackSigningSecret: k.String("slack_signing_secret"),
	}
	httpServer := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	slog.Info("control plane listening", "addr", listen, "grant_key", grantSigner.KeyID())
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// seedFromConfig decodes a base64 32-byte seed, or generates an ephemeral
// one with a loud warning — fine for development, wrong for production,
// where restarts would orphan every outstanding grant and sealed epoch.
func seedFromConfig(encoded, name string) ([]byte, error) {
	if encoded != "" {
		seed, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("%s key seed: %w", name, err)
		}
		return seed, nil
	}
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("randomness: %w", err)
	}
	slog.Warn("ephemeral signing key generated — set the seed to survive restarts",
		"key", name, "seed_b64", base64.StdEncoding.EncodeToString(seed))
	return seed, nil
}
