// Package controlplane assembles and runs the control-plane service (plan
// §2): ConnectRPC surface, River workers, and the Sealer loop. It is the
// shared core behind `controlplane` (env-configured) and `actiongate up`
// (dev bootstrap, in-process).
package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
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

type Config struct {
	DatabaseURL string
	Listen      string // defaults to ":8091"
	TokenSecret string // >= 32 bytes

	GrantKeySeed []byte // 32-byte ed25519 seed
	EpochKeySeed []byte // 32-byte ed25519 seed

	ApproverDefault string // defaults to "team-lead"

	SlackBotToken      string
	SlackSigningSecret string
	SlackChannel       string

	Logger *slog.Logger // defaults to slog.Default()
}

// Run starts the full control plane and blocks until ctx is cancelled or a
// fatal error occurs. River's schema is migrated at boot; goose migrations
// must already be applied.
func Run(ctx context.Context, cfg Config) error {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	if cfg.DatabaseURL == "" {
		return errors.New("database URL is required")
	}
	if len(cfg.TokenSecret) < 32 {
		return errors.New("token secret must be at least 32 bytes")
	}
	listen := cfg.Listen
	if listen == "" {
		listen = ":8091"
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
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

	grantSigner, grantPub, err := grant.NewSignerFromSeed("grant-1", cfg.GrantKeySeed)
	if err != nil {
		return fmt.Errorf("grant signer: %w", err)
	}
	epochSigner, _, err := seal.NewEd25519SignerFromSeed("epoch-1", cfg.EpochKeySeed)
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
		TokenSecret: []byte(cfg.TokenSecret),
		Router:      approval.Router{Default: cfg.ApproverDefault},
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
	if cfg.SlackBotToken != "" {
		port = notify.SlackPort{
			Client:         slack.New(cfg.SlackBotToken),
			DefaultChannel: cfg.SlackChannel,
		}
		log.Info("slack notifications enabled", "default_channel", cfg.SlackChannel)
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
			log.Error("sealer stopped", "error", err)
		}
	}()

	srv := &server.Server{
		Pool: pool, Orchestrator: orch, Approvals: approvals, Coordinator: coordinator,
		GrantKeyID: grantSigner.KeyID(), GrantPublicKey: grantPub,
		SlackSigningSecret: cfg.SlackSigningSecret,
		EpochKeyIDs:        []string{epochSigner.KeyID()},
	}
	httpServer := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	// #nosec G118 -- shutdown runs after ctx is already cancelled; the
	// graceful-drain window must come from a fresh context.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	log.Info("control plane listening", "addr", listen, "grant_key", grantSigner.KeyID())
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
