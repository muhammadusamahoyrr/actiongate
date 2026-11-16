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
	"net"
	"net/http"
	"strings"
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
	// DatabaseURL is the role every request path runs as. It should be a
	// non-superuser, non-owner role so RLS and the append-only triggers
	// bind it (internal/dbroles.AppRole).
	DatabaseURL string
	// SealerDatabaseURL, if set, is the role the sealer runs as: it reads
	// across tenants, so it needs BYPASSRLS (dbroles.SealerRole). Empty
	// means DatabaseURL.
	SealerDatabaseURL string
	// SkipQueueMigrate: the caller already ran River's migrations as the
	// owning role (the app role cannot run DDL).
	SkipQueueMigrate bool
	Listen           string // see ListenAddr: defaults to 127.0.0.1:8091
	TokenSecret      string // >= 32 bytes

	GrantKeySeed []byte // 32-byte ed25519 seed
	EpochKeySeed []byte // 32-byte ed25519 seed
	// GrantKeyID and EpochKeyID name the keys (audit L3). They default to
	// DefaultGrantKeyID and DefaultEpochKeyID; rotating a seed means giving
	// it a new id, so material signed under the old key still verifies
	// with the old public key.
	GrantKeyID string
	EpochKeyID string

	ApproverDefault string // defaults to "team-lead"

	SlackBotToken      string
	SlackSigningSecret string
	SlackChannel       string
	// SlackApprovers limits who can approve from Slack (user ids).
	SlackApprovers []string

	Logger *slog.Logger // defaults to slog.Default()
}

// DefaultListen is loopback-only: the control plane serves plain HTTP, with
// an unauthenticated Enroll and approval callback (audit H11).
const DefaultListen = "127.0.0.1:8091"

// ListenAddr resolves the configured listen address. Empty means
// DefaultListen, and an address with no host (":8091", the old default
// that bound every interface) is narrowed to 127.0.0.1. To listen on the
// network, name the host explicitly ("0.0.0.0:8091").
func ListenAddr(s string) string {
	if s == "" {
		return DefaultListen
	}
	if host, port, err := net.SplitHostPort(s); err == nil && host == "" {
		return net.JoinHostPort("127.0.0.1", port)
	}
	return s
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
	if err := cfg.validateSlack(); err != nil {
		return err
	}
	if len(cfg.TokenSecret) < 32 {
		return errors.New("token secret must be at least 32 bytes")
	}
	listen := ListenAddr(cfg.Listen)
	if !isLoopbackAddr(listen) {
		log.Warn("control plane listening beyond loopback over plain HTTP: Enroll, /approval/callback and gateway credentials are exposed to the network — put it behind TLS",
			"listen", listen)
	}

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	if !cfg.SkipQueueMigrate {
		if err := queue.Migrate(ctx, pool); err != nil {
			return err
		}
	}
	// The sealer discovers unsealed streams across every tenant, so it
	// needs a role that reads past RLS (internal/dbroles). Everything else
	// runs on the RLS-bound pool.
	sealerPool := pool
	if cfg.SealerDatabaseURL != "" && cfg.SealerDatabaseURL != cfg.DatabaseURL {
		sealerPool, err = pgxpool.New(ctx, cfg.SealerDatabaseURL)
		if err != nil {
			return fmt.Errorf("connect sealer: %w", err)
		}
		defer sealerPool.Close()
		if err := sealerPool.Ping(ctx); err != nil {
			return fmt.Errorf("ping sealer: %w", err)
		}
	}

	grantSigner, grantPub, err := grant.NewSignerFromSeed(orDefault(cfg.GrantKeyID, DefaultGrantKeyID), cfg.GrantKeySeed)
	if err != nil {
		return fmt.Errorf("grant signer: %w", err)
	}
	epochSigner, _, err := seal.NewEd25519SignerFromSeed(orDefault(cfg.EpochKeyID, DefaultEpochKeyID), cfg.EpochKeySeed)
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
	mint := approvals.CallbackToken
	if cfg.SlackBotToken != "" {
		port = notify.SlackPort{
			Client:         slack.New(cfg.SlackBotToken),
			DefaultChannel: cfg.SlackChannel,
		}
		// Slack buttons carry Slack-bound tokens: anyone who can read the
		// channel sees them, and they must not work at /approval/callback,
		// past the approver allowlist (audit M5).
		mint = approvals.SlackToken
		log.Info("slack notifications enabled", "default_channel", cfg.SlackChannel)
	}
	workers, err := queue.NewWorkers(pool, port, mint)
	if err != nil {
		return fmt.Errorf("workers: %w", err)
	}
	// Older builds put the raw callback token in delivery job args; River
	// retains finished jobs, so strip it from those (audit C5).
	if n, err := queue.ScrubLegacyCallbackTokens(ctx, pool); err != nil {
		log.Warn("could not scrub legacy callback tokens from finished jobs", "err", err)
	} else if n > 0 {
		log.Info("scrubbed legacy callback tokens from finished delivery jobs", "jobs", n)
	}
	if err := execution.RegisterWorker(workers, coordinator); err != nil {
		return fmt.Errorf("authorize worker: %w", err)
	}
	workerClient, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues:  map[string]river.QueueConfig{river.QueueDefault: {MaxWorkers: 10}},
		Workers: workers,
		// River's periodic REINDEX needs table ownership, which the
		// least-privilege app role deliberately lacks (internal/dbroles).
		// An empty list disables it; the queue tables stay small.
		ReindexerIndexNames: []string{},
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

	sealer := &seal.Sealer{Pool: sealerPool, Signer: epochSigner, Logger: log}
	go func() {
		if err := sealer.Run(ctx, seal.DefaultInterval); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("sealer stopped", "error", err)
		}
	}()

	srv := &server.Server{
		Pool: pool, Orchestrator: orch, Approvals: approvals, Coordinator: coordinator,
		GrantKeyID: grantSigner.KeyID(), GrantPublicKey: grantPub, Logger: log,
		SlackSigningSecret: cfg.SlackSigningSecret,
		SlackApprovers:     cfg.SlackApprovers,
		EpochKeyIDs:        []string{epochSigner.KeyID()},
	}
	httpServer := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Gateways poll with short requests (no long-polling), so a request
		// body that takes a minute is a stalled or hostile client.
		ReadTimeout: 60 * time.Second,
		IdleTimeout: 2 * time.Minute,
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

// The key ids every install has used so far. Changing a default would
// orphan existing epochs and enrolled gateways, so new ids come from
// configuration only.
const (
	DefaultGrantKeyID = "grant-1"
	DefaultEpochKeyID = "epoch-1"
)

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

// validateSlack refuses a half-configured Slack setup at startup (audit
// L4). A bot token without a channel posts nowhere, and one without the
// signing secret posts buttons nobody can click: either way approvals
// would sit pending until they expire, with nothing to say why.
func (cfg Config) validateSlack() error {
	set := map[string]bool{
		"slack_bot_token":      cfg.SlackBotToken != "",
		"slack_signing_secret": cfg.SlackSigningSecret != "",
		"slack_channel":        cfg.SlackChannel != "",
	}
	var have, missing []string
	for _, name := range []string{"slack_bot_token", "slack_signing_secret", "slack_channel"} {
		if set[name] {
			have = append(have, name)
		} else {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	if len(have) == 0 {
		if len(cfg.SlackApprovers) > 0 {
			return errors.New("slack_approvers is set but Slack approvals are not configured (set slack_bot_token, slack_signing_secret and slack_channel)")
		}
		return nil
	}
	return fmt.Errorf("slack approvals are half-configured: %s set but %s missing (set all three, or none)",
		strings.Join(have, ", "), strings.Join(missing, ", "))
}

// SplitList parses a comma-separated setting (such as AG_SLACK_APPROVERS)
// into its non-empty, trimmed entries.
func SplitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
