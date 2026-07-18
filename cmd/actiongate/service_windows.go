//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "actiongate"

// cmdService manages the control plane as a Windows service so the stack
// survives reboots unattended — while it is down, hooked projects fail
// closed, which makes auto-restart a correctness property, not polish.
func cmdService(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: actiongate service <install|uninstall|start|stop|status|run>")
		return 1
	}
	switch args[0] {
	case "install":
		return serviceInstall()
	case "uninstall":
		return serviceUninstall()
	case "start", "stop":
		return serviceControl(args[0])
	case "status":
		return serviceStatus()
	case "run":
		return serviceRun(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "service: unknown subcommand %q\n", args[0])
		return 1
	}
}

func connectSCM() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("cannot open the service manager (run this from an elevated terminal): %w", err)
	}
	return m, nil
}

func serviceInstall() int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return 1
	}
	exe, _ = filepath.Abs(exe)
	cfgPath, err := devConfigPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return 1
	}
	if _, err := loadDevConfigAt(cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return 1
	}

	m, err := connectSCM()
	if err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return 1
	}
	defer func() { _ = m.Disconnect() }()

	if s, err := m.OpenService(serviceName); err == nil {
		_ = s.Close()
		fmt.Fprintf(os.Stderr, "service: %q is already installed — `actiongate service uninstall` first to change it\n", serviceName)
		return 1
	}

	// Delayed auto-start: the database rides Docker Desktop, which itself
	// only appears around user login — no point racing it at boot.
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		DisplayName:      "actiongate control plane",
		Description:      "Action firewall for AI coding agents: policy decisions, human approvals, and the sealed audit log. While this service is down, protected projects fail closed.",
	}, "service", "run", "-config", cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "service: create:", err)
		return 1
	}
	defer func() { _ = s.Close() }()

	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}, 86400); err != nil {
		fmt.Fprintln(os.Stderr, "service: recovery actions:", err)
		return 1
	}
	if err := s.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "service: installed but failed to start: %v\n", err)
		return 1
	}
	fmt.Printf(`service %q installed and started.

  config: %s
  log:    %s
  It starts automatically after every reboot (delayed) and restarts itself
  on failure. Keep Docker Desktop's "start when you log in" enabled — the
  service waits patiently for the database while Docker comes up.

  status:    actiongate service status
  uninstall: actiongate service uninstall   (elevated)
`, serviceName, cfgPath, serviceLogPath(cfgPath))
	return 0
}

func serviceUninstall() int {
	m, err := connectSCM()
	if err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return 1
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(serviceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "service: %q is not installed\n", serviceName)
		return 1
	}
	defer func() { _ = s.Close() }()
	if status, err := s.Control(svc.Stop); err == nil {
		for i := 0; i < 20 && status.State != svc.Stopped; i++ {
			time.Sleep(500 * time.Millisecond)
			status, _ = s.Query()
		}
	}
	if err := s.Delete(); err != nil {
		fmt.Fprintln(os.Stderr, "service: delete:", err)
		return 1
	}
	fmt.Printf("service %q removed. Run the stack manually with `actiongate up`.\n", serviceName)
	return 0
}

func serviceControl(verb string) int {
	m, err := connectSCM()
	if err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return 1
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(serviceName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "service: %q is not installed — `actiongate service install` (elevated)\n", serviceName)
		return 1
	}
	defer func() { _ = s.Close() }()
	if verb == "start" {
		if err := s.Start(); err != nil {
			fmt.Fprintln(os.Stderr, "service: start:", err)
			return 1
		}
		fmt.Println("started")
		return 0
	}
	if _, err := s.Control(svc.Stop); err != nil {
		fmt.Fprintln(os.Stderr, "service: stop:", err)
		return 1
	}
	fmt.Println("stopping")
	return 0
}

// serviceStatus works without elevation: it reports via `sc query` first
// and falls back to the HTTP health endpoint, which is the truth that
// matters to hooks anyway.
func serviceStatus() int {
	out, err := exec.Command("sc", "query", serviceName).CombinedOutput()
	if err != nil {
		fmt.Printf("service: not installed (%s)\n", serviceName)
	} else {
		fmt.Print(string(out))
	}
	cfgPath, err := devConfigPath()
	if err == nil {
		if cfg, err := loadDevConfigAt(cfgPath); err == nil {
			if healthy(context.Background(), cfg.ServerURL) {
				fmt.Printf("control plane at %s: healthy\n", cfg.ServerURL)
				return 0
			}
			fmt.Printf("control plane at %s: NOT answering — hooked projects fail closed\n", cfg.ServerURL)
			return 1
		}
	}
	return 1
}

// serviceRun is the service entry point (invoked by the SCM with the
// installing user's config path). -debug runs the identical loop in the
// console for testing without an installed service.
func serviceRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgFlag := fs.String("config", "", "dev config path (required)")
	debugFlag := fs.Bool("debug", false, "run in the console instead of under the SCM")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	cfgPath := *cfgFlag
	if cfgPath == "" {
		p, err := devConfigPath()
		if err != nil {
			fmt.Fprintln(os.Stderr, "service run:", err)
			return 1
		}
		cfgPath = p
	}

	log, closeLog, err := serviceLogger(cfgPath, *debugFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "service run:", err)
		return 1
	}
	defer closeLog()

	if *debugFlag {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		serveResilient(ctx, cfgPath, log)
		return 0
	}

	if err := svc.Run(serviceName, &agService{cfgPath: cfgPath, log: log}); err != nil {
		log.Error("service run failed", "error", err)
		return 1
	}
	return 0
}

type agService struct {
	cfgPath string
	log     *slog.Logger
}

func (s *agService) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveResilient(ctx, s.cfgPath, s.log)
	}()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-requests:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		case <-done:
			// The serve loop only exits on ctx cancel; reaching here without
			// a stop request means it crashed — report failure so the SCM's
			// recovery actions restart us.
			return true, 1
		}
	}
}

// serviceHint tells `up` whether to nudge the user toward reboot-proofing.
func serviceHint() string {
	if err := exec.Command("sc", "query", serviceName).Run(); err == nil {
		return ""
	}
	return `
  Survive reboots (recommended, once, from an elevated terminal):
      actiongate service install
`
}

func serviceLogPath(cfgPath string) string {
	return filepath.Join(filepath.Dir(cfgPath), "service.log")
}

func serviceLogger(cfgPath string, debug bool) (*slog.Logger, func(), error) {
	if debug {
		return slog.New(slog.NewTextHandler(os.Stderr, nil)), func() {}, nil
	}
	f, err := os.OpenFile(serviceLogPath(cfgPath), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open service log: %w", err)
	}
	return slog.New(slog.NewTextHandler(f, nil)), func() { _ = f.Close() }, nil
}

// serveResilient keeps the control plane alive until ctx is cancelled:
// wait for config and database (retrying forever — at boot, Docker Desktop
// arrives whenever the user logs in), migrate, ensure the tenant, serve;
// on any failure, log and start over. Nothing here ever gives up.
func serveResilient(ctx context.Context, cfgPath string, log *slog.Logger) {
	for ctx.Err() == nil {
		cfg, err := loadDevConfigAt(cfgPath)
		if err != nil {
			log.Warn("config not ready", "path", cfgPath, "error", err)
			sleepCtx(ctx, 30*time.Second)
			continue
		}
		if err := ensurePostgres(ctx, cfg.DatabaseURL); err != nil {
			if ctx.Err() == nil {
				log.Warn("database not ready, waiting", "error", err)
				sleepCtx(ctx, 10*time.Second)
			}
			continue
		}
		if err := migrate(ctx, cfg.DatabaseURL); err != nil {
			log.Error("migrate failed", "error", err)
			sleepCtx(ctx, 10*time.Second)
			continue
		}
		if err := ensureTenantResilient(ctx, cfg, cfgPath); err != nil {
			log.Error("tenant provisioning failed", "error", err)
			sleepCtx(ctx, 10*time.Second)
			continue
		}
		log.Info("starting control plane", "listen", cfg.Listen)
		if err := runControlPlane(ctx, cfg, log); err != nil && ctx.Err() == nil {
			log.Error("control plane exited, restarting", "error", err)
			sleepCtx(ctx, 5*time.Second)
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func ensureTenantResilient(ctx context.Context, cfg *devConfig, cfgPath string) error {
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	_, err = ensureTenant(ctx, pool, cfg, cfgPath)
	return err
}
