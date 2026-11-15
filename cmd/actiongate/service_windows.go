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

	"github.com/muhammadusamahoyrr/actiongate/internal/dbruntime"
)

// serviceName is the Windows service older versions installed (as
// LocalSystem). It is still recognised so it can be found and removed.
const serviceName = "actiongate"

// cmdService keeps the control plane running in the background so it
// survives reboots: while it is down, hooked projects fail closed, which
// makes auto-start a correctness property, not polish. On Windows it is a
// sign-in task (see service_task_windows.go), not a Windows service.
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
	case "start":
		return serviceStart()
	case "stop":
		return serviceStop()
	case "status":
		return serviceStatus()
	case "run":
		return serviceRun(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "service: unknown subcommand %q\n", args[0])
		return 1
	}
}

const legacyServiceHelp = "an older actiongate Windows service is installed (it runs as LocalSystem).\n" +
	"  Remove it from an elevated terminal with `actiongate service uninstall`, then install again."

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
	cfg, err := loadDevConfigAt(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return 1
	}
	if legacyServiceInstalled() {
		fmt.Fprintln(os.Stderr, "service:", legacyServiceHelp)
		return 1
	}
	if taskInstalled() {
		fmt.Fprintf(os.Stderr, "service: already installed — `actiongate service uninstall` first to change it\n")
		return 1
	}
	if healthy(context.Background(), cfg.ServerURL) {
		fmt.Fprintf(os.Stderr, "service: a control plane is already answering at %s (an `actiongate up` window?).\n"+
			"  Stop it with Ctrl+C first, then install again.\n", cfg.ServerURL)
		return 1
	}
	account, err := currentAccount()
	if err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return 1
	}
	if err := createTask(account, exe, cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "service: create task:", err)
		return 1
	}
	if _, err := schtasks("/Run", "/TN", taskName); err != nil {
		fmt.Fprintf(os.Stderr, "service: installed but failed to start: %v\n", err)
		return 1
	}
	fmt.Print("installed; waiting for the control plane")
	up := waitForControlPlane(cfg.ServerURL, 90*time.Second)
	fmt.Println()
	if !up {
		fmt.Fprintln(os.Stderr, "service: installed and started, but the control plane is not answering yet.\n"+
			"  Check `actiongate service status`.")
		return 1
	}
	fmt.Printf(`actiongate runs in the background as %s (not as SYSTEM, no password needed).

  config: %s
  log:    %s
  It starts by itself each time you sign in to Windows and restarts if it
  crashes. It runs only while you are signed in, which is when agents run.

  status:    actiongate service status
  stop/start: actiongate service stop | start
  uninstall: actiongate service uninstall
`, account, cfgPath, serviceLogPath(cfgPath))
	return 0
}

func waitForControlPlane(serverURL string, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if healthy(context.Background(), serverURL) {
			return true
		}
		fmt.Print(".")
		time.Sleep(2 * time.Second)
	}
	return false
}

func serviceUninstall() int {
	removed := false
	if taskInstalled() {
		_ = stopTask()
		if _, err := schtasks("/Delete", "/TN", taskName, "/F"); err != nil {
			fmt.Fprintln(os.Stderr, "service:", err)
			return 1
		}
		removed = true
	}
	if legacyServiceInstalled() {
		if err := removeLegacyService(); err != nil {
			fmt.Fprintln(os.Stderr, "service: the older actiongate Windows service is still installed:", err)
			return 1
		}
		removed = true
	}
	if !removed {
		fmt.Fprintln(os.Stderr, "service: not installed")
		return 1
	}
	fmt.Println("removed. Run the stack manually with `actiongate up`.")
	return 0
}

func removeLegacyService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("run this from an elevated terminal to remove it: %w", err)
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	if status, err := s.Control(svc.Stop); err == nil {
		for i := 0; i < 20 && status.State != svc.Stopped; i++ {
			time.Sleep(500 * time.Millisecond)
			status, _ = s.Query()
		}
	}
	return s.Delete()
}

func serviceStart() int {
	if !taskInstalled() {
		fmt.Fprintln(os.Stderr, "service: not installed — `actiongate service install`")
		return 1
	}
	if _, err := schtasks("/Run", "/TN", taskName); err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return 1
	}
	fmt.Println("started")
	return 0
}

func serviceStop() int {
	if !taskInstalled() {
		fmt.Fprintln(os.Stderr, "service: not installed")
		return 1
	}
	if err := stopTask(); err != nil {
		fmt.Fprintln(os.Stderr, "service:", err)
		return 1
	}
	fmt.Println("stopped")
	return 0
}

// stopTask asks the running task to shut down cleanly (so it also stops
// the embedded PostgreSQL) and waits for it. Only if it does not stop in
// time is the task ended by force.
func stopTask() error {
	cfgPath, err := devConfigPath()
	if err != nil {
		return err
	}
	if st, err := readServiceState(cfgPath); err != nil || st.Phase == "stopped" {
		return nil // not running
	}
	asked := time.Now()
	if err := requestServiceStop(cfgPath); err != nil {
		return fmt.Errorf("request stop: %w", err)
	}
	for time.Since(asked) < 60*time.Second {
		if st, err := readServiceState(cfgPath); err == nil && st.Phase == "stopped" && st.UpdatedAt.After(asked.Add(-time.Second)) {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = os.Remove(serviceStopPath(cfgPath))
	if _, err := schtasks("/End", "/TN", taskName); err != nil {
		return err
	}
	return fmt.Errorf("did not stop within 60 s and was ended by force; the database may still be running (`actiongate up` reuses it)")
}

// serviceStatus needs no elevation.
func serviceStatus() int {
	switch {
	case taskInstalled():
		fmt.Printf("background task %q: installed (starts at sign-in)\n", taskName)
	case legacyServiceInstalled():
		fmt.Println("WARNING:", legacyServiceHelp)
	default:
		fmt.Println("background task: not installed (`actiongate service install`)")
	}
	cfgPath, err := devConfigPath()
	if err != nil {
		return 1
	}
	cfg, err := loadDevConfigAt(cfgPath)
	if err != nil {
		return 1
	}
	if healthy(context.Background(), cfg.ServerURL) {
		fmt.Printf("control plane at %s: healthy\n", cfg.ServerURL)
		return 0
	}
	fmt.Printf("control plane at %s: NOT answering — hooked projects fail closed\n", cfg.ServerURL)
	if st, err := readServiceState(cfgPath); err == nil {
		fmt.Println(st.describe())
	}
	return 1
}

// serviceRun is the background entry point: the sign-in task runs it, and
// so does a Windows service left by an older version. -debug runs the same
// loop in the console.
func serviceRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgFlag := fs.String("config", "", "dev config path (required)")
	debugFlag := fs.Bool("debug", false, "log to the console instead of service.log")
	workerFlag := fs.Bool("worker", false, "internal: run the control plane under the supervisor")
	adoptFlag := fs.Bool("adopt-db", false, "internal: take over a database left running by a crashed worker")
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

	isSvc, _ := svc.IsWindowsService()
	if !isSvc && !*debugFlag && !*workerFlag {
		return superviseWorker(cfgPath)
	}

	log, closeLog, err := serviceLogger(cfgPath, *debugFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "service run:", err)
		return 1
	}
	defer closeLog()

	if isSvc {
		// An older install: a Windows service running as LocalSystem.
		log.Warn("running as an older LocalSystem Windows service; reinstall with `actiongate service uninstall` (elevated) then `install`")
		if err := svc.Run(serviceName, &agService{cfgPath: cfgPath, log: log}); err != nil {
			log.Error("service run failed", "error", err)
			return 1
		}
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go watchStopRequest(ctx, cfgPath, time.Second, cancel)
	serveResilient(ctx, cfgPath, log, *adoptFlag)
	return 0
}

// superviseWorker is what the sign-in task runs. It starts the control
// plane as a child process and restarts it if it exits with an error, so a
// crash (a panic, say) does not leave protection down until the next
// sign-in. Task Scheduler cannot do this: the database processes keep the
// task's hidden console alive, so it never sees the crash. A worker that
// exits cleanly was asked to stop, and the supervisor stops with it.
func superviseWorker(cfgPath string) int {
	logFile, err := openRotatingFile(supervisorLogPath(cfgPath), 1<<20)
	if err != nil {
		fmt.Fprintln(os.Stderr, "service run:", err)
		return 1
	}
	defer func() { _ = logFile.Close() }()
	log := slog.New(slog.NewTextHandler(logFile, nil))

	exe, err := os.Executable()
	if err != nil {
		log.Error("cannot find own executable", "error", err)
		return 1
	}
	retry := newRetrier(2*time.Second, 5*time.Minute, 10*time.Minute)
	adopt := false
	for {
		args := []string{"service", "run", "-config", cfgPath, "-worker"}
		if adopt {
			args = append(args, "-adopt-db")
		}
		started := time.Now()
		// #nosec G204 -- our own executable with our own arguments.
		err := exec.Command(exe, args...).Run()
		if err == nil {
			log.Info("control plane stopped")
			return 0
		}
		if time.Since(started) > 10*time.Minute {
			retry.reset() // it ran fine for a while; this is a fresh failure
		}
		delay, suppressed := retry.fail(err)
		if suppressed >= 0 {
			log.Error("control plane exited unexpectedly; restarting", "error", err, "retry_in", delay.String())
		}
		writeServiceState(cfgPath, serviceState{Phase: "restarting", Error: "worker exited: " + err.Error(), NextRetry: time.Now().Add(delay)})
		if stopRequestedWithin(cfgPath, delay) {
			log.Info("stop requested while restarting")
			writeServiceState(cfgPath, serviceState{Phase: "stopped"})
			return 0
		}
		// The crashed worker may have left the database running. The next
		// one takes it over, so a later `service stop` still stops it.
		adopt = true
	}
}

func supervisorLogPath(cfgPath string) string {
	return filepath.Join(filepath.Dir(cfgPath), "service-supervisor.log")
}

// stopRequestedWithin waits up to d and reports (and consumes) a stop
// request that arrives in that time.
func stopRequestedWithin(cfgPath string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		if _, err := os.Lstat(serviceStopPath(cfgPath)); err == nil {
			_ = os.Remove(serviceStopPath(cfgPath))
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
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
		serveResilient(ctx, s.cfgPath, s.log, false)
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

// serviceHint tells `up` whether to suggest starting at sign-in.
func serviceHint() string {
	if taskInstalled() || legacyServiceInstalled() {
		return ""
	}
	return `
  Start automatically at every sign-in (recommended, once, no admin needed):
      actiongate service install
`
}

// serviceLogMaxBytes caps service.log; one rotated copy (service.log.1) is
// kept, so the log never uses more than about 20 MB.
const serviceLogMaxBytes = 10 << 20

func serviceLogPath(cfgPath string) string {
	return filepath.Join(filepath.Dir(cfgPath), "service.log")
}

func serviceLogger(cfgPath string, debug bool) (*slog.Logger, func(), error) {
	if debug {
		return slog.New(slog.NewTextHandler(os.Stderr, nil)), func() {}, nil
	}
	f, err := openRotatingFile(serviceLogPath(cfgPath), serviceLogMaxBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("open service log: %w", err)
	}
	return slog.New(slog.NewTextHandler(f, nil)), func() { _ = f.Close() }, nil
}

// serveResilient keeps the control plane alive until ctx is cancelled:
// wait for config and the database, migrate, ensure the tenant, serve; on
// any failure, start over. It never gives up, but it backs off (10 s up to
// 5 min), logs a repeating error only every 10 min, and records what it is
// waiting for in service-status.json for `actiongate service status`.
// (Before, it logged the same error every 10 s forever: 130 MB in a day.)
func serveResilient(ctx context.Context, cfgPath string, log *slog.Logger, adopt bool) {
	var rt *dbruntime.Embedded
	defer func() {
		if rt != nil {
			stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = rt.Stop(stopCtx, dbruntime.ShutdownFast)
		}
	}()
	retry := newRetrier(10*time.Second, 5*time.Minute, 10*time.Minute)
	// wait logs (when due) and records a failed step, then sleeps.
	wait := func(phase, msg string, err error) {
		delay, suppressed := retry.fail(err)
		if suppressed >= 0 {
			args := []any{"error", err, "retry_in", delay.String()}
			if suppressed > 0 {
				args = append(args, "repeats_since_last_log", suppressed)
			}
			log.Warn(msg, args...)
		}
		writeServiceState(cfgPath, serviceState{Phase: phase, Error: err.Error(), NextRetry: time.Now().Add(delay)})
		sleepCtx(ctx, delay)
	}
	defer writeServiceState(cfgPath, serviceState{Phase: "stopped"})

	for ctx.Err() == nil {
		cfg, err := loadDevConfigAt(cfgPath)
		if err != nil {
			wait("waiting_for_config", "config not ready", err)
			continue
		}
		if rt == nil {
			// startManagedDB brings up the embedded cluster (or reuses a running
			// one, returning nil). External-DB users are unsupported under the
			// service; the default managed path is embedded.
			r, err := startManagedDB(ctx, cfg, cfgPath)
			if err != nil {
				if ctx.Err() == nil {
					wait("waiting_for_database", "database not ready, waiting", err)
				}
				continue
			}
			if r == nil && adopt {
				// Left running by the worker that crashed: make it ours.
				if r, err = newManagedDB(cfg, cfgPath); err == nil {
					r.Adopt()
					log.Info("took over the database left running by the previous worker")
				}
				adopt = false
			}
			rt = r
		}
		if err := migrate(ctx, cfg.DatabaseURL); err != nil {
			wait("migrating", "migrate failed", err)
			continue
		}
		if err := ensureTenantResilient(ctx, cfg, cfgPath); err != nil {
			wait("migrating", "tenant provisioning failed", err)
			continue
		}
		retry.reset()
		log.Info("starting control plane", "listen", cfg.Listen)
		writeServiceState(cfgPath, serviceState{Phase: "serving"})
		if err := runControlPlane(ctx, cfg, log); err != nil && ctx.Err() == nil {
			wait("restarting", "control plane exited, restarting", err)
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
