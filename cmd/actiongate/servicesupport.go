package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Helpers for the long-running service. They are platform-neutral so they
// can be tested everywhere; only the SCM glue is Windows-only.

// rotatingFile is an append-only log file capped at maxBytes. When a write
// would cross the cap, the file is renamed to path+".1" (replacing the
// previous backup) and a fresh file is started, so the log never uses more
// than about 2*maxBytes. The old service.log had no cap and reached 130 MB
// in a day while waiting for a database that never came.
type rotatingFile struct {
	path     string
	maxBytes int64

	mu   sync.Mutex
	f    *os.File
	size int64
}

func openRotatingFile(path string, maxBytes int64) (*rotatingFile, error) {
	r := &rotatingFile{path: path, maxBytes: maxBytes}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

// The service runs as LocalSystem but its files live in the installing
// user's profile, which that user can change. A privileged process must not
// follow a link the user planted there (a symlink or a junction pointing at
// a system file would make SYSTEM overwrite, rename or delete it), so every
// write below first checks that the directory and the file are plain.
// errLinked is returned when one is not.
var errLinked = errors.New("refusing to follow a link or junction in the service directory")

// checkPlain verifies that path's directory is a real directory and that
// path itself is a regular file or does not exist.
func checkPlain(path string) error {
	di, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !di.IsDir() || di.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return fmt.Errorf("%w: %s", errLinked, filepath.Dir(path))
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s", errLinked, path)
	}
	return nil
}

func (r *rotatingFile) open() error {
	if err := checkPlain(r.path); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Clean(r.path), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	return nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, fs.ErrClosed
	}
	if r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	r.f = nil
	backup := r.path + ".1"
	if err := checkPlain(r.path); err != nil {
		return err
	}
	if err := checkPlain(backup); err != nil {
		return err
	}
	if err := os.Remove(backup); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(r.path, backup); err != nil {
		return err
	}
	return r.open()
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// retrier paces a retry loop: delays double from min up to max, and an
// error that repeats unchanged is logged only every logEvery, with a count.
// Before, the service logged the same "database not ready" line every 10 s
// forever.
type retrier struct {
	min, max time.Duration
	logEvery time.Duration
	now      func() time.Time

	delay    time.Duration
	lastMsg  string
	lastLog  time.Time
	repeated int
}

func newRetrier(minDelay, maxDelay, logEvery time.Duration) *retrier {
	return &retrier{min: minDelay, max: maxDelay, logEvery: logEvery, now: time.Now}
}

// fail records a failed attempt. It returns the delay before the next
// attempt and, when this failure should be logged, the number of identical
// failures suppressed since the last log line (-1 means do not log).
func (r *retrier) fail(err error) (time.Duration, int) {
	if r.delay == 0 {
		r.delay = r.min
	} else if r.delay *= 2; r.delay > r.max {
		r.delay = r.max
	}
	msg := err.Error()
	now := r.now()
	if msg != r.lastMsg || now.Sub(r.lastLog) >= r.logEvery {
		suppressed := r.repeated
		if msg != r.lastMsg {
			suppressed = 0
		}
		r.lastMsg, r.lastLog, r.repeated = msg, now, 0
		return r.delay, suppressed
	}
	r.repeated++
	return r.delay, -1
}

// reset is called after a success, so the next failure starts fast again.
func (r *retrier) reset() {
	r.delay, r.lastMsg, r.repeated = 0, "", 0
}

// serviceState is what the running service is doing, written next to the
// config so `actiongate service status` can say why the control plane is
// not answering instead of only "NOT answering".
type serviceState struct {
	Phase     string    `json:"phase"` // waiting_for_config | waiting_for_database | migrating | serving | restarting
	Error     string    `json:"error,omitempty"`
	NextRetry time.Time `json:"next_retry,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

func serviceStatePath(cfgPath string) string {
	return filepath.Join(filepath.Dir(cfgPath), "service-status.json")
}

func writeServiceState(cfgPath string, st serviceState) {
	st.UpdatedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	path := serviceStatePath(cfgPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	_ = writeNoFollow(path, raw)
}

// writeNoFollow replaces path via a temp file and a rename. Unlike
// fsutil.WriteFileAtomic it never resolves links: renaming onto a link
// replaces the link itself, and checkPlain refuses a linked directory.
func writeNoFollow(path string, data []byte) error {
	if err := checkPlain(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

func readServiceState(cfgPath string) (serviceState, error) {
	var st serviceState
	raw, err := os.ReadFile(filepath.Clean(serviceStatePath(cfgPath)))
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(raw, &st)
	return st, err
}

func (st serviceState) describe() string {
	s := fmt.Sprintf("service phase: %s (as of %s)", st.Phase, st.UpdatedAt.Local().Format(time.DateTime))
	if st.Error != "" {
		s += "\n  last error: " + st.Error
	}
	if !st.NextRetry.IsZero() {
		s += "\n  next retry: " + st.NextRetry.Local().Format(time.DateTime)
	}
	return s
}
