package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRotatingFileCapsSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	r, err := openRotatingFile(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(strings.Repeat("x", 29) + "\n") // 30 bytes
	for i := 0; i < 50; i++ {
		if _, err := r.Write(line); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, path + ".1"} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if fi.Size() > 100 {
			t.Errorf("%s is %d bytes, cap is 100", p, fi.Size())
		}
	}
	if _, err := os.Stat(path + ".2"); err == nil {
		t.Error("more than one backup kept")
	}
}

func TestRotatingFileResumesExistingSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("y", 90)), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := openRotatingFile(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Write([]byte(strings.Repeat("z", 20))); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	if fi, _ := os.Stat(path); fi.Size() != 20 {
		t.Errorf("expected rotation on reopen-then-overflow, log is %d bytes", fi.Size())
	}
}

func TestRetrierBacksOffAndDedupes(t *testing.T) {
	now := time.Unix(0, 0)
	r := newRetrier(10*time.Second, 5*time.Minute, 10*time.Minute)
	r.now = func() time.Time { return now }
	errDB := errors.New("database not ready")

	var delays []time.Duration
	logged := 0
	for i := 0; i < 8; i++ {
		d, suppressed := r.fail(errDB)
		delays = append(delays, d)
		if suppressed >= 0 {
			logged++
		}
		now = now.Add(d)
	}
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i := range want {
		if delays[i] != want[i] {
			t.Errorf("delay %d = %v, want %v", i, delays[i], want[i])
		}
	}
	// Attempts land at t=0,10,30,70,150,310,610,910s: logged at 0 and at 610
	// (the first attempt 10 min after the last log line).
	if logged != 2 {
		t.Errorf("logged %d of 8 identical failures, want 2", logged)
	}

	if _, suppressed := r.fail(errors.New("a different error")); suppressed != 0 {
		t.Errorf("a new error must be logged at once, got suppressed=%d", suppressed)
	}
	r.reset()
	if d, _ := r.fail(errDB); d != 10*time.Second {
		t.Errorf("after reset the delay restarts at min, got %v", d)
	}
}

func TestServiceStateRoundTrip(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "dev.json")
	writeServiceState(cfg, serviceState{Phase: "waiting_for_database", Error: "boom"})
	st, err := readServiceState(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if st.Phase != "waiting_for_database" || st.Error != "boom" || st.UpdatedAt.IsZero() {
		t.Errorf("got %+v", st)
	}
	if !strings.Contains(st.describe(), "boom") {
		t.Errorf("describe() = %q", st.describe())
	}
}
