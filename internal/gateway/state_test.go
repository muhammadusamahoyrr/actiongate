package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func writeTestState(t *testing.T, path string, receipts map[string]Grant) {
	t.Helper()
	s := &State{ServerURL: "http://cp", GatewayID: "gw", PendingReceipts: receipts}
	if err := s.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
}

// Regression for issue #5: parallel hook invocations each load the state,
// add a receipt, and save. No receipt may be lost and no save may fail.
func TestSaveReceiptsConcurrentAddsAllSurvive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.json")
	writeTestState(t, path, map[string]Grant{})

	const n = 32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			s, err := LoadState(path)
			if err != nil {
				errs <- err
				return
			}
			id := fmt.Sprintf("action-%d", i)
			s.PendingReceipts[id] = Grant{GrantID: "g-" + id, ActionID: id}
			time.Sleep(5 * time.Millisecond) // the control-plane round trip
			if err := s.SaveReceipts(path); err != nil {
				errs <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent save: %v", err)
	}

	final, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(final.PendingReceipts) != n {
		t.Fatalf("got %d pending receipts, want %d (lost updates)", len(final.PendingReceipts), n)
	}
	leftovers, _ := filepath.Glob(path + ".*.tmp")
	if len(leftovers) != 0 {
		t.Errorf("temp files left behind: %v", leftovers)
	}
}

// A report that removes its own receipt must not resurrect or drop the
// receipts other processes added in the meantime.
func TestSaveReceiptsRemovalKeepsOthers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.json")
	writeTestState(t, path, map[string]Grant{"a": {ActionID: "a"}})

	reporter, err := LoadState(path) // sees only "a"
	if err != nil {
		t.Fatal(err)
	}
	checker, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	checker.PendingReceipts["b"] = Grant{ActionID: "b"}
	if err := checker.SaveReceipts(path); err != nil {
		t.Fatal(err)
	}

	delete(reporter.PendingReceipts, "a")
	if err := reporter.SaveReceipts(path); err != nil {
		t.Fatal(err)
	}

	final, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := final.PendingReceipts["a"]; ok {
		t.Error("reported receipt a is still pending")
	}
	if _, ok := final.PendingReceipts["b"]; !ok {
		t.Error("receipt b, added by another process, was lost")
	}
}

func TestSaveReceiptsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.json")
	s := &State{PendingReceipts: map[string]Grant{"x": {ActionID: "x"}}}
	if err := s.SaveReceipts(path); !os.IsNotExist(err) {
		t.Fatalf("SaveReceipts on a missing file: got %v, want not-exist", err)
	}
}

func TestSaveReceiptsPrunesStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.json")
	old := time.Now().Add(-48 * time.Hour)
	writeTestState(t, path, map[string]Grant{
		"old":   {ActionID: "old", ExpiresAt: old},
		"fresh": {ActionID: "fresh", ExpiresAt: time.Now().Add(time.Minute)},
	})
	s, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	s.PendingReceipts["new"] = Grant{ActionID: "new", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.SaveReceipts(path); err != nil {
		t.Fatal(err)
	}
	final, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := final.PendingReceipts["old"]; ok {
		t.Error("receipt expired 48h ago was not pruned")
	}
	if len(final.PendingReceipts) != 2 {
		t.Errorf("got %v, want fresh and new", final.PendingReceipts)
	}
}

func TestLoadStateMissingCreatesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "actiongate")
	if _, err := LoadState(filepath.Join(dir, "gateway.json")); !os.IsNotExist(err) {
		t.Fatalf("got %v, want not-exist", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("LoadState created %s", dir)
	}
}
