package dbruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBackupRestoreRoundTrip: stop cluster A, back it up, restore into a fresh
// DataPath, boot it, and the data is present. Because a physical backup carries
// the source cluster's credentials, the restored runtime uses A's password.
func TestBackupRestoreRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	ctx := context.Background()
	const pw = "pw-backup-shared"

	a := startHardened(t, pw, nil)
	execSQL(t, ctx, a.DSN(), `CREATE TABLE t (id int primary key, note text)`)
	execSQL(t, ctx, a.DSN(), `INSERT INTO t VALUES (1, 'backed up')`)
	if err := a.Stop(ctx, ShutdownFast); err != nil { // cold backup requires stopped
		t.Fatalf("stop A: %v", err)
	}

	dir := filepath.Join(t.TempDir(), "backups")
	info, err := a.WriteBackup(ctx, dir, "snap1.tgz", BackupMeta{TenantID: "tenant-x", SchemaVersion: "9"})
	if err != nil {
		t.Fatalf("WriteBackup: %v", err)
	}

	list, err := ListBackups(dir)
	if err != nil {
		t.Fatalf("ListBackups: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListBackups returned %d, want 1", len(list))
	}

	// Restore into a fresh DataPath, then boot it with the source password.
	b, err := New(Config{
		DataPath:     filepath.Join(t.TempDir(), "restored"),
		Password:     pw,
		Version:      "test",
		StartTimeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatalf("New B: %v", err)
	}
	if err := b.Restore(ctx, info.Path); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if err := b.Start(ctx); err != nil {
		t.Fatalf("start restored: %v", err)
	}
	t.Cleanup(func() { _ = b.Stop(context.Background(), ShutdownFast) })

	if got := queryString(t, ctx, b.DSN(), `SELECT note FROM t WHERE id = 1`); got != "backed up" {
		t.Fatalf("restored value = %q, want 'backed up'", got)
	}
}

// TestRestoreRejectsCorruptBackup: a corrupted archive is refused and leaves no
// usable cluster in the target.
func TestRestoreRejectsCorruptBackup(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	ctx := context.Background()

	a := startHardened(t, "pw-corrupt", nil)
	if err := a.Stop(ctx, ShutdownFast); err != nil {
		t.Fatalf("stop A: %v", err)
	}
	archive := filepath.Join(t.TempDir(), "c.tgz")
	if err := a.Backup(ctx, archive); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	// Corrupt it so it is no longer a valid gzip stream.
	if err := os.WriteFile(archive, []byte("not a gzip archive"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	b, err := New(Config{DataPath: filepath.Join(t.TempDir(), "target"), Password: "x", Version: "test"})
	if err != nil {
		t.Fatalf("New B: %v", err)
	}
	if err := b.Restore(ctx, archive); err == nil {
		t.Fatal("Restore accepted a corrupt archive; want an error")
	}
}

// TestBackupRequiresStopped: backing up a running cluster is refused.
func TestBackupRequiresStopped(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Postgres; skipped in -short")
	}
	ctx := context.Background()
	a := startHardened(t, "pw-running", nil) // started, not stopped
	err := a.Backup(ctx, filepath.Join(t.TempDir(), "x.tgz"))
	if err == nil {
		t.Fatal("Backup of a running cluster should be refused")
	}
}

// TestIncompleteBackupNotOffered: ListBackups returns only complete backups —
// never ".partial" files or archives missing a metadata sidecar. No Postgres.
func TestIncompleteBackupNotOffered(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("good.tgz", "archive-bytes")
	write("good.tgz"+metaSuffix, `{"type":"physical-cold","created_at":"2026-01-01T00:00:00Z"}`)
	write("interrupted.tgz.partial", "half-written")
	write("orphan.tgz", "archive-bytes")

	list, err := ListBackups(dir)
	if err != nil {
		t.Fatalf("ListBackups: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListBackups returned %d, want 1 (only the complete one)", len(list))
	}
	if !strings.HasSuffix(list[0].Path, "good.tgz") {
		t.Fatalf("offered the wrong backup: %s", list[0].Path)
	}
}
