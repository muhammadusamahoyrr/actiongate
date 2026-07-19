package dbruntime

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// backupType is the backup kind Developer Edition produces. The bundled
// (Zonky) Postgres distribution ships only initdb/pg_ctl/postgres — no
// pg_dump/pg_restore — so Developer Edition uses a cold physical backup: a
// crash-consistent tar of pgdata taken while the cluster is stopped. It needs no
// extra binaries and restore-into-staging-then-swap matches the Step 9 junction
// pattern. (Logical/pg_dump backups would require vendoring client tools; online
// physical backup is a later, Team/Enterprise concern.)
const backupType = "physical-cold"

// errRunning is returned when a cold backup/restore is attempted on a running
// cluster; a consistent filesystem copy requires the cluster stopped.
type errRunning struct{ op string }

func (e errRunning) Error() string {
	return fmt.Sprintf("dbruntime: %s requires the cluster to be stopped (cold backup)", e.op)
}

func (e *Embedded) isRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// Backup writes a crash-consistent gzip-compressed tar of the data directory to
// path. The cluster must be stopped.
func (e *Embedded) Backup(_ context.Context, path string) error {
	if e.isRunning() {
		return errRunning{op: "backup"}
	}
	if ClassifyCluster(e.cfg.DataPath) != ClusterPresent {
		return fmt.Errorf("dbruntime: backup: no cluster at %s", e.cfg.DataPath)
	}
	return archiveDir(e.cfg.DataPath, path)
}

// Restore extracts a backup produced by Backup into this runtime's (empty) data
// directory. It is meant for a fresh staging DataPath; the cluster must be
// stopped and the DataPath must not already hold a cluster.
func (e *Embedded) Restore(_ context.Context, path string) error {
	if e.isRunning() {
		return errRunning{op: "restore"}
	}
	if ClassifyCluster(e.cfg.DataPath) == ClusterPresent {
		return fmt.Errorf("dbruntime: restore target %s already holds a cluster; restore into a fresh location", e.cfg.DataPath)
	}
	if err := os.MkdirAll(e.cfg.DataPath, 0o700); err != nil {
		return fmt.Errorf("dbruntime: restore target: %w", err)
	}
	return extractArchive(path, e.cfg.DataPath)
}

// archiveDir writes dir into a gzip-compressed tar at dst. The stale
// postmaster.pid is skipped so a restored copy never inherits a bogus pid.
func archiveDir(dir, dst string) (err error) {
	f, err := os.Create(dst) //nolint:gosec // dst is a caller-chosen backup path
	if err != nil {
		return fmt.Errorf("dbruntime: create backup file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	walkErr := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if rel == "." || rel == "postmaster.pid" {
			return nil
		}
		hdr, err := tar.FileInfoHeader(fi, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		if !fi.Mode().IsRegular() {
			return nil // skip sockets/symlinks; embedded single-node has none
		}
		src, err := os.Open(p) //nolint:gosec // p comes from walking our own DataPath
		if err != nil {
			return err
		}
		defer func() { _ = src.Close() }()
		_, err = io.Copy(tw, src)
		return err
	})
	if walkErr != nil {
		return fmt.Errorf("dbruntime: archive data dir: %w", walkErr)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("dbruntime: finalize tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("dbruntime: finalize gzip: %w", err)
	}
	return nil
}

// extractArchive extracts a gzip-compressed tar into dir, guarding against path
// traversal.
func extractArchive(src, dir string) error {
	f, err := os.Open(src) //nolint:gosec // src is a caller-chosen backup path
	if err != nil {
		return fmt.Errorf("dbruntime: open backup: %w", err)
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("dbruntime: read backup (gzip): %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("dbruntime: read backup (tar): %w", err)
		}
		target := filepath.Join(dir, filepath.FromSlash(hdr.Name))
		if !strings.HasPrefix(target, filepath.Clean(dir)+string(os.PathSeparator)) {
			return fmt.Errorf("dbruntime: backup entry escapes target: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777) //nolint:gosec // path checked above
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil { //nolint:gosec // trusted local backup
				_ = out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}

// BackupMeta is the sidecar recorded next to every completed backup so a restore
// can make version and tenant decisions (Step 7). Fields are opaque strings to
// keep dbruntime audit-chain-agnostic; the caller supplies the checkpoint
// separately.
type BackupMeta struct {
	ActionGateVersion string    `json:"actiongate_version"`
	PostgresVersion   string    `json:"postgres_version"`
	SchemaVersion     string    `json:"schema_version"`
	TenantID          string    `json:"tenant_id,omitempty"`
	Type              string    `json:"type"`
	CreatedAt         time.Time `json:"created_at"`
}

// BackupInfo is a discovered, complete backup.
type BackupInfo struct {
	Path string
	Meta BackupMeta
}

const metaSuffix = ".meta.json"

// WriteBackup writes the backup to a ".partial" file and only on full success
// renames it to its final name and writes the metadata sidecar. An interrupted
// backup leaves a ".partial" that ListBackups never offers as a restore
// candidate — "marked incomplete at write time".
func (e *Embedded) WriteBackup(ctx context.Context, dir, name string, meta BackupMeta) (BackupInfo, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return BackupInfo{}, fmt.Errorf("dbruntime: backups dir: %w", err)
	}
	final := filepath.Join(dir, name)
	partial := final + ".partial"

	if err := e.Backup(ctx, partial); err != nil {
		_ = os.Remove(partial)
		return BackupInfo{}, err
	}

	meta.Type = backupType
	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now().UTC()
	}
	if meta.PostgresVersion == "" {
		meta.PostgresVersion = pgVersion
	}
	if meta.ActionGateVersion == "" {
		meta.ActionGateVersion = e.cfg.Version
	}
	metaBytes, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		_ = os.Remove(partial)
		return BackupInfo{}, fmt.Errorf("dbruntime: marshal backup meta: %w", err)
	}
	// Write the sidecar first, then the atomic rename that publishes the backup.
	if err := os.WriteFile(final+metaSuffix, metaBytes, 0o600); err != nil {
		_ = os.Remove(partial)
		return BackupInfo{}, fmt.Errorf("dbruntime: write backup meta: %w", err)
	}
	if err := os.Rename(partial, final); err != nil {
		_ = os.Remove(partial)
		_ = os.Remove(final + metaSuffix)
		return BackupInfo{}, fmt.Errorf("dbruntime: publish backup: %w", err)
	}
	return BackupInfo{Path: final, Meta: meta}, nil
}

// ListBackups returns only complete backups — those with both the archive and
// its metadata sidecar. ".partial" files and archives missing a sidecar are
// never offered. Newest first.
func ListBackups(dir string) ([]BackupInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("dbruntime: read backups dir: %w", err)
	}
	var out []BackupInfo
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || strings.HasSuffix(name, metaSuffix) || strings.HasSuffix(name, ".partial") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name+metaSuffix)) //nolint:gosec // path derived from a dir entry we own
		if err != nil {
			continue // archive without a sidecar: incomplete, never offered
		}
		var meta BackupMeta
		if err := json.Unmarshal(raw, &meta); err != nil {
			continue
		}
		out = append(out, BackupInfo{Path: filepath.Join(dir, name), Meta: meta})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Meta.CreatedAt.After(out[j].Meta.CreatedAt) })
	return out, nil
}
