package dbruntime

import (
	"fmt"
	"os"
	"path/filepath"
)

// ClusterState classifies what a DataPath currently holds.
type ClusterState int

const (
	// ClusterAbsent means no cluster exists (no PG_VERSION) — a fresh initdb is
	// required.
	ClusterAbsent ClusterState = iota
	// ClusterPresent means an initialized cluster exists and must be reused,
	// never reinitialized.
	ClusterPresent
)

func (s ClusterState) String() string {
	switch s {
	case ClusterAbsent:
		return "absent"
	case ClusterPresent:
		return "present"
	default:
		return "unknown"
	}
}

// ClassifyCluster reports whether dataPath holds an existing cluster, based on
// the PG_VERSION marker Postgres writes at initdb time.
func ClassifyCluster(dataPath string) ClusterState {
	if _, err := os.Stat(filepath.Join(dataPath, "PG_VERSION")); err == nil {
		return ClusterPresent
	}
	return ClusterAbsent
}

// ClusterError signals that an existing cluster could not be started — for
// example WAL crash recovery could not complete. The runtime never
// reinitializes in this case (that would destroy the audit history); the
// operator recovers the data directory by hand (there is no restore command
// yet). This is the Step 4 "WAL-recovery-failed ≠ no-cluster" guarantee.
type ClusterError struct {
	Path string
	Err  error
}

func (e *ClusterError) Error() string {
	return fmt.Sprintf("dbruntime: existing cluster at %s failed to start and was NOT reinitialized; "+
		"check postgres.log next to it, and keep a copy of the directory before changing anything "+
		"(moving it aside makes the next start create a new, empty database): %v", e.Path, e.Err)
}

func (e *ClusterError) Unwrap() error { return e.Err }
