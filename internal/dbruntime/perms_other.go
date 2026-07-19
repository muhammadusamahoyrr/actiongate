//go:build !windows

package dbruntime

import "os"

// hardenDataDirPerms restricts pgdata to the owning user. Best-effort: initdb
// already applies 0700, so this is defense-in-depth only.
func hardenDataDirPerms(path string) error {
	// pgdata is a directory; 0700 (not 0600) is required so the owner can
	// traverse it — the same mode initdb sets.
	return os.Chmod(path, 0o700) //nolint:gosec // G302: directory perms, 0700 intended
}
