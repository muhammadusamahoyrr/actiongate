//go:build !windows

package dbruntime

import "os"

// hardenDataDirPerms restricts pgdata to the owning user. Best-effort: initdb
// already applies 0700, so this is defense-in-depth only.
func hardenDataDirPerms(path string) error {
	return os.Chmod(path, 0o700)
}
