//go:build !windows

package gateway

import (
	"os"

	"golang.org/x/sys/unix"
)

// lockFile blocks until it holds an exclusive advisory lock on f.
func lockFile(f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			return err
		}
	}
}

func unlockFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
