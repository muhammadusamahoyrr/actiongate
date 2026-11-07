//go:build windows

package fsutil

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// rename retries briefly on the transient errors Windows returns when
// another process (a concurrent writer, a reader, an antivirus scanner)
// has the target open — the same approach as Go's cmd/go robustio.
func rename(from, to string) error {
	const (
		errAccessDenied     = syscall.Errno(5)
		errSharingViolation = syscall.Errno(32)
	)
	deadline := time.Now().Add(2 * time.Second)
	delay := time.Millisecond
	for {
		err := os.Rename(from, to)
		var errno syscall.Errno
		if err == nil || !errors.As(err, &errno) ||
			(errno != errAccessDenied && errno != errSharingViolation) ||
			time.Now().After(deadline) {
			return err
		}
		time.Sleep(delay)
		if delay < 100*time.Millisecond {
			delay *= 2
		}
	}
}
