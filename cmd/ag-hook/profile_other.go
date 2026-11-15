//go:build !windows

package main

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
)

// profileStatePath is gateway.json under the user's config directory,
// derived from the home directory in the user database rather than $HOME
// or $XDG_CONFIG_HOME, which hook settings can override. It matches
// os.UserConfigDir's default layout.
//
// user.LookupId, unlike user.Current, never falls back to $HOME when the
// database lookup fails: a failed lookup is an error, and the hook fails
// closed.
func profileStatePath() (string, error) {
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return "", err
	}
	if u.HomeDir == "" {
		return "", errors.New("user has no home directory in the user database")
	}
	base := filepath.Join(u.HomeDir, ".config")
	if runtime.GOOS == "darwin" {
		base = filepath.Join(u.HomeDir, "Library", "Application Support")
	}
	return filepath.Join(base, "actiongate", "gateway.json"), nil
}
