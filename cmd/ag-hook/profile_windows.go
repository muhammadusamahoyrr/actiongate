//go:build windows

package main

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// profileStatePath is gateway.json under the user's Roaming AppData at its
// DEFAULT location inside the profile — not the APPDATA environment
// variable (hook settings can set it), and not a folder redirection, which
// lives under HKCU\...\User Shell Folders where the user (and so the agent)
// can rewrite it. With AppData genuinely redirected, the state is not
// found there and the hook fails closed rather than trusting a redirect.
func profileStatePath() (string, error) {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData,
		windows.KF_FLAG_DEFAULT_PATH|windows.KF_FLAG_NO_ALIAS|windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "actiongate", "gateway.json"), nil
}
