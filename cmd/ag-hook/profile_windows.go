//go:build windows

package main

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// profileStatePath is gateway.json under the user's Roaming AppData as the
// OS records it (SHGetKnownFolderPath), not the APPDATA environment
// variable, which hook settings can override.
func profileStatePath() (string, error) {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_RoamingAppData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "actiongate", "gateway.json"), nil
}
