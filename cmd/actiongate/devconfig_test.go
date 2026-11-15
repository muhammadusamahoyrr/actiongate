package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// isolateConfigDir points os.UserConfigDir at a temp dir on every OS.
func isolateConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("APPDATA", dir)         // windows
	t.Setenv("XDG_CONFIG_HOME", dir) // linux
	t.Setenv("HOME", dir)            // darwin: $HOME/Library/Application Support
	return dir
}

// Concurrent first runs must agree on one set of secrets: before the lock,
// each generated its own and the last save won, leaving earlier callers
// holding keys that no longer matched dev.json.
func TestLoadOrInitDevConfigConcurrentAgree(t *testing.T) {
	isolateConfigDir(t)
	const n = 16
	got := make([]*devConfig, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cfg, _, err := loadOrInitDevConfig()
			if err != nil {
				t.Errorf("loadOrInitDevConfig: %v", err)
				return
			}
			got[i] = cfg
		}()
	}
	wg.Wait()
	path, err := devConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	disk, err := readDevConfig(path)
	if err != nil || disk == nil {
		t.Fatalf("read dev.json: %v", err)
	}
	for i, cfg := range got {
		if cfg == nil {
			continue
		}
		if cfg.TokenSecret != disk.TokenSecret || cfg.GrantKeySeed != disk.GrantKeySeed || cfg.EpochKeySeed != disk.EpochKeySeed {
			t.Errorf("caller %d holds secrets that differ from dev.json", i)
		}
	}
}

// Two processes holding stale copies each change a different field; both
// changes must survive (a plain save of a stale copy reverted the other).
func TestUpdateDevConfigKeepsOtherWriters(t *testing.T) {
	isolateConfigDir(t)
	a, path, err := loadOrInitDevConfig()
	if err != nil {
		t.Fatal(err)
	}
	b := *a // second process, loaded at the same time

	if err := updateDevConfig(path, a, func(c *devConfig) (bool, error) {
		c.TenantID = "tenant-from-a"
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := updateDevConfig(path, &b, func(c *devConfig) (bool, error) {
		c.DBPort = 54321
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}

	disk, err := readDevConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if disk.TenantID != "tenant-from-a" || disk.DBPort != 54321 {
		t.Errorf("lost update: tenant %q port %d", disk.TenantID, disk.DBPort)
	}
	if b.TenantID != "tenant-from-a" {
		t.Errorf("caller's copy not refreshed from disk: tenant %q", b.TenantID)
	}
}

// A user-edited field (Slack creds) survives a concurrent `up` update.
func TestUpdateDevConfigConcurrentFields(t *testing.T) {
	isolateConfigDir(t)
	base, path, err := loadOrInitDevConfig()
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mem := *base
			err := updateDevConfig(path, &mem, func(c *devConfig) (bool, error) {
				switch i % 3 {
				case 0:
					c.SlackChannel = "#approvals"
				case 1:
					c.DBPort = 6000
				default:
					if c.TenantID == "" {
						c.TenantID = "t"
					}
				}
				return true, nil
			})
			if err != nil {
				t.Errorf("update: %v", err)
			}
		}()
	}
	wg.Wait()
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	var disk devConfig
	if err := json.Unmarshal(raw, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.SlackChannel != "#approvals" || disk.DBPort != 6000 || disk.TenantID != "t" {
		t.Errorf("lost update: %+v", disk)
	}
}
