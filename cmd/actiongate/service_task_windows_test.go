//go:build windows

package main

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestCurrentAccountIsDomainQualified(t *testing.T) {
	account, err := currentAccount()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(account, `\`) {
		t.Fatalf("account %q is not DOMAIN\\user", account)
	}
}

// The definition must be well-formed XML and carry paths with spaces and
// XML-special characters through intact.
func TestTaskXML(t *testing.T) {
	exe := `C:\Users\A & B <x>\bin\actiongate.exe`
	cfg := `C:\Users\A & B <x>\AppData\Roaming\actiongate\dev.json`
	doc := taskXML(`PC\A & B`, exe, cfg)

	var parsed struct {
		Principals struct {
			Principal struct {
				UserId    string
				LogonType string
				RunLevel  string
			}
		}
		Settings struct {
			ExecutionTimeLimit         string
			StopIfGoingOnBatteries     string
			DisallowStartIfOnBatteries string
		}
		Actions struct {
			Exec struct {
				Command   string
				Arguments string
			}
		}
	}
	// encoding/xml rejects a UTF-16 declaration on a Go string; parse the body.
	body := doc[strings.Index(doc, "<Task"):]
	if err := xml.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("task XML is not well-formed: %v", err)
	}
	p := parsed.Principals.Principal
	if p.UserId != `PC\A & B` || p.LogonType != "InteractiveToken" || p.RunLevel != "LeastPrivilege" {
		t.Errorf("principal = %+v", p)
	}
	s := parsed.Settings
	if s.ExecutionTimeLimit != "PT0S" || s.StopIfGoingOnBatteries != "false" || s.DisallowStartIfOnBatteries != "false" {
		t.Errorf("settings = %+v", s)
	}
	want := `--headless "` + exe + `" service run -config "` + cfg + `"`
	if parsed.Actions.Exec.Arguments != want {
		t.Errorf("arguments = %q, want %q", parsed.Actions.Exec.Arguments, want)
	}
	if !strings.HasSuffix(parsed.Actions.Exec.Command, `conhost.exe`) {
		t.Errorf("command = %q", parsed.Actions.Exec.Command)
	}
}

func TestWriteUTF16(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.xml")
	if err := writeUTF16(path, "aé"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if raw[0] != 0xFF || raw[1] != 0xFE {
		t.Fatalf("missing UTF-16LE BOM: % x", raw[:2])
	}
	u := make([]uint16, (len(raw)-2)/2)
	for i := range u {
		u[i] = uint16(raw[2+2*i]) | uint16(raw[3+2*i])<<8
	}
	if got := string(utf16.Decode(u)); got != "aé" {
		t.Errorf("round trip = %q", got)
	}
}
