//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

// The background control plane runs as a Task Scheduler task that starts
// at sign-in, as the signed-in user:
//
//   - Not LocalSystem. Its files are in the user's %APPDATA%\actiongate,
//     and a SYSTEM process writing there can be steered by links into
//     overwriting system files.
//   - Not a Windows service under the user's account. That needs the
//     account's password, and many accounts have none.
//
// A sign-in task needs no password and no elevation. It runs only while the
// user is signed in, which is when agents run. conhost --headless (Windows
// 10 1809 and later) keeps the console program from opening a window.

const taskName = "actiongate"

func currentAccount() (string, error) {
	n := uint32(256)
	for {
		buf := make([]uint16, n)
		err := windows.GetUserNameEx(windows.NameSamCompatible, &buf[0], &n)
		if err == nil {
			return windows.UTF16ToString(buf[:n]), nil
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) {
			return "", fmt.Errorf("current user: %w", err)
		}
	}
}

func xmlText(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// taskXML is the Task Scheduler definition. The settings that matter:
// no battery stop (laptops), no execution time limit (the default kills a
// task after 72 h), restart on failure, and a single instance.
func taskXML(account, exe, cfgPath string) string {
	args := fmt.Sprintf(`--headless "%s" service run -config "%s"`, exe, cfgPath)
	return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>actiongate control plane: policy decisions, human approvals and the sealed audit log for AI coding agents. While it is down, protected projects fail closed.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>` + xmlText(account) + `</UserId>
      <Delay>PT10S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>` + xmlText(account) + `</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
    </IdleSettings>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%SystemRoot%\System32\conhost.exe</Command>
      <Arguments>` + xmlText(args) + `</Arguments>
    </Exec>
  </Actions>
</Task>
`
}

// writeUTF16 writes s as UTF-16LE with a BOM, the encoding schtasks /XML
// expects for a document that declares encoding="UTF-16".
func writeUTF16(path, s string) error {
	u := utf16.Encode([]rune(s))
	buf := make([]byte, 2+2*len(u))
	buf[0], buf[1] = 0xFF, 0xFE
	for i, c := range u {
		binary.LittleEndian.PutUint16(buf[2+2*i:], c)
	}
	return os.WriteFile(path, buf, 0o600)
}

func schtasks(args ...string) (string, error) {
	// #nosec G204 -- fixed program; the arguments are our own constants and paths.
	out, err := exec.Command("schtasks", args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("schtasks %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func taskInstalled() bool {
	return exec.Command("schtasks", "/Query", "/TN", taskName).Run() == nil
}

func createTask(account, exe, cfgPath string) error {
	dir, err := os.MkdirTemp("", "actiongate-task-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	def := filepath.Join(dir, "task.xml")
	if err := writeUTF16(def, taskXML(account, exe, cfgPath)); err != nil {
		return err
	}
	_, err = schtasks("/Create", "/TN", taskName, "/XML", def)
	return err
}

// legacyServiceInstalled reports a Windows service left by an older
// actiongate, which ran as LocalSystem.
func legacyServiceInstalled() bool {
	return exec.Command("sc", "query", serviceName).Run() == nil
}
