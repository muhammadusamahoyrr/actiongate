package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/muhammadusamahoyrr/actiongate/internal/facts"
)

// Write-then-run (audit H2): the gateway is the one component that shares
// the agent's filesystem, so it reads the scripts a command would run and
// attaches their text for the control plane's analyzer (facts.ScriptsKey).

const (
	maxScriptBytes = 256 << 10
	maxScripts     = 8
)

// AttachScripts returns a copy of params with the scripts the command runs
// attached under facts.ScriptsKey. Any value the caller put there is
// discarded first: only the gateway may fill it. cwd is the directory the
// command runs in (the hook's working directory).
//
// A script that cannot be read in full — missing (the same command may be
// about to create it), too large, unreadable, or in a directory the
// analyzer could not resolve — is attached with an error, which the
// analyzer treats as opaque. A binary run directly (./build/app) is a
// compiled program, not a script, and is skipped.
func AttachScripts(params map[string]any, tool, cwd string) map[string]any {
	out := make(map[string]any, len(params)+1)
	for k, v := range params {
		if k != facts.ScriptsKey {
			out[k] = v
		}
	}
	scripts := facts.ScriptsRun(tool, out)
	if len(scripts) == 0 {
		return out
	}
	var entries []any
	for i, s := range scripts {
		if i == maxScripts {
			entries = append(entries, map[string]any{
				"path": "(more)", "via": "", "error": fmt.Sprintf("command runs more than %d scripts", maxScripts),
			})
			break
		}
		e := readScript(s, cwd)
		if e != nil {
			entries = append(entries, e)
		}
	}
	if len(entries) > 0 {
		out[facts.ScriptsKey] = entries
	}
	return out
}

func readScript(s facts.Script, cwd string) map[string]any {
	entry := map[string]any{"path": s.Path, "via": s.Via}
	if s.Name != "" {
		entry["name"] = s.Name
	}
	fail := func(msg string) map[string]any {
		entry["error"] = msg
		return entry
	}
	if s.UnknownDir {
		return fail("runs after a cd to a directory that cannot be resolved")
	}
	if s.Uncertain {
		return fail("an option before the script is not modelled, so which file runs is uncertain")
	}
	p := resolveScriptPath(s.Path, cwd)
	// Never copy a secret into the action (it would be stored with it):
	// `source .env` is reported as reading a secret, not attached. The
	// check covers the name as written, the resolved path and, through any
	// symlink, the file actually read (notes.sh -> .env).
	secret := facts.IsSecretPath(s.Path) || facts.IsSecretPath(p)
	if real, err := filepath.EvalSymlinks(p); err == nil {
		secret = secret || facts.IsSecretPath(real)
		p = real
	}
	if secret {
		entry["secret"] = true
		return entry
	}

	if s.Via == "npm" {
		raw, err := readBounded(p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil // no package.json: npm fails, nothing runs
		}
		if err != nil {
			return fail(err.Error())
		}
		var pkg struct {
			Scripts map[string]string `json:"scripts"`
		}
		if err := json.Unmarshal(raw, &pkg); err != nil {
			return fail("package.json does not parse")
		}
		var parts []string
		for _, n := range []string{"pre" + s.Name, s.Name, "post" + s.Name} {
			if body, ok := pkg.Scripts[n]; ok {
				parts = append(parts, body)
			}
		}
		if len(parts) == 0 {
			return nil // unknown script: npm errors out
		}
		entry["content"] = strings.Join(parts, "\n")
		return entry
	}

	raw, err := readBounded(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return fail("does not exist yet (the same command may create it)")
	case err != nil:
		return fail(err.Error())
	}
	head := raw
	if len(head) > 8000 {
		head = head[:8000]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		if s.Via == "exec" {
			return nil // a compiled program run by path, not a script
		}
		return fail("is binary")
	}
	entry["content"] = string(raw)
	return entry
}

func resolveScriptPath(p, cwd string) string {
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	p = filepath.FromSlash(p)
	if filepath.IsAbs(p) || len(p) >= 2 && p[1] == ':' {
		return p
	}
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	return filepath.Join(cwd, p)
}

// readBounded reads a regular file of at most maxScriptBytes.
func readBounded(p string) ([]byte, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, errors.New("is a directory")
	}
	if fi.Size() > maxScriptBytes {
		return nil, fmt.Errorf("is larger than %d KiB", maxScriptBytes>>10)
	}
	f, err := os.Open(filepath.Clean(p))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, maxScriptBytes+1)
	n, err := f.Read(buf)
	for err == nil && n < len(buf) {
		var m int
		m, err = f.Read(buf[n:])
		n += m
	}
	if n > maxScriptBytes {
		return nil, fmt.Errorf("is larger than %d KiB", maxScriptBytes>>10)
	}
	return buf[:n], nil
}
