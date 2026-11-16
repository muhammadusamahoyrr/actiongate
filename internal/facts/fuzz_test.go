package facts

import "testing"

// FuzzAnalyzers runs the shell and PowerShell analyzers directly — not
// through Derive, whose recover() would turn a panic into "opaque" and hide
// it — on arbitrary input. Run with: go test -fuzz=FuzzAnalyzers ./internal/facts
func FuzzAnalyzers(f *testing.F) {
	for _, seed := range []string{
		`rm -rf ~`, `$'\x72\x6d' -rf ~`, `/bin/r? -rf ~`, `rm $(echo -rf) ~`, `git push --forc origin main`,
		`bash -o pipefail -c 'rm -rf ~'`, `python3 -Bc "import shutil; shutil.rmtree('/x')"`,
		`awk 'BEGIN{system("rm" " -rf ~")}'`, `sed '/a/,/b/e id' f`, `env -iS 'rm -rf ~'`,
		`find . -exec sh -c 'rm -rf "$1"' _ {} \;`, `su -lc 'rm -rf /'`, `ssh -p 22 host 'rm -rf /srv'`,
		`cat $(printf '.e%sv' n)`, `cp -t /tmp/out .env`, `echo key >> ~/.ssh/authorized_keys`,
		`python3 -c "open('.e'+'nv').read()"`, `[IO.Directory]::Delete('C:\data', $true)`,
		"sed 's/\\/x/y/e' f", `$'\x00\x01\c'`, `flock -c`, `env -S`, `awk 'system(`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, cmd string) {
		_ = ShellWith(cmd, Options{})
		_ = PowerShell(cmd)
		_ = decodeANSIC(cmd)
		_ = sedHasECommand(cmd)
		_ = sedSubstituteExec(cmd)
		_ = Derive("Bash", map[string]any{"command": cmd})
	})
}
