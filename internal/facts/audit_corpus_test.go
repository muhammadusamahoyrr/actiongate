package facts

import "testing"

// The audit's bypass corpus (H1 destructive spellings, H3 secret reads,
// H5 inline code), every one confirmed ALLOWED by the default pack on
// fabf586. Each must now produce the fact a policy gates on — or opaque,
// which the default pack sends to a human. This list only ever grows.
func TestAuditBypassCorpus(t *testing.T) {
	type want int
	const (
		destructive want = iota
		secret
		gated // destructive, secret or opaque: anything the default pack holds
	)
	cases := []struct {
		id, tool, cmd string
		want          want
	}{
		// H1: spellings that hid destructive commands.
		{"ansi-c quoting", "Bash", `$'\x72\x6d' -rf ~`, gated},
		{"glob in command name", "Bash", `/bin/r? -rf ~`, gated},
		{"computed flag", "Bash", `rm $(echo -rf) ~`, gated},
		{"computed flag in quotes", "Bash", `rm "-$(echo r)f" ~`, gated},
		{"rm --rec abbreviation", "Bash", `rm --rec -f ~`, destructive},
		{"git reset --har", "Bash", `git reset --har`, destructive},
		{"git push --forc", "Bash", `git push --forc origin main`, destructive},
		{"git push --force-with", "Bash", `git push --force-with origin main`, destructive},
		{"git clean --forc", "Bash", `git clean --forc -d`, destructive},
		{"git push --del", "Bash", `git push origin --del main`, destructive},
		{"bash -o before -c", "Bash", `bash -o pipefail -c 'rm -rf ~'`, destructive},
		{"bash -O before -c", "Bash", `bash -O extglob -c 'rm -rf ~'`, destructive},
		{"python -Bc cluster", "Bash", `python3 -Bc "import shutil; shutil.rmtree('/home/x')"`, destructive},
		{"python -W value then -c", "Bash", `python3 -W ignore -c "import shutil; shutil.rmtree('/home/x')"`, destructive},
		{"perl -we cluster", "Bash", `perl -we 'system("rm -rf /x")'`, destructive},
		{"subprocess list form", "Bash", `python3 -c "import subprocess; subprocess.run(['rm','-rf','/x'])"`, destructive},
		{"awk system", "Bash", `awk 'BEGIN{system("rm -rf /x")}'`, gated},
		{"sed e command", "Bash", `sed 'e rm -rf /x' f`, gated},
		{"env -S", "Bash", `env -S 'rm -rf ~'`, destructive},
		{"sudo --user", "Bash", `sudo --user root rm -rf /`, destructive},
		{"busybox", "Bash", `busybox rm -rf /`, destructive},
		{"su -c", "Bash", `su -c 'rm -rf /'`, destructive},
		{"ssh remote", "Bash", `ssh host 'rm -rf /srv'`, destructive},
		{"find -exec sh -c", "Bash", `find . -exec sh -c 'rm -rf "$1"' _ {} \;`, destructive},
		{"find -exec sudo rm", "Bash", `find . -exec sudo rm -rf {} +`, destructive},
		{"kubectl -n before delete", "Bash", `kubectl -n prod delete ns app`, destructive},
		{"git -c alias", "Bash", `git -c alias.p='push --force' p`, gated},
		{"git config alias", "Bash", `git config alias.x '!rm -rf ~'`, gated},
		{"PowerShell running bash", "PowerShell", `bash -c 'rm -rf ~'`, destructive},
		{"rm -f *", "Bash", `rm -f *`, destructive},
		{"docker compose down -v", "Bash", `docker compose down -v`, destructive},
		{"aws terminate", "Bash", `aws ec2 terminate-instances --instance-ids i-1`, destructive},
		{"DELETE WHERE true", "Bash", `psql -c "DELETE FROM t WHERE true"`, destructive},
		{"UPDATE without WHERE", "Bash", `psql -c "UPDATE t SET pw=null"`, destructive},
		{"chmod -R 000", "Bash", `chmod -R 000 ~`, destructive},
		{"PowerShell Directory.Delete", "PowerShell", `[IO.Directory]::Delete('C:\data', $true)`, destructive},

		// Found in review of the fixes above.
		{"sudo env -S", "Bash", `sudo env -S 'rm -rf ~'`, destructive},
		{"env -iS cluster", "Bash", `env -iS 'rm -rf ~'`, destructive},
		{"env -u X -S", "Bash", `env -u HOME -S 'rm -rf ~'`, destructive},
		{"env --split-string=", "Bash", `env --split-string='rm -rf ~'`, destructive},
		{"perl -M then -e", "Bash", `perl -MPOSIX -e 'system("rm -rf /x")'`, destructive},
		{"perl -x does not eat -e", "Bash", `perl -x -e 'system("rm -rf /x")'`, destructive},
		{"node -pe", "Bash", `node -pe "require('child_process').execSync('rm -rf /x')"`, destructive},
		{"php -B", "Bash", `php -B 'system("rm -rf /x");'`, destructive},
		{"awk concatenation", "Bash", `awk 'BEGIN{system("rm" " -rf ~")}'`, gated},
		{"awk pipe", "Bash", `awk 'BEGIN{print "x" | "sh"}'`, gated},
		{"gawk --source", "Bash", `gawk --source 'BEGIN{system("rm -rf ~")}'`, destructive},
		{"sed address 1e", "Bash", `sed '1e rm -rf /x' f`, gated},
		{"sed range e", "Bash", `sed '/a/,/b/e id' f`, gated},
		{"sed -ne cluster", "Bash", `sed -ne 'e rm -rf /x' f`, gated},
		{"sed --expression=", "Bash", `sed --expression='e rm -rf /x' f`, gated},
		{"su -lc cluster", "Bash", `su -lc 'rm -rf /'`, destructive},
		{"su --command=", "Bash", `su --command='rm -rf /'`, destructive},
		{"runuser -u X --", "Bash", `runuser -u root -- rm -rf /`, destructive},
		{"flock FILE cmd", "Bash", `flock /tmp/l rm -rf ~`, destructive},
		{"flock -c", "Bash", `flock /tmp/l -c 'rm -rf ~'`, destructive},
		{"chrt prio cmd", "Bash", `chrt 10 rm -rf ~`, destructive},
		{"taskset mask cmd", "Bash", `taskset 0x1 rm -rf ~`, destructive},
		{"ionice -c 3 cmd", "Bash", `ionice -c 3 rm -rf ~`, destructive},
		{"PowerShell bash -o", "PowerShell", `bash -o pipefail -c 'rm -rf ~'`, destructive},

		// H3: secret reads.
		{"ln then cat", "Bash", `ln -s .env notes.txt && cat notes.txt`, secret},
		{"cat .e*", "Bash", `cat .e*`, secret},
		{"cp -t", "Bash", `cp -t /tmp/out .env`, secret},
		{"printf-built name", "Bash", `cat $(printf '.e%sv' n)`, gated},
		{"base64-built name", "Bash", `cat "$(echo LmVudg== | base64 -d)"`, gated},
		{"perl -ne", "Bash", `perl -ne 'print' .env`, secret},
		{"vim -es", "Bash", `vim -es -c '%p' .env`, secret},
		{"printenv", "Bash", `printenv`, secret},
		{"/proc/self/environ", "Bash", `cat /proc/self/environ`, secret},
		{".envrc", "Bash", `cat .envrc`, secret},
		{"kube config", "Bash", `cat ~/.kube/config`, secret},
		{"docker config", "Bash", `cat ~/.docker/config.json`, secret},
		{"cargo credentials", "Bash", `cat ~/.cargo/credentials.toml`, secret},
		{"terraform.tfvars", "Bash", `cat terraform.tfvars`, secret},
		{"gcloud ADC", "Bash", `cat application_default_credentials.json`, secret},
		{"append to authorized_keys", "Bash", `echo key >> ~/.ssh/authorized_keys`, secret},

		// H5: inline code built at run time.
		{"inline dynamic open", "Bash", `python3 -c "open('.e'+'nv').read()"`, gated},
	}
	for _, c := range cases {
		f := Derive(c.tool, map[string]any{"command": c.cmd})
		ok := false
		switch c.want {
		case destructive:
			ok = f.Destructive
		case secret:
			ok = f.SecretAccess
		case gated:
			ok = f.Destructive || f.SecretAccess || f.Opaque
		}
		if !ok {
			t.Errorf("%-28s %s %q: facts %+v", c.id, c.tool, c.cmd, f)
		}
	}
}

// Ordinary commands must stay ungated: the fixes must not turn the
// analyzer into a wall of approvals.
func TestAuditCorpusLookAlikesStayClean(t *testing.T) {
	for _, cmd := range []string{
		"rm build/out.o", "rm -f *.log", "git push origin main", "git reset --soft HEAD~1",
		"git push --force-with-lease=main:abc origin main", // still a force push: covered elsewhere
		"bash -o pipefail -c 'ls -la'", "python3 -Bc 'print(1)'", "find . -name '*.go' -exec gofmt -l {} +",
		"kubectl -n prod get pods", "docker compose up -d", "docker compose down",
		"aws ec2 describe-instances", "psql -c 'SELECT 1'", `psql -c "DELETE FROM t WHERE id = 3"`,
		"chmod 644 file.txt", "cat README.md", "cat .env.example", "env", "sudo apt-get update",
		"ssh host uptime", "awk '{print $1}' f", "sed -n 1p f", "cat ~/.kube/config.example",
		`python3 -c "print('a' + 'b')"`, `node -e "console.log([1,2].join(','))"`, "git commit -m \"$(date)\"",
		"sed 's/one two/three/' f", "cat \"$FILE\"",
		"sed -i 's/version/edition/' f", "sed -e 's/e/E/g' f", "awk '$1 == \"x\" || $2 == \"y\" {print}' f",
		"sed '/error/d' log", "env FOO=1 go test ./...", "node -p '1+1'", "perl -pi -e 's/a/b/' f",
	} {
		f := Derive("Bash", map[string]any{"command": cmd})
		if cmd == "git push --force-with-lease=main:abc origin main" {
			continue // a force push is destructive by design
		}
		if cmd == "env" {
			if f.Destructive || f.Opaque {
				t.Errorf("%q: %+v", cmd, f)
			}
			continue
		}
		if f.Destructive || f.SecretAccess || f.Opaque {
			t.Errorf("look-alike gated: %q: %+v", cmd, f)
		}
	}
}
