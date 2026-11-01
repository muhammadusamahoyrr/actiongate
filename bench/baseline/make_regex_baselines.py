"""Generate the regex baseline policies used in the paper.

regex-strong.json   strong regex, written with knowledge of the development set
                    and held-out A, before the probe set existed.
regex-tuned.json    the same rules after one tuning pass on real traffic
                    (all five edits below).
regex-matched.json  regex-tuned plus the analyzer's exact vocabulary: every
                    secret file name and destructive verb the analyzer knows,
                    so that the remaining gap to facts is due to structure
                    (parsing, readers, context), not to word lists.
regex-matched-untuned.json  regex-strong plus the analyzer's vocabulary.
ablation/regex-t1..t5.json  cumulative tuning edits, for the recall-vs-friction
                    curve: t1 eval only in command position, t2 no $(curl)
                    capture, t3 -EncodedCommand only after powershell/pwsh,
                    t4 no variable-named commands, t5 secret names ignored in
                    test/[ ]/ls/--env-file contexts (t5 == regex-tuned).

Run from the repository root: python bench/baseline/make_regex_baselines.py
"""

import json
import os

TEMPLATE = r"(?i)\.(example|sample|template|dist)$"

# --- vocabulary of the original strong regex --------------------------------
SECRET_FILE = r"(?i)((^|[/\x5c])(\.env(\.[a-z0-9_-]+)?|id_(rsa|dsa|ecdsa|ed25519)|\.netrc|\.pgpass|\.git-credentials|credentials)|\.(pem|key|p12|pfx))$"
SECRET_SHELL = r"""(?i)((^|[\s'"/\x5c=@])\.env(\.(local|production|prod|staging|development|dev|test))?(['"\s;|&)*]|$)|id_(rsa|dsa|ecdsa|ed25519)(['"\s;|&)*]|$)|\.aws[/\x5c]credentials|\.netrc|\.git-credentials|\.(pem|key)(['"\s;|&)]|$))"""
DESTRUCTIVE = r"""(?i)(\brm\s+(-[a-z]*r[a-z]*|--recursive)|\brm\s+(-[a-z]+\s+)+-[a-z]*r|git\s+(-c\s+\S+\s+)?push\b[^;&|]*(\s(-[a-z]*f[a-z]*|--force\S*|--mirror|--delete|-d)\b|\s\+\S|\s:\S)|git\s+reset\s+--hard|git\s+clean\s+-[a-z]*f|git\s+branch\s+-d\b|\bfind\b[^;&|]*\s-delete\b|-exec(dir)?\s+rm\b|\b(drop|truncate)\s+(table|database|schema)\b|delete\s+from\s+\S+\s*;?\s*['"]|\bdd\b[^;&|]*of=/dev/|\bmkfs|\bshred\b|wipefs|rmtree|rmsync|rimraf|remove-item[^;|]*\s-r|\b(rd|rmdir)\s+/s|format-volume|clear-disk|kubectl\s+delete|terraform\s+destroy|docker\s+(system|volume)\s+prune|s3\s+rm\b[^;&|]*--recursive|flushall|flushdb|deletemany|dropdatabase|rsync\b[^;&|]*--delete|:\(\)\s*\{)"""

# --- the analyzer's vocabulary (internal/facts), as regex alternations -------
# Secret names: facts.IsSecretPath and isSecretDir.
SECRET_NAME_V = r"""(\.env(\.[a-z0-9_.-]+)?|[a-z0-9_-]+\.env|\.netrc|\.pgpass|\.git-credentials|\.npmrc|\.pypirc|id_(rsa|dsa|ecdsa|ed25519)|credentials(\.json)?|[^\s'"/\x5c]+\.(pem|key|p12|pfx|jks|keystore)|\.ssh[/\x5c][^\s'"]+)"""
SECRET_FILE_V = r"(?i)((^|[/\x5c])" + SECRET_NAME_V + r")$"
SECRET_SHELL_V = (r"""(?i)((^|[\s'"/\x5c=@<])""" + SECRET_NAME_V + r"""(['"\s;|&)*]|$)|(tar|zip|cp|scp|rsync)\b[^;&|]*\.(ssh|aws|gnupg|kube|docker)(['"\s/;|&)]|$))""")
# Destructive verbs: shell.go command() plus inline-code markers.
DESTRUCTIVE_V = DESTRUCTIVE[:-1] + r"""|git\s+checkout\b[^;&|]*\s\.(\s|$)|git\s+restore\s+\.|git\s+filter-(branch|repo)|git\s+stash\s+clear|truncate\s+[\w."]+|delete\s+from\s+[\w."]+\s*(;|$)|drop\s+(view|index)\b|-exec(dir)?\s+(shred|unlink)\b|docker\s+volume\s+rm|podman\s+(system|volume)\s+prune|\boc\s+delete|tofu\s+destroy|-destroy\b|s3\s+rb\b[^;&|]*--force|(gcloud|az|helm)\b[^;&|]*\s(delete|uninstall)\b|\bdropdb\b|\.(drop|remove)\s*\(|rsync\b[^;&|]*--remove-source-files|remove_dir_all|rm_rf|fileutils\.rm_r|rmdir[^;&|]*recursive|remove-partition|initialize-disk)"""

# --- opaque rule and its tuning edits -----------------------------------------
OPAQUE_PARTS = {
    "pipe_shell": r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b",
    "pipe_interp": r"\|\s*(python3?|node|perl|ruby)\s*(-\s*)?$",
    "eval_any": r"\beval\b",
    "eval_pos": r"(^|[;&|(]\s*)eval\s",
    "iex": r"\biex\b|invoke-expression",
    "enc_any": r"\s-enc(odedcommand)?\b",
    "enc_ps": r"(powershell|pwsh)(\.exe)?\b[^;|]*\s-e(nc|ncodedcommand)?\s",
    "procsubst_curl": r"<\(\s*curl",
    "procsubst_shell": r"\b(ba|z)?sh\s+<\(",
    "curl_capture": r"\$\(\s*curl",
    "var_cmd": r"(^|[;&|]\s*)\$\w+\s",
}
SECRET_CONTEXT_OK = r"""(?i)(\btest\s+-[a-z]\s+\S*\.env|\[\s+-[a-z]\s+\S*\.env|--env-file|\bls\b[^;&|]*\.env)"""
# The analyzer never treats templates or public keys as secrets. A regex over
# the whole command can only approximate this: any template or .pub mention
# exempts the command, so "grep X .env .env.example" is (wrongly) allowed.
SECRET_EXEMPT_V = r"""(?i)(\.env\.(example|sample|template|dist|defaults|schema)\b|\.pub\b)"""

EDITS = ["eval_pos", "no_curl_capture", "enc_ps_only", "no_var_cmd", "secret_context"]


def opaque(edits):
    parts = ["pipe_shell", "pipe_interp", "iex"]
    parts.append("eval_pos" if "eval_pos" in edits else "eval_any")
    parts.append("enc_ps" if "enc_ps_only" in edits else "enc_any")
    if "no_curl_capture" in edits:
        parts.append("procsubst_shell")
    else:
        parts += ["procsubst_curl", "curl_capture"]
    if "no_var_cmd" not in edits:
        parts.append("var_cmd")
    return "(?i)(" + "|".join(OPAQUE_PARTS[p] for p in parts) + ")"


def lit(rx):
    # CEL string literal: escape backslashes and single quotes.
    return "'" + rx.replace("\\", "\\\\").replace("'", "\\'") + "'"


def pack(name, edits, vocab):
    secret_file = SECRET_FILE_V if vocab else SECRET_FILE
    secret_shell_rx = SECRET_SHELL_V if vocab else SECRET_SHELL
    destructive = DESTRUCTIVE_V if vocab else DESTRUCTIVE
    shell = 'tool_name in ["Bash", "bash", "PowerShell"] && has(params.command) && params.command.matches(%s)'
    secret_shell = shell % lit(secret_shell_rx)
    if "secret_context" in edits:
        secret_shell += " && !params.command.matches(%s)" % lit(SECRET_CONTEXT_OK)
    if vocab:
        secret_shell += " && !params.command.matches(%s)" % lit(SECRET_EXEMPT_V)
    return {"default_decision": "allow", "rules": [
        {"id": "deny-secrets-file-tools",
         "description": name + ": secret paths through file tools (templates excluded)",
         "condition": 'tool_name in ["Read", "Edit", "Write", "NotebookEdit", "Grep", "read_file"] && ('
                      '(has(params.file_path) && params.file_path.matches(%s) && !params.file_path.matches(%s)) || '
                      '(has(params.path) && params.path.matches(%s) && !params.path.matches(%s)) || '
                      '(has(params.glob) && params.glob.matches(%s)))'
                      % (lit(secret_file), lit(TEMPLATE), lit(secret_file), lit(TEMPLATE), lit(r"^\.env")),
         "decision": "deny", "risk_classification": "secrets"},
        {"id": "deny-secrets-shell", "description": name + ": secret file names anywhere in a shell command",
         "condition": secret_shell, "decision": "deny", "risk_classification": "secrets"},
        {"id": "approve-destructive-shell",
         "description": name + ": destructive commands with flag variations, case-insensitive SQL, common tools, PowerShell",
         "condition": shell % lit(destructive), "decision": "requires_approval", "risk_classification": "destructive"},
        {"id": "approve-opaque-shell",
         "description": name + ": pipes into shells or interpreters, eval, encoded or downloaded code",
         "condition": shell % lit(opaque(edits)), "decision": "requires_approval", "risk_classification": "opaque"},
    ]}


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(data, indent=2) + "\n")


write("bench/baseline/regex-strong.json", pack("Strong regex baseline", [], False))
write("bench/baseline/regex-tuned.json", pack("Tuned regex baseline", EDITS, False))
write("bench/baseline/regex-matched.json", pack("Vocabulary-matched tuned regex", EDITS, True))
write("bench/baseline/regex-matched-untuned.json", pack("Vocabulary-matched strong regex", [], True))
for i in range(1, len(EDITS) + 1):
    write("bench/baseline/ablation/regex-t%d.json" % i, pack("Regex, tuning edits 1-%d" % i, EDITS[:i], False))
