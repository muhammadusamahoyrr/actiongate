"""Convert public DataClaw session exports into agbench call records.

Usage: python bench/tools/dataclaw_calls.py EXPORTS_DIR OUT.jsonl
       python bench/tools/dataclaw_calls.py --raw RAW_DIR OUT.jsonl
         (raw ~/.claude/projects transcripts or Codex rollouts, one
          sub-directory per uploaded dataset)

EXPORTS_DIR holds one sub-directory per Hugging Face dataset, named
OWNER__DATASET (as written by fetch). Each output line is

  {"dev": OWNER, "session": ID, "agent": "claude-code"|"codex"|"gemini",
   "tool": "Bash"|"Read"|..., "params": {...}, "complete": true|false}

"complete" is false when the export stored the tool input as a string cut
at about 300 characters (older DataClaw versions); such a call cannot be
evaluated faithfully. Exports that repeat another export's sessions are
counted once, under the owner that sorts first.
"""

import ast
import json
import os
import shlex
import sys

SHELL = {"Bash": "claude-code", "PowerShell": "claude-code", "exec_command": "codex",
         "shell": "codex", "local_shell": "codex", "run_shell_command": "gemini"}
FILE_TOOLS = {"Read", "Edit", "Write", "NotebookEdit", "Grep"}


def parse_input(raw):
    """Returns (dict, complete)."""
    if isinstance(raw, dict):
        return raw, True
    if not isinstance(raw, str):
        return None, False
    # Exports that store inputs as strings are the older, cutting format. Even
    # a short call from them is marked incomplete here; the secondary analysis
    # (agbench -maxlen) re-admits short commands from every export alike.
    complete = False
    s = raw.strip()
    if s.startswith("{"):
        for parse in (json.loads, ast.literal_eval):
            try:
                v = parse(s)
                if isinstance(v, dict):
                    return v, complete
            except Exception:
                pass
        return None, False
    return {"command": raw}, complete


def shell_params(name, inp):
    c = inp.get("command", inp.get("cmd"))
    if isinstance(c, list):
        argv = [str(x) for x in c]
        if len(argv) >= 3 and os.path.basename(argv[0]) in ("bash", "sh", "zsh") and argv[1] in ("-c", "-lc"):
            c = argv[2]
        else:
            c = " ".join(argv)
    if not isinstance(c, str):
        return None
    if name != "Bash" and c.startswith(("/bin/", "/usr/bin/", "bash ", "zsh ", "sh ")):
        # Codex logs some commands as one string: /bin/zsh -lc "..."
        try:
            argv = shlex.split(c)
            if len(argv) == 3 and os.path.basename(argv[0]) in ("bash", "sh", "zsh") and argv[1] in ("-c", "-lc"):
                c = argv[2]
        except ValueError:
            pass
    tool = "PowerShell" if name == "PowerShell" else "Bash"
    return tool, {"command": c}


def raw_calls(path):
    """Yields (session, agent, tool, params) from one raw Claude Code
    transcript (~/.claude/projects/*.jsonl) or Codex rollout file."""
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            o = json.loads(line)
        except Exception:
            continue
        if not isinstance(o, dict):
            continue
        if o.get("type") == "assistant":  # Claude Code
            sid = o.get("sessionId") or ""
            content = (o.get("message") or {}).get("content")
            for b in content if isinstance(content, list) else []:
                if not isinstance(b, dict) or b.get("type") != "tool_use":
                    continue
                name, inp = b.get("name"), b.get("input")
                if not isinstance(inp, dict):
                    continue
                if name in ("Bash", "PowerShell"):
                    r = shell_params(name, inp)
                    if r:
                        yield sid, "claude-code", r[0], r[1]
                elif name in FILE_TOOLS:
                    yield sid, "claude-code", name, inp
        elif o.get("type") == "message":  # Cursor agent export
            m = o.get("message") or {}
            content = m.get("content")
            for b in content if m.get("role") == "assistant" and isinstance(content, list) else []:
                if isinstance(b, dict) and b.get("type") in ("toolCall", "tool_use") and b.get("name") in ("Shell", "bash", "Bash"):
                    inp = b.get("arguments") or b.get("input")
                    r = shell_params("Bash", inp) if isinstance(inp, dict) else None
                    if r:
                        yield o.get("sessionId") or "", "cursor", r[0], r[1]
        elif o.get("type") == "response_item":  # Codex rollout
            p = o.get("payload") or {}
            if p.get("type") == "function_call" and p.get("name") in ("shell", "exec_command", "shell_command", "local_shell"):
                args = p.get("arguments")
                if isinstance(args, str):
                    try:
                        args = json.loads(args or "{}")
                    except Exception:
                        continue
                r = shell_params("exec_command", args) if isinstance(args, dict) else None
                if r:
                    yield "", "codex", r[0], r[1]
            elif p.get("type") == "local_shell_call":
                r = shell_params("exec_command", (p.get("action") or {}))
                if r:
                    yield "", "codex", r[0], r[1]


def main_raw(root, out):
    """Raw uploads: one sub-directory per dataset, one transcript per file."""
    n = 0
    with open(out, "w", encoding="utf-8") as w:
        for d in sorted(os.listdir(root)):
            p = os.path.join(root, d)
            if not os.path.isdir(p):
                continue
            owner = d.split("__")[0]
            for f in sorted(os.listdir(p)):
                if not f.endswith(".jsonl"):
                    continue
                for sid, agent, tool, params in raw_calls(os.path.join(p, f)):
                    w.write(json.dumps({"dev": owner, "session": sid or f"{d}/{f}", "agent": agent, "tool": tool,
                                        "params": params, "complete": True}) + "\n")
                    n += 1
    print(json.dumps({"calls": n}))


def main(root, out):
    seen = set()
    n = {"calls": 0, "dup_sessions": 0}
    with open(out, "w", encoding="utf-8") as w:
        for d in sorted(os.listdir(root)):
            p = os.path.join(root, d)
            if not os.path.isdir(p):
                continue
            owner = d.split("__")[0]
            for f in sorted(os.listdir(p)):
                if not f.endswith(".jsonl"):
                    continue
                for line in open(os.path.join(p, f), encoding="utf-8", errors="replace"):
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    sid = o.get("session_id") or ""
                    key = (sid, o.get("start_time"))
                    if sid and key in seen:
                        n["dup_sessions"] += 1
                        continue
                    seen.add(key)
                    for m in o.get("messages") or []:
                        for t in m.get("tool_uses") or []:
                            name = t.get("tool") or t.get("name")
                            if name not in SHELL and name not in FILE_TOOLS:
                                continue
                            inp, complete = parse_input(t.get("input"))
                            if inp is None:
                                continue
                            if name in SHELL:
                                r = shell_params(name, inp)
                                if r is None:
                                    continue
                                tool, params = r
                                agent = SHELL[name]
                            else:
                                tool, params, agent = name, inp, "claude-code"
                            w.write(json.dumps({"dev": owner, "session": sid, "agent": agent, "tool": tool,
                                                "params": params, "complete": complete}) + "\n")
                            n["calls"] += 1
    print(json.dumps(n))


if __name__ == "__main__":
    if sys.argv[1] == "--raw":
        main_raw(sys.argv[2], sys.argv[3])
    else:
        main(sys.argv[1], sys.argv[2])
