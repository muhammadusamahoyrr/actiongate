---
name: protect
description: Protect this project with actiongate (installs the PreToolUse enforcement hook and applies a policy pack)
---

Protect the current project with actiongate.

1. Check the binaries exist: run `actiongate service status` (or `actiongate --help`). If the command is not found, tell the user to install actiongate first — https://github.com/muhammadusamahoyrr/actiongate#quickstart-60-seconds — and stop.
2. If the control plane is not healthy, tell the user to run `actiongate up` (or `actiongate service start`) first and stop — installing the hook while the stack is down would immediately fail closed.
3. Run `actiongate protect claude-code -project .` — if the user asked for a stricter or looser posture, pass `-pack paranoid` or `-pack relaxed` ($ARGUMENTS may name a pack).
4. Show the user the command output and remind them: the hook takes effect for **new** Claude Code sessions in this project; secrets reads will be blocked and destructive commands will wait for approval.
