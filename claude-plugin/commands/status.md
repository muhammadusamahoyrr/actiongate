---
name: status
description: Check whether actiongate is running and this project is protected
---

Report actiongate's health for this project:

1. Run `actiongate service status` and show the result.
2. Check whether `.claude/settings.local.json` in the project contains an `ag-hook` PreToolUse entry — that is what "protected" means. Report protected/unprotected accordingly.
3. If the control plane is down and the project IS protected, warn clearly: governed tools (Read/Edit/Write/Bash/Grep) are failing closed right now; `actiongate service start` or `actiongate up` fixes it.
