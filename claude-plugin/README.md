# actiongate — Claude Code plugin

Slash commands for the [actiongate](https://github.com/muhammadusamahoyrr/actiongate)
action firewall:

- `/actiongate:protect [paranoid|relaxed]` — install the enforcement hook in
  the current project and apply a policy pack
- `/actiongate:status` — is the stack healthy, is this project protected?
- `/actiongate:tamper-demo` — the "you can't quietly rewrite history" demo

**Prerequisite:** the actiongate binaries must be installed and on PATH
(see the main README's 60-second quickstart). The plugin wraps the CLI; it
does not replace it.

The SessionStart down-stack warning is not part of the plugin — it is
installed directly into the project by `actiongate protect claude-code`
(`ag-hook -warn`), so it protects every user, plugin or not.
