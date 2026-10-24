# Hooks

A **hook** is code that runs automatically at a fixed point, before or after something happens. It can stop the action or change its result. This project uses hooks in two places:

1. **In the app:** around every model call and every tool call made by the four agents ([`assistant/hooks.py`](../assistant/hooks.py)).
2. **For AI coding agents** such as Claude Code that edit this repository ([`.claude/settings.json`](../.claude/settings.json) and [`.claude/hooks/guard.py`](../.claude/hooks/guard.py)).

## In-app hooks

| Point | Signature | Can |
|---|---|---|
| `pre_model` | `hook(agent, request)` | Stop the request (raise) |
| `post_model` | `hook(agent, response, usage)` | Observe, e.g. charge the budget |
| `pre_tool` | `hook(call)` | Block the call (raise `HookBlock`); the reason goes back to the model as an error it can fix |
| `post_tool` | `hook(call, content, is_error)` | Return a changed result |

`default_hooks(redactor, budget)` registers the standard set for a session. The order matters: validation runs before path checks, and leak detection runs before redaction.

| Point | Hook | Guardrail | What it does |
|---|---|---|---|
| pre_model | `budget_check` | G6 | Stops the call if the turn or session budget is used up |
| pre_model | `outbound_scan` | G4 | Checks every string in the system prompt, tool definitions and history (raw, not JSON-escaped) for every stored secret. A hit raises `PrivacyLeak`, and nothing is sent |
| post_model | `budget_charge` | G6 | Adds the call's tokens to both budgets |
| pre_tool | `known_tool` | G3 | Refuses tools the agent doesn't have (built into the runtime) |
| pre_tool | `schema` | G2 | Validates the arguments against the JSON schema |
| pre_tool | `path_guard` | G8 | Refuses path-like arguments outside the project |
| pre_tool | `call_limit` | G7 | Refuses calls beyond 30 per agent run |
| post_tool | `leak_detector` | G5 | Flags a raw result that contains a stored secret |
| post_tool | `redact` | G4 | Replaces secrets, other emails and card numbers |
| post_tool | `size_cap` | G7 | Truncates results over 20,000 characters |

Every hook that blocks or changes something emits a `hook` event (`{"type": "hook", "hook", "action": "blocked" | "modified" | "flagged", ...}`). It appears in the turn's trace, in `--verbose` output and in the harness reports.

**Adding a hook:** append a function to the right list in `default_hooks`, emit an event when it acts, and add a test that shows it blocking the bad case and allowing the benign one.

## Claude Code hooks

Claude Code reads hooks from `.claude/settings.json`. This project registers one **PreToolUse** hook for the `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `Bash` and `PowerShell` tools. Before each such call, Claude Code runs the hook command, passing the pending call as JSON on stdin. The hook replies with an exit code:
- **0** allows the call.
- **2** blocks it, and the message on stderr is shown to the agent.

The command runs the project's own `.venv` Python; the `python` on PATH can be a Microsoft Store placeholder. If that Python isn't found, the command exits 2, so the guard **fails closed** instead of silently allowing everything. The command uses POSIX shell syntax, which Claude Code's hook runner uses on Windows through Git Bash; I haven't checked this in a live Claude Code session.

`guard.py` uses no `os` module. It **blocks**:

| Rule | Examples |
|---|---|
| File writes and edits outside the project | `Write` to `C:/elsewhere/x.txt`, `../x.txt`, `~/x.txt` |
| Any file deletion (CLAUDE.md: never delete) | `rm`, `rmdir`, `del`, `erase`, `rd`, `Remove-Item`, `unlink`, `shred`, `git clean`, `git rm`, `find -delete`, `[IO.File]::Delete`, `os.remove`, `shutil.rmtree`, `.unlink(` |
| Running strings as commands (can hide a deletion) | `iex "..."`, `Invoke-Expression` |
| Leaving the project | `cd ..`, `Set-Location C:/`, `pushd /tmp` |
| Writing outside through the shell | `> ../out.txt`, `Copy-Item a C:/x`, `cp a ~/a`, `mv a ..`, `mkdir ../new`, `tee /elsewhere/log`, UNC shares (`\\server\share`), `$HOME`, `$env:...`, `%VAR%` paths, Python `open(..., 'w')` |

It **allows** normal work inside the project, such as `git status`, `pytest -q` and `echo x > .cache/out.txt`. It also allows reads elsewhere, because CLAUDE.md governs reads; the hook targets irreversible actions.

**Limits:** this is pattern matching, not a sandbox. A command can hide a path in a variable or an encoding. The hook catches honest mistakes and obvious attempts. It applies to Claude Code sessions opened in this folder.

**Tests:** [`tests/test_claude_hook.py`](../tests/test_claude_hook.py) runs the script on 30+ sample calls, including the real exit-code protocol as a subprocess.
