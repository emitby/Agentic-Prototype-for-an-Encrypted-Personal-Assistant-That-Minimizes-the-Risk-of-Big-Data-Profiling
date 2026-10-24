"""Claude Code PreToolUse hook: keep AI coding agents inside this project and stop deletions.

Claude Code runs this script before every Write, Edit, MultiEdit, NotebookEdit, Bash and
PowerShell tool call made by an AI coding agent working in this repository (see
``.claude/settings.json``). It receives the pending call as JSON on stdin, for example::

    {"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": "...",
     "tool_input": {"file_path": "C:/elsewhere/notes.txt", "content": "..."}}

It **blocks** (exit code 2, with the reason on stderr, which Claude Code shows to the agent):

* file edits or writes whose path resolves outside the project folder;
* shell commands that delete files: ``rm``, ``rmdir``, ``del``, ``erase``, ``rd``,
  ``Remove-Item`` (and its aliases ``ri``/``rmdir``), ``unlink``, ``shred``, ``git clean``,
  ``git rm``, ``find -delete``, .NET ``[IO.File]::Delete``, and Python deletion calls
  (``os.remove``, ``shutil.rmtree``, ``.unlink(``);
* running strings as commands (``iex`` / ``Invoke-Expression``), which can hide any of the above;
* shell commands that change directory (``cd``, ``Set-Location``, ``pushd``) to, or write
  (``>``, ``>>``, ``Out-File``, ``Set-Content``, ``Add-Content``, ``Copy-Item``,
  ``Move-Item``, ``New-Item``, ``cp``, ``mv``, ``mkdir``, ``touch``, ``tee``, Python
  ``open(..., "w")``) to, a path outside the project. Paths built from ``~``, ``$HOME``,
  ``$env:...``, ``%VAR%`` or a UNC share count as outside.

If the hook can't find the project's Python, the command in ``settings.json`` exits 2,
so the guard fails closed rather than silently allowing everything.

Everything else is allowed (exit code 0). The rules mirror CLAUDE.md's guardrails and the
app's own ``path_guard`` hook. Limits: this is pattern matching, not a sandbox; a command
can hide a path (variables, encodings). It catches honest mistakes and obvious attempts.

No ``os`` module is used (CLAUDE.md); the project root is this file's grandparent folder.
"""

import json
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[2]

DELETE_RE = re.compile(
    r"(?:^|[\s;&|(`])(?:rm|rmdir|del|erase|rd|ri|unlink|shred|Remove-Item)(?=\s|$)"
    r"|\bgit\s+(?:clean|rm)\b|\bos\.(?:remove|unlink|rmdir)\b|\bshutil\.rmtree\b|\.unlink\(|\.rmdir\("
    r"|\s-delete\b"                                              # find ... -delete
    r"|\[(?:System\.)?IO\.(?:File|Directory)\]::Delete",          # .NET deletion from PowerShell
    re.IGNORECASE)
# Running a string as a command can hide anything (e.g. iex "Remove-Item x"), so it's refused.
DYNAMIC_RE = re.compile(r"(?:^|[\s;&|(])(?:iex|Invoke-Expression|Invoke-Command)(?=\s|$)", re.IGNORECASE)
CD_RE = re.compile(r"(?:^|[;&|]\s*)(?:cd|Set-Location|sl|pushd|chdir)\s+(\"[^\"]+\"|'[^']+'|\S+)", re.IGNORECASE)
WRITE_VERB_RE = re.compile(r"\b(?:Out-File|Set-Content|Add-Content|Copy-Item|Move-Item|New-Item|cp|mv|mkdir|md|"
                           r"touch|tee|copy|move)\b|\bopen\([^)]*['\"][wax]", re.IGNORECASE)
REDIRECT_RE = re.compile(r"\d?>{1,2}\s*(\"[^\"]+\"|'[^']+'|[^\s;&|]+)")
# Path tokens: Windows drive paths (not the "s://" inside a URL), UNC shares (\\server),
# POSIX/Git-Bash absolute paths (not URL paths), ~ paths, $HOME / $env: / %VAR% paths,
# ../ escapes and a bare "..".
PATH_TOKEN_RE = re.compile(
    r"\"(?<![\w/])[A-Za-z]:[\\/][^\"]*\"|'[A-Za-z]:[\\/][^']*'|(?<![\w/])[A-Za-z]:[\\/](?!/)[^\s;&|\"')]*"
    r"|\\\\[^\s;&|\"')]+|(?<![\w.:/])/[^\s;&|\"')]+|~[\\/]?[^\s;&|\"')]*"
    r"|\$(?:HOME|env:\w+|\{HOME\})[^\s;&|\"')]*|%\w+%[^\s;&|\"')]*"
    r"|(?:\.\.[\\/])+[^\s;&|\"')]*|(?<![\w.])\.\.(?=[\s;&|\"')]|$)")
DEVICE_NULLS = {"/dev/null", "nul", "$null"}


def to_path(token, cwd):
    """Turn a command-line path token into an absolute Path (Git Bash ``/c/...`` becomes ``C:/...``).

    Args:
        token: The raw token (quotes allowed).
        cwd: Directory relative paths are taken from.

    Returns:
        The resolved Path, or ``None`` for paths that depend on the environment or another
        machine: ``~``, ``$HOME``, ``$env:...``, ``%VAR%`` and UNC shares (``\\\\server``).
        Those are treated as outside: resolving them would mean reading system settings,
        which CLAUDE.md forbids, and nothing in this project needs them.
    """
    t = token.strip("\"'")
    if t.startswith(("~", "$", "%", "\\\\")):
        return None
    m = re.match(r"^/([a-zA-Z])(/.*)?$", t)
    if m:
        t = f"{m.group(1)}:{m.group(2) or '/'}"
    p = Path(t)
    return (p if p.is_absolute() else Path(cwd) / p).resolve()


def inside(path):
    """True if ``path`` is the project folder or inside it (``None``, a ``~`` path, is outside)."""
    return path is not None and (path == PROJECT or PROJECT in path.parents)


def check_command(command, cwd):
    """Decide whether a shell command is allowed.

    Args:
        command: The Bash or PowerShell command text.
        cwd: The session's working directory.

    Returns:
        ``None`` if allowed, otherwise the reason it's blocked.
    """
    if DELETE_RE.search(command):
        return "Deleting files is not allowed in this project (CLAUDE.md: never delete files)."
    if DYNAMIC_RE.search(command):
        return "Running strings as commands (iex / Invoke-Expression) is not allowed: it can hide deletions."
    for m in CD_RE.finditer(command):
        target = m.group(1)
        if target not in ("-", "~-") and not inside(to_path(target, cwd)):
            return f"Changing directory outside the project is not allowed: {target}"
    for m in REDIRECT_RE.finditer(command):
        target = m.group(1)
        if target.strip("\"'").lower() not in DEVICE_NULLS and not target.startswith("&") \
                and not inside(to_path(target, cwd)):
            return f"Writing outside the project is not allowed: {target}"
    if WRITE_VERB_RE.search(command):
        for token in PATH_TOKEN_RE.findall(command):
            if token.strip("\"'").lower() in DEVICE_NULLS:
                continue
            if not inside(to_path(token, cwd)):
                return f"File operations outside the project are not allowed: {token}"
    return None


def decide(payload):
    """Decide one PreToolUse call.

    Args:
        payload: The JSON object Claude Code sends on stdin.

    Returns:
        ``None`` to allow, or the reason to block.
    """
    tool = payload.get("tool_name", "")
    data = payload.get("tool_input") or {}
    cwd = payload.get("cwd") or str(PROJECT)
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        target = data.get("file_path") or data.get("notebook_path") or ""
        if target and not inside(to_path(target, cwd)):
            return f"Writing outside the project folder ({PROJECT}) is not allowed: {target}"
        return None
    if tool in ("Bash", "PowerShell"):
        return check_command(data.get("command", ""), cwd)
    return None


def main():
    """Read the hook payload from stdin; exit 2 with a reason to block, 0 to allow."""
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        return 0          # not a hook payload we understand: don't interfere
    reason = decide(payload)
    if reason:
        print(f"Blocked by project guard hook: {reason}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
