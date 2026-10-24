"""Tests for the Claude Code PreToolUse hook (``.claude/hooks/guard.py``).

The script is loaded as a module for the decision tests, and run as a real process with
JSON on stdin to check the exit-code protocol Claude Code relies on (2 = block, 0 = allow).
"""

import importlib.util
import json
import subprocess
import sys

import pytest

from assistant.paths import PROJECT_DIR

HOOK = PROJECT_DIR / ".claude" / "hooks" / "guard.py"
_spec = importlib.util.spec_from_file_location("guard", HOOK)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)

CWD = str(PROJECT_DIR)
OUTSIDE = PROJECT_DIR.anchor + "elsewhere"          # e.g. C:\elsewhere or /elsewhere


def call(tool, **tool_input):
    """A PreToolUse payload as Claude Code sends it."""
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": CWD, "tool_input": tool_input}


def test_settings_register_the_hook_for_file_and_shell_tools():
    """``.claude/settings.json`` runs guard.py before Write/Edit/MultiEdit/NotebookEdit/Bash/PowerShell,
    and fails closed (exit 2) if the project's Python can't be found."""
    settings = json.loads((PROJECT_DIR / ".claude" / "settings.json").read_text(encoding="utf-8"))
    entry = settings["hooks"]["PreToolUse"][0]
    assert set(entry["matcher"].split("|")) == {"Write", "Edit", "MultiEdit", "NotebookEdit", "Bash", "PowerShell"}
    command = entry["hooks"][0]["command"]
    assert "guard.py" in command and "exit 2" in command


@pytest.mark.parametrize("path", ["assistant/new.py", str(PROJECT_DIR / "docs" / "x.md"), "./tests/t.py"])
def test_writes_inside_the_project_are_allowed(path):
    """Edits to files in the project pass."""
    assert guard.decide(call("Write", file_path=path, content="x")) is None
    assert guard.decide(call("Edit", file_path=path, old_string="a", new_string="b")) is None


@pytest.mark.parametrize("path", [OUTSIDE + "/notes.txt", "../outside.txt", "~/notes.txt"])
def test_writes_outside_the_project_are_blocked(path):
    """Edits to files outside the project are blocked."""
    assert "outside the project" in guard.decide(call("Write", file_path=path, content="x"))


@pytest.mark.parametrize("command", [
    "rm notes.txt", "rm -rf build", "del data\\x.txt", "Remove-Item .\\x -Recurse", "rmdir old",
    "git clean -fd", "git rm README.md", "python -c \"import shutil; shutil.rmtree('x')\"",
    "ls; rm x", "python -c \"from pathlib import Path; Path('x').unlink()\"",
    "find . -name x -delete", "[IO.File]::Delete('a.txt')", "[System.IO.Directory]::Delete('d', $true)",
])
def test_delete_commands_are_blocked(command):
    """Any file deletion is blocked, inside the project too (CLAUDE.md: never delete files)."""
    assert "Deleting files" in guard.check_command(command, CWD)


@pytest.mark.parametrize("command", ["iex \"Remove-Item x\"", "Invoke-Expression $cmd"])
def test_running_strings_as_commands_is_blocked(command):
    """Regression (independent review): iex / Invoke-Expression could hide a deletion."""
    assert "Invoke-Expression" in guard.check_command(command, CWD)


@pytest.mark.parametrize("command", [
    f"cd {OUTSIDE}", "cd ..", "Set-Location ../..", "echo hi > ../outside.txt",
    f"Copy-Item a.txt {OUTSIDE}\\a.txt", "cp a.txt ~/a.txt", f"echo x | tee {OUTSIDE}/log.txt",
    "mkdir ../newdir",
    # Regression (independent review): UNC shares, environment-based paths, a bare "..", Python writes.
    "Copy-Item a \\\\server\\share\\x", "Out-File \\\\srv\\s\\x", "Move-Item a $HOME\\x",
    "Set-Content -Path $env:USERPROFILE\\x -Value 1", "mv a ..", "copy a %USERPROFILE%\\x",
    f"python -c \"open('{OUTSIDE}/x.txt','w').write('x')\"",
])
def test_leaving_or_writing_outside_is_blocked(command):
    """Changing directory or writing outside the project is blocked."""
    assert guard.check_command(command, CWD) is not None


@pytest.mark.parametrize("command", [
    "git status", "pytest -q", ".venv/Scripts/python.exe -m pytest", "echo done > .cache/out.txt",
    "ls -la docs", "cd tests", "python -m assistant.harness.run_scenarios 2>/dev/null",
    "grep -rn 'remove' assistant", "git commit -m \"rm old notes from docs\"",
    "Get-ChildItem C:\\Windows\\System32 | Select-Object -First 1",
    "cp a.txt b.txt; echo https://example.com/docs",            # a URL isn't a drive path
    "python -c \"open('.cache/x.txt','w').write('x')\"",
])
def test_ordinary_commands_are_allowed(command):
    """Normal work passes, including reads elsewhere and the word 'rm' inside a quoted message.

    Reading outside the project is governed by CLAUDE.md, not this hook; the hook stops
    writes and deletions, which are the irreversible actions.
    """
    assert guard.check_command(command, CWD) is None, command


def test_other_tools_are_not_affected():
    """Read-only tools aren't matched (and would be allowed anyway)."""
    assert guard.decide(call("Read", file_path=OUTSIDE + "/x.txt")) is None


@pytest.mark.parametrize("payload, code", [
    (call("Write", file_path=OUTSIDE + "/x.txt", content="x"), 2),
    (call("Bash", command="rm -rf data"), 2),
    (call("Bash", command="git status"), 0),
])
def test_exit_codes_follow_the_claude_code_protocol(payload, code):
    """As a real process: exit 2 (with a reason on stderr) blocks, exit 0 allows."""
    proc = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload), capture_output=True,
                          text=True, timeout=30)
    assert proc.returncode == code
    if code == 2:
        assert proc.stderr.startswith("Blocked by project guard hook:")
