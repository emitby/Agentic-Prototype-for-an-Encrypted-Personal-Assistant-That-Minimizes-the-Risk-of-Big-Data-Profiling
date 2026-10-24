"""Project paths and the confinement rule for every file the assistant writes.

CLAUDE.md requires that nothing is read or written outside the project folder, that
``os`` is never used, and that files are never deleted. This module enforces it in one
place:

* :data:`PROJECT_DIR` is the folder containing ``pyproject.toml``.
* :func:`confine` resolves a path (relative paths are taken from the project root) and
  raises :class:`PathError` for anything outside, including ``..`` escapes, absolute
  paths elsewhere and the Windows ``\\\\?\\`` long-path spelling of either.
* :func:`write_text` / :func:`write_bytes` write atomically: a sibling ``.tmp`` file is
  written and renamed over the target with ``Path.replace``. A crash never leaves a
  half-written file, and nothing is ever deleted.

The vault (``vault.py``), the harness run folders and the PDF builder all use these.
The in-app path-guard hook (``hooks.py``) and the Claude Code hook script
(``.claude/hooks/guard.py``) apply the same rule to tool arguments and to AI coding
agents' file edits and shell commands.
"""

from pathlib import Path

#: The project root: this file lives in ``<root>/assistant/paths.py``.
PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_DIR / "data"
RUNS_DIR = PROJECT_DIR / "runs"
CACHE_DIR = PROJECT_DIR / ".cache"
DOCS_DIR = PROJECT_DIR / "docs"


class PathError(ValueError):
    """A path that resolves outside the project folder."""


def _strip_long_prefix(path):
    """Drop Windows' ``\\\\?\\`` prefix so inside/outside comparisons are like for like.

    Args:
        path: A resolved path.

    Returns:
        The same path without the prefix (unchanged on other systems).
    """
    text = str(path)
    return Path(text[4:]) if text.startswith("\\\\?\\") else path


def is_inside(path):
    """True if ``path`` (relative to the project root if not absolute) resolves inside the project."""
    p = Path(path)
    if not p.is_absolute():
        p = PROJECT_DIR / p
    resolved = _strip_long_prefix(p.resolve())
    root = _strip_long_prefix(PROJECT_DIR)
    return resolved == root or root in resolved.parents


def confine(path):
    """Resolve ``path`` and check that it's inside the project.

    Args:
        path: A ``str`` or :class:`~pathlib.Path`; relative paths start at the project root.

    Returns:
        The absolute, resolved path.

    Raises:
        PathError: If the path resolves outside :data:`PROJECT_DIR`.
    """
    if not is_inside(path):
        raise PathError(f"Refusing to use {path}: it is outside the project folder {PROJECT_DIR}.")
    p = Path(path)
    return _strip_long_prefix((p if p.is_absolute() else PROJECT_DIR / p).resolve())


def write_bytes(path, data):
    """Atomically write bytes to a confined path, creating parent folders.

    Args:
        path: Target path (must be inside the project).
        data: Bytes to write.

    Returns:
        The resolved target path.

    Raises:
        PathError: If the path is outside the project.

    Side effects:
        Creates parent folders, writes ``<name>.tmp`` and renames it over the target.
    """
    target = confine(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_bytes(data)
    tmp.replace(target)
    return target


def write_text(path, text):
    """Atomically write UTF-8 text to a confined path. See :func:`write_bytes`."""
    return write_bytes(path, text.encode("utf-8"))
