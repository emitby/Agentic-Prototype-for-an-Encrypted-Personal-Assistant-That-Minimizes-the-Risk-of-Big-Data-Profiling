"""CLAUDE.md rules checked on the source itself, plus path confinement.

* No ``os`` module (imports or ``os.`` use) anywhere.
* No file-deletion calls (the hook script and its test name the patterns they block, so
  they're scanned with those pattern strings removed).
* A docstring on every module, class and function (including tests and the hook script).
* No backslash inside f-string expressions (CI runs Python 3.10-3.12).
* ``confine`` keeps every path inside the project.
"""

import ast
import io
import re
import sys
import tokenize

import pytest

from assistant.paths import PROJECT_DIR, PathError, confine, is_inside

SOURCES = sorted(p for d in ("assistant", "tests", ".claude/hooks") for p in (PROJECT_DIR / d).rglob("*.py"))
IDS = [p.relative_to(PROJECT_DIR).as_posix() for p in SOURCES]
DELETION = re.compile(r"\.(unlink|rmdir)\(|\brmtree\b|\bos\.remove\b")
# Files that name deletion calls only as text (patterns to block, or examples in the PDF guide).
NAMES_PATTERNS = {"guard.py", "test_claude_hook.py", "test_project_guardrails.py", "guide.py"}


def test_sources_found():
    """The scans see the project's Python files."""
    assert len(SOURCES) > 20


@pytest.mark.parametrize("path", SOURCES, ids=IDS)
def test_no_os_module(path):
    """No file imports or uses ``os``."""
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            assert all(a.name.split(".")[0] != "os" for a in node.names), path
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] != "os", path
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            assert node.value.id != "os", path


@pytest.mark.parametrize("path", SOURCES, ids=IDS)
def test_no_deletion_calls(path):
    """No file deletes files (string literals are ignored in the files that name the patterns)."""
    code = path.read_text(encoding="utf-8")
    if path.name in NAMES_PATTERNS:
        # Remove string literals: these files mention deletion calls only as text to detect.
        code = "".join(tok.string for tok in tokenize.generate_tokens(io.StringIO(code).readline)
                       if tok.type not in (tokenize.STRING, tokenize.COMMENT)
                       and getattr(tokenize, "FSTRING_MIDDLE", None) != tok.type)
    assert not DELETION.search(code), path


@pytest.mark.parametrize("path", SOURCES, ids=IDS)
def test_every_module_class_and_function_has_a_docstring(path):
    """CLAUDE.md: docstrings on every module, class and function."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    missing = [] if ast.get_docstring(tree) else ["<module>"]
    missing += [f"{n.name}:{n.lineno}" for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and not ast.get_docstring(n)]
    assert not missing, f"{path.name}: {missing}"


@pytest.mark.skipif(sys.version_info < (3, 12), reason="older Pythons fail to parse such files in the scans above")
@pytest.mark.parametrize("path", SOURCES, ids=IDS)
def test_no_backslash_in_fstring_expressions(path):
    """Python 3.10/3.11 (in CI) reject backslashes inside f-string ``{...}``; catch it on 3.12 too."""
    depth, bad = 0, []
    for tok in tokenize.generate_tokens(io.StringIO(path.read_text(encoding="utf-8")).readline):
        if tok.type == tokenize.FSTRING_START:
            depth += 1
        elif tok.type == tokenize.FSTRING_END:
            depth -= 1
        elif depth and tok.type == tokenize.STRING and "\\" in tok.string:
            bad.append(tok.start[0])
    assert not bad, f"{path.name}: lines {bad}"


def test_confine_allows_project_paths():
    """Relative and absolute paths inside the project are allowed."""
    assert confine("data/x.enc") == PROJECT_DIR / "data" / "x.enc"
    assert is_inside(PROJECT_DIR / "runs")


@pytest.mark.parametrize("bad", ["../outside.txt", "data/../../outside.txt"])
def test_confine_rejects_escapes(bad):
    """``..`` escapes are refused on every OS."""
    with pytest.raises(PathError):
        confine(bad)


def test_confine_rejects_absolute_paths_elsewhere():
    """An absolute path at the filesystem root is refused."""
    with pytest.raises(PathError):
        confine(PROJECT_DIR.anchor + "elsewhere.txt")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only path spelling")
def test_confine_handles_windows_long_path_prefix():
    """The ``\\\\?\\`` prefix doesn't break the inside/outside check."""
    assert confine("\\\\?\\" + str(PROJECT_DIR / "data")) == PROJECT_DIR / "data"
