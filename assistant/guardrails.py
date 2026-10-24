"""Guardrails: the rules that keep the assistant private, safe and affordable, as plain functions.

Prompts *describe* these rules so the agents usually comply first time, but nothing
depends on a model obeying. Each rule is code with its own tests
(``tests/test_guardrails.py``), and most are applied through the hook pipeline in
:mod:`assistant.hooks`, so every tool call and every model call passes through them.

====  ===============================  ==============================================
 #    Guardrail                        Enforced by
====  ===============================  ==============================================
 G1   Customer input check             ``PersonalAssistant.send`` (before any model call)
 G2   Tool-argument schema             pre-tool hook ``schema``
 G3   Least privilege                  ``Agent`` refuses human-only tools; pre-tool hook
                                       ``known_tool``; per-agent tool sets in ``team.py``
 G4   Outbound privacy                 redactor on input and briefs; post-tool hook
                                       ``redact``; pre-model hook ``outbound_scan``
 G5   Secret-free tool results         post-tool hook ``leak_detector``
 G6   Token budgets                    pre-model ``budget_check`` / post-model ``budget_charge``
 G7   Tool-call and web-search limits  pre-tool hook ``call_limit``; ``max_uses`` on web search
 G8   Host safety                      pre-tool hook ``path_guard``; ``paths.confine``;
                                       Claude Code hook ``.claude/hooks/guard.py``
 G9   Vault integrity                  ``vault.py`` (AES-256-GCM, scrypt, atomic writes)
====  ===============================  ==============================================
"""

import re
import threading
from dataclasses import dataclass
from pathlib import PureWindowsPath

from assistant.paths import PROJECT_DIR, is_inside

# --------------------------------------------------------------------------- G1 input

MAX_MESSAGE_CHARS = 4000

# An override verb followed directly by the assistant's *own* instructions ("your ...",
# "previous/system ... instructions", "the rules above"), plus a few well-known phrases.
# Ordinary sentences pass: "ignore the previous list", "don't forget the house rules".
_VERB = r"\b(?:ignore|disregard|forget|override)\b\s+(?:all\s+|any\s+)?(?:of\s+)?"
_TARGET = r"(?:instructions?|rules|prompts?|guardrails?)\b"
_INJECTION_RE = re.compile(
    _VERB + r"(?:(?:your|the|these|my)\s+)?(?:previous|prior|above|earlier|system|original|existing)\s+" + _TARGET
    + r"|" + _VERB + r"your\s+" + _TARGET
    + r"|" + _VERB + r"(?:the\s+)?" + _TARGET + r"\s+above\b"
    + r"|\bsystem prompt\b|\byou are now\b|\bdeveloper mode\b|\bjailbreak\b"
    + r"|\byour new instructions?\b|\bact as (?:the |an? )?(?:admin|administrator|developer|system)\b",
    re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

INJECTION_REPLY = ("I can only help with your account security, travel searches, grocery lists and "
                   "household supplies, and I can't change how I work. What would you like to do?")


@dataclass
class InputCheck:
    """Result of :func:`check_user_message`.

    Attributes:
        ok: Whether the message may go to the agents.
        text: The cleaned message (control characters removed, trimmed).
        reason: Why it was refused, for the trace (``None`` when ok).
        reply: What to tell the user when refused.
    """
    ok: bool
    text: str
    reason: str | None = None
    reply: str | None = None


def check_user_message(text):
    """G1: clean a chat message and refuse prompt-injection attempts before any model call.

    Args:
        text: The raw message.

    Returns:
        An :class:`InputCheck`. A refused message costs nothing: no model is called.
    """
    clean = _CONTROL_RE.sub("", str(text)).strip()
    if not clean:
        return InputCheck(False, clean, "empty", "What can I help with?")
    if len(clean) > MAX_MESSAGE_CHARS:
        return InputCheck(False, clean[:MAX_MESSAGE_CHARS], "too_long",
                          f"That message is too long. Please keep it under {MAX_MESSAGE_CHARS} characters.")
    if _INJECTION_RE.search(clean):
        return InputCheck(False, clean, "prompt_injection", INJECTION_REPLY)
    return InputCheck(True, clean)


# --------------------------------------------------------------------------- G2 schema

_JSON_TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool,
               "array": list, "object": dict}


def validate_args(schema, value, path="input"):
    """G2: check tool arguments against the tool's JSON schema (the subset the tools use).

    Supports ``type``, ``properties``, ``required``, ``additionalProperties: false``,
    ``enum``, ``minimum``/``maximum``, ``maxLength``, ``minItems``/``maxItems`` and
    ``items``, recursively.

    Args:
        schema: The tool's ``input_schema`` (or a nested part of it).
        value: The arguments the model sent (or a nested part).
        path: Where in the input we are, for error messages.

    Returns:
        A list of problems naming the field and the fix; empty means valid.
    """
    problems = []
    expected = schema.get("type")
    if expected:
        py_type = _JSON_TYPES[expected]
        # bool is an int in Python but not a number in JSON Schema.
        if not isinstance(value, py_type) or (expected in ("integer", "number") and isinstance(value, bool)):
            return [f"{path} must be {'an' if expected[0] in 'aeiou' else 'a'} {expected}"]
    if "enum" in schema and value not in schema["enum"]:
        problems.append(f"{path} must be one of {schema['enum']}")
    if expected in ("integer", "number"):
        if "minimum" in schema and value < schema["minimum"]:
            problems.append(f"{path} must be at least {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            problems.append(f"{path} must be at most {schema['maximum']}")
    if expected == "string" and "maxLength" in schema and len(value) > schema["maxLength"]:
        problems.append(f"{path} must be at most {schema['maxLength']} characters")
    if expected == "array":
        if "minItems" in schema and len(value) < schema["minItems"]:
            problems.append(f"{path} needs at least {schema['minItems']} item(s)")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            problems.append(f"{path} allows at most {schema['maxItems']} items")
        for i, item in enumerate(value):
            problems += validate_args(schema.get("items", {}), item, f"{path}[{i}]")
    if expected == "object":
        props = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                problems.append(f"missing required field '{name}'")
        for name, item in value.items():
            if name in props:
                problems += validate_args(props[name], item, name)
            elif schema.get("additionalProperties") is False:
                problems.append(f"unexpected field '{name}' (allowed: {', '.join(props) or 'none'})")
    return problems


# --------------------------------------------------------------------------- G3 least privilege

#: Operations that accept or reveal secrets. They exist only as CLI commands; an Agent
#: refuses to be built with a tool of any of these names.
HUMAN_ONLY = frozenset({"reveal", "reveal_password", "add_credential", "add_login", "add_email",
                        "set_hibp_key", "complete_rotation", "rotated", "export_vault", "delete_account"})


# --------------------------------------------------------------------------- G4 / G5 privacy

def find_secrets(text, secrets_list):
    """Return the stored secrets that appear in ``text`` (used by G4's final scan and G5).

    Args:
        text: Any text about to leave the machine, or a raw tool result.
        secrets_list: Secret values (passwords, usernames, stored emails, staged passwords).

    Returns:
        The secrets found (values, for internal use only; never log or send these).
    """
    return [s for s in secrets_list if s and s in text]


class PrivacyLeak(RuntimeError):
    """G4: a request about to be sent to the model still contains a stored secret. It is not sent."""


#: Tool results longer than this are cut (G7), so one tool can't flood an agent's context.
MAX_RESULT_CHARS = 20_000


# --------------------------------------------------------------------------- G6 budgets

TURN_TOKEN_BUDGET = 400_000
SESSION_TOKEN_BUDGET = 2_000_000


class BudgetExceeded(RuntimeError):
    """A turn or session used up its token budget; no further model call is made."""


class TokenBudget:
    """G6: per-turn and per-session token budgets shared by all agents in a session.

    Checked before every model call and charged after it (by hooks). Thread-safe;
    specialists running in parallel can overshoot by the calls already in flight.

    Args:
        turn_limit: Tokens (input + output + cache) allowed per user turn.
        session_limit: Tokens allowed per chat session.
    """

    def __init__(self, turn_limit=TURN_TOKEN_BUDGET, session_limit=SESSION_TOKEN_BUDGET):
        """Start with nothing used."""
        self.turn_limit, self.session_limit = turn_limit, session_limit
        self.turn_used = self.session_used = 0
        self._lock = threading.Lock()

    def start_turn(self):
        """Reset the per-turn count at the start of a user turn."""
        self.turn_used = 0

    def check(self):
        """Raise :class:`BudgetExceeded` if either budget is used up."""
        if self.turn_used >= self.turn_limit:
            raise BudgetExceeded(f"This request used its token budget ({self.turn_limit:,} tokens).")
        if self.session_used >= self.session_limit:
            raise BudgetExceeded(f"This session used its token budget ({self.session_limit:,} tokens).")

    def charge(self, tokens):
        """Add one model call's tokens to both counts."""
        with self._lock:
            self.turn_used += tokens
            self.session_used += tokens


# --------------------------------------------------------------------------- G7 limits

#: Client-tool calls one agent may make in one run (web searches are capped by ``max_uses``).
MAX_TOOL_CALLS_PER_RUN = 30
WEB_SEARCH_MAX_USES = 10


# --------------------------------------------------------------------------- G8 host safety

# A string "looks like a path" if it starts with a drive letter (C:\ or C:/), a UNC share
# (\\server), ~/ or ~\, ./ or ../, an absolute POSIX path with at least two segments
# (/etc/passwd), or contains a ../ or ..\ segment anywhere. Plain values pass: "groceries",
# "JFK", "github.com", "~2 lbs", "1/2 cup", a brief starting "/add-login now".
_PATHLIKE_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|~[\\/]|\.{1,2}[\\/]|/[^\s/]+/)|(?:^|[\\/])\.\.(?:[\\/]|$)")
_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
#: The project's drive letter ("C:" on Windows, "" elsewhere). Read from the project path
#: itself, so no operating-system query is needed.
_PROJECT_DRIVE = PureWindowsPath(str(PROJECT_DIR)).drive


def _foreign_drive(text):
    """True for a Windows drive path (``C:\\...``) that can't be inside the project.

    On Linux and macOS the project has no drive letter, so a drive path is never inside
    it. Without this check, ``Path("C:\\Windows")`` there reads as a relative file *name*
    and would resolve inside the project. (Found by the red-team on Linux CI.) On Windows,
    :func:`~assistant.paths.is_inside` decides as usual.
    """
    return bool(_DRIVE_RE.match(text)) and not _PROJECT_DRIVE


def outside_paths(value):
    """G8: list every path-like string in a tool's arguments that points outside the project.

    No tool reads or writes files today; this guarantees that any argument naming a
    path (now or in a future tool) stays inside the project folder.

    Args:
        value: Tool arguments (any JSON value).

    Returns:
        The offending strings.
    """
    found = []
    if isinstance(value, str):
        text = value.strip()
        # "~/" means the home folder; it is never treated as inside (resolving it would mean
        # reading system settings). UNC shares (\\server\share) are always outside.
        if _PATHLIKE_RE.search(text) and (text.startswith(("~", "\\\\")) or _foreign_drive(text)
                                          or not is_inside(text)):
            found.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            found += outside_paths(v)
    elif isinstance(value, list):
        for v in value:
            found += outside_paths(v)
    return found
