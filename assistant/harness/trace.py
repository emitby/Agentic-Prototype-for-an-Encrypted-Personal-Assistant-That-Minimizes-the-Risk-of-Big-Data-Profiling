"""Run folders, ``trace.jsonl`` and JSON reports, with secrets removed before writing.

Each line of ``trace.jsonl`` is one event (model call, tool call, tool result or hook
event) tagged with its scenario and turn. Before anything is written, every string is
passed through :func:`scrub`: stored secrets are replaced with their tags by the session's
redactor, and any remaining email address is masked. All paths are confined to the
project; files are written atomically; nothing is deleted.
"""

import json
import re
from datetime import datetime

from assistant.paths import RUNS_DIR, confine, write_text

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def scrub(value, redactor=None):
    """Remove secrets from a JSON-like value (returns a copy).

    Args:
        value: Any JSON-compatible value.
        redactor: Optional :class:`~assistant.privacy.Redactor`; stored secrets become tags.

    Returns:
        The scrubbed copy.
    """
    if isinstance(value, str):
        if redactor is not None:
            value, _ = redactor.redact(value)
        return _EMAIL_RE.sub("[email]", value)
    if isinstance(value, dict):
        return {k: scrub(v, redactor) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [scrub(v, redactor) for v in value]
    return value


def new_run_dir(label):
    """Create a fresh ``runs/<timestamp>-<label>/`` folder (never reuses an earlier one).

    Returns:
        The folder's path.
    """
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    path = confine(RUNS_DIR / f"{stamp}-{label}")
    path.mkdir(parents=True, exist_ok=False)
    return path


def write_trace(path, events, redactor=None):
    """Write events as JSON Lines, scrubbed. Returns the path."""
    return write_text(path, "\n".join(json.dumps(scrub(e, redactor), default=str) for e in events) + "\n")


def write_json(path, data, redactor=None):
    """Write a scrubbed, pretty-printed JSON report. Returns the path."""
    return write_text(path, json.dumps(scrub(data, redactor), indent=2, default=str) + "\n")
