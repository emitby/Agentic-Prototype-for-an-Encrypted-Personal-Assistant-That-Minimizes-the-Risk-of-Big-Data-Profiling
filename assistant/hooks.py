"""The in-app hook pipeline: code that runs before and after every tool call and model call.

A *hook* is a small function the agent runtime calls at a fixed point in the loop. Hooks
are how the guardrails (:mod:`assistant.guardrails`) are applied uniformly to all four
agents, without each tool having to remember them:

==============  =====================================  =======================================
 Point          Signature                              Can
==============  =====================================  =======================================
 pre_tool       ``hook(call)``                          block the call (raise :class:`HookBlock`)
 post_tool      ``hook(call, content, is_error)``       return a changed result (e.g. redacted)
 pre_model      ``hook(agent, request)``                stop the request (raise an exception)
 post_model     ``hook(agent, response, usage)``        observe (e.g. charge the token budget)
==============  =====================================  =======================================

Every hook that blocks or changes something reports a ``hook`` event, so the trace and
the PDF guide can show exactly which hook acted and why.

:func:`default_hooks` builds the standard set for a session (order matters: validation
before path checks, leak detection before redaction):

* pre_tool: ``schema`` (G2), ``path_guard`` (G8), ``call_limit`` (G7)
* post_tool: ``leak_detector`` (G5), ``redact`` (G4), ``size_cap`` (G7)
* pre_model: ``budget_check`` (G6), ``outbound_scan`` (G4, final check of everything about to be sent)
* post_model: ``budget_charge`` (G6)

These are *application* hooks. The separate Claude Code hooks in ``.claude/`` police AI
coding agents editing this repository (see ``docs/hooks.md``).
"""

import json
import threading
from collections import defaultdict
from dataclasses import dataclass, field

from assistant import guardrails as g


class HookBlock(Exception):
    """Raised by a pre-tool hook to stop a tool call; the message goes back to the model.

    Args:
        hook: The hook's name (for the trace).
        reason: Why, phrased so the agent can correct itself.
    """

    def __init__(self, hook, reason):
        """Store the hook name and the reason."""
        super().__init__(reason)
        self.hook = hook


@dataclass
class ToolCall:
    """What a pre/post-tool hook sees about one tool call.

    Attributes:
        agent: The calling agent's name.
        tool: The tool's name.
        input: The arguments from the model.
        id: The tool_use id.
        run: The ``Agent.run`` invocation this call belongs to.
        schema: The tool's input schema (``None`` for an unknown tool).
    """
    agent: str
    tool: str
    input: dict
    id: str
    run: int
    schema: dict | None = None


@dataclass
class Hooks:
    """The hook lists the runtime calls, plus an ``emit`` callback for hook events.

    Attributes:
        pre_tool, post_tool, pre_model, post_model: Lists of hook functions (see module docstring).
        emit: Receives ``{"type": "hook", ...}`` events; set per turn by the session.
    """
    pre_tool: list = field(default_factory=list)
    post_tool: list = field(default_factory=list)
    pre_model: list = field(default_factory=list)
    post_model: list = field(default_factory=list)
    emit: object = None

    def event(self, hook, action, **detail):
        """Report that ``hook`` blocked or changed something."""
        if self.emit:
            self.emit({"type": "hook", "hook": hook, "action": action, **detail})


def to_plain(obj):
    """Convert SDK content blocks and test doubles to JSON-compatible values (for scanning and sizing)."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    if isinstance(obj, dict):
        return {k: to_plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_plain(v) for v in obj]
    if hasattr(obj, "__dict__"):
        return {k: to_plain(v) for k, v in vars(obj).items()}
    return obj


def _strings(value):
    """Yield every string (keys and values) in a JSON-like structure."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)
    elif value is not None:
        yield str(value)


def default_hooks(redactor, budget):
    """Build the standard hook set for one session.

    Args:
        redactor: The session's :class:`~assistant.privacy.Redactor` (knows the stored secrets).
        budget: The session's :class:`~assistant.guardrails.TokenBudget`.

    Returns:
        A :class:`Hooks` with every guardrail hook registered, in order.
    """
    hooks = Hooks()
    calls_per_run = defaultdict(int)
    lock = threading.Lock()

    # ---------------------------------------------------------------- pre_tool
    def schema(call):
        """G2: arguments must match the tool's JSON schema."""
        if call.schema is None:
            return
        problems = g.validate_args(call.schema, call.input)
        if problems:
            raise HookBlock("schema", f"Invalid arguments for {call.tool}: {'; '.join(problems)}.")

    def path_guard(call):
        """G8: no argument may name a file path outside the project folder."""
        bad = g.outside_paths(call.input)
        if bad:
            raise HookBlock("path_guard", "File paths outside the assistant's own folder aren't allowed "
                                          f"({len(bad)} found). The assistant can't read, write or delete "
                                          "files elsewhere on this computer.")

    def call_limit(call):
        """G7: at most MAX_TOOL_CALLS_PER_RUN client-tool calls per agent run."""
        with lock:
            calls_per_run[call.run] += 1
            n = calls_per_run[call.run]
        if n > g.MAX_TOOL_CALLS_PER_RUN:
            raise HookBlock("call_limit", f"Tool-call limit reached ({g.MAX_TOOL_CALLS_PER_RUN} per task). "
                                          "Summarize what you have.")

    hooks.pre_tool += [schema, path_guard, call_limit]

    # ---------------------------------------------------------------- post_tool
    def leak_detector(call, content, is_error):
        """G5: a tool result should never contain a stored secret; if one does, record it (it's redacted next)."""
        leaked = g.find_secrets(content, redactor.known_secret_values())
        if leaked:
            hooks.event("leak_detector", "flagged", tool=call.tool, agent=call.agent, count=len(leaked))
        return content

    def redact(call, content, is_error):
        """G4: replace stored secrets, other emails and card numbers before the result reaches a model."""
        safe, found = redactor.redact(content)
        if found:
            hooks.event("redact", "modified", tool=call.tool, agent=call.agent, tags=sorted(set(found)))
        return safe

    def size_cap(call, content, is_error):
        """G7: cut very large results so one tool can't flood an agent's context (and token bill)."""
        if len(content) > g.MAX_RESULT_CHARS:
            hooks.event("size_cap", "modified", tool=call.tool, chars=len(content))
            return content[:g.MAX_RESULT_CHARS] + "\n[result truncated by the size limit]"
        return content

    hooks.post_tool += [leak_detector, redact, size_cap]

    # ---------------------------------------------------------------- model calls
    def budget_check(agent, request):
        """G6: stop before a model call once the turn or session budget is used up."""
        try:
            budget.check()
        except g.BudgetExceeded:
            hooks.event("budget_check", "blocked", agent=agent)
            raise

    def outbound_scan(agent, request):
        """G4 (final check): nothing about to be sent may contain a stored secret, or it isn't sent.

        Scans every string in the system prompt, the tool definitions and the whole message
        history, compared raw (not JSON-escaped), so secrets with quotes, backslashes or
        non-ASCII characters are found too.
        """
        text = "\n".join(_strings(to_plain({"system": request["system"], "tools": request.get("tools", []),
                                            "messages": request["messages"]})))
        leaked = g.find_secrets(text, redactor.known_secret_values())
        if leaked:
            hooks.event("outbound_scan", "blocked", agent=agent, count=len(leaked))
            raise g.PrivacyLeak("A stored secret was about to be sent to the AI service, so the request "
                                "was stopped. Nothing was sent.")

    def budget_charge(agent, response, usage):
        """G6: charge every token of the call (input, output, cache) to the budget."""
        budget.charge(usage["input"] + usage["output"] + usage["cache_write"] + usage["cache_read"])

    hooks.pre_model += [budget_check, outbound_scan]
    hooks.post_model += [budget_charge]
    return hooks
