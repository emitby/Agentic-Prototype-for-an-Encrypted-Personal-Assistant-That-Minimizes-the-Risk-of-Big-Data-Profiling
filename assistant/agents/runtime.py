"""Agent loop on the Claude Messages API, with the hook pipeline around every call.

Each :class:`Agent` has a system prompt and tools, and runs the standard tool-use loop:
call Claude, run the tools it asks for, send the results back, repeat until it answers.

What the runtime adds:

* **Hooks** (:mod:`assistant.hooks`): ``pre_model`` hooks run before every model call
  (token budget, final outbound privacy scan), ``post_model`` after it (budget charge);
  ``pre_tool`` hooks run before every tool call (schema, path guard, call limit) and
  ``post_tool`` hooks after it (leak detector, redaction, size cap).
* **Server tools** (web search) run on Anthropic's side. A long server-tool turn can
  stop with ``pause_turn``; the loop sends the conversation back to let it finish.
* **Events** for the harness: a ``model_call`` event per model call (usage, latency, stop
  reason, the client and server tools it requested and their sizes), ``tool_call`` /
  ``tool_result`` events per tool call, and ``hook`` events from hooks. Each carries the
  ``run`` id of its ``Agent.run`` invocation and the ``parent`` delegation call, so a
  specialist's tokens can be attributed to the tool that started it.
* **Least privilege (G3)**: an Agent refuses to be built with a human-only tool.
"""

import contextvars
import inspect
import itertools
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable

import anthropic

from assistant import guardrails as g
from assistant.hooks import HookBlock, Hooks, ToolCall, to_plain

log = logging.getLogger(__name__)

MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TOKENS = 16000
REFUSAL_REPLY = "Sorry, I can't help with that request."

# The tool call being executed in this thread. A delegation tool runs a specialist in the
# same thread, so the specialist's run can record which call it answers. Pool threads
# start with an empty context and _execute sets it, so it's always the right call.
_current_call = contextvars.ContextVar("current_tool_call", default=None)
_run_ids = itertools.count(1)


class AgentError(RuntimeError):
    """An agent couldn't finish (for example it hit its turn limit)."""


class ToolInputError(ValueError):
    """Bad arguments from the model. Returned to it as an error result."""


@dataclass
class Tool:
    """A client tool an agent may call.

    Attributes:
        name: Tool name the model uses.
        description: What it does (sent to the model).
        input_schema: JSON schema; also enforced in code by the ``schema`` hook (G2).
        handler: Called with the arguments as keyword arguments; its return value
            (str or JSON-serializable) becomes the result.
    """
    name: str
    description: str
    input_schema: dict
    handler: Callable[..., Any]

    def to_param(self):
        """The tool definition in Messages API format."""
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


def text_of(content):
    """Join the text blocks of a response's content."""
    return "\n".join(b.text for b in content if b.type == "text").strip()


def usage_of(response):
    """Read token usage (and web searches) from a response; missing fields count as 0.

    Returns:
        ``{"input", "output", "cache_write", "cache_read", "web_searches"}``.
    """
    u = getattr(response, "usage", None)

    def get(obj, name):
        """An integer usage field, 0 if absent."""
        return int(getattr(obj, name, 0) or 0) if obj is not None else 0

    server = getattr(u, "server_tool_use", None) if u is not None else None
    return {"input": get(u, "input_tokens"), "output": get(u, "output_tokens"),
            "cache_write": get(u, "cache_creation_input_tokens"), "cache_read": get(u, "cache_read_input_tokens"),
            "web_searches": get(server, "web_search_requests")}


class Agent:
    """One Claude agent.

    Args:
        client: ``anthropic.Anthropic`` or a stand-in with ``beta.messages.create``.
        name: Display name ("Coordinator", "Security Agent" ...).
        system: System prompt.
        tools: Client :class:`Tool` objects (least privilege: only these).
        server_tools: Server tool definitions, e.g. web search.
        effort: ``output_config.effort``.
        hooks: The session's :class:`~assistant.hooks.Hooks` (an empty set if omitted).
        safe_errors: Exception types whose message is safe to return to the model.
        max_turns: Model calls per run before :class:`AgentError`.

    Raises:
        ValueError: If any tool is human-only (G3).
    """

    def __init__(self, client, name, system, tools=(), server_tools=(), effort="medium",
                 hooks=None, safe_errors=(), max_turns=15):
        """Store the configuration and enforce G3 (see the class docstring)."""
        forbidden = sorted({t.name for t in tools} & g.HUMAN_ONLY)
        if forbidden:
            raise ValueError(f"{name} can't be given human-only tools: {forbidden}")
        self.client = client
        self.name = name
        self.system = system
        self.tools = {t.name: t for t in tools}
        self.tool_params = [t.to_param() for t in tools] + list(server_tools)
        self.effort = effort
        self.hooks = hooks or Hooks()
        self.safe_errors = (ToolInputError, *safe_errors)
        self.max_turns = max_turns

    def run(self, messages, on_event=None):
        """Advance the conversation until the agent replies in text.

        Args:
            messages: The conversation; appended to in place, never edited.
            on_event: Optional callback for trace events.

        Returns:
            The final reply (a fixed safe reply on refusal).

        Raises:
            AgentError: Turn limit reached.
            assistant.guardrails.BudgetExceeded: Token budget used up (pre-model hook).
            assistant.guardrails.PrivacyLeak: A secret was about to be sent (pre-model hook).
            anthropic.APIError: API failures.
        """
        emit = on_event or (lambda e: None)
        run_id, parent = next(_run_ids), _current_call.get()
        base = {"agent": self.name, "run": run_id, "parent": parent}
        for turn in range(self.max_turns):
            request = dict(model=MODEL, max_tokens=MAX_TOKENS, system=self.system, tools=self.tool_params,
                           messages=messages, output_config={"effort": self.effort},
                           cache_control={"type": "ephemeral"}, betas=[FALLBACK_BETA], fallbacks="default")
            for hook in self.hooks.pre_model:
                hook(self.name, request)
            started = time.perf_counter()
            response = self.client.beta.messages.create(**request)
            usage = usage_of(response)
            for hook in self.hooks.post_model:
                hook(self.name, response, usage)
            messages.append({"role": "assistant", "content": response.content})

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            server_uses = [b for b in response.content if b.type == "server_tool_use"]
            server_results = [b for b in response.content if b.type.endswith("_tool_result")]
            emit({**base, "type": "model_call", "turn": turn, "usage": usage, "stop_reason": response.stop_reason,
                  "latency_s": round(time.perf_counter() - started, 3),
                  # getattr: tolerate minimal server-tool blocks (ids and inputs are always present in real API responses)
                  "tool_uses": [{"id": getattr(b, "id", None), "name": b.name,
                                 "input_chars": len(json.dumps(to_plain(getattr(b, "input", {})), default=str)),
                                 "server": b.type == "server_tool_use"}
                                for b in tool_uses + server_uses],
                  "server_result_chars": sum(len(json.dumps(to_plain(b), default=str)) for b in server_results)})
            for b in server_uses:
                emit({**base, "type": "tool_call", "id": getattr(b, "id", None), "tool": b.name, "server": True})

            if response.stop_reason == "refusal":
                emit({**base, "type": "refusal"})
                return REFUSAL_REPLY
            if response.stop_reason == "pause_turn":
                continue   # a server tool is still working: send it back to let it finish
            if response.stop_reason != "tool_use" or not tool_uses:
                if response.stop_reason == "max_tokens":
                    log.warning("%s hit max_tokens", self.name)
                return text_of(response.content) or "(no reply)"

            with ThreadPoolExecutor(max_workers=len(tool_uses)) as pool:
                results = list(pool.map(lambda b: self._execute(b, emit, base), tool_uses))
            messages.append({"role": "user", "content": results})

        raise AgentError(f"{self.name} did not finish within {self.max_turns} turns.")

    def _execute(self, block, emit, base):
        """Run one tool call through the pre-tool hooks, the handler and the post-tool hooks.

        Args:
            block: The ``tool_use`` content block.
            emit: Event callback.
            base: The run's ``agent``/``run``/``parent`` fields.

        Returns:
            A ``tool_result`` block. Blocked calls, bad arguments and safe errors become
            ``is_error`` results the model can act on; unexpected exceptions become a
            generic message, so internals never reach the model.
        """
        emit({**base, "type": "tool_call", "id": block.id, "tool": block.name})
        tool = self.tools.get(block.name)
        call = ToolCall(self.name, block.name, block.input if isinstance(block.input, dict) else {},
                        block.id, base["run"], tool.input_schema if tool else None)
        started = time.perf_counter()
        token = _current_call.set(block.id)
        is_error = True
        try:
            if tool is None:
                raise HookBlock("known_tool", f"Unknown tool {block.name!r}. Use only your listed tools.")
            if not isinstance(block.input, dict):
                raise ToolInputError("Tool input must be a JSON object.")
            for hook in self.hooks.pre_tool:
                hook(call)
            try:
                inspect.signature(tool.handler).bind(**block.input)
            except TypeError as exc:
                raise ToolInputError(f"Invalid arguments for {block.name}: {exc}") from None
            output = tool.handler(**block.input)
            content = output if isinstance(output, str) else json.dumps(output, default=str)
            is_error = False
        except HookBlock as exc:
            self.hooks.event(exc.hook, "blocked", tool=block.name, agent=self.name, reason=str(exc))
            content = f"Blocked by the {exc.hook} guardrail: {exc}"
        except self.safe_errors as exc:
            content = str(exc)
        except anthropic.APIError as exc:
            log.exception("Sub-agent call failed in %s", block.name)
            content = f"That specialist is unavailable right now ({type(exc).__name__})."
        except (g.BudgetExceeded, g.PrivacyLeak):
            raise   # a specialist hit a session-wide stop: end the whole turn
        except Exception:
            log.exception("Tool %s failed", block.name)
            content = "Internal error while running this tool."
        finally:
            _current_call.reset(token)

        for hook in self.hooks.post_tool:
            content = hook(call, content, is_error)
        emit({**base, "type": "tool_result", "id": block.id, "tool": block.name, "ok": not is_error,
              "result_chars": len(content), "latency_s": round(time.perf_counter() - started, 3)})
        result = {"type": "tool_result", "tool_use_id": block.id, "content": content}
        if is_error:
            result["is_error"] = True
        return result
