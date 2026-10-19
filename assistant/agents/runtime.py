"""Agent loop on the Claude Messages API, with an outbound privacy filter.

Each Agent has a system prompt and tools, and runs the standard tool-use loop.
Two additions over a plain loop:
- Server tools (e.g. web search) run on Anthropic's side. A long server-tool
  turn can stop with `pause_turn`, and the loop simply continues it.
- Every tool result passes through the Redactor before it is sent to Claude.
"""

import inspect
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable

import anthropic

log = logging.getLogger(__name__)

MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_TOKENS = 16000
REFUSAL_REPLY = "Sorry, I can't help with that request."


class AgentError(RuntimeError):
    pass


class ToolInputError(ValueError):
    """Bad arguments from the model. Returned to it as an error result."""


@dataclass
class Tool:
    name: str
    description: str
    input_schema: dict
    handler: Callable[..., Any]

    def to_param(self):
        return {"name": self.name, "description": self.description, "input_schema": self.input_schema}


def text_of(content):
    return "\n".join(b.text for b in content if b.type == "text").strip()


class Agent:
    def __init__(self, client, name, system, tools=(), server_tools=(), effort="medium",
                 redactor=None, safe_errors=(), max_turns=15):
        self.client = client
        self.name = name
        self.system = system
        self.tools = {t.name: t for t in tools}
        self.tool_params = [t.to_param() for t in tools] + list(server_tools)
        self.effort = effort
        self.redactor = redactor
        self.safe_errors = (ToolInputError, *safe_errors)
        self.max_turns = max_turns

    def run(self, messages, on_event=None):
        """Advance the conversation until the agent replies. Appends to `messages`."""
        emit = on_event or (lambda e: None)
        for _ in range(self.max_turns):
            response = self.client.beta.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=self.system,
                tools=self.tool_params,
                messages=messages,
                output_config={"effort": self.effort},
                cache_control={"type": "ephemeral"},
                betas=[FALLBACK_BETA],
                fallbacks="default",
            )
            messages.append({"role": "assistant", "content": response.content})

            for block in response.content:
                if block.type == "server_tool_use":
                    emit({"agent": self.name, "type": "tool_call", "tool": block.name})

            if response.stop_reason == "refusal":
                emit({"agent": self.name, "type": "refusal"})
                return REFUSAL_REPLY
            if response.stop_reason == "pause_turn":
                continue   # server tool still working: re-send to let it finish

            tool_uses = [b for b in response.content if b.type == "tool_use"]
            if response.stop_reason != "tool_use" or not tool_uses:
                if response.stop_reason == "max_tokens":
                    log.warning("%s hit max_tokens", self.name)
                return text_of(response.content) or "(no reply)"

            with ThreadPoolExecutor(max_workers=len(tool_uses)) as pool:
                results = list(pool.map(lambda b: self._execute(b, emit), tool_uses))
            messages.append({"role": "user", "content": results})

        raise AgentError(f"{self.name} did not finish within {self.max_turns} turns.")

    def _execute(self, block, emit):
        emit({"agent": self.name, "type": "tool_call", "tool": block.name})
        tool = self.tools.get(block.name)
        is_error = True
        try:
            if tool is None:
                raise ToolInputError(f"Unknown tool {block.name!r}.")
            if not isinstance(block.input, dict):
                raise ToolInputError("Tool input must be a JSON object.")
            try:
                inspect.signature(tool.handler).bind(**block.input)
            except TypeError as exc:
                raise ToolInputError(f"Invalid arguments for {block.name}: {exc}") from None
            output = tool.handler(**block.input)
            content = output if isinstance(output, str) else json.dumps(output, default=str)
            is_error = False
        except self.safe_errors as exc:
            content = str(exc)
        except anthropic.APIError as exc:
            log.exception("Sub-agent call failed in %s", block.name)
            content = f"That specialist is unavailable right now ({type(exc).__name__})."
        except Exception:
            log.exception("Tool %s failed", block.name)
            content = "Internal error while running this tool."

        if self.redactor:
            content, _ = self.redactor.redact(content)
        emit({"agent": self.name, "type": "tool_result", "tool": block.name, "ok": not is_error})
        result = {"type": "tool_result", "tool_use_id": block.id, "content": content}
        if is_error:
            result["is_error"] = True
        return result
