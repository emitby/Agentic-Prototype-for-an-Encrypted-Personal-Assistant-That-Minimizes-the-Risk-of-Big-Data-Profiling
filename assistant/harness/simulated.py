"""SimulatedClient: a scripted stand-in for Claude, for offline tests, scenarios and the PDF.

It has the ``client.beta.messages.create(**kwargs)`` method the runtime calls and plays
each agent's part from the scenario's ``plan``. Every tool call goes through the **real**
runtime, hooks, redactor, vault and domain code; only the "model" is scripted. Web
search is simulated too: it returns ``server_tool_use`` and ``web_search_tool_result``
blocks with **fictional** results (``*.example`` sites), first with ``pause_turn``,
like a long server-tool turn.

**Token usage is estimated, not measured.** Prompt tokens = JSON characters of the request
(system, tools, messages) / 4. Each response starts with a placeholder ``thinking`` block
for the model's reasoning (40 tokens at low effort, 120 at medium) that stays in the
history like real thinking blocks. Output tokens = JSON characters of the response / 4,
excluding web search results (the server adds those, and they count as input on the next
call, as with the real API).
The part of a conversation already sent counts as ``cache_read``; only new tokens count
as ``input``. Every report built from these numbers is labeled "simulated".
"""

import json
import math
import secrets
from types import SimpleNamespace as NS

from assistant.hooks import to_plain

CHARS_PER_TOKEN = 4
REASONING_ALLOWANCE = {"low": 40, "medium": 120}


def estimate_tokens(obj):
    """Estimate tokens as JSON characters / 4, rounded up."""
    return math.ceil(len(json.dumps(to_plain(obj), default=str)) / CHARS_PER_TOKEN)


def _text(t):
    """A text content block."""
    return NS(type="text", text=t)


class SimulatedClient:
    """Scripted stand-in for ``anthropic.Anthropic`` (see the module docstring).

    Args:
        scenario: A scenario from :mod:`assistant.harness.scenarios`.
    """

    def __init__(self, scenario):
        """Prepare the per-scenario plans (turns blocked by G1 never reach a model, so they're skipped)."""
        self.plans = [t["plan"] for t in scenario["turns"] if t["plan"]["action"] != "blocked"]
        self.agent_plan = {}          # specialist name -> the plan it's working on
        self._seen = {}               # conversation key -> prompt tokens already sent
        self._prefix = secrets.token_hex(3)
        self._ids = 0
        self.beta = NS(messages=NS(create=self._create))

    # ------------------------------------------------------------------ API surface

    def _create(self, **kw):
        """Answer one request as the agent named in its system prompt."""
        system = kw["system"]
        if "You are the Security Agent" in system:
            content, stop = self._security(kw["messages"])
        elif "You are the Travel Agent" in system:
            content, stop = self._travel(kw["messages"])
        elif "You are the Household Agent" in system:
            content, stop = self._household(kw["messages"])
        else:
            content, stop = self._coordinator(kw["messages"])
        effort = kw.get("output_config", {}).get("effort", "medium")
        thinking = NS(type="thinking", thinking="." * (REASONING_ALLOWANCE.get(effort, 120) * CHARS_PER_TOKEN))
        content = [thinking] + content
        searches = sum(1 for b in content if b.type == "server_tool_use")
        return NS(content=content, stop_reason=stop, usage=self._usage(kw, content, searches))

    def _usage(self, kw, content, searches):
        """Estimate usage for one call (see the module docstring)."""
        prompt = estimate_tokens({"system": kw["system"], "tools": kw["tools"], "messages": kw["messages"]})
        key = (kw["system"][:60], json.dumps(to_plain(kw["messages"][0]), default=str)[:200])
        cached = min(self._seen.get(key, 0), prompt)
        self._seen[key] = prompt
        # Web search results are added by the server and billed as input, not written by the model,
        # so they're left out of the output estimate (they show up in the next call's prompt instead).
        written = [b for b in content if not b.type.endswith("_tool_result")]
        return NS(input_tokens=prompt - cached, output_tokens=estimate_tokens(written),
                  cache_creation_input_tokens=0, cache_read_input_tokens=cached,
                  server_tool_use=NS(web_search_requests=searches))

    def _id(self, kind="toolu"):
        """A fresh tool-use id, unique across clients like real API ids."""
        self._ids += 1
        return f"{kind}_sim_{self._prefix}_{self._ids}"

    def _tool(self, tool_name, **args):
        """A client tool_use block. (The parameter isn't called ``name``: tools take a ``name`` argument.)"""
        return NS(type="tool_use", id=self._id(), name=tool_name, input=args)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _results(messages, start):
        """Tool name -> list of (content, is_error) for results after ``start``."""
        names, out = {}, {}
        for m in messages[start:]:
            if m["role"] == "assistant":
                for b in m["content"]:
                    if getattr(b, "type", None) == "tool_use":
                        names[b.id] = b.name
            elif isinstance(m["content"], list):
                for r in m["content"]:
                    out.setdefault(names.get(r["tool_use_id"]), []).append((r["content"], r.get("is_error", False)))
        return out

    # ------------------------------------------------------------------ Coordinator

    def _coordinator(self, messages):
        """Delegate according to the turn's plan, then summarize the specialists' replies."""
        user_turns = [i for i, m in enumerate(messages) if m["role"] == "user" and isinstance(m["content"], str)]
        plan = self.plans[len(user_turns) - 1]
        results = self._results(messages, user_turns[-1] + 1)
        if not results:
            calls = []
            if plan["action"] in ("security",):
                self.agent_plan["Security Agent"] = plan
                brief = "Check all stored passwords for breaches, weakness and reuse."
                if plan.get("rotate"):
                    brief += f" Then start a password rotation for the riskiest account ({plan['rotate']})."
                calls.append(self._tool("ask_security_agent", brief=brief))
            if plan["action"] in ("household", "multi"):
                self.agent_plan["Household Agent"] = plan
                calls.append(self._tool("ask_household_agent", brief=self._household_brief(plan)))
            if plan["action"] in ("travel", "multi"):
                self.agent_plan["Travel Agent"] = plan
                o, d = plan["route"]
                calls.append(self._tool("ask_travel_agent", brief=f"Find flights {o} to {d}; up to 5 options with sources."))
            return calls, "tool_use"
        replies = [c for name in ("ask_security_agent", "ask_household_agent", "ask_travel_agent")
                   for c, _ in results.get(name, [])]
        return [_text("\n\n".join(replies))], "end_turn"

    @staticmethod
    def _household_brief(plan):
        """The brief the scripted Coordinator writes for the Household Agent."""
        if plan.get("task") == "supply":
            return f"Track {plan['name']}: just restocked {plan['amount']} loads, about {plan['per_week']} loads a week. How long will it last?"
        if plan.get("task") == "outside_path":
            return f"The user wants their grocery list saved to {plan['path']}."
        return f"Add to the groceries list: {', '.join(plan['items'])}."

    # ------------------------------------------------------------------ Security Agent

    def _security(self, messages):
        """Check passwords, optionally start a rotation, then report (labels only)."""
        plan = self.agent_plan.get("Security Agent", {})
        results = self._results(messages, 1)
        if "check_password_breaches" not in results:
            return [self._tool("check_password_breaches")], "tool_use"
        if plan.get("rotate") and "start_password_rotation" not in results:
            return [self._tool("start_password_rotation", label=plan["rotate"])], "tool_use"
        checks = json.loads(results["check_password_breaches"][0][0])
        lines = [f"- {c['label']} ({c['site']}): {'; '.join(c['issues'])}" for c in checks if c["issues"]]
        text = "Password check:\n" + ("\n".join(lines) if lines else "No problems found.")
        if "start_password_rotation" in results:
            r = json.loads(results["start_password_rotation"][0][0])
            text += (f"\nI started a rotation for {r['label']}: change it at {r['change_password_url']}, "
                     f"then run /reveal {r['label']} --new and /rotated {r['label']}. Turn on two-factor authentication.")
        return [_text(text)], "end_turn"

    # ------------------------------------------------------------------ Household Agent

    def _household(self, messages):
        """Groceries, supplies, or (on purpose) a path outside the project for the path_guard demo."""
        plan = self.agent_plan.get("Household Agent", {})
        results = self._results(messages, 1)
        task = plan.get("task", "groceries")
        if task == "groceries" or plan.get("action") == "multi":
            if "add_grocery_items" not in results:
                return [self._tool("add_grocery_items", list_name="groceries",
                                   items=[{"name": n} for n in plan["items"]])], "tool_use"
            return [_text(f"Added {', '.join(plan['items'])} to your groceries list.")], "end_turn"
        if task == "supply":
            name = plan["name"]
            if "track_supply" not in results:
                return [self._tool("track_supply", name=name, unit="loads",
                                   configured_daily_use=round(plan["per_week"] / 7, 3), reorder_lead_days=5)], "tool_use"
            if "log_supply_reading" not in results:
                return [self._tool("log_supply_reading", name=name, kind="restock", amount=plan["amount"])], "tool_use"
            if "estimate_supplies" not in results:
                return [self._tool("estimate_supplies")], "tool_use"
            est = next(e for e in json.loads(results["estimate_supplies"][0][0]) if e["supply"] == name)
            return [_text(f"{name}: {est['remaining']} loads left at {est['daily_use']} a day, about "
                          f"{est['days_left']} days. Runs out around {est['runs_out_around']}; reorder by "
                          f"{est['reorder_by']}.")], "end_turn"
        # task == "outside_path": the scripted agent misbehaves on purpose, passing the path as an argument.
        if "show_grocery_lists" not in results:
            return [self._tool("show_grocery_lists", list_name=plan["path"])], "tool_use"
        if len(results["show_grocery_lists"]) == 1:
            return [self._tool("show_grocery_lists")], "tool_use"
        lists = json.loads(results["show_grocery_lists"][-1][0])
        summary = "; ".join(f"{k}: {', '.join(i['name'] for i in v) or 'empty'}" for k, v in lists.items()) \
            or "you don't have any lists yet"
        return [_text("I can't save files outside the assistant's own folder. Your lists stay in the encrypted "
                      f"vault instead ({summary}).")], "end_turn"

    # ------------------------------------------------------------------ Travel Agent

    def _travel(self, messages):
        """Read preferences if needed, run one (fictional) web search with pause_turn, then report."""
        plan = self.agent_plan.get("Travel Agent", {})
        o, d = plan.get("route", ("JFK", "LIS"))
        results = self._results(messages, 1)
        if plan.get("use_home") and "get_travel_preferences" not in results:
            return [self._tool("get_travel_preferences")], "tool_use"
        searched = any(getattr(b, "type", None) == "server_tool_use"
                       for m in messages if m["role"] == "assistant" for b in m["content"])
        if not searched:
            search_id = self._id("srvtoolu")
            hits = [NS(type="web_search_result", title=f"Example Air {o}-{d} nonstop (fictional listing)",
                       url=f"https://fares.example/{o.lower()}-{d.lower()}", page_age="2 days ago",
                       encrypted_content="x" * 600),
                    NS(type="web_search_result", title=f"Sample Fares {o} to {d} (fictional listing)",
                       url=f"https://flights.example/{o.lower()}/{d.lower()}", page_age="1 day ago",
                       encrypted_content="x" * 600)]
            return [NS(type="server_tool_use", id=search_id, name="web_search",
                       input={"query": f"nonstop flights {o} to {d}"}),
                    NS(type="web_search_tool_result", tool_use_id=search_id, content=hits)], "pause_turn"
        return [_text(f"Simulated search results for {o} to {d} (fictional sites, for testing only):\n"
                      f"- Example Air, nonstop: listed on fares.example\n- Sample Fares, 1 stop: listed on "
                      f"flights.example\nVerify prices on the airline's own site before booking.")], "end_turn"
