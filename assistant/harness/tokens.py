"""Token and cost accounting per agent and per tool.

The Messages API reports usage per **model call**, not per tool, so per-tool usage is
attributed from the runtime's events:

* **Decision tokens** (to call a tool): the output tokens of the model call that
  requested it, split by argument size when one call requests several tools. Output
  includes the model's reasoning, so this is "what it cost to decide on and write the call".
* **Result tokens** (to read the result): how much the agent's prompt grew on its next
  call, minus the previous call's output (now part of the history), split by result size.
  For web search, the size of the search results in the response is used.
* **Specialist tokens**: the delegation tools (``ask_security_agent``,
  ``ask_travel_agent``, ``ask_household_agent``) also carry everything the specialist's
  run used.

Per-agent totals are exact sums of reported usage; per-tool numbers are an attribution.
Totals include cache reads. Web searches are counted separately and priced per search.
Ids are keyed by ``(scenario, id)`` so combined scenarios never mix.
"""

from collections import defaultdict

#: USD per million tokens, as configured for claude-opus-5-5. Check current pricing.
PRICES = {"input": 4.00, "output": 20.00, "cache_write": 5.00, "cache_read": 0.20}
#: USD per web search, as configured. Check current pricing.
WEB_SEARCH_PRICE = 10.00 / 1000
TOKEN_KINDS = ("input", "output", "cache_write", "cache_read")


def cost_of(usage):
    """USD cost of a usage dict: tokens at :data:`PRICES` plus web searches at :data:`WEB_SEARCH_PRICE`."""
    return (sum(usage.get(k, 0) * PRICES[k] for k in TOKEN_KINDS) / 1_000_000
            + usage.get("web_searches", 0) * WEB_SEARCH_PRICE)


def tokens_of(usage):
    """All tokens of one call (input + output + cache writes + cache reads)."""
    return sum(usage.get(k, 0) for k in TOKEN_KINDS)


def _prompt(usage):
    """Prompt-side tokens of one call."""
    return usage["input"] + usage["cache_write"] + usage["cache_read"]


def _split(total, weights):
    """Split ``total`` across ``weights`` proportionally (equally if all are 0)."""
    s = sum(weights)
    return [total * (w / s if s else 1 / len(weights)) for w in weights] if weights else []


def ledger(events):
    """Build the ledger from one session's (or one suite's) events.

    Args:
        events: Events from ``PersonalAssistant.send(...)["events"]``, in order (optionally
            tagged with ``scenario``). Uses ``model_call`` and ``tool_result`` events.

    Returns:
        ``{"agents": {...}, "tools": {...}, "totals": {...}}``:

        * ``agents[name]``: ``calls, input, output, cache_write, cache_read, web_searches, total, cost``
        * ``tools[name]``: ``calls, errors, server, decision, result, specialist, total, cost``
        * ``totals``: ``tokens, cost, model_calls, tool_calls, web_searches``
    """
    agents = defaultdict(lambda: {"calls": 0, **{k: 0 for k in TOKEN_KINDS}, "web_searches": 0,
                                  "total": 0, "cost": 0.0})
    tools = defaultdict(lambda: {"calls": 0, "errors": 0, "server": False, "decision": 0.0, "result": 0.0,
                                 "specialist": 0.0, "total": 0.0, "cost": 0.0})
    runs, results, run_parent, names = defaultdict(list), {}, {}, {}
    for e in events:
        scope = e.get("scenario")
        if e.get("type") == "model_call":
            runs[(scope, e["run"])].append(e)
            # An event with a parent sets the link; one without never erases it.
            if e.get("parent"):
                run_parent[(scope, e["run"])] = (scope, e["parent"])
            else:
                run_parent.setdefault((scope, e["run"]), None)
            for tu in e["tool_uses"]:
                names[(scope, tu["id"])] = tu["name"]
        elif e.get("type") == "tool_result":
            results[(scope, e["id"])] = e

    run_usage = {}
    for key, calls in runs.items():
        total = defaultdict(int)
        for c in calls:
            a = agents[c["agent"]]
            a["calls"] += 1
            for k in (*TOKEN_KINDS, "web_searches"):
                a[k] += c["usage"].get(k, 0)
                total[k] += c["usage"].get(k, 0)
            a["total"] += tokens_of(c["usage"])
            a["cost"] += cost_of(c["usage"])
        run_usage[key] = dict(total)

    for key, calls in runs.items():
        scope = key[0]
        for i, c in enumerate(calls):
            tus = c["tool_uses"]
            if not tus:
                continue
            decision = _split(c["usage"]["output"], [t["input_chars"] for t in tus])
            n_server = sum(1 for t in tus if t.get("server"))
            sizes = [(c.get("server_result_chars", 0) / n_server) if t.get("server")
                     else results.get((scope, t["id"]), {}).get("result_chars", 0) for t in tus]
            if i + 1 < len(calls):
                grown = _prompt(calls[i + 1]["usage"]) - _prompt(c["usage"]) - c["usage"]["output"]
                result = _split(max(grown, 0), sizes)
            else:
                result = [0.0] * len(tus)
            for t, d, r in zip(tus, decision, result):
                row = tools[t["name"]]
                row["calls"] += 1
                row["server"] = row["server"] or bool(t.get("server"))
                row["errors"] += 0 if results.get((scope, t["id"]), {}).get("ok", True) else 1
                row["decision"] += d
                row["result"] += r
                row["cost"] += (d * PRICES["output"] + r * PRICES["input"]) / 1_000_000
                if t.get("server"):
                    row["cost"] += WEB_SEARCH_PRICE        # each server web_search call is one search

    for key, parent in run_parent.items():
        if parent is not None and parent in names:
            row = tools[names[parent]]
            row["specialist"] += tokens_of(run_usage[key])
            row["cost"] += cost_of(run_usage[key])

    for row in tools.values():
        for k in ("decision", "result", "specialist"):
            row[k] = round(row[k])
        row["total"] = row["decision"] + row["result"] + row["specialist"]
        row["cost"] = round(row["cost"], 4)
    for row in agents.values():
        row["cost"] = round(row["cost"], 4)
    totals = {"tokens": sum(a["total"] for a in agents.values()),
              "cost": round(sum(a["cost"] for a in agents.values()), 4),
              "model_calls": sum(a["calls"] for a in agents.values()),
              "tool_calls": sum(t["calls"] for t in tools.values()),
              "web_searches": sum(a["web_searches"] for a in agents.values())}
    return {"agents": dict(agents), "tools": dict(tools), "totals": totals}
