"""Harness tests: token attribution, the simulated scenario suite, scorers and trace scrubbing."""

import json
import secrets

import pytest

from assistant.harness.run_scenarios import run_suite
from assistant.harness.scenarios import SCENARIOS, score
from assistant.harness.simulated import estimate_tokens
from assistant.harness.tokens import PRICES, WEB_SEARCH_PRICE, cost_of, ledger
from assistant.harness.trace import scrub, write_trace
from assistant.paths import CACHE_DIR


def model_call(run, agent, usage, tool_uses=(), parent=None, server_chars=0):
    """A model_call event; usage is (input, output, cache_write, cache_read, web_searches)."""
    keys = ("input", "output", "cache_write", "cache_read", "web_searches")
    return {"type": "model_call", "run": run, "agent": agent, "parent": parent,
            "usage": dict(zip(keys, usage)), "server_result_chars": server_chars,
            "tool_uses": [{"id": i, "name": n, "input_chars": c, "server": s} for i, n, c, s in tool_uses]}


def tool_result(id_, chars, ok=True):
    """A tool_result event."""
    return {"type": "tool_result", "id": id_, "ok": ok, "result_chars": chars}


def test_ledger_attributes_decision_result_specialist_and_web_search():
    """Decision/result/specialist tokens follow the documented method; web searches are counted."""
    events = [
        model_call(1, "Coordinator", (1000, 300, 0, 0, 0), [("a", "ask_travel_agent", 100, False),
                                                            ("b", "ask_household_agent", 200, False)]),
        # The Travel Agent's run (from call "a"): one web search, then an answer.
        model_call(2, "Travel Agent", (400, 60, 0, 0, 1), [("s", "web_search", 50, True)], parent="a", server_chars=800),
        model_call(2, "Travel Agent", (100, 40, 0, 600, 0)),
        tool_result("a", 600), tool_result("b", 200, ok=False),
        model_call(1, "Coordinator", (100, 40, 0, 2000, 0)),
    ]
    led = ledger(events)
    travel, house, search = led["tools"]["ask_travel_agent"], led["tools"]["ask_household_agent"], led["tools"]["web_search"]
    assert (travel["decision"], house["decision"]) == (100, 200)          # 300 output split 1:2
    assert (travel["result"], house["result"]) == (600, 200)              # 2100-1000-300 = 800 split 3:1
    assert travel["specialist"] == 400 + 60 + 100 + 40 + 600 and house["specialist"] == 0
    # The search: all 60 output tokens of its call; result = (100+600) - 400 - 60 = 240 prompt growth.
    assert search["server"] and search["decision"] == 60 and search["result"] == 240
    assert house["errors"] == 1 and led["totals"]["web_searches"] == 1


def test_scenarios_never_mix_ids():
    """Ids repeated across scenarios stay separate (keyed by scenario)."""
    a = [{**e, "scenario": "A"} for e in [model_call(1, "Coordinator", (10, 5, 0, 0, 0), [("x", "ask_travel_agent", 1, False)]),
                                          model_call(2, "Travel Agent", (30, 3, 0, 0, 0), parent="x")]]
    b = [{**e, "scenario": "B"} for e in [model_call(1, "Household Agent", (10, 5, 0, 0, 0), [("x", "add_grocery_items", 1, False)])]]
    tools = ledger(a + b)["tools"]
    assert tools["ask_travel_agent"]["specialist"] == 33 and tools["add_grocery_items"]["specialist"] == 0


def test_cost_uses_configured_prices():
    """Cost = tokens x price per million, plus web searches x price per search."""
    assert cost_of({"input": 1_000_000}) == PRICES["input"]
    assert cost_of({"web_searches": 2}) == pytest.approx(2 * WEB_SEARCH_PRICE)


def test_estimate_tokens_is_chars_over_four():
    """The simulated estimate is JSON characters / 4, rounded up."""
    assert estimate_tokens("x" * 10) == 3


@pytest.fixture(scope="module")
def suite():
    """The whole simulated suite, run once for this module (no run folder written)."""
    return run_suite("simulated", write=False)


@pytest.mark.parametrize("sid", sorted(SCENARIOS))
def test_every_simulated_scenario_passes_every_scorer(suite, sid):
    """Each scenario passes all scorers through the real runtime, hooks, redactor and vault."""
    failed = {k: v["detail"] for k, v in suite["scenarios"][sid]["scores"].items() if not v["ok"]}
    assert not failed


def test_suite_ledger_covers_every_agent_and_tool(suite):
    """The suite reports tokens for all four agents and every tool the scenarios use, including web search."""
    led = suite["ledger"]
    assert set(led["agents"]) == {"Coordinator", "Security Agent", "Travel Agent", "Household Agent"}
    assert {"ask_security_agent", "ask_travel_agent", "ask_household_agent", "web_search", "check_password_breaches",
            "start_password_rotation", "add_grocery_items", "track_supply", "estimate_supplies"} <= set(led["tools"])
    assert led["totals"]["web_searches"] >= 1 and suite["mode"] == "simulated"


def test_scorers_fail_on_a_broken_scenario():
    """The scorers catch leaked secrets, a plaintext vault, wrong hooks and out-of-role tool calls."""
    sc = SCENARIOS["breach-check-rotation"]

    class V:
        """A stand-in vault with a leaky transcript."""
        data = {"credentials": {"github": {"pending_password": None}}, "transcript": [{"text": "password123"}]}

    bad = [{"reply": "x", "redactions": [], "guardrails": ["path_guard: blocked"],
            "events": [{"type": "tool_call", "agent": "Household Agent", "tool": "check_password_breaches"}]}]
    scores = score(sc, bad, "sent: password123", V(), b'{"grocery_lists": "plaintext"}')
    for name in ("no_secrets_sent", "transcript_redacted", "vault_encrypted_on_disk", "expected_guardrails",
                 "least_privilege", "final_state"):
        assert not scores[name]["ok"], name


def test_trace_is_scrubbed_and_confined():
    """Traces never contain emails or stored secrets."""
    class R:
        """A redactor that knows one secret."""
        def redact(self, t):
            """Replace the secret with its tag."""
            return t.replace("password123", "[password:github]"), []
    out = CACHE_DIR / "test-output" / secrets.token_hex(6) / "trace.jsonl"
    write_trace(out, [{"input": {"note": "password123 for ada@example.com"}}], R())
    line = json.loads(out.read_text(encoding="utf-8"))
    assert line == {"input": {"note": "[password:github] for [email]"}}
    assert scrub(["a@b.co"]) == ["[email]"]
