"""The eval suite: every layer passes on the real code, and each one fails when it should.

An eval that can't fail proves nothing, so most tests here plant a defect (switch off a
guardrail, break the supply math, leak a secret into a trace) and check that the
matching red-team cases, cross-check or scorer catch it.
"""

import json
import secrets as pysecrets
from datetime import date

import pytest

from assistant import guardrails, household, privacy
from assistant.harness.scenarios import SCENARIOS
from assistant.harness.simulated import SimulatedClient
from assistant.harness.run_scenarios import SCENARIO_PASSPHRASE
from assistant.household import Supplies
from assistant.paths import CACHE_DIR
from evals import redteam
from evals.crosscheck_supplies import crosscheck, independent_estimate
from evals.run_evals import converse, play, run_all, run_scenarios
from evals.scorers import score_eval


def _results(cases):
    """Run some red-team cases and return ``{case id: ok}``."""
    return {c["id"]: c["ok"] for c in redteam.run_redteam(cases)["cases"]}


def _attacks(cases):
    """The attack cases in a list."""
    return [c for c in cases if c.kind == "attack"]


def test_redteam_all_pass_and_cover_every_guardrail():
    """Every case passes, and each guardrail has attacks; most also have benign look-alikes."""
    r = redteam.run_redteam()
    assert r["passed"] == r["total"] >= 70, r["failures"]
    for gid in ("G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8", "G9", "HIBP"):
        kinds = {c.kind for c in redteam.CASES if c.guardrail == gid}
        assert kinds == {"attack", "benign"}, gid
    assert len({c.id for c in redteam.CASES}) == len(redteam.CASES)


def test_redteam_catches_a_disabled_input_check(monkeypatch):
    """With G1 switched off, every G1 attack fails and every benign case still passes."""
    monkeypatch.setattr(guardrails, "check_user_message", lambda text: guardrails.InputCheck(True, text))
    res = _results(redteam.G1_CASES)
    assert not any(res[c.id] for c in _attacks(redteam.G1_CASES))
    assert all(res[c.id] for c in redteam.G1_CASES if c.kind == "benign")


def test_redteam_catches_a_disabled_redactor(monkeypatch):
    """With redaction switched off, every masking attack fails."""
    monkeypatch.setattr(privacy.Redactor, "redact", lambda self, text: (text, []))
    res = _results(redteam.G4_CASES)
    masking = [c for c in _attacks(redteam.G4_CASES) if not c.id.startswith("g4-outbound")]
    assert masking and not any(res[c.id] for c in masking)


def test_redteam_catches_a_disabled_path_guard(monkeypatch):
    """With path detection switched off, every path-escape attack fails."""
    monkeypatch.setattr(guardrails, "outside_paths", lambda value: [])
    res = _results(redteam.G8_CASES)
    assert not any(res[c.id] for c in _attacks(redteam.G8_CASES))


def test_redteam_catches_an_empty_human_only_list(monkeypatch):
    """With the human-only list emptied, agents can be given reveal/export tools, and that's caught."""
    monkeypatch.setattr(guardrails, "HUMAN_ONLY", frozenset())
    res = _results(redteam.G3_CASES)
    assert not res["g3-reveal-password"] and not res["g3-export-vault"]


def test_redteam_reports_a_crashing_case_as_failed():
    """A case that raises is recorded as a failure with its error, not a crash of the suite."""
    r = redteam.run_redteam([redteam.Case("boom", "G1", "attack", "raises", lambda: 1 / 0)])
    assert r["passed"] == 0 and "ZeroDivisionError" in r["failures"][0]["error"]


# ------------------------------------------------------------------ supply cross-check

def _supplies(today):
    """Supplies on a fresh red-team vault."""
    return Supplies(redteam._vault(), today=today)


def test_supply_crosscheck_agrees_and_covers_every_branch():
    """400 random histories agree field by field, and every branch of the method is exercised."""
    r = crosscheck(_supplies)
    assert r["ok"] and r["checked"] == 400 and r["fields_compared"] == 2000
    assert all(n > 0 for n in r["coverage"].values()), r["coverage"]


def test_supply_crosscheck_catches_restock_intervals_being_counted(monkeypatch):
    """If restock intervals were counted as usage (a plausible bug), the cross-check finds mismatches."""
    def buggy(self, readings):
        """Learned daily use that wrongly includes intervals ending in a restock."""
        used = days = 0
        for prev, cur in zip(readings, readings[1:]):
            span = (date.fromisoformat(cur["date"]) - date.fromisoformat(prev["date"])).days
            if span > 0:
                used += abs(prev["amount"] - cur["amount"])
                days += span
        return used / days if days else None
    monkeypatch.setattr(household.Supplies, "_learned_daily_use", buggy)
    assert crosscheck(_supplies)["mismatches"]


def test_supply_crosscheck_catches_an_off_by_one_reorder_date(monkeypatch):
    """A reorder-by date one day off is caught."""
    original = household.Supplies.estimate

    def shifted(self, name):
        """The real estimate with reorder_by moved a day later."""
        est = original(self, name)
        if est.get("reorder_by"):
            est["reorder_by"] = date.fromordinal(date.fromisoformat(est["reorder_by"]).toordinal() + 1).isoformat()
        return est
    monkeypatch.setattr(household.Supplies, "estimate", shifted)
    assert any(m["field"] == "reorder_by" for m in crosscheck(_supplies)["mismatches"])


def test_independent_estimate_matches_a_hand_calculation():
    """64 loads restocked 10 days ago, 34 left 4 days ago: 5 loads a day, 14 left today, 2.8 days."""
    today = date(2027, 3, 20)
    readings = [{"date": "2027-03-10", "kind": "restock", "amount": 64},
                {"date": "2027-03-16", "kind": "level", "amount": 34}]
    est = independent_estimate(readings, None, 2, today)
    assert est == {"daily_use": 5.0, "remaining": 14.0, "days_left": 2.8,
                   "runs_out_around": "2027-03-22", "reorder_by": "2027-03-20"}


# ------------------------------------------------------------------ scorers on planted defects

@pytest.fixture
def rotation():
    """A real simulated breach-check-rotation conversation (it stages a new password)."""
    sc = SCENARIOS["breach-check-rotation"]
    folder = CACHE_DIR / "test-output" / "evals" / pysecrets.token_hex(6)
    c = converse(sc, SimulatedClient(sc), folder, live=False)
    return {**c, "sc": sc}


def _score(c, **overrides):
    """Score the conversation, optionally with a planted defect."""
    args = {"scenario": c["sc"], "transcript": c["transcript"], "events": c["events"], "vault": c["vault"],
            "trace_text": c["trace_text"], "hibp_requests": c["hibp_urls"], "seed_passwords": c["seed_passwords"],
            "passphrase": SCENARIO_PASSPHRASE, **overrides}
    return score_eval(**args)


def test_eval_scorers_pass_on_a_good_conversation(rotation):
    """All six eval scorers pass, and the conversation really did query HIBP and stage a password."""
    scores = _score(rotation)
    assert all(s["ok"] for s in scores.values()), scores
    assert rotation["hibp_urls"] and rotation["vault"].data["credentials"]["github"]["pending_password"]


def test_trace_scrubbed_catches_a_secret_on_disk(rotation):
    """A trace containing a stored password fails ``trace_scrubbed``."""
    assert not _score(rotation, trace_text=rotation["trace_text"] + '\n{"x": "password123"}')["trace_scrubbed"]["ok"]


def test_replies_secret_free_catches_the_staged_password(rotation):
    """A reply that shows the newly staged password fails ``replies_secret_free``."""
    staged = rotation["vault"].data["credentials"]["github"]["pending_password"]
    bad = [dict(t) for t in rotation["transcript"]]
    bad[-1]["reply"] += f"\nYour new password is {staged}"
    assert not _score(rotation, transcript=bad)["replies_secret_free"]["ok"]


def test_human_only_untouched_catches_a_reveal_call_and_a_changed_password(rotation):
    """A reveal_password call, or a stored password that changed, fails ``human_only_untouched``."""
    events = rotation["events"] + [{"type": "tool_call", "tool": "reveal_password", "agent": "Security Agent"}]
    assert not _score(rotation, events=events)["human_only_untouched"]["ok"]
    rotation["vault"].data["credentials"]["bank"]["password"] = "changed-by-an-agent"
    assert not _score(rotation)["human_only_untouched"]["ok"]


def test_hibp_k_anonymity_catches_a_full_hash(rotation):
    """A request carrying the full SHA-1 of a password fails ``hibp_k_anonymity``."""
    import hashlib
    full = hashlib.sha1(b"password123").hexdigest().upper()
    urls = rotation["hibp_urls"] + [f"https://api.pwnedpasswords.com/range/{full}"]
    assert not _score(rotation, hibp_requests=urls)["hibp_k_anonymity"]["ok"]


def test_vault_reopens_catches_a_corrupted_file(rotation):
    """A vault file damaged after the conversation fails ``vault_reopens``."""
    env = json.loads(rotation["vault"].path.read_text("utf-8"))
    env["ct"] = env["ct"][:-8] + "AAAAAAAA"
    rotation["vault"].path.write_text(json.dumps(env), "utf-8")
    assert not _score(rotation)["vault_reopens"]["ok"]


def test_supplies_recomputed_catches_a_wrong_estimate(monkeypatch):
    """If the app's estimate drifts from the documented method, ``supplies_recomputed`` fails."""
    sc = SCENARIOS["groceries-detergent"]
    c = {**converse(sc, SimulatedClient(sc), CACHE_DIR / "test-output" / "evals" / pysecrets.token_hex(6), False),
         "sc": sc}
    assert _score(c)["supplies_recomputed"]["ok"] and c["vault"].data["supplies"]
    original = household.Supplies.estimate
    monkeypatch.setattr(household.Supplies, "estimate",
                        lambda self, name: {**original(self, name), "days_left": 999.0})
    assert not _score(c)["supplies_recomputed"]["ok"]


# ------------------------------------------------------------------ the runner

def test_play_scores_with_all_sixteen_scorers():
    """``play`` scores a conversation with the 10 harness and 6 eval scorers (final_state where defined)."""
    sc = SCENARIOS["card-number-pasted"]
    result = play(sc, SimulatedClient(sc), CACHE_DIR / "test-output" / "evals" / pysecrets.token_hex(6), False)
    assert result["passed"] and len(result["scores"]) == 16


def test_offline_suite_passes_and_results_hold_no_secrets():
    """The offline suite passes end to end, and nothing secret appears in its results."""
    r = run_all(write=False)
    assert r["ok"], r["scenarios"]["scorer_pass_rates"]
    text = json.dumps(r, default=str)
    for secret in ("password123", "adalove", "ada.l.1815", "Tr0ub4dor&3", "ada_shop", "ada@example.com",
                   "4111 1111 1111 1111"):
        assert secret not in text, secret
    assert len(r["scenarios"]["conversations"]) == len(SCENARIOS)


class _NoCreditClient:
    """A client whose every call fails the way the API does when the account has no credit."""

    def __init__(self):
        """Expose ``beta.messages.create`` like the real client."""
        from types import SimpleNamespace
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._fail))

    def _fail(self, **kwargs):
        """Raise the API's out-of-credit error."""
        raise RuntimeError("Error code: 400 - Your credit balance is too low to access the Anthropic API.")


def test_live_run_stops_cleanly_on_an_account_problem(monkeypatch):
    """An out-of-credit API is recorded as an error and stops the run instead of crashing it."""
    import anthropic
    monkeypatch.setattr(anthropic, "Anthropic", _NoCreditClient)
    sc = run_scenarios("live", trials=2, only="groceries-detergent")
    assert sc["stopped_early"] and "credit balance" in sc["stop_reason"]
    assert len(sc["conversations"]) == 1 and "error" in sc["conversations"][0]
