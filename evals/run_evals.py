"""Run the eval suite and write a results file.

    .\\run.ps1 eval                                         # offline: free, no network
    .\\run.ps1 eval --live --trials 3 --max-cost 8          # real agents and real HIBP

Offline (the default):

1. **Red-team:** every case in :mod:`evals.redteam`.
2. **Supply cross-check:** :mod:`evals.crosscheck_supplies` on 400 random histories.
3. **Scenarios, simulated:** every scripted conversation through the real hooks, vault,
   redactor and tools with the scripted stand-in for Claude and a mock HIBP, scored by
   the harness's 10 scorers and the 6 eval scorers.

``--live`` replaces step 3 with the real Claude agents and the real Have I Been Pwned
API, ``--trials`` times, and reports the pass rate of every scorer across trials. The
cost cap is checked between conversations; an API account problem (no credit, a bad
key) stops the run with the reason, keeping every conversation already scored.

Writes ``evals/results/<timestamp>-<mode>.json`` (secret-free summaries) and each
conversation's scrubbed trace under ``runs/``. Exit status 0 means everything passed.
"""

import argparse
import sys
from datetime import date, datetime

import httpx

from assistant.agents import PersonalAssistant
from assistant.harness.run_scenarios import (MOCK_PWNED, SCENARIO_PASSPHRASE, RecordingClient,
                                             seed_vault)
from assistant.harness.scenarios import SCENARIOS, SEED, score
from assistant.harness.tokens import ledger
from assistant.harness.trace import new_run_dir, write_json, write_trace
from assistant.household import Supplies
from assistant.paths import PROJECT_DIR, confine
from assistant.privacy import Redactor
from assistant.security import USER_AGENT, HIBPClient
from evals.crosscheck_supplies import crosscheck
from evals.redteam import _vault
from evals.scorers import score_eval

RESULTS_DIR = PROJECT_DIR / "evals" / "results"


def recording_hibp(live):
    """An HIBP client that records every request URL.

    Simulated mode answers from :data:`MOCK_PWNED` offline; live mode calls the real API.

    Returns:
        ``(client, urls)``.
    """
    urls = []
    if live:
        http = httpx.Client(timeout=15, headers={"user-agent": USER_AGENT},
                            event_hooks={"request": [lambda r: urls.append(str(r.url))]})
        return HIBPClient(http=http), urls

    def handler(request):
        """Record the request and answer like the range API (with a padding row)."""
        urls.append(str(request.url))
        prefix = request.url.path.rsplit("/", 1)[-1]
        rows = [f"{h[5:]}:{c}" for h, c in MOCK_PWNED.items() if h.startswith(prefix)] + ["0" * 35 + ":0"]
        return httpx.Response(200, text="\r\n".join(rows))
    return HIBPClient(http=httpx.Client(transport=httpx.MockTransport(handler))), urls


def converse(scenario, client, folder, live):
    """Play one conversation and return everything the scorers need.

    Args:
        scenario: A scenario dict.
        client: A ``SimulatedClient`` or ``anthropic.Anthropic`` client.
        folder: The conversation's folder (its vault and trace go here).
        live: Whether real agents (and the real HIBP) are used.

    Returns:
        ``{"transcript", "events", "sent", "vault", "trace_text", "hibp_urls", "seed_passwords"}``.
        The vault is still unlocked.
    """
    folder.mkdir(parents=True, exist_ok=True)
    vault = seed_vault(folder / "vault.enc")
    seed_passwords = {label: pw for label, _, _, pw, _ in SEED["logins"]}
    hibp, urls = recording_hibp(live)
    recorder = RecordingClient(client)
    pa = PersonalAssistant(recorder, vault, hibp=hibp)
    transcript, events = [], []
    for i, turn in enumerate(scenario["turns"]):
        result = pa.send(turn["say"])
        transcript.append({"say": turn["say"], **result})
        events += [{**e, "scenario": scenario["id"], "turn": i} for e in result["events"]]
    trace_path = write_trace(folder / "trace.jsonl", events, Redactor(vault))
    return {"transcript": transcript, "events": events, "sent": "\n".join(recorder.sent), "vault": vault,
            "trace_text": confine(trace_path).read_text(encoding="utf-8"), "hibp_urls": urls,
            "seed_passwords": seed_passwords}


def play(scenario, client, folder, live):
    """Play one conversation and score it with all 16 scorers.

    Returns:
        ``{"scores": {...}, "passed": bool, "cost": float, "tokens": int}``.
    """
    c = converse(scenario, client, folder, live)
    vault, transcript, events = c["vault"], c["transcript"], c["events"]
    scores = {**score(scenario, transcript, c["sent"], vault, vault.path.read_bytes(), live=live),
              **score_eval(scenario, transcript, events, vault, c["trace_text"], c["hibp_urls"],
                           c["seed_passwords"], SCENARIO_PASSPHRASE)}
    vault.lock()
    totals = ledger(events)["totals"]
    return {"scores": scores, "passed": all(s["ok"] for s in scores.values()),
            "cost": totals["cost"], "tokens": totals["tokens"]}


def _account_problem(exc):
    """True for errors no retry can fix: no credit, a bad key or no permission."""
    text = str(exc).lower()
    return (type(exc).__name__ in ("AuthenticationError", "PermissionDeniedError")
            or "credit balance" in text or "billing" in text)


def run_scenarios(mode, trials=1, max_cost=8.0, only=None):
    """Play every scenario ``trials`` times and aggregate the scores.

    Returns:
        ``{"mode", "trials", "conversations", "scorer_pass_rates", "scenario_pass_rates",
        "cost", "stopped_early", "stop_reason", "run_dir"}``.
    """
    live = mode == "live"
    if live:
        import anthropic
        live_client = anthropic.Anthropic()
    else:
        from assistant.harness.simulated import SimulatedClient
    run_dir = new_run_dir(f"eval-{mode}")
    scenarios = [SCENARIOS[only]] if only else list(SCENARIOS.values())
    conversations, spent, stopped, stop_reason = [], 0.0, False, None
    for trial in range(1, trials + 1):
        for sc in scenarios:
            if live and spent > max_cost:
                stopped, stop_reason = True, f"cost cap ${max_cost:.2f} reached"
                break
            client = live_client if live else SimulatedClient(sc)
            try:
                result = play(sc, client, run_dir / f"trial{trial}" / sc["id"], live)
            except Exception as exc:
                # A crashed conversation is a failed one, recorded with its cause, so the
                # conversations already scored are never lost.
                result = {"scores": {}, "passed": False, "cost": 0.0, "tokens": 0,
                          "error": f"{type(exc).__name__}: {exc}"}
            spent += result["cost"]
            conversations.append({"trial": trial, "scenario": sc["id"], **result})
            if "error" in result:
                print(f"  trial {trial} ERROR {sc['id']}: {result['error']}", flush=True)
                if _account_problem(Exception(result["error"])):
                    stopped, stop_reason = True, f"API account problem: {result['error']}"
                    break
                continue
            print(f"  trial {trial} {'PASS' if result['passed'] else 'FAIL'} {sc['id']}"
                  + "".join(f"\n      {k}: {v['detail']}" for k, v in result["scores"].items() if not v["ok"]),
                  flush=True)
        if stopped:
            break
    scorer_rates, scenario_rates = {}, {}
    for c in conversations:
        for name, s in c["scores"].items():
            tally = scorer_rates.setdefault(name, [0, 0])
            tally[0] += s["ok"]
            tally[1] += 1
        tally = scenario_rates.setdefault(c["scenario"], [0, 0])
        tally[0] += c["passed"]
        tally[1] += 1
    return {"mode": mode, "trials": trials, "conversations": conversations,
            "scorer_pass_rates": scorer_rates, "scenario_pass_rates": scenario_rates,
            "cost": round(spent, 4), "stopped_early": stopped, "stop_reason": stop_reason,
            "run_dir": str(run_dir)}


def run_all(live=False, trials=1, max_cost=8.0, only=None, write=True):
    """Run the red-team, the supply cross-check and the scenarios, then write the results.

    Returns:
        The results dict, with ``"ok"`` true when every layer passed.
    """
    from evals.redteam import run_redteam
    redteam = run_redteam()
    supplies = crosscheck(lambda today: Supplies(_vault(), today=today))
    scenarios = run_scenarios("live" if live else "simulated", trials if live else 1, max_cost, only)
    ok = (redteam["passed"] == redteam["total"] and supplies["ok"]
          and all(p == t for p, t in scenarios["scenario_pass_rates"].values()) and not scenarios["stopped_early"])
    results = {"ran_at": datetime.now().isoformat(timespec="seconds"), "ok": ok,
               "redteam": {k: v for k, v in redteam.items() if k != "cases"}, "redteam_cases": redteam["cases"],
               "supplies_crosscheck": {**supplies, "on": date.today().isoformat()}, "scenarios": scenarios}
    if write:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = confine(RESULTS_DIR / f"{stamp}-{scenarios['mode']}.json")
        results["results_file"] = path.relative_to(PROJECT_DIR).as_posix()
        write_json(path, results)
    return results


def main(argv=None):
    """Command-line entry point. Returns 0 if everything passed, else 1."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--live", action="store_true", help="real Claude agents and real HIBP (costs money)")
    parser.add_argument("--trials", type=int, default=3, help="live trials per scenario (default 3)")
    parser.add_argument("--max-cost", type=float, default=8.0, help="live spending cap in USD (default 8)")
    parser.add_argument("--only", choices=sorted(SCENARIOS), help="run one scenario")
    args = parser.parse_args(argv)
    print("Scenarios (" + (f"LIVE, {args.trials} trial(s)" if args.live else "simulated") + "):")
    r = run_all(args.live, args.trials, args.max_cost, args.only)
    rt, sx, sc = r["redteam"], r["supplies_crosscheck"], r["scenarios"]
    print(f"\nRed-team: {rt['passed']}/{rt['total']}  "
          + "  ".join(f"{g} {p}/{t}" for g, (p, t) in rt["by_guardrail"].items()))
    for f in rt["failures"]:
        print(f"  FAIL {f['id']}: {f['description']} {f.get('error', '')}")
    print(f"Supply cross-check: {sx['checked']} histories, {sx['fields_compared']:,} fields, "
          f"{len(sx['mismatches'])} mismatches; coverage {sx['coverage']}")
    print("Scorer pass rates:")
    for name, (p, t) in sc["scorer_pass_rates"].items():
        print(f"  {name:<26} {p}/{t}")
    passed = sum(p for p, _ in sc["scenario_pass_rates"].values())
    total = sum(t for _, t in sc["scenario_pass_rates"].values())
    cost_label = "cost" if sc["mode"] == "live" else "estimated cost (simulated)"
    print(f"Conversations passed: {passed}/{total}   {cost_label} ${sc['cost']:.2f}"
          + (f"   STOPPED EARLY: {sc['stop_reason']}" if sc["stopped_early"] else ""))
    print(f"\n{'ALL PASSED' if r['ok'] else 'FAILURES ABOVE'}  ->  {r.get('results_file')}")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
