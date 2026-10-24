"""Run the scripted scenarios through the real agent team and write a run report.

    .\\run.ps1 scenarios                        # simulated: no API key, no cost, no network
    .\\run.ps1 scenarios --only flight-search
    .\\run.ps1 scenarios --live --max-cost 5    # real Claude agents and real HIBP lookups

Each scenario gets a fresh vault seeded with a fictional user (see ``scenarios.SEED``),
stored inside the run folder. Scenario vaults use a faster scrypt setting (N = 2^14)
so runs are quick; real vaults use N = 2^17. In simulated mode, Have I Been Pwned is
replaced by an offline mock that knows one fictional breached password.

Output ``runs/<timestamp>-<mode>/``:
    <scenario>/vault.enc     the scenario's encrypted vault (checked by a scorer)
    <scenario>/trace.jsonl   every event, secrets removed
    <scenario>/report.json   transcript, scores and token ledger
    summary.json             all scores and the suite ledger per agent and per tool
"""

import argparse
import hashlib
import json
import secrets
import sys

import httpx

from assistant.agents import PersonalAssistant
from assistant.harness.scenarios import SCENARIOS, SEED, score
from assistant.harness.tokens import ledger
from assistant.harness.trace import new_run_dir, write_json, write_trace
from assistant.hooks import to_plain
from assistant.paths import CACHE_DIR
from assistant.security import HIBPClient
from assistant.vault import Vault

SCENARIO_SCRYPT_N = 2 ** 14
SCENARIO_PASSPHRASE = "scenario passphrase, not a real one"
#: The mock HIBP's "breach corpus": the fictional seed password and a made-up count.
MOCK_PWNED = {hashlib.sha1(b"password123").hexdigest().upper(): 251_682}


class RecordingClient:
    """Wraps a Claude client and records everything sent to it (as text) for the privacy scorer.

    Args:
        client: The real or simulated client.
    """

    def __init__(self, client):
        """Wrap ``client``; ``sent`` collects one JSON string per request."""
        self.client, self.sent = client, []
        outer = self

        class _Messages:
            """Stand-in for ``client.beta.messages`` that records, then forwards."""

            def create(self, **kw):
                """Record the system prompt, tools and messages, then call the wrapped client."""
                outer.sent.append(json.dumps(to_plain({"system": kw["system"], "tools": kw["tools"],
                                                       "messages": kw["messages"]}), default=str))
                return outer.client.beta.messages.create(**kw)

        self.beta = type("Beta", (), {"messages": _Messages()})()


def mock_hibp():
    """An offline HIBP client: k-anonymity range responses from :data:`MOCK_PWNED`, with padding rows."""
    def handler(request):
        """Answer a range query like the real API (suffix:count lines)."""
        prefix = request.url.path.rsplit("/", 1)[-1]
        lines = [f"{h[5:]}:{c}" for h, c in MOCK_PWNED.items() if h.startswith(prefix)]
        lines.append("0000000000000000000000000000000000A:0")
        return httpx.Response(200, text="\r\n".join(lines))
    return HIBPClient(http=httpx.Client(transport=httpx.MockTransport(handler)))


def seed_vault(path):
    """Create a vault at ``path`` with the fictional user's emails, logins and home airport."""
    vault = Vault.create(path, SCENARIO_PASSPHRASE, scrypt_n=SCENARIO_SCRYPT_N)
    for label, address in SEED["emails"].items():
        vault.data["emails"][label] = address
    for label, site, username, password, email_label in SEED["logins"]:
        vault.data["credentials"][label] = {"site": site, "username": username, "password": password,
                                            "email_label": email_label, "added": None, "last_rotated": None,
                                            "pending_password": None, "last_check": None}
    vault.data["travel"]["home_airport"] = SEED["home_airport"]
    vault.save()
    return vault


def run_scenario(scenario, client, folder, hibp=None):
    """Play one scenario through a fresh :class:`PersonalAssistant`.

    Args:
        scenario: A scenario dict.
        client: Simulated or real Claude client (wrapped here for recording).
        folder: Where the scenario's vault goes (inside the project).
        hibp: HIBP client (mock in simulated mode; real if ``None``).

    Returns:
        ``(transcript, events, sent_text, vault)``.
    """
    vault = seed_vault(folder / "vault.enc")
    recorder = RecordingClient(client)
    pa = PersonalAssistant(recorder, vault, hibp=hibp)
    transcript, events = [], []
    for i, turn in enumerate(scenario["turns"]):
        result = pa.send(turn["say"])
        transcript.append({"say": turn["say"], **result})
        events += [{**e, "scenario": scenario["id"], "turn": i} for e in result["events"]]
    return transcript, events, "\n".join(recorder.sent), vault


def run_suite(mode="simulated", only=None, max_cost=5.0, write=True):
    """Run all scenarios (or one) and return the summary.

    Args:
        mode: ``"simulated"`` or ``"live"``.
        only: One scenario id, or ``None`` for all.
        max_cost: Live mode: stop before the next scenario once spending passes this (USD).
            Checked between scenarios, so the last one can go somewhat over.
        write: Write ``runs/<id>/``; otherwise scenario vaults go to ``.cache/test-output/``.

    Returns:
        The summary dict (also written as ``summary.json`` when ``write``).
    """
    if mode == "live":
        import anthropic
        live = anthropic.Anthropic()
    else:
        from assistant.harness.simulated import SimulatedClient
    base = new_run_dir(mode) if write else CACHE_DIR / "test-output" / secrets.token_hex(6)
    chosen = [SCENARIOS[only]] if only else list(SCENARIOS.values())
    results, all_events, spent = {}, [], 0.0
    for sc in chosen:
        if mode == "live" and spent > max_cost:
            results[sc["id"]] = {"skipped": f"cost cap ${max_cost:.2f} reached"}
            continue
        folder = base / sc["id"]
        folder.mkdir(parents=True, exist_ok=True)
        client = live if mode == "live" else SimulatedClient(sc)
        transcript, events, sent, vault = run_scenario(sc, client, folder, None if mode == "live" else mock_hibp())
        scores = score(sc, transcript, sent, vault, (folder / "vault.enc").read_bytes(), live=(mode == "live"))
        led = ledger(events)
        spent += led["totals"]["cost"]
        all_events += events
        redactor = None
        results[sc["id"]] = {"title": sc["title"], "scores": scores, "ledger": led,
                             "passed": all(s["ok"] for s in scores.values()),
                             "transcript": [{k: t[k] for k in ("say", "reply", "redactions", "guardrails")}
                                            for t in transcript]}
        if write:
            from assistant.privacy import Redactor
            redactor = Redactor(vault)
            write_trace(folder / "trace.jsonl", events, redactor)
            write_json(folder / "report.json", results[sc["id"]], redactor)
        vault.lock()
    summary = {"mode": mode, "scenarios": results, "ledger": ledger(all_events),
               "passed": sum(1 for r in results.values() if r.get("passed")), "total": len(results),
               "run_dir": str(base) if write else None}
    if write:
        # The suite summary is scrubbed of seeded secrets by masking emails and replacing known values.
        write_json(base / "summary.json", summary, _SeedRedactor())
    return summary


class _SeedRedactor:
    """Minimal redactor for the suite summary: masks the seeded secrets wherever they appear."""

    def redact(self, text):
        """Replace each seeded secret with ``[secret]``; returns ``(text, tags)``."""
        from assistant.harness.scenarios import SEED_SECRETS
        for s in sorted(SEED_SECRETS, key=len, reverse=True):
            text = text.replace(s, "[secret]")
        return text, []


def main(argv=None):
    """Command-line entry point: run the suite and print scores and the token ledger.

    Returns:
        0 if every scenario passed, else 1.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--live", action="store_true", help="use the real Claude API and HIBP (costs money)")
    parser.add_argument("--max-cost", type=float, default=5.0, help="live-mode cost cap in USD")
    parser.add_argument("--only", choices=sorted(SCENARIOS), help="run one scenario")
    args = parser.parse_args(argv)
    summary = run_suite("live" if args.live else "simulated", args.only, args.max_cost)
    print(f"\nScenarios, {'LIVE' if args.live else 'SIMULATED (token counts are estimates)'}")
    for sid, r in summary["scenarios"].items():
        if "skipped" in r:
            print(f"  SKIP {sid}: {r['skipped']}")
            continue
        failed = [k for k, s in r["scores"].items() if not s["ok"]]
        print(f"  {'PASS' if r['passed'] else 'FAIL'} {sid}" + (f"  failed: {failed}" if failed else ""))
    led = summary["ledger"]
    print("\nTokens by tool (attributed)")
    for name, t in sorted(led["tools"].items(), key=lambda kv: -kv[1]["total"]):
        print(f"  {name:<26} calls {t['calls']:>3}  total {t['total']:>8,}  ${t['cost']:.4f}")
    print("\nTokens by agent (as reported)")
    for name, a in led["agents"].items():
        print(f"  {name:<26} calls {a['calls']:>3}  total {a['total']:>8,}  ${a['cost']:.4f}")
    print(f"\n{summary['passed']}/{summary['total']} scenarios passed | {led['totals']['tokens']:,} tokens "
          f"(incl. cache reads) | {led['totals']['web_searches']} web searches | ${led['totals']['cost']:.4f} | "
          f"report: {summary['run_dir']}")
    return 0 if summary["passed"] == summary["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
