"""Evaluation suite for the encrypted personal assistant (see ``docs/evals.md``).

Five layers, from cheapest to most realistic:

1. Unit tests (``tests/``): vault, privacy, security, household, agents, guardrails,
   hooks, harness and the Claude Code hook.
2. Red-team (:mod:`evals.redteam`): attacks on every guardrail G1-G9, each paired with a
   benign look-alike that must still work.
3. Independent supply-estimate cross-check (:mod:`evals.crosscheck_supplies`): run-out
   estimates re-derived by separate code over many randomized reading histories.
4. Scenario scorers (:mod:`evals.scorers`): the harness's ten scorers plus six eval
   scorers, run on every scripted conversation.
5. Live trials (:mod:`evals.run_evals` ``--live --trials N``): the real agents and the
   real Have I Been Pwned API, scored the same way, with pass rates across trials.
"""
