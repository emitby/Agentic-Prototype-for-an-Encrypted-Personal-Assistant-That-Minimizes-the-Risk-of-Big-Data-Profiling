"""The harness: tracing, token accounting and scripted scenarios around the agent team.

* :mod:`assistant.harness.trace`: run folders and ``trace.jsonl`` with secrets redacted.
* :mod:`assistant.harness.tokens`: the token and cost ledger per agent and per tool.
* :mod:`assistant.harness.scenarios`: scripted conversations and the code checks (scorers).
* :mod:`assistant.harness.simulated`: :class:`SimulatedClient`, a scripted stand-in for
  Claude that drives the real tools, hooks, redactor and vault offline. Its token counts
  are estimates and are labeled "simulated" everywhere they appear.
* :mod:`assistant.harness.run_scenarios`: runs the suite (simulated, or live with a cost
  cap) and writes ``runs/<id>/``.
"""
