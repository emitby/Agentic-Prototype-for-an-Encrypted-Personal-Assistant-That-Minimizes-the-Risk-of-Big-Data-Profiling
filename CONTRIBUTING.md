# Contributing

Thanks for your interest! This is a prototype exploring privacy-preserving agent design, so contributions that **reduce data exposure** are especially welcome.

## Development setup

```bash
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
pytest
```

The tests make no network or API calls.

## Ground rules for changes

1. **No secret may reach the model.** New tools must take and return labels, never passwords, addresses, usernames or keys. Add a check to `test_secrets_never_reach_the_model` for any new kind of secret.
2. **Secret operations stay human-only.** Anything that reveals a secret or commits a credential change belongs in `cli.py`, not in an agent's tool list.
3. **Numbers come from code.** Estimates, prices and dates should be computed in the domain layer and reported by the model, not computed by it.
4. **Least privilege.** Give each specialist only the tools for its area. In particular, the agent that reads the web must not get security tools.
5. **Document what leaves the machine.** If a change sends anything new to an external service, update the table in the README and the [threat model](docs/threat-model.md).
6. **Stay inside the project directory.** Follow the guardrails in [CLAUDE.md](CLAUDE.md): no `import os`, no environment-variable, home-directory or system-path access, no file deletion, and no code that reads or writes outside this folder. Tests write only to `.pytest_tmp/`.

## Pull requests

- Keep changes focused, and include tests.
- Run `pytest` before opening the PR. CI runs it on Python 3.10–3.12.
- Report security issues privately. See [SECURITY.md](SECURITY.md).
