# Agentic Prototype for an Encrypted Personal Assistant That Minimizes the Risk of Big Data Profiling

**A four-agent Claude assistant for account security, travel and household chores that keeps everything in an AES-256-GCM vault and never lets your passwords, usernames or stored emails reach the model.**

[![CI](https://github.com/emitby/Agentic-Prototype-for-an-Encrypted-Personal-Assistant-That-Minimizes-the-Risk-of-Big-Data-Profiling/actions/workflows/ci.yml/badge.svg)](https://github.com/emitby/Agentic-Prototype-for-an-Encrypted-Personal-Assistant-That-Minimizes-the-Risk-of-Big-Data-Profiling/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-315%20passing-success)
![Red-team](https://img.shields.io/badge/red--team-72%2F72-success)
![Supply cross-check](https://img.shields.io/badge/supply%20cross--check-2%2C000%20fields%2C%200%20mismatches-success)
![Encryption](https://img.shields.io/badge/vault-AES--256--GCM%20%2B%20scrypt-success)
![Claude](https://img.shields.io/badge/model-claude--opus--5--5-8a5a2b)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

<p align="center">
  <img src="docs/images/session-pasted-password.png" width="100%" alt="The user types a password, username and email; the privacy filter replaces all three with tags before anything is sent, and the breach check runs on labels">
  <img src="docs/images/privacy-layers.png" width="100%" alt="Six layers between the vault and the AI service: labels, input redaction, brief redaction, leak detector, result redaction and the outbound scan">
</p>

**→ [How it works (PDF): agent workflows, the encrypted vault, guardrails, hooks, the harness, tokens per tool and evals](docs/how-it-works-personal-assistant.pdf)**

[Evals](docs/evals.md) · [Threat model](docs/threat-model.md) · [Architecture](docs/architecture.md) · [Guardrails](docs/guardrails.md) · [Hooks](docs/hooks.md) · [Harness](docs/harness.md) · [Example session](docs/example-session.md) · [Security policy](SECURITY.md)

> **Status: research prototype.** It's useful for exploring privacy-preserving agent design. Don't make it your only password manager.

## Results

| Eval | Result |
|---|---|
| Unit tests (vault, privacy, security, household, agents, guardrails, hooks, harness, Claude Code hook, evals) | **315 / 315 passing** on Python 3.10–3.12 in CI |
| Red-team: 53 attacks on G1–G9 and HIBP k-anonymity, plus 19 benign look-alikes | **72 / 72**, with no secret let through and no ordinary request blocked |
| Independent supply-estimate cross-check over 400 random reading histories | **2,000 fields, 0 mismatches**, with every branch of the method exercised |
| Ten scripted conversations through the real hooks, vault and redactor, 16 scorers each (simulated agents, mock HIBP) | **10 / 10** conversations, **16 / 16** scorers at 100%, including "no secret ever sent" |
| Planted-defect tests: each eval must fail when its guardrail or math is broken | **all pass**, so no eval passes vacuously |
| Live trials with the real agents and the real HIBP | Pending: the Anthropic API account is out of credits ([details](docs/evals.md#5-live-trials)) |

Run it yourself with `.\run.ps1 eval` (free, offline) or `.\run.ps1 eval --live --trials 3 --max-cost 8`. Every layer is described in [docs/evals.md](docs/evals.md).

## Quick start

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install --no-cache-dir -r requirements.txt
.\run.ps1 eval        # offline: red-team, cross-check and 10 conversations, no API key needed
```

To chat with it, set `ANTHROPIC_API_KEY`, then `.\run.ps1 init` once and `.\run.ps1 chat --verbose`. Details in [Setup](#setup).

## What it does

A multi-agent personal assistant built on Claude. It keeps every stored item encrypted and keeps your secrets out of everything sent to the AI. The design question it explores: **how much can an AI assistant do for you while sending as little as possible about you to anyone else?**

| Area | What it does |
|---|---|
| **Account security** | Checks your saved passwords against Have I Been Pwned without sending them anywhere. Finds weak and reused passwords, checks your email addresses for breaches, and guides password rotation. |
| **Travel** | Searches the web for flights and compares fares, with sources. |
| **Household** | Keeps grocery lists, and tracks supplies like laundry detergent, estimating when you'll run out from how fast you actually use them. |

## Agents

```mermaid
flowchart LR
    U([You]) -->|chat| IN{{"Input redaction + G1<br/>secrets become tags,<br/>injection refused"}}
    U -->|"/add-login, /reveal, /rotated<br/>terminal only (G3)"| V
    IN --> CO[Coordinator]
    CO -->|redacted brief| SA[Security Agent]
    CO -->|redacted brief| TA[Travel Agent]
    CO -->|redacted brief| HA[Household Agent]
    SA --> PRE{{"Pre-tool hooks<br/>G2 schema · G8 path guard · G7 call limit"}}
    HA --> PRE
    TA --> PRE
    PRE --> T[Tools<br/>labels only]
    T --> V[(Encrypted vault<br/>AES-256-GCM · G9)]
    T -->|SHA-1 prefix only| HIBP[Have I Been Pwned]
    T --> POST{{"Post-tool hooks<br/>G5 leak detector · G4 redact · G7 size cap"}}
    POST --> OUT{{"Before every model call<br/>G4 outbound scan · G6 budget"}}
    OUT --> AI([Claude API])
    TA -->|web search| WEB[Web]
    classDef guard fill:#fff4d6,stroke:#b45309,color:#78350f
    class IN,PRE,POST,OUT guard
```

Amber hexagons are guardrails enforced in code, mostly as hooks that every agent's tool and model calls pass through.

| Agent | Tools | Effort |
|---|---|---|
| **Coordinator** | Delegates to the three specialists, in parallel when a request spans areas | medium |
| **Security Agent** | `list_accounts`, `check_password_breaches`, `check_email_breaches`, `start_password_rotation` | low |
| **Travel Agent** | Claude web search (server tool), `get_travel_preferences`, `set_home_airport` | medium |
| **Household Agent** | `show_grocery_lists`, `add_grocery_items`, `check_off_grocery_items`, `remove_grocery_items`, `track_supply`, `log_supply_reading`, `estimate_supplies` | low |

Each specialist starts every task with a fresh context and gets only the tools for its area, so data from one area never sits in another agent's context.

## Privacy and security design

### At rest: everything is encrypted

- The whole store is in one file, `data/vault.enc` inside the project: accounts, email addresses, grocery lists, supply readings, travel preferences and the chat transcript.
- **Contained to the project directory.** The app refuses any vault path outside the project folder, never deletes files, and doesn't use `os`, environment variables or home-directory paths. See [CLAUDE.md](CLAUDE.md).
- **AES-256-GCM** with a fresh random nonce on every save. Any change to the file is detected and rejected.
- The key comes from your passphrase via **scrypt** (N=2¹⁷, about 128 MiB). It isn't stored anywhere, and the passphrase can't be recovered.
- Writes are atomic, so a crash can't leave a half-written vault.

### In transit: secrets never reach the AI

- **Passwords, stored email addresses and usernames are never sent to Claude.** Tools refer to accounts by label (`github`), and their outputs leave out all secrets.
- **Outbound filter.** Every message, brief and tool result passes through a redactor before it goes to the API. Stored secrets become `[password:github]` or `[email:personal]`. Any other email address becomes `[email]`, and any number that passes the card checksum becomes `[card]`. If you paste a password into the chat, it's removed before Claude sees it, and the CLI tells you.
- **Human-only actions.** Adding logins, revealing passwords and confirming rotations are terminal commands. No agent has these tools.
- **Breach checks use k-anonymity.** Only the first 5 hex characters of a password's SHA-1 hash go to Have I Been Pwned, with response padding enabled. The password and full hash never leave your machine.

### What this does *not* protect

"Profiling is impossible" isn't a claim any app that uses cloud AI or web search can honestly make. Here is exactly what leaves your machine:

| Data | Goes to | Why |
|---|---|---|
| Your chat messages, after redaction | Anthropic (Claude API) | The model has to read a request to act on it. Grocery items, travel plans and supply levels you mention are visible to it. |
| Flight search queries (route, dates) | Anthropic's web search and the sites it reads | Searching requires saying what you're searching for. |
| 5-character password hash prefixes | Have I Been Pwned | Shared by hundreds of passwords, so they reveal nothing about yours. |
| Email addresses, only when you ask for an email breach check | Have I Been Pwned | HIBP has to know the address to look it up. |
| Your IP address and request timing | All of the above | Use a VPN or Tor if that matters to you. |

To reduce this further, keep chats to the task, use an Anthropic organization with zero data retention, and run breach checks only when needed.

## Guardrails, hooks and harness

**Guardrails.** Nine rules, each enforced in code and tested in both directions ([docs/guardrails.md](docs/guardrails.md)):

| # | Guardrail | # | Guardrail |
|---|---|---|---|
| G1 | Input check: prompt injection is refused before any model call | G6 | Token budgets per turn and per session |
| G2 | Tool arguments validated against each tool's JSON schema | G7 | Tool-call, web-search and result-size limits |
| G3 | Least privilege: no agent can hold a human-only tool | G8 | Host safety: no path outside the project, no deletions, no `os` |
| G4 | Outbound privacy: redaction, plus a final scan that refuses to send a request containing a secret | G9 | Vault integrity: AES-256-GCM, scrypt, atomic writes |
| G5 | Secret-free tool results: a leak detector flags any tool that returns a secret | | |

**Hooks** ([docs/hooks.md](docs/hooks.md)):
- **Inside the app**, every model call and tool call passes through a hook pipeline:
  - before a model call: the budget check and the outbound privacy scan
  - before a tool call: the schema check, the path guard and the call limit
  - after a tool call: the leak detector, redaction and the size cap
- **For AI coding agents** working on this repository, a Claude Code PreToolUse hook (`.claude/hooks/guard.py`) blocks file writes outside the project folder, every file-deletion command, and changing directory to outside the project.

**Harness** ([docs/harness.md](docs/harness.md)):
- It traces every call and attributes tokens **to each tool**: the tokens spent calling it, reading its result, and (for delegations) the whole specialist run. Web searches are counted separately.
- It runs ten scripted scenarios, judged by ten scorers, including "no secret was ever sent".

**Evals** ([docs/evals.md](docs/evals.md)) add four more layers:
- **Red-team:** 72 attacks and benign look-alikes on G1–G9 and HIBP k-anonymity.
- **Independent supply-estimate cross-check:** run-out math re-derived over 400 random histories.
- **Six eval scorers:** a scrubbed trace, secret-free replies, no human-only operations, prefix-only HIBP requests, a vault that re-opens intact, and supply estimates matching the independent math.
- **Live trials:** pass rates across repeated runs with the real agents.

```powershell
.\run.ps1 scenarios                       # simulated: offline, free, estimated tokens
.\run.ps1 scenarios --live --max-cost 5   # real Claude and HIBP
.\run.ps1 eval                            # evals: red-team, cross-check, 16 scorers (offline)
.\run.ps1 eval --live --trials 3 --max-cost 8
```

## Why password changes aren't automatic

Websites have no standard API for changing a password. Scripting each site's login page breaks on 2FA, CAPTCHAs and redesigns, can lock you out of your own accounts, and would require giving an AI agent the ability to change your credentials. So rotation is **assisted**:

1. The agent generates a 20-character random password and stages it in the vault. The agent never sees it.
2. It gives you the site's change-password page, using the W3C [`/.well-known/change-password`](https://w3c.github.io/webappsec-change-password-url/) URL.
3. You run `/reveal github --new`, change the password on the site, then run `/rotated github`.

## How supply estimates work

Supplies are tracked in a unit you choose, such as loads or fl oz. You log readings: a **restock** (the amount on hand after buying) or a **level** (the amount left now).

- **Daily use** is learned from the drop between consecutive readings. Restock intervals are skipped, since their usage is unknown. Until you have two readings, a configured rate is used, e.g. 4 loads a week = 0.571 a day.
- **Remaining now** = last reading − daily use × days since then.
- From that it reports days left, the run-out date, a **reorder-by** date (run-out minus lead time) and whether there's enough for the next week.

All of this is plain Python in [`household.py`](assistant/household.py), so the model reports these numbers but never computes them.

## Setup

Requires Python 3.10+ and an [Anthropic API key](https://console.anthropic.com/).

```bash
git clone https://github.com/emitby/Agentic-Prototype-for-an-Encrypted-Personal-Assistant-That-Minimizes-the-Risk-of-Big-Data-Profiling.git personal-assistant
cd personal-assistant

python -m venv .venv
.venv\Scripts\python.exe -m pip install --no-cache-dir -r requirements.txt
$env:ANTHROPIC_API_KEY = "sk-ant-..."   # macOS/Linux: export ANTHROPIC_API_KEY=sk-ant-...

.\run.ps1 init                 # first time: create the vault and choose a passphrase
.\run.ps1 chat --verbose       # later: unlock and chat (shows agent steps, hooks and tokens)
```

Use the launcher (`run.ps1` on Windows, `run.sh` elsewhere). It keeps Python's cache, the Playwright browser and temporary files inside the project folder. To rebuild the PDF guide, run `pip install playwright`, then `.\run.ps1 install-browser`, then `.\run.ps1 guide`.

**Your passphrase can't be recovered.** Without it, the vault can't be decrypted.

Optional: a [Have I Been Pwned API key](https://haveibeenpwned.com/API/Key) (paid) enables email breach checks. Password checks are free and need no key.

## Usage

```
you> /add-email personal
you> /add-login github          # site, username, hidden password, linked email
you> check my passwords for breaches
you> /reveal github --new       # during a rotation
you> /rotated github
you> add eggs, oat milk and coffee to groceries
you> I just bought detergent, 64 loads. We do about 5 loads a week.
you> how much detergent is left?
you> find flights from JFK to Lisbon May 14-21, nonstop if possible
```

| Command | Purpose |
|---|---|
| `/add-email <label>` | Store an email address |
| `/add-login <label>` | Store a website login (password typed hidden) |
| `/set-hibp-key` | Store an HIBP API key (typed hidden) |
| `/accounts` | List accounts and their breach status |
| `/reveal <label> [--new]` | Show a stored password, or the staged one with `--new` |
| `/rotated <label>` | Confirm you changed the password on the site |
| `/quit` | Lock the vault and exit |

## Tests

```powershell
.\run.ps1 test
```

The 315 tests make no network or API calls, and they write only inside the project (`.pytest_tmp/`, `.cache/test-output/`). They use a mock HIBP server and a scripted Claude client. On top of the original 25, they add:
- **Guardrails:** G1–G9, each in both directions
- **Hooks:** schema, path guard, unknown tool, human-only tools, a leaky tool caught, the outbound scan stopping a request, budget, call limit
- **Harness:** token attribution math, all ten scenarios passing every scorer, scorers failing on a broken scenario, scrubbed traces
- **Evals:** the red-team, the supply cross-check and every eval scorer, each tested against planted defects:
  - a disabled redactor
  - an emptied human-only list
  - a supply-math bug
  - a secret leaked into a trace

  Also: results free of secrets, and clean stops on API account problems.
- **Claude Code hook:** writes, deletions, leaving the folder, normal commands, and the exit-code protocol
- **CLAUDE.md scans:** no `os`, no deletion calls, a docstring everywhere, Python 3.10 f-string compatibility, path confinement

The original 25 cover:

- **Vault:** round-trip, nothing readable on disk, wrong passphrase, tamper detection, KDF parameters bound to the ciphertext, fresh nonces, refusing paths outside the project
- **Privacy:** the redactor handles stored secrets, other email addresses and card numbers. An end-to-end test checks that **no password, email, username or staged password appears in anything sent to the model**, or in the stored transcript.
- **Security:** k-anonymity requests and padding, reuse and weakness detection, the rotation flow, email checks with and without a key
- **Household:** list lifecycle, configured and learned usage rates, restock handling, reorder alerts, validation
- **Agents:** fresh specialist contexts, least-privilege tool sets, parallel delegation, web-search `pause_turn` continuation, tool errors returned to the model

## Project layout

```
assistant/
├── vault.py          AES-256-GCM + scrypt encrypted store
├── privacy.py        Outbound redactor
├── guardrails.py     G1-G9 as plain, tested functions
├── hooks.py          In-app hook pipeline (pre/post model and tool calls)
├── paths.py          Path confinement and atomic writes (no os, no deletions)
├── security.py       HIBP client, credential store, rotation
├── household.py      Grocery lists, supply tracking and estimates
├── agents/
│   ├── runtime.py    Agent loop (hooks, events, server tools, pause_turn)
│   └── team.py       Coordinator and the three specialists
├── harness/          trace, token ledger, scenarios + scorers, simulated client, runner
├── guide.py          Builds docs/how-it-works-personal-assistant.pdf
└── cli.py            Terminal interface
evals/
├── redteam.py        72 attacks and benign look-alikes on G1-G9 and HIBP
├── crosscheck_supplies.py  Independent re-derivation of supply estimates
├── scorers.py        Six eval scorers for every conversation
├── run_evals.py      Runs every layer (offline or live trials); writes evals/results/
└── results/          Results files (secret-free), kept in git
.claude/
├── settings.json     Claude Code PreToolUse hook registration
└── hooks/guard.py    Blocks writes outside the project and file deletions
docs/
├── how-it-works-personal-assistant.pdf  Illustrated guide (generated)
├── evals.md          Every eval layer, what it proves and the latest results
├── threat-model.md   Assets, adversaries, mitigations, residual risks
├── architecture.md   Layers, sequence diagram, agent loop, vault format
├── guardrails.md     G1-G9: where each is enforced, its tests and limits
├── hooks.md          In-app hooks and the Claude Code hook
├── harness.md        Events, token attribution, scenarios, scorers, modes
└── example-session.md  A real run, with every number checked
tests/                Vault, privacy, security, household, agents, guardrails, hooks, harness, hook script, evals, CLAUDE.md scans
run.ps1, run.sh       Launchers
SECURITY.md           How to report vulnerabilities
CONTRIBUTING.md       Ground rules for privacy-preserving changes
CLAUDE.md             Guardrails and workflow rules for AI coding agents working on this repo
data/vault.enc        Your encrypted vault (created on first run, gitignored)
```

## Model

All agents use `claude-opus-5-5` with adaptive thinking and server-side refusal fallbacks (`fallbacks="default"`). The Travel Agent uses the `web_search_20260209` server tool with up to 10 searches per task.

## Roadmap

- [ ] Local model option for household tasks, so grocery and supply data never leaves the machine
- [ ] Pseudonymized travel queries (e.g. strip exact dates until booking intent is confirmed)
- [ ] Auto-lock after inactivity, and clipboard copy with auto-clear for `/reveal`
- [ ] Import from password-manager exports (Bitwarden, 1Password CSV)
- [ ] Scheduled breach monitoring with local notifications

## License

[MIT](LICENSE) © 2026 Edward Mitby
