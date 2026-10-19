# Architecture

## Layers

| Layer | Module | Responsibility |
|---|---|---|
| Storage | [`vault.py`](../assistant/vault.py) | Encrypted JSON store (AES-256-GCM + scrypt) |
| Privacy | [`privacy.py`](../assistant/privacy.py) | Outbound redaction of secrets and identifiers |
| Domain | [`security.py`](../assistant/security.py), [`household.py`](../assistant/household.py) | Breach checks, rotation, grocery lists, supply estimates. **No AI.** |
| Agent runtime | [`agents/runtime.py`](../assistant/agents/runtime.py) | Claude tool-use loop with server tools, `pause_turn` and redaction |
| Agent team | [`agents/team.py`](../assistant/agents/team.py) | Prompts, tool wiring, delegation |
| Interface | [`cli.py`](../assistant/cli.py) | Chat, plus human-only secret commands |

The domain layer is deterministic Python with its own tests. The agents choose which operations to run, and the code decides what those operations return.

## A multi-area request

```mermaid
sequenceDiagram
    actor U as You
    participant R as Redactor
    participant C as Coordinator
    participant S as Security Agent
    participant H as Household Agent
    participant T as Travel Agent
    participant V as Vault / domain

    U->>R: "check my passwords, how long will 40 loads of detergent last, flights JFK→LIS in May. My github pw is password123"
    R->>C: same text with [password:github]
    par in parallel
        C->>S: brief
        S->>V: list_accounts, check_password_breaches
        V-->>S: labels + issues (no secrets)
        S-->>C: findings
    and
        C->>H: brief
        H->>V: track_supply, log_supply_reading
        V-->>H: days left, run-out date
        H-->>C: estimate
    and
        C->>T: brief
        T->>T: web_search (server tool, may pause_turn)
        T-->>C: fares with sources
    end
    C-->>U: action items first, then details
    Note over V: transcript stored encrypted, in redacted form
```

## Agent loop

`Agent.run(messages)`:

1. Call `client.beta.messages.create` with the agent's prompt, tools (custom and server), effort, prompt caching and server-side fallbacks.
2. Append the full assistant `content` to the history. The history is never edited.
3. `refusal` returns a safe reply. `pause_turn` (a long server-side web search) loops again to let it finish. With no tool calls, return the text.
4. Run the custom tool calls concurrently. Arguments are checked against the handler's signature first. Domain errors become `is_error` results, and unexpected exceptions are logged and returned as generic errors.
5. **Redact every tool result**, then append all results in one user message.
6. Stop after `max_turns`.

## Delegation

Specialists are tools whose handlers run another `Agent` on a one-message conversation:

```python
Tool("ask_security_agent", ..., lambda brief: self._delegate(self.security_agent, brief))
```

`_delegate` redacts the brief, too. Each specialist:

- starts with a **fresh context**, so no other area's data is present
- gets **only its own tools**, so the Travel Agent, which reads untrusted web pages, can't touch credentials
- runs at the **lowest effort that does the job**: `low` for Security and Household, `medium` for Travel

## Vault format

```json
{
  "v": 1,
  "kdf":   {"salt": "<b64 16 bytes>", "n": 131072, "r": 8, "p": 1},
  "nonce": "<b64 12 bytes>",
  "ct":    "<b64 AES-256-GCM(ciphertext || tag)>"
}
```

- Key: `scrypt(passphrase, salt, n, r, p) → 32 bytes`
- Associated data: `{"v", "kdf"}`, canonical JSON
- Plaintext: one JSON document with the sections `credentials`, `emails`, `grocery_lists`, `supplies`, `travel`, `transcript` and `settings`
- Saves write to `vault.tmp`, then `os.replace` it over the vault, which is atomic

## Supply estimation

Readings are `{date, kind: "restock" | "level", amount}`:

```
daily_use = Σ max(prev - cur, 0) / Σ days     over consecutive pairs where cur is a "level" reading
            (falls back to configured_daily_use until such a pair exists)
remaining = last.amount - daily_use × days_since(last)
days_left = remaining / daily_use
reorder_by = today + days_left - reorder_lead_days
```

Restock intervals are skipped because the amount used before the restock is unknown.
