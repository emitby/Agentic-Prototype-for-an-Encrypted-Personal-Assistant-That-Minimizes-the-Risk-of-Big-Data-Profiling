# Threat model

This document states what the assistant protects, from whom, and what it does **not** protect. The goal is to **minimize** the data that could be used to profile you. No app that uses a cloud AI model and web search can eliminate it, and this one doesn't claim to.

## Assets

| Asset | Sensitivity | Where it lives |
|---|---|---|
| Website passwords | Critical | Encrypted vault only |
| Email addresses, usernames | High | Encrypted vault only |
| HIBP API key | High | Encrypted vault only |
| Chat transcript | Medium–high | Encrypted vault (stored redacted) |
| Grocery lists, supply readings | Low–medium (behavioral) | Encrypted vault |
| Travel preferences and searches | Medium (location, movement) | Encrypted vault, plus queries sent to web search |
| Vault passphrase | Critical | Your memory only, never stored |

## Adversaries and mitigations

### 1. Someone who gets the vault file (stolen laptop, backup, cloud sync)

| Mitigation | Detail |
|---|---|
| Authenticated encryption | AES-256-GCM over the whole store. Nothing is plaintext, not even list names. |
| Slow key derivation | scrypt with N=2¹⁷, r=8, p=1 (about 128 MiB and 0.3–1 s per guess) makes brute-forcing the passphrase expensive. |
| Tamper detection | GCM authentication fails on any change. The KDF parameters are bound in as associated data, so an attacker can't swap in weaker ones. |
| Fresh nonces | A new random 96-bit nonce on every save. |
| Minimum passphrase length | 12 characters. Use more. |

**Residual risk:** a weak passphrase can still be guessed offline. Use a long, random one.

### 2. The AI provider, or anyone who can read API traffic or logs

| Mitigation | Detail |
|---|---|
| Labels, not secrets | Tools speak in labels (`github`, `personal`). Passwords, addresses and usernames never appear in tool outputs. |
| Outbound redaction | User messages, delegation briefs and tool results all pass through `Redactor`. Stored secrets, any email address and any Luhn-valid card number are masked. |
| Least-privilege agents | Each specialist sees only its area's tools and a fresh context, so no single prompt combines security, travel and household data unless you put them in one message. |
| Human-only secret operations | Adding, revealing and confirming credentials happens in the CLI and never goes through a model. |

**Residual risk:** the content of your requests (groceries, supply levels, travel routes and dates) has to go to the model to be acted on. Over time, that content could support behavioral inferences. To reduce it, use an organization with zero data retention, and keep requests to the task.

### 3. Breach-lookup services (Have I Been Pwned)

| Mitigation | Detail |
|---|---|
| k-anonymity | Only the first 5 hex characters of a password's SHA-1 hash are sent. Each prefix matches hundreds of hashes. |
| Response padding | `Add-Padding: true` hides the true result count. |
| On-demand email checks | An address is sent only when you explicitly request an email breach check. |

**Residual risk:** an email breach check reveals the address to HIBP.

### 4. Web search providers and the sites the search reads

Flight queries reveal route and dates. **No mitigation is possible without giving up the feature.** The vault doesn't store your home airport outside encryption, and searches don't include your identity, but your IP address and timing are visible. Use a VPN or Tor if this matters.

### 5. A prompt-injected or misbehaving model

Web pages read during flight search could contain instructions aimed at the model.

| Mitigation | Detail |
|---|---|
| No secret-revealing tools | No agent can read a password, address or username, so injected text has nothing to steal. |
| No destructive security tools | The worst an agent can do is stage a new password, which changes nothing until you confirm with `/rotated`. |
| Specialist isolation | The Travel Agent, the one that reads the web, has no security or household tools. |
| Typed tool errors | Invalid tool calls are returned as errors and never executed. |

### 5b. Defense in depth around every model and tool call

The [hook pipeline](hooks.md) applies guardrails to every agent:
- schema validation, the path guard and call limits before each tool call
- leak detection, redaction and size caps after it
- the token budget and a final **outbound scan** before each model call

The outbound scan refuses to send any request that still contains a stored secret. See [guardrails.md](guardrails.md).

### 7. AI coding agents editing this repository

An AI coding agent could write outside the project or delete files by mistake. A Claude Code PreToolUse hook (`.claude/hooks/guard.py`) blocks file writes and edits outside the folder, every deletion command, and changing directory to outside it. It matches patterns and isn't a sandbox. See [hooks.md](hooks.md).

### 6. Someone at your keyboard

Out of scope while the vault is unlocked. `/reveal` prints a password to your terminal, so clear the screen afterwards. The vault is locked on exit, and the key isn't written anywhere.

## Explicit non-goals

- **Anonymity on the network.** IP address and request timing are visible to every service contacted.
- **Protection against a compromised machine.** Malware that can read process memory or log keystrokes defeats any local encryption.
- **Automatic password changes on websites.** This is deliberately excluded. See the README.

## Verifying the claims

The test suite checks the most important claims directly:

- `test_roundtrip_and_nothing_readable_on_disk`: no plaintext in the vault file
- `test_tampering_detected`, `test_kdf_params_bound_to_ciphertext`: integrity
- `test_password_check_uses_k_anonymity`: only 5-character prefixes are sent, with padding
- `test_agent_facing_outputs_never_contain_secrets`: tool outputs are secret-free
- `test_secrets_never_reach_the_model`: an end-to-end check that every request sent to the model is free of passwords, addresses, usernames and staged passwords, even when the user pastes them into the chat
