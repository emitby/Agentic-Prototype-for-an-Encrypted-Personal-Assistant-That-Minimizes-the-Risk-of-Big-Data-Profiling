# Security policy

This is a research prototype that handles credentials, so security reports are very welcome.

## Reporting a vulnerability

Please **don't open a public issue** for a security problem. Report it privately through GitHub's [private vulnerability reporting](../../security/advisories/new) for this repository.

Please include:

- what an attacker could do, and under which assumptions (see the [threat model](docs/threat-model.md))
- steps to reproduce, or a failing test
- the affected file or function, if known

Expect an acknowledgement within a week.

## In scope

- Anything that lets a password, email address, username, staged password or API key reach the model, a log, or disk in plaintext
- Weaknesses in vault encryption, key derivation or integrity checks
- Ways for an agent, including one manipulated by web content, to read secrets or complete a rotation without the user
- Requests to Have I Been Pwned that reveal more than the 5-character hash prefix

## Out of scope

The [threat model](docs/threat-model.md) lists these as non-goals: network-level anonymity, a compromised host, and content you deliberately send to the model.

## Using this safely

- Choose a long, random vault passphrase. It can't be recovered.
- Keep the vault file (`data/vault.enc` in the project folder) out of public places, even though it's encrypted. It's gitignored, so don't force-add it.
- Clear your terminal after using `/reveal`.
- This is a prototype. Don't make it your only password manager.
