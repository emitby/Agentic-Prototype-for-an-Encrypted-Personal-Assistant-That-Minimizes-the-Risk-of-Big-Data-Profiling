"""Outbound privacy filter: secrets never reach the language model.

Everything the agents send to Claude goes through `Redactor.redact`. Stored
passwords, email addresses and usernames are replaced with labels, and any
other email address or payment-card-like number is masked. Tool results are
built to contain labels only, and they go through the same filter as a second
line of defense (the ``redact`` post-tool hook). As a third line, the
``outbound_scan`` pre-model hook checks the whole request against
:meth:`Redactor.known_secret_values` and refuses to send it if any secret remains.
"""

import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# 13-19 digits, optionally separated by spaces or dashes; only Luhn-valid numbers are masked.
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


class Redactor:
    """Replaces stored secrets and other sensitive patterns in outgoing text.

    Args:
        vault: The unlocked :class:`~assistant.vault.Vault`; secrets are read from it
            on every call, so newly added secrets are covered immediately.
    """

    def __init__(self, vault):
        """Keep a reference to the vault (secrets are looked up fresh each time)."""
        self.vault = vault

    def known_secret_values(self):
        """Every stored secret value (passwords, staged passwords, usernames, email addresses).

        Used by the leak checks in :mod:`assistant.hooks`. The values are never logged or sent.
        """
        return [value for value, _ in self._known_secrets()]

    def _known_secrets(self):
        """Return ``(secret, tag)`` pairs, longest secret first.

        Values shorter than 4 characters are skipped for passwords and usernames: replacing
        e.g. "ab" everywhere would mangle ordinary text and protects almost nothing.
        """
        data = self.vault.data
        pairs = []
        for label, cred in data["credentials"].items():
            for field, tag in (("password", "password"), ("pending_password", "password"),
                               ("username", "username")):
                value = cred.get(field)
                if value and len(value) >= 4:
                    pairs.append((value, f"[{tag}:{label}]"))
        for label, address in data["emails"].items():
            pairs.append((address, f"[email:{label}]"))
        # Longest first, so a password containing a username is fully replaced.
        return sorted(pairs, key=lambda p: len(p[0]), reverse=True)

    def redact(self, text):
        """Replace secrets, other email addresses and Luhn-valid card numbers in ``text``.

        Args:
            text: Outgoing text.

        Returns:
            ``(safe_text, tags)``: the redacted text and the tags of what was replaced.
        """
        found = []
        for secret, tag in self._known_secrets():
            if secret in text:
                text = text.replace(secret, tag)
                found.append(tag)

        def mask_email(m):
            """Mask any email address that isn't a stored one (those were tagged above)."""
            found.append("[email]")
            return "[email]"

        def mask_card(m):
            """Mask a card-like number only if it passes the Luhn checksum (fewer false hits)."""
            digits = re.sub(r"\D", "", m.group())
            if not _luhn_ok(digits):
                return m.group()
            found.append("[card]")
            return "[card]"

        text = EMAIL_RE.sub(mask_email, text)
        text = CARD_RE.sub(mask_card, text)
        return text, found


def _luhn_ok(digits):
    """True if a digit string passes the Luhn checksum used by payment cards."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0
