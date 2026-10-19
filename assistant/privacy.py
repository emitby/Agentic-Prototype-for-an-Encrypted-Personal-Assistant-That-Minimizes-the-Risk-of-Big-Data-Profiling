"""Outbound privacy filter: secrets never reach the language model.

Everything the agents send to Claude goes through `Redactor.redact`. Stored
passwords, email addresses and usernames are replaced with labels, and any
other email address or payment-card-like number is masked. Tool results are
built to contain labels only, and they go through the same filter as a second
line of defense.
"""

import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


class Redactor:
    def __init__(self, vault):
        self.vault = vault

    def _known_secrets(self):
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
        """Return (safe_text, list_of_redaction_tags)."""
        found = []
        for secret, tag in self._known_secrets():
            if secret in text:
                text = text.replace(secret, tag)
                found.append(tag)

        def mask_email(m):
            found.append("[email]")
            return "[email]"

        def mask_card(m):
            digits = re.sub(r"\D", "", m.group())
            if not _luhn_ok(digits):
                return m.group()
            found.append("[card]")
            return "[card]"

        text = EMAIL_RE.sub(mask_email, text)
        text = CARD_RE.sub(mask_card, text)
        return text, found


def _luhn_ok(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0
