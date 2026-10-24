"""Breach monitoring and password rotation for your own accounts.

Breach data comes from Have I Been Pwned (haveibeenpwned.com):

- Passwords use the Pwned Passwords range API (k-anonymity). Only the first
  5 hex characters of the password's SHA-1 hash leave this machine, with
  padding enabled so response size reveals nothing. The password itself is
  never sent anywhere.
- Email addresses use the breachedaccount API, which needs your own HIBP API
  key (paid). This sends the address to HIBP, so it only runs when you ask.

Rotation is deliberately human-completed: the assistant generates a strong
password and points you to the site's change-password page, and you make the
change. Websites have no standard API for changing passwords, and scripting
their login pages is unreliable and can lock you out.
"""

import hashlib
import secrets
import string
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import httpx

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
BREACHED_ACCOUNT_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
USER_AGENT = "private-personal-assistant/0.1"
MIN_STRONG_LENGTH = 12
GENERATED_LENGTH = 20


class SecurityError(Exception):
    """A problem that's safe to show to the user and the model."""


def _now():
    """The current UTC time as an ISO-8601 string (seconds)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def generate_password(length=GENERATED_LENGTH):
    """Random password with at least one lowercase, uppercase, digit and symbol."""
    symbols = "!@#$%^&*-_=+?"
    alphabet = string.ascii_letters + string.digits + symbols
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in symbols for c in pw)):
            return pw


def change_password_url(site):
    """The W3C well-known URL that redirects to a site's change-password page."""
    host = urlparse(site if "://" in site else f"https://{site}").hostname
    if not host:
        raise SecurityError(f"Can't work out the website for {site!r}.")
    return f"https://{host}/.well-known/change-password"


class HIBPClient:
    """Minimal Have I Been Pwned client.

    Args:
        http: An ``httpx.Client`` (tests pass one with a mock transport).
        api_key: HIBP API key, needed only for email breach checks.
    """
    def __init__(self, http=None, api_key=None):
        """Create the HTTP client (15 s timeout, identifying user agent) unless one is given."""
        self.http = http or httpx.Client(timeout=15, headers={"user-agent": USER_AGENT})
        self.api_key = api_key

    def password_seen_count(self, password):
        """How many times a password appears in Pwned Passwords, using k-anonymity.

        Only the first 5 hex characters of the SHA-1 hash are sent; the response lists every
        suffix with that prefix (padded with fake rows), and the match is made locally.

        Returns:
            The breach count (0 if not found).

        Raises:
            httpx.HTTPError: Network or HTTP errors.
        """
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        resp = self.http.get(PWNED_RANGE_URL.format(prefix=prefix), headers={"Add-Padding": "true"})
        resp.raise_for_status()
        for line in resp.text.splitlines():
            candidate, _, count = line.partition(":")
            if candidate.strip() == suffix:
                return int(count)   # padded entries have count 0
        return 0

    def breaches_for_account(self, address):
        """Breaches that include an email address (sends the address to HIBP; needs an API key).

        Returns:
            ``[{breach, date, exposed, verified}]`` (empty if none).

        Raises:
            SecurityError: No key, a rejected key, or the rate limit.
        """
        if not self.api_key:
            raise SecurityError("Email breach checks need a Have I Been Pwned API key. "
                                "Add one with /set-hibp-key in the CLI.")
        resp = self.http.get(
            BREACHED_ACCOUNT_URL.format(account=quote(address)),
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": self.api_key},
        )
        if resp.status_code == 404:
            return []
        if resp.status_code == 401:
            raise SecurityError("Have I Been Pwned rejected the API key.")
        if resp.status_code == 429:
            raise SecurityError("Have I Been Pwned rate limit hit. Try again shortly.")
        resp.raise_for_status()
        return [{"breach": b["Title"], "date": b.get("BreachDate"),
                 "exposed": b.get("DataClasses", []), "verified": b.get("IsVerified")}
                for b in resp.json()]


class AccountSecurity:
    """Credential store on top of the vault. Methods marked HUMAN-ONLY are never
    given to an agent because they accept or return secrets."""

    def __init__(self, vault, hibp=None):
        """Use the given HIBP client, or one with the API key stored in the vault."""
        self.vault = vault
        self.hibp = hibp or HIBPClient(api_key=vault.data["settings"].get("hibp_api_key"))

    @property
    def _creds(self):
        """The vault's credentials section (label -> login record)."""
        return self.vault.data["credentials"]

    def _cred(self, label):
        """Return one login by label, or raise :class:`SecurityError` listing the known labels."""
        if label not in self._creds:
            known = ", ".join(sorted(self._creds)) or "none yet"
            raise SecurityError(f"No account labelled {label!r}. Known accounts: {known}.")
        return self._creds[label]

    # ------------------------------------------------- HUMAN-ONLY (CLI) methods

    def add_credential(self, label, site, username, password, email_label=None):
        """HUMAN-ONLY. Store a website login in the vault.

        Raises:
            SecurityError: If the linked email label doesn't exist.
        """
        if email_label and email_label not in self.vault.data["emails"]:
            raise SecurityError(f"No email labelled {email_label!r}.")
        self._creds[label] = {"site": site, "username": username, "password": password,
                              "email_label": email_label, "added": _now(),
                              "last_rotated": None, "pending_password": None,
                              "last_check": None}
        self.vault.save()

    def add_email(self, label, address):
        """HUMAN-ONLY. Store an email address under a label."""
        self.vault.data["emails"][label] = address.strip()
        self.vault.save()

    def set_hibp_key(self, key):
        """HUMAN-ONLY. Store the HIBP API key (in the vault) and use it from now on."""
        self.vault.data["settings"]["hibp_api_key"] = key
        self.hibp.api_key = key
        self.vault.save()

    def reveal(self, label, pending=False):
        """HUMAN-ONLY. Return a stored password, or the staged one during a rotation.

        Raises:
            SecurityError: Unknown label or no such password.
        """
        cred = self._cred(label)
        value = cred["pending_password"] if pending else cred["password"]
        if value is None:
            raise SecurityError(f"No {'pending ' if pending else ''}password for {label!r}.")
        return value

    def complete_rotation(self, label):
        """Call after you've changed the password on the website."""
        cred = self._cred(label)
        if not cred["pending_password"]:
            raise SecurityError(f"No rotation in progress for {label!r}.")
        cred["password"], cred["pending_password"] = cred["pending_password"], None
        cred["last_rotated"] = _now()
        cred["last_check"] = None
        self.vault.save()

    # --------------------------------------- agent-safe methods (labels only)

    def list_accounts(self):
        """Agent-safe. Every account by label with site, email label and status; no secrets."""
        return [{
            "label": label, "site": c["site"], "email_label": c["email_label"],
            "last_rotated": c["last_rotated"], "rotation_pending": bool(c["pending_password"]),
            "last_check": c["last_check"],
        } for label, c in sorted(self._creds.items())]

    def check_password_breaches(self, labels=None):
        """Check stored passwords against Pwned Passwords, plus weakness and reuse."""
        targets = labels or sorted(self._creds)
        by_password = {}
        for label, cred in self._creds.items():
            by_password.setdefault(cred["password"], []).append(label)

        results = []
        for label in targets:
            cred = self._cred(label)
            try:
                seen = self.hibp.password_seen_count(cred["password"])
            except httpx.HTTPError:
                raise SecurityError("Couldn't reach Have I Been Pwned. Check your connection.") from None
            issues = []
            if seen:
                issues.append(f"appears in known breaches {seen:,} times")
            if len(cred["password"]) < MIN_STRONG_LENGTH:
                issues.append(f"shorter than {MIN_STRONG_LENGTH} characters")
            reused = [other for other in by_password[cred["password"]] if other != label]
            if reused:
                issues.append("same password as " + ", ".join(reused))
            cred["last_check"] = {"at": _now(), "breached": bool(seen), "issues": issues}
            results.append({"label": label, "site": cred["site"], "breached": bool(seen),
                            "issues": issues, "should_rotate": bool(issues)})
        self.vault.save()
        return results

    def check_email_breaches(self, email_label):
        """Agent-safe. Check one stored email (by label) for breaches; the result has labels only.

        Raises:
            SecurityError: Unknown label, no API key, or HIBP unreachable.
        """
        address = self.vault.data["emails"].get(email_label)
        if address is None:
            known = ", ".join(sorted(self.vault.data["emails"])) or "none yet"
            raise SecurityError(f"No email labelled {email_label!r}. Known: {known}.")
        try:
            breaches = self.hibp.breaches_for_account(address)
        except httpx.HTTPError:
            raise SecurityError("Couldn't reach Have I Been Pwned. Check your connection.") from None
        affected = [label for label, c in self._creds.items() if c["email_label"] == email_label]
        return {"email_label": email_label, "breach_count": len(breaches), "breaches": breaches,
                "accounts_using_this_email": affected}

    def start_rotation(self, label):
        """Generate a new password and stage it. The password itself is NOT returned."""
        cred = self._cred(label)
        cred["pending_password"] = generate_password()
        self.vault.save()
        return {
            "label": label, "site": cred["site"],
            "change_password_url": change_password_url(cred["site"]),
            "next_steps": [
                f"Run /reveal {label} --new in the assistant's terminal to see the new password.",
                "Sign in to the site and change the password there.",
                f"Run /rotated {label} so the vault stores the new password.",
                "Turn on two-factor authentication if the site offers it.",
            ],
        }
