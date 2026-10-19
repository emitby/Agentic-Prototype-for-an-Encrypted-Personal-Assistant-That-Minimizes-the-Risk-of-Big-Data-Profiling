"""Terminal interface. Chat with the assistant, or use slash commands for anything secret.

    python -m assistant.cli --init      # create a new encrypted vault
    python -m assistant.cli             # unlock and chat
    python -m assistant.cli --verbose   # also show agent activity

Secrets (passwords, email addresses, API keys) are only ever entered through
the slash commands below, with hidden input where it matters. They go
straight into the encrypted vault and never into the chat.
"""

import argparse
import getpass
import os
from pathlib import Path

import anthropic

from assistant.agents import AgentError, PersonalAssistant
from assistant.security import SecurityError
from assistant.vault import Vault, VaultError

DEFAULT_VAULT = Path(os.environ.get("ASSISTANT_VAULT", Path.home() / ".personal-assistant" / "vault.enc"))

HELP = """Commands (secrets stay on this machine):
  /add-email <label>         store an email address under a label (e.g. personal)
  /add-login <label>         store a website login (password typed hidden)
  /set-hibp-key              store a Have I Been Pwned API key (for email breach checks)
  /accounts                  list stored accounts
  /reveal <label> [--new]    show a stored password (or the new one during a rotation)
  /rotated <label>           confirm you changed the password on the site
  /help                      this list
  /quit                      lock the vault and exit
Anything else is sent to the assistant, e.g. "check my passwords for breaches",
"find flights from JFK to Lisbon in May", "add eggs and milk to groceries",
"I have 40 loads of detergent left, how long will it last?"."""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--vault", type=Path, default=DEFAULT_VAULT)
    parser.add_argument("--init", action="store_true", help="create a new vault")
    parser.add_argument("--verbose", action="store_true", help="show agent activity")
    args = parser.parse_args()

    try:
        vault = _unlock(args.vault, args.init)
    except VaultError as exc:
        raise SystemExit(f"error: {exc}")

    assistant = PersonalAssistant(anthropic.Anthropic(), vault)
    print(f"Vault unlocked: {args.vault}\nType /help for commands.\n")
    try:
        _loop(assistant, args.verbose)
    finally:
        vault.lock()
        print("Vault locked.")


def _unlock(path, init):
    if init:
        print("Choose a passphrase. It can't be recovered, and without it the vault can't be decrypted.")
        first = getpass.getpass("New passphrase: ")
        if first != getpass.getpass("Repeat passphrase: "):
            raise VaultError("Passphrases didn't match.")
        return Vault.create(path, first)
    return Vault.open(path, getpass.getpass("Vault passphrase: "))


def _loop(assistant, verbose):
    while True:
        try:
            text = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not text:
            continue
        if text.startswith("/"):
            if text in ("/quit", "/exit"):
                return
            try:
                _command(assistant, text)
            except (SecurityError, VaultError) as exc:
                print(f"  {exc}")
            continue

        try:
            result = assistant.send(text)
        except anthropic.APIError as exc:
            print(f"  The AI service failed ({type(exc).__name__}). Try again.")
            continue
        except AgentError as exc:
            print(f"  {exc}")
            continue
        if result["redactions"]:
            print(f"  (privacy filter removed before sending: {', '.join(sorted(set(result['redactions'])))})")
        if verbose:
            for e in result["events"]:
                if e["type"] == "tool_call":
                    print(f"  · {e['agent']} → {e['tool']}")
        print(f"\nassistant> {result['reply']}\n")


def _command(assistant, text):
    sec = assistant.security
    cmd, *rest = text.split()
    label = rest[0] if rest else None

    if cmd == "/help":
        print(HELP)
    elif cmd == "/add-email":
        _need(label, "/add-email <label>")
        sec.add_email(label, input("  Email address: "))
        print(f"  Saved email '{label}'.")
    elif cmd == "/add-login":
        _need(label, "/add-login <label>")
        site = input("  Website (e.g. github.com): ").strip()
        username = input("  Username: ").strip()
        password = getpass.getpass("  Password (hidden): ")
        emails = sorted(assistant.vault.data["emails"])
        email_label = input(f"  Linked email label {emails or ''} (optional): ").strip() or None
        sec.add_credential(label, site, username, password, email_label)
        print(f"  Saved login '{label}' for {site}.")
    elif cmd == "/set-hibp-key":
        sec.set_hibp_key(getpass.getpass("  HIBP API key (hidden): ").strip())
        print("  Saved.")
    elif cmd == "/accounts":
        accounts = sec.list_accounts()
        if not accounts:
            print("  No accounts yet. Add one with /add-login <label>.")
        for a in accounts:
            check = a["last_check"]
            status = "unchecked" if not check else ("BREACHED" if check["breached"] else
                                                    "issues: " + "; ".join(check["issues"]) if check["issues"] else "ok")
            print(f"  {a['label']:<14} {a['site']:<24} {status}"
                  f"{'  (rotation pending)' if a['rotation_pending'] else ''}")
    elif cmd == "/reveal":
        _need(label, "/reveal <label> [--new]")
        print(f"  {sec.reveal(label, pending='--new' in rest)}")
        print("  (Clear your terminal when done.)")
    elif cmd == "/rotated":
        _need(label, "/rotated <label>")
        sec.complete_rotation(label)
        print(f"  Stored the new password for '{label}'.")
    else:
        print("  Unknown command. Type /help.")


def _need(value, usage):
    if not value:
        raise SecurityError(f"Usage: {usage}")


if __name__ == "__main__":
    main()
