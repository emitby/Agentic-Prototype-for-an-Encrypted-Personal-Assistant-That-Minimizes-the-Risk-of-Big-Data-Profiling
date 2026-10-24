"""The agent team.

    You ──► Coordinator ──► Security Agent   (breach checks, password rotation)
                       ├──► Travel Agent     (flight search via web search)
                       └──► Household Agent  (grocery lists, supply estimates)

The Coordinator only routes and summarizes; it has no data tools. Each
specialist gets just the tools for its job and starts every brief with a
fresh context, so data from one area never sits in another agent's context.

Nothing an agent sees contains a password, a stored email address or a
username: tools speak in labels, and all outbound text is redacted.

All four agents share one hook pipeline per session (:func:`assistant.hooks.default_hooks`),
so every guardrail applies to every tool call and every model call. The user's
message is checked (G1) before any agent runs.
"""

import threading
from datetime import date, datetime, timezone

from assistant import guardrails as g
from assistant.agents.runtime import Agent, Tool
from assistant.hooks import default_hooks
from assistant.household import Groceries, HouseholdError, Supplies
from assistant.privacy import Redactor
from assistant.security import AccountSecurity, SecurityError

LABEL = {"type": "string", "maxLength": 64, "description": "Account label, e.g. 'github'. Never a username or address."}
TEXT = {"type": "string", "maxLength": 200}


def _obj(properties, required=()):
    """A strict JSON object schema: only the listed properties, some required."""
    return {"type": "object", "properties": properties, "required": list(required),
            "additionalProperties": False}


def _today():
    """Today's date written out for the prompts, e.g. "Friday, October 23, 2026"."""
    return date.today().strftime("%A, %B %d, %Y")


SECURITY_PROMPT = """You are the Security Agent in a private personal assistant. Today is {today}.

You help the user keep their own online accounts safe. Accounts and email addresses are known to you only by labels. You never see passwords, addresses or usernames, and you must never ask for them. If the user wants to add an account or email, tell them to use the CLI commands /add-login or /add-email, which keep secrets out of the chat.

What you can do:
- Check stored passwords against the Have I Been Pwned breach corpus, and find weak or reused passwords.
- Check a stored email address against known breaches, if the user has set an HIBP API key.
- Start a password rotation: this generates a strong new password and returns the site's change-password page. The user finishes the change on the website and then runs /rotated <label>. You cannot change passwords on websites yourself, so say so plainly if asked.

When reporting, put the riskiest accounts first: breached passwords, then reused ones, then weak ones. Recommend rotating those, and turning on two-factor authentication. Be concise and factual. The Coordinator reads your reply."""

TRAVEL_PROMPT = """You are the Travel Agent in a private personal assistant. Today is {today}.

You find flight options using web search. You cannot book tickets or see live fares from airline systems, so present what you find as current listings to verify, and link to the sources.

How to work:
- Use the user's home airport from get_travel_preferences when no origin is given.
- Search for the route and dates. Prefer airline sites and major fare aggregators. Check two or three sources when you can.
- Report up to 5 options: airline, route and stops, dates and times if listed, price as listed with the source and its date, and the link. Flag fares that look stale or that come from a single source.
- Mention flexible-date or nearby-airport savings when the results show them.

Be concise. The Coordinator reads your reply."""

HOUSEHOLD_PROMPT = """You are the Household Agent in a private personal assistant. Today is {today}.

You manage grocery lists and track consumable supplies such as laundry detergent.

- For grocery lists, add, check off, remove and show items. The default list is "groceries" unless the user names another one.
- For supplies, start tracking with track_supply (pick a sensible unit such as "loads" or "fl oz"), log readings with log_supply_reading, and get estimates with estimate_supplies. All estimates come from the tools. Never compute or guess supply numbers yourself.
- If a supply needs reordering within its lead time, offer to add it to the grocery list, or add it if the user already asked for that.

Report the results briefly. The Coordinator reads your reply."""

COORDINATOR_PROMPT = """You are a private personal assistant. Today is {today}.

You coordinate three specialists. Delegate every task to the right one with a self-contained brief, because they don't see this conversation:
- ask_security_agent: breach checks for the user's passwords and email addresses, weak or reused passwords, and password rotation.
- ask_travel_agent: finding flights and fares.
- ask_household_agent: grocery lists, and supply levels and run-out estimates (e.g. laundry detergent).
If a request touches several areas, call those specialists in the same turn so they run in parallel.

Privacy rules:
- Never ask the user to type a password, email address or username into the chat. For adding accounts, point them to the CLI commands /add-login, /add-email and /set-hibp-key.
- Text like [password:x], [email:x], [email] or [card] marks values the privacy filter removed before you saw them. Don't ask for the original.
- Only pass a specialist the details its task needs.

Answer clearly and briefly, and list action items first. Don't mention internal agents or tools."""


class PersonalAssistant:
    """Wires the vault, domain services, hooks and agents together for one user.

    Args:
        client: ``anthropic.Anthropic`` (or a test/simulated stand-in).
        vault: The unlocked :class:`~assistant.vault.Vault`.
        hibp: Optional :class:`~assistant.security.HIBPClient` (tests pass a mock).
        today: Function returning today's date (tests pass a fixed one).
        budget: Optional :class:`~assistant.guardrails.TokenBudget` (default limits if omitted).
    """

    def __init__(self, client, vault, hibp=None, today=date.today, budget=None):
        """Build the services, the session's hook pipeline and the four agents."""
        self.vault = vault
        self.redactor = Redactor(vault)
        self.security = AccountSecurity(vault, hibp)
        self.groceries = Groceries(vault)
        self.supplies = Supplies(vault, today=today)
        self.messages = []
        self._lock = threading.Lock()
        self._events = []
        self.budget = budget or g.TokenBudget()
        self.hooks = default_hooks(self.redactor, self.budget)
        self.hooks.emit = lambda e: self._events.append(e)   # hook events join the current turn's trace

        common = {"hooks": self.hooks}
        self.security_agent = Agent(client, "Security Agent", SECURITY_PROMPT.format(today=_today()),
                                    self._security_tools(), effort="low",
                                    safe_errors=(SecurityError,), **common)
        self.travel_agent = Agent(client, "Travel Agent", TRAVEL_PROMPT.format(today=_today()),
                                  self._travel_tools(), effort="medium",
                                  server_tools=[{"type": "web_search_20260209", "name": "web_search",
                                                 "max_uses": g.WEB_SEARCH_MAX_USES}], **common)
        self.household_agent = Agent(client, "Household Agent", HOUSEHOLD_PROMPT.format(today=_today()),
                                     self._household_tools(), effort="low",
                                     safe_errors=(HouseholdError,), **common)
        brief = _obj({"brief": {"type": "string", "maxLength": 4000,
                                "description": "Self-contained task description."}}, ["brief"])
        self.coordinator = Agent(client, "Coordinator", COORDINATOR_PROMPT.format(today=_today()), [
            Tool("ask_security_agent", "Account security: breach checks, weak/reused passwords, password rotation.",
                 brief, lambda brief: self._delegate(self.security_agent, brief)),
            Tool("ask_travel_agent", "Flight search and fare comparison using the web.",
                 brief, lambda brief: self._delegate(self.travel_agent, brief)),
            Tool("ask_household_agent", "Grocery lists and supply tracking (e.g. laundry detergent run-out estimates).",
                 brief, lambda brief: self._delegate(self.household_agent, brief)),
        ], effort="medium", **common)

    # ------------------------------------------------------------------ chat

    def send(self, text):
        """Run one user turn: redact, check (G1), then let the Coordinator work.

        Redaction runs first, so even a refused message is stored without secrets.

        Args:
            text: The user's chat message.

        Returns:
            ``{"reply", "redactions", "events", "guardrails"}``. ``events`` is this turn's
            trace (model calls, tool calls, hook events); ``guardrails`` lists the
            guardrails that blocked or changed something this turn.

        Raises:
            AgentError, BudgetExceeded, PrivacyLeak, anthropic.APIError: for the caller
            (the CLI shows a friendly message).
        """
        with self._lock:
            safe_text, redactions = self.redactor.redact(text)
            self._events = []
            if redactions:
                self._events.append({"type": "hook", "hook": "input_redact", "action": "modified",
                                     "tags": sorted(set(redactions))})
            check = g.check_user_message(safe_text)
            if not check.ok:
                self._events.append({"type": "hook", "hook": "input_check", "action": "blocked",
                                     "reason": check.reason})
                self._record(check.text, check.reply)
                return {"reply": check.reply, "redactions": redactions, "events": self._events,
                        "guardrails": [f"G1 input_check: {check.reason}"]}
            self.budget.start_turn()
            mark = len(self.messages)
            self.messages.append({"role": "user", "content": check.text})
            try:
                reply = self.coordinator.run(self.messages, on_event=self._events.append)
            except BaseException:
                # A failed turn (budget, privacy stop, API error) can leave a tool_use without its
                # tool_result, or content the outbound scan refused. Roll the history back to
                # before this turn so the next turn starts clean instead of failing forever.
                del self.messages[mark:]
                raise
            self._record(check.text, reply)
            return {"reply": reply, "redactions": redactions, "events": self._events,
                    "guardrails": self._fired()}

    def _fired(self):
        """Summarize this turn's hook events as ``"<hook>: <action>"`` strings (one per distinct pair)."""
        seen = []
        for e in self._events:
            if e.get("type") == "hook":
                item = f"{e['hook']}: {e['action']}"
                if item not in seen:
                    seen.append(item)
        return seen

    def _delegate(self, agent, brief):
        """Run a specialist on a fresh one-message conversation; the brief is redacted first."""
        safe_brief, _ = self.redactor.redact(brief)
        return agent.run([{"role": "user", "content": safe_brief}], on_event=self._events.append)

    def _record(self, user_text, reply):
        """Append the (redacted) exchange to the encrypted transcript and save the vault."""
        at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.vault.data["transcript"] += [{"at": at, "role": "user", "text": user_text},
                                          {"at": at, "role": "assistant", "text": reply}]
        self.vault.save()

    # ----------------------------------------------------------------- tools

    def _security_tools(self):
        """Label-only security tools. Nothing here accepts or returns a secret."""
        s = self.security
        return [
            Tool("list_accounts", "List stored accounts by label, with site, linked email label, "
                 "last rotation and last breach-check result.", _obj({}), s.list_accounts),
            Tool("check_password_breaches", "Check stored passwords (all, or the given labels) against "
                 "Have I Been Pwned using k-anonymity, plus weakness and reuse checks.",
                 _obj({"labels": {"type": "array", "items": LABEL}}), s.check_password_breaches),
            Tool("check_email_breaches", "Check one stored email address (by label) against known breaches. "
                 "Needs an HIBP API key.",
                 _obj({"email_label": LABEL}, ["email_label"]), s.check_email_breaches),
            Tool("start_password_rotation", "Generate and stage a new strong password for an account and "
                 "return its change-password page. The user completes the change on the site.",
                 _obj({"label": LABEL}, ["label"]), s.start_rotation),
        ]

    def _travel_tools(self):
        """Travel preference tools (web search itself is a server tool)."""
        prefs = self.vault.data["travel"]

        def get_prefs():
            """Return the saved home airport."""
            return {"home_airport": prefs["home_airport"]}

        def set_home_airport(iata_code):
            """Save a 3-letter IATA code as the home airport."""
            code = iata_code.strip().upper()
            if len(code) != 3 or not code.isalpha():
                return "Use a 3-letter IATA airport code, e.g. JFK."
            prefs["home_airport"] = code
            self.vault.save()
            return {"home_airport": code}

        return [
            Tool("get_travel_preferences", "The user's saved travel preferences (home airport).",
                 _obj({}), get_prefs),
            Tool("set_home_airport", "Save the user's home airport (3-letter IATA code).",
                 _obj({"iata_code": {"type": "string", "maxLength": 40}}, ["iata_code"]), set_home_airport),
        ]

    def _household_tools(self):
        """Grocery-list and supply-tracking tools."""
        g, s = self.groceries, self.supplies
        names = {"type": "array", "items": TEXT, "minItems": 1}
        return [
            Tool("show_grocery_lists", "Show one grocery list or all of them.",
                 _obj({"list_name": {"type": "string"}}), g.show),
            Tool("add_grocery_items", "Add items (or update quantities) on a list. Creates the list if needed.",
                 _obj({"list_name": {"type": "string"},
                       "items": {"type": "array", "minItems": 1, "items": _obj(
                           {"name": {"type": "string"}, "qty": {"type": "string"}}, ["name"])}},
                      ["list_name", "items"]), g.add_items),
            Tool("check_off_grocery_items", "Mark items as bought.",
                 _obj({"list_name": {"type": "string"}, "item_names": names}, ["list_name", "item_names"]),
                 g.check_off),
            Tool("remove_grocery_items", "Delete items from a list.",
                 _obj({"list_name": {"type": "string"}, "item_names": names}, ["list_name", "item_names"]),
                 g.remove_items),
            Tool("track_supply", "Start (or update) tracking a consumable supply. configured_daily_use "
                 "is the expected use per day in the supply's unit, used until readings exist.",
                 _obj({"name": {"type": "string"}, "unit": {"type": "string"},
                       "configured_daily_use": {"type": "number", "minimum": 0},
                       "reorder_lead_days": {"type": "integer", "minimum": 0}}, ["name", "unit"]),
                 s.track),
            Tool("log_supply_reading", "Log a reading: kind 'restock' (amount on hand after buying) or "
                 "'level' (amount left now). Optional date YYYY-MM-DD, default today.",
                 _obj({"name": {"type": "string"}, "kind": {"type": "string", "enum": ["restock", "level"]},
                       "amount": {"type": "number", "minimum": 0}, "on": {"type": "string"}},
                      ["name", "kind", "amount"]), s.log),
            Tool("estimate_supplies", "Estimate remaining amount, daily use, days left, run-out date and "
                 "reorder-by date for all tracked supplies.", _obj({}), s.estimate_all),
        ]
