"""Agent tests with a scripted fake Claude client: no API calls are made."""

from types import SimpleNamespace as NS

from assistant.agents import PersonalAssistant
from conftest import FakeClaude, response, text, tool_use

SECRETS = ("password123", "adalove", "ada@example.com")


def make(vault, fake_hibp, *responses):
    client = FakeClaude(*responses)
    pa = PersonalAssistant(client, vault, hibp=fake_hibp.client())
    pa.security.add_email("personal", "ada@example.com")
    pa.security.add_credential("github", "github.com", "adalove", "password123", "personal")
    return client, pa


def test_secrets_never_reach_the_model(vault, fake_hibp):
    import hashlib
    fake_hibp.pwned = {hashlib.sha1(b"password123").hexdigest().upper(): 99}
    client, pa = make(
        vault, fake_hibp,
        # Coordinator delegates (it got a redacted message)...
        response(tool_use("c1", "ask_security_agent", brief="Check all passwords for breaches"), stop="tool_use"),
        # ...security agent checks breaches and starts a rotation...
        response(tool_use("s1", "check_password_breaches"), tool_use("s2", "start_password_rotation", label="github"),
                 stop="tool_use"),
        response(text("github is breached; rotation started.")),
        response(text("Your GitHub password was found in a breach. I've started a rotation.")),
    )
    # The user carelessly types their password and email into the chat.
    result = pa.send("is my password password123 safe? I'm adalove, ada@example.com")

    assert "[password:github]" in result["redactions"]
    sent = client.everything_sent()
    for secret in SECRETS + (pa.security.reveal("github", pending=True),):
        assert secret not in sent
    # Transcript is stored (encrypted) in redacted form too.
    assert all(s not in repr(vault.data["transcript"]) for s in SECRETS)


def test_specialists_get_fresh_context_and_only_their_tools(vault, fake_hibp):
    client = FakeClaude(by_agent={
        "Coordinator": [
            response(tool_use("c1", "ask_household_agent", brief="Add eggs to groceries"),
                     tool_use("c2", "ask_travel_agent", brief="Flights JFK to LIS in May"), stop="tool_use"),
            response(text("Done: eggs added, flights found.")),
        ],
        "Household": [
            response(tool_use("h1", "add_grocery_items", list_name="groceries",
                              items=[{"name": "eggs", "qty": "12"}]), stop="tool_use"),
            response(text("Added eggs.")),
        ],
        "Travel": [
            response(NS(type="server_tool_use", name="web_search"), stop="pause_turn"),
            response(text("Found 3 options.")),
        ],
    })
    pa = PersonalAssistant(client, vault, hibp=fake_hibp.client())
    result = pa.send("add eggs to my grocery list and find flights to Lisbon in May")

    assert result["reply"].startswith("Done")
    assert vault.data["grocery_lists"]["groceries"][0]["name"] == "eggs"

    household, travel = client.requests_for("Household"), client.requests_for("Travel")
    assert household[0]["messages"] == [{"role": "user", "content": "Add eggs to groceries"}]
    household_tools = {t["name"] for t in household[0]["tools"]}
    assert "check_password_breaches" not in household_tools and "add_grocery_items" in household_tools
    assert any(t.get("type") == "web_search_20260209" for t in travel[0]["tools"])
    assert len(travel) == 2   # pause_turn was continued


def test_tool_errors_are_returned_not_raised(vault, fake_hibp):
    client, pa = make(
        vault, fake_hibp,
        response(tool_use("c1", "ask_security_agent", brief="rotate twitter"), stop="tool_use"),
        response(tool_use("s1", "start_password_rotation", label="twitter"), stop="tool_use"),
        response(text("No twitter account is stored.")),
        response(text("You don't have a Twitter login saved. Add it with /add-login twitter.")),
    )
    pa.send("rotate my twitter password")
    tool_result = client.requests[2]["messages"][-1]["content"][0]
    assert tool_result["is_error"] and "Known accounts: github" in tool_result["content"]
