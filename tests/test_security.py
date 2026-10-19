import hashlib

import pytest

from assistant.security import (AccountSecurity, SecurityError, change_password_url,
                                generate_password)


def sha1(pw):
    return hashlib.sha1(pw.encode()).hexdigest().upper()


@pytest.fixture
def sec(vault, fake_hibp):
    fake_hibp.pwned = {sha1("password123"): 251682}
    s = AccountSecurity(vault, fake_hibp.client())
    s.add_email("personal", "ada@example.com")
    s.add_credential("github", "github.com", "adalove", "password123", "personal")
    s.add_credential("bank", "https://www.mybank.example/login", "ada", "Zq8!vR2#mL9$wT4p", None)
    s.add_credential("forum", "forum.example", "ada", "password123", "personal")
    return s


def test_password_check_uses_k_anonymity(sec, fake_hibp):
    results = {r["label"]: r for r in sec.check_password_breaches()}
    assert results["github"]["breached"] and results["github"]["should_rotate"]
    assert any("forum" in i for i in results["github"]["issues"])          # reuse detected
    assert not results["bank"]["breached"] and not results["bank"]["issues"]

    for req in fake_hibp.requests:
        assert req.headers["Add-Padding"] == "true"
        prefix = req.url.path.rsplit("/", 1)[-1]
        assert len(prefix) == 5
        assert "password123" not in str(req.url) and sha1("password123") not in str(req.url)


def test_agent_facing_outputs_never_contain_secrets(sec):
    sec.start_rotation("github")
    outputs = repr([sec.list_accounts(), sec.check_password_breaches(), sec.start_rotation("bank")])
    for secret in ("password123", "Zq8!vR2#mL9$wT4p", "adalove", "ada@example.com",
                   sec.reveal("github", pending=True)):
        assert secret not in outputs


def test_rotation_flow(sec):
    info = sec.start_rotation("bank")
    assert info["change_password_url"] == "https://www.mybank.example/.well-known/change-password"
    new = sec.reveal("bank", pending=True)
    assert new != "Zq8!vR2#mL9$wT4p"
    sec.complete_rotation("bank")
    assert sec.reveal("bank") == new
    bank = next(a for a in sec.list_accounts() if a["label"] == "bank")
    assert bank["last_rotated"] is not None and not bank["rotation_pending"]
    with pytest.raises(SecurityError, match="No rotation"):
        sec.complete_rotation("bank")


def test_email_breaches_need_key_then_work(vault, fake_hibp):
    fake_hibp.accounts = {"ada@example.com": [
        {"Title": "ExampleCorp", "BreachDate": "2023-01-01", "DataClasses": ["Emails", "Passwords"], "IsVerified": True}]}
    sec = AccountSecurity(vault, fake_hibp.client())
    sec.add_email("personal", "ada@example.com")
    with pytest.raises(SecurityError, match="API key"):
        sec.check_email_breaches("personal")

    sec = AccountSecurity(vault, fake_hibp.client(api_key="good-key"))
    result = sec.check_email_breaches("personal")
    assert result["breach_count"] == 1 and result["breaches"][0]["breach"] == "ExampleCorp"
    assert "ada@example.com" not in repr(result)


def test_unknown_labels_give_helpful_errors(sec):
    with pytest.raises(SecurityError, match="Known accounts: bank, forum, github"):
        sec.start_rotation("twitter")


def test_generated_passwords_are_strong_and_unique():
    pws = {generate_password() for _ in range(50)}
    assert len(pws) == 50
    for pw in pws:
        assert len(pw) == 20
        assert any(c.isupper() for c in pw) and any(c.islower() for c in pw) and any(c.isdigit() for c in pw)


def test_change_password_url():
    assert change_password_url("github.com") == "https://github.com/.well-known/change-password"
    assert change_password_url("https://accounts.example.com/x?y=1") == \
        "https://accounts.example.com/.well-known/change-password"
