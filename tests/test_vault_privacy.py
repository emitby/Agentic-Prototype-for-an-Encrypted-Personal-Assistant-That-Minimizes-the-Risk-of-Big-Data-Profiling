"""Vault encryption and the outbound redactor."""
import json
from pathlib import Path

import pytest

from assistant.privacy import Redactor
from assistant.vault import PROJECT_DIR, Vault, VaultError
from conftest import FAST_N, PASSPHRASE


def test_roundtrip_and_nothing_readable_on_disk(vault):
    """Data round-trips and nothing is readable in the file."""
    vault.data["emails"]["personal"] = "ada@example.com"
    vault.data["grocery_lists"]["groceries"] = [{"name": "laundry detergent", "qty": "1", "done": False}]
    vault.save()

    raw = vault.path.read_bytes()
    for needle in (b"ada@example.com", b"laundry", b"groceries", b"personal"):
        assert needle not in raw

    reopened = Vault.open(vault.path, PASSPHRASE)
    assert reopened.data["emails"]["personal"] == "ada@example.com"


def test_wrong_passphrase_rejected(vault):
    """A wrong passphrase can't open the vault."""
    with pytest.raises(VaultError, match="Wrong passphrase"):
        Vault.open(vault.path, "not the passphrase")


def test_tampering_detected(vault):
    """Any change to the file is detected."""
    envelope = json.loads(vault.path.read_text())
    ct = bytearray(envelope["ct"], "ascii")
    ct[10] = ord("A") if ct[10] != ord("A") else ord("B")
    envelope["ct"] = ct.decode()
    vault.path.write_text(json.dumps(envelope))
    with pytest.raises(VaultError):
        Vault.open(vault.path, PASSPHRASE)


def test_kdf_params_bound_to_ciphertext(vault):
    """Swapping KDF parameters breaks decryption (they're in the AAD)."""
    envelope = json.loads(vault.path.read_text())
    envelope["kdf"]["n"] = FAST_N * 2
    vault.path.write_text(json.dumps(envelope))
    with pytest.raises(VaultError):
        Vault.open(vault.path, PASSPHRASE)


def test_fresh_nonce_every_save(vault):
    """Every save uses a new nonce."""
    first = json.loads(vault.path.read_text())["nonce"]
    vault.save()
    assert json.loads(vault.path.read_text())["nonce"] != first


def test_short_passphrase_and_existing_vault_rejected(workdir, vault):
    """Short passphrases and overwriting an existing vault are refused."""
    with pytest.raises(VaultError, match="at least"):
        Vault.create(workdir / "other.enc", "short")
    with pytest.raises(VaultError, match="already exists"):
        Vault.create(vault.path, PASSPHRASE)


@pytest.mark.parametrize("outside", [
    PROJECT_DIR.parent / "elsewhere" / "vault.enc",
    PROJECT_DIR / ".." / "vault.enc",
    Path("/vault.enc"),
])
def test_vault_refuses_paths_outside_project(outside):
    """The vault refuses paths outside the project."""
    with pytest.raises(VaultError, match="inside the project"):
        Vault.create(outside, PASSPHRASE, scrypt_n=FAST_N)
    with pytest.raises(VaultError, match="inside the project"):
        Vault.open(outside, PASSPHRASE)
    assert not outside.resolve().exists()


def test_redactor_replaces_known_secrets_and_masks_others(vault):
    """Stored secrets become tags; other emails and cards are masked."""
    vault.data["emails"]["personal"] = "ada@example.com"
    vault.data["credentials"]["github"] = {"site": "github.com", "username": "adalove",
                                           "password": "hunter2hunter2", "pending_password": None}
    text = ("my github password is hunter2hunter2, user adalove, email ada@example.com, "
            "my boss is bob@corp.com, card 4111 1111 1111 1111, order 1234567890123")
    safe, found = Redactor(vault).redact(text)
    assert "hunter2hunter2" not in safe and "[password:github]" in safe
    assert "adalove" not in safe and "[username:github]" in safe
    assert "ada@example.com" not in safe and "[email:personal]" in safe
    assert "bob@corp.com" not in safe and "[email]" in safe
    assert "4111" not in safe and "[card]" in safe
    assert "1234567890123" in safe   # fails Luhn: not a card, left alone
    assert set(found) >= {"[password:github]", "[email:personal]", "[email]", "[card]"}
