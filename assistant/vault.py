"""Encrypted storage. Nothing the assistant keeps is written to disk in plaintext.

The whole store is one JSON document, encrypted with AES-256-GCM under a key
derived from your passphrase with scrypt. The passphrase and key are never
stored. Every save uses a fresh random nonce, and GCM authentication means
any tampering with the file is detected on load.

File layout (JSON):
    {"v": 1, "kdf": {"salt", "n", "r", "p"}, "nonce": ..., "ct": ...}   (base64 fields)
"""

import base64
import json
import secrets
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from assistant.paths import write_text

FORMAT_VERSION = 1
SCRYPT_N = 2 ** 17     # ~128 MiB, ~0.3-1 s per unlock: slows brute-force guessing
SCRYPT_R = 8
SCRYPT_P = 1
MIN_PASSPHRASE = 12

# The vault always lives inside the project directory; nothing is written elsewhere.
PROJECT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_VAULT = PROJECT_DIR / "data" / "vault.enc"

EMPTY_STORE = {
    "credentials": {},      # label -> {site, username, email_label, password, ...}
    "emails": {},           # label -> address
    "grocery_lists": {},    # list name -> [{name, qty, done}]
    "supplies": {},         # name -> {unit, readings: [...], ...}
    "travel": {"home_airport": None, "searches": []},
    "transcript": [],       # encrypted chat history: [{at, role, text}]
    "settings": {},         # e.g. hibp_api_key
}


class VaultError(Exception):
    """A vault problem that's safe to show the user (wrong passphrase, tampering, bad path ...)."""
    pass


def _b64(data):
    """Base64-encode bytes to an ASCII string (for the JSON envelope)."""
    return base64.b64encode(data).decode("ascii")


def _unb64(text):
    """Decode a base64 string from the envelope."""
    return base64.b64decode(text.encode("ascii"))


def _derive_key(passphrase, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P):
    """Derive the 256-bit AES key from the passphrase with scrypt.

    scrypt is memory-hard: N = 2^17 with r = 8 uses about 128 MiB per attempt, so guessing
    passphrases is slow and expensive even on GPUs.

    Returns:
        32 key bytes (never stored).
    """
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def _confined(path):
    """Resolve a vault path, refusing anything outside the project directory."""
    resolved = Path(path).resolve()
    if not resolved.is_relative_to(PROJECT_DIR):
        raise VaultError(f"The vault must be inside the project directory ({PROJECT_DIR}).")
    return resolved


class Vault:
    """An unlocked vault. Use `Vault.create` or `Vault.open`, then `vault.data` and `vault.save()`."""

    def __init__(self, path, key, kdf_params, data):
        """Wrap an already-derived key and decrypted data (use :meth:`create` or :meth:`open`)."""
        self.path = _confined(path)
        self._key = key
        self._kdf = kdf_params
        self.data = data
        self._lock = threading.RLock()

    @classmethod
    def create(cls, path, passphrase, scrypt_n=SCRYPT_N):
        """Create a new, empty vault file.

        Args:
            path: Inside the project only.
            passphrase: At least MIN_PASSPHRASE characters.
            scrypt_n: scrypt cost (tests and harness scenarios use a lower value for speed).

        Returns:
            The unlocked vault.

        Raises:
            VaultError: Existing file, short passphrase, or a path outside the project.
        """
        path = _confined(path)
        if path.exists():
            raise VaultError(f"A vault already exists at {path}.")
        if len(passphrase) < MIN_PASSPHRASE:
            raise VaultError(f"Use a passphrase of at least {MIN_PASSPHRASE} characters.")
        salt = secrets.token_bytes(16)
        kdf = {"salt": _b64(salt), "n": scrypt_n, "r": SCRYPT_R, "p": SCRYPT_P}
        vault = cls(path, _derive_key(passphrase, salt, scrypt_n), kdf, json.loads(json.dumps(EMPTY_STORE)))
        vault.save()
        return vault

    @classmethod
    def open(cls, path, passphrase):
        """Decrypt an existing vault.

        The salt and scrypt parameters come from the file; AES-GCM verifies the tag over the
        ciphertext and the AAD (format version + KDF parameters), so a wrong passphrase, any
        edit to the file, or swapped KDF parameters all fail the same way.

        Raises:
            VaultError: Missing file, wrong passphrase or tampering, corrupt or unsupported file.
        """
        path = _confined(path)
        try:
            envelope = json.loads(path.read_text("utf-8"))
            if envelope.get("v") != FORMAT_VERSION:
                raise VaultError("Unsupported vault format.")
            kdf = envelope["kdf"]
            key = _derive_key(passphrase, _unb64(kdf["salt"]), kdf["n"], kdf["r"], kdf["p"])
            plaintext = AESGCM(key).decrypt(_unb64(envelope["nonce"]), _unb64(envelope["ct"]),
                                            cls._aad(kdf))
        except FileNotFoundError:
            raise VaultError(f"No vault at {path}. Run with --init to create one.") from None
        except InvalidTag:
            raise VaultError("Wrong passphrase, or the vault file has been tampered with.") from None
        except (KeyError, ValueError, TypeError):
            raise VaultError("The vault file is corrupt.") from None
        data = json.loads(plaintext)
        for section, default in EMPTY_STORE.items():   # forward-compatible with new sections
            data.setdefault(section, json.loads(json.dumps(default)))
        return cls(path, key, kdf, data)

    def save(self):
        """Encrypt the whole store with a fresh 96-bit nonce and write it atomically.

        Side effects:
            Writes ``vault.enc.tmp`` then renames it over ``vault.enc`` via
            :func:`assistant.paths.write_text` (confined to the project; nothing is deleted).
        """
        with self._lock:
            nonce = secrets.token_bytes(12)
            plaintext = json.dumps(self.data, separators=(",", ":")).encode("utf-8")
            ct = AESGCM(self._key).encrypt(nonce, plaintext, self._aad(self._kdf))
            envelope = {"v": FORMAT_VERSION, "kdf": self._kdf, "nonce": _b64(nonce), "ct": _b64(ct)}
            write_text(self.path, json.dumps(envelope))   # atomic: a crash never leaves a half-written vault

    def lock(self):
        """Drop the key and data from this object."""
        self._key = None
        self.data = None

    @staticmethod
    def _aad(kdf):
        """Associated data bound into the GCM tag: the format version and KDF parameters."""
        # Bind the KDF parameters to the ciphertext so they can't be swapped.
        return json.dumps({"v": FORMAT_VERSION, "kdf": kdf}, sort_keys=True).encode("utf-8")
