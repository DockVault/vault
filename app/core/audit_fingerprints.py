"""Fingerprints: what the audit log keeps of a name recorded at the fingerprint level.

A fingerprint is a keyed HMAC-SHA256 of the value, written ``fp1:<key id>:<32 hex characters>``. The same
value gives the same fingerprint under the same key, so a search for a name typed now finds the rows that
recorded it, while the rows themselves never hold the name.

The key is AUDIT_FINGERPRINT_KEY (setup writes a random one on a new install), or, when it is not set, a key
derived from ENCRYPTION_KEY under a label of its own. The key id is computed from the key, so rows recorded
under another key say so instead of silently failing to match.

- A name typed at a failed sign-in, or into a filter, is fingerprinted under one key for the deployment.
- A vault, file or folder name is fingerprinted under a key derived for its vault, so the same name in two
  vaults gives two fingerprints. With one key, an administrator could upload a file of a guessed name to a
  vault of their own and spot the same fingerprint on events of a vault they are not in. Name fingerprints
  are shown and exported only for vaults the viewer can read (app/services/activity_names.py).

A fingerprint protects a value from someone who reads the database without the key. Anyone who holds .env
(it is in the backups dockvault.py makes) holds the key, and can test guesses: a short or common value is
found quickly. Any administrator can test a guess of a name typed at a failed sign-in too: the Activity page's
search fingerprints what is typed (app/services/activity_events.py).
"""
from __future__ import annotations

import functools
import hashlib
import hmac
import re
from typing import Optional

PREFIX = "fp1"
_KEY_LABEL = b"dockvault audit fingerprint key"
_DERIVED_LABEL = b"dockvault audit fingerprint key, derived from the encryption key"
_KEY_ID_LABEL = b"dockvault audit fingerprint key id"
# The shortest AUDIT_FINGERPRINT_KEY the start accepts.
MIN_KEY_LENGTH = 32
PATTERN = re.compile(r"fp1:[0-9a-f]{8}:[0-9a-f]{32}")

# What a fingerprint is of, each under a key of its own.
SIGNIN = "signin"
NAME = "name"


class FingerprintKeyMissing(RuntimeError):
    """Neither AUDIT_FINGERPRINT_KEY nor ENCRYPTION_KEY is set."""


@functools.lru_cache(maxsize=8)
def _base_key(explicit: str, encryption_key: str) -> bytes:
    if explicit:
        return hmac.new(explicit.encode("utf-8"), _KEY_LABEL, hashlib.sha256).digest()
    if encryption_key:
        return hmac.new(encryption_key.encode("utf-8"), _DERIVED_LABEL, hashlib.sha256).digest()
    raise FingerprintKeyMissing("no key to fingerprint with")


def _secrets(settings=None):
    if settings is None:
        from app.core.config import settings
    return ((getattr(settings, "audit_fingerprint_key", "") or "").strip(),
            (getattr(settings, "encryption_key", "") or "").strip())


def key_id(settings=None) -> str:
    """The id of the key in use: 8 hex characters computed from it."""
    return hmac.new(_base_key(*_secrets(settings)), _KEY_ID_LABEL, hashlib.sha256).hexdigest()[:8]


def _purpose_key(what: str, vault_id, settings=None) -> bytes:
    label = f"{what}|{vault_id}" if what == NAME else what
    return hmac.new(_base_key(*_secrets(settings)), label.encode("utf-8"), hashlib.sha256).digest()


def fingerprint(what: str, value, vault_id=None, settings=None) -> Optional[str]:
    """The fingerprint of ``value``: ``what`` is SIGNIN, or NAME with the vault it is in. None for a name
    with no vault (it is then not recorded at all) or a value that is None."""
    if value is None or (what == NAME and not vault_id):
        return None
    digest = hmac.new(_purpose_key(what, vault_id, settings), str(value).encode("utf-8", "surrogatepass"),
                      hashlib.sha256).hexdigest()[:32]
    return f"{PREFIX}:{key_id(settings)}:{digest}"


def is_fingerprint(text) -> bool:
    return isinstance(text, str) and PATTERN.fullmatch(text) is not None


def key_problem(settings) -> Optional[str]:
    """Why AUDIT_FINGERPRINT_KEY cannot be used, or None (an unset key is fine: one is derived)."""
    explicit = (getattr(settings, "audit_fingerprint_key", "") or "").strip()
    if explicit and len(explicit) < MIN_KEY_LENGTH:
        return (f"AUDIT_FINGERPRINT_KEY is shorter than {MIN_KEY_LENGTH} characters; set a random value of "
                f"at least {MIN_KEY_LENGTH} (for example 64 hex characters), or remove it to derive one from "
                "ENCRYPTION_KEY")
    return None
