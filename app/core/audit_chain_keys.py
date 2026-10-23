"""The keys of the audit log's integrity chain.

The chain's key is HKDF-SHA256 of AUDIT_CHAIN_KEY when it is set, and otherwise of ENCRYPTION_KEY (the UTF-8
text of each, as the app's other keys are derived). The database holds only its id (``kc1:`` and 16 hex
characters of an HMAC under the key), never the key. A process holds the current key and the key derived from
ENCRYPTION_KEY, which is there even when AUDIT_CHAIN_KEY is set: it verifies the history written before the
chain moved off it, and is never a reason to accept a new seal under it.

AUDIT_CHAIN_KEY must be as random as a generated one: every seal lets anyone with a copy of the database test
guesses of the key offline. The start refuses one shorter than 32 characters, and one equal to ENCRYPTION_KEY,
which would derive the same key and so give no separation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from app.core import audit_chain_format as fmt

MIN_KEY_LENGTH = 32


@dataclass(frozen=True)
class ChainKey:
    key: bytes
    key_id: str
    # Where it comes from: "chain" (AUDIT_CHAIN_KEY) or "encryption" (derived from ENCRYPTION_KEY).
    source: str


def _settings():
    from app.core.config import settings
    return settings


def key_problem(settings) -> Optional[str]:
    """Why AUDIT_CHAIN_KEY cannot be used, or None (an unset key is allowed: the chain then uses a key derived
    from ENCRYPTION_KEY)."""
    explicit = (getattr(settings, "audit_chain_key", "") or "").strip()
    if not explicit:
        return None
    if len(explicit) < MIN_KEY_LENGTH:
        return (f"AUDIT_CHAIN_KEY is shorter than {MIN_KEY_LENGTH} characters; set a random value of at least "
                f"{MIN_KEY_LENGTH} (for example 64 hex characters), or remove it to derive the chain's key from "
                "ENCRYPTION_KEY")
    if explicit == (getattr(settings, "encryption_key", "") or "").strip():
        return ("AUDIT_CHAIN_KEY equals ENCRYPTION_KEY, which would give the chain the same key; set a random "
                "value of its own")
    return None


def encryption_derived(settings=None) -> ChainKey:
    settings = settings or _settings()
    key = fmt.chain_key((settings.encryption_key or "").strip())
    return ChainKey(key, fmt.key_id(key), "encryption")


def current(settings=None) -> ChainKey:
    """The key new seals are written under."""
    settings = settings or _settings()
    explicit = (getattr(settings, "audit_chain_key", "") or "").strip()
    if explicit:
        key = fmt.chain_key(explicit)
        return ChainKey(key, fmt.key_id(key), "chain")
    return encryption_derived(settings)


def held(settings=None, extra: Optional[Dict[str, bytes]] = None) -> Dict[str, ChainKey]:
    """Every key this process holds, by id: the current key and the ENCRYPTION_KEY-derived key, and any given
    by the host tool."""
    settings = settings or _settings()
    out = {}
    for k in (encryption_derived(settings), current(settings)):
        out[k.key_id] = k
    for kid, key in (extra or {}).items():
        out[kid] = ChainKey(key, kid, "given")
    return out
