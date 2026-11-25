"""How an SFTP connection agrees its session keys (SFTP_KEX_POLICY).

The SSH library offers the hybrid post-quantum key exchange ``mlkem768x25519-sha256`` (ML-KEM-768 together with
X25519) first, when the cryptography library underneath it has ML-KEM. This module only filters what it offers:

* ``default``: nothing is taken away. In SSH the client's order decides which exchange is agreed, so the hybrid
  exchange is agreed with every client that lists it before any classical exchange this server supports
  (OpenSSH 9.9 and later do by default), and a client that does not agrees a classical one.
* ``pq-required``: every other exchange is taken away, so a connection is agreed with the hybrid exchange or
  not at all. Where the hybrid exchange is not available here, SFTP does not start: offering nothing would
  refuse everybody with no word why. In the one-container shape the supervisor stops the container when either
  half ends, so the web side stops too, until the setting is changed (``default`` is the recommended value).

There is no third value that "prefers" the hybrid exchange: a server cannot prefer, the client's order picks, so
such a value could take nothing away and reorder nothing, and did exactly what ``default`` does.

A value that is not one of the two never reaches this module from the settings: they refuse it when the server
starts (app/core/config.py). :func:`policy` reads one given to it directly as the default.
"""
from __future__ import annotations

from typing import Optional, Tuple

HYBRID = "mlkem768x25519-sha256"
DEFAULT, REQUIRED = "default", "pq-required"
POLICIES = (DEFAULT, REQUIRED)


class HybridUnavailable(RuntimeError):
    """``pq-required`` is set and this server cannot offer the hybrid exchange."""


def policy(value) -> str:
    """The policy in force for the configured ``value``: one of :data:`POLICIES`."""
    text = str(value or "").strip().lower()
    return text if text in POLICIES else DEFAULT


def offered(transport_class) -> Tuple[str, ...]:
    """The key exchanges the SSH library offers, in its order of preference."""
    return tuple(getattr(transport_class, "_preferred_kex", ()) or ())


def hybrid_available(transport_class) -> bool:
    return HYBRID in offered(transport_class)


def disabled_kex(value, transport_class) -> list:
    """The key exchanges to take away from what the library offers, for the configured policy. Raises
    :class:`HybridUnavailable` where only the hybrid exchange may be offered and there is none."""
    if policy(value) != REQUIRED:
        return []
    if not hybrid_available(transport_class):
        raise HybridUnavailable(
            "SFTP_KEX_POLICY=pq-required, and the hybrid key exchange " + HYBRID + " is not available in this "
            "server (its cryptography library has no ML-KEM). SFTP is not started; where the web side runs in the "
            "same container, the vault stops with it. Set SFTP_KEX_POLICY=default to start it and let clients "
            "connect with a classical key exchange.")
    return [name for name in offered(transport_class) if name != HYBRID]


def name_of(engine, table) -> Optional[str]:
    """The name of the key exchange a transport chose, from the engine the SSH library made for it and the
    library's own table of names to engine classes. Not every engine carries its name (the X25519 one does
    not), so the table is asked first."""
    if engine is None:
        return None
    for name, made_by in (table or {}).items():
        if made_by is type(engine):
            return name
    name = getattr(engine, "name", None)
    return name if isinstance(name, str) and name else None


def is_hybrid(name: Optional[str]) -> bool:
    return name == HYBRID

