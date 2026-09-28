"""A keyed stand-in for a name typed at sign-in, for the cache keys that count failed sign-ins by name.

Those keys only have to tell one name from another, so they carry an HMAC-SHA256 of the name, not the
name. A name typed at sign-in can be anything, a password typed into the name box included, and anyone
who can read the cache (it has no password by default) could otherwise list every one of them. Keyed,
the stand-ins cannot be reversed or confirmed by hashing guesses without the deployment's secret.

The key is LOG_TOKEN_PEPPER when it is set, else JWT_SECRET_KEY, each with a label of its own so the
same secret never produces the same value for two purposes. Changing either starts the counts afresh,
which is harmless: they last minutes, or a day at most.
"""
import hashlib
import hmac

_LABEL = "|sign-in-name-key"


def _key() -> bytes:
    from app.core.config import settings
    secret = (getattr(settings, "log_token_pepper", "") or "").strip()
    if not secret:
        secret = (getattr(settings, "jwt_secret_key", "") or "").strip()
    return (secret + _LABEL).encode("utf-8")


def name_key(identifier) -> str:
    """The stand-in for ``identifier`` in a cache key: 32 hex characters (128 bits) of its keyed
    HMAC-SHA256. The same name always gives the same stand-in on one deployment."""
    text = "" if identifier is None else str(identifier)
    return hmac.new(_key(), text.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:32]
