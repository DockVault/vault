"""Pure token helpers for account invitations.

Pure so the hashing is unit-testable offline; the table and the endpoints live in the app layer. The
discipline is copied verbatim from the log-pull token (``secrets.token_urlsafe(32)`` → 256-bit
plaintext, a short public prefix for lookup, a peppered HMAC-SHA256 at rest, and a constant-time
compare), with a DEDICATED pepper so a leak of the log-pull pepper cannot compromise invitation
token hashes.
"""
import hashlib
import hmac
import secrets

# Length of the public lookup handle stored alongside the hash. Only the prefix is indexed; the
# constant-time compare runs over the (usually one) rows sharing a prefix.
PREFIX_LEN = 12


def mint_invite():
    """Return (plaintext, prefix). The plaintext is shown to the admin exactly once and never stored."""
    plaintext = secrets.token_urlsafe(32)  # 256 bits of entropy
    return plaintext, plaintext[:PREFIX_LEN]


def token_prefix(token: str) -> str:
    """The public lookup handle for a presented token (empty for a blank/None token)."""
    return (token or "")[:PREFIX_LEN]


def hash_invite_token(token: str, pepper: str) -> str:
    """Peppered HMAC-SHA256 hex of a token — the only representation stored at rest."""
    return hmac.new(pepper.encode(), token.encode(), hashlib.sha256).hexdigest()


def invite_tokens_match(presented: str, pepper: str, stored_hash: str) -> bool:
    """Constant-time check that a presented token hashes to the stored hash under this pepper."""
    return hmac.compare_digest(hash_invite_token(presented, pepper), stored_hash or "")


def pepper_ok(pepper) -> bool:
    """A pepper is usable only if it is a string of at least 32 characters (mirrors the log-pull
    check). Minting under a weak pepper is refused rather than silently producing guessable hashes."""
    return isinstance(pepper, str) and len(pepper.strip()) >= 32
