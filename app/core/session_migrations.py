"""Idempotent boot migration: hash any session token still stored in plaintext at rest.

Sessions created before tokens were hashed at rest hold the plaintext token, so a database read
would expose a usable credential. This replaces each with its SHA-256 hash in place -- WITHOUT
logging anyone out: the client still holds the plaintext, and verification hashes the presented
token to match the rehashed row.

Kept out of the API module so it can be exercised directly against a database without importing the
whole application (which validates credentials at import time).
"""
from app.core.session_hash_utils import hash_session_token, is_token_hashed


def rehash_plaintext_session_tokens(db) -> int:
    """Replace any plaintext ``ActiveSession.session_token`` with its SHA-256 hash, in place.

    Returns the number of rows rehashed; the caller owns the transaction (this does not commit). A
    value that is already a 64-hex hash is left untouched, so this is a no-op on every run after the
    first and on a fresh install with no legacy rows. Session tokens are ``secrets.token_urlsafe``
    output -- never 64 lowercase-hex -- so a plaintext token is never mistaken for a hash.
    """
    from app.core.models import ActiveSession

    rehashed = 0
    for sid, token in db.query(ActiveSession.id, ActiveSession.session_token).all():
        if token and not is_token_hashed(token):
            db.query(ActiveSession).filter(ActiveSession.id == sid).update(
                {ActiveSession.session_token: hash_session_token(token)},
                synchronize_session=False,
            )
            rehashed += 1
    return rehashed
