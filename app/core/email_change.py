"""One-time codes that prove a user controls a NEW email address before the account's email is
changed to it.

Only a peppered HMAC-SHA256 hash of the code is stored (the same token-at-rest shape the log-pull
tokens use); the plaintext code reaches only the new address, by email, and is shown nowhere else.
These helpers are pure so the hashing is unit-testable offline; the table and the endpoints live in
the app layer.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

# The code is single-use, short-lived, and rate-limited, so it does not need link-length entropy;
# 12 lowercase-hex characters (~48 bits) is comfortably brute-force-proof under those controls and
# still short enough for someone to read out of an email and type.
CODE_TTL_MINUTES = 15
_CODE_BYTES = 6


def generate_code() -> str:
    """A fresh, high-entropy, human-typeable verification code (lowercase hex)."""
    return secrets.token_hex(_CODE_BYTES)


def hash_code(code: str, pepper: str) -> str:
    """Peppered HMAC-SHA256 hex of a code — matches the token-at-rest pattern used elsewhere, so a
    read of the database alone never yields a usable code."""
    return hmac.new((pepper or "").encode(), (code or "").encode(), hashlib.sha256).hexdigest()


def code_matches(code: str, pepper: str, stored_hash: str) -> bool:
    """Constant-time comparison of a presented code against a stored hash."""
    return hmac.compare_digest(hash_code(code, pepper), stored_hash or "")
