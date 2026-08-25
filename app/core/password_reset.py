"""Pure token helpers for password-reset links.

The reset link is the SAME token discipline as account invitations (``secrets.token_urlsafe(32)`` ->
256-bit plaintext, a short indexed prefix for lookup, a peppered HMAC-SHA256 at rest, and a
constant-time compare), so this reuses invitations' pure helpers rather than reimplementing them —
there is one audited implementation. The pepper is domain-separated from the invite/log-pull peppers
so a leak of one can't be used to forge the other.
"""
from app.core.invitations import (  # noqa: F401 (re-exported)
    PREFIX_LEN,
    token_prefix,
    pepper_ok,
    mint_invite as mint_reset_token,
    hash_invite_token as hash_reset_token,
    invite_tokens_match as reset_tokens_match,
)

# A stable domain-separation suffix so a reset-token hash is never equal to an invite/otp hash of the
# same secret material, even though both derive from the deployment's JWT secret.
_DOMAIN = ":password_reset"


def reset_pepper(jwt_secret: str) -> str:
    """The pepper for reset tokens: the deployment JWT secret with a domain-separation suffix."""
    return (jwt_secret or "").strip() + _DOMAIN
