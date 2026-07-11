"""RO2-3 log-pull — the PURE, security-critical helpers behind the authenticated GET /logs
endpoint, kept out of api_server.py so they unit-test without importing the whole app.

Nothing here reads config/DB — the caller passes the pepper, the secret list, and the effective
flags in. That keeps token hashing, scope validation, service filtering, the enable gate, and
redaction independently testable (and re-usable by Phase 2's tiering).
"""
import hashlib
import hmac
import re
import secrets

# The components the log system knows about. Phase 1 can SERVE only web/sftp (sourced from the
# run_combined sink); db-diag/redis-diag are accepted as scopes/flags but 404 until Phase 2 adds
# the vault-side DB/redis client-diagnostics view.
KNOWN_COMPONENTS = ("web", "sftp", "db-diag", "redis-diag")
SERVEABLE_COMPONENTS = ("web", "sftp")

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_BEARER_RE = re.compile(r"(?i)(authorization:\s*bearer\s+)\S+")
_KV_SECRET_RE = re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\s*[=:]\s*\S+")
_REDACTED = "«redacted»"


def mint_token():
    """Return (plaintext, prefix). The plaintext is shown to the admin ONCE; only its hash is
    stored. token_urlsafe(32) is 256 bits of entropy (matches the codebase minter)."""
    plaintext = secrets.token_urlsafe(32)
    return plaintext, plaintext[:12]


def token_prefix(token):
    return (token or "")[:12]


def hash_log_token(token, pepper):
    """Peppered HMAC-SHA256 hex of a token. A dedicated pepper (LOG_TOKEN_PEPPER) so a leak of
    ENCRYPTION_KEY/JWT_SECRET_KEY does not let an attacker reproduce stored hashes."""
    return hmac.new((pepper or "").encode(), (token or "").encode(), hashlib.sha256).hexdigest()


def tokens_match(presented, pepper, stored_hash):
    """Constant-time comparison of a presented token against a stored hash."""
    return hmac.compare_digest(hash_log_token(presented, pepper), stored_hash or "")


def validate_scope(scope):
    """Return a sanitized scope LIST: known components only, de-duplicated, order-stable. A
    non-list, or unknown/blank entries, are dropped — so a scope check is always exact list
    membership (never a substring match against a raw string)."""
    if not isinstance(scope, (list, tuple)):
        return []
    out = []
    for c in scope:
        if isinstance(c, str) and c in KNOWN_COMPONENTS and c not in out:
            out.append(c)
    return out


def is_pull_enabled(ceiling, flags, component):
    """Two-layer gate as a pure function: the env CEILING (bool) AND the per-component DB flag.
    Default per-component OFF; unknown component -> False. Callers wrap this with the real
    settings + a fail-closed DB read."""
    if not ceiling:
        return False
    if not isinstance(flags, dict):
        return False
    return bool(flags.get(component, False))


def filter_service_lines(lines, service):
    """Keep only sink lines emitted by `service`. Sink lines are stored as `[web] ...` / `[sftp]
    ...` with the tag at the very START (no docker timestamp — run_combined writes the raw tagged
    line), so the match is an exact line-start prefix and a tag appearing inside a body cannot
    cross-contaminate. Unknown/blank service -> [] (the handler 404s before reaching here)."""
    if not service or service not in KNOWN_COMPONENTS:
        return []
    tag = f"[{service}] "
    tag_empty = f"[{service}]"  # a bare-tag line with no content after it
    return [ln for ln in lines if ln.startswith(tag) or ln == tag_empty or ln.startswith(tag_empty + "\n")]


def redact_log_text(text, secret_values):
    """Best-effort scrub of KNOWN secrets and secret-shaped tokens from a log body before it is
    served. Phase 1 has ONE consumer — the tenant/self-hoster who owns this vault — so their own
    SFTP filenames pass; the job here is to stop SECRET leakage (signing keys, DB creds, bearer
    tokens, JWTs), NOT tenant PII. Phase 2 adds an 'untrusted' profile that also blanks paths.

    - Exact replace of each provided secret with len >= 8 (the guard stops an empty secret from
      inserting the placeholder between every character via str.replace('', ...)).
    - Regex passes for `Authorization: Bearer <x>`, `password=/token=/secret=/api_key=<x>`, and
      JWT-shaped tokens (incl. the pull token itself if it ever echoes back — feedback-leak guard).
    """
    if not text:
        return text
    for s in (secret_values or []):
        if isinstance(s, str) and len(s) >= 8:
            text = text.replace(s, _REDACTED)
    text = _BEARER_RE.sub(lambda m: m.group(1) + _REDACTED, text)
    text = _KV_SECRET_RE.sub(lambda m: m.group(1) + "=" + _REDACTED, text)
    text = _JWT_RE.sub("«redacted-jwt»", text)
    return text
