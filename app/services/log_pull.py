"""RO2-3 log-pull — the PURE, security-critical helpers behind the authenticated GET /logs
endpoint, kept out of app/api/api_server.py so they unit-test without importing the whole app.

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
_BEARER_RE = re.compile(r"(?i)(authorization\s*:\s*bearer\s+)\S+")

# A credential keyword. Prefix-tolerant (temp_password, admin_password, DB_PASSWORD — the prefix
# sits BEFORE the match and is left untouched) and suffix-tolerant (SECRET_KEY, api_key_id,
# password_field — a bounded `[\w.\-]{0,40}` run after the keyword) and style-tolerant (kv
# `password=x`, JSON `"password": "x"`, YAML `password: x`). Deliberately broad and
# fail-toward-redaction: over-scrubbing a non-secret ("token: expired") is acceptable; leaking a
# password is not. Bearer/JWT tokens are handled by their own passes.
#
# The pattern is ANCHORED on the keyword literal (no leading variable-length `[\w.\-]*` prefix)
# so the regex engine scans start positions in O(n): a non-keyword char fails the first token
# immediately, and the only backtracking is the bounded {0,40} suffix. (An earlier `[\w.\-]*`
# prefix was O(n^2) on a long separator-free line — an event-loop-blocking ReDoS.)
_CRED_KEY = (
    r"passwords?|passwd|pwd|passphrase|secrets?|api[-_]?keys?|apikey|"
    r"access[-_]?keys?|access[-_]?tokens?|auth[-_]?tokens?|refresh[-_]?tokens?|"
    r"client[-_]?secrets?|private[-_]?keys?|signing[-_]?keys?|session[-_]?keys?|"
    r"encryption[-_]?keys?|master[-_]?keys?|credentials?|tokens?"
)
# group(1) = keyword + bounded suffix + optional quote + separator; group(2) = the value.
# Only the value is replaced, so the key stays readable in the log. The value class excludes only
# whitespace and quotes (a JSON value ends at its closing quote) — NOT `& ; , }`, so a secret
# CONTAINING those does not leak its tail (over-redacts the rest of a token instead).
_CRED_RE = re.compile(
    r"(?i)((?:" + _CRED_KEY + r")[\w.\-]{0,40}[\"']?\s*[:=]\s*)[\"']?([^\s\"']+)"
)
# A password embedded in a connection string / URL: scheme://user:PASSWORD@host (the user part
# is optional so redis://:pass@host is caught too). The password class stops only at `@`/space, so
# a `/` inside the password does not break the match. Keeps the user and host, scrubs the secret.
# The password run is BOUNDED to {1,256}: an unbounded `[^@\s]+` overlaps the `://…:` structural
# chars, so a line with many `://X:` tokens and no `@` scans O(n) from each of O(n) starts — O(n^2)
# (a ~7s/line event-loop-blocking ReDoS even under the truncation cap). The bound makes it O(n).
_CONN_RE = re.compile(r"(?i)(://[^:/@\s]*:)([^@\s]{1,256})(@)")
# Bound the (str/regex) work per line: a pathological single line is truncated. Truncation only
# DROPS trailing content, so it can never reveal more of a secret than was already there.
_MAX_REDACT_LINE = 65536
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


def pepper_ok(pepper):
    """A usable pepper is a >=32-char string. A weak/absent pepper disables the endpoint (the
    effective ceiling requires this) rather than bricking the vault."""
    return isinstance(pepper, str) and len(pepper.strip()) >= 32


def effective_ceiling(plan_log_pull, pepper):
    """The REAL ceiling: the plan must allow the endpoint AND a strong pepper must be present.
    So a control plane that injects PLAN_LOG_PULL without also injecting a pepper (or an
    operator who forgets it) gets a SAFELY-DISABLED endpoint (404), never a dead container."""
    return bool(plan_log_pull) and pepper_ok(pepper)


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
    tokens, JWTs, and ANY credential/password), NOT tenant PII. Phase 2 adds an 'untrusted'
    profile that also blanks paths.

    A password reaching a log consumer is unacceptable regardless of where this vault is deployed,
    so credential redaction is deliberately broad and fails toward redaction:
    - Exact replace of each provided secret with len >= 8 (the guard stops an empty secret from
      inserting the placeholder between every character via str.replace('', ...)).
    - `Authorization: Bearer <x>`.
    - Any credential key/value: `password=`, `temp_password=`, `"password": "x"`, `passphrase:`,
      `secret=`, `api_key=`, `client_secret=`, `private_key=`, `token=`, ... (prefix- and
      quote-style-tolerant; the value is scrubbed, the key stays readable).
    - Passwords embedded in connection strings / URLs: `scheme://user:PASSWORD@host`.
    - JWT-shaped tokens (incl. the pull token itself if it ever echoes back — feedback-leak guard).
    """
    if not text:
        return text
    # Exact-scrub known secret VALUES on the FULL line first (linear str.replace) so the truncation
    # boundary below can never split a known secret and leak its head.
    for s in (secret_values or []):
        if isinstance(s, str) and len(s) >= 8:
            text = text.replace(s, _REDACTED)
    if len(text) > _MAX_REDACT_LINE:
        text = text[:_MAX_REDACT_LINE] + " …[truncated]"
    text = _BEARER_RE.sub(lambda m: m.group(1) + _REDACTED, text)
    text = _CRED_RE.sub(lambda m: m.group(1) + _REDACTED, text)
    text = _CONN_RE.sub(lambda m: m.group(1) + _REDACTED + m.group(3), text)
    text = _JWT_RE.sub("«redacted-jwt»", text)
    return text
