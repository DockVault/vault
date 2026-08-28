"""Access-log secret redaction.

Some single-use tokens travel in the request URL rather than a header: the invitation token and the
password-reset token in the PATH (``/invites/{token}``, ``/reset/{token}``), the share-claim secret in
``/shares/{secret}/claim``, and the ``?invite=`` / ``?reset=`` query the landing page carries on the
initial load. The web log-pull serves request lines to a ``web``-scoped token holder (a less-privileged
consumer), so those tokens must be masked before they reach any log sink — the leak the app's other
bearer tokens avoid by being header-only.

Kept as a small stdlib-only module (no app/DB imports) so the redaction is unit-testable offline and
reused by both the in-app log sink and the uvicorn access-log filter. Add any new secret-in-path or
secret-in-query route here and both surfaces are covered at once.
"""
import logging
import re

# Secrets that ride the URL PATH. Anchored at the start so only the leading segment is masked.
LOG_PATH_SECRET_SUBS = [
    (re.compile(r"^(/invites/)[^/]+"), r"\1<redacted>"),           # GET/POST /invites/{token}[/accept]
    (re.compile(r"^(/reset/)[^/]+"), r"\1<redacted>"),             # GET/POST /reset/{password-reset-token}
    (re.compile(r"^(/shares/)[^/]+(/claim)"), r"\1<redacted>\2"),  # /shares/{claim-secret}/claim
]

# Covers both the /?invite=<token> and /?reset=<token> landing links (the token rides the query on the
# initial page load, before the client strips it from the address bar).
INVITE_QUERY_RE = re.compile(r"(?i)([?&](?:invite|reset)=)[^&#]+")


def redact_log_path(path: str) -> str:
    """Mask replayable secrets carried in a URL path before it is written to the log-pull sink."""
    for rx, repl in LOG_PATH_SECRET_SUBS:
        path = rx.sub(repl, path)
    return path


def redact_access_path(full_path: str) -> str:
    """Redact secrets from a full request target (path + optional query) for the uvicorn access log:
    mask the invite/reset token in the PATH and the ?invite=/?reset=<token> QUERY the landing page
    carries."""
    path, sep, query = full_path.partition("?")
    path = redact_log_path(path)
    if not sep:
        return path
    query = INVITE_QUERY_RE.sub(r"\1<redacted>", "?" + query)[1:]
    return path + "?" + query


class AccessLogRedactFilter(logging.Filter):
    """Scrub the invite/share/password-reset tokens out of uvicorn's access log. Those single-use
    tokens travel in the URL (a path segment on the invite/reset endpoints, the ?invite=/?reset= query
    on the landing page), so uvicorn's default access log would otherwise write the raw token on every
    request. Rewrites the request-target arg in place; never raises, never drops a line."""
    def filter(self, record):  # noqa: A003
        try:
            args = record.args
            if (isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str)
                    and ("/invites/" in args[2] or "/shares/" in args[2] or "/reset/" in args[2]
                         or "invite=" in args[2] or "reset=" in args[2])):
                lst = list(args)
                lst[2] = redact_access_path(args[2])
                record.args = tuple(lst)
        except Exception:  # noqa: BLE001 — logging must never raise
            pass
        return True
