"""Access-log secret redaction.

Some tokens travel in the request URL rather than a header, and each one opens something by itself:
- the invitation token and the password-reset token in the PATH (``/invites/{token}``,
  ``/reset/{token}``), and the ``?invite=`` / ``?reset=`` query the landing page carries on the
  initial load;
- the share-claim path ``/shares/{x}/claim``;
- every public link a person can be sent: a note link (``/l/{token}``,
  ``/note-links/{token}/redeem``), a file link (``/p/{token}``, ``/public-links/{token}/redeem``,
  ``/public-links/{token}/download/...``) and an upload link (``/u/{token}``,
  ``/receivers/{token}/upload-session...``).

Whoever reads a line holding one of these can open or use what it points at. The web log-pull serves
request lines to a ``web``-scoped token holder (a less-privileged consumer), and ``docker logs`` shows
the same lines, so every one is masked before it reaches any log sink, and again when a log is read
back (for lines written before a route was added here). Routes that carry a link's database id
(``/public-links/{id}/revoke``, ``.../token-copy``) are not secret and are left readable.

Kept as a small stdlib-only module (no app/DB imports) so the redaction is unit-testable offline and
reused by the in-app log sink, the uvicorn access-log filter and the log-pull reader. Add any new
secret-in-path or secret-in-query route to SECRET_PATH_ROUTES and every surface is covered at once.
"""
import logging
import re

# One secret-carrying route per entry: (prefix before the secret, what may follow it). The secret is
# the single path segment after the prefix. `follow` constrains the next part when the same prefix
# also carries non-secret ids on other routes (e.g. /public-links/{id}/revoke).
SECRET_PATH_ROUTES = [
    ("/invites/", None),                        # GET/POST /invites/{token}[/accept]
    ("/reset/", None),                          # GET/POST /reset/{password-reset-token}
    ("/shares/", "/claim"),                     # /shares/{claim-secret}/claim
    ("/l/", None),                              # GET /l/{note-link-token} (public read)
    ("/note-links/", "/redeem"),                # POST /note-links/{token}/redeem
    ("/p/", None),                              # GET /p/{file-link-token} (public page)
    ("/public-links/", "/redeem"),              # POST /public-links/{token}/redeem
    ("/public-links/", "/download/"),           # GET /public-links/{token}/download/{file_id}
    ("/u/", None),                              # GET /u/{upload-link-token} (public page)
    ("/receivers/", "/upload-session"),         # /receivers/{token}/upload-session[/...]
]

_SEGMENT = r"[^/\s?#\"']+"


def _anchored(prefix, follow):
    tail = "(" + re.escape(follow) + ")" if follow else "()"
    return re.compile("^(" + re.escape(prefix) + ")" + _SEGMENT + tail)


def _anywhere(prefix, follow):
    tail = "(" + re.escape(follow) + ")" if follow else "()"
    # No boundary check before the prefix, on purpose: a full URL ("https://host/p/<token>") must be
    # caught too. The cost is that an unrelated path containing, say, "/p/" loses one segment, which
    # only ever hides text, never reveals it.
    return re.compile("(" + re.escape(prefix) + ")" + _SEGMENT + tail)


# Secrets that ride the URL PATH. Anchored at the start so only the leading segment is masked.
LOG_PATH_SECRET_SUBS = [(_anchored(p, f), r"\1<redacted>\2") for p, f in SECRET_PATH_ROUTES]

# The same routes found anywhere inside a formatted log line ("GET /p/<token> HTTP/1.1", "-> ...").
_TEXT_SECRET_SUBS = [(_anywhere(p, f), r"\1<redacted>\2") for p, f in SECRET_PATH_ROUTES]

# Covers both the /?invite=<token> and /?reset=<token> landing links (the token rides the query on the
# initial page load, before the client strips it from the address bar).
INVITE_QUERY_RE = re.compile(r"(?i)([?&](?:invite|reset)=)[^&#\s\"']+")


def redact_log_path(path: str) -> str:
    """Mask replayable secrets carried in a URL path before it is written to the log-pull sink."""
    for rx, repl in LOG_PATH_SECRET_SUBS:
        path = rx.sub(repl, path)
    return path


def redact_access_path(full_path: str) -> str:
    """Redact secrets from a full request target (path + optional query) for the uvicorn access log:
    mask every secret-carrying route in the PATH and the ?invite=/?reset=<token> QUERY the landing
    page carries."""
    path, sep, query = full_path.partition("?")
    path = redact_log_path(path)
    if not sep:
        return path
    query = INVITE_QUERY_RE.sub(r"\1<redacted>", "?" + query)[1:]
    return path + "?" + query


def redact_secret_urls_in_text(text: str) -> str:
    """Mask every secret-carrying route and query found ANYWHERE in a log line. Used when a log is read
    back, so a line written before a route was listed here (or by a writer that bypassed the filter)
    still never serves a usable token."""
    if not text:
        return text
    for rx, repl in _TEXT_SECRET_SUBS:
        text = rx.sub(repl, text)
    return INVITE_QUERY_RE.sub(r"\1<redacted>", text)


class AccessLogRedactFilter(logging.Filter):
    """Scrub URL-borne secrets out of uvicorn's access log. The request target is rewritten through
    redact_access_path on EVERY line: a hand-kept list of trigger substrings here once let the note,
    file and upload link tokens through, because it named only the invite, share and reset routes.
    The regexes are cheap next to the request itself. Never raises, never drops a line."""
    def filter(self, record):  # noqa: A003
        try:
            args = record.args
            if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
                redacted = redact_access_path(args[2])
                if redacted != args[2]:
                    lst = list(args)
                    lst[2] = redacted
                    record.args = tuple(lst)
        except Exception:  # noqa: BLE001 — logging must never raise
            pass
        return True
