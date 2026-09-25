"""Offline unit tests for URL-secret redaction in the access log.

The invite / password-reset / share-claim tokens ride the request URL (path segment or landing-page
query), so uvicorn's access log — served to a `web`-scoped log-pull holder — must mask them or a
read-only log capability becomes account takeover. These tests pin BOTH the pure redactors AND the
uvicorn filter's trigger condition, so a regression like "the filter fires for /invites/ but not
/reset/" is caught without a live instance.
"""
import logging

import pytest

from app.core.log_redaction import (
    redact_log_path, redact_access_path, redact_secret_urls_in_text, AccessLogRedactFilter,
    INVITE_QUERY_RE,
)

pytestmark = pytest.mark.unit

TOKEN = "SEKRETtoken_ABCDEF0123456789-xyz"


# ---- the pure path/query redactors ------------------------------------------------------------
@pytest.mark.parametrize("path, expected", [
    (f"/invites/{TOKEN}", "/invites/<redacted>"),
    (f"/invites/{TOKEN}/accept", "/invites/<redacted>/accept"),
    (f"/reset/{TOKEN}", "/reset/<redacted>"),
    (f"/shares/{TOKEN}/claim", "/shares/<redacted>/claim"),
    ("/users/me", "/users/me"),                    # a normal path is untouched
    ("/", "/"),
])
def test_redact_log_path(path, expected):
    out = redact_log_path(path)
    assert out == expected
    assert TOKEN not in out


@pytest.mark.parametrize("full, expected", [
    (f"/reset/{TOKEN}", "/reset/<redacted>"),
    (f"/?reset={TOKEN}", "/?reset=<redacted>"),
    (f"/?invite={TOKEN}", "/?invite=<redacted>"),
    (f"/accept?invite={TOKEN}&x=1", "/accept?invite=<redacted>&x=1"),
    (f"/reset/{TOKEN}?next=%2Fdash", "/reset/<redacted>?next=%2Fdash"),
    ("/dashboard?tab=vaults", "/dashboard?tab=vaults"),   # no secret -> unchanged
])
def test_redact_access_path(full, expected):
    out = redact_access_path(full)
    assert out == expected
    assert TOKEN not in out


def test_query_regex_is_case_insensitive():
    assert INVITE_QUERY_RE.sub(r"\1<redacted>", f"?Reset={TOKEN}") == "?Reset=<redacted>"


# ---- the uvicorn access-log filter ------------------------------------------------------------
def _access_record(target: str) -> logging.LogRecord:
    # mirrors uvicorn's access formatter args: (client, method, request_target, http_version, status)
    return logging.LogRecord("uvicorn.access", logging.INFO, "", 0,
                             '%s - "%s %s HTTP/%s" %s', ("1.2.3.4", "GET", target, "1.1", 200), None)


@pytest.mark.parametrize("target, expected", [
    (f"/reset/{TOKEN}", "/reset/<redacted>"),          # THE regression this guards: reset in the path
    (f"/?reset={TOKEN}", "/?reset=<redacted>"),         # ...and in the landing-page query
    (f"/invites/{TOKEN}", "/invites/<redacted>"),
    (f"/?invite={TOKEN}", "/?invite=<redacted>"),
    (f"/shares/{TOKEN}/claim", "/shares/<redacted>/claim"),
])
def test_filter_redacts_secret_targets(target, expected):
    rec = _access_record(target)
    assert AccessLogRedactFilter().filter(rec) is True     # never drops the line
    assert rec.args[2] == expected
    assert TOKEN not in (rec.getMessage())                 # the rendered line carries no raw token


def test_filter_leaves_ordinary_targets_untouched():
    rec = _access_record("/users/me")
    assert AccessLogRedactFilter().filter(rec) is True
    assert rec.args[2] == "/users/me"


# ---- every route that carries a usable secret in its path ------------------------------------------
# Each one opens or uses something by itself: a note link, a public file link, an upload link, an
# invitation, a password reset, a share claim. The filter once fired only for the invite, share and
# reset routes, so the three kinds of public link were written to the access log in full.
SECRET_TARGETS = [
    (f"/invites/{TOKEN}", "/invites/<redacted>"),
    (f"/invites/{TOKEN}/accept", "/invites/<redacted>/accept"),
    (f"/reset/{TOKEN}", "/reset/<redacted>"),
    (f"/shares/{TOKEN}/claim", "/shares/<redacted>/claim"),
    (f"/l/{TOKEN}", "/l/<redacted>"),
    (f"/note-links/{TOKEN}/redeem", "/note-links/<redacted>/redeem"),
    (f"/p/{TOKEN}", "/p/<redacted>"),
    (f"/public-links/{TOKEN}/redeem", "/public-links/<redacted>/redeem"),
    (f"/public-links/{TOKEN}/download/3f0c", "/public-links/<redacted>/download/3f0c"),
    (f"/u/{TOKEN}", "/u/<redacted>"),
    (f"/receivers/{TOKEN}/upload-session", "/receivers/<redacted>/upload-session"),
    (f"/receivers/{TOKEN}/upload-session/s1/chunks/0", "/receivers/<redacted>/upload-session/s1/chunks/0"),
    (f"/receivers/{TOKEN}/upload-session/s1/complete", "/receivers/<redacted>/upload-session/s1/complete"),
]

# Routes on the same prefixes that carry a database id, not a secret: they stay readable.
READABLE_TARGETS = [
    "/public-links/7d1e2a/revoke",
    "/public-links/7d1e2a/token-copy",
    "/note-links/7d1e2a/revoke",
    "/note-links/7d1e2a/token-copy",
    "/receivers",
    "/users/me",
    "/logs",
    "/permissions/users/1",
]


@pytest.mark.parametrize("target, expected", SECRET_TARGETS)
def test_every_secret_route_is_masked_on_every_surface(target, expected):
    assert redact_log_path(target) == expected                      # the in-app log line
    rec = _access_record(target)                                     # uvicorn's access line
    assert AccessLogRedactFilter().filter(rec) is True
    assert rec.args[2] == expected
    assert TOKEN not in rec.getMessage()
    line = f'[web] 2026-09-26T01:00:00Z 203.0.113.9:5123 - "GET {target} HTTP/1.1" 200'
    assert TOKEN not in redact_secret_urls_in_text(line)             # a line read back from the log


@pytest.mark.parametrize("target", READABLE_TARGETS)
def test_routes_with_ids_stay_readable(target):
    assert redact_log_path(target) == target
    rec = _access_record(target)
    AccessLogRedactFilter().filter(rec)
    assert rec.args[2] == target


@pytest.mark.parametrize("target, expected", [
    # The legacy query form an API client may still use to prove a vault password on delete.
    (f"/vaults/7d1e/delete?vault_password={TOKEN}", "/vaults/7d1e/delete?vault_password=<redacted>"),
    (f"/vaults/7d1e/delete?Vault_Password={TOKEN}&x=1", "/vaults/7d1e/delete?Vault_Password=<redacted>&x=1"),
    (f"/x?passcode={TOKEN}", "/x?passcode=<redacted>"),
    (f"/x?a=1&client_secret={TOKEN}", "/x?a=1&client_secret=<redacted>"),
    (f"/x?token={TOKEN}", "/x?token=<redacted>"),
    ("/files?key_version=3&tab=vaults", "/files?key_version=3&tab=vaults"),   # not secret-named
])
def test_secret_named_query_values_are_masked(target, expected):
    assert redact_access_path(target) == expected
    rec = _access_record(target)
    AccessLogRedactFilter().filter(rec)
    assert rec.args[2] == expected
    assert TOKEN not in redact_secret_urls_in_text(f'"POST {target} HTTP/1.1" 200')


def test_text_scrubber_catches_full_urls_and_queries():
    text = (f"sent https://vault.example.com/p/{TOKEN} and https://vault.example.com/u/{TOKEN}, "
            f"landing /?invite={TOKEN} and /?reset={TOKEN}")
    out = redact_secret_urls_in_text(text)
    assert TOKEN not in out
    assert "/p/<redacted>" in out and "/u/<redacted>" in out


def test_log_pull_reader_masks_lines_written_before_the_fix():
    # A line already in the log file from before this route was masked at write time.
    from app.services import log_pull
    line = f'[web] INFO: 172.18.0.1:40112 - "POST /public-links/{TOKEN}/redeem HTTP/1.1" 200 OK'
    assert TOKEN not in log_pull.redact_log_text(line, [])


def test_filter_never_raises_on_odd_args():
    # short/None/non-string args must not raise (logging must never raise) and must pass the record
    for args in (None, ("only-one",), ("a", "b", 12345), ("a", "b")):
        rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "x", args, None)
        assert AccessLogRedactFilter().filter(rec) is True
