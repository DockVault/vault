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
    redact_log_path, redact_access_path, AccessLogRedactFilter, INVITE_QUERY_RE,
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


def test_filter_never_raises_on_odd_args():
    # short/None/non-string args must not raise (logging must never raise) and must pass the record
    for args in (None, ("only-one",), ("a", "b", 12345), ("a", "b")):
        rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "x", args, None)
        assert AccessLogRedactFilter().filter(rec) is True
