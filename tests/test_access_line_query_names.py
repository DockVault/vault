"""An access line prints a query parameter's name, never its value, offline.

What someone typed into an Activity search (a person's name, an address, free text) rides the query of
GET /activity/events, and a query value can be a secret as well. Every line that records a request (the
uvicorn access line, the in-app access line, and a line read back through log access) prints the query's
parameter names only. A part with no ``=`` may be a value on its own and prints as ``<value>``; a name
that does not look like one prints as ``<name>``.
"""
import logging
import pathlib

import pytest

from app.core.log_redaction import (
    AccessLogRedactFilter, access_target, query_names, redact_access_path, redact_secret_urls_in_text,
)

pytestmark = pytest.mark.unit

ROOT = pathlib.Path(__file__).resolve().parents[1]

NAME, ADDRESS, TEXT = "alice.martin@example.com", "203.0.113.9", "quarterly report draft"
# The same values as a browser or client puts them in a query string.
SEARCH = ("/activity/events?user=alice.martin%40example.com&user_match=exact&ip=203.0.113.9"
          "&q=quarterly+report+draft&category=auth&category=vault")
VALUES = (NAME, "alice.martin%40example.com", "alice.martin", ADDRESS, TEXT, "quarterly", "report", "draft",
          "exact", "vault&", "=auth")
NAMES = "/activity/events?user&user_match&ip&q&category&category"


# Every method a request line can carry: a search can be sent with any of them, and a line read back may
# hold any of them.
METHODS = ("GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS")


def _uvicorn_line(target, method="GET"):
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %s',
                            ("198.51.100.20:5123", method, target, "1.1", 200), None)
    assert AccessLogRedactFilter().filter(rec) is True
    return rec.getMessage()


def _assert_no_value(text):
    for value in VALUES:
        assert value not in text, f"{value!r} reached the line: {text}"


@pytest.mark.parametrize("method", METHODS)
def test_an_activity_search_reaches_the_uvicorn_line_as_names_only(method):
    line = _uvicorn_line(SEARCH, method)
    _assert_no_value(line)
    assert f'"{method} {NAMES} HTTP/1.1"' in line


def test_an_activity_search_reaches_the_in_app_line_as_names_only():
    path, _, query = SEARCH.partition("?")
    assert access_target(path, query) == NAMES
    assert access_target(path, "") == path and access_target("/vaults", None) == "/vaults"


@pytest.mark.parametrize("method", METHODS)
def test_a_line_read_back_from_before_the_change_serves_names_only(method):
    old = f'[web] INFO: 172.18.0.1:40112 - "{method} {SEARCH} HTTP/1.1" 200 OK'
    out = redact_secret_urls_in_text(old)
    _assert_no_value(out)
    assert f'"{method} {NAMES} HTTP/1.1" 200 OK' in out
    from app.services import log_pull
    _assert_no_value(log_pull.redact_log_text(old, []))


@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("quote", ["'", '"'])
def test_a_line_read_back_with_a_raw_quote_in_its_target_serves_names_only(method, quote):
    """A browser sends a quote in a query encoded, but a client can send it raw, and a line written before the
    change holds the query as it came. Such a line is reduced as any other: the quote does not end the
    target, so the values after it are not served."""
    target = (f"/activity/events?q=it{quote}s+quarterly+report+draft&user=alice.martin%40example.com"
              f"&ip=203.0.113.9&tag={quote}secretval{quote}")
    old = f'[web] INFO: 172.18.0.1:40112 - "{method} {target} HTTP/1.1" 200 OK'
    out = redact_secret_urls_in_text(old)
    _assert_no_value(out)
    assert "secretval" not in out, out
    assert f'"{method} /activity/events?q&user&ip&tag HTTP/1.1" 200 OK' in out, out
    from app.services import log_pull
    served = log_pull.redact_log_text(old, [])
    _assert_no_value(served)
    assert "secretval" not in served, served


@pytest.mark.parametrize("query, expected", [
    ("a=1&b=2", "a&b"),
    ("a=1&&b=", "a&b"),                                   # an empty part is skipped, an empty value is a name
    ("lonely", "<value>"),                                # no "=": may be a value sent on its own
    ("alice%40example.com", "<value>"),
    ("x=1&secret-search-text", "x&<value>"),
    ("al ice=1", "<name>"),                               # not a name
    ("%40alice=1", "<name>"),                             # an encoded name is never printed
    ("a" * 65 + "=1", "<name>"),
    ("filter[status]=open&page.size=5&key_version=3&tab-x=1", "filter[status]&page.size&key_version&tab-x"),
    ("", ""),
])
def test_query_names(query, expected):
    assert query_names(query) == expected


def test_a_secret_route_is_still_masked_with_its_query_reduced():
    token = "SEKRETtoken_ABCDEF0123456789-xyz"
    out = redact_access_path(f"/public-links/{token}/download/3f0c?name={token}&inline=1")
    assert out == "/public-links/<redacted>/download/3f0c?name&inline"


def test_the_in_app_line_uses_the_reduced_target():
    """The in-app access line prints the target through access_target, once, and never the raw query."""
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    start = src.index("# Web log-pull access line.")
    block = src[start:src.index("return response", start)]
    assert block.count("_access_target(request.url.path, request.url.query)") == 1
    assert "request.url.query}" not in block and "str(request.url)" not in block
    assert "_redact_log_path(request.url.path)" not in src
