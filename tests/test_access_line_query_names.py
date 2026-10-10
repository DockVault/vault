"""An access line prints a query parameter's name, never its value, offline.

What someone typed into an Activity search (a person's name, an address, free text) rides the query of
GET /activity/events, and a query value can be a secret as well. Every line that records a request (the
uvicorn access line, the in-app access line, and a line read back through log access) prints the query's
parameter names only. A part with no ``=`` may be a value on its own and prints as ``<value>``; a name
that does not look like one prints as ``<name>``. A line already written with names only is read back as
it was written: reduced a second time, each name would print as ``<value>``.
"""
import logging
import pathlib

import pytest

from app.core import log_redaction
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


def _uvicorn_line(target, method="GET", version="1.1"):
    rec = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %s',
                            ("198.51.100.20:5123", method, target, version, 200), None)
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


# The versions a request line carries: uvicorn writes the version the client sent.
VERSIONS = ("1.1", "1.0")


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("method", METHODS)
def test_a_line_read_back_from_before_the_change_serves_names_only(method, version):
    old = f'[web] INFO: 172.18.0.1:40112 - "{method} {SEARCH} HTTP/{version}" 200 OK'
    out = redact_secret_urls_in_text(old)
    _assert_no_value(out)
    assert f'"{method} {NAMES} HTTP/{version}" 200 OK' in out
    from app.services import log_pull
    _assert_no_value(log_pull.redact_log_text(old, []))


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("method", METHODS)
@pytest.mark.parametrize("quote", ["'", '"'])
def test_a_line_read_back_with_a_raw_quote_in_its_target_serves_names_only(method, quote, version):
    """A browser sends a quote in a query encoded, but a client can send it raw, and a line written before the
    change holds the query as it came. Such a line is reduced as any other: the quote does not end the
    target, so the values after it are not served."""
    target = (f"/activity/events?q=it{quote}s+quarterly+report+draft&user=alice.martin%40example.com"
              f"&ip=203.0.113.9&tag={quote}secretval{quote}")
    old = f'[web] INFO: 172.18.0.1:40112 - "{method} {target} HTTP/{version}" 200 OK'
    out = redact_secret_urls_in_text(old)
    _assert_no_value(out)
    assert "secretval" not in out, out
    assert f'"{method} /activity/events?q&user&ip&tag HTTP/{version}" 200 OK' in out, out
    from app.services import log_pull
    served = log_pull.redact_log_text(old, [])
    _assert_no_value(served)
    assert "secretval" not in served, served


# A search whose query also holds a name that does not look like one and a part with no "=": the line
# written for it holds <name> and <value> beside the names.
ODD_SEARCH = SEARCH + "&al%20ice=1&quarterly+report+draft"
ODD_NAMES = NAMES + "&<name>&<value>"
# How the launcher of the single-container shape writes a line of the web server's output to the file
# log access reads: the service, the time, then the line as the server printed it.
FILE_PREFIX = "[web] 2026-10-10T06:20:07.763823Z INFO:     "


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("method", METHODS)
def test_a_line_written_with_names_only_is_read_back_as_it_was_written(method, version):
    """Every request line written since values were dropped holds names only, and log access serves it as it
    was written. Reduced a second time, each name would print as <value>."""
    written = FILE_PREFIX + _uvicorn_line(ODD_SEARCH, method, version)
    assert f'"{method} {ODD_NAMES} HTTP/{version}" 200' in written, written
    _assert_no_value(written)
    assert redact_secret_urls_in_text(written) == written
    from app.services import log_pull
    assert log_pull.redact_log_text(written, []) == written


def test_an_in_app_line_is_read_back_as_it_was_written():
    path, _, query = ODD_SEARCH.partition("?")
    written = f"[web] 2026-10-10T06:20:07.763823Z GET {access_target(path, query)} -> 200 198.51.100.20 4ms"
    assert ODD_NAMES in written, written
    assert redact_secret_urls_in_text(written) == written


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("target", [
    "/activity/events?q&user",
    "/activity/events?<value>",
    "/activity/events?<name>",
    "/activity/events?q&<name>&<value>&filter[status]&page.size&key_version&tab-x",
    "/invites/<redacted>?invite",
])
def test_a_target_with_names_only_is_read_back_unchanged(target, version):
    line = f'[web] INFO:     172.18.0.1:40112 - "GET {target} HTTP/{version}" 200 OK'
    assert redact_secret_urls_in_text(line) == line
    assert log_redaction.read_back_target(target) == target


@pytest.mark.parametrize("old, expected", [
    ("/activity/events?q&user=alice.martin", "/activity/events?<value>&user"),       # a value beside a bare part
    ("/activity/events?<value>&user=alice.martin", "/activity/events?<value>&user"),
    ("/activity/events?q&alice.martin%40example.com", "/activity/events?<value>&<value>"),   # not a name
    ("/activity/events?q&quarterly+report", "/activity/events?<value>&<value>"),
    ("/activity/events?q&&user", "/activity/events?<value>&<value>"),                # an empty part: never written
    ("/activity/events?q&" + "a" * 65, "/activity/events?<value>&<value>"),          # too long for a name
    ("/activity/events?q&user\n", "/activity/events?<value>&<value>"),               # a name never ends a line
    ("/activity/events?q&<alice.martin>", "/activity/events?<value>&<value>"),       # only the two markers pass
    ("/activity/events?q&<values>", "/activity/events?<value>&<value>"),
    ("/invites/SEKRETtoken_ABCDEF0123?q", "/invites/<redacted>?q"),                  # the path is still masked
])
def test_a_target_not_written_with_names_only_is_still_reduced(old, expected):
    assert log_redaction.read_back_target(old) == expected
    if "\n" not in old:
        line = f'[web] INFO:     172.18.0.1:40112 - "GET {old} HTTP/1.1" 200 OK'
        assert redact_secret_urls_in_text(line) == f'[web] INFO:     172.18.0.1:40112 - "GET {expected} HTTP/1.1" 200 OK'


def test_an_older_line_whose_query_held_only_bare_name_like_parts_is_served_as_written():
    """The one older line log access serves as it was written: a query of bare parts that each look like a
    name, as a line this release writes looks. Such a part may have been a value, and was served as written
    before values were dropped as well."""
    line = '[web] INFO:     172.18.0.1:40112 - "GET /activity/events?lonely&quiet HTTP/1.1" 200 OK'
    assert redact_secret_urls_in_text(line) == line


@pytest.mark.parametrize("version", VERSIONS)
def test_reading_a_line_back_twice_serves_what_reading_it_once_serves(version):
    for target in (SEARCH, ODD_SEARCH, "/a?q=1&u=2", "/a?q&u=2", "/a?al%40ice", "/a?", "/a",
                   "/public-links/SEKRETtoken_ABCDEF0123/redeem?token=x&inline"):
        line = f'[web] INFO:     172.18.0.1:40112 - "GET {target} HTTP/{version}" 200 OK'
        once = redact_secret_urls_in_text(line)
        assert redact_secret_urls_in_text(once) == once, once


@pytest.mark.parametrize("query, expected", [
    ("a=1&b=2", "a&b"),
    ("a=1&&b=", "a&b"),                                   # an empty part is skipped, an empty value is a name
    ("lonely", "<value>"),                                # no "=": may be a value sent on its own
    ("alice%40example.com", "<value>"),
    ("x=1&secret-search-text", "x&<value>"),
    ("al ice=1", "<name>"),                               # not a name
    ("%40alice=1", "<name>"),                             # an encoded name is never printed
    ("a" * 65 + "=1", "<name>"),
    ("a\n=1&x=2", "<name>&x"),                             # a line break never reaches a line in a name
    ("a\r\n=1", "<name>"),
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
