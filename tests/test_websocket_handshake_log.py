"""A WebSocket handshake's line prints its query's parameter names, never their values, offline.

uvicorn writes a WebSocket handshake to its error log (uvicorn.error), not the access log, as
'<client> - "WebSocket <path>" [accepted]' (or 403, or the status of a response), with the path and its
query. The access-log filter never saw it, so a request such as /ws/monitor?x=<value> put the value in the
server's output. The handshake line is now reduced as an access line is, when it is written and when a log
is read back. tests/test_websocket_handshake_log_live.py checks a running stack's output.
"""
import logging

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core.log_redaction import (  # noqa: E402
    WebSocketLogRedactFilter, redact_secret_urls_in_text,
)

pytestmark = pytest.mark.unit

VALUE = "handshake-value-7f3a9c"
TOKEN = "SEKRETtoken_ABCDEF0123456789-xyz"
TARGET = f"/ws/monitor?x={VALUE}&token={TOKEN}"
REDUCED = "/ws/monitor?x&token"
# The handshake lines uvicorn writes (the same three in each of its WebSocket protocols): accepted,
# refused, and answered with an HTTP response of the application's own, whose status follows.
FORMATS = (('%s - "WebSocket %s" [accepted]', ()), ('%s - "WebSocket %s" 403', ()),
           ('%s - "WebSocket %s" %d', (401,)))


def _record(fmt, target, extra=()):
    return logging.LogRecord("uvicorn.error", logging.INFO, "", 0, fmt, ("198.51.100.20:5123", target, *extra),
                             None)


@pytest.mark.parametrize("fmt, extra", FORMATS)
def test_a_handshake_line_prints_the_query_names_only(fmt, extra):
    rec = _record(fmt, TARGET, extra)
    assert WebSocketLogRedactFilter().filter(rec) is True        # never drops the line
    line = rec.getMessage()
    assert VALUE not in line and TOKEN not in line, line
    assert f'"WebSocket {REDUCED}"' in line, line


def test_a_handshake_with_no_query_is_left_as_it_is():
    rec = _record(FORMATS[0][0], "/ws/monitor")
    assert WebSocketLogRedactFilter().filter(rec) is True
    assert rec.getMessage() == '198.51.100.20:5123 - "WebSocket /ws/monitor" [accepted]'


def test_other_error_log_lines_are_left_as_they_are():
    for fmt, args in (("Uvicorn running on %s://%s:%d (Press CTRL+C to quit)", ("http", "0.0.0.0", 8000)),
                      ("Started server process [%d]", (7,)),
                      ("%s %s", ("/not/a/handshake?x=1", "/also?y=2"))):
        rec = logging.LogRecord("uvicorn.error", logging.INFO, "", 0, fmt, args, None)
        before = rec.getMessage()
        assert WebSocketLogRedactFilter().filter(rec) is True
        assert rec.getMessage() == before


def test_a_record_the_filter_cannot_read_is_passed_on():
    rec = logging.LogRecord("uvicorn.error", logging.INFO, "", 0, FORMATS[0][0], ("only one",), None)
    assert WebSocketLogRedactFilter().filter(rec) is True


def test_the_server_puts_the_filter_on_the_error_log_once():
    """What the server installs at start: a handshake logged on uvicorn.error is written with the names
    only, and installing again adds no second filter."""
    from app.api import api_server as api

    lg = logging.getLogger("uvicorn.error")
    before = list(lg.filters)
    seen = []

    class _Capture(logging.Handler):
        def emit(self, record):
            seen.append(record.getMessage())

    handler = _Capture()
    old_level, old_propagate = lg.level, lg.propagate
    lg.addHandler(handler)
    lg.setLevel(logging.INFO)
    lg.propagate = False
    try:
        api._install_access_log_redaction()
        api._install_access_log_redaction()
        assert sum(isinstance(f, WebSocketLogRedactFilter) for f in lg.filters) == 1
        lg.info(FORMATS[0][0], "198.51.100.20:5123", TARGET)
        assert seen == [f'198.51.100.20:5123 - "WebSocket {REDUCED}" [accepted]'], seen
    finally:
        lg.removeHandler(handler)
        lg.setLevel(old_level)
        lg.propagate = old_propagate
        lg.filters[:] = before


def test_a_handshake_line_read_back_serves_names_only():
    old = f'[web] INFO: 172.18.0.1:40112 - "WebSocket {TARGET}" [accepted]'
    out = redact_secret_urls_in_text(old)
    assert VALUE not in out and TOKEN not in out, out
    assert f'"WebSocket {REDUCED}" [accepted]' in out, out
    from app.services import log_pull
    served = log_pull.redact_log_text(old, [])
    assert VALUE not in served and TOKEN not in served, served


@pytest.mark.parametrize("path", ["/ws/monitor", "/ws/no-such-socket", "/ws/vaults/42/events", "/socket"])
@pytest.mark.parametrize("fmt, extra", FORMATS)
def test_a_handshake_line_to_any_path_read_back_serves_names_only(path, fmt, extra):
    """A line written before the change may record a handshake to any path, in any of the three forms: one
    to a path no socket serves is logged as refused (403), and a client chooses the path and its query."""
    old = "[web] INFO: " + fmt % ("172.18.0.1:40112", f"{path}?x={VALUE}&token={TOKEN}", *extra)
    out = redact_secret_urls_in_text(old)
    assert VALUE not in out and TOKEN not in out, out
    assert f'"WebSocket {path}?x&token"' in out, out
    from app.services import log_pull
    served = log_pull.redact_log_text(old, [])
    assert VALUE not in served and TOKEN not in served, served
