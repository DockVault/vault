"""The access log's redaction is in place from the start (app/api/api_server.py lifespan, _install_access_log_redaction).

A secret that rides a path (an upload link's token, an invitation's) or a query is written to uvicorn's access
log on every request unless the access logger carries the redaction filter. The server puts it there as it starts,
unconditionally and before it serves a request: the lifespan calls the installer before its yield. The installer
puts one filter on the access log however often it runs, and a line logged there is then written masked.
"""
import ast
import logging
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core.log_redaction import AccessLogRedactFilter  # noqa: E402

pytestmark = pytest.mark.unit

SOURCE = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
TOKEN = "Qw8Rt5Yu2Io7Pa3Sd"


def _lifespan():
    found = [n for n in ast.walk(ast.parse(SOURCE)) if isinstance(n, ast.AsyncFunctionDef) and n.name == "lifespan"]
    assert len(found) == 1
    return found[0]


def test_the_start_installs_the_filter_before_serving_and_unconditionally():
    body = _lifespan().body
    serving = next(i for i, stmt in enumerate(body) if any(isinstance(n, ast.Yield) for n in ast.walk(stmt)))
    # A statement of its own at the top of the lifespan (not under an if or a try that could skip it), before the
    # statement that hands the app over to serve requests.
    calls = [i for i, stmt in enumerate(body) if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
             and isinstance(stmt.value.func, ast.Name) and stmt.value.func.id == "_install_access_log_redaction"]
    assert len(calls) == 1 and calls[0] < serving, (calls, serving)
    # And nowhere else is it called, so the start is where it happens.
    called = [n for n in ast.walk(ast.parse(SOURCE)) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
              and n.func.id == "_install_access_log_redaction"]
    assert len(called) == 1


def test_the_installer_puts_one_filter_on_the_access_log_and_a_line_there_is_masked():
    lg = logging.getLogger("uvicorn.access")
    before, errors_before = list(lg.filters), list(logging.getLogger("uvicorn.error").filters)
    seen = []

    class _Capture(logging.Handler):
        def emit(self, record):
            seen.append(record.getMessage())

    handler = _Capture()
    old_level, old_propagate = lg.level, lg.propagate
    lg.filters[:] = [f for f in lg.filters if not isinstance(f, AccessLogRedactFilter)]
    lg.addHandler(handler)
    lg.setLevel(logging.INFO)
    lg.propagate = False
    try:
        api._install_access_log_redaction()
        api._install_access_log_redaction()
        assert sum(isinstance(f, AccessLogRedactFilter) for f in lg.filters) == 1
        lg.info('%s - "%s %s HTTP/%s" %s', "198.51.100.20:5123", "GET", f"/receivers/{TOKEN}/page", "1.1", 200)
        lg.info('%s - "%s %s HTTP/%s" %s', "198.51.100.20:5123", "GET", f"/?invite={TOKEN}", "1.1", 200)
        assert len(seen) == 2 and not any(TOKEN in line for line in seen), seen
        assert "/receivers/" in seen[0] and "/page" in seen[0]
    finally:
        lg.removeHandler(handler)
        lg.setLevel(old_level)
        lg.propagate = old_propagate
        lg.filters[:] = before
        logging.getLogger("uvicorn.error").filters[:] = errors_before
