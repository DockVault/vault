"""A failed audit or notification write is logged by its exception class alone, offline.

The database's error text for a failed insert carries the statement's bound values: the username, the
address, the user agent, and details such as an old and a new email address. The process log can be
pulled through Log access, so none of that may reach it when a best-effort write fails."""
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402

pytestmark = pytest.mark.unit

SECRET = "carol-new@example.com"


class _InsertFailed(Exception):
    pass


class _FailingLogger:
    def __init__(self, db):
        pass

    def log_action(self, **_kwargs):
        raise _InsertFailed(f"INSERT INTO audit_logs ... parameters: ('{SECRET}', '203.0.113.9')")


class _Db:
    def rollback(self):
        pass


@pytest.mark.parametrize("helper", ["_audit_change", "_audit_access_change"])
def test_a_failed_audit_write_logs_the_class_and_not_the_values(monkeypatch, capsys, helper):
    monkeypatch.setattr(api, "AuditLogger", _FailingLogger)
    getattr(api, helper)(_Db(), SimpleNamespace(id="a-1", username="alice"), "user_updated", "user", "u-1",
                         {"new_email": SECRET})
    out = capsys.readouterr()
    logged = out.out + out.err
    assert "_InsertFailed" in logged
    assert SECRET not in logged and "203.0.113.9" not in logged


def test_a_failed_notification_write_logs_the_class_and_not_the_values(monkeypatch, capsys):
    import contextlib
    from app.core import database

    @contextlib.contextmanager
    def failing_context():
        raise _InsertFailed(f"INSERT INTO notifications ... parameters: ('{SECRET}',)")
        yield  # pragma: no cover

    monkeypatch.setattr(database, "get_db_context", failing_context)
    api._notify_users(["u-1"], "account_changed", "Your email address was changed", body=SECRET)
    out = capsys.readouterr()
    logged = out.out + out.err
    assert "_InsertFailed" in logged and SECRET not in logged


def test_a_failed_security_event_write_logs_the_class_and_not_the_values(monkeypatch, capsys):
    # The failed sign-in's security event carries the name typed at sign-in and the address.
    from app.services import security_monitor

    def failing_monitor(_db):
        raise _InsertFailed(f"INSERT INTO security_events ... parameters: ('{SECRET}', '203.0.113.9')")

    monkeypatch.setattr(security_monitor, "get_security_monitor", failing_monitor)
    api._record_failed_login_bg(SECRET, "203.0.113.9", "Invalid username or password")
    out = capsys.readouterr()
    logged = out.out + out.err
    assert "_InsertFailed" in logged
    assert SECRET not in logged and "203.0.113.9" not in logged


def test_an_unhandled_error_is_logged_by_its_class_and_place_not_its_message(capsys):
    # The global handler printed the error and its traceback, whose last line repeats the message: for
    # a database error, the statement and its values.
    from starlette.requests import Request
    from _async_run import run_coroutine

    def raise_it():
        try:
            raise KeyError("the cause")
        except KeyError as cause:
            raise _InsertFailed(f"INSERT INTO users ... parameters: ('{SECRET}',)") from cause

    async def call_next(_request):
        raise_it()

    request = Request({"type": "http", "method": "GET", "path": "/boom", "raw_path": b"/boom",
                       "query_string": b"", "headers": [], "scheme": "http", "server": ("testserver", 80),
                       "client": ("203.0.113.9", 1234), "root_path": "", "http_version": "1.1"})
    response = run_coroutine(api.SecurityHeadersMiddleware(app=None).dispatch(request, call_next))
    assert response.status_code == 500
    out = capsys.readouterr()
    logged = out.out + out.err
    assert "_InsertFailed" in logged and "KeyError" in logged, logged
    assert "raise_it" in logged, "where it was raised is kept"
    assert SECRET not in logged and "the cause" not in logged, logged


def test_the_outline_of_an_error_keeps_the_frames_and_drops_the_messages():
    from app.core.safe_log import exception_outline

    def inner():
        raise ValueError(SECRET)

    try:
        try:
            inner()
        except ValueError:
            raise RuntimeError("second " + SECRET)
    except RuntimeError as exc:
        text = exception_outline(exc)
    assert SECRET not in text
    assert text.index("builtins.ValueError") < text.index("builtins.RuntimeError"), text
    assert "in inner" in text and "led to" in text


def test_the_database_engine_hides_statement_values():
    # A database error's text, and the DEBUG echo, would otherwise carry the statement's bound values.
    import ast
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / "app" / "core" / "database.py").read_text(encoding="utf-8")
    calls = [n for n in ast.walk(ast.parse(source))
             if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "create_engine"]
    assert len(calls) == 1, "one engine, made in one place"
    hidden = [k for k in calls[0].keywords if k.arg == "hide_parameters"]
    assert len(hidden) == 1 and isinstance(hidden[0].value, ast.Constant) and hidden[0].value.value is True
