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
