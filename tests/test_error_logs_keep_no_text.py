"""What the web server's log says of a failure or a sign-out, offline (app/api/api_server.py, app/core/safe_log.py).

The log can be pulled through Log access and is read by whoever runs the containers, so it says what happened and
where, never the text of an error (a database error's carries the statement's values; a path; a value a request
sent) and never a part of a session's token:

- a 500 is logged with an error id, its class and place, and those of the error that led to it, never its detail;
  the answer carries the same id;
- the 500 paths that wrapped the error's text into their detail, or printed it, now raise with the error as the
  cause and print nothing of their own;
- a sign-out logs the prefix of the token's hash, as it is stored, never of the token.

test_managed_settings_routes.py checks a failed managed-setting change or cancel; test_reset_ends_sessions_with_the_
password.py a failed password reset.
"""
import json
import re
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.responses import Response

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402

pytestmark = pytest.mark.unit

SECRET = "carol@example.com /app/storage/payroll-2026.xlsx"


class _Failed(Exception):
    pass


def _logged(capsys) -> str:
    out = capsys.readouterr()
    return out.out + out.err


def _ids(text: str) -> list:
    return re.findall(r"Sanitized HTTP 500 \(ID: ([0-9a-f-]{36})\)", text)


def test_a_500_logs_an_error_id_and_where_it_came_from_never_its_detail(capsys):
    try:
        try:
            raise _Failed(f"INSERT ... parameters: ('{SECRET}',)")
        except _Failed as e:
            raise HTTPException(status_code=500, detail=f"Failed: {e}") from e
    except HTTPException as exc:
        caught = exc
    capsys.readouterr()
    resp = run_coroutine(api._http_exception_handler(SimpleNamespace(), caught))
    body = json.loads(resp.body)
    logged = _logged(capsys)
    assert resp.status_code == 500 and _ids(logged) == [body["error_id"]]
    assert "HTTPException" in logged and "_Failed" in logged, "the classes, of the 500 and of what led to it"
    assert "test_error_logs_keep_no_text.py" in logged, "and where they were raised"
    assert SECRET not in logged and SECRET not in resp.body.decode()


@pytest.mark.parametrize("route, call", [
    ("security metrics", lambda: api.get_security_metrics(hours=24, current_user=None, db=None)),
    ("security alerts", lambda: api.get_security_alerts(limit=5, severity=None, current_user=None, db=None)),
    ("resolving an alert", lambda: api.resolve_security_alert(alert_id="a-1", notes=None,
                                                              current_user=SimpleNamespace(username="ada"),
                                                              db=None)),
    ("a user's activity", lambda: api.get_user_security_activity(user_id="7f1c2f4e-58a4-4a0f-9a8b-2c5f0e1d9b31",
                                                                 hours=24, current_user=None, db=None)),
])
def test_a_500_path_raises_with_its_cause_and_prints_nothing_of_it(monkeypatch, capsys, route, call):
    from app.services import security_monitor

    def failing(_db):
        raise _Failed(SECRET)
    monkeypatch.setattr(security_monitor, "get_security_monitor", failing)
    capsys.readouterr()
    with pytest.raises(HTTPException) as caught:
        run_coroutine(call())
    assert caught.value.status_code == 500 and SECRET not in str(caught.value.detail), route
    assert isinstance(caught.value.__cause__, _Failed), "the error is its cause, for the 500 handler's log"
    assert _logged(capsys) == "", "the 500 handler logs it, once"
    run_coroutine(api._http_exception_handler(SimpleNamespace(), caught.value))
    logged = _logged(capsys)
    assert len(_ids(logged)) == 1 and "_Failed" in logged and SECRET not in logged


class _Query:
    def __init__(self, row):
        self.row = row

    def filter(self, *_a, **_k):
        return self

    def first(self):
        return self.row

    def update(self, values, **_k):
        """The sign-out ends its row with one UPDATE of that row (by its id, while it is not yet revoked):
        written onto the one row there is, which it reports as the one row it changed."""
        if self.row is None:
            return 0
        for column, value in values.items():
            setattr(self.row, column.key, value)
        return 1


class _Db:
    def __init__(self, row):
        self.row = row

    def query(self, *_a, **_k):
        return _Query(self.row)

    def commit(self):
        pass

    def flush(self):
        pass


@pytest.mark.parametrize("found", [True, False])
def test_a_sign_out_logs_the_prefix_of_the_tokens_hash_never_of_the_token(monkeypatch, capsys, found):
    from app.services import auth_service
    token = "sess-" + "Zq7" * 20
    monkeypatch.setattr(api, "verify_access_token", lambda raw: {"session_token": token, "exp": 9_999_999_999})
    monkeypatch.setattr(auth_service, "denylist_token", lambda value, ttl: None)
    monkeypatch.setattr(api, "AuditLogger", lambda db: SimpleNamespace(log_logout=lambda user, ip: None))
    monkeypatch.setattr(api, "broadcast_event", lambda event: None)
    row = SimpleNamespace(id=7, is_active=True, revoked=False, temp_credential_id=None) if found else None
    request = SimpleNamespace(headers={"Authorization": "Bearer signed"}, client=SimpleNamespace(host="192.0.2.7"))
    capsys.readouterr()
    run_coroutine(api.logout(request=request, response=Response(), current_user=SimpleNamespace(username="ada"),
                             db=_Db(row)))
    logged = _logged(capsys)
    assert api.hash_session_token(token)[:8] in logged
    assert token[:8] not in logged, "no part of the token itself"
    assert (row.revoked is True and row.is_active is False) if found else ("not found" in logged)
