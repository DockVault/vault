"""What the web server's log says of a failure or a sign-out, offline (app/api/api_server.py, app/core/safe_log.py).

The log can be pulled through Log access and is read by whoever runs the containers, so it says what happened and
where, never the text of an error (a database error's carries the statement's values; a path; a value a request
sent) and never a part of a session's token:

- a 500 is logged with an error id, its class and place, and those of the error that led to it, never its detail;
  the answer carries the same id;
- the 500 paths that wrapped the error's text into their detail, or printed it, now raise with the error as the
  cause and print nothing of their own (the routes of vaults, their permissions, files and folders, and the two of
  the encryption keys too);
- a failed upload or download tells the live monitor the error's class, never its text;
- a failed pass of the audit chain's sealer is logged with an error id, its class and place;
- a sign-out logs the prefix of the token's hash, as it is stored, never of the token.

test_managed_settings_routes.py checks a failed managed-setting change or cancel; test_reset_ends_sessions_with_the_
password.py a failed password reset; test_email_send.py and test_settings_test_email_tls.py a failed send of mail.
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


class _Raising:
    """Whatever a route asks of it fails with SECRET in the error's text: the failure inside the route's try."""

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        raise _Failed(SECRET)


class _FailingDb(_Raising):
    """A session whose queries fail; ending its transaction does not."""

    def rollback(self):
        pass

    def commit(self):
        pass

    def close(self):
        pass


class _Quiet:
    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return lambda *a, **k: None


ROUTE_500S = [
    ("api", "delete_vault"), ("api", "update_vault_info"), ("api", "change_vault_password"),
    ("api", "update_vault_settings"), ("api", "list_vault_permissions"), ("api", "grant_vault_permission"),
    ("api", "revoke_vault_permission"), ("api", "list_vault_files"), ("api", "upload_file"), ("api", "delete_file"),
    ("api", "rename_file"), ("api", "create_folder"), ("ecc", "decompress_point"), ("ecc", "register_public_key"),
]


@pytest.fixture
def broken_world(monkeypatch):
    """The services a route uses fail with SECRET in the error's text; what it tells the live monitor is kept."""
    from app.api import ecc_router
    told = []
    monkeypatch.setattr(api, "VaultService", lambda *a, **k: _Raising())
    monkeypatch.setattr(api, "PermissionService", lambda *a, **k: _Raising())
    monkeypatch.setattr(api, "AuditLogger", lambda *a, **k: _Quiet())
    monkeypatch.setattr(api, "broadcast_event", lambda event, *a, **k: told.append(event))
    monkeypatch.setattr(ecc_router, "_ecc_rate_limit", lambda *a, **k: None)
    return told


def _route_call(where, name):
    """The route ``name`` past its decorators, called with a failing session and services, an administrator, and a
    stand-in that fails for every other argument (a request body)."""
    import inspect
    import uuid
    from app.api import ecc_router
    from app.core.models import RoleEnum
    module = api if where == "api" else ecc_router
    fn = inspect.unwrap(getattr(module, name))
    user = SimpleNamespace(id=uuid.uuid4(), username="ada", role=RoleEnum.ADMIN, is_active=True)
    request = SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.7"), state=SimpleNamespace(),
                              url=SimpleNamespace(path="/"), method="POST", query_params={})
    kwargs = {}
    for param in inspect.signature(fn).parameters.values():
        if param.name == "db":
            kwargs["db"] = _FailingDb()
        elif param.name == "current_user":
            kwargs["current_user"] = user
        elif param.name == "request" and where == "api":
            kwargs["request"] = request
        elif param.name.endswith("_id") and param.name != "folder_id":
            kwargs[param.name] = uuid.uuid4()
        elif param.name.startswith("x_") or param.name in ("vault_password", "folder_id", "file_password"):
            kwargs[param.name] = None
        elif param.annotation is dict:
            kwargs[param.name] = {}           # a JSON body read before the route's try
        else:
            kwargs[param.name] = _Raising()
    return lambda: run_coroutine(fn(**kwargs))


@pytest.mark.parametrize("where, name", ROUTE_500S, ids=[name for _w, name in ROUTE_500S])
def test_a_route_that_fails_answers_its_own_text_and_never_the_errors(broken_world, capsys, where, name):
    """The 500 detail is fixed text, the error its cause: the 500 handler answers with an error id and logs the
    error's class and place (test_a_500_logs_an_error_id_...), never its message."""
    call = _route_call(where, name)
    capsys.readouterr()
    with pytest.raises(HTTPException) as caught:
        call()
    assert caught.value.status_code == 500, (name, caught.value.detail)
    assert SECRET not in str(caught.value.detail), name
    assert isinstance(caught.value.__cause__, _Failed), name
    assert SECRET not in _logged(capsys), name
    assert all(SECRET not in json.dumps(event, default=str) for event in broken_world), name


@pytest.mark.parametrize("name, said", [("upload_file", "Upload error (_Failed)"),
                                        ("download_file", "Download error (_Failed)")])
def test_a_failed_upload_or_download_tells_the_live_monitor_the_errors_class_only(broken_world, name, said):
    with pytest.raises(HTTPException):
        _route_call("api", name)()
    events = [e["event"] for e in broken_world if e.get("event", {}).get("type") == "error"]
    assert [e["description"] for e in events] == [said]


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


def test_a_failed_pass_of_the_audit_chains_sealer_logs_an_id_and_where_never_the_text(monkeypatch, capsys):
    from app.core import audit_integrity as ai

    class Failing:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            raise _Failed(f"SELECT ... parameters: ('{SECRET}',)")

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(ai, "ChainWriter", Failing)
    monkeypatch.setattr(ai, "every_pass_checks", lambda *a, **k: {})
    capsys.readouterr()
    result = ai.seal_pass(lambda: None, engine=object(), st=ai.ChainState())
    logged = _logged(capsys)
    assert result.stopped == "error"
    assert re.search(r"\[ERROR\] the audit chain's sealer failed; the next pass tries again \(ID: [0-9a-f-]{36}\): "
                     r"_Failed", logged), logged
    assert "test_error_logs_keep_no_text.py" in logged, "where it was raised"
    assert SECRET not in logged
