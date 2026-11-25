"""A statement that waited for a lock longer than a request waits is answered as busy (503 with the wait), not as
an error of the server: app/api/api_server.py, _lock_wait_ran_out_handler.

Every connection waits a bounded time for a lock, and a path may set a shorter wait for itself. Where the path
catches the database's refusal it answers for itself (a sign-in that found its account's turn held). Where
nothing caught it ("Stay signed in", an administrator's change of an account's sign-in details, while a change
that settles many accounts held the turn) the answer was the 500 of an unknown failure, which no client tries
again. Offline: the handler by itself, where it is registered, and one request through the application.
"""
import json
import types

import pytest
from sqlalchemy.exc import OperationalError

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit


def _api():
    set_bare_api_env()
    import app.api.api_server as S
    return S


def _the_databases_error(pgcode):
    return OperationalError("SELECT pg_advisory_xact_lock(%(cls)s, hashtext(%(account)s))",
                            {"cls": 1, "account": "a-name-that-must-not-be-shown"},
                            types.SimpleNamespace(pgcode=pgcode))


def _request(path="/auth/session/extend"):
    return types.SimpleNamespace(method="POST", url=types.SimpleNamespace(path=path))


def test_a_lock_wait_that_ran_out_is_answered_as_busy_with_the_wait(capsys):
    S = _api()
    from app.core import sign_in_lockout
    answer = run_coroutine(S._lock_wait_ran_out_handler(_request(), _the_databases_error("55P03")), timeout=30)
    assert answer.status_code == 503
    assert json.loads(answer.body) == {"detail": "The vault is busy with this right now. Try again in a moment."}
    assert answer.headers["retry-after"] == str(sign_in_lockout.BUSY_RETRY_SECONDS) == "5"
    # The log names the route and nothing of the statement or its values.
    logged = capsys.readouterr().out
    assert "POST /auth/session/extend" in logged and "busy" in logged
    assert "a-name-that-must-not-be-shown" not in logged and "pg_advisory_xact_lock" not in logged


@pytest.mark.parametrize("pgcode", ["08006", "40P01", "57014", None, ""])
def test_any_other_error_of_the_database_is_the_error_it_was(pgcode, capsys):
    """Only the wait for a lock is busy. A lost connection, a deadlock, a cancelled statement, an error with no
    code: raised again, the same object, for the answer every unknown failure gets."""
    S = _api()
    error = _the_databases_error(pgcode)
    with pytest.raises(OperationalError) as raised:
        run_coroutine(S._lock_wait_ran_out_handler(_request(), error), timeout=30)
    assert raised.value is error and capsys.readouterr().out == ""
    # An error that carries no database error at all (made by the driver's pool, say).
    bare = OperationalError("SELECT 1", {}, None)
    with pytest.raises(OperationalError) as raised:
        run_coroutine(S._lock_wait_ran_out_handler(_request(), bare), timeout=30)
    assert raised.value is bare


def test_the_application_gives_the_databases_refusal_to_that_handler():
    S = _api()
    assert S.app.exception_handlers[OperationalError] is S._lock_wait_ran_out_handler
    assert S.LOCK_WAIT_RAN_OUT == "55P03"


def _post(S, path):
    out = {}

    async def _drive():
        scope = {"type": "http", "http_version": "1.1", "method": "POST", "path": path, "raw_path": path.encode(),
                 "query_string": b"", "headers": [(b"content-type", b"application/json"),
                                                   (b"authorization", b"Bearer not-a-token")],
                 "client": ("127.0.0.1", 1234), "server": ("testserver", 80), "scheme": "http"}
        chunks = []

        async def receive():
            return {"type": "http.request", "body": b"{}", "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.start":
                out["status"] = msg["status"]
                out["headers"] = {k.decode().lower(): v.decode() for k, v in msg["headers"]}
            elif msg["type"] == "http.response.body":
                chunks.append(msg.get("body", b""))

        await S.app(scope, receive, send)
        out["body"] = json.loads(b"".join(chunks) or b"null")

    run_coroutine(_drive(), timeout=60)
    return out["status"], out["headers"], out["body"]


@pytest.mark.parametrize("pgcode, status", [("55P03", 503), ("08006", 500)])
def test_stay_signed_in_while_the_accounts_turn_is_held_is_busy_and_not_an_error(monkeypatch, pgcode, status):
    """Through the application: the renewal waits for the account's turn at its sessions, the wait runs out, and
    nothing in the route catches it. The answer is 503 with the wait and the hardening headers of every answer;
    another failure of the database is still the 500 that shows nothing."""
    S = _api()
    from app.services import sign_in
    user = types.SimpleNamespace(id="u1", username="alice")
    monkeypatch.setitem(S.app.dependency_overrides, S.get_current_user, lambda: user)
    monkeypatch.setitem(S.app.dependency_overrides, S.get_db, lambda: object())

    def the_turn_is_held(db, current_user, payload, *, client_ip):
        raise _the_databases_error(pgcode)
    monkeypatch.setattr(sign_in, "renew", the_turn_is_held)
    got, headers, body = _post(S, "/auth/session/extend")
    assert got == status, body
    assert headers.get("x-content-type-options") == "nosniff"
    assert "a-name-that-must-not-be-shown" not in json.dumps(body) and "pg_advisory" not in json.dumps(body)
    if status == 503:
        assert body == {"detail": "The vault is busy with this right now. Try again in a moment."}
        assert headers["retry-after"] == "5"
    else:
        assert "retry-after" not in headers and "error_id" in body
