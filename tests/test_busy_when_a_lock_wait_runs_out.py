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


def _request(path="/auth/session/extend", pattern=None):
    """A request for ``path``; ``pattern`` is the route it matched, as the framework notes it on the request."""
    scope = {"route": types.SimpleNamespace(path=pattern)} if pattern else {}
    return types.SimpleNamespace(method="POST", url=types.SimpleNamespace(path=path), scope=scope)


TOKEN = "Zm9yLWFsaWNlLW9ubHktYS1yZXNldC10b2tlbg"


@pytest.mark.parametrize("path, pattern, logged_as", [
    (f"/reset/{TOKEN}", "/reset/{token}", "POST /reset/{token}"),
    (f"/invites/{TOKEN}/accept", "/invites/{token}/accept", "POST /invites/{token}/accept"),
    # A request that matched no route (none is noted on it): the path, with the secret a path may carry masked.
    (f"/reset/{TOKEN}", None, "POST /reset/<redacted>"),
    (f"/invites/{TOKEN}/accept", None, "POST /invites/<redacted>/accept"),
    (f"/shares/{TOKEN}/claim", None, "POST /shares/<redacted>/claim"),
    # A path with nothing secret in it is named as it is.
    ("/auth/session/extend", None, "POST /auth/session/extend"),
])
def test_the_busy_line_never_holds_a_token_that_rides_the_path(capsys, path, pattern, logged_as):
    """A person submits a reset link while a change holds the account's turn for longer than the request waits.
    The answer is "busy, try again", and the token is not spent. The line the server prints for it named the
    request by its path: the token, whole and still good, in the container's log, for whoever reads logs to set
    the person's password with. The same for an invitation. The line names the route by its pattern."""
    S = _api()
    answer = run_coroutine(S._lock_wait_ran_out_handler(_request(path, pattern), _the_databases_error("55P03")),
                           timeout=30)
    assert answer.status_code == 503
    logged = capsys.readouterr().out
    assert TOKEN not in logged, logged
    assert f"({logged_as})" in logged and logged.count("\n") == 1


def test_the_routes_whose_path_is_a_secret_have_a_pattern_that_names_no_value():
    """The real routes: what the framework notes on a request for a reset link or an invitation is the pattern,
    with the parameter's name where the token was."""
    S = _api()
    patterns = {route.path for route in S.app.routes if hasattr(route, "path")}
    secret = [p for p in patterns if p.startswith(("/reset/", "/invites/"))]
    assert secret and all("{" in p.split("/")[2] for p in secret), sorted(secret)
    for pattern in secret:
        assert S._route_for_a_log(_request("/reset/" + TOKEN, pattern)) == pattern


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


def test_a_route_that_spent_a_one_time_code_answers_a_lock_wait_in_its_own_words():
    """The exchange of a sign-in code, the provider's answer coming back, the claim of a finished link or test:
    each has spent what carried the request by the time it works. The application's answer for a lock wait says
    "try again" with a wait; the try after the wait was told the code is not valid. Such a route gives its own
    answer: rolled back first, the answer returned or raised as the route would give it, and the database's
    error (which carries the statement) not shown with it. Anything else passes as it is."""
    set_bare_api_env()
    from fastapi import HTTPException
    from app.services import sign_in
    rolled = []

    class DB:
        def rollback(self):
            rolled.append("rolled back")

    def route_that(raises=None, returns="done"):
        @sign_in.after_a_spent_code_busy_is(lambda: made[0])
        async def route(body, db=None):
            """Its own words."""
            if raises is not None:
                raise raises
            return returns
        return route
    made = [sign_in.start_again()]
    waited = _the_databases_error("55P03")
    # Raised by the answer: the route's own refusal, with no wait to count down.
    with pytest.raises(HTTPException) as busy:
        run_coroutine(route_that(waited)("body", db=DB()), timeout=30)
    assert (busy.value.status_code, busy.value.detail) == (503, sign_in.BUSY_START_AGAIN)
    assert busy.value.headers is None and rolled == ["rolled back"] and busy.value.__suppress_context__ is True
    # Returned by the answer: a navigation gets a page to go to.
    made[0] = "a redirect"
    assert run_coroutine(route_that(waited)("body", db=DB()), timeout=30) == "a redirect" and len(rolled) == 2
    # No session among its arguments: answered all the same.
    assert run_coroutine(route_that(waited)("body"), timeout=30) == "a redirect" and len(rolled) == 2
    # Another error of the database, a refusal of the route's own, and an answer: each as it was.
    for other in (_the_databases_error("40P01"), _the_databases_error(None)):
        with pytest.raises(OperationalError) as raised:
            run_coroutine(route_that(other)("body", db=DB()), timeout=30)
        assert raised.value is other
    refusal = HTTPException(status_code=401, detail="This sign-in code is not valid; start again.")
    with pytest.raises(HTTPException) as raised:
        run_coroutine(route_that(refusal)("body", db=DB()), timeout=30)
    assert raised.value is refusal
    assert run_coroutine(route_that()("body", db=DB()), timeout=30) == "done" and len(rolled) == 2
    # The route is still read as itself (the framework reads its parameters from it).
    wrapped = route_that()
    assert wrapped.__name__ == "route" and wrapped.__doc__ == "Its own words." and hasattr(wrapped, "__wrapped__")


def test_every_route_that_spends_a_one_time_code_gives_its_own_busy_answer():
    """The five routes, and what each answers: the exchange of a sign-in code "start the sign-in again", the claim
    of a finished link, test or confirmation "start it again" in the shape those routes refuse in, and the
    browser's return from the provider the sign-in page with the reason. None gives a wait to count down."""
    import inspect
    S = _api()
    from fastapi import HTTPException
    from app.api import sso_router
    from app.services import sign_in
    for route in (S.finish_sign_in, sso_router.sign_in_callback, sso_router.finish_link, sso_router.finish_test,
                  sso_router.finish_reauth):
        assert hasattr(route, "__wrapped__"), route.__name__
        parameters = inspect.signature(route).parameters
        assert "db" in parameters, route.__name__                    # rolled back by name before the answer
    source = inspect.getsource(sso_router)
    assert source.count("@_sign_in.after_a_spent_code_busy_is(_start_the_step_again)\nasync def finish_") == 3
    assert "@_sign_in.after_a_spent_code_busy_is(_back_to_the_sign_in_page_as_busy)\nasync def sign_in_callback(" in source
    assert "@sign_in.after_a_spent_code_busy_is(sign_in.start_again)\nasync def finish_sign_in(" in inspect.getsource(S)
    step = sso_router._start_the_step_again()
    assert isinstance(step, HTTPException) and step.status_code == 503 and step.headers is None
    assert step.detail == {"reason": "busy", "message": "The vault is busy with this right now. Start it again in a moment."}
    back = sso_router._back_to_the_sign_in_page_as_busy()
    assert back.status_code in (302, 303, 307) and back.headers["location"].endswith("/#sso-error=busy")
    again = sign_in.start_again()
    assert (again.status_code, again.detail, again.headers) == (503, sign_in.BUSY_START_AGAIN, None)
