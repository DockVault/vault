"""Every request body is bounded by its route's limit as it arrives, whether or not it declared a length.

The framework reads a JSON body whole and parses it on the event loop before any dependency runs, so
before the caller is known; a limit that only read a declared Content-Length let a chunked body in
unbounded. These drive app.core.body_limit.BodyLimitMiddleware directly with ASGI messages -- no
server, no socket -- and sweep the application's routes so every route that reads a body before it
knows the caller, and every route that streams one, is covered by an explicit rule.
"""
import inspect
import json

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from app.core import body_limit as bl

pytestmark = pytest.mark.unit

KiB, MiB = bl.KiB, bl.MiB


# --------------------------------------------------------------------------- an ASGI harness

class _App:
    """Records what the middleware handed on: how often it was called and every message it read."""

    def __init__(self, read=True, answer=200, swallow=False, start_first=False):
        self.calls = 0
        self.messages = []
        self.read, self.answer, self.swallow, self.start_first = read, answer, swallow, start_first

    @property
    def body(self):
        return b"".join(m.get("body", b"") for m in self.messages if m["type"] == "http.request")

    async def __call__(self, scope, receive, send):
        self.calls += 1
        if self.start_first:
            await send({"type": "http.response.start", "status": 200, "headers": []})
        if self.read:
            try:
                while True:
                    m = await receive()
                    self.messages.append(m)
                    if m["type"] != "http.request" or not m.get("more_body"):
                        break
            except Exception:
                if not self.swallow:
                    raise
        if not self.start_first:
            await send({"type": "http.response.start", "status": self.answer, "headers": []})
        await send({"type": "http.response.body", "body": b"handled"})


def _scope(method, path, headers=()):
    return {"type": "http", "method": method, "path": path, "headers": list(headers)}


def _drive(app, method, path, pieces, *, declared=None, chunked=False, auth=None,
           classify=bl.rule_for, has_session=lambda _h: False):
    """Send `pieces` as the request body; return (status, response body, receive calls, app)."""
    headers = []
    if declared is not None:
        headers.append((b"content-length", str(declared).encode()))
    if chunked:
        headers.append((b"transfer-encoding", b"chunked"))
    if auth is not None:
        headers.append((b"authorization", auth))
    queue = [{"type": "http.request", "body": p, "more_body": i < len(pieces) - 1}
             for i, p in enumerate(pieces)] or [{"type": "http.request", "body": b"", "more_body": False}]
    state = {"reads": 0}
    sent = []

    async def receive():
        state["reads"] += 1
        if queue:
            return queue.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    mw = bl.BodyLimitMiddleware(app, classify=classify, has_session=has_session)
    run_coroutine(mw(_scope(method, path, headers), receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return start["status"], body, state["reads"], app


def _pieces(total, size=16 * KiB):
    """`total` bytes as pieces of at most `size`, reusing one buffer so a large body costs nothing."""
    block = b"x" * size
    out, left = [], total
    while left > 0:
        out.append(block if left >= size else block[:left])
        left -= size
    return out


# --------------------------------------------------------------------------- the four cases

def test_a_declared_body_over_the_limit_is_refused_before_anything_is_read():
    app = _App()
    status, body, reads, _ = _drive(app, "POST", "/auth/login", [b"x"], declared=bl.PUBLIC_LIMIT + 1)
    assert status == 413
    assert "64 KiB" in json.loads(body)["detail"]
    assert reads == 0, "the body was read although its declared length already refused it"
    assert app.calls == 0, "the application ran for a refused body"


def test_a_chunked_body_over_the_limit_is_refused_as_soon_as_it_passes_it():
    app = _App()
    pieces = _pieces(20 * MiB)             # 1280 pieces of 16 KiB, no declared length
    status, _, reads, _ = _drive(app, "POST", "/auth/login", pieces, chunked=True)
    assert status == 413
    assert app.calls == 0, "the application ran for a refused body"
    # 64 KiB is four pieces; the fifth passes the limit. Nothing after it is read.
    assert reads == bl.PUBLIC_LIMIT // (16 * KiB) + 1, f"read {reads} pieces of a refused body"


def test_the_other_json_routes_are_refused_past_one_mib_and_not_before():
    over = _App()
    status, _, reads, _ = _drive(over, "POST", "/vaults", _pieces(2 * MiB), chunked=True)
    assert (status, over.calls) == (413, 0)
    assert reads == bl.JSON_LIMIT // (16 * KiB) + 1
    under = _App()
    status, _, _, _ = _drive(under, "POST", "/vaults", _pieces(bl.JSON_LIMIT), chunked=True)
    assert status == 200 and under.body == b"x" * bl.JSON_LIMIT


@pytest.mark.parametrize("declared", [True, False], ids=["declared", "chunked"])
def test_a_body_exactly_at_the_limit_reaches_the_application_whole(declared):
    app = _App()
    pieces = _pieces(bl.PUBLIC_LIMIT, size=10_000)   # uneven pieces: the count lands exactly on it
    status, _, _, _ = _drive(app, "POST", "/auth/login", pieces,
                             declared=bl.PUBLIC_LIMIT if declared else None, chunked=not declared)
    assert status == 200
    assert app.calls == 1 and app.body == b"x" * bl.PUBLIC_LIMIT
    # A JSON route's body is handed on in one message, so the handler never acts on half of it.
    assert [m["more_body"] for m in app.messages] == [False]
    over = _App()
    status, _, _, _ = _drive(over, "POST", "/auth/login", pieces + [b"x"],
                             declared=bl.PUBLIC_LIMIT + 1 if declared else None, chunked=not declared)
    assert (status, over.calls) == (413, 0)


def test_a_streaming_upload_route_is_streamed_through_not_held_and_not_capped_at_the_json_limit():
    app = _App()
    pieces = _pieces(3 * MiB, size=256 * KiB)
    path = "/vaults/v/uploads/s/chunks/0"
    status, _, _, _ = _drive(app, "PUT", path, pieces, chunked=True)
    assert status == 200 and app.body == b"x" * (3 * MiB)
    # Handed on piece by piece as it arrived: the chunk goes to disk as it streams, never held here.
    assert len(app.messages) == len(pieces)
    link = _App()
    status, _, _, _ = _drive(link, "PUT", "/receivers/t/upload-session/s/chunks/0", pieces, chunked=True)
    assert status == 200 and len(link.messages) == len(pieces)


def test_a_streaming_upload_route_is_still_refused_past_its_own_limit():
    app = _App()
    pieces = _pieces(bl.CHUNK_LIMIT + 1, size=1 * MiB)
    status, body, reads, _ = _drive(app, "PUT", "/vaults/v/uploads/s/chunks/0", pieces, chunked=True)
    assert status == 413 and "64 MiB" in json.loads(body)["detail"]
    assert reads == 65, "reading went on past the limit"
    status, _, reads, _ = _drive(_App(), "PUT", "/vaults/v/uploads/s/chunks/0", [b"x"],
                                 declared=bl.CHUNK_LIMIT + 1)
    assert (status, reads) == (413, 0)


def test_a_handler_that_swallows_the_refusal_still_answers_413():
    # The upload-complete handler reads its optional body under `except Exception`. A refused body
    # must not turn into that handler's success.
    app = _App(swallow=True)
    classify = lambda m, p: bl.BodyRule("t", 1 * KiB, stream=True)   # noqa: E731
    status, body, _, _ = _drive(app, "POST", "/x", _pieces(8 * KiB, 1 * KiB), chunked=True,
                                classify=classify)
    assert app.calls == 1 and status == 413 and body != b"handled"


def test_a_response_already_started_before_the_limit_is_left_to_finish():
    app = _App(start_first=True, swallow=True)
    classify = lambda m, p: bl.BodyRule("t", 1 * KiB, stream=True)   # noqa: E731
    status, body, _, _ = _drive(app, "POST", "/x", _pieces(8 * KiB, 1 * KiB), chunked=True,
                                classify=classify)
    assert (status, body) == (200, b"handled")


# --------------------------------------------------------------------------- sessions and no body

def test_a_larger_limit_that_needs_a_session_is_given_only_with_one():
    body = _pieces(2 * MiB)
    without = _App()
    status, _, _, _ = _drive(without, "POST", "/notes", body, chunked=True)
    assert (status, without.calls) == (413, 0), "a caller with no session got the note limit"
    status, _, _, _ = _drive(_App(), "POST", "/notes", body, chunked=True, auth=b"Bearer forged",
                             has_session=lambda h: False)
    assert status == 413
    with_session = _App()
    status, _, _, _ = _drive(with_session, "POST", "/notes", body, chunked=True, auth=b"Bearer ok",
                             has_session=lambda h: h == b"Bearer ok")
    assert status == 200 and with_session.body == b"x" * (2 * MiB)


def test_a_multipart_upload_has_no_cap_here_for_a_session_and_the_json_one_without():
    pieces = _pieces(3 * MiB, size=256 * KiB)
    app = _App()
    status, _, _, _ = _drive(app, "POST", "/vaults/v/files", pieces, chunked=True, auth=b"Bearer ok",
                             has_session=lambda h: True)
    assert status == 200 and len(app.messages) == len(pieces), "a signed-in upload was held or capped"
    anon = _App()
    status, _, _, _ = _drive(anon, "POST", "/vaults/v/files", pieces, chunked=True)
    assert (status, anon.calls) == (413, 0), "an anonymous multipart body was spooled past 1 MiB"


def test_a_request_without_a_body_goes_straight_through_unread():
    app = _App(read=False)
    status, _, reads, _ = _drive(app, "GET", "/vaults", [])
    assert (status, reads, app.calls) == (200, 0, 1)
    status, _, reads, _ = _drive(_App(read=False), "POST", "/auth/login", [], declared=0)
    assert (status, reads) == (200, 0)


def test_an_unreadable_content_length_is_refused():
    status, _, reads, _ = _drive(_App(), "POST", "/auth/login", [b"{}"], declared="12x")
    assert (status, reads) == (400, 0)


def test_websockets_and_lifespan_pass_through():
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    mw = bl.BodyLimitMiddleware(app)
    for kind in ("websocket", "lifespan"):
        run_coroutine(mw({"type": kind, "path": "/ws/monitor", "headers": []}, None, None))
    assert seen == ["websocket", "lifespan"]


def test_the_session_check_accepts_only_a_signed_unexpired_session_token():
    _app()   # installs the runtime settings the token helpers read
    from datetime import timedelta
    from app.core.security import create_access_token
    ok = create_access_token({"sub": "u1", "session_token": "s"})
    assert bl.bearer_has_session(b"Bearer " + ok.encode())
    assert bl.bearer_has_session(b"bearer  " + ok.encode() + b" ")
    pending = create_access_token({"sub": "u1", "stage": "second_factor", "pre_auth": "p"})
    assert not bl.bearer_has_session(b"Bearer " + pending.encode()), "a second-factor token is no session"
    no_session = create_access_token({"sub": "u1"})
    assert not bl.bearer_has_session(b"Bearer " + no_session.encode())
    expired = create_access_token({"sub": "u1", "session_token": "s"}, expires_delta=timedelta(minutes=-5))
    assert not bl.bearer_has_session(b"Bearer " + expired.encode())
    head, payload, sig = ok.split(".")
    assert not bl.bearer_has_session(f"Bearer {head}.{payload}.{sig[::-1]}".encode())
    for bad in (None, b"", b"Bearer", b"Basic " + ok.encode(), b"\xff\xfe"):
        assert not bl.bearer_has_session(bad)


# --------------------------------------------------------------------------- the classifier

@pytest.mark.parametrize("method,path,name", [
    ("POST", "/auth/login", "public"),
    ("POST", "/auth/login/", "public"),
    ("POST", "/auth/signup", "public"),
    ("POST", "/auth/second-factor/verify", "public"),
    ("POST", "/invites/abc/accept", "public"),
    ("POST", "/reset/abc", "public"),
    ("POST", "/note-links/abc/redeem", "public"),
    ("POST", "/public-links/abc/redeem", "public"),
    ("POST", "/receivers/abc/upload-session", "public"),
    ("POST", "/receivers/abc/upload-session/s/complete", "public"),
    ("POST", "/device/sync-credential", "public"),
    ("PUT", "/vaults/v/uploads/s/chunks/3", "upload_chunk"),
    ("PUT", "/receivers/t/upload-session/s/chunks/3", "link_upload_chunk"),
    ("POST", "/vaults/v/files", "multipart_upload"),
    ("PATCH", "/notes/n", "note"),
    ("POST", "/vaults/v/zk/seal-names", "seal_names"),
    ("POST", "/note-links/abc/revoke", "json"),
    ("GET", "/auth/login", "json"),
    ("POST", "/vaults/v/uploads/s/chunks/3", "json"),
    ("POST", "/auth/login/extra", "json"),
    ("POST", "/vaults", "json"),
])
def test_each_route_meets_its_rule(method, path, name):
    assert bl.rule_for(method, path).name == name


# --------------------------------------------------------------------------- the route sweep

def _app():
    set_bare_api_env()
    import app.api.api_server as S
    return S


def _routes(app):
    """Every HTTP route with its full path, the included routers' routes too (the framework keeps
    those behind an included-router object rather than in app.routes)."""
    from fastapi.routing import APIRoute, _IncludedRouter

    def walk(routes, prefix):
        for r in routes:
            if isinstance(r, _IncludedRouter):
                yield from walk(r.original_router.routes, prefix + r.include_context.prefix)
            elif isinstance(r, APIRoute):
                yield prefix + r.path, r

    return list(walk(app.router.routes, ""))


_AUTHENTICATES = {"get_current_user", "require_admin", "require_interactive_admin"}


def _dependency_names(route):
    names, stack = set(), [route.dependant]
    while stack:
        d = stack.pop()
        for sub in d.dependencies:
            if sub.call is not None:
                names.add(getattr(sub.call, "__name__", ""))
            stack.append(sub)
    return names


def _source(route):
    return inspect.getsource(inspect.unwrap(route.endpoint))


def _reads_a_stream(route):
    src = _source(route)
    return "request.stream()" in src or "UploadFile" in src


def test_the_sweep_sees_the_included_routers():
    paths = {p for p, _ in _routes(_app().app)}
    assert "/email/resources" in paths and "/ecc/vaults/{vault_id}/rekey" in paths and "/auth/login" in paths


def test_every_rule_names_a_route_that_exists_with_that_method():
    have = {(m, p) for p, r in _routes(_app().app) for m in r.methods}
    for methods, template, _rule, why in bl.ROUTE_RULES:
        assert why, f"{template} has no reason recorded"
        for m in methods:
            assert (m, template) in have, f"a body rule names {m} {template}, which is no route"


def test_every_route_that_takes_a_body_without_a_session_is_public_or_explicit():
    """A route with a body and no session dependency is one anyone can call (or one whose credential,
    a device secret or a pending sign-in, is checked after the body is read): it must be in the
    64 KiB class, or carry an explicit rule saying why not."""
    missing = []
    for path, route in _routes(_app().app):
        if _dependency_names(route) & _AUTHENTICATES:
            continue
        if route.body_field is None and not _reads_a_stream(route):
            continue
        for m in route.methods - {"HEAD", "OPTIONS"}:
            rule = bl.rule_for(m, path)
            if rule is bl.JSON:
                missing.append(f"{m} {path}")
    assert not missing, f"a body without a session, but only JSON-limited: {missing}"


def test_every_route_that_streams_or_takes_a_form_has_an_explicit_rule():
    missing = []
    for path, route in _routes(_app().app):
        if not _reads_a_stream(route):
            continue
        for m in route.methods - {"HEAD", "OPTIONS"}:
            rule = bl.rule_for(m, path)
            if not rule.stream:
                missing.append(f"{m} {path} -> {rule.name}")
    assert not missing, f"stream or form routes without a streaming rule: {missing}"


def test_a_limit_above_the_json_one_needs_a_session_unless_the_route_checks_first():
    """The two chunk routes read their body themselves, after the caller or the link has been
    checked. Every other limit above the JSON one is for a signed-in caller only, because the
    framework reads those bodies before the route checks anyone."""
    for methods, template, rule, _why in bl.ROUTE_RULES:
        bigger = rule.limit is None or rule.limit > bl.JSON_LIMIT
        if bigger and not rule.needs_session:
            assert rule.stream and template.endswith("/chunks/{chunk_index}"), template


def test_the_limits_cover_what_the_handlers_accept():
    S = _app()
    from app.api import email_studio_router as E
    assert bl.CHUNK_LIMIT == S._MAX_UPLOAD_CHUNK_BYTES
    assert bl.rule_for("POST", "/settings/brand/asset/logo").limit > S.BRAND_ASSET_MAX_BYTES
    assert bl.rule_for("POST", "/email/resources").limit > E._MAX_RESOURCE_BYTES
    # Six bytes per character is the worst JSON escaping; the title and keys fit in the rest.
    assert bl.LARGE_TEXT_LIMIT > 6 * S._NOTE_BODY_MAX_CEILING + 6 * S._NOTE_TITLE_MAX + 1024
    assert bl.LARGE_TEXT_LIMIT > 6 * E._MAX_BODY + 6 * 1024
    seal = S.ZkSealRequest.model_fields["items"].metadata
    assert any(getattr(m, "max_length", None) == 1000 for m in seal), "seal-names batch size changed"


def test_the_middleware_is_installed_innermost_and_the_old_declared_only_cap_is_gone():
    S = _app()
    assert S.app.user_middleware[-1].cls is bl.BodyLimitMiddleware, (
        "the body limit must be the innermost middleware, so every outer layer wraps its 413")
    assert not hasattr(S, "_MAX_REQUEST_BODY_BYTES")
