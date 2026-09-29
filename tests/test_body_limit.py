"""Every request body is bounded by its route's limit as it arrives, whether or not it declared a length.

The framework reads a JSON body whole and parses it on the event loop before any dependency runs, so
before the caller is known; a limit that only read a declared Content-Length let a chunked body in
unbounded. These drive app.core.body_limit.BodyLimitMiddleware directly with ASGI messages -- no
server, no socket -- and sweep the application's routes so every route that reads a body before it
knows the caller, and every route that streams one, is covered by an explicit rule. Whether a caller
is a live session is app.core.live_session's answer (tests/test_live_session.py); here a stand-in
gives each answer in turn.
"""
import inspect
import json
from pathlib import Path

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from app.core import body_limit as bl
from app.core import live_session as ls

pytestmark = pytest.mark.unit

KiB, MiB = bl.KiB, bl.MiB
ROOT = Path(__file__).resolve().parent.parent
LIVE, ENDED, UNKNOWN = b"Bearer live", b"Bearer ended", b"Bearer unknown"


def _caller():
    """A stand-in for live_session.caller_state that records every question: LIVE, ENDED and UNKNOWN
    above answer as named, no header is no credential."""
    asked = []

    async def caller(authorization):
        asked.append(authorization)
        return {None: ls.NO_CREDENTIAL, LIVE: ls.LIVE, UNKNOWN: ls.UNKNOWN}.get(authorization, ls.ENDED)

    caller.asked = asked
    return caller


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


LARGEST_FILE = 8 * MiB    # the largest file the stand-in deployment accepts


def _largest_file(value=LARGEST_FILE):
    """A stand-in for body_limit.largest_file_bytes that records every question."""
    asked = []

    async def largest_file():
        asked.append(value)
        return value

    largest_file.asked = asked
    return largest_file


def _drive(app, method, path, pieces, *, declared=None, chunked=False, auth=None,
           classify=bl.rule_for, caller=None, largest_file=None):
    """Send `pieces` as the request body; return (status, response body, receive calls, app). The
    response's headers are left on app.response_headers, the questions asked on app.asked (who is
    calling) and app.asked_largest (the largest file)."""
    caller = caller or _caller()
    largest_file = largest_file or _largest_file()
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

    mw = bl.BodyLimitMiddleware(app, classify=classify, caller=caller, largest_file=largest_file)
    run_coroutine(mw(_scope(method, path, headers), receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    app.response_headers = dict(start["headers"])
    app.asked = caller.asked
    app.asked_largest = largest_file.asked
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


def test_the_other_json_routes_take_one_mib_from_a_live_session_and_64_kib_from_anyone_else():
    over = _App()
    status, _, reads, _ = _drive(over, "POST", "/vaults", _pieces(2 * MiB), chunked=True, auth=LIVE)
    assert (status, over.calls) == (413, 0)
    assert reads == bl.JSON_LIMIT // (16 * KiB) + 1
    under = _App()
    status, _, _, _ = _drive(under, "POST", "/vaults", _pieces(bl.JSON_LIMIT), chunked=True, auth=LIVE)
    assert status == 200 and under.body == b"x" * bl.JSON_LIMIT
    anonymous = _App()
    status, text, reads, _ = _drive(anonymous, "POST", "/groups", _pieces(bl.JSON_LIMIT), chunked=True)
    assert (status, anonymous.calls) == (413, 0), "a caller with no session had 1 MiB parsed before its 401"
    assert "64 KiB" in json.loads(text)["detail"]
    assert reads == bl.PUBLIC_LIMIT // (16 * KiB) + 1
    status, _, reads, _ = _drive(_App(), "POST", "/groups", [b"x"], declared=bl.JSON_LIMIT)
    assert (status, reads) == (413, 0)
    ended = _App()
    status, _, reads, _ = _drive(ended, "PUT", "/users/me/preferences", _pieces(128 * KiB), chunked=True,
                                 auth=ENDED)
    assert (status, reads, ended.calls) == (401, 0, 0)


def test_the_real_application_refuses_an_anonymous_megabyte_on_a_route_that_needs_a_session():
    """The measured case: an anonymous 1 MiB JSON body to /groups was parsed (41 ms against 3 ms for a
    tiny one) before the route answered 401. Now it is refused at 64 KiB and never parsed."""
    import tracemalloc
    S = _app()
    body = ("[" + ",".join(["{}"] * (MiB // 3 - 1)) + "]").encode()
    chunks = [body[i:i + 16 * KiB] for i in range(0, len(body), 16 * KiB)]

    async def run():
        pieces = list(chunks)
        read, out = {"n": 0}, []

        async def receive():
            if pieces:
                read["n"] += 1
                return {"type": "http.request", "body": pieces.pop(0), "more_body": bool(pieces)}
            return {"type": "http.disconnect"}

        async def send(message):
            out.append(message)

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
                 "path": "/groups", "raw_path": b"/groups", "query_string": b"", "root_path": "",
                 "scheme": "http", "server": ("localhost", 80), "client": ("198.51.100.79", 1234),
                 "headers": [(b"host", b"localhost"), (b"content-type", b"application/json"),
                             (b"transfer-encoding", b"chunked")]}
        await S.app(scope, receive, send)
        return next(m["status"] for m in out if m["type"] == "http.response.start"), read["n"]

    run_coroutine(run())   # the first call builds the application's middleware
    tracemalloc.start()
    try:
        status, pieces_read = run_coroutine(run())
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert status == 413
    assert pieces_read == bl.PUBLIC_LIMIT // (16 * KiB) + 1, pieces_read
    assert peak < 1 * MiB, f"refusing it allocated {peak / KiB:.0f} KiB"


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

def test_a_larger_limit_that_needs_a_session_is_given_only_to_a_live_one():
    body = _pieces(2 * MiB)
    live = _App()
    status, _, _, _ = _drive(live, "POST", "/notes", body, chunked=True, auth=LIVE)
    assert status == 200 and live.body == b"x" * (2 * MiB)
    anonymous = _App()
    status, text, reads, _ = _drive(anonymous, "POST", "/notes", body, chunked=True)
    assert (status, anonymous.calls) == (413, 0), "a caller with no session got the note limit"
    assert "64 KiB" in json.loads(text)["detail"]
    assert reads == bl.PUBLIC_LIMIT // (16 * KiB) + 1, "read past the anonymous limit"


@pytest.mark.parametrize("declared", [True, False], ids=["declared", "chunked"])
def test_a_token_that_is_no_live_session_is_answered_401_before_its_body_is_read(declared):
    """A revoked, logged-out, locked, deactivated or expired session: the route would answer 401 once
    it had read the body, so this answers it without reading any. The web app signs out on it."""
    app = _App()
    status, text, reads, _ = _drive(app, "POST", "/vaults/v/files", _pieces(3 * MiB, 256 * KiB),
                                    declared=3 * MiB if declared else None, chunked=not declared, auth=ENDED)
    assert (status, reads, app.calls) == (401, 0, 0)
    detail = json.loads(text)["detail"]
    assert "sign in" in detail and "password" not in detail.lower(), detail   # app.js: 401 -> sign out
    assert app.response_headers[b"www-authenticate"] == b"Bearer"
    assert app.response_headers[b"clear-site-data"] == b'"cache", "cookies", "storage"'


def test_a_session_that_could_not_be_checked_is_answered_503_before_its_body_is_read():
    app = _App()
    status, _, reads, _ = _drive(app, "POST", "/notes", _pieces(2 * MiB), chunked=True, auth=UNKNOWN)
    assert (status, reads, app.calls) == (503, 0, 0)
    assert app.response_headers[b"retry-after"] == b"5"


def test_a_body_anyone_may_send_is_let_in_without_asking_who_is_calling():
    """A declared body within the anonymous limit fits every caller's limit, so no one is asked and a
    small request costs nothing; the route's own authentication still answers it."""
    for auth in (None, ENDED, UNKNOWN, LIVE):
        app = _App()
        status, _, _, _ = _drive(app, "POST", "/notes", [b"x" * bl.PUBLIC_LIMIT], declared=bl.PUBLIC_LIMIT,
                                 auth=auth)
        assert (status, app.asked) == (200, []), auth


def test_the_caller_is_asked_once_and_only_where_a_larger_limit_is_at_stake():
    big = _pieces(128 * KiB)
    for method, path in (("POST", "/notes"), ("POST", "/vaults/v/files"), ("POST", "/email/templates")):
        app = _App()
        _drive(app, method, path, big, declared=128 * KiB, auth=LIVE)
        assert app.asked == [LIVE], path
        app = _App()
        _drive(app, method, path, big, chunked=True, auth=LIVE)
        assert app.asked == [LIVE], path
    for method, path in (("POST", "/auth/login"), ("PUT", "/vaults/v/uploads/s/chunks/0"),
                         ("PUT", "/receivers/t/upload-session/s/chunks/0"), ("POST", "/device/sync-credential")):
        app = _App()
        _drive(app, method, path, big, chunked=True, auth=ENDED)
        assert app.asked == [], f"{path} asked who was calling"


def test_a_chunk_route_takes_its_limit_from_anyone_because_it_checks_the_caller_first():
    """The upload-link chunk is sent by someone with no account, and both chunk handlers check the
    caller or the link before they read a byte, so neither needs a session here."""
    pieces = _pieces(3 * MiB, size=256 * KiB)
    for path in ("/receivers/t/upload-session/s/chunks/0", "/vaults/v/uploads/s/chunks/0"):
        app = _App()
        status, _, _, _ = _drive(app, "PUT", path, pieces, chunked=True)
        assert status == 200 and app.body == b"x" * (3 * MiB), path


# A multipart upload's whole form is spooled to /tmp (a tmpfs: memory) before the route checks the
# caller's right to upload, so a signed-in session is held to the largest file the deployment accepts,
# plus the form's framing. It had no limit here at all: any session could fill the tmpfs.
MULTIPART_LIMIT = LARGEST_FILE + bl._MULTIPART_HEADROOM


def test_a_multipart_upload_from_a_live_session_is_streamed_through_up_to_the_largest_file():
    pieces = _pieces(MULTIPART_LIMIT, size=256 * KiB)
    app = _App()
    status, _, _, _ = _drive(app, "POST", "/vaults/v/files", pieces, chunked=True, auth=LIVE)
    assert status == 200 and len(app.messages) == len(pieces), "a signed-in upload was held or capped"
    assert app.asked_largest == [LARGEST_FILE]


def test_a_declared_multipart_upload_over_the_largest_file_is_refused_before_anything_is_read():
    app = _App()
    status, body, reads, _ = _drive(app, "POST", "/vaults/v/files", [b"x"], declared=MULTIPART_LIMIT + 1,
                                    auth=LIVE)
    assert (status, reads, app.calls) == (413, 0, 0)
    detail = json.loads(body)["detail"]
    assert detail == ("Request body too large. The limit for this request is 9 MiB. Send a larger file, or "
                      "several files together, with the resumable uploader (POST /vaults/{vault_id}/uploads)."), detail


def test_a_chunked_multipart_upload_over_the_largest_file_is_refused_as_soon_as_it_passes_it():
    app = _App()
    pieces = _pieces(64 * MiB, size=1 * MiB)                 # no declared length
    status, body, reads, _ = _drive(app, "POST", "/vaults/v/files", pieces, chunked=True, auth=LIVE)
    assert status == 413 and "resumable uploader" in json.loads(body)["detail"]
    assert reads == MULTIPART_LIMIT // MiB + 1, f"read {reads} pieces of a refused body"
    assert app.body == b"x" * MULTIPART_LIMIT, "handed on as it came, up to the limit"


def test_the_multipart_limit_follows_the_largest_file_the_deployment_accepts_now():
    for largest in (0, 3 * MiB, 20 * MiB):
        app = _App()
        limit = largest + bl._MULTIPART_HEADROOM
        status, _, _, _ = _drive(app, "POST", "/vaults/v/files", [b"x"], declared=limit + 1, auth=LIVE,
                                 largest_file=_largest_file(largest))
        assert status == 413, largest
        status, _, _, _ = _drive(_App(), "POST", "/vaults/v/files", _pieces(limit, 256 * KiB), chunked=True,
                                 auth=LIVE, largest_file=_largest_file(largest))
        assert status == 200, largest


# The single-request cap (MAX_SINGLE_REQUEST_UPLOAD_MB). The largest file is 10 GiB by default, more than
# the web container's memory, so it is no bound on a body spooled to /tmp (a tmpfs) before the handler
# runs: the multipart upload has a cap of its own, bounded by the largest file.

DEFAULT_LARGEST = 10240 * MiB     # MAX_FILE_SIZE_MB's default


@pytest.fixture
def cap(monkeypatch):
    from app.core.config import settings

    def set_cap(mb):
        monkeypatch.setattr(settings, "max_single_request_upload_mb", mb)
    return set_cap


def test_the_single_request_cap_holds_a_multipart_upload_below_the_largest_file(cap):
    cap(4)
    limit = 4 * MiB + bl._MULTIPART_HEADROOM
    app = _App()
    status, body, reads, _ = _drive(app, "POST", "/vaults/v/files", [b"x"], declared=limit + 1, auth=LIVE,
                                    largest_file=_largest_file(DEFAULT_LARGEST))
    assert (status, reads, app.calls) == (413, 0, 0), "a declared body over the cap was read"
    assert json.loads(body)["detail"] == (
        "Request body too large. The limit for this request is 5 MiB. Send a larger file, or several files "
        "together, with the resumable uploader (POST /vaults/{vault_id}/uploads).")
    chunked = _App()
    status, _, reads, _ = _drive(chunked, "POST", "/vaults/v/files", _pieces(64 * MiB, size=1 * MiB),
                                 chunked=True, auth=LIVE, largest_file=_largest_file(DEFAULT_LARGEST))
    assert status == 413 and reads == limit // MiB + 1, f"read {reads} pieces of a body over the cap"
    assert chunked.body == b"x" * limit, "handed on as it came, up to the cap"
    at_cap = _App()
    status, _, _, _ = _drive(at_cap, "POST", "/vaults/v/files", _pieces(limit, 256 * KiB), chunked=True,
                             auth=LIVE, largest_file=_largest_file(DEFAULT_LARGEST))
    assert status == 200, "a body at the cap was refused"


@pytest.mark.parametrize("cap_mb,largest,expected", [
    (4, 3 * MiB, 3 * MiB),               # bounded by the largest file the deployment accepts
    (4, DEFAULT_LARGEST, 4 * MiB),       # the cap below the largest file
    (0, 20 * MiB, 20 * MiB),             # turned off: the largest file alone
])
def test_the_multipart_limit_is_the_smaller_of_the_cap_and_the_largest_file(cap, cap_mb, largest, expected):
    cap(cap_mb)
    assert bl.multipart_limit(largest) == expected + bl._MULTIPART_HEADROOM
    status, _, _, _ = _drive(_App(), "POST", "/vaults/v/files", [b"x"],
                             declared=expected + bl._MULTIPART_HEADROOM + 1, auth=LIVE,
                             largest_file=_largest_file(largest))
    assert status == 413


def test_the_default_cap_is_well_below_the_containers_memory_and_matches_a_resumable_chunk():
    # The web container is given 4 GiB in the shipped compose files; one request may take a chunk's worth.
    from app.core.config import Settings
    default = Settings.model_fields["max_single_request_upload_mb"].default * MiB
    assert default == bl.CHUNK_LIMIT == 64 * MiB
    compose = (ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "mem_limit: 4g" in compose and default * 32 <= 4 * 1024 * MiB


def test_no_client_the_project_ships_sends_a_file_in_one_multipart_request():
    # So the cap breaks none of them. The web app (the desktop app carries a copy of it) sends files only
    # through the resumable uploader; its only multipart forms are a logo or favicon and an email image,
    # which have limits of their own. The upload-link page sends chunks to its own route.
    import re as _re
    for js in sorted((ROOT / "static" / "js").glob("*.js")):
        src = js.read_text(encoding="utf-8")
        for m in _re.finditer(r"new FormData\(", src):
            window = src[m.start():m.start() + 700]
            posts_to = _re.findall(r"fetch\(`\$\{API_BASE\}(/[^`]*)`", window)
            assert posts_to and posts_to[0] in ("/settings/brand/asset/${slot}", "/email/resources"), (
                f"{js.name}: a multipart form goes to {posts_to or 'somewhere unknown'}")
        assert not _re.search(r"/vaults/\$\{[^}]+\}/files`,\s*\{\s*method:\s*'POST'", src), js.name


def test_an_anonymous_multipart_upload_is_held_to_64_kib_and_the_largest_file_is_not_asked():
    pieces = _pieces(3 * MiB, size=256 * KiB)
    anon = _App()
    status, _, reads, _ = _drive(anon, "POST", "/vaults/v/files", pieces, chunked=True)
    assert (status, anon.calls) == (413, 0), "an anonymous multipart body was spooled past 64 KiB"
    assert reads == 1, "an anonymous multipart body was read past its first piece"
    assert anon.asked_largest == []
    small = _App()
    _drive(small, "POST", "/vaults/v/files", [b"x" * KiB], declared=KiB, auth=LIVE)
    assert small.asked_largest == [], "a body anyone may send asks nothing"


def test_the_largest_file_is_the_ceiling_lowered_by_the_administrators_setting(monkeypatch):
    import tempfile
    from pathlib import Path
    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker
    from app.core.config import settings
    from app.core.models import SystemSetting
    set_bare_api_env()
    import app.api.api_server as S
    monkeypatch.setattr(settings, "max_file_size_mb", 100)
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'settings.db'}")
        SystemSetting.__table__.create(engine)
        db = sessionmaker(bind=engine)()
        try:
            assert bl.largest_file_from(db) == 100 * MiB, "no setting: the ceiling"
            row = SystemSetting(key="global", value={"max_file_size": 5})
            db.add(row)
            db.commit()
            for stored, expected in ((5, 5 * MiB), (500, 100 * MiB), (0, 100 * MiB), ("junk", 100 * MiB)):
                row.value = {"max_file_size": stored}
                db.commit()
                assert bl.largest_file_from(db) == expected, stored
                # The same limit the upload route holds each file to.
                assert S._upload_policy(db)[1] == expected, stored
        finally:
            db.close()
            engine.dispose()


def test_the_largest_file_is_kept_a_few_seconds_and_the_ceiling_stands_in_when_unreadable(monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "max_file_size_mb", 100)
    monkeypatch.setattr(bl, "_largest", {"value": None, "until": 0.0})
    asked = []

    def ask():
        asked.append(1)
        return 7 * MiB

    assert run_coroutine(bl.largest_file_bytes(ask)) == 7 * MiB
    assert run_coroutine(bl.largest_file_bytes(ask)) == 7 * MiB and asked == [1], "asked again at once"
    bl._largest["until"] = 0.0                                  # its time ran out
    assert run_coroutine(bl.largest_file_bytes(ask)) == 7 * MiB and asked == [1, 1]

    monkeypatch.setattr(bl, "_largest", {"value": None, "until": 0.0})

    def broken():
        raise ConnectionError("database down")

    assert run_coroutine(bl.largest_file_bytes(broken)) == 100 * MiB, "the deployment's ceiling"
    assert bl._largest["value"] is None, "a failed read is not kept"


def test_the_largest_file_is_the_default_and_is_looked_up_when_used(monkeypatch):
    asked = []

    async def largest_file_bytes():
        asked.append(1)
        return 2 * MiB

    async def caller_state(authorization):
        return ls.LIVE

    monkeypatch.setattr(bl, "largest_file_bytes", largest_file_bytes)
    monkeypatch.setattr(ls, "caller_state", caller_state)
    sent = []
    queue = [{"type": "http.request", "body": b"x", "more_body": False}]

    async def receive():
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    headers = [(b"content-length", str(4 * MiB).encode()), (b"authorization", LIVE)]
    app = _App()
    run_coroutine(bl.BodyLimitMiddleware(app)(_scope("POST", "/vaults/v/files", headers), receive, send))
    assert asked == [1] and sent[0]["status"] == 413 and app.calls == 0


def test_the_live_session_check_is_the_default_and_is_looked_up_when_used(monkeypatch):
    asked = []

    async def caller_state(authorization):
        asked.append(authorization)
        return ls.LIVE

    monkeypatch.setattr(ls, "caller_state", caller_state)
    app = _App()
    sent = []
    queue = [{"type": "http.request", "body": b"x" * (128 * KiB), "more_body": False}]

    async def receive():
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    headers = [(b"content-length", str(128 * KiB).encode()), (b"authorization", LIVE)]
    run_coroutine(bl.BodyLimitMiddleware(app)(_scope("POST", "/notes", headers), receive, send))
    assert asked == [LIVE] and app.calls == 1


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


def test_a_limit_above_the_anonymous_one_needs_a_session_unless_the_route_checks_first():
    """The two chunk routes read their body themselves, after the caller or the link has been
    checked. Every other limit above 64 KiB, the JSON class's included, is for a signed-in caller
    only, because the framework reads those bodies before the route checks anyone."""
    rules = [(template, rule) for _m, template, rule, _why in bl.ROUTE_RULES]
    rules.append(("every other route", bl.JSON))
    for template, rule in rules:
        bigger = rule.limit is None or rule.limit > bl.PUBLIC_LIMIT
        if bigger and not rule.needs_session:
            assert rule.stream and template.endswith("/chunks/{chunk_index}"), template
    assert bl.JSON.needs_session and bl.rule_for("POST", "/groups") is bl.JSON


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


def test_saving_the_maximum_file_size_forgets_the_largest_file_kept(monkeypatch):
    """A lower or higher maximum takes effect on the next upload, not five seconds later."""
    import tempfile
    from pathlib import Path
    from types import SimpleNamespace
    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker
    from app.core.models import AuditLog, SystemSetting, User
    set_bare_api_env()
    import app.api.api_server as S
    monkeypatch.setattr(S, "_enforce_step_up", lambda *a, **k: None)
    admin = SimpleNamespace(id=None, username="admin", role=S.RoleEnum.ADMIN)
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'settings.db'}")
        for model in (SystemSetting, User, AuditLog):
            model.__table__.create(engine)
        db = sessionmaker(bind=engine)()
        try:
            for payload, forgotten in (({"session_timeout": 30}, False), ({"max_file_size": 3}, True)):
                monkeypatch.setattr(bl, "_largest", {"value": 9 * MiB, "until": float("inf")})
                run_coroutine(S.update_settings(payload=payload, request=SimpleNamespace(headers={}, client=None),
                                                current_user=admin, db=db))
                assert (bl._largest["value"] is None) is forgotten, payload
        finally:
            db.close()
            engine.dispose()
