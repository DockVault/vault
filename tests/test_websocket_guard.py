"""A WebSocket costs little before anyone knows who opened it.

/ws/monitor accepts anyone and parses the first message to learn who is calling. With uvicorn's
defaults (16 MiB messages, per-message compression on) about 16 KB on the wire became a 16 MiB message
parsed on the event loop: a second of event loop and 400 MiB for one message, and the HTTP rate
limiter never saw the socket. These drive app.core.websocket_guard directly with ASGI messages, then
the real application's socket route, and pin that the server is started with the small limits.
tests/test_websocket_guard_live.py checks the deployed stack.
"""
import ast
import json
import re
import time
import tracemalloc
from pathlib import Path

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from app.core import websocket_guard as wg

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
KiB = 1024


# --------------------------------------------------------------------------- an ASGI harness

class _Socket:
    """An application that accepts, then reads messages until the client goes away, answering each."""

    def __init__(self):
        self.calls = 0
        self.read = []
        self.sent_after_close = 0

    async def __call__(self, scope, receive, send):
        self.calls += 1
        assert (await receive())["type"] == "websocket.connect"
        await send({"type": "websocket.accept"})
        while True:
            message = await receive()
            self.read.append(message)
            if message["type"] == "websocket.disconnect":
                await send({"type": "websocket.close", "code": 1000})   # the finally of a real handler
                return
            await send({"type": "websocket.send", "text": "ok"})


def _drive(app, messages, *, allow=True, limit=wg.WS_MESSAGE_LIMIT, client=("198.51.100.7", 4000)):
    """Run the guard over `app` with the client sending `messages`; return what the server was sent."""
    queue = [{"type": "websocket.connect"}] + [
        {"type": "websocket.receive", **({"bytes": m} if isinstance(m, bytes) else {"text": m})}
        for m in messages] + [{"type": "websocket.disconnect", "code": 1000}]
    sent, sources = [], []

    async def receive():
        return queue.pop(0)

    async def send(message):
        sent.append(message)

    def allow_connect(source):
        sources.append(source)
        if isinstance(allow, Exception):
            raise allow
        return allow

    scope = {"type": "websocket", "path": "/ws/monitor", "headers": [], "client": client}
    mw = wg.WebSocketGuardMiddleware(app, allow_connect=allow_connect,
                                     source=lambda s: s["client"][0], message_limit=limit)
    run_coroutine(mw(scope, receive, send))
    return sent, sources


def _auth(size):
    """A sign-in message of exactly `size` bytes."""
    head = '{"type":"auth","token":"'
    return head + "t" * (size - len(head) - 2) + '"}'


# --------------------------------------------------------------------------- messages

def test_a_first_message_over_the_limit_is_closed_with_1009_and_never_reaches_the_application():
    app = _Socket()
    sent, _ = _drive(app, [_auth(wg.WS_MESSAGE_LIMIT + 1)])
    closes = [m for m in sent if m["type"] == "websocket.close"]
    assert closes and closes[0]["code"] == wg.CLOSE_TOO_BIG
    assert [m["type"] for m in app.read] == ["websocket.disconnect"], "the application read the message"
    assert not [m for m in sent if m["type"] == "websocket.send"], "the application answered it"
    assert len(closes) == 1, "the application's own close after the guard's went out"


def test_a_message_at_the_limit_is_read_and_the_socket_stays_open():
    app = _Socket()
    message = _auth(wg.WS_MESSAGE_LIMIT)
    sent, _ = _drive(app, [message, json.dumps({"type": "ping"})])
    assert [m.get("text") for m in app.read[:2]] == [message, '{"type": "ping"}']
    assert [m["type"] for m in sent].count("websocket.send") == 2
    assert [m["code"] for m in sent if m["type"] == "websocket.close"] == [1000]


def test_after_the_guard_closes_the_application_reads_nothing_more_from_the_client():
    read = []

    async def keeps_reading(scope, receive, send):
        await receive()
        await send({"type": "websocket.accept"})
        for _ in range(3):
            read.append(await receive())

    sent, _ = _drive(keeps_reading, ["x" * (wg.WS_MESSAGE_LIMIT + 1), '{"type":"ping"}', '{"type":"ping"}'])
    assert [m["type"] for m in read] == ["websocket.disconnect"] * 3, read
    assert [m.get("code") for m in sent if m["type"] == "websocket.close"] == [wg.CLOSE_TOO_BIG]


def test_a_later_message_over_the_limit_is_closed_too():
    app = _Socket()
    sent, _ = _drive(app, ['{"type":"ping"}', "x" * (wg.WS_MESSAGE_LIMIT + 1)])
    assert [m.get("text") for m in app.read] == ['{"type":"ping"}', None]
    assert [m["code"] for m in sent if m["type"] == "websocket.close"] == [wg.CLOSE_TOO_BIG]


@pytest.mark.parametrize("message,over", [
    ("é" * (2 * KiB), False),           # 2048 two-byte characters: exactly 4 KiB
    ("é" * (2 * KiB) + "x", True),      # one byte more
    ("\U0001F600" * KiB, False),             # 1024 four-byte characters: exactly 4 KiB
    ("\U0001F600" * KiB + "x", True),
    ("x" * (4 * KiB), False),
    ("x" * (4 * KiB + 1), True),
    (b"x" * (4 * KiB), False),
    (b"x" * (4 * KiB + 1), True),
])
def test_the_limit_counts_bytes_not_characters(message, over):
    key = "bytes" if isinstance(message, bytes) else "text"
    assert wg.over_limit({"type": "websocket.receive", key: message}, 4 * KiB) is over
    app = _Socket()
    sent, _ = _drive(app, [message], limit=4 * KiB)
    assert (wg.CLOSE_TOO_BIG in [m.get("code") for m in sent]) is over


# --------------------------------------------------------------------------- connects

def test_a_connect_over_the_address_limit_is_closed_before_it_is_accepted():
    app = _Socket()
    sent, sources = _drive(app, [_auth(100)], allow=False)
    assert sent == [{"type": "websocket.close", "code": wg.CLOSE_POLICY}]
    assert app.calls == 0, "the application ran for a refused connect"
    assert sources == ["198.51.100.7"]


def test_a_connect_within_the_limit_reaches_the_application_and_is_counted_once():
    app = _Socket()
    sent, sources = _drive(app, [_auth(100)])
    assert app.calls == 1 and sent[0]["type"] == "websocket.accept"
    assert sources == ["198.51.100.7"]


def test_the_connect_limit_fails_open_when_it_cannot_be_checked():
    app = _Socket()
    sent, _ = _drive(app, [_auth(100)], allow=RuntimeError("redis down"))
    assert app.calls == 1 and sent[0]["type"] == "websocket.accept"


def test_http_and_lifespan_pass_through_untouched():
    seen = []

    async def app(scope, receive, send):
        seen.append((scope["type"], receive, send))

    marker_receive, marker_send = object(), object()
    mw = wg.WebSocketGuardMiddleware(app, allow_connect=lambda s: pytest.fail("counted a non-socket"))
    for kind in ("http", "lifespan"):
        run_coroutine(mw({"type": kind, "path": "/", "headers": []}, marker_receive, marker_send))
    assert seen == [("http", marker_receive, marker_send), ("lifespan", marker_receive, marker_send)]


def test_connect_allowed_counts_per_address_in_its_own_bucket_and_fails_open(monkeypatch):
    set_bare_api_env()
    from app.core import rate_limiter as rl
    from app.core.config import settings
    calls = []

    def check(identifier, limit, window, prefix="rate_limit", fail_open=True):
        calls.append((identifier, limit, window, prefix, fail_open))
        return (len(calls) <= 2), 0, 0

    monkeypatch.setattr(rl.rate_limiter, "check_rate_limit", check)
    monkeypatch.setattr(settings, "rate_limit_ws_connect", 2, raising=False)
    monkeypatch.setattr(settings, "rate_limit_ws_connect_window", 30, raising=False)
    assert [wg.connect_allowed("203.0.113.9") for _ in range(3)] == [True, True, False]
    assert calls[0] == ("ip:203.0.113.9", 2, 30, "rate_limit:ws_connect", True)
    monkeypatch.setattr(settings, "rate_limit_ws_connect", 0, raising=False)
    calls.clear()
    assert wg.connect_allowed("203.0.113.9") and not calls, "a limit of 0 still counted"


def test_the_shipped_default_leaves_room_for_many_tabs_behind_one_address():
    set_bare_api_env()
    from app.core.config import Settings
    fields = Settings.model_fields
    # A tab reconnects no faster than every 5 s (static/js/app.js scheduleAppSocketReconnect): 12 a minute.
    assert fields["rate_limit_ws_connect"].default >= 10 * 12
    assert fields["rate_limit_ws_connect_window"].default == 60
    app_js = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    reconnect = app_js.split("function scheduleAppSocketReconnect()", 1)[1].split("\n}", 1)[0]
    assert "}, 5000);" in reconnect


@pytest.mark.parametrize("client,source", [
    ("198.51.100.7", "198.51.100.7"),
    ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"),
    ("2001:db8:1:2:ffff::1", "2001:db8:1:2::/64"),
    ("::ffff:198.51.100.7", "198.51.100.7"),
])
def test_a_connect_is_counted_under_the_client_address_with_ipv6_by_its_64(client, source):
    set_bare_api_env()
    scope = {"type": "websocket", "path": "/ws/monitor", "headers": [], "client": (client, 1)}
    assert wg.connect_source(scope) == source


def test_a_forwarded_address_counts_only_behind_a_trusted_proxy():
    set_bare_api_env()
    from app.core import net_utils
    scope = {"type": "websocket", "path": "/ws/monitor", "client": ("10.0.0.2", 1),
             "headers": [(b"x-forwarded-for", b"203.0.113.50")]}
    before = net_utils.settings.trusted_proxies
    try:
        for trusted, source in (("", "10.0.0.2"), ("10.0.0.0/8", "203.0.113.50")):
            net_utils.settings.trusted_proxies = trusted
            net_utils._trusted_networks.cache_clear()
            assert wg.connect_source(scope) == source, trusted
    finally:
        net_utils.settings.trusted_proxies = before
        net_utils._trusted_networks.cache_clear()


# --------------------------------------------------------------------------- the real application

def _server():
    set_bare_api_env()
    import app.api.api_server as S
    return S


def _run_socket(S, messages):
    """Drive the real application's /ws/monitor; return (seconds, [(type, code)] sent, peak bytes)."""
    queue = [{"type": "websocket.connect"}] + [{"type": "websocket.receive", "text": m} for m in messages]
    out = []

    async def run():
        import asyncio
        done = asyncio.Event()

        async def receive():
            if queue:
                return queue.pop(0)
            await asyncio.wait_for(done.wait(), 10)
            return {"type": "websocket.disconnect", "code": 1000}

        async def send(message):
            out.append((message["type"], message.get("code")))
            if message["type"] == "websocket.close":
                done.set()

        scope = {"type": "websocket", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "path": "/ws/monitor", "raw_path": b"/ws/monitor", "query_string": b"", "root_path": "",
                 "scheme": "ws", "server": ("localhost", 80), "client": ("198.51.100.77", 1234),
                 "headers": [(b"host", b"localhost")], "subprotocols": []}
        await S.app(scope, receive, send)

    tracemalloc.start()
    started = time.perf_counter()
    try:
        run_coroutine(run())
        seconds = time.perf_counter() - started
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return seconds, out, peak


def test_the_real_socket_route_refuses_a_large_first_message_without_parsing_it(monkeypatch):
    S = _server()
    monkeypatch.setattr(wg, "connect_allowed", lambda source: True)
    _run_socket(S, [json.dumps({"type": "auth", "token": "x"})])   # the first call builds the app
    # 1 MiB of empty objects, the costliest shape to parse: about 20 MiB to parse, nothing to refuse.
    pad = "[" + ",".join(["{}"] * (1024 * KiB // 3)) + "]"
    message = '{"type":"auth","token":"x","pad":' + pad + "}"
    seconds, out, peak = _run_socket(S, [message])
    assert ("websocket.close", wg.CLOSE_TOO_BIG) in out, out
    assert peak < 1024 * KiB, f"refusing the message allocated {peak / KiB:.0f} KiB"
    assert seconds < 2, f"refusing the message took {seconds:.1f} s"


def test_the_real_socket_route_still_reads_a_sign_in_message(monkeypatch):
    """A well-formed sign-in of an ordinary size gets through the guard to the handler, which answers
    it (here with its own refusal of a token it cannot verify)."""
    S = _server()
    monkeypatch.setattr(wg, "connect_allowed", lambda source: True)
    seconds, out, _ = _run_socket(S, [json.dumps({"type": "auth", "token": "not-a-token"})])
    assert ("websocket.accept", None) in out
    assert ("websocket.send", None) in out, "the handler never answered the sign-in message"
    assert ("websocket.close", 1008) in out and ("websocket.close", wg.CLOSE_TOO_BIG) not in out


def test_the_real_socket_route_refuses_a_connect_over_the_address_limit(monkeypatch):
    S = _server()
    monkeypatch.setattr(wg, "connect_allowed", lambda source: False)
    _, out, _ = _run_socket(S, [json.dumps({"type": "auth", "token": "x"})])
    assert out == [("websocket.close", wg.CLOSE_POLICY)]


def test_the_guard_is_installed_on_the_application():
    S = _server()
    classes = [m.cls for m in S.app.user_middleware]
    assert classes.count(wg.WebSocketGuardMiddleware) == 1


# --------------------------------------------------------------------------- the server's own limits

def test_the_server_options_are_small_messages_without_compression():
    options = wg.server_options()
    assert options == {"ws_max_size": wg.WS_MAX_SIZE, "ws_per_message_deflate": False}
    assert wg.WS_MESSAGE_LIMIT <= wg.WS_MAX_SIZE <= 64 * KiB


def test_the_largest_sign_in_message_the_page_sends_fits_twice_over():
    """The page's one message is {"type": "auth", "token": ...} (static/js/app.js connectAppSocket).
    The largest token carries the longest username a sign-in accepts and every claim a sign-in adds."""
    set_bare_api_env()
    import secrets
    import uuid
    from app.core.security import create_access_token
    token = create_access_token({"sub": str(uuid.uuid4()), "username": "u" * 254,
                                 "session_token": secrets.token_urlsafe(32), "is_temporary": True,
                                 "amr": ["pwd", "recovery"], "mfa_at": 4_102_444_800})
    message = json.dumps({"type": "auth", "token": token})
    assert 2 * len(message.encode()) <= wg.WS_MESSAGE_LIMIT <= 8 * KiB, len(message)
    app_js = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    assert app_js.count("ws.send(") == 1 and "ws.send(JSON.stringify({ type: 'auth', token: authToken }))" in app_js


def test_the_server_is_started_with_them():
    """The one place the web app's server starts (run_combined.py and every compose file run
    `python -m app.api.api_server`) passes the options to uvicorn.run."""
    tree = ast.parse((ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8"))
    runs = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and ast.unparse(node.func) == "uvicorn.run"]
    assert len(runs) == 1, "expected exactly one uvicorn.run"
    spread = [ast.unparse(k.value) for k in runs[0].keywords if k.arg is None]
    assert "websocket_guard.server_options()" in spread, spread
    named = {k.arg for k in runs[0].keywords if k.arg}
    assert not named & {"ws_max_size", "ws_per_message_deflate"}, "set in two places"
    # Nothing starts the server another way, which would miss the options.
    starts_uvicorn = re.compile(r'uvicorn\.run\(|-m",?\s*"?uvicorn|\buvicorn\s+app[.:]|\["uvicorn"')
    entries = [ROOT / name for name in ("run_combined.py", "Dockerfile", "docker-entrypoint.py",
                                         "deploy/docker-compose.yml", "deploy/docker-compose.secure.yml")]
    entries += [p for p in (ROOT / "app").rglob("*.py") if p.name != "api_server.py"]
    for path in entries:
        assert not starts_uvicorn.search(path.read_text(encoding="utf-8")), path
    assert '_spawn("app.api.api_server", "web")' in (ROOT / "run_combined.py").read_text(encoding="utf-8")
