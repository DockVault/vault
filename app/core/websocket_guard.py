"""What a WebSocket may cost before anyone knows who opened it.

The app's socket (/ws/monitor) is opened by anyone and learns who is calling from its first message,
which it then parses. Three bounds keep that cheap, for every WebSocket route:

- The server's limits (server_options, passed to uvicorn.run): a message is at most WS_MAX_SIZE bytes
  and per-message compression is off. uvicorn's defaults are 16 MiB and on, so about 16 KB of
  compressed bytes on the wire became a 16 MiB message that was parsed on the event loop before the
  caller was checked (about a second of event loop and 400 MiB, for one message).
- WebSocketGuardMiddleware closes the socket with 1009 (message too big) on any message over
  WS_MESSAGE_LIMIT, before the application reads it. The page sends one message, its sign-in
  {"type": "auth", "token": ...} with a token well under 1 KiB, and the server answers a ping; nothing
  a client legitimately sends comes near the limit.
- It also limits how often one address may open a socket: RATE_LIMIT_WS_CONNECT per
  RATE_LIMIT_WS_CONNECT_WINDOW seconds, an IPv6 address counted as its /64 (0 turns it off). The HTTP
  rate limiter never sees a WebSocket. A refused connect is closed before it is accepted, which the
  client sees as an HTTP 403. The page reconnects no faster than every 5 seconds, so one tab stays
  far below the default.

Kept free of the application's imports at module level (the rate limiter and the client address are
imported only when first needed) so it is unit-testable offline.
"""
from typing import Callable, Optional

KiB = 1024

# The largest message the server accepts on any WebSocket. The application's own limit below is
# smaller; this is the backstop the server applies before a message reaches the application at all.
WS_MAX_SIZE = 16 * KiB
# The largest message the application reads: the page's sign-in message is under 1 KiB.
WS_MESSAGE_LIMIT = 4 * KiB

CLOSE_POLICY = 1008      # policy violation: a connect refused before it is accepted
CLOSE_TOO_BIG = 1009     # message too big

CONNECT_PREFIX = "rate_limit:ws_connect"


def server_options() -> dict:
    """uvicorn's WebSocket settings: small messages and no per-message compression."""
    return {"ws_max_size": WS_MAX_SIZE, "ws_per_message_deflate": False}


def over_limit(message: dict, limit: int) -> bool:
    """Whether a websocket.receive message carries more than `limit` bytes, measured without
    copying a message that is plainly too long or plainly short enough."""
    text = message.get("text")
    if text is not None:
        if len(text) > limit:
            return True            # every character is at least one byte
        if 4 * len(text) <= limit:
            return False           # and at most four
        return len(text.encode("utf-8", "surrogatepass")) > limit
    return len(message.get("bytes") or b"") > limit


def connect_source(scope) -> str:
    """The address a connect is counted under: the client address the HTTP side would record
    (trusted-proxy aware), with an IPv6 address grouped to its /64."""
    from starlette.requests import HTTPConnection
    from app.core.net_utils import client_ip
    from app.core.sign_in_lockout import source_of
    return source_of(client_ip(HTTPConnection(scope)))


def connect_allowed(source: str) -> bool:
    """Count one connect from `source`; False when it is over RATE_LIMIT_WS_CONNECT in the window.
    Fails open on a Redis error, like the general API limiter: a Redis outage must not end every
    live page's socket."""
    from app.core.config import settings
    limit = int(getattr(settings, "rate_limit_ws_connect", 120) or 0)
    if limit <= 0:
        return True
    window = max(1, int(getattr(settings, "rate_limit_ws_connect_window", 60) or 60))
    from app.core.rate_limiter import rate_limiter
    allowed, _remaining, _reset = rate_limiter.check_rate_limit(
        f"ip:{source}", limit, window, prefix=CONNECT_PREFIX, fail_open=True)
    return bool(allowed)


class WebSocketGuardMiddleware:
    """Pure ASGI: limit WebSocket connects per address and the size of every message the application
    reads (see the module docstring). HTTP and lifespan pass through untouched."""

    def __init__(self, app, allow_connect: Optional[Callable[[str], bool]] = None,
                 source: Callable = connect_source, message_limit: int = WS_MESSAGE_LIMIT):
        self.app = app
        self.allow_connect = allow_connect   # None: connect_allowed, looked up when used
        self.source = source
        self.message_limit = message_limit

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "websocket":
            await self.app(scope, receive, send)
            return
        if not await self._admitted(scope):
            message = await receive()
            if message.get("type") == "websocket.connect":
                await send({"type": "websocket.close", "code": CLOSE_POLICY})
            return

        closed = False
        limit = self.message_limit

        async def guarded_receive():
            nonlocal closed
            if closed:
                return {"type": "websocket.disconnect", "code": CLOSE_TOO_BIG}
            message = await receive()
            if message.get("type") == "websocket.receive" and over_limit(message, limit):
                closed = True
                await send({"type": "websocket.close", "code": CLOSE_TOO_BIG, "reason": "Message too big"})
                return {"type": "websocket.disconnect", "code": CLOSE_TOO_BIG}
            return message

        async def guarded_send(message):
            if closed:
                return   # this layer closed the socket; whatever the application says goes nowhere
            await send(message)

        await self.app(scope, guarded_receive, guarded_send)

    async def _admitted(self, scope) -> bool:
        from starlette.concurrency import run_in_threadpool
        try:
            source = self.source(scope)
            return bool(await run_in_threadpool(self.allow_connect or connect_allowed, source))
        except Exception:  # noqa: BLE001 -- fail open, as connect_allowed does on a Redis error
            return True
