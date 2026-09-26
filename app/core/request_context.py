"""What the current request is, for audit rows written without a request in hand: the channel it came
in on, its method, its route and its user agent.

The web process sets one RequestContext per HTTP request (RequestContextMiddleware in api_server). The
SFTP server runs as its own process and sets the process default channel to "sftp" at start, so every
row it writes, its sign-ins included, carries that channel. Rows written outside any request (a
background cleanup, say) have no channel.
"""
import contextvars
from typing import Optional

from app.core.log_redaction import redact_log_path

# The channels an audit row can carry.
CHANNELS = ("web", "sftp", "public_link", "upload_link", "device_sync")

# Anonymous link routes by channel: (path prefix, text that must follow the token, or None). They
# mirror the secret routes the access log masks (app.core.log_redaction.SECRET_PATH_ROUTES).
_LINK_ROUTES = (
    ("public_link", "/l/", None),
    ("public_link", "/note-links/", "/redeem"),
    ("public_link", "/p/", None),
    ("public_link", "/public-links/", "/redeem"),
    ("public_link", "/public-links/", "/download/"),
    ("upload_link", "/u/", None),
    ("upload_link", "/receivers/", "/upload-session"),
)

MAX_USER_AGENT = 512    # audit_logs.user_agent
MAX_ENDPOINT = 255      # audit_logs.endpoint


def channel_for_path(path: str) -> str:
    """The channel a request path arrives on. Anything that is not an anonymous link route or a
    device's own API is the web app (its pages and its JSON API alike)."""
    for channel, prefix, follow in _LINK_ROUTES:
        if path.startswith(prefix):
            if follow is None:
                return channel
            rest = path[len(prefix):]
            if "/" in rest and rest[rest.index("/"):].startswith(follow):
                return channel
    if path == "/devices" or path.startswith("/devices/"):
        return "device_sync"
    return "web"


class RequestContext:
    __slots__ = ("method", "path", "user_agent", "channel", "_scope")

    def __init__(self, method: str, path: str, user_agent: Optional[str], channel: str, scope=None):
        self.method = (method or "")[:10] or None
        self.path = path
        self.user_agent = (user_agent or "")[:MAX_USER_AGENT] or None
        self.channel = channel
        self._scope = scope

    @property
    def endpoint(self) -> Optional[str]:
        """The route template (`/vaults/{vault_id}/files`) once routing has matched one, else the path
        with any link token masked. Never the raw path: that can hold a token."""
        route = self._scope.get("route") if isinstance(self._scope, dict) else None
        template = getattr(route, "path", None)
        text = template or redact_log_path(self.path or "")
        return text[:MAX_ENDPOINT] or None


_CTX: contextvars.ContextVar = contextvars.ContextVar("dv_request_context", default=None)
_process_default_channel: Optional[str] = None


def set_process_default_channel(channel: Optional[str]) -> None:
    """For a process whose every audit row has one channel (the SFTP server)."""
    global _process_default_channel
    _process_default_channel = channel if channel in CHANNELS else None


def set_request_context(ctx: Optional[RequestContext]):
    return _CTX.set(ctx)


def reset_request_context(token) -> None:
    try:
        _CTX.reset(token)
    except Exception:  # noqa: BLE001 - resetting a stale token must never surface
        pass


def current_request_context() -> Optional[RequestContext]:
    try:
        return _CTX.get()
    except Exception:  # noqa: BLE001
        return None


def current_channel() -> Optional[str]:
    ctx = current_request_context()
    return ctx.channel if ctx else _process_default_channel
