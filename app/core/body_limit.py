"""How large a request body may be, decided per route before the application reads a byte of it.

The framework reads a JSON body whole and parses it on the event loop, and it reads a multipart form
whole (spooling each file to /tmp) -- both BEFORE any dependency runs, so before the caller is known.
A limit that only looks at a declared Content-Length misses a chunked body, which declares nothing.
So this middleware counts the bytes as they arrive, declared or chunked, and answers 413 the moment a
body passes its route's limit, without reading the rest.

Three classes, and an explicit entry for every route that needs more than the JSON class:

- PUBLIC_LIMIT (64 KiB): the routes anyone can call with a body -- sign-in and its second factor,
  signup, invitation and reset acceptance, forgot-password, the public note, file and upload link
  endpoints -- and the routes whose credential is checked only after the body has been read: device
  sync (a device secret) and second-factor enrollment (a session or a pending sign-in). Every one of
  them takes a handful of short fields.
- JSON_LIMIT (1 MiB): every other route, for a caller who is signed in (below). Every one of these
  routes needs a session, so a caller who has none meets PUBLIC_LIMIT there too: nothing larger than
  64 KiB is read on any route before its caller is known, not even to be refused with a 401.
- ROUTE_RULES: the file routes and the few JSON routes whose legitimate body is larger, each with its
  own limit and the reason for it. The direct multipart upload (POST /vaults/{vault_id}/files) is
  held to the largest file the deployment accepts right now, plus the form's framing (largest_file):
  the framework spools its whole form to /tmp, a tmpfs in the shipped compose files and so memory,
  before the route checks anything about the caller's rights. A batch larger than one file, and any
  large file, goes through the resumable uploader, whose chunks are checked before they are read.

A route whose rule has needs_session=True (the JSON class and every explicit rule but the chunk
routes) has its body read before it authenticates the caller, so a limit there above PUBLIC_LIMIT is
given only to a session that is signed in right now: the token is signed and unexpired, and the
session, the account and any temporary credential behind it pass the checks get_current_user makes
(app/core/live_session.py, whose answer is kept a few seconds so an upload burst pays for one
lookup). Everyone else meets PUBLIC_LIMIT on that route:

- a body that declares no more than PUBLIC_LIMIT goes in without anyone being asked, since anyone may
  send that much;
- a request with no bearer token is held to PUBLIC_LIMIT;
- a bearer token that is not a live session (a revoked or logged-out session, a deactivated or locked
  account, a temporary credential that is off, finished or past its time, a token this server did not
  sign) is answered 401 without its body being read, as the route would answer it;
- a session that could not be checked (the database did not answer) is answered 503.

The two chunk routes are the exception: they read the body themselves, after the caller or the link
has been checked, so their limit applies to whoever reaches them. A stream rule marks a route that
reads the body as it arrives (a chunk written straight to disk, a multipart form spooled part by part):
its bytes are counted, never held here.

Kept free of the application's imports at module level (live_session imports the database only when
it is first asked) so it is unit-testable offline.
"""
import json
import re
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional, Sequence, Tuple

from starlette.exceptions import HTTPException

from app.core import live_session

KiB = 1024
MiB = 1024 * KiB

PUBLIC_LIMIT = 64 * KiB
JSON_LIMIT = 1 * MiB
# One resumable chunk. Both chunk handlers bound each request to this themselves (the plaintext a
# chunk may add, never more than 64 MiB), so the limit here never refuses what they would accept.
CHUNK_LIMIT = 64 * MiB
# A note body and an email template body may each be up to 1,000,000 characters. JSON escaping can
# turn one character into six bytes (a control character is written as a six-byte escape), so 8 MiB
# covers the worst case.
LARGE_TEXT_LIMIT = 8 * MiB
# Headroom above a multipart route's own file cap, so a file somewhat over it still gets the route's
# own message ("File too large (max 2 MB)") rather than this layer's generic one.
_MULTIPART_HEADROOM = 1 * MiB


@dataclass(frozen=True)
class BodyRule:
    """One route class. ``limit`` None means this layer sets no cap (the handler meters the body)."""
    name: str
    limit: Optional[int]
    stream: bool = False          # the route reads the body as a stream: count it, never hold it
    needs_session: bool = False   # above PUBLIC_LIMIT only for a live session; anyone else gets PUBLIC
    # The limit is the largest file the deployment accepts right now plus _MULTIPART_HEADROOM, asked
    # when a live session sends a body over PUBLIC_LIMIT (largest_file_bytes); ``limit`` is unused then.
    largest_file: bool = False
    hint: Optional[str] = None    # added to the refusal: where a body this large should go instead


PUBLIC = BodyRule("public", PUBLIC_LIMIT)
JSON = BodyRule("json", JSON_LIMIT, needs_session=True)

_POST, _PUT, _PATCH = ("POST",), ("PUT",), ("PATCH",)

# (methods, route template). Templates are the routes' own paths; {name} is one path segment.
_PUBLIC_ROUTES: Sequence[Tuple[Tuple[str, ...], str]] = (
    (_POST, "/auth/login"),
    (_POST, "/auth/second-factor/verify"),
    (_POST, "/auth/second-factor/cancel"),
    # Second-factor enrollment takes a session OR a pending sign-in token, resolved after the body.
    (_POST, "/users/me/second-factor/totp/enroll"),
    (_POST, "/users/me/second-factor/totp/confirm"),
    (_POST, "/auth/signup"),
    (_POST, "/auth/forgot-password"),
    (_POST, "/invites/{token}/accept"),
    (_POST, "/reset/{token}"),
    (_POST, "/note-links/{token}/redeem"),
    (_POST, "/public-links/{token}/redeem"),
    (_POST, "/receivers/{token}/upload-session"),
    (_POST, "/receivers/{token}/upload-session/{session_id}/complete"),
    # Device sync: the device secret is resolved after the framework has read the body.
    (_POST, "/device/sync-credential"),
    (_POST, "/device/refresh"),
)

# (methods, route template, rule, why). The first rule that matches a request applies.
ROUTE_RULES: Sequence[Tuple[Tuple[str, ...], str, BodyRule, str]] = (
    (_PUT, "/vaults/{vault_id}/uploads/{session_id}/chunks/{chunk_index}",
     BodyRule("upload_chunk", CHUNK_LIMIT, stream=True),
     "one resumable chunk, written to disk as it arrives after the caller is authenticated"),
    (_PUT, "/receivers/{token}/upload-session/{session_id}/chunks/{chunk_index}",
     BodyRule("link_upload_chunk", CHUNK_LIMIT, stream=True),
     "one chunk of an upload-link upload, written to disk as it arrives after the link is checked"),
    (_POST, "/vaults/{vault_id}/files",
     BodyRule("multipart_upload", None, stream=True, needs_session=True, largest_file=True,
              hint="Send a larger file, or several files together, with the resumable uploader "
                   "(POST /vaults/{vault_id}/uploads)."),
     "a multipart upload, spooled whole to /tmp (memory) before the handler runs: at most the largest "
     "file the deployment accepts, plus the form's framing; each file is then held to that size and "
     "the quotas by the handler"),
    (_POST, "/settings/brand/asset/{slot}",
     BodyRule("brand_asset", 2 * MiB + _MULTIPART_HEADROOM, stream=True, needs_session=True),
     "a logo or favicon, at most 2 MB"),
    (_POST, "/email/resources",
     BodyRule("email_image", 5 * MiB + _MULTIPART_HEADROOM, stream=True, needs_session=True),
     "an email template image, at most 5 MB"),
    (_POST, "/notes",
     BodyRule("note", LARGE_TEXT_LIMIT, needs_session=True),
     "a note of up to 1,000,000 characters"),
    (_PATCH, "/notes/{note_id}",
     BodyRule("note", LARGE_TEXT_LIMIT, needs_session=True),
     "a note of up to 1,000,000 characters"),
    (_POST, "/email/templates",
     BodyRule("email_template", LARGE_TEXT_LIMIT, needs_session=True),
     "an email template of up to 1,000,000 characters"),
    (_PUT, "/email/templates/{template_id}",
     BodyRule("email_template", LARGE_TEXT_LIMIT, needs_session=True),
     "an email template of up to 1,000,000 characters"),
    (_POST, "/email/templates/preview",
     BodyRule("email_template", LARGE_TEXT_LIMIT, needs_session=True),
     "an email template of up to 1,000,000 characters"),
    (_POST, "/vaults/{vault_id}/zk/seal-names",
     BodyRule("seal_names", 4 * MiB, needs_session=True),
     "up to 1,000 encrypted names sent by the browser in one request (about 1.5 KB each at most)"),
) + tuple((m, t, PUBLIC, "a public route: a handful of short fields") for m, t in _PUBLIC_ROUTES)


def _compile(template: str):
    """A route template as a pattern: each {name} segment matches exactly one path segment."""
    return re.compile("^" + "/".join(
        "[^/]+" if seg.startswith("{") and seg.endswith("}") else re.escape(seg)
        for seg in template.split("/")) + "$")


_COMPILED = tuple((frozenset(m), _compile(t), rule) for m, t, rule, _why in ROUTE_RULES)


def rule_for(method: str, path: str) -> BodyRule:
    """The rule for a request, before any session check. Anything not listed is JSON."""
    method = (method or "").upper()
    path = (path or "/")
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    for methods, pattern, rule in _COMPILED:
        if method in methods and pattern.match(path):
            return rule
    return JSON


def _human(n: int) -> str:
    if n % MiB == 0:
        return f"{n // MiB} MiB"
    if n % KiB == 0:
        return f"{n // KiB} KiB"
    return f"{n} bytes"


def too_large_detail(limit: int, hint: Optional[str] = None) -> str:
    detail = f"Request body too large. The limit for this request is {_human(limit)}."
    return f"{detail} {hint}" if hint else detail


def too_large_body(limit: int, hint: Optional[str] = None) -> bytes:
    return json.dumps({"detail": too_large_detail(limit, hint)}).encode()


# --------------------------------------------------------------------------- the largest file

# How long the answer of largest_file_bytes is kept, so an upload burst pays for one read. Saving the
# administrators' maximum file size forgets it at once (forget_largest_file).
LARGEST_FILE_CACHE_SECONDS = 5.0
_largest = {"value": None, "until": 0.0}


def forget_largest_file() -> None:
    """Drop the kept answer of largest_file_bytes: the setting it reads was just saved."""
    _largest.update(value=None, until=0.0)


def _ceiling_bytes() -> int:
    """The deployment's ceiling on one file (MAX_FILE_SIZE_MB), in bytes."""
    from app.core.config import settings
    return max(0, int(settings.max_file_size_mb or 0)) * MiB


def largest_file_from(db) -> int:
    """The largest file the deployment accepts, read from ``db``: the ceiling, lowered (never raised)
    by the administrators' maximum file size setting. The per-file limit the upload route holds each
    file to (api_server._upload_policy), from the same setting."""
    from app.core.models import SystemSetting
    from app.core.upload_policy import effective_max_file_bytes
    row = db.query(SystemSetting.value).filter(SystemSetting.key == "global").first()
    blob = row[0] if row is not None and isinstance(row[0], dict) else {}
    return effective_max_file_bytes(_ceiling_bytes(), blob.get("max_file_size"))


def _ask_database() -> int:
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        return largest_file_from(db)
    finally:
        db.close()


async def largest_file_bytes(ask=None) -> int:
    """The largest file the deployment accepts right now, in bytes (largest_file_from), asked in a worker
    thread and kept LARGEST_FILE_CACHE_SECONDS. The ceiling alone when the setting could not be read,
    and that is not kept. `ask() -> int` defaults to the database."""
    now = time.monotonic()
    if _largest["value"] is not None and now < _largest["until"]:
        return _largest["value"]
    from starlette.concurrency import run_in_threadpool
    try:
        value = int(await run_in_threadpool(ask or _ask_database))
    except Exception:  # noqa: BLE001 -- the setting could not be read: the deployment's ceiling
        return _ceiling_bytes()
    _largest.update(value=value, until=now + LARGEST_FILE_CACHE_SECONDS)
    return value


# A token that is no live session is told what get_current_user would tell it; the web app signs the
# person out on a 401 (a detail that mentions no password).
SESSION_ENDED_BODY = json.dumps({"detail": "Your session has ended. Please sign in again."}).encode()
SESSION_ENDED_HEADERS = [(b"www-authenticate", b"Bearer"),
                         (b"clear-site-data", b'"cache", "cookies", "storage"')]
SESSION_UNCHECKED_BODY = json.dumps(
    {"detail": "Your sign-in could not be checked just now. Try again in a moment."}).encode()
SESSION_UNCHECKED_HEADERS = [(b"retry-after", b"5")]


class BodyTooLarge(HTTPException):
    """Raised out of receive() when a streamed body passes its limit. An HTTPException, so the
    framework's body readers and the handlers' ``except HTTPException: raise`` pass it on untouched."""

    def __init__(self, limit: int, hint: Optional[str] = None):
        super().__init__(status_code=413, detail=too_large_detail(limit, hint))
        self.limit = limit


async def _answer(send, status: int, body: bytes, headers=()) -> None:
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())] + list(headers)})
    await send({"type": "http.response.body", "body": body})


class BodyLimitMiddleware:
    """Pure ASGI: bound every HTTP request body by its route's rule (see the module docstring).

    `caller(authorization)` answers live_session's NO_CREDENTIAL, LIVE, ENDED or UNKNOWN; left out, it
    is live_session.caller_state, looked up when used. `largest_file()` answers the largest file the
    deployment accepts, in bytes; left out, it is largest_file_bytes, looked up when used."""

    def __init__(self, app, classify: Callable[[str, str], BodyRule] = rule_for,
                 caller: Optional[Callable[[Optional[bytes]], Awaitable[str]]] = None,
                 largest_file: Optional[Callable[[], Awaitable[int]]] = None):
        self.app = app
        self.classify = classify
        self.caller = caller
        self.largest_file = largest_file

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        declared = authorization = None
        chunked = False
        for key, value in scope.get("headers") or ():
            if key == b"content-length":
                declared = value
            elif key == b"transfer-encoding":
                chunked = b"chunked" in value.lower()
            elif key == b"authorization":
                authorization = value
        length = None
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                length = -1
            if length < 0:
                await _answer(send, 400, json.dumps({"detail": "Invalid Content-Length header."}).encode())
                return
        if not chunked and not length:
            await self.app(scope, receive, send)   # no body at all
            return

        rule = self.classify(scope.get("method", ""), scope.get("path", ""))
        if rule.needs_session and (rule.limit is None or rule.limit > PUBLIC_LIMIT):
            if length is not None and length <= PUBLIC_LIMIT:
                rule = PUBLIC   # anyone may send this much: no need to ask who is calling
            else:
                state = await (self.caller or live_session.caller_state)(authorization)
                if state == live_session.ENDED:
                    await _answer(send, 401, SESSION_ENDED_BODY, SESSION_ENDED_HEADERS)
                    return
                if state == live_session.UNKNOWN:
                    await _answer(send, 503, SESSION_UNCHECKED_BODY, SESSION_UNCHECKED_HEADERS)
                    return
                if state != live_session.LIVE:
                    rule = PUBLIC   # no credential: what anyone may send, held until it is whole
        limit = rule.limit
        if rule.largest_file:
            limit = await (self.largest_file or largest_file_bytes)() + _MULTIPART_HEADROOM
        if limit is None:
            await self.app(scope, receive, send)
            return
        if length is not None and length > limit:
            # Refused on the declaration: nothing is read, and the server discards the rest.
            await _answer(send, 413, too_large_body(limit, rule.hint))
            return
        if rule.stream:
            await self._counted(scope, receive, send, limit, rule.hint)
        else:
            await self._buffered(scope, receive, send, limit)

    async def _buffered(self, scope, receive, send, limit):
        """Read the whole body (at most `limit` bytes) before the application runs, then hand it on
        as one message. The application would have read it whole anyway; this way a body over the
        limit never reaches it, and a handler that swallows read errors cannot act on half a body."""
        parts, received = [], 0
        while True:
            message = await receive()
            if message.get("type") != "http.request":
                return   # the client went away mid-body; there is no one to answer
            chunk = message.get("body") or b""
            received += len(chunk)
            if received > limit:
                await _answer(send, 413, too_large_body(limit))
                return
            if chunk:
                parts.append(chunk)
            if not message.get("more_body", False):
                break
        body = b"".join(parts)
        del parts
        handed = False

        async def replay():
            nonlocal handed
            if not handed:
                handed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()   # after the body: wait for a disconnect, as the server would

        await self.app(scope, replay, send)

    async def _counted(self, scope, receive, send, limit, hint=None):
        """Pass the body through as it arrives, counting it. Past the limit, receive() raises and
        whatever the application answers is replaced by the 413 (unless it had already started a
        response before the limit was reached, which it then finishes as it can)."""
        state = {"received": 0, "tripped": False, "started": False, "started_at_trip": False}

        async def counted_receive():
            if state["tripped"]:
                raise BodyTooLarge(limit, hint)
            message = await receive()
            if message.get("type") == "http.request":
                state["received"] += len(message.get("body") or b"")
                if state["received"] > limit:
                    state["tripped"] = True
                    state["started_at_trip"] = state["started"]
                    raise BodyTooLarge(limit, hint)
            return message

        async def guarded_send(message):
            if state["tripped"] and not state["started_at_trip"]:
                return   # the application's answer to a refused body is replaced below
            if message.get("type") == "http.response.start":
                state["started"] = True
            await send(message)

        try:
            await self.app(scope, counted_receive, guarded_send)
        except Exception:
            if not state["tripped"]:
                raise
        if state["tripped"] and not state["started_at_trip"]:
            await _answer(send, 413, too_large_body(limit, hint))
