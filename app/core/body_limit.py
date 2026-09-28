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
- JSON_LIMIT (1 MiB): every other route.
- ROUTE_RULES: the file routes and the few JSON routes whose legitimate body is larger, each with its
  own limit and the reason for it.

A route listed with needs_session=True parses its body before it authenticates the caller, so its
larger limit is given only to a request carrying a bearer token this server signed for a session
(signature and expiry checked, which needs no database). Anyone else meets JSON_LIMIT there: nothing
larger than 1 MiB is parsed for a caller who has not signed in. A stream rule marks a route that reads
the body itself as it arrives (a chunk written straight to disk, a multipart form spooled part by
part): its bytes are counted, never held here.

Kept free of the application's imports (the token check is imported only when first needed) so it is
unit-testable offline.
"""
import json
import re
from dataclasses import dataclass
from typing import Callable, Optional, Sequence, Tuple

from starlette.exceptions import HTTPException

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
    needs_session: bool = False   # the limit is for a signed-in caller only; anyone else gets JSON


PUBLIC = BodyRule("public", PUBLIC_LIMIT)
JSON = BodyRule("json", JSON_LIMIT)

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
     BodyRule("multipart_upload", None, stream=True, needs_session=True),
     "a multipart upload of one or more files: each file is held to the maximum file size and the "
     "vault and deployment quotas by the handler, and a batch may legitimately exceed any one file"),
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


def bearer_has_session(authorization: Optional[bytes]) -> bool:
    """True if the Authorization header carries a session token this server signed and that has not
    expired. A signature and expiry check only (no database): enough to know the caller signed in,
    which is all a larger body limit needs. The same rule as the session resolver: a token without a
    session_token is no session, which is what keeps a second-factor pending token out."""
    if not authorization:
        return False
    try:
        scheme, _, token = authorization.decode("latin-1").strip().partition(" ")
    except Exception:  # noqa: BLE001 -- an undecodable header is no session
        return False
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        return False
    try:
        from app.core.security import verify_access_token
        payload = verify_access_token(token)
    except Exception:  # noqa: BLE001 -- a broken token is no session, never a 500
        return False
    return bool(isinstance(payload, dict) and payload.get("sub") and payload.get("session_token"))


def _human(n: int) -> str:
    if n % MiB == 0:
        return f"{n // MiB} MiB"
    if n % KiB == 0:
        return f"{n // KiB} KiB"
    return f"{n} bytes"


def too_large_detail(limit: int) -> str:
    return f"Request body too large. The limit for this request is {_human(limit)}."


def too_large_body(limit: int) -> bytes:
    return json.dumps({"detail": too_large_detail(limit)}).encode()


class BodyTooLarge(HTTPException):
    """Raised out of receive() when a streamed body passes its limit. An HTTPException, so the
    framework's body readers and the handlers' ``except HTTPException: raise`` pass it on untouched."""

    def __init__(self, limit: int):
        super().__init__(status_code=413, detail=too_large_detail(limit))
        self.limit = limit


async def _answer(send, status: int, body: bytes) -> None:
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


class BodyLimitMiddleware:
    """Pure ASGI: bound every HTTP request body by its route's rule (see the module docstring)."""

    def __init__(self, app, classify: Callable[[str, str], BodyRule] = rule_for,
                 has_session: Callable[[Optional[bytes]], bool] = bearer_has_session):
        self.app = app
        self.classify = classify
        self.has_session = has_session

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
        if rule.needs_session and not self.has_session(authorization):
            rule = JSON
        limit = rule.limit
        if limit is None:
            await self.app(scope, receive, send)
            return
        if length is not None and length > limit:
            # Refused on the declaration: nothing is read, and the server discards the rest.
            await _answer(send, 413, too_large_body(limit))
            return
        if rule.stream:
            await self._counted(scope, receive, send, limit)
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

    async def _counted(self, scope, receive, send, limit):
        """Pass the body through as it arrives, counting it. Past the limit, receive() raises and
        whatever the application answers is replaced by the 413 (unless it had already started a
        response before the limit was reached, which it then finishes as it can)."""
        state = {"received": 0, "tripped": False, "started": False, "started_at_trip": False}

        async def counted_receive():
            if state["tripped"]:
                raise BodyTooLarge(limit)
            message = await receive()
            if message.get("type") == "http.request":
                state["received"] += len(message.get("body") or b"")
                if state["received"] > limit:
                    state["tripped"] = True
                    state["started_at_trip"] = state["started"]
                    raise BodyTooLarge(limit)
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
            await _answer(send, 413, too_large_body(limit))
