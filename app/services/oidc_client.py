"""The vault's OpenID Connect relying party, written out in full on PyJWT and ``urllib``.

No framework: every check the vault relies on is here, named, so the hostile tests and the conformance suite
can hold it to account. Discovery and the provider's keys are fetched over TLS with a short timeout and a
small body cap, never following a redirect; every endpoint the vault calls or sends a browser to must be
``https`` on a public host (a provider inside the network needs the provider's ``private_network`` option),
so a compromised discovery document cannot send the code and the client secret to an internal address. The
ID token is verified with the algorithms the vault allows (asymmetric only), the exact issuer, the audience
and the ``azp`` rule, a 60-second skew, the login's nonce, ``auth_time`` when re-authentication was asked,
and a bounded size; a back-channel logout token the same way, with its own rules (an ``events`` claim, no
nonce, a fresh ``jti`` kept against replay). The reason for a refusal is a short code; the provider's own
error text never reaches the person.

Two deliberate narrowings of the design: ``userinfo`` is read as JSON only (the vault never registers a signed
userinfo response, so a JWT answer is a provider error), and the host's addresses are vetted by a lookup of our own
before the connection rather than pinned into it. The connection then judges its own lookup as well: made directly,
it takes only the public addresses its name answers, unless the provider is marked as inside the network
(:func:`_reach`), so a name that answers a public address to the first lookup and a private one to the second
reaches nothing. Through a proxy the proxy looks the name up, and the vault cannot judge the address it connects
to: there the check before the call and the TLS handshake are what stand (the handshake must present a certificate
valid for the provider's name, which whoever merely controls that name cannot place inside the network).
"""
from __future__ import annotations

import base64
import contextvars
import hashlib
import http.client
import io
import ipaddress
import json
import logging
import math
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import jwt

log = logging.getLogger("dockvault.sso")

ALLOWED_ALGS = ("RS256", "PS256", "ES256")
SKEW_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 10
MAX_BODY_BYTES = 256 * 1024
MAX_TOKEN_BYTES = 16 * 1024
MAX_SUBJECT_LENGTH = 255
CACHE_SECONDS = 3600
DISCOVERY_FAILURE_SECONDS = 30   # a fetch of discovery or keys that failed is not tried again for this long
# How long after it was fetched a good discovery document or key set is still served when a fetch fails (the provider
# down, a bad answer): one bad response does not stop sign-ins, and a copy older than this is never served.
STALE_IF_ERROR_SECONDS = 24 * 3600
JWKS_REFETCH_INTERVAL_SECONDS = 60
LOGOUT_TOKEN_FRESHNESS_SECONDS = 120
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
USER_AGENT = "DockVault"
WELL_KNOWN = "/.well-known/openid-configuration"
TOKEN_AUTH_BASIC = "client_secret_basic"
TOKEN_AUTH_POST = "client_secret_post"

# The reason codes a refusal carries (the audit detail; the person sees them in words).
PROVIDER_ERROR = "provider_error"
ISSUER_MISMATCH = "issuer_mismatch"
TOKEN_INVALID = "token_invalid"
PROVIDER_CLOCK_AHEAD = "provider_clock_ahead"     # a time the provider states lies ahead of now, beyond the skew
NONCE_MISMATCH = "nonce_mismatch"
ENDPOINT_REFUSED = "endpoint_refused"
TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
DISCOVERY_INVALID = "discovery_invalid"
# RFC 6749 section 5.2: the only words of the token endpoint's refusal that reach a log.
_TOKEN_ERROR_CODES = frozenset(("invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
                                "unsupported_grant_type", "invalid_scope"))


class OidcError(Exception):
    """A refusal with its reason code; ``detail`` is for the server log, never the person."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProviderConfig:
    """What the client needs of a configured provider."""
    id: str
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)      # never in a log line, an error's text or a test's diff
    token_auth: str = TOKEN_AUTH_BASIC
    scopes: str = "openid profile email"
    discovery_url: Optional[str] = None
    private_network: bool = False


@dataclass(frozen=True)
class Discovery:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: Optional[str]
    end_session_endpoint: Optional[str]
    id_token_signing_algs: Tuple[str, ...]
    code_challenge_methods: Optional[Tuple[str, ...]]      # None: the document does not say (RFC 8414 absence)
    backchannel_logout_supported: bool
    iss_in_callback: bool
    claims_supported: Tuple[str, ...]
    acr_values_supported: Tuple[str, ...]


@dataclass(frozen=True)
class TokenResponse:
    id_token: str
    access_token: Optional[str]
    token_type: str


class Cache:
    """A small time-bounded cache: the process's own by default (:data:`_DEFAULT_CACHE`); the routes may hand one
    backed by Redis, which every worker then shares."""

    def __init__(self):
        self._rows: Dict[str, Tuple[float, object]] = {}

    def get(self, key: str, now: Optional[float] = None):
        now = time.time() if now is None else now
        row = self._rows.get(key)
        if row is None or row[0] <= now:
            self._rows.pop(key, None)
            return None
        return row[1]

    def set(self, key: str, value, ttl: int, now: Optional[float] = None) -> None:
        now = time.time() if now is None else now
        self._rows[key] = (now + ttl, value)

    def clear(self, key: str) -> None:
        self._rows.pop(key, None)


_DEFAULT_CACHE = Cache()


def _cache(cache: Optional[Cache]) -> Cache:
    return cache if cache is not None else _DEFAULT_CACHE


def _where(provider: ProviderConfig, *parts: str) -> str:
    """A short digest of what a cached answer was fetched for (the addresses, the issuer, whether private addresses
    were allowed), so an answer is never served for another configuration later saved under the same provider id."""
    scope = ["private" if provider.private_network else "public", *parts]
    return hashlib.sha256(json.dumps(scope).encode("utf-8")).hexdigest()[:16]


def _remember_failure(cache: Cache, key: str, exc: OidcError, now: Optional[float]) -> None:
    """Pace the next attempt: a fetch that failed is not tried again for :data:`DISCOVERY_FAILURE_SECONDS`, so a
    provider that is down (or tokens naming made-up keys) cannot make the vault fetch on every request."""
    cache.set(key, exc.code, DISCOVERY_FAILURE_SECONDS, now)


def _keep_good(cache: Cache, key: str, value, now: Optional[float]) -> None:
    """Keep ``value`` as the last good copy, with the time it was fetched; it lapses :data:`STALE_IF_ERROR_SECONDS`
    after that fetch, whatever is served meanwhile."""
    now = time.time() if now is None else now
    cache.set(key, (now, value), STALE_IF_ERROR_SECONDS, now)


def _good_copy(cache: Cache, key: str, now: Optional[float], *, kid: Optional[str] = None):
    """The last good copy kept under ``key`` as ``(fetched_at, value)``, or None: none was kept, it is older than
    the ceiling, or (for a key set) it does not hold the key the token names."""
    row = cache.get(key, now)
    if row is None or (kid is not None and kid not in row[1]):
        return None
    return row


def _serve_good(row, provider: ProviderConfig, what: str, exc: OidcError, now: Optional[float]):
    """Serve the last good copy for a fetch that has just failed, with a warning in the server log (one for each
    failed fetch: a failure remembered for the next requests serves the copy without a new warning)."""
    age = int((time.time() if now is None else now) - row[0])
    log.warning("sso: the %s of provider %s could not be fetched (%s); serving the copy fetched %d s ago",
                what, provider.id, exc.code, age)
    return row[1]


# --------------------------------------------------------------------------- the endpoint rule

def endpoint_problem(url: Optional[str], *, private_network: bool = False) -> Optional[str]:
    """Why ``url`` is not an endpoint the vault may call or send a browser to, or None.

    ``https`` only; a host name, not a bare IP address; no user name or password; a public name (not localhost,
    not a ``.local``/``.internal`` suffix) unless ``private_network`` allows the provider to live inside the
    network. Name resolution is checked separately at use (:func:`resolved_address_problem`).
    """
    if not isinstance(url, str) or not url.strip():
        return "the endpoint is missing"
    try:
        parts = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return "the endpoint cannot be read as an address"
    if parts.scheme.lower() != "https":
        return "the endpoint must use https"
    if parts.username is not None or parts.password is not None:
        return "the endpoint must not carry a user name or password"
    host = parts.hostname
    if not host:
        return "the endpoint has no host name"
    try:
        parts.port
    except ValueError:
        return "the endpoint has a bad port"
    if _looks_like_ip(host):
        if private_network:
            return None
        return "the endpoint is a bare IP address"
    if not private_network and (host.lower() in ("localhost",) or host.lower().endswith((".localhost", ".local", ".internal", ".lan", ".home", ".arpa"))):
        return "the endpoint is on a private name"
    return None


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _address_is_private(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    # Not global covers the private ranges, loopback, link-local, multicast, reserved and unspecified addresses,
    # and the shared address space of RFC 6598 (100.64/10, carrier NAT and mesh networks), which is not private.
    return (not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified or getattr(ip, "is_site_local", False))


UNRESOLVED = "the endpoint's name does not resolve"


def resolved_address_problem(url: str, *, private_network: bool = False, resolve=None) -> Optional[str]:
    """At use: the host must resolve, and (without ``private_network``) to public addresses only."""
    host = urllib.parse.urlsplit(url).hostname or ""
    resolve = resolve or _resolve
    try:
        addresses = resolve(host)
    except OSError:
        return UNRESOLVED
    if not addresses:
        return UNRESOLVED
    if private_network:
        return None
    if any(_address_is_private(a) for a in addresses):
        return "the endpoint resolves to a private address"
    return None


def _resolve(host: str) -> List[str]:
    if _looks_like_ip(host):
        return [host.strip("[]")]
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return sorted({info[4][0] for info in infos})


def check_endpoint(url: str, *, private_network: bool = False, resolve=None) -> None:
    """Raise :class:`OidcError` (``endpoint_refused``) unless ``url`` passes both rules; a name that does not resolve
    (a lookup that failed, or no address) is ``temporarily_unavailable``: the resolver's state, not the address."""
    why = endpoint_problem(url, private_network=private_network)
    if why is None:
        why = resolved_address_problem(url, private_network=private_network, resolve=resolve)
    if why == UNRESOLVED:
        raise OidcError(TEMPORARILY_UNAVAILABLE, why)
    if why is not None:
        raise OidcError(ENDPOINT_REFUSED, why)


# --------------------------------------------------------------------------- outbound HTTP

class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise urllib.error.HTTPError(req.full_url, code, "redirects are not followed", headers, fp)


class _NotPublic(OSError):
    """The name answered no public address where the connection was made."""


# Whether the connections made now may take only public addresses, read where the connection looks the name up
# (:class:`_DeadlineConnection`). They may not take any other unless a call says so: :func:`_reach` lifts it for a
# provider marked as inside, for that call. A fetch made some other way is held to public addresses.
_PUBLIC_ONLY: contextvars.ContextVar = contextvars.ContextVar("oidc_public_addresses_only", default=True)


def _reach(provider: "ProviderConfig", fetch: Callable, url: str, **kw) -> dict:
    """``fetch(url)`` for ``provider``. The endpoint rule looked the name up a moment ago; the connection looks it
    up again. Whoever answers for the name could say a public address to the first and one inside to the second
    (a lookup that lives no time at all), and the vault would open a connection to a host inside. So unless the
    provider is marked as inside, the connection made here takes no address that is not public."""
    token = _PUBLIC_ONLY.set(not provider.private_network)
    try:
        return fetch(url, **kw)
    finally:
        _PUBLIC_ONLY.reset(token)


def _addresses_allowed(addresses: list, *, through_a_proxy: bool) -> list:
    """The addresses a connection may try, of those its name answered (``getaddrinfo``'s entries): all of them,
    or only the public ones while a call is held to public addresses (:func:`_reach`); none left is
    :class:`_NotPublic`. Through a proxy the connection is to the proxy, which looks the provider's name up
    itself: nothing is judged here."""
    if through_a_proxy or not _PUBLIC_ONLY.get():
        return addresses
    public = [found for found in addresses if not _address_is_private(found[4][0])]
    if not public:
        raise _NotPublic("the name answers no public address")
    return public


def _time_left(deadline: float) -> float:
    """The seconds a call has left, or TimeoutError once it has none."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("the call's deadline passed")
    return left


class _DeadlinedReader(io.RawIOBase):
    """The bytes of a connection, each read waiting no longer than the call has left."""

    def __init__(self, raw, sock, deadline: float):
        self._raw, self._sock, self._deadline = raw, sock, deadline

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        self._sock.settimeout(_time_left(self._deadline))
        return self._raw.readinto(buffer)

    def close(self) -> None:
        try:
            self._raw.close()
        finally:
            super().close()


class _Deadlined:
    """A connected socket whose every read and write waits no longer than the call has left. The socket's own
    timeout bounds one read; a provider that sent a byte of its status line or of a header just inside that timeout,
    again and again, would hold the call for as long as it liked."""

    def __init__(self, sock, deadline: float):
        self._sock, self._deadline = sock, deadline

    @property
    def plain(self):
        """The socket itself, for the one step that needs it: wrapping it in TLS."""
        return self._sock

    def sendall(self, data, *args):
        self._sock.settimeout(_time_left(self._deadline))
        return self._sock.sendall(data, *args)

    def makefile(self, mode="rb", *args, **kwargs):
        # The reader the standard library would make, with the deadline in front of every read. It is made by the
        # socket itself, so the socket stays open for as long as the answer is being read.
        return io.BufferedReader(_DeadlinedReader(self._sock.makefile("rb", buffering=0), self._sock, self._deadline))

    def __getattr__(self, name):
        return getattr(self._sock, name)


class _DeadlineConnection(http.client.HTTPSConnection):
    """One call to a provider under one deadline: every address tried, the TLS handshake, the request, the status
    line, the headers and the body together take no longer than the call's timeout."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        whole = self.timeout if isinstance(self.timeout, (int, float)) and self.timeout > 0 else HTTP_TIMEOUT_SECONDS
        self._deadline = time.monotonic() + whole          # the connection is made as the call starts
        self._create_connection = self._connect_by_the_deadline

    def _connect_by_the_deadline(self, address, timeout=None, source_address=None):
        host, port = address
        # Judged where the connection is made (see _reach), not only where the name was looked up before.
        addresses = _addresses_allowed(socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM),
                                       through_a_proxy=bool(self._tunnel_host))
        failure: Optional[OSError] = None
        for tried, (family, kind, proto, _name, where) in enumerate(addresses):
            # Each address gets an even share of what is left. One that never answers (a route that drops IPv6,
            # say) then leaves time for the next, and the first to answer is taken, as the standard connection
            # does; all of them together still take no longer than the call has.
            share = _time_left(self._deadline) / (len(addresses) - tried)
            sock = socket.socket(family, kind, proto)
            try:
                sock.settimeout(share)
                sock.connect(where)
                # Held to the deadline from here on: what follows on the bare connection (a proxy's CONNECT
                # exchange, where the deployment reaches the provider through one) waits no longer either.
                return _Deadlined(sock, self._deadline)
            except OSError as exc:
                failure = exc
                sock.close()
        raise failure or OSError("the name has no address")

    def connect(self):
        http.client.HTTPConnection.connect(self)
        plain = self.sock.plain
        plain.settimeout(_time_left(self._deadline))
        secured = self._context.wrap_socket(plain, server_hostname=self._tunnel_host or self.host)
        self.sock = _Deadlined(secured, self._deadline)


class _Https(urllib.request.HTTPSHandler):
    """The https handler, with every connection held to one deadline: the timeout of the request it serves."""

    def do_open(self, http_class, req, **http_conn_args):
        return super().do_open(_DeadlineConnection, req, **http_conn_args)


def _build_opener(context=None):
    """The opener every call of this module is made with (``context``: a test's own trust store). Every
    connection is held to the call's deadline, and no redirect is followed: the address a redirect names was
    never judged under the endpoint rule, and urllib would replay the request there with its headers, the
    client's credentials among them."""
    return urllib.request.build_opener(_Https(context=context) if context is not None else _Https(), _NoRedirects())


_opener = _build_opener()


def fetch_json(url: str, *, method: str = "GET", data: Optional[bytes] = None, headers: Optional[dict] = None,
               timeout: int = HTTP_TIMEOUT_SECONDS, opener=None) -> dict:
    """GET or POST ``url`` and return its JSON object: TLS verified against the image's trust store, a short
    timeout, a body cap, no redirects, a fixed user agent. ``timeout`` is the whole call's: connecting, the TLS
    handshake, the request, the status line, the headers and the body together, however slowly a provider sends
    any of them. Any failure is ``temporarily_unavailable`` (the provider's answer is logged, never shown) except
    a non-JSON or non-object body, which is ``provider_error``."""
    if urllib.parse.urlsplit(url).scheme.lower() != "https":
        raise OidcError(ENDPOINT_REFUSED, "the endpoint must use https")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Accept", "application/json")
    request.add_header("User-Agent", USER_AGENT)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    deadline = time.monotonic() + timeout
    try:
        with (opener or _opener).open(request, timeout=timeout) as response:
            raw = _read_capped(response, deadline)
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 401) and method == "POST":
            # The token endpoint's own refusal (RFC 6749 section 5.2): a provider error, with a body we never show.
            raise OidcError(PROVIDER_ERROR, f"token endpoint answered {exc.code}") from exc
        raise OidcError(TEMPORARILY_UNAVAILABLE, f"HTTP {exc.code}") from exc
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        if isinstance(exc, _NotPublic) or isinstance(getattr(exc, "reason", None), _NotPublic):
            raise OidcError(ENDPOINT_REFUSED, "the endpoint resolves to a private address") from exc
        raise OidcError(TEMPORARILY_UNAVAILABLE, type(exc).__name__) from exc
    if len(raw) > MAX_BODY_BYTES:
        raise OidcError(TEMPORARILY_UNAVAILABLE, "answer over the size cap")
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise OidcError(PROVIDER_ERROR, "answer is not JSON") from exc
    if not isinstance(body, dict):
        raise OidcError(PROVIDER_ERROR, "answer is not a JSON object")
    return body


def _read_capped(response, deadline: float) -> bytes:
    """The body up to one byte over the cap, in chunks, under one wall-clock deadline for the whole answer: the
    socket timeout alone is per read, and a provider trickling bytes would hold the worker for as long as it liked."""
    chunks, total = [], 0
    while total <= MAX_BODY_BYTES:
        if time.monotonic() > deadline:
            raise OidcError(TEMPORARILY_UNAVAILABLE, "the answer took too long")
        chunk = response.read(min(16 * 1024, MAX_BODY_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- discovery and keys

def discovery_url(provider: ProviderConfig) -> str:
    return provider.discovery_url or (provider.issuer.rstrip("/") + WELL_KNOWN)


def discover(provider: ProviderConfig, *, fetch: Callable = fetch_json, cache: Optional[Cache] = None,
             resolve=None, now: Optional[float] = None, refresh: bool = False) -> Discovery:
    """The provider's discovery document, checked: the issuer exactly as configured, the required endpoints,
    an allowed signing algorithm, ``S256`` when the document lists methods; every endpoint under the endpoint
    rule. Cached an hour.

    When a fetch fails (the network, a name that would not resolve, an address refused, an answer that is not a
    document or fails its checks) the last good document is served, with a warning, for up to
    :data:`STALE_IF_ERROR_SECONDS` after it was fetched; the failure is the answer only when there is no such copy.
    Either way the next fetch waits :data:`DISCOVERY_FAILURE_SECONDS`. Every endpoint of a document served this way
    is checked again under the endpoint rule when it is called. ``refresh`` asks for a new document and never takes
    the old one instead."""
    cache = _cache(cache)
    url = discovery_url(provider)
    where = _where(provider, provider.issuer, url)
    key = f"sso:disc:{provider.id}:{where}"
    if not refresh:
        cached = cache.get(key, now)
        if cached is not None:
            return cached
    failed_key = f"sso:disc-failed:{provider.id}:{where}"
    good_key = f"sso:disc-good:{provider.id}:{where}"
    if not refresh:
        # A fetch that failed moments ago is not tried again yet: the last good copy, else the same failure with its
        # own code, without the name lookup or the timeout.
        remembered = cache.get(failed_key, now)
        if remembered is not None:
            good = _good_copy(cache, good_key, now)
            if good is not None:
                return good[1]
            raise OidcError(remembered, "the provider's discovery failed moments ago")
    try:
        # The fetch and the document's own checks: a document that is wrong is a failed fetch like any other.
        found = _discovery_document(provider, url, fetch=fetch, resolve=resolve)
    except OidcError as exc:
        _remember_failure(cache, failed_key, exc, now)
        good = None if refresh else _good_copy(cache, good_key, now)
        if good is None:
            raise
        return _serve_good(good, provider, "discovery document", exc, now)
    cache.set(key, found, CACHE_SECONDS, now)
    _keep_good(cache, good_key, found, now)
    return found


def _discovery_document(provider: ProviderConfig, url: str, *, fetch: Callable, resolve) -> "Discovery":
    """Fetch the discovery document and check it: the issuer exactly as configured, the required endpoints, an
    allowed signing algorithm, ``S256`` when the document lists methods, every endpoint under the endpoint rule."""
    check_endpoint(url, private_network=provider.private_network, resolve=resolve)
    doc = _reach(provider, fetch, url)
    issuer = doc.get("issuer")
    if not isinstance(issuer, str) or issuer != provider.issuer:
        raise OidcError(ISSUER_MISMATCH, "the discovery document's issuer is not the configured one")
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not isinstance(doc.get(name), str):
            raise OidcError(DISCOVERY_INVALID, f"{name} missing")
    algs = doc.get("id_token_signing_alg_values_supported")
    algs = [a for a in algs if isinstance(a, str)] if isinstance(algs, list) else []
    if not set(algs) & set(ALLOWED_ALGS):
        raise OidcError(DISCOVERY_INVALID, "no allowed ID token signing algorithm")
    methods = doc.get("code_challenge_methods_supported")
    if methods is not None:
        if not isinstance(methods, list) or "S256" not in methods:
            raise OidcError(DISCOVERY_INVALID, "the provider does not support PKCE S256")
        methods = tuple(m for m in methods if isinstance(m, str))
    for name in ("authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint", "end_session_endpoint"):
        value = doc.get(name)
        if value is not None:
            if not isinstance(value, str):
                raise OidcError(DISCOVERY_INVALID, f"{name} is not an address")
            check_endpoint(value, private_network=provider.private_network, resolve=resolve)

    def _strings(name):
        value = doc.get(name)
        return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()

    found = Discovery(
        issuer=issuer, authorization_endpoint=doc["authorization_endpoint"], token_endpoint=doc["token_endpoint"],
        jwks_uri=doc["jwks_uri"], userinfo_endpoint=doc.get("userinfo_endpoint"),
        end_session_endpoint=doc.get("end_session_endpoint"),
        id_token_signing_algs=tuple(algs), code_challenge_methods=methods,
        backchannel_logout_supported=doc.get("backchannel_logout_supported") is True,
        iss_in_callback=doc.get("authorization_response_iss_parameter_supported") is True,
        claims_supported=_strings("claims_supported"), acr_values_supported=_strings("acr_values_supported"))
    return found


def _usable_keys(doc: dict) -> Dict[str, dict]:
    keys = doc.get("keys")
    if not isinstance(keys, list):
        raise OidcError(DISCOVERY_INVALID, "the key set has no keys")
    out: Dict[str, dict] = {}
    for key in keys:
        if not isinstance(key, dict):
            continue
        if key.get("kty") not in ("RSA", "EC") or key.get("use", "sig") != "sig":
            continue
        kid = key.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        out[kid] = key
    return out


def signing_keys(provider: ProviderConfig, discovery: Discovery, *, kid: Optional[str] = None,
                 fetch: Callable = fetch_json, cache: Optional[Cache] = None, resolve=None,
                 now: Optional[float] = None, stale_ok: bool = True) -> Dict[str, dict]:
    """The provider's signing keys by ``kid`` (RSA or EC, for signing, with a key id), cached an hour. When a
    token names a ``kid`` the cache does not hold, the set is fetched again: after a refetch that succeeded, not
    again for a minute; after any fetch that failed, not again for 30 seconds (meanwhile the last good copy is
    served, else the failure is answered again with its own code). A key still unknown after a successful refetch is a refusal for the caller; a key unknown while a
    refetch is throttled is not the token's fault: that answers ``TEMPORARILY_UNAVAILABLE`` (the key may be newer
    than the last fetch). Keys already held are served whatever the throttle or the failure says. When a fetch
    fails, the last good key set is served, with a warning, for up to :data:`STALE_IF_ERROR_SECONDS` after it was
    fetched, if it holds the key asked for; the failure is the answer only when no such copy exists. ``stale_ok``
    False takes no such copy: a back-channel logout token is posted by anyone, and a key the provider has since
    removed must not outlive the hour's cache for it."""
    cache = _cache(cache)
    where = _where(provider, discovery.jwks_uri)
    key = f"sso:jwks:{provider.id}:{where}"
    keys = cache.get(key, now)
    if keys is not None and (kid is None or kid in keys):
        return keys
    failed_key = f"sso:jwks-failed:{provider.id}:{where}"
    good_key = f"sso:jwks-good:{provider.id}:{where}"
    remembered = cache.get(failed_key, now)
    if remembered is not None:
        good = _good_copy(cache, good_key, now, kid=kid) if stale_ok else None
        if good is not None:
            return good[1]
        raise OidcError(remembered, "the provider's keys failed moments ago")
    refetch_key = f"sso:jwks-refetch:{provider.id}:{where}"
    refetching = keys is not None and kid is not None
    if refetching and cache.get(refetch_key, now) is not None:
        raise OidcError(TEMPORARILY_UNAVAILABLE, "the provider's keys were fetched moments ago without that key")
    try:
        check_endpoint(discovery.jwks_uri, private_network=provider.private_network, resolve=resolve)
        keys = _usable_keys(_reach(provider, fetch, discovery.jwks_uri))
    except OidcError as exc:
        _remember_failure(cache, failed_key, exc, now)          # any failure: a refetch cannot be forced per request
        good = _good_copy(cache, good_key, now, kid=kid) if stale_ok else None
        if good is None:
            raise
        return _serve_good(good, provider, "key set", exc, now)
    cache.set(key, keys, CACHE_SECONDS, now)
    _keep_good(cache, good_key, keys, now)
    if refetching:
        # Only a fetch that succeeded throttles the next one: a failed refetch must not leave real keys unknown.
        cache.set(refetch_key, True, JWKS_REFETCH_INTERVAL_SECONDS, now)
    return keys


# --------------------------------------------------------------------------- the authorization request

def make_state() -> str:
    return _b64(secrets.token_bytes(32))


def make_nonce() -> str:
    return _b64(secrets.token_bytes(32))


def make_code_verifier() -> str:
    return _b64(secrets.token_bytes(48))          # 64 unreserved characters


def code_challenge(code_verifier: str) -> str:
    return _b64(hashlib.sha256(code_verifier.encode("ascii")).digest())


def authorization_url(provider: ProviderConfig, discovery: Discovery, *, redirect_uri: str, state: str, nonce: str,
                      code_verifier: str, reauthenticate: bool = False, acr_values: Optional[str] = None,
                      login_hint: Optional[str] = None, resolve=None) -> str:
    """The address the browser is sent to: the authorization code flow with PKCE ``S256``, ``state`` and
    ``nonce``; ``prompt=login`` and ``max_age=0`` for a re-authentication; ``acr_values`` and ``login_hint`` when
    asked. ``redirect_uri`` is built by the caller from the vault's public address. The endpoint is checked again
    here, at use: a cached document may be an hour old."""
    check_endpoint(discovery.authorization_endpoint, private_network=provider.private_network, resolve=resolve)
    scopes = provider.scopes.split()
    if "openid" not in scopes:
        scopes.insert(0, "openid")            # without it the answer is plain OAuth: no ID token, nothing to verify
    params = [("response_type", "code"), ("scope", " ".join(scopes)), ("client_id", provider.client_id),
              ("redirect_uri", redirect_uri), ("state", state), ("nonce", nonce),
              ("code_challenge", code_challenge(code_verifier)), ("code_challenge_method", "S256")]
    if reauthenticate:
        params += [("prompt", "login"), ("max_age", "0")]
    if acr_values:
        params.append(("acr_values", acr_values))
    if login_hint:
        params.append(("login_hint", login_hint))
    separator = "&" if "?" in discovery.authorization_endpoint else "?"
    return discovery.authorization_endpoint + separator + urllib.parse.urlencode(params)


def exchange_code(provider: ProviderConfig, discovery: Discovery, *, code: str, redirect_uri: str,
                  code_verifier: str, fetch: Callable = fetch_json, resolve=None) -> TokenResponse:
    """POST the code to the token endpoint with the PKCE verifier and the client's secret (basic or post, per
    the provider). The answer must carry a bearer token type and an ID token; the access token serves
    ``userinfo`` only."""
    check_endpoint(discovery.token_endpoint, private_network=provider.private_network, resolve=resolve)
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "code_verifier": code_verifier}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if provider.token_auth == TOKEN_AUTH_POST:
        form["client_id"] = provider.client_id
        form["client_secret"] = provider.client_secret
    else:
        credentials = f"{urllib.parse.quote(provider.client_id, safe='')}:{urllib.parse.quote(provider.client_secret, safe='')}"
        headers["Authorization"] = "Basic " + base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    body = _reach(provider, fetch, discovery.token_endpoint, method="POST",
                  data=urllib.parse.urlencode(form).encode("ascii"), headers=headers)
    if "error" in body:
        code = body.get("error")
        raise OidcError(PROVIDER_ERROR, "token endpoint error " + (code if code in _TOKEN_ERROR_CODES else "(other)"))
    token_type = body.get("token_type")
    id_token = body.get("id_token")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise OidcError(PROVIDER_ERROR, "token type is not Bearer")
    if not isinstance(id_token, str) or not id_token:
        raise OidcError(PROVIDER_ERROR, "no ID token")
    access_token = body.get("access_token")
    return TokenResponse(id_token=id_token, access_token=access_token if isinstance(access_token, str) else None,
                         token_type=token_type)


# --------------------------------------------------------------------------- tokens

def _header(token: str) -> dict:
    try:
        return jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise OidcError(TOKEN_INVALID, "header unreadable") from exc


def _key_for(provider, discovery, header, *, fetch, cache, resolve, now, stale_ok: bool = True):
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise OidcError(TOKEN_INVALID, "algorithm not allowed")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise OidcError(TOKEN_INVALID, "no key id")
    keys = signing_keys(provider, discovery, kid=kid, fetch=fetch, cache=cache, resolve=resolve, now=now,
                        stale_ok=stale_ok)
    jwk = keys.get(kid)
    if jwk is None:
        raise OidcError(TOKEN_INVALID, "unknown key id")
    try:
        return jwt.PyJWK(jwk, algorithm=alg).key, alg
    except jwt.PyJWTError as exc:
        raise OidcError(TOKEN_INVALID, "key unusable") from exc


def _decode(token: str, key, alg: str, *, issuer: str, audience: str, now: float, require: Iterable[str],
            ahead: str = TOKEN_INVALID) -> dict:
    """Signature, required claims, issuer and audience by PyJWT; the time claims by :func:`_check_times` against
    the caller's clock (PyJWT would read the wall clock itself, and one clock must rule every check)."""
    try:
        claims = jwt.decode(token, key=key, algorithms=[alg], issuer=issuer, audience=audience,
                            options={"require": list(require), "verify_signature": True, "verify_exp": False,
                                     "verify_iat": False, "verify_nbf": False, "verify_iss": True, "verify_aud": True})
    except jwt.InvalidIssuerError as exc:
        raise OidcError(ISSUER_MISMATCH, "the token's issuer is not the provider's") from exc
    except jwt.PyJWTError as exc:
        raise OidcError(TOKEN_INVALID, type(exc).__name__) from exc
    _check_times(claims, now, ahead)
    return claims


def _check_times(claims: dict, now: float, ahead: str = TOKEN_INVALID) -> None:
    """``exp`` and ``iat`` are required numbers, ``nbf`` a number when present; each gets 60 seconds of skew.

    An ``iat`` ahead of now is refused with ``ahead``: for an ID token the reason that names the provider's clock,
    so the person is told what is wrong; for a logout token an invalid token, as it always was."""
    exp, iat, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf", 0)
    if not all(_is_time(v) for v in (exp, iat, nbf)):
        raise OidcError(TOKEN_INVALID, "a time claim is not a number")
    if exp + SKEW_SECONDS < now:
        raise OidcError(TOKEN_INVALID, "expired")
    if iat > now + SKEW_SECONDS:
        raise OidcError(ahead, "iat in the future")
    if nbf > now + SKEW_SECONDS:
        raise OidcError(TOKEN_INVALID, "not yet valid")


def _is_time(value) -> bool:
    """A finite number of seconds since the epoch, never a bool, NaN or an infinity, and small enough that the
    arithmetic on it cannot overflow (below 2**40, about the year 36800)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value) and 0 <= value < 2 ** 40
    except OverflowError:
        return False


def _check_azp(claims: dict, provider: ProviderConfig) -> None:
    """With several audiences, ``azp`` must name this client (OpenID Connect Core 3.1.3.7, rules 4 and 5)."""
    aud = claims.get("aud")
    audiences = aud if isinstance(aud, list) else [aud]
    if len(audiences) > 1 and claims.get("azp") != provider.client_id:
        raise OidcError(TOKEN_INVALID, "several audiences and azp is not this client")


def _hash_half(value: str) -> str:
    """``at_hash``/``c_hash``: the left half of the hash the signing algorithm uses (SHA-256 for every allowed one)."""
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return _b64(digest[: len(digest) // 2])


def verify_id_token(provider: ProviderConfig, discovery: Discovery, token: str, *, nonce: str,
                    max_age: Optional[int] = None, access_token: Optional[str] = None, code: Optional[str] = None,
                    fetch: Callable = fetch_json, cache: Optional[Cache] = None, resolve=None,
                    now: Optional[float] = None) -> dict:
    """The ID token's claims, or :class:`OidcError`: size under 16 KB; ``alg`` in the allow-list (never ``none``,
    never HMAC); a known ``kid``; the signature; ``iss`` exactly the provider's; ``aud`` containing the client
    id and ``azp`` equal to it when there are several; ``exp``, ``iat`` and ``nbf`` with 60 seconds of skew;
    ``nonce`` equal to the login's; ``auth_time`` present and fresh when re-authentication was asked; ``sub``
    present and at most 255 characters; ``at_hash`` and ``c_hash`` when present."""
    now = time.time() if now is None else now
    if not isinstance(nonce, str) or not nonce:
        raise OidcError(NONCE_MISMATCH, "the login state holds no nonce")
    if not isinstance(token, str) or len(token.encode("utf-8", "ignore")) > MAX_TOKEN_BYTES:
        raise OidcError(TOKEN_INVALID, "token missing or over the size cap")
    header = _header(token)
    key, alg = _key_for(provider, discovery, header, fetch=fetch, cache=cache, resolve=resolve, now=now)
    claims = _decode(token, key, alg, issuer=provider.issuer, audience=provider.client_id, now=now,
                     ahead=PROVIDER_CLOCK_AHEAD,
                     require=("exp", "iat", "iss", "aud", "sub", "nonce"))
    _check_azp(claims, provider)
    if claims.get("nonce") != nonce:
        raise OidcError(NONCE_MISMATCH)
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub or len(sub) > MAX_SUBJECT_LENGTH:
        raise OidcError(TOKEN_INVALID, "sub missing or too long")
    if max_age is not None:
        auth_time = claims.get("auth_time")
        if not _is_time(auth_time):
            raise OidcError(TOKEN_INVALID, "auth_time missing after a re-authentication")
        if auth_time + max_age + SKEW_SECONDS < now:
            raise OidcError(TOKEN_INVALID, "auth_time too old after a re-authentication")
    for claim, value in (("at_hash", access_token), ("c_hash", code)):
        if claim in claims and value is not None and claims[claim] != _hash_half(value):
            raise OidcError(TOKEN_INVALID, f"{claim} mismatch")
    return claims


def verify_logout_token(provider: ProviderConfig, discovery: Discovery, token: str, *, seen_jti: Callable[[str, int], bool],
                        fetch: Callable = fetch_json, cache: Optional[Cache] = None, resolve=None,
                        now: Optional[float] = None) -> dict:
    """A back-channel logout token's claims, or :class:`OidcError`: verified like an ID token, then: the
    ``events`` claim names the back-channel logout event, there is **no** ``nonce``, ``jti`` is present and not
    seen before (``seen_jti(jti, ttl_seconds)`` records it for the token's remaining life and says whether it was
    already there), ``sid`` or ``sub`` is present, and ``iat`` is within two minutes of now (plus the skew)."""
    now = time.time() if now is None else now
    if not isinstance(token, str) or len(token.encode("utf-8", "ignore")) > MAX_TOKEN_BYTES:
        raise OidcError(TOKEN_INVALID, "token missing or over the size cap")
    header = _header(token)
    key, alg = _key_for(provider, discovery, header, fetch=fetch, cache=cache, resolve=resolve, now=now,
                        stale_ok=False)       # posted by anyone: never a key from a stale copy
    claims = _decode(token, key, alg, issuer=provider.issuer, audience=provider.client_id, now=now,
                     require=("exp", "iat", "iss", "aud", "jti", "events"))
    _check_azp(claims, provider)
    events = claims.get("events")
    if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
        raise OidcError(TOKEN_INVALID, "not a back-channel logout event")
    if "nonce" in claims:
        raise OidcError(TOKEN_INVALID, "a logout token carries no nonce")
    if not any(isinstance(claims.get(name), str) and claims.get(name) for name in ("sid", "sub")):
        raise OidcError(TOKEN_INVALID, "neither sid nor sub")             # an empty string names nothing
    if abs(now - claims["iat"]) > LOGOUT_TOKEN_FRESHNESS_SECONDS + SKEW_SECONDS:
        raise OidcError(TOKEN_INVALID, "logout token is not fresh")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti or len(jti) > 255:
        raise OidcError(TOKEN_INVALID, "no usable jti")
    remaining = max(1, int(claims["exp"] + SKEW_SECONDS - now))
    if seen_jti(jti, remaining):
        raise OidcError(TOKEN_INVALID, "logout token replayed")
    return claims


def userinfo(provider: ProviderConfig, discovery: Discovery, access_token: str, *, expected_sub: str,
             fetch: Callable = fetch_json, resolve=None) -> dict:
    """The provider's ``userinfo`` answer for the access token, as JSON; its ``sub`` must be the ID token's."""
    if not discovery.userinfo_endpoint:
        raise OidcError(DISCOVERY_INVALID, "no userinfo endpoint")
    check_endpoint(discovery.userinfo_endpoint, private_network=provider.private_network, resolve=resolve)
    body = _reach(provider, fetch, discovery.userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
    if body.get("sub") != expected_sub:
        raise OidcError(TOKEN_INVALID, "userinfo sub is not the ID token's")
    return body


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
