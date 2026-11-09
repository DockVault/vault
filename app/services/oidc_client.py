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
before the connection rather than pinned into it. A name that flips to a private address between the two lookups
reaches an internal host only through a TLS handshake that must present a certificate valid for the provider's
name, which an attacker who merely controls that name cannot place inside the network.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import ipaddress
import json
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

ALLOWED_ALGS = ("RS256", "PS256", "ES256")
SKEW_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 10
MAX_BODY_BYTES = 256 * 1024
MAX_TOKEN_BYTES = 16 * 1024
MAX_SUBJECT_LENGTH = 255
CACHE_SECONDS = 3600
DISCOVERY_FAILURE_SECONDS = 30   # a provider that could not be reached is not asked again for this long
# The failures remembered for that long: the network, and an address that could not be resolved or is refused.
REMEMBERED_FAILURES = frozenset({"temporarily_unavailable", "endpoint_refused"})


def _where(*parts: str) -> str:
    """A short digest of what a cached answer was fetched for, so an answer is never served for another address or
    issuer configured later under the same provider id."""
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
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
    client_secret: str
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


def resolved_address_problem(url: str, *, private_network: bool = False, resolve=None) -> Optional[str]:
    """At use: the host must resolve, and (without ``private_network``) to public addresses only."""
    host = urllib.parse.urlsplit(url).hostname or ""
    resolve = resolve or _resolve
    try:
        addresses = resolve(host)
    except OSError:
        return "the endpoint's name does not resolve"
    if not addresses:
        return "the endpoint's name does not resolve"
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
    """Raise :class:`OidcError` (``endpoint_refused``) unless ``url`` passes both rules."""
    why = endpoint_problem(url, private_network=private_network)
    if why is None:
        why = resolved_address_problem(url, private_network=private_network, resolve=resolve)
    if why is not None:
        raise OidcError(ENDPOINT_REFUSED, why)


# --------------------------------------------------------------------------- outbound HTTP

class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        raise urllib.error.HTTPError(req.full_url, code, "redirects are not followed", headers, fp)


# https only: no file, ftp, data or plain-http handler can ever answer, whatever the address.
_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(), _NoRedirects())


def fetch_json(url: str, *, method: str = "GET", data: Optional[bytes] = None, headers: Optional[dict] = None,
               timeout: int = HTTP_TIMEOUT_SECONDS, opener=None) -> dict:
    """GET or POST ``url`` and return its JSON object: TLS verified against the image's trust store, a short
    timeout, a body cap, no redirects, a fixed user agent. Any failure is ``temporarily_unavailable`` (the
    provider's answer is logged, never shown) except a non-JSON or non-object body, which is ``provider_error``."""
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
    rule. Cached an hour."""
    cache = _cache(cache)
    url = discovery_url(provider)
    where = _where(provider.issuer, url)
    key = f"sso:disc:{provider.id}:{where}"
    if not refresh:
        cached = cache.get(key, now)
        if cached is not None:
            return cached
    failed_key = f"sso:disc-failed:{provider.id}:{where}"
    if not refresh and cache.get(failed_key, now) is not None:
        # Unreachable moments ago (the network, or a name that would not resolve): every request in the meantime
        # would wait out the same timeout, the name lookup included.
        raise OidcError(TEMPORARILY_UNAVAILABLE, "the provider could not be reached moments ago")
    try:
        check_endpoint(url, private_network=provider.private_network, resolve=resolve)
        doc = fetch(url)
    except OidcError as exc:
        if exc.code in REMEMBERED_FAILURES:
            cache.set(failed_key, True, DISCOVERY_FAILURE_SECONDS, now)
        raise
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
    cache.set(key, found, CACHE_SECONDS, now)
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
                 now: Optional[float] = None) -> Dict[str, dict]:
    """The provider's signing keys by ``kid`` (RSA or EC, for signing, with a key id), cached an hour. When a
    token names a ``kid`` the cache does not hold, the set is fetched again once, at most once a minute per
    provider; a key still unknown after that fetch is a refusal for the caller. A key unknown while a refetch is
    throttled, or while the key set could not be fetched moments ago, is not the token's fault: that answers
    ``TEMPORARILY_UNAVAILABLE`` (the key may be newer than the last fetch)."""
    cache = _cache(cache)
    where = _where(discovery.jwks_uri)
    key = f"sso:jwks:{provider.id}:{where}"
    keys = cache.get(key, now)
    if keys is not None and (kid is None or kid in keys):
        return keys
    failed_key = f"sso:jwks-failed:{provider.id}:{where}"
    if cache.get(failed_key, now) is not None:
        raise OidcError(TEMPORARILY_UNAVAILABLE, "the provider's keys could not be fetched moments ago")
    refetch_key = f"sso:jwks-refetch:{provider.id}:{where}"
    refetching = keys is not None and kid is not None
    if refetching and cache.get(refetch_key, now) is not None:
        raise OidcError(TEMPORARILY_UNAVAILABLE, "the provider's keys were fetched moments ago without that key")
    try:
        check_endpoint(discovery.jwks_uri, private_network=provider.private_network, resolve=resolve)
        keys = _usable_keys(fetch(discovery.jwks_uri))
    except OidcError as exc:
        if exc.code in REMEMBERED_FAILURES:
            cache.set(failed_key, True, DISCOVERY_FAILURE_SECONDS, now)
        raise
    cache.set(key, keys, CACHE_SECONDS, now)
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
    body = fetch(discovery.token_endpoint, method="POST", data=urllib.parse.urlencode(form).encode("ascii"),
                 headers=headers)
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


def _key_for(provider, discovery, header, *, fetch, cache, resolve, now):
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise OidcError(TOKEN_INVALID, "algorithm not allowed")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise OidcError(TOKEN_INVALID, "no key id")
    keys = signing_keys(provider, discovery, kid=kid, fetch=fetch, cache=cache, resolve=resolve, now=now)
    jwk = keys.get(kid)
    if jwk is None:
        raise OidcError(TOKEN_INVALID, "unknown key id")
    try:
        return jwt.PyJWK(jwk, algorithm=alg).key, alg
    except jwt.PyJWTError as exc:
        raise OidcError(TOKEN_INVALID, "key unusable") from exc


def _decode(token: str, key, alg: str, *, issuer: str, audience: str, now: float, require: Iterable[str]) -> dict:
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
    _check_times(claims, now)
    return claims


def _check_times(claims: dict, now: float) -> None:
    """``exp`` and ``iat`` are required numbers, ``nbf`` a number when present; each gets 60 seconds of skew."""
    exp, iat, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf", 0)
    if not all(_is_time(v) for v in (exp, iat, nbf)):
        raise OidcError(TOKEN_INVALID, "a time claim is not a number")
    if exp + SKEW_SECONDS < now:
        raise OidcError(TOKEN_INVALID, "expired")
    if iat > now + SKEW_SECONDS:
        raise OidcError(TOKEN_INVALID, "iat in the future")
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
    key, alg = _key_for(provider, discovery, header, fetch=fetch, cache=cache, resolve=resolve, now=now)
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
    body = fetch(discovery.userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
    if body.get("sub") != expected_sub:
        raise OidcError(TOKEN_INVALID, "userinfo sub is not the ID token's")
    return body


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
