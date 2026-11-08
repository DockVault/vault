"""The OpenID Connect client (app/services/oidc_client.py) against a local signer: discovery and its rules, the
endpoint rule, the authorization request, the code exchange, and every ID token and logout token check by its
reason. Offline: the fetch is a fake, the clock is the test's."""
import base64
import hashlib
import json
import time
import urllib.error

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

ISSUER = "https://idp.example.com/realms/dv"
CLIENT = "vault"
NOW = 1_800_000_000.0


def _oc():
    set_bare_api_env()
    from app.services import oidc_client as oc
    return oc


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Signer:
    """A provider's keys and documents."""

    def __init__(self):
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.hs = b"s" * 32

    def jwks(self, *, with_rsa=True, with_ec=True, extra=()):
        keys = []
        if with_rsa:
            keys.append({**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.rsa.public_key())), "kid": "rsa1", "use": "sig"})
        if with_ec:
            keys.append({**json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self.ec.public_key())), "kid": "ec1"})
        keys.extend(extra)
        return {"keys": keys}

    def discovery(self, **overrides):
        doc = {
            "issuer": ISSUER, "authorization_endpoint": ISSUER + "/protocol/openid-connect/auth",
            "token_endpoint": ISSUER + "/protocol/openid-connect/token", "jwks_uri": ISSUER + "/protocol/openid-connect/certs",
            "userinfo_endpoint": ISSUER + "/protocol/openid-connect/userinfo",
            "end_session_endpoint": ISSUER + "/protocol/openid-connect/logout",
            "id_token_signing_alg_values_supported": ["RS256", "ES256", "HS256"],
            "code_challenge_methods_supported": ["plain", "S256"], "backchannel_logout_supported": True,
            "authorization_response_iss_parameter_supported": True, "claims_supported": ["sub", "email"],
            "acr_values_supported": ["1", "2"],
        }
        doc.update(overrides)
        return {k: v for k, v in doc.items() if v is not ...}

    def token(self, claims, *, alg="RS256", kid="rsa1", headers=None):
        key = {"RS256": self.rsa, "PS256": self.rsa, "ES256": self.ec, "HS256": self.hs}[alg]
        hdr = {"kid": kid} if kid is not None else {}
        hdr.update(headers or {})
        return jwt.encode(claims, key, algorithm=alg, headers=hdr)

    def id_claims(self, **overrides):
        claims = {"iss": ISSUER, "sub": "user-1", "aud": CLIENT, "exp": NOW + 300, "iat": NOW - 5, "nonce": "n1",
                  "auth_time": NOW - 10, "email": "a@example.com"}
        claims.update(overrides)
        return {k: v for k, v in claims.items() if v is not ...}


def _provider(oc, **kw):
    base = dict(id="p1", issuer=ISSUER, client_id=CLIENT, client_secret="s3cret")
    base.update(kw)
    return oc.ProviderConfig(**base)


def _fetch_for(signer, *, discovery=None, jwks=None, calls=None):
    calls = calls if calls is not None else []

    def fetch(url, **kw):
        calls.append((url, kw))
        if url.endswith("openid-configuration"):
            return signer.discovery() if discovery is None else discovery
        if url.endswith("/certs"):
            return signer.jwks() if jwks is None else jwks
        raise AssertionError(url)
    fetch.calls = calls
    return fetch


# A genuinely public address: the documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24) count as private.
_PUBLIC = lambda host: ["8.8.8.8"]  # noqa: E731


@pytest.fixture(autouse=True)
def _fresh_default_cache(monkeypatch):
    oc = _oc()
    monkeypatch.setattr(oc, "_DEFAULT_CACHE", oc.Cache())


def _disc(oc, signer, **kw):
    return oc.discover(_provider(oc), fetch=_fetch_for(signer, **kw), cache=oc.Cache(), resolve=_PUBLIC, now=NOW)


# --------------------------------------------------------------------------- the endpoint rule

def test_endpoints_must_be_https_on_a_public_name_unless_the_provider_is_private():
    oc = _oc()
    assert oc.endpoint_problem("https://idp.example.com/auth") is None
    for bad, words in (("http://idp.example.com", "https"), ("https://10.0.0.5/auth", "IP"),
                       ("https://[::1]/auth", "IP"), ("https://localhost/auth", "private"),
                       ("https://idp.local/auth", "private"), ("https://idp.internal/auth", "private"),
                       ("https://u:p@idp.example.com", "user name"), ("", "missing"), (None, "missing"),
                       ("https://idp.example.com:99999", "port")):
        why = oc.endpoint_problem(bad)
        assert why and words in why, (bad, why)
    assert oc.endpoint_problem("https://10.0.0.5/auth", private_network=True) is None
    assert oc.endpoint_problem("https://idp.internal/auth", private_network=True) is None
    assert oc.endpoint_problem("http://idp.internal/auth", private_network=True)      # never plain http
    # At use: the name must resolve to public addresses.
    assert oc.resolved_address_problem("https://idp.example.com", resolve=lambda h: ["8.8.8.8", "2001:4860:4860::8888"]) is None
    for private in (["10.1.2.3"], ["127.0.0.1"], ["169.254.1.1"], ["fd00::1"], ["8.8.8.8", "192.168.1.1"],
                    ["203.0.113.10"], ["0.0.0.0"], ["224.0.0.1"], ["::1"], ["100.64.1.1"], ["100.127.255.254"]):
        assert "private" in oc.resolved_address_problem("https://idp.example.com", resolve=lambda h, p=private: p)
    assert oc.resolved_address_problem("https://idp.example.com", resolve=lambda h, p=["10.1.2.3"]: p, private_network=True) is None
    assert "resolve" in oc.resolved_address_problem("https://idp.example.com", resolve=lambda h: [])

    def _fails(h):
        raise OSError("no such host")
    assert "resolve" in oc.resolved_address_problem("https://idp.example.com", resolve=_fails)
    with pytest.raises(oc.OidcError) as e:
        oc.check_endpoint("https://idp.example.com", resolve=lambda h: ["10.0.0.1"])
    assert e.value.code == "endpoint_refused"


# --------------------------------------------------------------------------- discovery and keys

def test_discovery_is_checked_and_cached():
    oc = _oc()
    signer = Signer()
    fetch = _fetch_for(signer)
    cache = oc.Cache()
    d = oc.discover(_provider(oc), fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW)
    assert d.issuer == ISSUER and d.code_challenge_methods == ("plain", "S256") and d.backchannel_logout_supported
    assert d.iss_in_callback and d.acr_values_supported == ("1", "2") and d.id_token_signing_algs == ("RS256", "ES256", "HS256")
    assert oc.discover(_provider(oc), fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 100) is d
    assert len(fetch.calls) == 1
    oc.discover(_provider(oc), fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 3601)
    assert len(fetch.calls) == 2
    oc.discover(_provider(oc), fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 3602, refresh=True)
    assert len(fetch.calls) == 3
    # Without a caller's cache the process's own serves: two discoveries, one fetch.
    fetch2 = _fetch_for(signer)
    oc.discover(_provider(oc), fetch=fetch2, resolve=_PUBLIC, now=NOW)
    oc.discover(_provider(oc), fetch=fetch2, resolve=_PUBLIC, now=NOW + 10)
    assert len(fetch2.calls) == 1
    # The default discovery address is the issuer's well-known one; a configured one is used instead.
    assert oc.discovery_url(_provider(oc)) == ISSUER + "/.well-known/openid-configuration"
    assert oc.discovery_url(_provider(oc, discovery_url="https://inside.example.com/x")) == "https://inside.example.com/x"


@pytest.mark.parametrize("override,code", [
    ({"issuer": ISSUER + "/"}, "issuer_mismatch"),
    ({"issuer": "https://evil.example.com"}, "issuer_mismatch"),
    ({"token_endpoint": ...}, "discovery_invalid"),
    ({"jwks_uri": 5}, "discovery_invalid"),
    ({"id_token_signing_alg_values_supported": ["HS256"]}, "discovery_invalid"),
    ({"id_token_signing_alg_values_supported": [["RS256"]]}, "discovery_invalid"),
    ({"id_token_signing_alg_values_supported": "RS256"}, "discovery_invalid"),
    ({"code_challenge_methods_supported": ["plain"]}, "discovery_invalid"),
    ({"token_endpoint": "http://idp.example.com/token"}, "endpoint_refused"),
    ({"userinfo_endpoint": "https://10.0.0.9/userinfo"}, "endpoint_refused"),
])
def test_a_discovery_document_that_breaks_a_rule_is_refused(override, code):
    oc = _oc()
    signer = Signer()
    with pytest.raises(oc.OidcError) as e:
        _disc(oc, signer, discovery=signer.discovery(**override))
    assert e.value.code == code


def test_absent_pkce_methods_are_unknown_not_refused_and_a_private_provider_may_be_inside():
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer, discovery=signer.discovery(code_challenge_methods_supported=...))
    assert d.code_challenge_methods is None
    doc = signer.discovery(token_endpoint="https://10.0.0.9/token")
    with pytest.raises(oc.OidcError):
        _disc(oc, signer, discovery=doc)
    d = oc.discover(_provider(oc, private_network=True), fetch=_fetch_for(signer, discovery=doc),
                    resolve=lambda h: ["10.0.0.9"], now=NOW)
    assert d.token_endpoint == "https://10.0.0.9/token"


def test_only_signing_keys_with_an_id_are_kept_and_an_unknown_kid_refetches_once_a_minute():
    oc = _oc()
    signer = Signer()
    extra = [{"kty": "oct", "kid": "sym", "k": "AAAA"}, {"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"},
             {"kty": "RSA", "n": "AQAB", "e": "AQAB"}]
    fetch = _fetch_for(signer, jwks=signer.jwks(extra=extra))
    cache = oc.Cache()
    d = _disc(oc, signer)
    keys = oc.signing_keys(_provider(oc), d, fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW)
    assert set(keys) == {"rsa1", "ec1"}
    fetched = len(fetch.calls)
    # A known kid: no fetch. An unknown one: one refetch, then not again for a minute.
    oc.signing_keys(_provider(oc), d, kid="rsa1", fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 1)
    assert len(fetch.calls) == fetched
    oc.signing_keys(_provider(oc), d, kid="nope", fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 2)
    assert len(fetch.calls) == fetched + 1
    oc.signing_keys(_provider(oc), d, kid="nope", fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 30)
    assert len(fetch.calls) == fetched + 1
    oc.signing_keys(_provider(oc), d, kid="nope", fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 70)
    assert len(fetch.calls) == fetched + 2
    # The limiter holds without a caller's cache too (the process's own): five unknown kids, one fetch after the first.
    fetch3 = _fetch_for(signer)
    oc.signing_keys(_provider(oc, id="p2"), d, fetch=fetch3, resolve=_PUBLIC, now=NOW)
    for i in range(5):
        oc.signing_keys(_provider(oc, id="p2"), d, kid="nope", fetch=fetch3, resolve=_PUBLIC, now=NOW + 1 + i)
    assert len(fetch3.calls) == 2


# --------------------------------------------------------------------------- the request and the exchange

def test_the_authorization_request_carries_pkce_state_and_nonce():
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)
    verifier = oc.make_code_verifier()
    assert 43 <= len(verifier) <= 128 and oc.code_challenge(verifier) == _b64(hashlib.sha256(verifier.encode()).digest())
    url = oc.authorization_url(_provider(oc), d, redirect_uri="https://vault.example.com/auth/sso/p1/callback",
                               state="st", nonce="no", code_verifier=verifier, resolve=_PUBLIC)
    from urllib.parse import parse_qs, urlsplit
    parts = urlsplit(url)
    q = parse_qs(parts.query)
    assert parts.scheme == "https" and parts.path.endswith("/auth")
    assert q["response_type"] == ["code"] and q["client_id"] == [CLIENT] and q["scope"] == ["openid profile email"]
    assert q["redirect_uri"] == ["https://vault.example.com/auth/sso/p1/callback"] and q["state"] == ["st"]
    assert q["nonce"] == ["no"] and q["code_challenge"] == [oc.code_challenge(verifier)]
    assert q["code_challenge_method"] == ["S256"] and "prompt" not in q and "max_age" not in q
    url = oc.authorization_url(_provider(oc), d, redirect_uri="https://v/cb", state="s", nonce="n", code_verifier=verifier,
                               reauthenticate=True, acr_values="2", login_hint="alice", resolve=_PUBLIC)
    q = parse_qs(urlsplit(url).query)
    assert q["prompt"] == ["login"] and q["max_age"] == ["0"] and q["acr_values"] == ["2"] and q["login_hint"] == ["alice"]
    # Secrets never ride in the request.
    assert "s3cret" not in url
    # A scope list without openid gets it back: without it the provider answers with no ID token at all.
    url = oc.authorization_url(_provider(oc, scopes="profile email"), d, redirect_uri="https://v/cb", state="s", nonce="n",
                               code_verifier=verifier, resolve=_PUBLIC)
    assert parse_qs(urlsplit(url).query)["scope"] == ["openid profile email"]


def test_the_code_exchange_posts_the_verifier_and_authenticates_the_client():
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)
    seen = []

    def fetch(url, method="GET", data=None, headers=None, **kw):
        seen.append((url, method, data, headers))
        return {"token_type": "bearer", "id_token": "x.y.z", "access_token": "at"}

    out = oc.exchange_code(_provider(oc), d, code="c0de", redirect_uri="https://v/cb", code_verifier="v" * 43,
                           fetch=fetch, resolve=_PUBLIC)
    assert out.id_token == "x.y.z" and out.access_token == "at"
    url, method, data, headers = seen[0]
    from urllib.parse import parse_qs
    form = parse_qs(data.decode())
    assert url == d.token_endpoint and method == "POST"
    assert form["grant_type"] == ["authorization_code"] and form["code"] == ["c0de"] and form["code_verifier"] == ["v" * 43]
    assert "client_secret" not in form
    assert headers["Authorization"] == "Basic " + base64.b64encode(b"vault:s3cret").decode()
    oc.exchange_code(_provider(oc, token_auth="client_secret_post"), d, code="c", redirect_uri="r", code_verifier="v" * 43,
                     fetch=fetch, resolve=_PUBLIC)
    form = parse_qs(seen[1][2].decode())
    assert form["client_secret"] == ["s3cret"] and "Authorization" not in seen[1][3]

    def bad(url, **kw):
        return {"token_type": "mac", "id_token": "x"}
    with pytest.raises(oc.OidcError) as e:
        oc.exchange_code(_provider(oc), d, code="c", redirect_uri="r", code_verifier="v" * 43, fetch=bad, resolve=_PUBLIC)
    assert e.value.code == "provider_error"

    def error(url, **kw):
        return {"error": "invalid_grant", "error_description": "secret stuff"}
    with pytest.raises(oc.OidcError) as e:
        oc.exchange_code(_provider(oc), d, code="c", redirect_uri="r", code_verifier="v" * 43, fetch=error, resolve=_PUBLIC)
    assert e.value.code == "provider_error" and "secret stuff" not in str(e.value)
    assert e.value.detail == "token endpoint error invalid_grant"      # a known RFC 6749 code, never free text

    def hostile(url, **kw):
        return {"error": "E" * 100000}
    with pytest.raises(oc.OidcError) as e:
        oc.exchange_code(_provider(oc), d, code="c", redirect_uri="r", code_verifier="v" * 43, fetch=hostile, resolve=_PUBLIC)
    assert e.value.detail == "token endpoint error (other)" and len(str(e.value)) < 80
    # At use the token endpoint's address is vetted again, with the resolver of the moment.
    with pytest.raises(oc.OidcError) as e:
        oc.exchange_code(_provider(oc), d, code="c", redirect_uri="r", code_verifier="v" * 43, fetch=fetch,
                         resolve=lambda h: ["10.0.0.7"])
    assert e.value.code == "endpoint_refused"


def test_fetch_follows_no_redirect_caps_the_body_and_never_shows_the_providers_text():
    oc = _oc()

    class _Resp:
        def __init__(self, body):
            self.body, self.at = body, 0

        def read(self, n):
            chunk = self.body[self.at:self.at + n]
            self.at += len(chunk)
            return chunk

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class _Opener:
        def __init__(self, body=None, exc=None):
            self.body, self.exc, self.requests = body, exc, []

        def open(self, request, timeout=None):
            self.requests.append((request, timeout))
            if self.exc:
                raise self.exc
            return _Resp(self.body)

    opener = _Opener(body=b'{"a": 1}')
    assert oc.fetch_json("https://idp.example.com/x", opener=opener) == {"a": 1}
    request, timeout = opener.requests[0]
    assert timeout == 10 and request.get_header("Accept") == "application/json"
    assert request.get_header("User-agent") == "DockVault"
    with pytest.raises(oc.OidcError) as e:
        oc.fetch_json("https://idp.example.com/x", opener=_Opener(body=b"x" * (256 * 1024 + 1)))
    assert e.value.code == "temporarily_unavailable"
    with pytest.raises(oc.OidcError) as e:
        oc.fetch_json("https://idp.example.com/x", opener=_Opener(body=b"[1,2]"))
    assert e.value.code == "provider_error"
    redirect = urllib.error.HTTPError("https://idp.example.com/x", 302, "redirects are not followed", {}, None)
    with pytest.raises(oc.OidcError) as e:
        oc.fetch_json("https://idp.example.com/x", opener=_Opener(exc=redirect))
    assert e.value.code == "temporarily_unavailable"
    with pytest.raises(oc.OidcError) as e:
        oc.fetch_json("https://idp.example.com/x", opener=_Opener(exc=urllib.error.URLError("timed out")))
    assert e.value.code == "temporarily_unavailable"
    # A hostile wire answer (bad status line, too many headers, a cut-off body) is an outage, never a crash.
    import http.client
    for exc in (http.client.BadStatusLine("x"), http.client.LineTooLong("header"), http.client.IncompleteRead(b"")):
        with pytest.raises(oc.OidcError) as e:
            oc.fetch_json("https://idp.example.com/x", opener=_Opener(exc=exc))
        assert e.value.code == "temporarily_unavailable"
    # A body nested deeper than the parser can take, under the cap, is a provider error.
    with pytest.raises(oc.OidcError) as e:
        oc.fetch_json("https://idp.example.com/x", opener=_Opener(body=b"[" * 100000))
    assert e.value.code == "provider_error"
    # Only https is ever fetched, whatever a caller passes.
    for url in ("http://idp.example.com/x", "file:///etc/passwd", "ftp://idp.example.com/x", "data:application/json,{}"):
        with pytest.raises(oc.OidcError) as e:
            oc.fetch_json(url, opener=_Opener(body=b"{}"))
        assert e.value.code == "endpoint_refused", url
    # The whole answer must arrive within the timeout, however slowly the bytes trickle.

    class _Trickle(_Resp):
        def __init__(self):
            self.n = 0

        def read(self, n):
            self.n += 1
            return b"{" if self.n == 1 else b" "

    class _TrickleOpener(_Opener):
        def open(self, request, timeout=None):
            return _Trickle()
    clock = iter([0.0, 0.0, 0.0, 100.0])
    real_monotonic = oc.time.monotonic
    oc.time.monotonic = lambda: next(clock, 100.0)
    try:
        with pytest.raises(oc.OidcError) as e:
            oc.fetch_json("https://idp.example.com/x", opener=_TrickleOpener())
    finally:
        oc.time.monotonic = real_monotonic
    assert e.value.detail == "the answer took too long"
    # The redirect handler the real opener uses refuses to follow.
    handler = oc._NoRedirects()
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(urllib.request.Request("https://idp.example.com/x"), None, 302, "Found", {}, "https://evil/")


# --------------------------------------------------------------------------- the ID token

def _verify(oc, signer, token, **kw):
    kw.setdefault("nonce", "n1")
    kw.setdefault("now", NOW)
    return oc.verify_id_token(_provider(oc), _disc(oc, signer), token, fetch=_fetch_for(signer), resolve=_PUBLIC, **kw)


@pytest.mark.parametrize("alg,kid", [("RS256", "rsa1"), ("PS256", "rsa1"), ("ES256", "ec1")])
def test_a_good_id_token_is_accepted_for_every_allowed_algorithm(alg, kid):
    oc = _oc()
    signer = Signer()
    claims = _verify(oc, signer, signer.token(signer.id_claims(), alg=alg, kid=kid))
    assert claims["sub"] == "user-1" and claims["email"] == "a@example.com"


def _tamper(token, changes):
    """The same signature over a payload that was changed afterwards."""
    h, p, s = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    payload.update(changes)
    return h + "." + _b64(json.dumps(payload).encode()) + "." + s


def _raw_token(header: dict, payload: dict) -> str:
    """A token assembled by hand (a header PyJWT would refuse to write), with a signature of the right length."""
    return ".".join([_b64(json.dumps(header).encode()), _b64(json.dumps(payload).encode()), _b64(b"s" * 256)])


@pytest.mark.parametrize("make,code", [
    (lambda s: s.token(s.id_claims(), alg="HS256", kid="rsa1"), "token_invalid"),
    (lambda s: jwt.encode(s.id_claims(), None, algorithm="none"), "token_invalid"),
    (lambda s: s.token(s.id_claims(), kid=None), "token_invalid"),
    (lambda s: s.token(s.id_claims(), kid="unknown"), "token_invalid"),
    (lambda s: s.token(s.id_claims(), alg="ES256", kid="rsa1"), "token_invalid"),          # key of another kind
    (lambda s: s.token(s.id_claims(iss="https://evil.example.com")), "issuer_mismatch"),
    (lambda s: s.token(s.id_claims(iss=ISSUER + "/")), "issuer_mismatch"),
    (lambda s: s.token(s.id_claims(aud="other")), "token_invalid"),
    (lambda s: s.token(s.id_claims(aud=[CLIENT, "other"])), "token_invalid"),                 # several, no azp
    (lambda s: s.token(s.id_claims(aud=[CLIENT, "other"], azp="other")), "token_invalid"),
    (lambda s: s.token(s.id_claims(exp=NOW - 61)), "token_invalid"),
    (lambda s: s.token(s.id_claims(iat=NOW + 61)), "token_invalid"),
    (lambda s: s.token(s.id_claims(nbf=NOW + 61)), "token_invalid"),
    (lambda s: s.token(s.id_claims(nonce="other")), "nonce_mismatch"),
    (lambda s: s.token(s.id_claims(exp=float("nan"))), "token_invalid"),
    (lambda s: s.token(s.id_claims(iat=True)), "token_invalid"),
    (lambda s: s.token(s.id_claims(nbf=True)), "token_invalid"),
    (lambda s: s.token(s.id_claims(iat=-10 ** 400)), "token_invalid"),
    (lambda s: s.token(s.id_claims(exp=10 ** 400)), "token_invalid"),
    (lambda s: s.token(s.id_claims(nbf=float("inf"))), "token_invalid"),
    (lambda s: s.token(s.id_claims(nonce=...)), "token_invalid"),
    (lambda s: s.token(s.id_claims(sub=...)), "token_invalid"),
    (lambda s: s.token(s.id_claims(sub="x" * 256)), "token_invalid"),
    (lambda s: s.token(s.id_claims(exp=...)), "token_invalid"),
    (lambda s: s.token(s.id_claims(iat=...)), "token_invalid"),
    (lambda s: "not.a.token", "token_invalid"),
    (lambda s: s.token(s.id_claims(pad="x" * 17000)), "token_invalid"),
    # Signed by someone else's key under the provider's kid, and a payload changed after signing.
    (lambda s: Signer().token(s.id_claims(), kid="rsa1"), "token_invalid"),
    (lambda s: _tamper(s.token(s.id_claims()), {"sub": "user-2"}), "token_invalid"),
])
def test_an_id_token_that_breaks_a_rule_is_refused(make, code):
    oc = _oc()
    signer = Signer()
    with pytest.raises(oc.OidcError) as e:
        _verify(oc, signer, make(signer))
    assert e.value.code == code


def test_the_refusal_names_its_reason_for_the_log():
    oc = _oc()
    signer = Signer()
    for make, detail in ((lambda: signer.token(signer.id_claims(), kid=None), "no key id"),
                         (lambda: signer.token(signer.id_claims(), kid="unknown"), "unknown key id"),
                         (lambda: signer.token(signer.id_claims(), alg="HS256", kid="rsa1"), "algorithm not allowed"),
                         (lambda: _raw_token({"alg": "<script>" + "A" * 3000, "kid": "rsa1", "typ": "JWT"},
                                             signer.id_claims()), "algorithm not allowed"),
                         (lambda: signer.token(signer.id_claims(exp=NOW - 61)), "expired"),
                         (lambda: signer.token(signer.id_claims(sub="x" * 256)), "sub missing or too long")):
        with pytest.raises(oc.OidcError) as e:
            _verify(oc, signer, make())
        assert e.value.detail == detail


def test_the_skew_azp_hashes_and_auth_time_rules():
    oc = _oc()
    signer = Signer()
    # Inside the skew: accepted.
    _verify(oc, signer, signer.token(signer.id_claims(exp=NOW - 30)))
    _verify(oc, signer, signer.token(signer.id_claims(iat=NOW + 30, nbf=NOW + 30)))
    # Several audiences with azp = this client: accepted.
    _verify(oc, signer, signer.token(signer.id_claims(aud=[CLIENT, "other"], azp=CLIENT)))
    # at_hash and c_hash are checked when present.
    at = "access-token"
    good = _b64(hashlib.sha256(at.encode()).digest()[:16])
    _verify(oc, signer, signer.token(signer.id_claims(at_hash=good)), access_token=at)
    with pytest.raises(oc.OidcError) as e:
        _verify(oc, signer, signer.token(signer.id_claims(at_hash="bad")), access_token=at)
    assert e.value.code == "token_invalid"
    with pytest.raises(oc.OidcError):
        _verify(oc, signer, signer.token(signer.id_claims(c_hash="bad")), code="c0de")
    # An empty or missing nonce on the vault's side is refused before anything is read.
    for empty in ("", None):
        with pytest.raises(oc.OidcError) as e:
            _verify(oc, signer, signer.token(signer.id_claims(nonce="")), nonce=empty)
        assert e.value.code == "nonce_mismatch"
    # auth_time is required and fresh only when re-authentication was asked.
    _verify(oc, signer, signer.token(signer.id_claims(auth_time=...)))
    with pytest.raises(oc.OidcError):
        _verify(oc, signer, signer.token(signer.id_claims(auth_time=float("nan"))), max_age=0)
    with pytest.raises(oc.OidcError):
        _verify(oc, signer, signer.token(signer.id_claims(auth_time=...)), max_age=0)
    _verify(oc, signer, signer.token(signer.id_claims(auth_time=NOW - 30)), max_age=0)
    with pytest.raises(oc.OidcError):
        _verify(oc, signer, signer.token(signer.id_claims(auth_time=NOW - 200)), max_age=0)


def test_a_key_rotation_is_followed_once():
    oc = _oc()
    signer = Signer()
    cache = oc.Cache()
    d = _disc(oc, signer)
    old_fetch = _fetch_for(signer)
    oc.signing_keys(_provider(oc), d, fetch=old_fetch, cache=cache, resolve=_PUBLIC, now=NOW)
    rotated = Signer()
    new_jwks = rotated.jwks()
    new_jwks["keys"][0]["kid"] = "rsa2"
    fetch = _fetch_for(rotated, jwks=new_jwks)
    claims = oc.verify_id_token(_provider(oc), d, rotated.token(rotated.id_claims(), kid="rsa2"), nonce="n1",
                                fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 1)
    assert claims["sub"] == "user-1"


# --------------------------------------------------------------------------- the logout token

def _logout_claims(signer, **overrides):
    claims = {"iss": ISSUER, "aud": CLIENT, "iat": NOW - 5, "exp": NOW + 120, "jti": "j1", "sid": "sid-1",
              "events": {"http://schemas.openid.net/event/backchannel-logout": {}}}
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not ...}


def test_a_logout_token_is_checked_by_its_own_rules():
    oc = _oc()
    signer = Signer()
    seen = {}

    def seen_jti(jti, ttl):
        if jti in seen:
            return True
        seen[jti] = ttl
        return False

    d = _disc(oc, signer)
    good = signer.token(_logout_claims(signer))
    claims = oc.verify_logout_token(_provider(oc), d, good, seen_jti=seen_jti, fetch=_fetch_for(signer), resolve=_PUBLIC, now=NOW)
    assert claims["sid"] == "sid-1"
    assert seen["j1"] == 120 + 60       # kept for the token's remaining life plus the skew
    # Replayed.
    with pytest.raises(oc.OidcError) as e:
        oc.verify_logout_token(_provider(oc), d, good, seen_jti=seen_jti, fetch=_fetch_for(signer), resolve=_PUBLIC, now=NOW)
    assert "replayed" in e.value.detail
    for bad in (_logout_claims(signer, jti="j2", nonce="n"), _logout_claims(signer, jti="j3", events={"other": {}}),
                _logout_claims(signer, jti="j4", events=...), _logout_claims(signer, jti="j5", sid=...),
                _logout_claims(signer, jti=...), _logout_claims(signer, jti="j6", iat=NOW - 200),
                _logout_claims(signer, jti="j7", iss="https://evil.example.com"),
                _logout_claims(signer, jti="j9", iat=-10 ** 400), _logout_claims(signer, jti="j10", iat=float("nan")),
                _logout_claims(signer, jti="j11", aud=[CLIENT, "other"]), _logout_claims(signer, jti="x" * 256)):
        with pytest.raises(oc.OidcError):
            oc.verify_logout_token(_provider(oc), d, signer.token(bad), seen_jti=seen_jti, fetch=_fetch_for(signer),
                                   resolve=_PUBLIC, now=NOW)
    # sub instead of sid is enough.
    oc.verify_logout_token(_provider(oc), d, signer.token(_logout_claims(signer, jti="j8", sid=..., sub="user-1")),
                           seen_jti=seen_jti, fetch=_fetch_for(signer), resolve=_PUBLIC, now=NOW)


def test_userinfo_must_speak_of_the_same_person():
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)

    def fetch(url, headers=None, **kw):
        assert headers == {"Authorization": "Bearer at"}
        return {"sub": "user-1", "groups": ["a"]}
    assert oc.userinfo(_provider(oc), d, "at", expected_sub="user-1", fetch=fetch, resolve=_PUBLIC)["groups"] == ["a"]
    with pytest.raises(oc.OidcError) as e:
        oc.userinfo(_provider(oc), d, "at", expected_sub="user-2", fetch=fetch, resolve=_PUBLIC)
    assert e.value.code == "token_invalid"
    # Vetted again at use.
    with pytest.raises(oc.OidcError) as e:
        oc.userinfo(_provider(oc), d, "at", expected_sub="user-1", fetch=fetch, resolve=lambda h: ["172.16.0.2"])
    assert e.value.code == "endpoint_refused"


def test_every_address_the_vault_calls_or_sends_a_browser_to_is_vetted_at_use():
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)
    private = lambda h: ["10.9.9.9"]  # noqa: E731
    with pytest.raises(oc.OidcError) as e:
        oc.authorization_url(_provider(oc), d, redirect_uri="https://v/cb", state="s", nonce="n",
                             code_verifier=oc.make_code_verifier(), resolve=private)
    assert e.value.code == "endpoint_refused"
    with pytest.raises(oc.OidcError) as e:
        oc.signing_keys(_provider(oc), d, fetch=_fetch_for(signer), cache=oc.Cache(), resolve=private, now=NOW)
    assert e.value.code == "endpoint_refused"
    with pytest.raises(oc.OidcError) as e:
        oc.discover(_provider(oc), fetch=_fetch_for(signer), cache=oc.Cache(), resolve=private, now=NOW)
    assert e.value.code == "endpoint_refused"
