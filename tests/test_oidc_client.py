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
    # A name that does not resolve is the resolver's state (a blip, an outage): temporarily unavailable, not refused.
    for unresolved in (_fails, lambda h: []):
        with pytest.raises(oc.OidcError) as e:
            oc.check_endpoint("https://idp.example.com", resolve=unresolved)
        assert e.value.code == "temporarily_unavailable"


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
    # A known kid: no fetch. An unknown one: one refetch (still unknown: the caller refuses the token), then not again
    # for a minute, during which an unknown key is not the token's fault: the key may be newer than the last fetch.
    oc.signing_keys(_provider(oc), d, kid="rsa1", fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 1)
    assert len(fetch.calls) == fetched
    assert "nope" not in oc.signing_keys(_provider(oc), d, kid="nope", fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 2)
    assert len(fetch.calls) == fetched + 1
    with pytest.raises(oc.OidcError) as e:
        oc.signing_keys(_provider(oc), d, kid="nope", fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 30)
    assert e.value.code == oc.TEMPORARILY_UNAVAILABLE and len(fetch.calls) == fetched + 1
    oc.signing_keys(_provider(oc), d, kid="nope", fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW + 70)
    assert len(fetch.calls) == fetched + 2
    # The limiter holds without a caller's cache too (the process's own): five unknown kids, one fetch after the first.
    fetch3 = _fetch_for(signer)
    oc.signing_keys(_provider(oc, id="p2"), d, fetch=fetch3, resolve=_PUBLIC, now=NOW)
    for i in range(5):
        try:
            oc.signing_keys(_provider(oc, id="p2"), d, kid="nope", fetch=fetch3, resolve=_PUBLIC, now=NOW + 1 + i)
        except oc.OidcError as exc:
            assert exc.code == oc.TEMPORARILY_UNAVAILABLE and i > 0
    assert len(fetch3.calls) == 2


def test_a_refetch_that_fails_on_any_answer_is_not_repeated_per_request():
    """Junk tokens naming random key ids must not each make the vault fetch the key set, whatever the provider
    answers: a refetch that fails, also with a page or an answer without keys, is remembered for 30 seconds."""
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)
    for code in (oc.PROVIDER_ERROR, oc.DISCOVERY_INVALID):
        cache = oc.Cache()
        oc.signing_keys(_provider(oc), d, fetch=_fetch_for(signer), cache=cache, resolve=_PUBLIC, now=NOW)
        calls = []

        def broken(url, _code=code, **kw):
            calls.append(url)
            raise oc.OidcError(_code, "the provider is answering with a page")
        for i in range(10):
            with pytest.raises(oc.OidcError) as e:
                oc.signing_keys(_provider(oc), d, kid=f"junk-{i}", fetch=broken, cache=cache, resolve=_PUBLIC, now=NOW + 1 + i)
            assert e.value.code == code
        assert len(calls) == 1, code
        # Keys already held are still served meanwhile.
        assert "rsa1" in oc.signing_keys(_provider(oc), d, kid="rsa1", fetch=broken, cache=cache, resolve=_PUBLIC, now=NOW + 12)


def test_a_document_that_fails_its_own_checks_is_remembered_like_a_failed_fetch():
    """A discovery document with a wrong issuer, a missing endpoint or an endpoint at a refused address is not
    fetched again on every request: it is answered from memory for a short while, with its own reason."""
    oc = _oc()
    signer = Signer()
    for bad, code in (({"issuer": "https://elsewhere.example.com"}, oc.ISSUER_MISMATCH),
                      ({"jwks_uri": ...}, oc.DISCOVERY_INVALID)):
        cache = oc.Cache()
        fetch = _fetch_for(signer, discovery=signer.discovery(**bad))
        for _ in range(3):
            with pytest.raises(oc.OidcError) as e:
                oc.discover(_provider(oc), fetch=fetch, cache=cache, resolve=_PUBLIC, now=NOW)
            assert e.value.code == code
        assert len(fetch.calls) == 1, code
    # An endpoint inside the document at a refused address.
    cache, looked = oc.Cache(), []

    def resolve(host):
        looked.append(host)
        return ["10.0.0.9"] if "keys.internal" in host else ["8.8.8.8"]
    fetch = _fetch_for(signer, discovery=signer.discovery(jwks_uri="https://keys.internal.example.com/certs"))
    for _ in range(2):
        with pytest.raises(oc.OidcError) as e:
            oc.discover(_provider(oc), fetch=fetch, cache=cache, resolve=resolve, now=NOW)
        assert e.value.code == oc.ENDPOINT_REFUSED
    assert len(fetch.calls) == 1
    # A refresh that fails is remembered again: the next ordinary call is answered from memory.
    cache2 = oc.Cache()
    down_calls = []

    def down(url, **kw):
        down_calls.append(url)
        raise oc.OidcError(oc.TEMPORARILY_UNAVAILABLE, "down")
    with pytest.raises(oc.OidcError):
        oc.discover(_provider(oc), fetch=down, cache=cache2, resolve=_PUBLIC, now=NOW, refresh=True)
    with pytest.raises(oc.OidcError):
        oc.discover(_provider(oc), fetch=down, cache=cache2, resolve=_PUBLIC, now=NOW + 1)
    assert len(down_calls) == 1


def test_the_cache_digest_cannot_be_confused_by_a_separator_inside_an_address():
    oc = _oc()
    p = _provider(oc)
    assert oc._where(p, "https://a|https://b", "c") != oc._where(p, "https://a", "https://b|c")
    assert oc._where(p, "x") != oc._where(_provider(oc, private_network=True), "x")


def test_a_key_set_that_cannot_be_used_is_remembered_and_belongs_to_its_private_network_setting():
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)
    # A body without keys (no exception from the fetch itself) is remembered.
    cache = oc.Cache()
    calls = []

    def no_keys(url, **kw):
        calls.append(url)
        return {"x": 1}
    for _ in range(2):
        with pytest.raises(oc.OidcError) as e:
            oc.signing_keys(_provider(oc), d, fetch=no_keys, cache=cache, resolve=_PUBLIC, now=NOW)
        assert e.value.code == oc.DISCOVERY_INVALID
    assert len(calls) == 1
    # A key-set address refused is remembered without looking the name up again.
    cache2, looked = oc.Cache(), []

    def private(host):
        looked.append(host)
        return ["10.0.0.7"]
    for _ in range(2):
        with pytest.raises(oc.OidcError) as e:
            oc.signing_keys(_provider(oc), d, fetch=_fetch_for(signer), cache=cache2, resolve=private, now=NOW)
        assert e.value.code == oc.ENDPOINT_REFUSED
    assert len(looked) == 1
    # Keys fetched while private addresses were allowed are not served once they are not.
    cache3 = oc.Cache()
    allowed = _fetch_for(signer)
    oc.signing_keys(_provider(oc, private_network=True), d, fetch=allowed, cache=cache3, resolve=private, now=NOW)
    with pytest.raises(oc.OidcError) as e:
        oc.signing_keys(_provider(oc), d, fetch=allowed, cache=cache3, resolve=private, now=NOW + 1)
    assert e.value.code == oc.ENDPOINT_REFUSED


def test_the_throttle_and_the_failures_belong_to_the_key_set_address():
    """A refetch throttled for one key-set address does not throttle another; a failure at one does not hold back
    another."""
    import dataclasses
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)
    other = dataclasses.replace(d, jwks_uri=ISSUER + "/other/certs")
    cache = oc.Cache()
    oc.signing_keys(_provider(oc), d, fetch=_fetch_for(signer), cache=cache, resolve=_PUBLIC, now=NOW)
    oc.signing_keys(_provider(oc), d, kid="nope", fetch=_fetch_for(signer), cache=cache, resolve=_PUBLIC, now=NOW + 1)
    fetch_other = _fetch_for(signer)
    oc.signing_keys(_provider(oc), other, fetch=fetch_other, cache=cache, resolve=_PUBLIC, now=NOW + 2)
    oc.signing_keys(_provider(oc), other, kid="nope", fetch=fetch_other, cache=cache, resolve=_PUBLIC, now=NOW + 3)
    assert len(fetch_other.calls) == 2                                        # its own refetch, not throttled by d's
    down_calls = []

    def down(url, **kw):
        down_calls.append(url)
        raise oc.OidcError(oc.TEMPORARILY_UNAVAILABLE, "down")
    cache2 = oc.Cache()
    with pytest.raises(oc.OidcError):
        oc.signing_keys(_provider(oc), d, fetch=down, cache=cache2, resolve=_PUBLIC, now=NOW)
    fine = _fetch_for(signer)
    assert "rsa1" in oc.signing_keys(_provider(oc), other, fetch=fine, cache=cache2, resolve=_PUBLIC, now=NOW + 1)


def test_a_key_fetch_that_failed_neither_throttles_the_next_nor_is_retried_at_once():
    """Only a refetch that succeeded throttles the next one; a fetch that failed on the network is remembered for a
    short while (the same answer, without fetching), then tried again."""
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)
    cache = oc.Cache()
    oc.signing_keys(_provider(oc), d, fetch=_fetch_for(signer), cache=cache, resolve=_PUBLIC, now=NOW)
    calls = []

    def down(url, **kw):
        calls.append(url)
        raise oc.OidcError(oc.TEMPORARILY_UNAVAILABLE, "down")
    with pytest.raises(oc.OidcError):
        oc.signing_keys(_provider(oc), d, kid="new", fetch=down, cache=cache, resolve=_PUBLIC, now=NOW + 1)
    with pytest.raises(oc.OidcError) as e:
        oc.signing_keys(_provider(oc), d, kid="new", fetch=down, cache=cache, resolve=_PUBLIC, now=NOW + 5)
    assert e.value.code == oc.TEMPORARILY_UNAVAILABLE and len(calls) == 1
    # After the pause, and with no throttle left behind by the failed refetch, the new key is fetched.
    rotated = _fetch_for(signer, jwks={"keys": signer.jwks()["keys"] + [{**signer.jwks()["keys"][0], "kid": "new"}]})
    keys = oc.signing_keys(_provider(oc), d, kid="new", fetch=rotated, cache=cache, resolve=_PUBLIC, now=NOW + 32)
    assert "new" in keys


def test_cached_answers_belong_to_the_address_and_issuer_they_were_fetched_for():
    """A provider row pointed at another issuer, discovery address or key set does not get the old answers, however
    recently they were cached under the same id."""
    oc = _oc()
    signer = Signer()
    cache = oc.Cache()
    first = _fetch_for(signer)
    explicit = ISSUER + "/.well-known/openid-configuration"
    oc.discover(_provider(oc, discovery_url=explicit), fetch=first, cache=cache, resolve=_PUBLIC, now=NOW)
    seen = len(first.calls)
    oc.discover(_provider(oc, discovery_url=explicit), fetch=first, cache=cache, resolve=_PUBLIC, now=NOW + 1)
    assert len(first.calls) == seen                                           # the same provider: cached
    # The same discovery address with another issuer configured: not the old document (its issuer is checked anew).
    renamed = _fetch_for(signer)
    with pytest.raises(oc.OidcError) as e:
        oc.discover(_provider(oc, discovery_url=explicit, issuer=ISSUER + "/renamed"), fetch=renamed, cache=cache,
                    resolve=_PUBLIC, now=NOW + 2)
    assert e.value.code == oc.ISSUER_MISMATCH and len(renamed.calls) == 1
    moved = _fetch_for(signer)
    oc.discover(_provider(oc, discovery_url=ISSUER + "/other/.well-known/openid-configuration"), fetch=moved,
                cache=cache, resolve=_PUBLIC, now=NOW + 2)
    assert len(moved.calls) == 1                                              # another address: asked again
    d = _disc(oc, signer)
    keys_first = _fetch_for(signer)
    oc.signing_keys(_provider(oc), d, fetch=keys_first, cache=cache, resolve=_PUBLIC, now=NOW)
    import dataclasses
    elsewhere = dataclasses.replace(d, jwks_uri=ISSUER + "/other/certs")
    keys_moved = _fetch_for(signer)
    oc.signing_keys(_provider(oc), elsewhere, fetch=keys_moved, cache=cache, resolve=_PUBLIC, now=NOW + 1)
    assert len(keys_moved.calls) == 1                                         # another key-set address: fetched again


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
    (lambda s: s.token(s.id_claims(iat=NOW + 61)), "provider_clock_ahead"),      # the provider's clock, by name
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
                _logout_claims(signer, jti="j11", aud=[CLIENT, "other"]), _logout_claims(signer, jti="x" * 256),
                _logout_claims(signer, jti="j12", sid=""), _logout_claims(signer, jti="j13", sid="", sub="")):
        with pytest.raises(oc.OidcError):
            oc.verify_logout_token(_provider(oc), d, signer.token(bad), seen_jti=seen_jti, fetch=_fetch_for(signer),
                                   resolve=_PUBLIC, now=NOW)
    # sub instead of sid is enough, also beside an empty sid.
    oc.verify_logout_token(_provider(oc), d, signer.token(_logout_claims(signer, jti="j8", sid=..., sub="user-1")),
                           seen_jti=seen_jti, fetch=_fetch_for(signer), resolve=_PUBLIC, now=NOW)
    oc.verify_logout_token(_provider(oc), d, signer.token(_logout_claims(signer, jti="j14", sid="", sub="user-1")),
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


@pytest.mark.parametrize("private_network", [False, True])
def test_every_call_to_a_provider_holds_its_connection_to_public_addresses_unless_it_is_inside(private_network):
    """Each of the four calls the vault makes to a provider (the discovery document, the keys, the code exchange,
    userinfo) is made with the connection's own rule set: public addresses only, unless the provider is marked
    as inside. The rule is set for the call and gone after it."""
    oc = _oc()
    signer = Signer()
    held = []

    def fetch(url, **kw):
        held.append((url.rsplit("/", 1)[-1], oc._PUBLIC_ONLY.get()))
        if url.endswith("openid-configuration"):
            return signer.discovery()
        if url.endswith("/certs"):
            return signer.jwks()
        if url.endswith("/token"):
            return {"token_type": "bearer", "id_token": "x.y.z", "access_token": "at"}
        return {"sub": "user-1"}

    provider = _provider(oc, private_network=private_network)
    d = oc.discover(provider, fetch=fetch, cache=oc.Cache(), resolve=_PUBLIC, now=NOW)
    oc.signing_keys(provider, d, fetch=fetch, cache=oc.Cache(), resolve=_PUBLIC, now=NOW)
    oc.exchange_code(provider, d, code="c", redirect_uri="https://v/cb", code_verifier="v" * 43, fetch=fetch,
                     resolve=_PUBLIC)
    oc.userinfo(provider, d, "at", expected_sub="user-1", fetch=fetch, resolve=_PUBLIC)
    assert held == [(name, not private_network) for name in ("openid-configuration", "certs", "token", "userinfo")]
    # After the call the rule is what it is with no call under way: public addresses only. A fetch made without
    # saying whose it is connects to nothing else.
    assert oc._PUBLIC_ONLY.get() is True
    import contextvars
    assert contextvars.Context().run(oc._PUBLIC_ONLY.get) is True


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


def test_a_provider_that_cannot_be_reached_is_not_asked_again_for_a_short_while():
    oc = _oc()
    signer = Signer()
    cache = oc.Cache()
    calls = []

    def down(url, **kw):
        calls.append(url)
        raise oc.OidcError(oc.TEMPORARILY_UNAVAILABLE, "down")
    for _ in range(3):
        with pytest.raises(oc.OidcError) as e:
            oc.discover(_provider(oc), fetch=down, cache=cache, resolve=_PUBLIC, now=NOW)
        assert e.value.code == oc.TEMPORARILY_UNAVAILABLE
    assert len(calls) == 1
    # A short while: within 30 seconds, not the hour a good answer is kept.
    assert 0 < oc.DISCOVERY_FAILURE_SECONDS <= 60
    with pytest.raises(oc.OidcError):
        oc.discover(_provider(oc), fetch=down, cache=cache, resolve=_PUBLIC, now=NOW + 29)
    assert len(calls) == 1
    # Another provider is not held back by this one's failure.
    other = _fetch_for(signer)
    oc.discover(_provider(oc, id="p-other"), fetch=other, cache=cache, resolve=_PUBLIC, now=NOW + 29)
    assert len(other.calls) == 1
    # After the pause it is asked again, and an answer is cached as before.
    up = _fetch_for(signer)
    found = oc.discover(_provider(oc), fetch=up, cache=cache, resolve=_PUBLIC, now=NOW + 31)
    assert found.issuer == ISSUER
    # A refresh asks however recently it failed (each failure is remembered again).
    for later in (40, 41):
        with pytest.raises(oc.OidcError):
            oc.discover(_provider(oc), fetch=down, cache=cache, resolve=_PUBLIC, now=NOW + later, refresh=True)
    assert len(calls) == 3
    # An address refused is remembered too, with its own reason, and the name is not looked up again; allowing
    # private addresses is another configuration, asked at once.
    cache3, looked_up = oc.Cache(), []

    def private(host):
        looked_up.append(host)
        return ["10.0.0.7"]
    for _ in range(2):
        with pytest.raises(oc.OidcError) as e:
            oc.discover(_provider(oc, id="p3"), fetch=_fetch_for(signer), cache=cache3, resolve=private, now=NOW)
        assert e.value.code == oc.ENDPOINT_REFUSED
    assert len(looked_up) == 1
    found = oc.discover(_provider(oc, id="p3", private_network=True), fetch=_fetch_for(signer), cache=cache3,
                        resolve=private, now=NOW + 1)
    assert found.issuer == ISSUER and len(looked_up) >= 2
    # An answer that is not a document (a page instead of JSON) is remembered as well, with its own code.
    cache2, wrong = oc.Cache(), []

    def not_a_document(url, **kw):
        wrong.append(url)
        raise oc.OidcError(oc.PROVIDER_ERROR, "not JSON")
    for _ in range(2):
        with pytest.raises(oc.OidcError) as e:
            oc.discover(_provider(oc), fetch=not_a_document, cache=cache2, resolve=_PUBLIC, now=NOW)
        assert e.value.code == oc.PROVIDER_ERROR
    assert len(wrong) == 1
    # The failure belongs to the address: another discovery address for the same provider is asked at once.
    moved = _fetch_for(signer)
    oc.discover(_provider(oc, discovery_url=ISSUER + "/moved/.well-known/openid-configuration"), fetch=moved,
                cache=cache2, resolve=_PUBLIC, now=NOW + 1)
    assert len(moved.calls) == 1


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if "could not be fetched" in r.getMessage()]


def test_a_failed_fetch_serves_the_last_good_document_for_a_day_with_a_warning(caplog):
    """One bad response from the provider does not stop sign-ins: the last good document is served, with a warning
    in the server log for each fetch that failed, until a day after it was fetched; then the failure is the answer."""
    import logging
    oc = _oc()
    signer = Signer()
    cache = oc.Cache()
    first = oc.discover(_provider(oc), fetch=_fetch_for(signer), cache=cache, resolve=_PUBLIC, now=NOW)
    calls = []

    def down(url, **kw):
        calls.append(url)
        raise oc.OidcError(oc.TEMPORARILY_UNAVAILABLE, "down")
    later = NOW + oc.CACHE_SECONDS + 1          # the hour's copy has lapsed: a fetch is due, and it fails
    caplog.set_level(logging.WARNING, logger="dockvault.sso")
    assert oc.discover(_provider(oc), fetch=down, cache=cache, resolve=_PUBLIC, now=later) is first
    assert len(calls) == 1
    warned = _warnings(caplog)
    assert len(warned) == 1
    assert "p1" in warned[0] and oc.TEMPORARILY_UNAVAILABLE in warned[0] and f"{oc.CACHE_SECONDS + 1} s ago" in warned[0]
    # Within the pause the copy is served again without a fetch and without another warning.
    assert oc.discover(_provider(oc), fetch=down, cache=cache, resolve=_PUBLIC, now=later + 29) is first
    assert len(calls) == 1 and len(_warnings(caplog)) == 1
    # After it the provider is asked again; still failing, the copy again, one more warning.
    assert oc.discover(_provider(oc), fetch=down, cache=cache, resolve=_PUBLIC, now=later + 31) is first
    assert len(calls) == 2 and len(_warnings(caplog)) == 2
    # A document that now fails its own checks is a failed fetch like any other.
    wrong = _fetch_for(signer, discovery=signer.discovery(issuer="https://elsewhere.example.com"))
    assert oc.discover(_provider(oc), fetch=wrong, cache=cache, resolve=_PUBLIC, now=later + 62) is first
    assert len(wrong.calls) == 1 and oc.ISSUER_MISMATCH in _warnings(caplog)[-1]
    # A refresh asks for a new document and never takes the old one instead.
    with pytest.raises(oc.OidcError) as e:
        oc.discover(_provider(oc), fetch=down, cache=cache, resolve=_PUBLIC, now=later + 100, refresh=True)
    assert e.value.code == oc.TEMPORARILY_UNAVAILABLE
    # The copy belongs to its configuration: another issuer or address setting has none to fall back on.
    with pytest.raises(oc.OidcError):
        oc.discover(_provider(oc, private_network=True), fetch=down, cache=cache, resolve=_PUBLIC, now=later + 200)
    # The ceiling: a day after the good copy was fetched it is not served; the failure is the answer.
    assert oc.STALE_IF_ERROR_SECONDS == 24 * 3600
    oc.discover(_provider(oc), fetch=down, cache=cache, resolve=_PUBLIC, now=NOW + oc.STALE_IF_ERROR_SECONDS - 1)
    with pytest.raises(oc.OidcError) as e:
        oc.discover(_provider(oc), fetch=down, cache=cache, resolve=_PUBLIC, now=NOW + oc.STALE_IF_ERROR_SECONDS + 31)
    assert e.value.code == oc.TEMPORARILY_UNAVAILABLE
    # Remembered once the copy is gone: the failure again, without a fetch.
    before = len(calls)
    with pytest.raises(oc.OidcError):
        oc.discover(_provider(oc), fetch=down, cache=cache, resolve=_PUBLIC, now=NOW + oc.STALE_IF_ERROR_SECONDS + 32)
    assert len(calls) == before


def test_the_day_is_counted_from_the_last_good_fetch():
    oc = _oc()
    signer = Signer()
    cache = oc.Cache()

    def down(url, **kw):
        raise oc.OidcError(oc.PROVIDER_ERROR, "down")
    oc.discover(_provider(oc), fetch=_fetch_for(signer), cache=cache, resolve=_PUBLIC, now=NOW)
    # Back at hour 23: that fetch is the new good copy, served through hour 25 when the provider fails again.
    renewed = oc.discover(_provider(oc), fetch=_fetch_for(signer), cache=cache, resolve=_PUBLIC, now=NOW + 23 * 3600,
                          refresh=True)
    assert oc.discover(_provider(oc), fetch=down, cache=cache, resolve=_PUBLIC, now=NOW + 25 * 3600) is renewed


def test_a_failed_key_fetch_serves_the_last_good_key_set_only_for_a_key_it_holds(caplog):
    import logging
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)
    cache = oc.Cache()
    held = oc.signing_keys(_provider(oc), d, fetch=_fetch_for(signer), cache=cache, resolve=_PUBLIC, now=NOW)
    calls = []

    def down(url, **kw):
        calls.append(url)
        raise oc.OidcError(oc.TEMPORARILY_UNAVAILABLE, "down")
    later = NOW + oc.CACHE_SECONDS + 1
    caplog.set_level(logging.WARNING, logger="dockvault.sso")
    assert oc.signing_keys(_provider(oc), d, kid="rsa1", fetch=down, cache=cache, resolve=_PUBLIC, now=later) is held
    assert len(calls) == 1 and len(_warnings(caplog)) == 1 and "key set" in _warnings(caplog)[0]
    # Remembered: the copy again for any key it holds, no fetch, no warning.
    assert oc.signing_keys(_provider(oc), d, kid="ec1", fetch=down, cache=cache, resolve=_PUBLIC, now=later + 1) is held
    assert oc.signing_keys(_provider(oc), d, fetch=down, cache=cache, resolve=_PUBLIC, now=later + 2) is held
    assert len(calls) == 1 and len(_warnings(caplog)) == 1
    # A key the copy does not hold is the failure, not the copy, during the pause and after it.
    for at in (later + 3, later + 40):
        with pytest.raises(oc.OidcError) as e:
            oc.signing_keys(_provider(oc), d, kid="rsa9", fetch=down, cache=cache, resolve=_PUBLIC, now=at)
        assert e.value.code == oc.TEMPORARILY_UNAVAILABLE
    assert len(calls) == 2
    # An ID token is verified end to end while the provider is down.
    token = signer.token(signer.id_claims(iat=later + 45, exp=later + 300, auth_time=later + 40))
    claims = oc.verify_id_token(_provider(oc), d, token, nonce="n1", fetch=down, cache=cache, resolve=_PUBLIC,
                                now=later + 50)
    assert claims["sub"] == "user-1"
    # The ceiling, counted from the good fetch.
    with pytest.raises(oc.OidcError):
        oc.signing_keys(_provider(oc), d, kid="rsa1", fetch=down, cache=cache, resolve=_PUBLIC,
                        now=NOW + oc.STALE_IF_ERROR_SECONDS + 31)


def test_a_failed_refetch_for_an_unknown_key_does_not_serve_or_spoil_the_keys_held():
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)
    cache = oc.Cache()
    held = oc.signing_keys(_provider(oc), d, fetch=_fetch_for(signer), cache=cache, resolve=_PUBLIC, now=NOW)
    calls = []

    def down(url, **kw):
        calls.append(url)
        raise oc.OidcError(oc.PROVIDER_ERROR, "down")
    with pytest.raises(oc.OidcError) as e:
        oc.signing_keys(_provider(oc), d, kid="rsa9", fetch=down, cache=cache, resolve=_PUBLIC, now=NOW + 10)
    assert e.value.code == oc.PROVIDER_ERROR
    # The keys held are served as before; another made-up key is not fetched for.
    assert oc.signing_keys(_provider(oc), d, kid="rsa1", fetch=down, cache=cache, resolve=_PUBLIC, now=NOW + 11) is held
    with pytest.raises(oc.OidcError):
        oc.signing_keys(_provider(oc), d, kid="rsa8", fetch=down, cache=cache, resolve=_PUBLIC, now=NOW + 12)
    assert len(calls) == 1


def test_a_logout_token_is_never_verified_with_a_stale_key_set():
    """A back-channel logout token is posted by anyone: a key the provider has since removed must not outlive the
    hour's cache for it, so the last good copy that serves sign-ins during an outage does not serve logout tokens."""
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)
    cache = oc.Cache()
    oc.signing_keys(_provider(oc), d, fetch=_fetch_for(signer), cache=cache, resolve=_PUBLIC, now=NOW)

    def down(url, **kw):
        raise oc.OidcError(oc.TEMPORARILY_UNAVAILABLE, "down")
    later = NOW + oc.CACHE_SECONDS + 1
    # Within the hour the cached keys serve a logout token as before.
    token = signer.token(_logout_claims(signer, iat=NOW + 60, exp=NOW + 180, jti="j-early"))
    assert oc.verify_logout_token(_provider(oc), d, token, seen_jti=lambda jti, ttl: False, fetch=down, cache=cache,
                                  resolve=_PUBLIC, now=NOW + 61)["jti"] == "j-early"
    # After it, with the provider down: refused, on the failed fetch and on the remembered one.
    for at, jti in ((later, "j1"), (later + 1, "j2")):
        token = signer.token(_logout_claims(signer, iat=at, exp=at + 120, jti=jti))
        with pytest.raises(oc.OidcError) as e:
            oc.verify_logout_token(_provider(oc), d, token, seen_jti=lambda jti, ttl: False, fetch=down, cache=cache,
                                   resolve=_PUBLIC, now=at)
        assert e.value.code == oc.TEMPORARILY_UNAVAILABLE
    # An ID token in the same state is verified with the copy: it arrives over the code exchange's own connection.
    at = later + 2
    token = signer.token(signer.id_claims(iat=at - 5, exp=at + 300, auth_time=at - 10))
    assert oc.verify_id_token(_provider(oc), d, token, nonce="n1", fetch=down, cache=cache, resolve=_PUBLIC,
                              now=at)["sub"] == "user-1"



def test_an_issue_time_ahead_names_the_clock_for_an_id_token_and_stays_an_invalid_token_for_a_logout_token():
    """A provider whose clock runs ahead issues ID tokens the vault refuses: the person is told it is the clock.
    A logout token with such a time is an invalid token, as before, so the provider is answered that it need not
    send it again."""
    oc = _oc()
    signer = Signer()
    d = _disc(oc, signer)
    token = signer.token(_logout_claims(signer, jti="j-ahead", iat=NOW + 61, exp=NOW + 180))
    with pytest.raises(oc.OidcError) as e:
        oc.verify_logout_token(_provider(oc), d, token, seen_jti=lambda jti, ttl: False, fetch=_fetch_for(signer),
                               resolve=_PUBLIC, now=NOW)
    assert e.value.code == oc.TOKEN_INVALID
    with pytest.raises(oc.OidcError) as e:
        oc._check_times({"exp": NOW + 300, "iat": NOW + 61}, NOW, oc.PROVIDER_CLOCK_AHEAD)
    assert e.value.code == oc.PROVIDER_CLOCK_AHEAD
    oc._check_times({"exp": NOW + 300, "iat": NOW + 60}, NOW, oc.PROVIDER_CLOCK_AHEAD)        # within the skew
    # Only the issue time is the clock's: a token past its end is an invalid one, whoever asks.
    with pytest.raises(oc.OidcError) as e:
        oc._check_times({"exp": NOW - 61, "iat": NOW - 300}, NOW, oc.PROVIDER_CLOCK_AHEAD)
    assert e.value.code == oc.TOKEN_INVALID


@pytest.mark.parametrize("alg", ["RS256", "PS256"])
def test_a_provider_key_too_short_to_trust_verifies_no_token(alg):
    """A provider publishes an RSA signing key of 1024 bits (a misconfigured realm, a legacy key). The library
    verified with it and only warned. A provider's logout is posted to an address open to anyone: whoever
    factored such a key could end any linked person's sessions. A key under 2048 bits verifies nothing, for an ID
    token and for a logout token alike; the provider's other keys are not touched by it."""
    oc = _oc()
    signer = Signer()
    signer.rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(oc.OidcError) as refused:
        _verify(oc, signer, signer.token(signer.id_claims(), alg=alg))
    assert refused.value.code == oc.SIGNING_KEY_TOO_SHORT and refused.value.detail == "an RSA key of 1024 bits"
    with pytest.raises(oc.OidcError) as refused:
        oc.verify_logout_token(_provider(oc), _disc(oc, signer), signer.token(_logout_claims(signer), alg=alg),
                               seen_jti=lambda jti, ttl: False, fetch=_fetch_for(signer), resolve=_PUBLIC, now=NOW)
    assert refused.value.code == oc.SIGNING_KEY_TOO_SHORT and refused.value.detail == "an RSA key of 1024 bits"
    # The key is what is refused, before the token is looked at: a token that is wrong in other ways as well
    # (another audience here) is still answered with the reason an administrator can act on.
    with pytest.raises(oc.OidcError) as refused:
        _verify(oc, signer, signer.token({**signer.id_claims(), "aud": "another-client"}, alg=alg))
    assert refused.value.code == oc.SIGNING_KEY_TOO_SHORT
    assert oc.RSA_KEY_MIN_BITS == 2048 and oc.SIGNING_KEY_TOO_SHORT == "signing_key_too_short"
    # The provider's elliptic-curve key is as it was.
    assert _verify(oc, signer, signer.token(signer.id_claims(), alg="ES256", kid="ec1"))["sub"] == "user-1"
    # (A key of 2048 bits verifies: every other test here signs with one.)
    assert Signer().rsa.key_size == 2048


def test_a_key_one_bit_under_the_floor_is_too_short_and_one_at_it_is_not(monkeypatch):
    """The floor is the number itself: a key of exactly that many bits verifies."""
    oc = _oc()
    signer = Signer()
    assert _verify(oc, signer, signer.token(signer.id_claims(), alg="RS256"))["sub"] == "user-1"
    monkeypatch.setattr(oc, "RSA_KEY_MIN_BITS", 2049)
    with pytest.raises(oc.OidcError) as refused:
        _verify(oc, signer, signer.token(signer.id_claims(), alg="RS256"))
    assert refused.value.code == oc.SIGNING_KEY_TOO_SHORT and refused.value.detail == "an RSA key of 2048 bits"
    # An elliptic-curve key has a size too (256), and is no RSA key: the floor is not asked of it.
    assert _verify(oc, signer, signer.token(signer.id_claims(), alg="ES256", kid="ec1"))["sub"] == "user-1"
