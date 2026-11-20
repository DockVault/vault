"""Every address single sign-on gives a provider or a browser is built on the vault's configured address: the first
ALLOWED_HOSTS entry that is not a wildcard, read as an origin (app/core/allowed_hosts.py). Never on the request that
asked: a Host header is the caller's to write, and a provider sent the browser back to a forged one would hand the
sign-in to whoever wrote it.

With no address sign-in can be built on (none configured, or one that is not https off localhost) nothing is
started: a provider is never given an address made of anything else. Offline, through the application's own
routes."""
from urllib.parse import parse_qs, urlsplit

import pytest

from test_oidc_client import ISSUER
from test_sso_sign_in import Harness, _call, _h, _identity, _provider, _user

import app.core.public_url as public_url

pytestmark = pytest.mark.unit

# The module's own answer: the harness stands a fixed address in its place, and these tests put the rule back.
THE_RULE = public_url.public_base_url
FORGED = {"host": "evil.example", "x-forwarded-host": "evil.example", "x-forwarded-proto": "http",
          "origin": "https://evil.example", "referer": "https://evil.example/"}


def _configured(monkeypatch, allowed_hosts):
    import app.core.config as config
    monkeypatch.setattr(public_url, "public_base_url", THE_RULE)
    monkeypatch.setattr(config.settings, "allowed_hosts", allowed_hosts, raising=False)


def _harness(monkeypatch, allowed_hosts, **provider):
    alice, p = _user(), _provider(**provider)
    h = Harness(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    _configured(monkeypatch, allowed_hosts)
    return h, p


def _start(h, p):
    return _call(h.S, "POST", f"/auth/sso/{p.id}/start", {"verifier_hash": _h("tab-verifier")}, headers=FORGED)


@pytest.mark.parametrize("allowed_hosts, address", [
    ("https://vault.example.com:8443", "https://vault.example.com:8443"),                    # a full address, a port
    ("vault.example.com:8443, other.example.com", "https://vault.example.com:8443"),         # a bare name, a port
    ("*.example.com, .example.org, vault.example.com", "https://vault.example.com"),         # a wildcard first
    ("https://*.example.com, https://files.example.com", "https://files.example.com"),
    ("http://localhost:8200,vault-api", "http://localhost:8200"),                            # as the tests run it
])
def test_the_provider_is_given_the_configured_address_whatever_host_the_request_names(monkeypatch, allowed_hosts,
                                                                                      address):
    h, p = _harness(monkeypatch, allowed_hosts)
    status, out, _ = _start(h, p)
    assert status == 200, out
    asked = parse_qs(urlsplit(out["authorization_url"]).query)
    assert asked["redirect_uri"] == [f"{address}/auth/sso/{p.id}/callback"]
    assert "evil.example" not in out["authorization_url"]
    # The callback, reached under the forged name too, redeems the code for the same address and sends the browser
    # to a place in the app, never to an address.
    state, _ = h.state_of(out["authorization_url"])
    query = f"state={state}&code=c0de&iss={ISSUER}"
    status, _, headers = _call(h.S, "GET", f"/auth/sso/{p.id}/callback?{query}", headers=FORGED)
    (data, _), = h.token_calls
    assert parse_qs(data.decode())["redirect_uri"] == [f"{address}/auth/sso/{p.id}/callback"]
    assert status == 302 and headers["location"].startswith("/#sso="), headers
    from app.services import sso_sign_in as sso
    assert sso.redirect_uri(p.id) == f"{address}/auth/sso/{p.id}/callback"
    assert sso.post_logout_address() == f"{address}/" and sso.address_refusal() is None


@pytest.mark.parametrize("allowed_hosts", ["", "*", "*.example.com, .example.org", "http://vault.lan:8200",
                                           "bad host, vault.example.com"])
def test_with_no_address_sign_in_can_be_built_on_nothing_is_started(monkeypatch, allowed_hosts):
    h, p = _harness(monkeypatch, allowed_hosts)
    from app.services import sso_sign_in as sso
    status, out, _ = _start(h, p)
    assert status == 409 and out["detail"]["reason"] == "no_public_address", out
    assert out["detail"]["message"] == sso.REASON_TEXTS["no_public_address"]
    assert "evil.example" not in str(out)
    # Nothing was made for it, and the provider was never asked.
    assert not [k for k in h.redis.rows if k.startswith("sso:state:")] and h.token_calls == []
    # Every purpose is refused the same way, a test included; no address is made of anything else.
    from app.core import sso_state
    for purpose in (sso_state.SIGN_IN, sso_state.APP, sso_state.TEST):
        assert sso.usable_for(p, purpose) == "no_public_address", purpose
    with pytest.raises(sso.Refusal) as refused:
        sso.redirect_uri(p.id)
    assert refused.value.code == "no_public_address"
    assert sso.post_logout_address() is None
    # What an administrator is told names the setting and never repeats the value.
    why = sso.address_refusal()
    assert why.startswith("Single sign-on needs the vault's public address. ") and "ALLOWED_HOSTS" in why
    assert "vault.lan" not in why and "example" not in why and "bad host" not in why


def test_a_provider_that_is_off_says_only_that_whatever_the_address(monkeypatch):
    """What a caller learns about a provider does not change with the vault's own configuration."""
    for allowed_hosts in ("", "https://vault.example.com"):
        h, p = _harness(monkeypatch, allowed_hosts, state="disabled")
        status, out, _ = _start(h, p)
        assert status == 404 and out["detail"]["reason"] == "provider_disabled", (allowed_hosts, out)


def test_the_callback_is_refused_when_the_address_went_since_the_start(monkeypatch):
    h, p = _harness(monkeypatch, "https://vault.example.com")
    status, out, _ = _start(h, p)
    assert status == 200, out
    state, _ = h.state_of(out["authorization_url"])
    _configured(monkeypatch, "")
    status, location, _ = h.callback(p, state, iss=ISSUER)
    assert status == 302 and location == "/#sso-error=no_public_address", location
    assert h.token_calls == [] and all(a[0] != "login_success" for a in h.audits)
