"""The address a passkey is bound to is the vault's configured one: the first ALLOWED_HOSTS entry that is not a
wildcard, read as an origin (app/core/allowed_hosts.py). Its host is the relying-party id and its origin is what the
browser must have signed into an assertion. Never the Host of the request that asked: a passkey made or asked for
under a forged name would be bound to it.

With no address a passkey can be made at (none configured, one sign-in cannot be built on, or one reached by IP) the
passkey routes refuse with a sentence that says what to change, and the sign-in page offers no passkey. Offline,
through the application's own routes."""
import pytest

from test_passkey_sign_in import Harness, _call_h, _user

from app.services import webauthn_service as ws

pytestmark = pytest.mark.unit

# The module's own answer: the harness stands a fixed relying party in its place, and these tests put the rule back.
THE_RULE = ws.relying_party
FORGED = {"host": "evil.example", "x-forwarded-host": "evil.example", "x-forwarded-proto": "http",
          "origin": "https://evil.example", "referer": "https://evil.example/"}


def _harness(monkeypatch, allowed_hosts):
    import app.core.config as config
    h = Harness(monkeypatch, [_user()])
    monkeypatch.setattr(ws, "relying_party", THE_RULE)
    monkeypatch.setattr(config.settings, "allowed_hosts", allowed_hosts, raising=False)
    return h


def _options(h):
    return _call_h(h.S, "POST", "/auth/passkeys/sign-in/options", {}, headers=FORGED)[:2]


@pytest.mark.parametrize("allowed_hosts, rp_id, origin", [
    ("https://vault.example.com:8443", "vault.example.com", "https://vault.example.com:8443"),     # a full address
    ("vault.example.com:8443, other.example.com", "vault.example.com", "https://vault.example.com:8443"),
    ("*.example.com, .example.org, vault.example.com", "vault.example.com", "https://vault.example.com"),
    ("https://*.example.com, https://files.example.com", "files.example.com", "https://files.example.com"),
    ("http://localhost:8200,vault-api", "localhost", "http://localhost:8200"),                     # as the tests run it
])
def test_a_passkey_is_asked_for_at_the_configured_address_whatever_host_the_request_names(monkeypatch, allowed_hosts,
                                                                                         rp_id, origin):
    h = _harness(monkeypatch, allowed_hosts)
    status, body = _options(h)
    assert status == 200, body
    assert body["options"]["publicKey"]["rpId"] == rp_id and "evil.example" not in str(body)
    party = ws.relying_party("Acme Vault")
    assert party.rp_id == rp_id and party.origin == origin
    assert h.S._sign_in_methods(h.db)["passkeys"] is True


@pytest.mark.parametrize("allowed_hosts, words", [
    ("", "no public address"),
    ("*, .example.com", "no public address"),
    ("http://vault.lan:8200", "https://"),                       # the emailed links use it; sign-in cannot
    ("bad host, vault.example.com", "no browser accepts"),       # and no other entry is looked for
    ("https://203.0.113.9:8443", "reached by IP"),
    ("203.0.113.9", "reached by IP"),
])
def test_with_no_address_a_passkey_can_be_made_at_the_routes_say_what_to_change(monkeypatch, allowed_hosts, words):
    from fastapi import HTTPException
    h = _harness(monkeypatch, allowed_hosts)
    # Someone who is not signed in learns only that there are no passkeys here, nothing of how the vault is set up.
    status, body = _options(h)
    assert status == 409 and body["detail"] == "Passkeys are not available on this deployment.", body
    # A signed-in person adding a passkey is told what is wrong, which is what an administrator needs to hear.
    with pytest.raises(HTTPException) as refused:
        h.S._passkey_relying_party(h.db)
    assert refused.value.status_code == 409
    said = refused.value.detail
    assert said.startswith("Passkeys need the vault's public address. ") and words in said and "ALLOWED_HOSTS" in said
    # What is wrong is said without the value, and nothing of the request's own name.
    for never in ("evil.example", "vault.lan", "203.0.113.9", "bad host", "example.com"):
        assert never not in said, said
    assert ws.relying_party("Acme Vault") is None
    assert h.S._sign_in_methods(h.db)["passkeys"] is False
