"""The first passkey of an account that signs in only through its provider, through the ASGI app against an
in-memory database and a software authenticator.

Such an account has no factor yet and no password it could type, so neither of the two proofs a registration takes
is open to it. Its proof is a fresh sign-in at a provider it is linked to (the re-authentication the session stages
for managing its own factors), spent once by the registration. The password in the body counts for nothing there,
an account with a password it can type keeps proving the password, and an account nothing can confirm is told to
ask an administrator. The passkey list says how the account proves it and carries the sentence that a passkey does
not replace the provider's sign-in. Offline."""
import types
import uuid

import pytest

from _webauthn_softauth import SoftAuthenticator
from test_passkey_routes import ORIGIN, Harness, _call, _user

pytestmark = pytest.mark.unit

ACTION = "account.second_factor"


def _provider(name="entra", label="Company sign-in", *, state="enabled", auth_time=True, sort_order=0, kind="oidc"):
    return types.SimpleNamespace(id=uuid.uuid4(), name=name, label=label, state=state, kind=kind,
                                 sort_order=sort_order, show_on_sign_in=True,
                                 last_test={"auth_time_present": True} if auth_time else {"auth_time_present": False})


class ProviderHarness(Harness):
    """The passkey harness with the account linked to ``providers`` and the staged proofs kept in its fake store."""

    def __init__(self, monkeypatch, user, providers=(), **kw):
        super().__init__(monkeypatch, user, **kw)
        from app.core import sso_state
        from app.core.models import ExternalIdentity, SsoProvider
        self.db.rows_of(SsoProvider).extend(providers)
        self.db.rows_of(ExternalIdentity).extend(
            types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, provider_id=p.id) for p in providers)
        self.sso_state = sso_state
        monkeypatch.setattr(sso_state, "_redis", lambda redis: self.redis)
        monkeypatch.setattr(self.S, "_current_session_hash", lambda request: "sess-1")

    def confirm_at_the_provider(self, session="sess-1", action=ACTION, provider=None):
        from app.core.models import SsoProvider
        rows = self.db.rows_of(SsoProvider)
        provider = provider if provider is not None else (rows[0] if rows else types.SimpleNamespace(id=uuid.uuid4()))
        self.sso_state.stage_reauth(session, action, provider.id)

    def options(self, body=None):
        return _call(self.S, "POST", "/users/me/passkeys/register/options", body or {})


def _provider_only(**extra):
    return _user(sso_only=True, **extra)


def test_a_provider_only_account_adds_its_first_passkey_after_a_fresh_sign_in_at_its_provider(monkeypatch):
    entra = _provider()
    h = ProviderHarness(monkeypatch, _provider_only(), [entra])
    # Nothing staged: the page is told what to do and where. The account's password (nobody knows it) proves nothing.
    for body in ({}, {"current_password": "pw"}):
        status, out = h.options(body)
        assert status == 403, out
        assert out["detail"] == {"reason": "provider_confirmation_required", "action": ACTION,
                                 "message": "Confirm with your organisation's sign-in first, then add the passkey.",
                                 "providers": [{"id": str(entra.id), "label": "Company sign-in"}]}
    assert h.redis.rows == {} and h.receipts == []
    h.confirm_at_the_provider()
    status, out = h.options()
    assert status == 200, out
    # The proof was spent by that one request: the same session asking again has to confirm again.
    assert h.options()[0] == 403
    credential = SoftAuthenticator().make_credential(out["options"], ORIGIN)
    status, shown = _call(h.S, "POST", "/users/me/passkeys/register/verify",
                          {"challenge_id": out["challenge_id"], "credential": credential, "label": "Laptop"})
    assert status == 201, shown
    (row,) = h.rows()
    assert row.user_id == h.user.id and row.label == "Laptop"
    # With a factor on the account, the next passkey is proved by the step-up, as for everyone.
    status, out = h.options()
    assert status == 403 and out["detail"]["reason"] == "step_up_required" and out["detail"]["action"] == ACTION


def test_a_confirmation_for_something_else_or_someone_elses_session_proves_nothing(monkeypatch):
    h = ProviderHarness(monkeypatch, _provider_only(), [_provider()])
    h.confirm_at_the_provider(action="vault.delete")
    h.confirm_at_the_provider(session="sess-2")
    status, out = h.options()
    assert status == 403 and out["detail"]["reason"] == "provider_confirmation_required"
    # And neither of them was spent by the attempt.
    assert h.sso_state.take_reauth("sess-1", "vault.delete") is not None
    assert h.sso_state.take_reauth("sess-2", ACTION) is not None


@pytest.mark.parametrize("providers", [
    [], [_provider(state="disabled")], [_provider(state="tested")], [_provider(auth_time=False)],
    [_provider(kind="saml")]])
def test_an_account_nothing_can_confirm_is_told_to_ask_an_administrator(monkeypatch, providers):
    """No provider, or none that can confirm a person afresh (it is off, or its test sign-in showed no sign-in time):
    there is no way to prove the request here, staged proof or not, password or not."""
    for user in (_provider_only(), _user(password_hash=None)):
        h = ProviderHarness(monkeypatch, user, providers)
        h.confirm_at_the_provider()
        status, out = h.options({"current_password": "pw"})
        assert status == 409, out
        assert out["detail"] == ("Your account has no password and no second factor yet, and no sign-in of your "
                                 "organisation can confirm you here. Ask an administrator.")
        assert h.sso_state.take_reauth("sess-1", ACTION) is not None       # left where it was


def test_only_the_accounts_own_identities_count(monkeypatch):
    """A provider someone else is linked to confirms nobody else, and is not named to them."""
    from app.core.models import ExternalIdentity, SsoProvider
    entra = _provider()
    h = ProviderHarness(monkeypatch, _provider_only(), [])
    h.db.rows_of(SsoProvider).append(entra)
    h.db.rows_of(ExternalIdentity).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=uuid.uuid4(), provider_id=entra.id))
    h.confirm_at_the_provider()
    assert h.options()[0] == 409
    listed = _call(h.S, "GET", "/users/me/passkeys")[1]
    assert listed["first_proof"] == {"kind": "none", "action": ACTION, "providers": []}
    assert "through its own sign-in;" in listed["provider_only"] and "Company sign-in" not in listed["provider_only"]


def test_a_first_passkey_is_added_only_on_a_confirmation_from_a_provider_that_still_stands(monkeypatch):
    """Linked to two providers, confirmed at the first, which is turned off before the passkey is added: the
    other provider being on does not make that confirmation count, and it is spent all the same."""
    entra, okta = _provider(), _provider(name="okta", label="Okta", sort_order=1)
    h = ProviderHarness(monkeypatch, _provider_only(), [entra, okta])
    h.confirm_at_the_provider(provider=entra)
    entra.state = "disabled"
    status, out = h.options()
    assert status == 403 and out["detail"]["reason"] == "provider_confirmation_required", out
    assert [p["label"] for p in out["detail"]["providers"]] == ["Okta"]
    assert h.sso_state.take_reauth("sess-1", ACTION) is None           # spent, not left for later
    h.confirm_at_the_provider(provider=okta)
    assert h.options()[0] == 200


def test_a_password_less_account_linked_to_a_provider_proves_it_the_same_way(monkeypatch):
    h = ProviderHarness(monkeypatch, _user(password_hash=None), [_provider()])
    assert h.options()[0] == 403
    h.confirm_at_the_provider()
    assert h.options()[0] == 200


def test_an_account_with_a_password_it_can_type_still_proves_the_password(monkeypatch):
    """A linked provider changes nothing for an account that keeps its password: the password is the proof, and a
    staged confirmation is neither needed nor spent."""
    h = ProviderHarness(monkeypatch, _user(), [_provider()])
    h.confirm_at_the_provider()
    status, out = h.options()
    assert status == 400 and "password" in out["detail"]
    assert h.options({"current_password": "pw"})[0] == 200
    assert h.sso_state.take_reauth("sess-1", ACTION) is not None


def test_without_the_store_the_request_is_unavailable_not_refused_for_good(monkeypatch):
    h = ProviderHarness(monkeypatch, _provider_only(), [_provider()])

    def _down(redis):
        raise RuntimeError("down")
    monkeypatch.setattr(h.sso_state, "_redis", _down)
    status, out = h.options()
    assert status == 503 and "temporarily unavailable" in out["detail"], out


def test_the_passkey_list_says_how_the_account_proves_adding_one(monkeypatch):
    entra, okta = _provider(sort_order=2), _provider("okta", None, sort_order=1)
    cases = [
        (_user(), [], False, "password", []),
        (_user(), [], True, "step_up", []),
        (_user(), [entra], False, "password", []),
        (_provider_only(), [entra, okta], False, "provider", [{"id": str(okta.id), "label": "okta"},
                                                             {"id": str(entra.id), "label": "Company sign-in"}]),
        (_provider_only(), [entra], True, "step_up", []),
        (_provider_only(), [_provider(state="disabled")], False, "none", []),
        (_user(password_hash=None), [], False, "none", []),
    ]
    for user, providers, totp, kind, offered in cases:
        h = ProviderHarness(monkeypatch, user, providers, totp=totp)
        status, listed = _call(h.S, "GET", "/users/me/passkeys")
        assert status == 200, listed
        assert listed["first_proof"] == {"kind": kind, "action": ACTION, "providers": offered}, (kind, listed)


def test_the_list_carries_the_sentence_for_a_provider_only_account_and_nothing_for_anyone_else(monkeypatch):
    entra, okta, off = _provider(), _provider("okta", None), _provider("old", "Old sign-in", state="disabled")
    h = ProviderHarness(monkeypatch, _provider_only(), [entra, okta, off])
    assert _call(h.S, "GET", "/users/me/passkeys")[1]["provider_only"] == (
        "Your organisation signs you in through Company sign-in or okta; this passkey confirms it's you after that, "
        "it does not replace it.")
    # No provider of the account is on right now: the sentence still says what a passkey is for.
    h = ProviderHarness(monkeypatch, _provider_only(), [off])
    assert _call(h.S, "GET", "/users/me/passkeys")[1]["provider_only"] == (
        "Your organisation signs you in through its own sign-in; this passkey confirms it's you after that, it does "
        "not replace it.")
    # An account that keeps its password is told nothing of the kind, linked or not.
    for user, providers in ((_user(), [entra]), (_user(), []), (_user(sso_only=False, password_hash=None), [entra])):
        h = ProviderHarness(monkeypatch, user, providers)
        assert _call(h.S, "GET", "/users/me/passkeys")[1]["provider_only"] is None


def test_the_page_shows_the_sentence_above_the_list():
    from pathlib import Path
    app = (Path(__file__).resolve().parents[1] / "static" / "js" / "app.js").read_text(encoding="utf-8")
    section = app[app.index("async function renderAccountPasskeys() {"):app.index("let _passkeyFirstProof = null;")]
    line = "    if (data.provider_only) body.appendChild(_el('p', 'text-secondary text-sm mb-sm passkey-provider-only', data.provider_only));"
    assert section.count(line) == 1
    # Before the list and its "No passkeys yet" line, as text, never as markup.
    assert section.index(line) < section.index("No passkeys yet.") < section.index("const list = _el('div', 'passkey-list');")
