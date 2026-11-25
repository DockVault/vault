"""Passkeys turned off: an account whose only second factor was a passkey is not left with its password alone
(app/core/webauthn_settings.py, why_none_can_be_used and only_a_passkey).

Turned off, a passkey is no factor, by the deployment's choice. An account that had made one its only second
factor would sign in with its password alone from then on, and nothing said so. It sets an authenticator app up
at its next sign-in instead, and is told why; the Sign-in page has the number of such accounts before the switch
is saved; they are told when it is turned off; and their passkeys count again the day passkeys are turned back on.
"""
import types
import uuid
from datetime import datetime

import pytest

from _memory_db import MemoryDB
# The route harness sets the application's overrides itself: cleared after every test here, as in its own file.
from test_passkey_routes import _clean_overrides  # noqa: F401
from test_passkey_settings import _mod, _resolving
from test_passkey_settings import _the_vault_has_an_address  # noqa: F401  (a fixture, used by every test here)
from test_passkey_sign_in import Harness as SignInHarness, _api, _call, _user
from test_passkeys_that_never_verified import _key, _settings_route

pytestmark = pytest.mark.unit

IP = "203.0.113.9"


@pytest.mark.parametrize("role", ["user", "admin"])
def test_an_account_whose_only_second_factor_was_a_passkey_sets_one_up_again_while_passkeys_are_off(monkeypatch,
                                                                                                    role):
    registry, wss = _mod()
    from app.core.models import PendingLogin, SecondFactorEnrollment, WebAuthnCredential
    from app.services import sign_in
    S = _api()
    in_effect, effective = S._login_second_factor_in_effect, S._second_factor_effective      # as the server has them
    bob, carol, dave = _user("bob", role=role), _user("carol", role=role), _user("dave", role=role)
    h = SignInHarness(monkeypatch, [bob, carol, dave])
    monkeypatch.setattr(S, "_login_second_factor_in_effect", in_effect)
    monkeypatch.setattr(S, "_second_factor_effective", effective)
    _resolving(monkeypatch, registry, {wss.MODE: "optional"})
    h.db.rows_of(WebAuthnCredential).extend([_key(bob, verified=True), _key(carol, verified=True)])
    # Carol holds an authenticator app beside her passkey; Dave holds no factor at all.
    h.db.rows_of(SecondFactorEnrollment).append(
        types.SimpleNamespace(id=uuid.uuid4(), user_id=carol.id, method="totp", status="active"))

    def after_the_password(user):
        outcome = sign_in.finish(h.db, sign_in.SignInResult(user, ["pwd"], IP))
        return None if isinstance(outcome, sign_in.SignedIn) else outcome.body

    assert after_the_password(bob)["methods"] == ["passkey"]
    assert after_the_password(carol)["methods"] == ["totp", "recovery", "passkey"]
    assert after_the_password(dave) is None
    # Passkeys are turned off.
    _resolving(monkeypatch, registry, {wss.MODE: "off"})
    assert wss.usable_passkeys(h.db, bob.id) == 0 and sign_in.holds_a_factor(h.db, bob) is False
    assert S._second_factor_to_set_up_again(h.db, bob) is True
    body = after_the_password(bob)
    assert body["stage"] == "second_factor" and body["enrollment_required"] is True, body
    assert body["methods"] == [] and body["enrollment_methods"] == ["totp"], body       # no passkey can be made
    assert body["set_up_again"] == "passkeys_turned_off"
    # The account that holds an authenticator is asked for it, and one with no factor signs in as before.
    assert S._second_factor_to_set_up_again(h.db, carol) is False and S._second_factor_to_set_up_again(h.db, dave) is False
    body = after_the_password(carol)
    assert body["enrollment_required"] is False and body["methods"] == ["totp", "recovery"], body
    assert after_the_password(dave) is None
    # Bob sets the authenticator up and signs in with it.
    h.db.rows_of(SecondFactorEnrollment).append(
        types.SimpleNamespace(id=uuid.uuid4(), user_id=bob.id, method="totp", status="active"))
    held = [p for p in h.db.rows_of(PendingLogin) if p.user_id == bob.id][-1]
    done = sign_in.finish(h.db, sign_in.SignInResult(bob, ["pwd", "totp"], IP, pending=held, sessions_ended=0))
    assert isinstance(done, sign_in.SignedIn)
    assert S._second_factor_to_set_up_again(h.db, bob) is False
    assert after_the_password(bob)["methods"] == ["totp", "recovery"]
    # Passkeys back on: the keys count again, by themselves.
    _resolving(monkeypatch, registry, {wss.MODE: "optional"})
    assert after_the_password(bob)["methods"] == ["totp", "recovery", "passkey"]
    # A retired key is no key: an account left with only that sets nothing up again.
    for key in h.db.rows_of(WebAuthnCredential):
        key.retired_at = datetime.utcnow()
    h.db.rows_of(SecondFactorEnrollment).clear()
    _resolving(monkeypatch, registry, {wss.MODE: "off"})
    assert wss.why_none_can_be_used(h.db, bob.id) is None and after_the_password(bob) is None


def test_the_sign_in_page_is_told_who_holds_only_a_passkey_and_they_are_told_when_passkeys_go_off(monkeypatch):
    registry, wss = _mod()
    from app.core.models import SecondFactorEnrollment, User, WebAuthnCredential
    root, alice, bob, carol = _user("root", role="admin"), _user("alice"), _user("bob"), _user("carol")
    keys = [_key(root, verified=True),                                          # an administrator, only a passkey
            _key(alice, verified=True), _key(alice, verified=True),             # two keys, one account
            _key(bob, verified=True),                                           # ...and an authenticator app
            _key(carol, verified=True, retired_at=datetime.utcnow())]           # retired: no key
    apps = [types.SimpleNamespace(id=uuid.uuid4(), user_id=bob.id, method="totp", status="active"),
            types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, method="totp", status="unconfirmed")]
    db = MemoryDB({User: [root, alice, bob, carol], WebAuthnCredential: keys, SecondFactorEnrollment: apps})
    S, told, in_force = _settings_route(monkeypatch, db, root, registry, wss)
    assert wss.only_a_passkey(db) == {"accounts": 2, "administrators": 1, "owners": [root.id, alice.id]}
    status, body = _call(S, "GET", "/settings/sign-in")
    assert status == 200 and body["accounts_with_only_a_passkey"] == 2
    assert body["administrators_with_only_a_passkey"] == 1
    # A change that leaves passkeys on tells nobody.
    assert _call(S, "PUT", "/settings/sign-in/webauthn_mode", {"value": "required_for_roles"})[0] == 200
    assert _call(S, "PUT", "/settings/sign-in/webauthn_mode", {"value": "optional"})[0] == 200
    assert told == []
    # Turned off: the two accounts are told what happens at their next sign-in.
    status, body = _call(S, "PUT", "/settings/sign-in/webauthn_mode", {"value": "off"})
    assert status == 200 and body["status"] == "applied", body
    ((ids, ntype, title, text, target, dedup),) = told
    assert ids == sorted([str(root.id), str(alice.id)]) and ntype == "security" and target == "#profile"
    assert title == "Passkeys were turned off on this vault"
    assert text == ("Your passkey was your only second factor here, and passkeys are no longer accepted. At your "
                    "next sign-in you set an authenticator app up, after your password. Your passkeys are kept, "
                    "and count again if passkeys are turned back on.")
    assert dedup == f"passkeys_turned_off:{datetime.utcnow().date().isoformat()}"
    # The numbers stay on the page while passkeys are off: these are the accounts that set a factor up again.
    assert _call(S, "GET", "/settings/sign-in")[1]["accounts_with_only_a_passkey"] == 2
    # Saved off again, or turned back on: nobody is told.
    del told[:]
    assert _call(S, "PUT", "/settings/sign-in/webauthn_mode", {"value": "off"})[0] == 200
    assert _call(S, "PUT", "/settings/sign-in/webauthn_mode", {"value": None})[0] == 200          # the default: on
    assert told == []
    # Nobody holds only a passkey: nothing is sent. A failure to tell undoes nothing.
    in_use = db.rows_of(SecondFactorEnrollment)
    in_use.append(types.SimpleNamespace(id=uuid.uuid4(), user_id=root.id, method="totp", status="active"))
    apps[1].status = "active"
    assert wss.only_a_passkey(db) == {"accounts": 0, "administrators": 0, "owners": []}
    assert _call(S, "PUT", "/settings/sign-in/webauthn_mode", {"value": "off"})[0] == 200 and told == []
    in_use.pop()
    in_force[wss.MODE] = "optional"

    def broken(*a, **k):
        raise RuntimeError("the notices are down")
    monkeypatch.setattr(S, "_notify_users", broken)
    status, body = _call(S, "PUT", "/settings/sign-in/webauthn_mode", {"value": "off"})
    assert status == 200 and body["status"] == "applied"
    # A database from before passkeys has none.
    assert wss.only_a_passkey(MemoryDB({User: [root]})) == {"accounts": 0, "administrators": 0, "owners": []}


def test_the_switch_says_what_turning_passkeys_off_does_to_such_an_account():
    registry, wss = _mod()
    said = registry.spec_for(wss.MODE).help
    assert "an account whose only second factor is a passkey sets an authenticator app up at its next sign-in" in said
    assert "its passkeys count again when passkeys are turned back on" in said
