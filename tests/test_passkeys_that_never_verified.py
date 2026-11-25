"""While the vault asks every passkey to verify the person, a key that never has is no second factor
(app/core/webauthn_settings.py, verified_the_person).

An administrator turns "the authenticator must verify the person" off so that keys with no PIN can be added, and
later turns it back on. From then on every use of such a key is refused. Counted as the account's factor all the
same, the key left every account whose only factor it was, administrators among them, held at a step it could not
answer. Such a key no longer counts: the account sets a factor up again at its next sign-in and is told why, the
Sign-in page shows how many such keys there are before the switch is saved, their owners are told when it is
turned on, and a requirement on administrators is not left with nobody able to meet it. A key that verifies the
person at a later use (its owner set a PIN) counts again from that use.
"""
import types
import uuid
from datetime import datetime, timedelta

import pytest

from _memory_db import MemoryDB
from _webauthn_softauth import FLAG, SoftAuthenticator
# The route harness sets the application's overrides itself: cleared after every test here, as in its own file.
from test_passkey_routes import Harness as RouteHarness, _call as _rcall, _clean_overrides  # noqa: F401
from test_passkey_settings import _mod, _resolving
from test_passkey_settings import _the_vault_has_an_address  # noqa: F401  (a fixture, used by every test here)
from test_passkey_sign_in import Harness as SignInHarness, _api, _call, _user

pytestmark = pytest.mark.unit

IP = "203.0.113.9"


def _key(user, *, verified, **extra):
    fields = dict(id=uuid.uuid4(), user_id=user.id, retired_at=None, cose_alg=-7, rp_id=None, label="key",
                  uv_initialized=verified)
    fields.update(extra)
    return types.SimpleNamespace(**fields)


def test_a_key_that_never_verified_the_person_counts_only_while_the_vault_does_not_ask_for_it(monkeypatch):
    registry, wss = _mod()
    from app.core.models import WebAuthnCredential
    alice = _user()
    h = SignInHarness(monkeypatch, [alice])
    never, did = _key(alice, verified=False), _key(alice, verified=True)
    h.db.rows_of(WebAuthnCredential).append(never)
    # The rule off: the key is a factor like any other.
    _resolving(monkeypatch, registry, {wss.REQUIRE_UV: False})
    assert wss.verified_the_person(never) is True and wss.usable_passkeys(h.db, alice.id) == 1
    assert wss.only_lapsed_passkeys(h.db, alice.id) is False and wss.why_none_can_be_used(h.db, alice.id) is None
    # Asked what the rule would leave if it were turned on: nothing.
    assert wss.verified_the_person(never, True) is False
    assert wss.usable_passkeys(h.db, alice.id, verification=True) == 0
    # The rule on (as it is by default): the key is on the account in name only.
    _resolving(monkeypatch, registry, {wss.REQUIRE_UV: True})
    assert wss.require_uv() is True
    assert wss.verified_the_person(never) is False and wss.verified_the_person(did) is True
    assert wss.usable_passkeys(h.db, alice.id) == 0 and wss.only_lapsed_passkeys(h.db, alice.id) is True
    assert wss.why_none_can_be_used(h.db, alice.id) == "passkeys_without_verification"
    assert wss.usable_passkeys(h.db, alice.id, whatever_the_switch=True) == 0
    assert wss.usable_passkeys(h.db, alice.id, verification=False) == 1         # ...and what turning it off gives back
    # A key that did verify beside it: the account has a passkey, and nothing to be told.
    h.db.rows_of(WebAuthnCredential).append(did)
    assert wss.usable_passkeys(h.db, alice.id) == 1 and wss.only_lapsed_passkeys(h.db, alice.id) is False
    assert wss.why_none_can_be_used(h.db, alice.id) is None
    assert wss.usable_passkeys(h.db, alice.id, without=did.id) == 0
    # A row that says nothing of it is one that never did.
    del never.uv_initialized
    assert wss.verified_the_person(never) is False
    # The other reasons come first: a key made elsewhere, or of an algorithm that ran out, is told as that.
    h.db.rows_of(WebAuthnCredential).remove(did)
    never.uv_initialized = False
    never.rp_id = "old.example.test"
    assert wss.why_none_can_be_used(h.db, alice.id) == "passkeys_at_another_address"
    never.rp_id = None
    monkeypatch.setattr(wss, "algorithm_usable", lambda db, alg, now=None: (False, False))
    assert wss.why_none_can_be_used(h.db, alice.id) == "passkeys_no_longer_accepted"
    # With passkeys turned off none is a factor, by the deployment's choice, and that is what the account is told.
    _resolving(monkeypatch, registry, {wss.MODE: "off", wss.REQUIRE_UV: True})
    assert wss.only_lapsed_passkeys(h.db, alice.id) is True
    assert wss.why_none_can_be_used(h.db, alice.id) == "passkeys_turned_off"


@pytest.mark.parametrize("role", ["user", "admin"])
def test_an_account_whose_only_passkey_never_verified_sets_a_factor_up_again_and_signs_in(monkeypatch, role):
    """From the password to a session. With the rule off the account is asked for its passkey. The rule turned on,
    the key would be refused: the sign-in is held for a set-up instead, behind the password, and says why; with an
    authenticator set up it ends in a session. The rule off again, the passkey is asked for again."""
    registry, wss = _mod()
    from app.core.models import PendingLogin, SecondFactorEnrollment, WebAuthnCredential
    from app.services import sign_in
    S = _api()
    in_effect, effective = S._login_second_factor_in_effect, S._second_factor_effective      # as the server has them
    bob = _user("bob", role=role)
    h = SignInHarness(monkeypatch, [bob])
    monkeypatch.setattr(S, "_login_second_factor_in_effect", in_effect)
    monkeypatch.setattr(S, "_second_factor_effective", effective)
    _resolving(monkeypatch, registry, {wss.MODE: "optional", wss.REQUIRE_UV: False})
    h.db.rows_of(WebAuthnCredential).append(_key(bob, verified=False))

    def after_the_password():
        outcome = sign_in.finish(h.db, sign_in.SignInResult(bob, ["pwd"], IP))
        assert isinstance(outcome, sign_in.PendingStep)
        return outcome.body

    body = after_the_password()
    assert body["enrollment_required"] is False and body["methods"] == ["passkey"], body
    assert "set_up_again" not in body
    # An administrator turns the rule back on.
    _resolving(monkeypatch, registry, {wss.MODE: "optional", wss.REQUIRE_UV: True})
    assert S._second_factor_to_set_up_again(h.db, bob) is True and sign_in.holds_a_factor(h.db, bob) is False
    body = after_the_password()
    assert body["stage"] == "second_factor" and body["enrollment_required"] is True, body
    assert body["methods"] == [] and "totp" in body["enrollment_methods"], body
    assert body["set_up_again"] == "passkeys_without_verification"
    # The set-up, then the code: a session.
    h.db.rows_of(SecondFactorEnrollment).append(
        types.SimpleNamespace(id=uuid.uuid4(), user_id=bob.id, method="totp", status="active"))
    held = h.db.rows_of(PendingLogin)[-1]
    done = sign_in.finish(h.db, sign_in.SignInResult(bob, ["pwd", "totp"], IP, pending=held, sessions_ended=0))
    assert isinstance(done, sign_in.SignedIn) and held.consumed_at is not None
    # It holds a factor again: asked for the code, never for a key it cannot give.
    assert S._second_factor_to_set_up_again(h.db, bob) is False
    body = after_the_password()
    assert body["enrollment_required"] is False and body["methods"] == ["totp", "recovery"], body
    # The rule off again: the passkey counts again, by itself.
    _resolving(monkeypatch, registry, {wss.MODE: "optional", wss.REQUIRE_UV: False})
    body = after_the_password()
    assert body["enrollment_required"] is False and body["methods"] == ["totp", "recovery", "passkey"], body


def test_the_rule_is_not_turned_on_over_a_requirement_no_administrator_could_then_meet(monkeypatch):
    """Administrators must hold a passkey, the grace has run out, and the only keys they hold never verified the
    person: turning the rule on would leave none of them with a passkey that counts."""
    registry, wss = _mod()
    from app.core import public_url
    from app.core.models import User, WebAuthnCredential
    root = _user("root", role="admin", passkey_required_since=datetime.utcnow() - timedelta(days=30),
                 passkey_requirement_cleared_at=None)
    ada = _user("ada", role="admin", passkey_required_since=datetime.utcnow() - timedelta(days=30),
                passkey_requirement_cleared_at=None)
    db = MemoryDB({User: [root, ada], WebAuthnCredential: [_key(root, verified=False), _key(ada, verified=False)]})
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": True})
    on_admins = {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["admin"], wss.GRACE_DAYS: 14}
    _resolving(monkeypatch, registry, dict(on_admins, **{wss.REQUIRE_UV: False}))
    assert wss.save_refusal(db, wss.GRACE_DAYS, 7) is None            # as things are, each holds a key that counts
    refused = wss.save_refusal(db, wss.REQUIRE_UV, True)
    assert refused and "no administrator" in refused
    assert "no administrator" in wss.save_refusal(db, wss.REQUIRE_UV, None)      # back to the default: on
    assert wss.save_refusal(db, wss.REQUIRE_UV, False) is None
    # One administrator holds a key that verified the person: the rule may be turned on.
    ada_key = _key(ada, verified=True)
    db.rows_of(WebAuthnCredential).append(ada_key)
    assert wss.save_refusal(db, wss.REQUIRE_UV, True) is None
    db.rows_of(WebAuthnCredential).remove(ada_key)
    # ...or one is still within the grace, or was cleared by the server's operator.
    ada.passkey_required_since = datetime.utcnow() - timedelta(days=2)
    assert wss.save_refusal(db, wss.REQUIRE_UV, True) is None
    ada.passkey_required_since = datetime.utcnow() - timedelta(days=30)
    ada.passkey_requirement_cleared_at = datetime.utcnow()
    assert wss.save_refusal(db, wss.REQUIRE_UV, True) is None
    ada.passkey_requirement_cleared_at = None
    assert "no administrator" in wss.save_refusal(db, wss.REQUIRE_UV, True)
    # No requirement on administrators: the rule is theirs to turn on (each then sets a factor up again).
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["user"],
                                       wss.REQUIRE_UV: False})
    assert wss.save_refusal(db, wss.REQUIRE_UV, True) is None
    _resolving(monkeypatch, registry, {wss.MODE: "optional", wss.REQUIRED_ROLES: ["admin"], wss.REQUIRE_UV: False})
    assert wss.save_refusal(db, wss.REQUIRE_UV, True) is None
    # With the rule already on, the other saves count the same way: these keys protect nobody.
    _resolving(monkeypatch, registry, dict(on_admins, **{wss.REQUIRE_UV: True}))
    assert "no administrator" in wss.save_refusal(db, wss.GRACE_DAYS, 7)


def _settings_route(monkeypatch, db, root, registry, wss):
    """The Sign-in settings routes as an administrator calls them; returns (api, what was told to whom)."""
    import time
    import app.api.api_server as S
    import app.core.public_url as public_url
    from app.api import sign_in_settings_router as router
    from app.api.user_management_api import require_interactive_admin as uma
    from app.core import rate_limiter as R
    from app.core import setting_changes
    from app.core.database import get_db
    from app.core.rate_limiter import rate_limiter
    monkeypatch.setitem(S.app.dependency_overrides, get_db, lambda: db)
    monkeypatch.setitem(S.app.dependency_overrides, uma, lambda: root)
    monkeypatch.setattr(rate_limiter, "check_rate_limit", lambda *a, **kw: (True, 1, 0))
    R._cb_record_failure(time.time())
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": True, "rp_id": "vault.example.test"})
    monkeypatch.setattr(wss, "trust_anchors", lambda: ())
    monkeypatch.setattr(router, "limit_statements", lambda db, timeout_ms=0: None)
    monkeypatch.setattr(router, "_step_up", lambda db, user, request: None)
    in_force = {}

    def request(db, key, value, *, actor, now=None, judge=None):
        in_force[key] = registry.spec_for(key).default if value is None else value
        return setting_changes.Outcome("applied", key=key, old=None, new=value)
    monkeypatch.setattr(setting_changes, "request", request)
    monkeypatch.setattr(setting_changes, "announce_outcome", lambda outcome, by: None)
    monkeypatch.setattr(registry, "refresh", lambda *a, **k: True)
    real = registry.resolve
    monkeypatch.setattr(registry, "resolve", lambda key: in_force[key] if key in in_force else real(key))
    told = []
    monkeypatch.setattr(S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None: (
        told.append((sorted(ids), ntype, title, body, target, dedup_prefix)) or list(ids)))
    return S, told, in_force


def test_the_sign_in_page_is_told_how_many_keys_never_verified_and_their_owners_are_told_when_the_rule_goes_on(
        monkeypatch):
    registry, wss = _mod()
    from app.core.models import User, WebAuthnCredential
    root, alice, bob, carol = (_user(name, role="admin" if name == "root" else "user",
                                     passkey_requirement_cleared_at=None) for name in ("root", "alice", "bob", "carol"))
    keys = [_key(alice, verified=False), _key(alice, verified=False),           # alice: two, none that did
            _key(bob, verified=False), _key(bob, verified=True),                # bob: one of each
            _key(carol, verified=True),                                         # carol: one that did
            _key(carol, verified=False, retired_at=datetime.utcnow())]          # ...and a retired one, not in use
    db = MemoryDB({User: [root, alice, bob, carol], WebAuthnCredential: keys})
    S, told, in_force = _settings_route(monkeypatch, db, root, registry, wss)
    assert wss.never_verified(db) == {"passkeys": 3, "owners": [alice.id, bob.id], "accounts_with_no_other": 1}
    # The page has the numbers whichever way the rule stands: before it is turned on, and after.
    in_force[wss.REQUIRE_UV] = False
    status, body = _call(S, "GET", "/settings/sign-in")
    assert status == 200 and body["passkeys_without_verification"] == 3
    assert body["accounts_with_only_such_passkeys"] == 1
    # Turned on: the two owners are told, once, in words that say what to do.
    status, body = _call(S, "PUT", "/settings/sign-in/webauthn_require_uv", {"value": True})
    assert status == 200 and body["status"] == "applied", body
    ((ids, ntype, title, text, target, dedup),) = told
    assert ids == sorted([str(alice.id), str(bob.id)]) and ntype == "security" and target == "#profile"
    assert title == "One of your passkeys no longer counts here"
    assert text == ("This vault now asks every passkey to check a PIN, a fingerprint or a face. A passkey of yours "
                    "has never done so, and is refused until it does: set a PIN on it and sign in with it, or add "
                    "another passkey or an authenticator app. If it was your only second factor, you set one up "
                    "again at your next sign-in.")
    assert dedup == f"passkey_never_verified:{datetime.utcnow().date().isoformat()}"
    assert _call(S, "GET", "/settings/sign-in")[1]["passkeys_without_verification"] == 3
    # Saved again while it is on, turned off, or another setting saved: nobody is told anything.
    del told[:]
    assert _call(S, "PUT", "/settings/sign-in/webauthn_require_uv", {"value": True})[0] == 200
    assert _call(S, "PUT", "/settings/sign-in/webauthn_require_uv", {"value": False})[0] == 200
    assert _call(S, "PUT", "/settings/sign-in/webauthn_require_uv", {"value": False})[0] == 200     # off, and stays off
    assert _call(S, "PUT", "/settings/sign-in/webauthn_enrollment_grace_days", {"value": 20})[0] == 200
    assert told == []
    # Back to the deployment's value (on) from off: told again.
    assert _call(S, "PUT", "/settings/sign-in/webauthn_require_uv", {"value": None})[0] == 200
    assert len(told) == 1
    # Nobody holds such a key: nothing is sent. A failure to tell undoes nothing.
    del told[:]
    for key in keys:
        key.uv_initialized = True
    in_force[wss.REQUIRE_UV] = False
    assert _call(S, "PUT", "/settings/sign-in/webauthn_require_uv", {"value": True})[0] == 200 and told == []
    keys[0].uv_initialized = False
    in_force[wss.REQUIRE_UV] = False

    def broken(*a, **k):
        raise RuntimeError("the notices are down")
    monkeypatch.setattr(S, "_notify_users", broken)
    status, body = _call(S, "PUT", "/settings/sign-in/webauthn_require_uv", {"value": True})
    assert status == 200 and body["status"] == "applied"
    # A database from before passkeys has none.
    assert wss.never_verified(MemoryDB({User: [root]})) == {"passkeys": 0, "owners": [], "accounts_with_no_other": 0}


def test_a_key_counts_from_the_first_proof_that_verified_the_person(monkeypatch):
    """Its owner sets a PIN on the key and signs in with it: the proof carries the verification, and from then on
    the key is one of the account's factors. A proof without it is refused while the rule is on, and changes
    nothing; with the rule off it is accepted and leaves the key as one that never verified."""
    registry, wss = _mod()
    alice = _user()
    h = SignInHarness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    row.uv_initialized = False
    assert wss.usable_passkeys(h.db, alice.id) == 0
    status, body = h.sign_in(auth, flags=FLAG.UP)
    assert status == 401 and row.uv_initialized is False and wss.usable_passkeys(h.db, alice.id) == 0
    status, body = h.sign_in(auth, flags=FLAG.UP | FLAG.UV, sign_count=2)
    assert status == 200, body
    assert row.uv_initialized is True and wss.usable_passkeys(h.db, alice.id) == 1
    # What the proof leaves, by itself: the mark is only ever raised, and before the sign-in is judged.
    S = h.S
    key = types.SimpleNamespace(uv_initialized=False, sign_count=1, backup_state=False)
    S._passkey_proved(key, types.SimpleNamespace(uv=False, sign_count=5, bs=True))
    assert (key.uv_initialized, key.sign_count, key.backup_state) == (False, 5, True)
    S._passkey_proved(key, types.SimpleNamespace(uv=True, sign_count=6, bs=False))
    assert (key.uv_initialized, key.sign_count, key.backup_state) == (True, 6, False)
    S._passkey_proved(key, types.SimpleNamespace(uv=False, sign_count=7, bs=False))
    assert key.uv_initialized is True
    import inspect
    source = inspect.getsource(S.passkey_sign_in_verify)
    assert source.index("_passkey_verified_the_person(row, assertion)") < source.index("sign_in.finish(db, result)")
    # With the rule off a proof without the verification signs in and leaves the key as it was.
    h2 = SignInHarness(monkeypatch, [alice])
    _resolving(monkeypatch, registry, {wss.REQUIRE_UV: False})
    auth2, row2 = h2.enroll(alice)
    row2.uv_initialized = False
    status, body = h2.sign_in(auth2, flags=FLAG.UP)
    assert status == 200 and row2.uv_initialized is False, body


def test_a_key_that_never_verified_may_be_added_again_and_is_shown_as_what_it_is(monkeypatch):
    """Its owner sets a PIN on the same key and adds it again. Named among the keys a registration may not repeat,
    the authenticator would answer that it is already registered. While the rule is off it is named as any other
    key. The lists say of each key whether it verified the person, and whether the vault asks for it."""
    registry, wss = _mod()
    alice = _user()
    h = RouteHarness(monkeypatch, alice)
    now = datetime.utcnow()

    def row(credential_id, verified):
        return types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, credential_id=credential_id, retired_at=None,
                                     provisional_until=None, created_at=now, transports=["usb"], label="k",
                                     backup_eligible=False, cose_alg=-7, last_used_at=None, rp_id=None,
                                     uv_initialized=verified, attested=False)
    never, did = row(b"never-verified", False), row(b"did-verify-it", True)
    h.rows().extend([never, did])

    def excluded():
        status, body = _rcall(h.S, "POST", "/users/me/passkeys/register/options", {}, {"X-Second-Factor": "ok"})
        assert status == 200, body
        return {entry["id"] for entry in body["options"]["publicKey"]["excludeCredentials"]}
    from app.services import webauthn_service as ws
    assert excluded() == {ws.b64url(b"did-verify-it")}
    _resolving(monkeypatch, registry, {wss.REQUIRE_UV: False})
    assert excluded() == {ws.b64url(b"never-verified"), ws.b64url(b"did-verify-it")}
    status, body = _rcall(h.S, "GET", "/users/me/passkeys")
    assert status == 200 and body["require_user_verification"] is False
    assert [k["user_verified"] for k in body["passkeys"]] == [False, True]
    _resolving(monkeypatch, registry, {wss.REQUIRE_UV: True})
    assert _rcall(h.S, "GET", "/users/me/passkeys")[1]["require_user_verification"] is True
    # An administrator sees the same of another account's keys.
    import app.core.endpoint_permissions as ep
    monkeypatch.setattr(ep, "check_endpoint_permission", lambda *a, **k: None)
    status, body = _rcall(h.S, "GET", f"/users/{alice.id}/passkeys")
    assert status == 200 and body["require_user_verification"] is True
    assert [k["user_verified"] for k in body["passkeys"]] == [False, True]
    # A soft authenticator that checks nothing still makes a key with the rule off, marked as one that never did.
    _resolving(monkeypatch, registry, {wss.REQUIRE_UV: False})
    h.rows().clear()
    status, body, _auth = h.register(authenticator=SoftAuthenticator(), flags=FLAG.UP)
    assert status == 201 and h.rows()[0].uv_initialized is False, body
    assert _rcall(h.S, "GET", "/users/me/passkeys")[1]["passkeys"][0]["user_verified"] is False


def test_a_key_of_a_removed_algorithm_may_be_replaced_on_the_same_authenticator(monkeypatch):
    """A Windows Hello key was made as RS256. An administrator removes RS256: the key is accepted for 30 more
    days, and its owner is told to register a new passkey before then. On the same device that was refused: the
    old key was named among the keys the registration may not repeat, so the authenticator answered "already
    registered". Named are the keys the account goes on using."""
    registry, wss = _mod()
    alice = _user()
    h = RouteHarness(monkeypatch, alice)
    now = datetime.utcnow()

    def row(credential_id, **what):
        fields = dict(id=uuid.uuid4(), user_id=alice.id, credential_id=credential_id, retired_at=None,
                      provisional_until=None, created_at=now, transports=["internal"], label="k", backup_eligible=False,
                      cose_alg=-7, last_used_at=None, rp_id=None, uv_initialized=True, attested=False)
        fields.update(what)
        return types.SimpleNamespace(**fields)
    kept, to_replace = row(b"es256-kept"), row(b"rs256-removed", cose_alg=-257)
    elsewhere = row(b"made-elsewhere", rp_id="another.example.test")
    h.rows().extend([kept, to_replace, elsewhere])
    from app.services import webauthn_service as ws

    def excluded():
        status, body = _rcall(h.S, "POST", "/users/me/passkeys/register/options", {}, {"X-Second-Factor": "ok"})
        assert status == 200, body
        return {entry["id"] for entry in body["options"]["publicKey"]["excludeCredentials"]}
    # Every algorithm accepted: both keys made here are named (the one made at another address is no factor here).
    assert excluded() == {ws.b64url(b"es256-kept"), ws.b64url(b"rs256-removed")}
    # RS256 removed a moment ago: its key is still a factor for its 30 days, and may be replaced already.
    _resolving(monkeypatch, registry, {wss.ALLOWED_ALGS: ["ES256"]})
    monkeypatch.setattr(wss, "algorithm_usable", lambda db, cose_alg, now=None: (True, cose_alg != -7))
    assert wss.usable_passkeys(h.db, alice.id) == 2                    # both are factors still
    assert excluded() == {ws.b64url(b"es256-kept")}
    # Its 30 days over: no factor any more, and still not named.
    monkeypatch.setattr(wss, "algorithm_usable", lambda db, cose_alg, now=None: (cose_alg == -7, False))
    assert wss.usable_passkeys(h.db, alice.id) == 1 and excluded() == {ws.b64url(b"es256-kept")}
