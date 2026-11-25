"""A passkey answers only at the address it was made at, so one made at another address than the vault has now is
no second factor here (app/core/webauthn_settings.py, at_this_address).

The vault moves to another host name (a supported change: dockvault.py setup), or its address becomes one that can
carry no passkey. Every key was made for the old name, and the browser has none to give for the new one. Counted
as the account's factor all the same, such a key left every account whose only factor was a passkey, administrators
among them, held at a step it could not answer. Each key records the address it was made at; only the keys of the
address the vault has now count; an account left with none it can use sets a factor up again at its next sign-in,
as after a reset, and is told why. If the address goes back, the keys count again by themselves.
"""
import types
import uuid
from datetime import datetime

import pytest

from _bare_api_env import set_bare_api_env
# The route harness sets the application's overrides itself: cleared after every test here, as in its own file.
from test_passkey_routes import Harness as RouteHarness, _clean_overrides  # noqa: F401
from test_passkey_settings import _mod, _resolving
from test_passkey_sign_in import ORIGIN, RP_ID, Harness as SignInHarness, _api, _user

pytestmark = pytest.mark.unit

ELSEWHERE = "old.example.test"
IP = "203.0.113.9"


def _address(monkeypatch, host):
    """The vault's address as it is now: ``host``, or none a passkey can be made at."""
    from app.services import webauthn_service as ws
    monkeypatch.setattr(ws, "relying_party", lambda name: (
        ws.RelyingParty(rp_id=host, origin=f"https://{host}", name="DockVault") if host else None))


def _key(user, made_at, **extra):
    fields = dict(id=uuid.uuid4(), user_id=user.id, uv_initialized=True, retired_at=None, cose_alg=-7, rp_id=made_at, label="key")
    fields.update(extra)
    return types.SimpleNamespace(**fields)


def test_a_key_is_one_of_the_address_it_was_made_at(monkeypatch):
    registry, wss = _mod()
    from app.core.models import WebAuthnCredential
    alice = _user()
    h = SignInHarness(monkeypatch, [alice])
    _resolving(monkeypatch, registry, {wss.MODE: "optional"})
    here, there, unrecorded = _key(alice, RP_ID), _key(alice, ELSEWHERE), _key(alice, None)
    assert wss.address_now() == RP_ID
    assert [wss.at_this_address(k) for k in (here, there, unrecorded)] == [True, False, True]
    h.db.rows_of(WebAuthnCredential).extend([there])
    assert wss.usable_passkeys(h.db, alice.id) == 0 and wss.only_lapsed_passkeys(h.db, alice.id) is True
    assert wss.why_none_can_be_used(h.db, alice.id) == "passkeys_at_another_address"
    h.db.rows_of(WebAuthnCredential).append(here)
    assert wss.usable_passkeys(h.db, alice.id) == 1 and wss.only_lapsed_passkeys(h.db, alice.id) is False
    assert wss.why_none_can_be_used(h.db, alice.id) is None
    assert wss.usable_passkeys(h.db, alice.id, without=here.id) == 0
    # The vault at the other address: the other key is the one that counts.
    _address(monkeypatch, ELSEWHERE)
    assert [wss.at_this_address(k) for k in (here, there, unrecorded)] == [False, True, True]
    assert wss.usable_passkeys(h.db, alice.id) == 1
    # An address no passkey can be made at: none can be used there, whatever was recorded.
    _address(monkeypatch, None)
    assert wss.address_now() == "" and not any(wss.at_this_address(k) for k in (here, there, unrecorded))
    assert wss.usable_passkeys(h.db, alice.id) == 0 and wss.only_lapsed_passkeys(h.db, alice.id) is True
    # A key made here of an algorithm that ran out is told apart from one made elsewhere.
    _address(monkeypatch, RP_ID)
    h.db.rows_of(WebAuthnCredential).remove(there)
    monkeypatch.setattr(wss, "algorithm_usable", lambda db, alg, now=None: (False, False))
    assert wss.why_none_can_be_used(h.db, alice.id) == "passkeys_no_longer_accepted"
    # With passkeys turned off none is a factor, by the deployment's choice, and that is what the account is
    # told, whatever else is true of its keys.
    _resolving(monkeypatch, registry, {wss.MODE: "off"})
    assert wss.only_lapsed_passkeys(h.db, alice.id) is True
    assert wss.why_none_can_be_used(h.db, alice.id) == "passkeys_turned_off"

def test_an_address_written_with_a_dot_at_its_end_is_one_no_passkey_is_made_or_counted_at(monkeypatch):
    """The vault's address written with the dot: no passkey can be made there, and one made at the name without
    it counts as made elsewhere (its account sets a factor up again), not as one a browser there could give."""
    registry, wss = _mod()
    import app.core.config as config
    from app.core import public_url
    alice = _user()
    made_without_the_dot = _key(alice, "vault.example.test")
    monkeypatch.setattr(config.settings, "allowed_hosts", "vault.example.test", raising=False)
    assert wss.address_now() == "vault.example.test" and wss.at_this_address(made_without_the_dot) is True
    monkeypatch.setattr(config.settings, "allowed_hosts", "vault.example.test.", raising=False)
    assert public_url.readiness()["reason"] == public_url.ADDRESS_NOT_USABLE
    assert wss.address_now() == "" and wss.at_this_address(made_without_the_dot) is False
    assert wss.passkeys_can_be_made() is False


@pytest.mark.parametrize("role", ["user", "admin"])
@pytest.mark.parametrize("address", ["another host name", "one that can carry no passkey"])
def test_an_account_whose_passkeys_were_made_at_another_address_sets_a_factor_up_again_and_signs_in(
        monkeypatch, role, address):
    """From the password to a session. Before the move the account is asked for its passkey. After it the browser
    has none to give: the sign-in is held for a set-up instead, behind the password, and says why; with an
    authenticator set up it ends in a session. The address back, the passkey is asked for again."""
    registry, wss = _mod()
    from app.core.models import PendingLogin, SecondFactorEnrollment, WebAuthnCredential
    from app.services import sign_in
    S = _api()
    in_effect, effective = S._login_second_factor_in_effect, S._second_factor_effective      # as the server has them
    bob = _user("bob", role=role)
    h = SignInHarness(monkeypatch, [bob])
    monkeypatch.setattr(S, "_login_second_factor_in_effect", in_effect)
    monkeypatch.setattr(S, "_second_factor_effective", effective)
    _resolving(monkeypatch, registry, {wss.MODE: "optional"})
    h.db.rows_of(WebAuthnCredential).append(_key(bob, RP_ID))

    def after_the_password():
        outcome = sign_in.finish(h.db, sign_in.SignInResult(bob, ["pwd"], IP))
        assert isinstance(outcome, sign_in.PendingStep)
        return outcome.body

    body = after_the_password()
    assert body["enrollment_required"] is False and body["methods"] == ["passkey"], body
    assert "set_up_again" not in body
    # The vault moves.
    _address(monkeypatch, "new.example.test" if address == "another host name" else None)
    assert S._second_factor_to_set_up_again(h.db, bob) is True and sign_in.holds_a_factor(h.db, bob) is False
    body = after_the_password()
    assert body["stage"] == "second_factor" and body["enrollment_required"] is True, body
    assert body["methods"] == [] and "totp" in body["enrollment_methods"], body
    assert body["set_up_again"] == "passkeys_at_another_address"
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
    # The address goes back: the passkey counts again, by itself.
    _address(monkeypatch, RP_ID)
    body = after_the_password()
    assert body["enrollment_required"] is False and body["methods"] == ["totp", "recovery", "passkey"], body


def test_a_role_that_must_hold_a_passkey_has_one_grace_while_its_keys_are_elsewhere_and_none_left_when_they_are_back(
        monkeypatch):
    """The key that met the requirement was made at another address: the requirement applies again, and the
    account sets a factor up again because its only factor is gone, as after a reset. Through the sign-in, as the
    server runs it: the first sign-in after the move writes the day the requirement began, and no later one moves
    it, so the grace runs once and does not start over. The address back, the key meets the requirement again
    and the next sign-in ends that day: left on the account, it would have made the account overdue at once, with
    no grace at all, the next time its last passkey left it."""
    registry, wss = _mod()
    from datetime import timedelta
    from app.core.models import WebAuthnCredential
    from app.services import sign_in
    S = _api()
    in_effect, effective = S._login_second_factor_in_effect, S._second_factor_effective      # as the server has them
    carol = _user("carol", passkey_required_since=None, passkey_requirement_cleared_at=None)
    h = SignInHarness(monkeypatch, [carol])
    monkeypatch.setattr(S, "_login_second_factor_in_effect", in_effect)
    monkeypatch.setattr(S, "_second_factor_effective", effective)
    _resolving(monkeypatch, registry, {wss.MODE: wss.REQUIRED_FOR_ROLES, wss.REQUIRED_ROLES: ["user"]})
    monkeypatch.setattr(wss, "passkeys_can_be_made", lambda: True)
    h.db.rows_of(WebAuthnCredential).append(_key(carol, RP_ID))

    def signs_in():
        return sign_in.finish(h.db, sign_in.SignInResult(carol, ["pwd"], IP))
    assert wss.requirement(h.db, carol).required is False
    signs_in()
    assert carol.passkey_required_since is None            # a requirement that is met writes nothing
    _address(monkeypatch, "new.example.test")
    assert wss.requirement(h.db, carol).required is True and S._second_factor_to_set_up_again(h.db, carol) is True
    held = signs_in()
    assert isinstance(held, sign_in.PendingStep) and held.body["set_up_again"] == "passkeys_at_another_address"
    began = carol.passkey_required_since
    assert began is not None
    for _again in range(3):
        signs_in()
        assert carol.passkey_required_since == began       # the grace runs once: no sign-in starts it over
    _address(monkeypatch, RP_ID)
    assert wss.requirement(h.db, carol).required is False and carol.passkey_required_since == began
    signs_in()
    assert carol.passkey_required_since is None            # ended where the key meets the requirement again
    # The vault moves again, weeks later: a grace of its own, from the first sign-in after that move.
    _address(monkeypatch, "new.example.test")
    later = datetime.utcnow() + timedelta(days=60)
    need = wss.requirement(h.db, carol, now=later)
    assert need.required is True and need.since is None and need.overdue is False
    # Only a passkey the account can use ends that day. A requirement that stops applying for another reason
    # (the role's rule switched off for a while) leaves it, as it always did: switching the rule off and on
    # hands nobody a new grace.
    signs_in()
    began_again = carol.passkey_required_since
    assert began_again is not None
    _resolving(monkeypatch, registry, {wss.MODE: "optional"})
    assert wss.requirement(h.db, carol).required is False
    signs_in()
    assert carol.passkey_required_since == began_again


def test_a_key_records_the_address_it_is_made_at_and_one_with_none_gets_it_at_its_first_use(monkeypatch):
    alice = _user()
    h = RouteHarness(monkeypatch, alice)
    status, shown, _auth = h.register(label="new")
    assert status == 201, shown
    assert [row.rp_id for row in h.rows()] == [RP_ID]
    # A row written before the address was recorded: it is taken as made here, and says so once it answered here.
    erin = _user("erin")
    s = SignInHarness(monkeypatch, [erin])
    auth, row = s.enroll(erin)
    assert getattr(row, "rp_id", None) is None
    status, body = s.sign_in(auth)[:2]
    assert status == 200, body
    assert row.rp_id == RP_ID and ORIGIN.endswith(RP_ID)
    # And so where such a key first answers at a further step (a step-up, a second factor), not at a sign-in.
    from test_passkey_second_factor import Harness as StepHarness
    fay = _user("fay")
    f = StepHarness(monkeypatch, [fay])
    auth, row = f.enroll(fay)
    assert getattr(row, "rp_id", None) is None
    status, body = f.step_up_with_passkey(auth, "account.second_factor")
    assert status == 200 and "receipt" in body, body
    assert row.rp_id == RP_ID


def test_an_administrators_removal_that_leaves_only_keys_made_elsewhere_leaves_no_factor(monkeypatch):
    registry, wss = _mod()
    from _memory_db import MemoryDB
    from app.core import auditor_rights, credential_changes as cc, legal_holds
    from app.core.models import SecondFactorEnrollment, User, WebAuthnCredential
    from app.services import sign_in
    S = _api()
    _address(monkeypatch, RP_ID)
    _resolving(monkeypatch, registry, {wss.MODE: "optional"})
    admin, carol = _user("root", role="admin"), _user("carol")
    lost, old = _key(carol, RP_ID, label="phone"), _key(carol, ELSEWHERE, label="old")
    db = MemoryDB({User: [admin, carol], WebAuthnCredential: [lost, old], SecondFactorEnrollment: []})
    monkeypatch.setattr(auditor_rights, "after_credential_change", lambda *a, **k: None)
    monkeypatch.setattr(legal_holds, "after_starter_change", lambda *a, **k: None)
    ended = []
    monkeypatch.setattr(S, "_revoke_sessions", lambda db_, **kw: ended.append(kw["user_id"]) or 0)
    monkeypatch.setattr(sign_in, "spend_sign_ins_under_way", lambda db_, user_id: 0)
    result = S._apply_credential_change(db, cc.PASSKEY, carol, {"passkey_id": str(lost.id)}, actor_id=admin.id,
                                        actor_name="root")
    assert result["left_without_a_factor"] is True and ended == [carol.id] and old.retired_at is None
    # No mark of a factor taken away: the key she still holds says by itself that she sets one up again, and
    # says nothing once it can be used again. With the mark, the next start would have retired that key as one
    # from before a reset, and the mark would have outlived the address going back.
    assert carol.second_factor_reset_at is None
    assert S._second_factor_to_set_up_again(db, carol) is True
    _address(monkeypatch, ELSEWHERE)
    assert wss.usable_passkeys(db, carol.id) == 1 and S._second_factor_to_set_up_again(db, carol) is False
    # Her last key of all, removed: nothing is left to say it, so the mark does.
    _address(monkeypatch, RP_ID)
    result = S._apply_credential_change(db, cc.PASSKEY, carol, {"passkey_id": str(old.id)}, actor_id=admin.id,
                                        actor_name="root")
    assert result["left_without_a_factor"] is True and carol.second_factor_reset_at is not None


HERE = "vault.example.test"
OLDER = "older.example.test"


def _the_deployments_account_of_its_passkeys(monkeypatch, *, on=True):
    """The deployment's answer for seven accounts: ann (a key made here, one made elsewhere), ben and gus (ben
    one made elsewhere and a retired one, gus two made elsewhere), cy (a key with no address on record), dee (keys at two other
    addresses, and an authenticator app), eve (a key made here that never verified the person, one made elsewhere
    that did) and fay (a key made elsewhere, of an algorithm that is accepted no longer)."""
    set_bare_api_env()
    from _kept_db import kept_database
    from app.core import host_operator, webauthn_settings as wss
    from app.core.models import RoleEnum, SecondFactorEnrollment, User, WebAuthnCredential
    monkeypatch.setattr(wss, "address_now", lambda: HERE)
    monkeypatch.setattr(wss, "require_uv", lambda: True)
    monkeypatch.setattr(wss, "enabled", lambda: on)
    monkeypatch.setattr(wss, "allowed_alg_codes", lambda: (-7,))
    with kept_database() as (make, _engine):
        with make() as db:
            who = {n: User(username=n, email=None, password_hash="x", role=RoleEnum.USER, is_active=True)
                   for n in ("ann", "ben", "cy", "dee", "eve", "fay", "gus")}
            db.add_all(who.values())
            db.flush()
            for index, (owner, address, extra) in enumerate((
                    ("ann", HERE, {}), ("ann", ELSEWHERE, {}),
                    ("ben", ELSEWHERE, {}), ("ben", ELSEWHERE, {"retired_at": datetime(2026, 11, 1)}),
                    ("cy", None, {}),
                    ("dee", ELSEWHERE, {}), ("dee", OLDER, {}),
                    ("eve", HERE, {"uv_initialized": False}), ("eve", ELSEWHERE, {}),
                    ("fay", ELSEWHERE, {"cose_alg": -999}),
                    ("gus", ELSEWHERE, {}), ("gus", ELSEWHERE, {}))):
                db.add(WebAuthnCredential(**{**dict(
                    user_id=who[owner].id, credential_id=bytes([index + 1]) * 8, public_key_cose=b"k", cose_alg=-7,
                    rp_id=address, uv_initialized=True), **extra}))
            db.add(SecondFactorEnrollment(user_id=who["dee"].id, method="totp", secret_enc="sealed", status="active"))
            # An authenticator app that was never confirmed is no factor: gus is left with none all the same.
            db.add(SecondFactorEnrollment(user_id=who["gus"].id, method="totp", secret_enc="sealed", status="unconfirmed"))
            db.commit()
            return host_operator.passkey_addresses(db)


def test_the_deployment_says_where_its_passkeys_were_made(monkeypatch):
    said = _the_deployments_account_of_its_passkeys(monkeypatch)
    assert said == {"here": HERE, "on": True, "made_at": [
        {"address": ELSEWHERE, "passkeys": 7, "accounts": 6},        # gus holds two of them: one account
        {"address": OLDER, "passkeys": 1, "accounts": 1},
        {"address": HERE, "passkeys": 3, "accounts": 3}],
        # The accounts in groups that are alike: where their keys were made, at which of those addresses one of
        # them would be a factor, and whether they hold an authenticator app. No account is named.
        "holders": [
            {"made_at": [ELSEWHERE], "usable_at": [], "other_factor": False, "accounts": 1},                    # fay
            {"made_at": [ELSEWHERE], "usable_at": [ELSEWHERE], "other_factor": False, "accounts": 2},           # ben, gus
            {"made_at": [ELSEWHERE, OLDER], "usable_at": [ELSEWHERE, OLDER], "other_factor": True, "accounts": 1},   # dee
            {"made_at": [ELSEWHERE, HERE], "usable_at": [ELSEWHERE], "other_factor": False, "accounts": 1},     # eve
            {"made_at": [ELSEWHERE, HERE], "usable_at": [ELSEWHERE, HERE], "other_factor": False, "accounts": 1},   # ann
            {"made_at": [HERE], "usable_at": [HERE], "other_factor": False, "accounts": 1}]}                    # cy
    assert _the_deployments_account_of_its_passkeys(monkeypatch, on=False)["on"] is False


def _the_host_tool():
    import importlib.util
    from pathlib import Path
    spec = importlib.util.spec_from_file_location("dockvault_tool_for_passkeys",
                                                  Path(__file__).resolve().parents[1] / "dockvault.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


def test_the_host_tool_counts_an_account_once_and_says_which_set_a_factor_up_again(monkeypatch):
    """The deployment's own answer, read by the tool for the address the vault has and for one setup is about to
    give it. An account with keys at two other addresses is one account; one that holds an authenticator app, or
    a key it can use at that address, signs in with that and sets nothing up again; the ones the sentence names
    are the ones the sign-in holds (the same accounts for which the vault says a factor is to be set up again)."""
    tool = _the_host_tool()
    answer = _the_deployments_account_of_its_passkeys(monkeypatch)
    # Where the vault is: 8 keys made elsewhere, of 6 accounts (dee's two addresses are one account). ann uses the
    # key made here, dee the authenticator app; ben, gus, fay and eve (whose key made here never verified the
    # person) are left with none.
    said = tool.passkeys_elsewhere_note(answer, HERE)
    assert said == (
        "8 passkeys (of 6 accounts) were made at %s, %s and cannot be used at %s. 4 of those accounts have no "
        "other second factor to use there and set one up again at their next sign-in: with the account's "
        "password, or through its organisation's sign-in where it has none. The others sign in with another one "
        "(an authenticator app, or a passkey made there). The passkeys work again if the vault goes back to that "
        "address." % (ELSEWHERE, OLDER, HERE)), said
    # Setup about to move the vault to the older address: every key but dee's one there stops, of all 7
    # accounts; dee has the app, the other six are left with none.
    moved = tool.passkeys_elsewhere_note(answer, OLDER)
    assert moved.startswith("10 passkeys (of 7 accounts) were made at %s, %s and cannot be used at %s. 6 of those "
                            "accounts have no other second factor to use there and set one up again at their "
                            "next sign-in:" % (ELSEWHERE, HERE, OLDER)), moved
    assert "The other signs in with another one (an authenticator app, or a passkey made there)." in moved
    # An address no passkey can be made at: no key is a factor there, whatever address it was made at.
    nowhere = tool.passkeys_elsewhere_note(answer, "")
    assert nowhere.startswith("11 passkeys (of 7 accounts) were made at %s, %s, %s and cannot be used at the "
                              "address the vault has now (no passkey can be made there). 6 of those accounts "
                              % (ELSEWHERE, OLDER, HERE)), nowhere


def test_the_vault_holds_at_a_set_up_the_accounts_the_host_tool_names(monkeypatch):
    """The tool's number is the vault's: an account is among those that "set one up again" exactly when the
    sign-in would take it through a set-up because its passkeys cannot be used (only_lapsed_passkeys) and it
    holds no other factor."""
    set_bare_api_env()
    from _kept_db import kept_database
    from app.core import host_operator, webauthn_settings as wss
    from app.core.active_factors import active_factors
    from app.core.models import RoleEnum, SecondFactorEnrollment, User, WebAuthnCredential
    tool = _the_host_tool()
    monkeypatch.setattr(wss, "address_now", lambda: HERE)
    monkeypatch.setattr(wss, "require_uv", lambda: True)
    monkeypatch.setattr(wss, "enabled", lambda: True)
    monkeypatch.setattr(wss, "allowed_alg_codes", lambda: (-7,))
    monkeypatch.setattr(wss, "_removed", lambda db: {})
    with kept_database() as (make, _engine):
        with make() as db:
            who = {n: User(username=n, email=None, password_hash="x", role=RoleEnum.USER, is_active=True)
                   for n in ("ann", "ben", "dee", "eve", "fay")}
            db.add_all(who.values())
            db.flush()
            for index, (owner, address, extra) in enumerate((
                    ("ann", HERE, {}), ("ann", ELSEWHERE, {}), ("ben", ELSEWHERE, {}),
                    ("dee", ELSEWHERE, {}), ("dee", OLDER, {}),
                    ("eve", HERE, {"uv_initialized": False}), ("eve", ELSEWHERE, {}),
                    ("fay", ELSEWHERE, {"cose_alg": -999}))):
                db.add(WebAuthnCredential(**{**dict(
                    user_id=who[owner].id, credential_id=bytes([index + 1]) * 8, public_key_cose=b"k", cose_alg=-7,
                    rp_id=address, uv_initialized=True), **extra}))
            db.add(SecondFactorEnrollment(user_id=who["dee"].id, method="totp", secret_enc="sealed", status="active"))
            db.commit()
            held = sorted(name for name, user in who.items()
                          if not active_factors(db, user.id).any and wss.only_lapsed_passkeys(db, user.id))
            answer = host_operator.passkey_addresses(db)
    assert held == ["ben", "eve", "fay"]
    assert tool._holders_of_passkeys_elsewhere(answer["holders"], HERE) == (5, len(held))


def test_the_host_tool_says_how_many_passkeys_stop_working_at_another_address():
    tool = _the_host_tool()
    answer = {"ok": True, "here": "old.example.test", "made_at": [
        {"address": "old.example.test", "passkeys": 3, "accounts": 2}]}
    assert tool.passkeys_elsewhere_note(answer, "old.example.test") is None
    said = tool.passkeys_elsewhere_note(answer, "new.example.test")
    assert said.startswith("3 passkeys (of 2 accounts) were made at old.example.test and cannot be used at "
                           "new.example.test.")
    # The deployment did not say which accounts hold another factor: the sentence claims no number.
    assert ("An account among them that has no other second factor to use there sets one up again at its next "
            "sign-in") in said and "goes back to that address" in said
    one = tool.passkeys_elsewhere_note({"made_at": [{"address": "old.example.test", "passkeys": 1, "accounts": 1}]}, "")
    assert one.startswith("1 passkey (of 1 account) was made at old.example.test and cannot be used at the address "
                          "the vault has now (no passkey can be made there).")
    # Nothing known, nothing in use, or an answer that is not one: nothing is said.
    for nothing in (None, {}, {"made_at": []}, {"made_at": [{"address": "x", "passkeys": 0}]}, {"made_at": "?"}):
        assert tool.passkeys_elsewhere_note(nothing, "new.example.test") is None
    assert tool.passkey_host("vault.example.test") == "vault.example.test"
    assert tool.passkey_host("https://Vault.Example.test:8443,other") == "vault.example.test"
    assert tool.passkey_host("203.0.113.9") == "" and tool.passkey_host("") == ""


def test_a_key_with_no_address_on_record_is_given_the_vaults_at_start_and_none_while_the_vault_has_none():
    """A table an earlier build of this release made holds keys with no address. Taken as made here only until
    they next answered, such a key went on counting after the vault moved, where no browser offers it. The start
    writes the address the vault has on each of them, once; with no address a passkey can be made at, nothing."""
    set_bare_api_env()
    from _kept_db import kept_database
    from app.core import webauthn_settings as wss
    from app.core.models import RoleEnum, User, WebAuthnCredential
    made = wss.address_now
    try:
        with kept_database() as (make, _engine):
            with make() as db:
                ann = User(username="ann", email=None, password_hash="x", role=RoleEnum.USER, is_active=True)
                db.add(ann)
                db.flush()
                for index, address in enumerate((None, None, ELSEWHERE)):
                    db.add(WebAuthnCredential(user_id=ann.id, credential_id=bytes([index + 1]) * 8,
                                              public_key_cose=b"k", cose_alg=-7, rp_id=address))
                db.commit()

                def addresses():
                    db.expire_all()
                    return sorted(str(row.rp_id) for row in db.query(WebAuthnCredential).all())
                wss.address_now = lambda: ""
                assert wss.fill_the_addresses_not_recorded(db) == 0
                db.commit()
                assert addresses() == ["None", "None", ELSEWHERE]
                wss.address_now = lambda: "vault.example.test"
                assert wss.fill_the_addresses_not_recorded(db) == 2
                db.commit()
                assert addresses() == [ELSEWHERE, "vault.example.test", "vault.example.test"]
                # Moved since: the keys stay where they were made, and the start writes nothing more.
                wss.address_now = lambda: "new.example.test"
                assert wss.fill_the_addresses_not_recorded(db) == 0
                assert addresses() == [ELSEWHERE, "vault.example.test", "vault.example.test"]
                assert wss.usable_passkeys(db, ann.id, whatever_the_switch=True) == 0
    finally:
        wss.address_now = made


def test_the_start_fills_the_addresses_in_a_step_of_its_own_after_the_column_is_there():
    import inspect
    from app.api import api_server
    source = inspect.getsource(api_server)
    column = source.index('"ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS rp_id VARCHAR(253)"')
    filled = source.index("_passkey_settings.fill_the_addresses_not_recorded(db)")
    assert column < source.index("for stmt in statements:") < filled


def test_the_lookup_says_how_many_of_an_accounts_passkeys_it_can_sign_in_with(monkeypatch):
    """The host operator who looks an account up after a move saw "passkeys: 2" for an account with no key it can
    use. The deployment says how many are a factor now, and the tool says it beside the number."""
    set_bare_api_env()
    from _kept_db import kept_database
    from app.core import host_operator, webauthn_settings as wss
    from app.core.models import RoleEnum, User, WebAuthnCredential
    tool = _the_host_tool()
    monkeypatch.setattr(wss, "address_now", lambda: HERE)
    monkeypatch.setattr(wss, "require_uv", lambda: True)
    monkeypatch.setattr(wss, "allowed_alg_codes", lambda: (-7,))
    on = [True]
    monkeypatch.setattr(wss, "enabled", lambda: on[0])
    with kept_database() as (make, _engine):
        with make() as db:
            who = {n: User(username=n, email=None, password_hash="x", role=RoleEnum.USER, is_active=True)
                   for n in ("moved", "stranded", "fine", "none")}
            db.add_all(who.values())
            db.flush()
            for index, (owner, address, extra) in enumerate((
                    ("moved", HERE, {}), ("moved", ELSEWHERE, {}), ("moved", HERE, {"uv_initialized": False}),
                    ("stranded", ELSEWHERE, {}), ("stranded", ELSEWHERE, {"retired_at": datetime(2026, 11, 1)}),
                    ("fine", HERE, {}), ("fine", None, {}))):
                db.add(WebAuthnCredential(**{**dict(
                    user_id=who[owner].id, credential_id=bytes([index + 1]) * 8, public_key_cose=b"k", cose_alg=-7,
                    rp_id=address, uv_initialized=True), **extra}))
            db.commit()
            said = {n: host_operator._describe(db, u) for n, u in who.items()}
            on[0] = False
            off = host_operator._describe(db, who["fine"])
    counts = {n: (a["passkeys"], a["passkeys_usable"]) for n, a in said.items()}
    assert counts == {"moved": (3, 1), "stranded": (1, 0), "fine": (2, 2), "none": (0, 0)}
    assert (off["passkeys"], off["passkeys_usable"]) == (2, 0)          # turned off: held, and none is a factor
    notes = {n: tool.passkeys_usable_note(a) for n, a in said.items()}
    assert notes == {"moved": " (it can sign in with 1 of them now)", "stranded": " (it cannot sign in with it now)",
                     "fine": "", "none": ""}
    assert tool.passkeys_usable_note(off) == " (it can sign in with none of them now)"
