"""The passkey settings, held to their rules at every route (app/core/webauthn_settings.py, app/services/sign_in.py,
app/api/api_server.py, app/api/managed_settings_router.py): a requirement past its grace is met by a passkey and
nothing else; the mode off stops passkeys at the sign-in, the second step, the step-ups and the registration while
the rows stay; the passwordless roles; the device-bound rule in a compliance step-up; the algorithm grace at the
route; the enrolling principal; the bounds refused before the step-up; the managed-settings route knowing nothing
of the Sign-in page; direct attestation without anchors refusing registrations. Offline."""
import types
import uuid
from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException

from _webauthn_softauth import FLAG, SoftAuthenticator
from test_passkey_routes import Harness as RouteHarness, _call as _rcall, _clean_overrides  # noqa: F401
from test_passkey_second_factor import Harness as StepHarness, _call_h
from test_passkey_settings import _mod, _resolving
from test_passkey_sign_in import ORIGIN, Harness as SignInHarness, _call, _claims, _user

pytestmark = pytest.mark.unit

SYNCED = FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS


def _required(monkeypatch, registry, wss, roles):
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: list(roles), wss.GRACE_DAYS: 14})


def test_a_requirement_past_its_grace_is_met_by_a_passkey_and_nothing_else(monkeypatch):
    registry, wss = _mod()
    overdue = datetime.utcnow() - timedelta(days=20)
    alice = _user(passkey_required_since=overdue, passkey_requirement_cleared_at=None)
    root = _user("root", role="admin", passkey_required_since=overdue, passkey_requirement_cleared_at=None)
    h = SignInHarness(monkeypatch, [alice, root])
    _required(monkeypatch, registry, wss, ["user", "admin"])
    from app.services import sign_in

    def finish(user, methods, **kw):
        return sign_in.finish(h.db, sign_in.SignInResult(user, methods, "203.0.113.9", **kw))

    # Every way the table is done without a passkey, with the password among the proofs: the password with a code,
    # and the password after a provider (its MFA trusted or not). Each stops at the passkey enrollment.
    for methods, kw in (
            (["pwd", "totp"], {}), (["pwd", "recovery"], {}),
            (["pwd"], {"provider_id": "p", "provider_mfa_trusted": True}), (["pwd"], {"provider_id": "p"})):
        outcome = finish(alice, methods, **kw)
        assert isinstance(outcome, sign_in.PendingStep), (methods, kw)
        assert outcome.body["enrollment_required"] is True and outcome.body["enrollment_methods"] == ["passkey"], (methods, kw)
        assert outcome.body["stage"] == "second_factor" and outcome.body["access_token"] is None
    # A provider alone, for an account that has a password it can type: the password first. A passkey outlives the
    # provider (it signs in after the provider was turned off or the identity unlinked), so it is set up on no less
    # than Your account asks of an account with no factor: its password.
    for kw in ({"provider_id": "p", "provider_mfa_trusted": True}, {"provider_id": "p"}):
        outcome = finish(alice, [], **kw)
        assert isinstance(outcome, sign_in.PendingStep) and outcome.body["stage"] == "password", kw
        assert outcome.body["enrollment_required"] is False and outcome.body["access_token"] is None, kw
    # An account that signs in only through its provider has no password to type, and its passkey signs nobody in
    # without the provider: the provider is proof enough.
    alice.sso_only = True
    for kw in ({"provider_id": "p", "provider_mfa_trusted": True}, {"provider_id": "p"}):
        outcome = finish(alice, [], **kw)
        assert isinstance(outcome, sign_in.PendingStep) and outcome.body["stage"] == "second_factor", kw
        assert outcome.body["enrollment_required"] is True and outcome.body["enrollment_methods"] == ["passkey"], kw
    alice.sso_only = False
    # The rule itself: only after a provider, only without the password among the proofs, only for an account that
    # has a password it can type.
    owed = sign_in.password_owed_before_an_enrollment
    assert owed(alice, [], "p") is True and owed(alice, ["totp"], "p") is True
    assert owed(alice, ["pwd"], "p") is False and owed(alice, [], None) is False and owed(alice, ["hwk"], None) is False
    alice.password_hash, kept = None, alice.password_hash            # and so has an account with no password at all
    outcome = finish(alice, [], provider_id="p")
    assert outcome.body["enrollment_required"] is True and outcome.body["stage"] == "second_factor"
    alice.password_hash = kept
    assert all(a[0] != "success" for a in h.audits)
    # A passkey among the proofs meets it, whatever else was proved.
    assert isinstance(finish(alice, ["pwd", "hwk"]), sign_in.SignedIn)
    assert isinstance(finish(alice, ["swk"], user_verified=True, passwordless_allowed=True), sign_in.SignedIn)
    assert isinstance(finish(alice, ["hwk"], provider_id="p"), sign_in.SignedIn)
    # An administrator through a provider types the password first; then the passkey is asked for.
    outcome = finish(root, [], provider_id="p", provider_mfa_trusted=True)
    assert isinstance(outcome, sign_in.PendingStep) and outcome.body["stage"] == "password"
    outcome = finish(root, ["pwd"], provider_id="p", provider_mfa_trusted=True)
    assert isinstance(outcome, sign_in.PendingStep) and outcome.body["enrollment_methods"] == ["passkey"]
    # Within the grace nothing is held.
    alice.passkey_required_since = datetime.utcnow() - timedelta(days=2)
    assert isinstance(finish(alice, ["pwd", "totp"]), sign_in.SignedIn)


def _authenticator(h, user):
    from app.core.models import SecondFactorEnrollment
    h.db.rows_of(SecondFactorEnrollment).append(
        types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, method="totp", status="active"))


def test_an_overdue_requirement_asks_the_accounts_own_factor_before_the_enrollment(monkeypatch):
    """An account that holds an authenticator and owes a passkey past its grace gives the authenticator's code first:
    its first proof alone (the password, a provider without trusted MFA) never reaches the enrollment, where whoever
    knows only the password would add a passkey of their own. The harness has the login switch off, the case in
    which nothing else would ask for the code. An account with no factor still enrolls after its first proof."""
    registry, wss = _mod()
    overdue = datetime.utcnow() - timedelta(days=20)
    alice = _user(passkey_required_since=overdue, passkey_requirement_cleared_at=None)
    bob = _user("bob", passkey_required_since=overdue, passkey_requirement_cleared_at=None)
    root = _user("root", role="admin", passkey_required_since=overdue, passkey_requirement_cleared_at=None)
    h = SignInHarness(monkeypatch, [alice, bob, root])
    _authenticator(h, alice)
    _authenticator(h, root)
    _required(monkeypatch, registry, wss, ["user", "admin"])
    from app.services import sign_in

    def finish(user, methods, **kw):
        return sign_in.finish(h.db, sign_in.SignInResult(user, methods, "203.0.113.9", **kw))

    for methods, kw in ((["pwd"], {}), ([], {"provider_id": "p"})):
        outcome = finish(alice, methods, **kw)
        assert isinstance(outcome, sign_in.PendingStep), (methods, kw)
        assert outcome.body["stage"] == "second_factor" and outcome.body["enrollment_required"] is False, (methods, kw)
        assert outcome.body["methods"] == ["totp", "recovery"] and outcome.body["enrollment_methods"] == [], (methods, kw)
        assert outcome.body["access_token"] is None
    # A provider whose MFA is trusted does not stand in for the account's code here, with or without the password:
    # Your account asks a holder of a factor for that factor before it adds a passkey, and so does the sign-in.
    for methods in ([], ["pwd"]):
        outcome = finish(alice, methods, provider_id="p", provider_mfa_trusted=True)
        assert isinstance(outcome, sign_in.PendingStep), methods
        assert outcome.body["stage"] == "second_factor" and outcome.body["enrollment_required"] is False, methods
        assert outcome.body["methods"] == ["totp", "recovery"] and outcome.body["enrollment_methods"] == [], methods
    # The code given: now the passkey is asked for.
    for methods, kw in ((["pwd", "totp"], {}), (["pwd", "recovery"], {}), (["totp"], {"provider_id": "p"}),
                        (["totp"], {"provider_id": "p", "provider_mfa_trusted": True})):
        outcome = finish(alice, methods, **kw)
        assert isinstance(outcome, sign_in.PendingStep), (methods, kw)
        assert outcome.body["enrollment_required"] is True and outcome.body["enrollment_methods"] == ["passkey"], (methods, kw)
        assert outcome.body["methods"] == []
    # An administrator: the password, then the code, then the passkey.
    outcome = finish(root, [], provider_id="p")
    assert outcome.body["stage"] == "password"
    outcome = finish(root, ["pwd"], provider_id="p")
    assert outcome.body["enrollment_required"] is False and outcome.body["methods"] == ["totp", "recovery"]
    outcome = finish(root, ["pwd", "totp"], provider_id="p")
    assert outcome.body["enrollment_required"] is True and outcome.body["enrollment_methods"] == ["passkey"]
    # No factor of its own: the enrollment follows the first proof, as it did.
    outcome = finish(bob, ["pwd"])
    assert outcome.body["enrollment_required"] is True and outcome.body["enrollment_methods"] == ["passkey"]
    assert all(a[0] != "success" for a in h.audits)
    # Within the grace the login switch decides, as before: nothing is held.
    alice.passkey_required_since = datetime.utcnow() - timedelta(days=2)
    assert isinstance(finish(alice, ["pwd"]), sign_in.SignedIn)


def test_a_requirement_waits_while_no_passkey_can_be_made_at_the_address(monkeypatch):
    """The address changed under a saved requirement (emptied, plain http, an IP put first): nobody is held for a
    passkey there is no way to make. A user and an administrator past the grace sign in as without the requirement,
    the grace is forgotten, and the profile is told that it waits; with an address again the requirement is back
    and the grace starts over."""
    registry, wss = _mod()
    overdue = datetime.utcnow() - timedelta(days=20)
    alice = _user(passkey_required_since=overdue, passkey_requirement_cleared_at=None)
    root = _user("root", role="admin", passkey_required_since=overdue, passkey_requirement_cleared_at=None)
    h = SignInHarness(monkeypatch, [alice, root])
    _required(monkeypatch, registry, wss, ["user", "admin"])
    from app.services import sign_in

    def finish(user, methods, **kw):
        return sign_in.finish(h.db, sign_in.SignInResult(user, methods, "203.0.113.9", **kw))

    assert wss.requirement(h.db, alice).overdue is True and wss.requirement_paused() is False
    monkeypatch.setattr(wss, "passkeys_can_be_made", lambda: False)
    waiting = wss.requirement(h.db, alice)
    assert waiting == wss.Requirement(False, paused=True) and wss.requirement_paused() is True
    assert wss.requirement_public(waiting) == {"required": False, "since": None, "due": None, "overdue": False,
                                               "cleared": False, "paused": True}
    for user in (alice, root):
        outcome = finish(user, ["pwd"])
        assert isinstance(outcome, sign_in.SignedIn), user.username
        assert user.passkey_required_since is None, user.username          # the grace does not run meanwhile
    # An account the host operator cleared stays cleared, not paused; a role not named is not paused either.
    alice.passkey_requirement_cleared_at = datetime.utcnow()
    assert wss.requirement(h.db, alice) == wss.Requirement(False, cleared=True)
    alice.passkey_requirement_cleared_at = None
    assert wss.requirement(h.db, _user("eve", role="external")) == wss.Requirement(False)
    # The address is back: required again, and the grace starts at this sign-in.
    monkeypatch.setattr(wss, "passkeys_can_be_made", lambda: True)
    assert isinstance(finish(alice, ["pwd"]), sign_in.SignedIn)
    back = wss.requirement(h.db, alice)
    assert back.required is True and back.overdue is False and back.paused is False
    assert alice.passkey_required_since is not None and datetime.utcnow() - alice.passkey_required_since < timedelta(minutes=1)


def test_a_roles_last_passkey_is_not_removed_by_its_holder_and_the_grace_starts_over_when_it_leaves(monkeypatch):
    """A role must hold a passkey, and the account set one up long ago. Its holder does not remove the last one:
    adding a passkey at the deadline and removing it at once would otherwise put the requirement off for ever. With
    another passkey added, the first goes. When the last one does leave (an administrator removed it: a lost
    device), the next sign-in is not stopped at once on a grace that ran out before the key existed: registering a
    passkey ended the grace, so the time to set one up starts again at the sign-in after the last one left."""
    registry, wss = _mod()
    long_ago = datetime.utcnow() - timedelta(days=200)
    alice = _user(passkey_required_since=long_ago, passkey_requirement_cleared_at=None)
    h = RouteHarness(monkeypatch, alice)
    _required(monkeypatch, registry, wss, ["user"])
    assert wss.requirement(h.db, alice).overdue is True
    status, shown, _auth = h.register()
    assert status == 201, shown
    assert alice.passkey_required_since is None and wss.requirement(h.db, alice) == wss.Requirement(False)
    status, body = _rcall(h.S, "DELETE", f"/users/me/passkeys/{shown['id']}", None, {"X-Second-Factor": "ok"})
    assert status == 409 and "Your role must hold a passkey, and this is your last one" in body["detail"], body
    assert len(h.rows()) == 1 and alice.passkey_required_since is None
    # The rule waits with the requirement: where no passkey can be made at the address, or the operator cleared
    # the requirement for this account, or the role is not named, the last one may go.
    assert wss.must_hold(alice) is True
    monkeypatch.setattr(wss, "passkeys_can_be_made", lambda: False)
    assert wss.must_hold(alice) is False
    monkeypatch.setattr(wss, "passkeys_can_be_made", lambda: True)
    alice.passkey_requirement_cleared_at = datetime.utcnow()
    assert wss.must_hold(alice) is False
    alice.passkey_requirement_cleared_at = None
    assert wss.must_hold(_user("eve", role="external")) is False
    # With another passkey on the account, the first one is the holder's to remove.
    status, second, _auth = h.register(label="phone", receipt="ok")
    assert status == 201, second
    status, body = _rcall(h.S, "DELETE", f"/users/me/passkeys/{shown['id']}", None, {"X-Second-Factor": "ok"})
    assert status == 200 and body == {"removed": True}, body
    status, body = _rcall(h.S, "DELETE", f"/users/me/passkeys/{second['id']}", None, {"X-Second-Factor": "ok"})
    assert status == 409, body
    h.rows().clear()                                    # an administrator removed it (a lost device)
    after = wss.requirement(h.db, alice)
    assert after.required is True and after.overdue is False and after.since is None
    assert wss.mark_required(alice) is True and wss.requirement(h.db, alice).overdue is False


def test_an_administrator_does_not_reset_away_the_last_passkey_their_own_role_must_hold(monkeypatch):
    """A reset of the second factor retires every passkey, and the time to set one up starts again when the account
    has none. An administrator whose role must hold a passkey could so reset their own factor at each deadline and
    never hold one. Their own reset is refused while it would retire the passkey their role must hold, as removing
    it is in Your account; another administrator's reset of the same account goes on, and so does their own
    where nothing is to be kept or the requirement waits."""
    from fastapi import HTTPException
    from app.core.models import User, WebAuthnCredential
    registry, wss = _mod()
    root = _user("root", role="admin", passkey_required_since=None, passkey_requirement_cleared_at=None)
    sam = _user("sam", role="admin", passkey_required_since=None, passkey_requirement_cleared_at=None)
    h = RouteHarness(monkeypatch, root)
    h.db.rows_of(User).append(sam)
    _required(monkeypatch, registry, wss, ["admin"])

    def the_reset_itself(*a, **k):
        raise HTTPException(status_code=418, detail="reached the reset")
    monkeypatch.setattr(h.S, "_credential_change", the_reset_itself)
    own, others = f"/users/{root.id}/second-factor/reset", f"/users/{sam.id}/second-factor/reset"
    receipt = {"X-Second-Factor": "ok"}
    assert _rcall(h.S, "POST", own, None, receipt)[0] == 418                # no passkey yet: nothing to keep
    status, shown, _auth = h.register()
    assert status == 201, shown
    status, body = _rcall(h.S, "POST", own, None, receipt)
    assert status == 409 and "Your role must hold a passkey, and a reset would retire yours" in body["detail"], body
    assert len(h.rows()) == 1 and h.rows()[0].retired_at is None
    # Another administrator's account is theirs to reset, passkey or not.
    h.rows().append(types.SimpleNamespace(id=uuid.uuid4(), user_id=sam.id, retired_at=None))
    assert _rcall(h.S, "POST", others, None, receipt)[0] == 418
    # The rule waits with the requirement.
    monkeypatch.setattr(wss, "passkeys_can_be_made", lambda: False)
    assert _rcall(h.S, "POST", own, None, receipt)[0] == 418
    monkeypatch.setattr(wss, "passkeys_can_be_made", lambda: True)
    root.passkey_requirement_cleared_at = datetime.utcnow()
    assert _rcall(h.S, "POST", own, None, receipt)[0] == 418
    root.passkey_requirement_cleared_at = None
    assert _rcall(h.S, "POST", own, None, receipt)[0] == 409


def test_whether_a_passkey_can_be_made_is_what_the_address_says(monkeypatch):
    registry, wss = _mod()
    import app.core.public_url as public_url
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": False, "rp_id": "", "origin": "", "reason": "no_public_host"})
    assert wss.passkeys_can_be_made() is False
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": False, "rp_id": "10.0.0.5", "origin": "https://10.0.0.5",
                                                         "reason": "ip_address"})
    assert wss.passkeys_can_be_made() is False
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": True, "rp_id": "vault.example.test",
                                                         "origin": "https://vault.example.test", "reason": "ok"})
    assert wss.passkeys_can_be_made() is True


def test_an_enrollment_token_without_the_accounts_factor_registers_nothing(monkeypatch):
    """The registration routes refuse a held sign-in that would enroll a passkey before the account's own factor
    was given, whatever made the token, a trusted provider's MFA included; with the code among its proofs it
    registers, and the sign-in then finishes with the new key. An account with no factor, held after a provider's
    sign-in, registers nothing before its password was given, unless it has none it can type."""
    registry, wss = _mod()
    overdue = datetime.utcnow() - timedelta(days=20)
    alice = _user(passkey_required_since=overdue, passkey_requirement_cleared_at=None)
    h = StepHarness(monkeypatch, [alice])
    _authenticator(h, alice)
    _required(monkeypatch, registry, wss, ["user"])
    from app.core.models import WebAuthnCredential
    options_path, verify_path = "/users/me/passkeys/register/options", "/users/me/passkeys/register/verify"
    pending, headers = h.pending_for(alice)                     # the password alone
    pending.enrollment_required = True
    status, body = _call_h(h.S, "POST", options_path, {}, headers)
    assert status == 401 and body["detail"] == "Confirm your second factor first; start the sign-in again.", body
    status, body = _call_h(h.S, "POST", verify_path, {"challenge_id": "ab" * 16, "credential": {}}, headers)
    assert status == 401 and body["detail"] == "Confirm your second factor first; start the sign-in again.", body
    pending, headers = h.pending_for(alice, methods=(), provider="p")       # a provider, its MFA not trusted
    pending.enrollment_required = True
    assert _call_h(h.S, "POST", options_path, {}, headers)[0] == 401
    assert h.db.rows_of(WebAuthnCredential) == [] and pending.consumed_at is None
    # A provider whose MFA is trusted does not stand in for the code: the passkey would outlive the provider.
    pending, headers = h.pending_for(alice, methods=(), provider="p", provider_mfa=True)
    pending.enrollment_required = True
    status, body = _call_h(h.S, "POST", options_path, {}, headers)
    assert status == 401 and body["detail"] == "Confirm your second factor first; start the sign-in again.", body
    status, body = _call_h(h.S, "POST", verify_path, {"challenge_id": "ab" * 16, "credential": {}}, headers)
    assert status == 401, body
    assert h.db.rows_of(WebAuthnCredential) == []
    # An account with no factor, after a provider: its password first, where it has one it can type.
    from app.core.models import SecondFactorEnrollment
    factor = h.db.rows_of(SecondFactorEnrollment).pop()
    for provider_mfa in (False, True):
        pending, headers = h.pending_for(alice, methods=(), provider="p", provider_mfa=provider_mfa)
        pending.enrollment_required = True
        status, body = _call_h(h.S, "POST", options_path, {}, headers)
        assert status == 401 and body["detail"] == "Enter your password first; start the sign-in again.", body
        status, body = _call_h(h.S, "POST", verify_path, {"challenge_id": "ab" * 16, "credential": {}}, headers)
        assert status == 401 and body["detail"] == "Enter your password first; start the sign-in again.", body
    assert h.db.rows_of(WebAuthnCredential) == []
    pending, headers = h.pending_for(alice, methods=("pwd",), provider="p")         # the password given
    pending.enrollment_required = True
    assert _call_h(h.S, "POST", options_path, {}, headers)[0] == 200
    alice.sso_only = True                                                           # none it can type
    pending, headers = h.pending_for(alice, methods=(), provider="p")
    pending.enrollment_required = True
    assert _call_h(h.S, "POST", options_path, {}, headers)[0] == 200
    alice.sso_only = False
    pending, headers = h.pending_for(alice)                                         # the password alone, no provider
    pending.enrollment_required = True
    assert _call_h(h.S, "POST", options_path, {}, headers)[0] == 200
    h.db.rows_of(SecondFactorEnrollment).append(factor)
    # The code among the proofs: the registration goes through and finishes the sign-in.
    pending, headers = h.pending_for(alice, methods=("pwd", "totp"))
    pending.enrollment_required = True
    status, body = _call_h(h.S, "POST", options_path, {}, headers)
    assert status == 200, body
    credential = SoftAuthenticator().make_credential(body["options"], ORIGIN)
    status, out = _call_h(h.S, "POST", verify_path,
                          {"challenge_id": body["challenge_id"], "credential": credential, "label": "k"}, headers)
    assert status == 201 and out.get("access_token"), out
    assert set(_claims(out["access_token"])["amr"]) >= {"pwd", "totp"}
    assert len(h.db.rows_of(WebAuthnCredential)) == 1


def test_a_challenge_made_for_one_account_is_no_challenge_for_another(monkeypatch):
    """A second-step challenge is made for one account. Presented by another account, with that other account's own
    key, it is unknown: refused before any key is looked up, and spent. (The keys offered with a challenge are its
    account's own, which refuses the same today; this is the rule itself.)"""
    registry, wss = _mod()
    alice, bob = _user(), _user("bob")
    h = StepHarness(monkeypatch, [alice, bob])
    S = h.S
    alices, _row = h.enroll(alice)
    _bobs, _row = h.enroll(bob)
    _pending, bobs_headers = h.pending_for(bob)
    status, made_for_bob = _call_h(S, "POST", "/auth/second-factor/passkey/options", {}, bobs_headers)
    assert status == 200, made_for_bob
    _pending, alices_headers = h.pending_for(alice)
    status, made_for_alice = _call_h(S, "POST", "/auth/second-factor/passkey/options", {}, alices_headers)
    assert status == 200, made_for_alice
    looked_up = []
    real = S._passkeys_of
    monkeypatch.setattr(S, "_passkeys_of", lambda db, user_id: looked_up.append(user_id) or real(db, user_id))
    # Alice signs with her own key, over her own options, and names the challenge made for Bob.
    credential = alices.get_assertion(made_for_alice["options"], ORIGIN, flags=FLAG.UP | FLAG.UV, sign_count=1)
    status, body = _call_h(S, "POST", "/auth/second-factor/passkey/verify",
                           {"challenge_id": made_for_bob["challenge_id"], "credential": credential}, alices_headers)
    assert status == 400 and body["detail"]["reason"] == "challenge_unknown", body
    assert looked_up == []
    # The control: her own challenge, the same key.
    status, body = _call_h(S, "POST", "/auth/second-factor/passkey/verify",
                           {"challenge_id": made_for_alice["challenge_id"], "credential": credential}, alices_headers)
    assert status == 200 and body.get("access_token"), body


def test_mode_off_stops_passkeys_at_every_step_but_keeps_the_rows(monkeypatch):
    registry, wss = _mod()
    alice = _user()
    h = StepHarness(monkeypatch, [alice])
    S = h.S
    auth, row = h.enroll(alice)
    from app.core.active_factors import active_factors
    assert "passkey" in S._sf_login_methods(h.db, alice) and active_factors(h.db, alice.id).passkeys == 1
    pending, headers = h.pending_for(alice)
    status, second = _call_h(S, "POST", "/auth/second-factor/passkey/options", {}, headers)
    assert status == 200, second
    status, first = _call(S, "POST", "/auth/passkeys/sign-in/options", {"username": "alice"})
    assert status == 200, first
    status, step = _call(S, "POST", "/auth/passkeys/step-up/options")
    assert status == 200, step
    _resolving(monkeypatch, registry, {wss.MODE: "off"})
    # No longer a factor, no longer offered.
    assert "passkey" not in S._sf_login_methods(h.db, alice) and active_factors(h.db, alice.id).passkeys == 0
    assert _call_h(S, "POST", "/auth/second-factor/passkey/options", {}, headers)[0] == 409
    assert _call(S, "POST", "/auth/passkeys/step-up/options")[0] == 409
    assert _call(S, "POST", "/auth/passkeys/sign-in/options", {"username": "alice"})[0] == 409
    # Challenges issued while on are not honoured once off, at any of the three steps.
    credential = auth.get_assertion(second["options"], ORIGIN, flags=FLAG.UP | FLAG.UV, sign_count=1)
    status, body = _call_h(S, "POST", "/auth/second-factor/passkey/verify",
                           {"challenge_id": second["challenge_id"], "credential": credential}, headers)
    assert status == 409, body
    credential = auth.get_assertion(first["options"], ORIGIN, flags=FLAG.UP | FLAG.UV, sign_count=2)
    status, body = _call(S, "POST", "/auth/passkeys/sign-in/verify", {"challenge_id": first["challenge_id"], "credential": credential})
    assert status == 409, body
    credential = auth.get_assertion(step["options"], ORIGIN, flags=FLAG.UP | FLAG.UV, sign_count=3)
    status, body = _call(S, "POST", "/auth/second-factor/step-up",
                         {"action": "admin.retention.write", "method": "passkey", "challenge_id": step["challenge_id"],
                          "credential": credential, "password": "pw"})
    # With no factor counted, the step-up's policy is met by the password alone or refused: never by the key.
    assert status in (200, 400, 403, 409) and "access_token" not in body, body
    assert all(not method.startswith("passkey:") for (_u, _a, _s, method) in h.receipts.values()), h.receipts
    # The rows stay, untouched (the key signed nothing); nothing was signed in.
    assert h.db.rows_of(type(row)) == [row] and row.retired_at is None and row.sign_count == 0
    assert pending.consumed_at is None and all(a[0] != "success" for a in h.audits)


def test_mode_off_refuses_a_registration_already_under_way(monkeypatch):
    registry, wss = _mod()
    alice = _user()
    h = RouteHarness(monkeypatch, alice)
    status, body = _rcall(h.S, "POST", "/users/me/passkeys/register/options", {"current_password": "pw"})
    assert status == 200, body
    _resolving(monkeypatch, registry, {wss.MODE: "off"})
    credential = SoftAuthenticator().make_credential(body["options"], ORIGIN)
    status, out = _rcall(h.S, "POST", "/users/me/passkeys/register/verify",
                         {"challenge_id": body["challenge_id"], "credential": credential, "label": "k"})
    assert status == 409 and h.rows() == [], out


def test_a_passkey_signs_in_alone_only_for_the_roles_the_setting_names(monkeypatch):
    registry, wss = _mod()
    alice, ext = _user(), _user("ext", role="external")
    h = SignInHarness(monkeypatch, [alice, ext])
    _resolving(monkeypatch, registry, {wss.SIGN_IN_ROLES: ["user"]})
    auth_e, _ = h.enroll(ext)
    status, body = h.sign_in(auth_e, username="ext")
    assert status == 200 and body["stage"] == "password" and body["access_token"] is None, body
    auth_a, _ = h.enroll(alice)
    status, body = h.sign_in(auth_a, username="alice")
    assert status == 200 and "access_token" in body and _claims(body["access_token"])["amr"] == ["hwk"], body
    _resolving(monkeypatch, registry, {wss.SIGN_IN_ROLES: ["user", "external"]})
    status, body = h.sign_in(auth_e, username="ext", sign_count=2)
    assert status == 200 and "access_token" in body, body
    # The reader drops a role that may never be passwordless, whatever the store says.
    _resolving(monkeypatch, registry, {wss.SIGN_IN_ROLES: ["user", "admin", "nobody"]})
    assert wss.sign_in_roles() == ("user",)


def test_a_compliance_step_up_refuses_a_synced_key_for_a_device_bound_role(monkeypatch):
    registry, wss = _mod()
    alice = _user()
    h = StepHarness(monkeypatch, [alice])
    auth, row = h.enroll(alice, backup_eligible=True)
    from app.core import auditor_rights
    monkeypatch.setattr(auditor_rights, "open_grant",
                        lambda db, user_id, **kw: types.SimpleNamespace(approved_credential_ids=[str(row.id)]))
    _resolving(monkeypatch, registry, {wss.DEVICE_BOUND_ROLES: ["user"]})
    status, body = h.step_up_with_passkey(auth, "compliance.case.request", flags=SYNCED, sign_count=1)
    assert status == 403 and "bound to one device" in body["detail"], body
    # The other fixed policies take the synced key; so does compliance for a role the setting does not name.
    status, body = h.step_up_with_passkey(auth, "admin.retention.write", flags=SYNCED, sign_count=2)
    assert status == 200, body
    _resolving(monkeypatch, registry, {wss.DEVICE_BOUND_ROLES: ["external"]})
    status, body = h.step_up_with_passkey(auth, "compliance.case.request", flags=SYNCED, sign_count=3)
    assert status == 200, body


def test_a_removed_algorithm_is_judged_at_the_route(monkeypatch):
    registry, wss = _mod()
    alice = _user()
    h = SignInHarness(monkeypatch, [alice])
    S = h.S
    auth, row = h.enroll(alice)
    monkeypatch.setattr(wss, "algorithm_usable", lambda db, alg, now=None: (False, False))
    status, body = h.sign_in(auth, username="alice", sign_count=1)
    assert status in (400, 401, 403) and "access_token" not in body, body
    assert all(a[0] != "success" for a in h.audits)
    notes = []
    monkeypatch.setattr(S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None: (
        notes.append((list(ids), dedup_prefix)) or list(ids)))
    monkeypatch.setattr(wss, "algorithm_usable", lambda db, alg, now=None: (True, True))
    status, body = h.sign_in(auth, username="alice", sign_count=2)
    assert status == 200 and "access_token" in body, body
    assert notes == [([str(alice.id)], f"passkey_alg_grace:{row.id}")]


def test_the_enrolling_principal_takes_only_a_pending_login_that_requires_an_enrollment(monkeypatch):
    alice = _user()
    h = StepHarness(monkeypatch, [alice])
    pending, headers = h.pending_for(alice)                    # a second-factor step, not an enrollment
    status, body = _call_h(h.S, "POST", "/users/me/passkeys/register/options", {}, headers)
    assert status == 401, body
    pending.enrollment_required = True
    assert _call_h(h.S, "POST", "/users/me/passkeys/register/options", {}, headers)[0] == 200
    pending.consumed_at = datetime.utcnow()
    assert _call_h(h.S, "POST", "/users/me/passkeys/register/options", {}, headers)[0] == 401


def test_bounds_refuse_before_the_step_up_and_the_managed_route_knows_nothing_of_the_sign_in_page(monkeypatch):
    registry, wss = _mod()
    from app.api import managed_settings_router as managed
    from app.api import sign_in_settings_router as router
    from app.core.database import get_db
    from app.core.models import User, WebAuthnCredential
    from app.api.user_management_api import require_interactive_admin as uma
    from _memory_db import MemoryDB
    import app.api.api_server as S
    import app.core.public_url as public_url
    import time
    from app.core import rate_limiter as R
    from app.core.rate_limiter import rate_limiter
    root = _user("root", role="admin", passkey_required_since=None, passkey_requirement_cleared_at=None)
    db = MemoryDB({User: [root], WebAuthnCredential: []})
    monkeypatch.setitem(S.app.dependency_overrides, get_db, lambda: db)
    monkeypatch.setitem(S.app.dependency_overrides, uma, lambda: root)
    monkeypatch.setattr(rate_limiter, "check_rate_limit", lambda *a, **kw: (True, 1, 0))
    R._cb_record_failure(time.time())
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": True, "rp_id": "vault.example.test"})
    monkeypatch.setattr(router, "limit_statements", lambda db, timeout_ms=0: None)
    monkeypatch.setattr(managed, "limit_statements", lambda db, timeout_ms=0: None)
    stepped = []
    monkeypatch.setattr(router, "_step_up", lambda db, user, request: stepped.append(("sign_in", user.username)))
    monkeypatch.setattr(managed, "_step_up", lambda db, user, request: stepped.append(("managed", user.username)))
    # Out of bounds, the wrong type, not a choice: refused before any step-up is asked for.
    assert _call(S, "PUT", "/settings/sign-in/webauthn_enrollment_grace_days", {"value": 0})[0] == 400
    assert _call(S, "PUT", "/settings/sign-in/webauthn_enrollment_grace_days", {"value": 91})[0] == 400
    assert _call(S, "PUT", "/settings/sign-in/webauthn_require_uv", {"value": "yes"})[0] == 400
    assert _call(S, "PUT", "/settings/sign-in/webauthn_mode", {"value": "on"})[0] == 400
    assert stepped == []
    # The managed-settings route neither lists nor writes a Sign-in page setting; the other pages stay its own.
    rows = managed.listed_specs()
    assert rows and not [r for r in rows if r["key"] in wss.KEYS] and not [r for r in rows if r["page"] == "signin"]
    with pytest.raises(HTTPException) as refused:
        managed.spec_or_404("webauthn_mode")
    assert refused.value.status_code == 404
    assert managed.spec_or_404("audit_max_days").key == "audit_max_days"
    for key in wss.KEYS:
        assert _call(S, "PUT", f"/settings/managed/{key}", {"value": None})[0] == 404, key
    assert stepped == []


def test_direct_attestation_without_readable_anchors_refuses_registrations(monkeypatch):
    registry, wss = _mod()
    alice = _user()
    h = RouteHarness(monkeypatch, alice)
    _resolving(monkeypatch, registry, {wss.ATTESTATION: "direct"})
    monkeypatch.setattr(wss, "trust_anchors", lambda: ())
    status, body, _auth = h.register(label="k")
    assert status == 400 and body["detail"]["reason"] == "attestation_unverifiable" and h.rows() == [], body


def test_under_direct_attestation_only_an_attested_key_of_a_listed_make_proves_a_compliance_step_up(monkeypatch):
    """Direct attestation and the list of makes bind what is added from then on. A key added before (its make and
    its device-bound flag were the authenticator's own word) and a key of a make taken off the list keep signing in
    and keep proving the other step-ups; neither proves a compliance step-up."""
    registry, wss = _mod()
    alice = _user()
    h = StepHarness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    row.attested = False
    row.aaguid = uuid.uuid4()
    from app.core import auditor_rights
    monkeypatch.setattr(auditor_rights, "open_grant",
                        lambda db, user_id, **kw: types.SimpleNamespace(approved_credential_ids=[str(row.id)]))
    monkeypatch.setattr(wss, "trust_anchors", lambda: (b"anchor",))
    count = [0]

    def step_up(action):
        count[0] += 1
        return h.step_up_with_passkey(auth, action, sign_count=count[0])

    assert step_up("compliance.case.request")[0] == 200                    # the vault asks for no attestation
    _resolving(monkeypatch, registry, {wss.ATTESTATION: "direct"})
    status, body = step_up("compliance.case.request")
    assert status == 403 and "added before the vault checked authenticator makes" in body["detail"], body
    assert step_up("admin.retention.write")[0] == 200                      # every other step-up takes it still
    row.attested = True
    assert step_up("compliance.case.request")[0] == 200
    _resolving(monkeypatch, registry, {wss.ATTESTATION: "direct", wss.ALLOWED_AAGUIDS: [str(uuid.uuid4())]})
    status, body = step_up("compliance.case.request")
    assert status == 403 and "not on the vault's list" in body["detail"], body
    assert step_up("admin.retention.write")[0] == 200
    _resolving(monkeypatch, registry, {wss.ATTESTATION: "direct", wss.ALLOWED_AAGUIDS: [str(row.aaguid).upper()]})
    assert step_up("compliance.case.request")[0] == 200                    # its make is on the list, however written
    reasons = [a for a in h.audits if a == ("action", "second_factor_failed")]
    assert len(reasons) == 2


def test_the_sign_in_page_is_told_how_many_passkeys_were_added_without_attestation(monkeypatch):
    registry, wss = _mod()
    from _memory_db import MemoryDB
    from app.core.models import WebAuthnCredential
    from app.core import table_presence
    monkeypatch.setattr(table_presence, "has_table", lambda db, name: True)

    def key(**kw):
        fields = dict(id=uuid.uuid4(), user_id=uuid.uuid4(), retired_at=None, attested=False)
        fields.update(kw)
        return types.SimpleNamespace(**fields)
    db = MemoryDB({WebAuthnCredential: [key(), key(), key(attested=True), key(retired_at=datetime.utcnow())]})
    assert wss.unattested_count(db) is None                                # no attestation asked: the number says nothing
    _resolving(monkeypatch, registry, {wss.ATTESTATION: "direct"})
    assert wss.unattested_count(db) == 2                                   # not the attested one, not the retired one
