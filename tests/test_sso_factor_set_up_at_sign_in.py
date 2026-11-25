"""A second factor set up at a sign-in that came through a provider, from the provider's answer to a session
(app/services/sign_in.py, app/services/sso_sign_in.py, the enrollment routes in app/api/api_server.py).

An account that can type no password (it signs in only through its provider, or its password is one nobody knows)
has nothing but the provider's sign-in to prove itself with. Held for a second factor it must set up, it sets up
an authenticator, or a passkey where one can be made, on that sign-in; an account that has a password types it
first. The cases: a factor required by the policy, an administrator's reset, an identity linked by email that is
between two factors. And the key such an account sets up serves after its provider, never around it. Offline:
the routes through the ASGI app, an in-memory database, a real provider row and identity."""
import time
import types
import uuid
from datetime import datetime

import pytest

from _webauthn_softauth import FLAG
from test_passkey_second_factor import Harness as StepHarness, _call_h
from test_passkey_settings import _mod, _resolving
from test_passkey_sign_in import ORIGIN, _api, _claims, _user

pytestmark = pytest.mark.unit

IP = "203.0.113.9"
ENROLL, CONFIRM, ACKNOWLEDGE = ("/users/me/second-factor/totp/enroll", "/users/me/second-factor/totp/confirm",
                                "/users/me/second-factor/recovery/acknowledge")
NO_PASSWORD = ["signs in only through its provider", "its password is one nobody knows", "it has no password at all"]


def _without_a_password(kind, name="dana"):
    from app.core import password_origin
    if kind == "signs in only through its provider":
        return _user(name, sso_only=True, password_nobody_knows=None)
    if kind == "it has no password at all":
        return _user(name, sso_only=False, password_hash=None, password_nobody_knows=None)
    user = _user(name, sso_only=False, password_hash="argon2:of-random-bytes", password_nobody_knows=None)
    password_origin.mark_nobody_knows(user)
    return user


class World:
    """The sign-in harness as the server has it: the second-factor rules read from the settings and the account,
    one provider that is on, and every account linked to it."""

    def __init__(self, monkeypatch, users, *, mfa_mode="required", passkeys="optional", trust=False, linked_by="self"):
        from app.core.models import ExternalIdentity, SsoProvider, SystemSetting
        self.registry, self.wss = _mod()
        S = _api()
        in_effect, effective = S._login_second_factor_in_effect, S._second_factor_effective
        self.h = h = StepHarness(monkeypatch, users)
        self.S, self.db, self.monkeypatch = S, h.db, monkeypatch
        monkeypatch.setattr(S, "_login_second_factor_in_effect", in_effect)
        monkeypatch.setattr(S, "_second_factor_effective", effective)
        _resolving(monkeypatch, self.registry, {self.wss.MODE: passkeys})
        h.db.rows_of(SystemSetting).append(types.SimpleNamespace(key="global", value={"mfa_mode": mfa_mode}))
        self.provider = types.SimpleNamespace(
            id=uuid.uuid4(), state="enabled", kind="oidc", name="Contoso", label="Sign in with Contoso",
            show_on_sign_in=True, sort_order=0,
            policy={"sso_trust_idp_mfa": trust, "sso_accepted_amr": ["mfa"]})
        h.db.tables[SsoProvider] = [self.provider]
        # The store a provider's logouts are remembered in (asked where a provider's sign-in is finished).
        from app.core import sso_state
        from test_sso_state import FakeRedis
        self.redis = FakeRedis()
        # The store has been up since long before these sign-ins began: its memory of the providers' logouts
        # covers them (a store emptied while a sign-in is under way is its own case, in test_sso_sessions.py).
        self.redis.set(sso_state.LOGGED_OUT_REACH_KEY, "0.0")
        monkeypatch.setattr(sso_state, "_redis", lambda redis: self.redis)
        h.db.tables[ExternalIdentity] = [
            types.SimpleNamespace(id=uuid.uuid4(), user_id=u.id, provider_id=self.provider.id,
                                  subject=f"subject-{u.username}", linked_by=linked_by) for u in users]

    def identity(self, user):
        from app.core.models import ExternalIdentity
        return next(i for i in self.db.rows_of(ExternalIdentity) if i.user_id == user.id)

    def through_the_provider(self, user, *, with_its_mfa=False):
        """What the provider's answer becomes: a session, or a held step."""
        from app.services import sign_in, sso_sign_in
        identity = self.identity(user)
        answer = sso_sign_in.ProviderAnswer(
            claims={}, subject=identity.subject, issuer="https://idp.example", tenant_id=None, email=None,
            email_verified=False, display_name=None, auth_time=None, amr=["mfa"] if with_its_mfa else [])
        result = sso_sign_in.pipeline_result(self.db, self.provider, user, answer, provider_id=str(self.provider.id),
                                             client_ip=IP, identity=identity, began_at=time.time())
        return sign_in.finish(self.db, result)

    def held(self, user, **kw):
        from app.services import sign_in
        outcome = self.through_the_provider(user, **kw)
        assert isinstance(outcome, sign_in.PendingStep), outcome
        return outcome.body, {"Authorization": f"Bearer {outcome.body['pre_auth_token']}"}

    def held_with(self, user, methods):
        """A sign-in held for an enrollment that came through the provider as the account's identity, with
        ``methods`` proved so far, however such a token came to be."""
        from app.core.security import create_access_token
        pending, _headers = self.h.pending_for(user, methods=methods)
        pending.enrollment_required = True
        claims = {"sub": str(user.id), "username": user.username, "pre_auth": str(pending.id),
                  "stage": "second_factor", "methods_so_far": list(methods), "idp": str(self.provider.id),
                  "idp_sub": self.identity(user).subject, "ended": 0}
        return pending, {"Authorization": f"Bearer {create_access_token(claims)}"}

    def held_with_no_provider(self, user, methods):
        """A sign-in held for an enrollment that came through no provider (the password form)."""
        pending, headers = self.h.pending_for(user, methods=methods)
        pending.enrollment_required = True
        return pending, headers

    def set_an_authenticator_up(self, headers, password=""):
        """The wizard's three requests; the last one's answer."""
        from app.core import second_factor as sf
        status, started = _call_h(self.S, "POST", ENROLL, {"current_password": password}, headers)
        assert status == 200, started
        code = sf._totp_at_step(started["secret"], sf.current_totp_step())
        status, codes = _call_h(self.S, "POST", CONFIRM, {"code": code}, headers)
        assert status == 200 and len(codes["recovery_codes"]) == 10, codes
        return _call_h(self.S, "POST", ACKNOWLEDGE, None, headers)


@pytest.mark.parametrize("kind", NO_PASSWORD)
def test_an_account_with_no_password_it_can_type_sets_an_authenticator_up_on_its_providers_sign_in(monkeypatch, kind):
    """A second factor is required of everyone, and the provider's own is not taken for it (the default). Dana's
    account has no password anybody can type. Her sign-in through the provider is held at the set-up of a factor.
    The authenticator's enrollment asked for "your current password", every time: she could never answer, and
    every sign-in of hers ended there. The held sign-in is her proof now: the enrollment starts with no password,
    and ends in a session whose proofs are the code after the provider. Her next sign-in asks for that code."""
    from app.core.models import SecondFactorEnrollment
    from app.services import sign_in
    dana = _without_a_password(kind)
    w = World(monkeypatch, [dana])
    assert sign_in.has_a_password_it_can_type(dana) is False
    body, headers = w.held(dana)
    assert body["stage"] == "second_factor" and body["enrollment_required"] is True and body["access_token"] is None
    assert "totp" in body["enrollment_methods"] and body["methods"] == []
    status, done = w.set_an_authenticator_up(headers)
    assert status == 200 and done["enrolled"] is True and done["token_type"] == "bearer", done
    claims = _claims(done["access_token"])
    assert claims["amr"] == ["totp"] and claims["idp"] == str(w.provider.id) and claims["sub"] == str(dana.id)
    assert [e.status for e in w.db.rows_of(SecondFactorEnrollment)] == ["active"]
    # The next sign-in through the provider: the code she set up, nothing to enroll.
    body, _headers = w.held(dana)
    assert body["enrollment_required"] is False and body["methods"] == ["totp", "recovery"], body


def test_the_held_sign_in_is_that_proof_only_for_an_account_without_a_password_and_only_through_a_provider(monkeypatch):
    """Whose enrollment the held sign-in proves, and whose it does not: an account that has a password proves it
    as before, whatever the token says of a provider; a held sign-in that came through no provider proves
    nothing; and under Your account (a session, no held sign-in) such an account is told where its authenticator
    is set up instead of being asked for a password."""
    from app.core.models import PendingLogin
    from app.services import sign_in
    alice, dana = _user(), _without_a_password("its password is one nobody knows")
    w = World(monkeypatch, [alice, dana])
    proves = sign_in.provider_proves_an_enrollment
    through = types.SimpleNamespace(_provider_id=str(w.provider.id))
    assert proves(dana, through) is True and proves(alice, through) is False
    assert proves(dana, types.SimpleNamespace(_provider_id=None)) is False and proves(dana, None) is False
    # An account with a password, on a held sign-in that came through the provider (however such a token came to
    # be): its password, as ever.
    pending, headers = w.h.pending_for(alice, methods=(), provider=str(w.provider.id))
    pending.enrollment_required = True
    for typed in ("", "pw"):                    # the password belongs at its own stage, as at the passkey's enrollment
        status, body = _call_h(w.S, "POST", ENROLL, {"current_password": typed}, headers)
        assert status == 401 and body["detail"] == "Enter your password first; start the sign-in again.", body
    # Held after that stage (the password among the proofs), the enrollment asks for it as ever.
    _pending, headers = w.held_with(alice, ("pwd",))
    status, body = _call_h(w.S, "POST", ENROLL, {"current_password": ""}, headers)
    assert status == 400 and body["detail"] == "Your current password is required and must be correct.", body
    assert _call_h(w.S, "POST", ENROLL, {"current_password": "pw"}, headers)[0] == 200
    # No provider behind the held sign-in: nothing proves it for an account that can type no password.
    pending, headers = w.h.pending_for(dana, methods=())
    pending.enrollment_required = True
    assert _call_h(w.S, "POST", ENROLL, {"current_password": ""}, headers)[0] == 400
    assert all(p.consumed_at is None for p in w.db.rows_of(PendingLogin))
    # An account that holds a factor gives that factor before another is set up on a held sign-in, as at the
    # passkey's enrollment: the provider's sign-in alone starts no authenticator beside a passkey it holds.
    w.h.enroll(dana)
    _pending, headers = w.held_with(dana, ())
    status, body = _call_h(w.S, "POST", ENROLL, {"current_password": ""}, headers)
    assert status == 401 and body["detail"] == "Confirm your second factor first; start the sign-in again.", body
    from app.core.models import WebAuthnCredential
    w.db.rows_of(WebAuthnCredential).clear()                    # without that passkey the same sign-in starts it
    assert _call_h(w.S, "POST", ENROLL, {"current_password": ""}, headers)[0] == 200
    # Under Your account (a session, no held sign-in): told, not asked; and the page knows beforehand.
    session = {"Authorization": "Bearer session"}
    signed_in = {}
    monkeypatch.setitem(w.S.app.dependency_overrides, w.S.get_enrolling_principal, lambda: (signed_in["user"], None))
    for user, typed in ((dana, False), (alice, True)):
        signed_in["user"] = w.h.current_user = user
        status, state = _call_h(w.S, "GET", "/users/me/second-factor", None, session)
        assert status == 200 and state["password_to_type"] is typed, state
        status, body = _call_h(w.S, "POST", ENROLL, {"current_password": ""}, session)
        if typed:
            assert status == 400 and body["detail"] == "Your current password is required and must be correct.", body
        else:
            assert status == 409 and "no password of its own" in body["detail"], body
            assert "sign-in that asks for a second factor" in body["detail"] and "passkey" in body["detail"], body


@pytest.mark.parametrize("what", ["the provider is turned off", "the identity is unlinked", "the account is locked"])
def test_the_enrollment_starts_only_while_the_held_sign_in_could_still_finish(monkeypatch, what):
    """The provider's sign-in is the proof, so the proof is asked again where it is used: a provider turned off
    since, an identity unlinked, an account locked, and no authenticator is started on it."""
    from app.core.models import ExternalIdentity, SecondFactorEnrollment
    dana = _without_a_password("signs in only through its provider")
    w = World(monkeypatch, [dana])
    _body, headers = w.held(dana)
    if what == "the provider is turned off":
        w.provider.state = "disabled"
    elif what == "the identity is unlinked":
        w.db.rows_of(ExternalIdentity).clear()
    else:
        dana.is_locked = True
    status, body = _call_h(w.S, "POST", ENROLL, {"current_password": ""}, headers)
    assert status in (401, 403, 423), (status, body)
    assert w.db.rows_of(SecondFactorEnrollment) == []


@pytest.mark.parametrize("kind", NO_PASSWORD)
def test_such_an_account_is_offered_a_passkey_too_where_one_can_be_made(monkeypatch, kind):
    """No role must hold a passkey; a second factor is to be set up; the provider's sign-in is all the account can
    give. A passkey is offered beside the authenticator where one can be made, and the page is told it is a
    choice, not the role's rule. Set up, it finishes the sign-in as the second proof after the provider."""
    from app.core.models import WebAuthnCredential
    from _webauthn_softauth import SoftAuthenticator
    dana = _without_a_password(kind)
    w = World(monkeypatch, [dana])
    body, headers = w.held(dana)
    assert body["enrollment_methods"] == ["totp", "passkey"] and body["passkey_required"] is False, body
    status, start = _call_h(w.S, "POST", "/users/me/passkeys/register/options", {}, headers)
    assert status == 200, start
    auth = SoftAuthenticator()
    credential = auth.make_credential(start["options"], ORIGIN, flags=FLAG.UP | FLAG.UV)
    status, done = _call_h(w.S, "POST", "/users/me/passkeys/register/verify",
                           {"challenge_id": start["challenge_id"], "credential": credential, "label": None}, headers)
    assert status == 201 and done["token_type"] == "bearer", done
    claims = _claims(done["access_token"])
    assert claims["amr"] == ["hwk"] and claims["idp"] == str(w.provider.id)
    assert len(w.db.rows_of(WebAuthnCredential)) == 1
    # Where none can be made (passkeys turned off; no address a passkey can be bound to): the authenticator alone.
    for off in ("turned off", "no address"):
        other = _without_a_password(kind, name=f"erin-{off[:2]}")
        w2 = World(monkeypatch, [other], passkeys="off" if off == "turned off" else "optional")
        if off == "no address":
            monkeypatch.setattr(w2.wss, "passkeys_can_be_made", lambda: False)
        body, _headers = w2.held(other)
        assert body["enrollment_methods"] == ["totp"] and "passkey_required" not in body, (off, body)


def test_an_account_that_has_a_password_types_it_before_it_sets_a_factor_up_after_a_provider(monkeypatch):
    """Alice has a password. A second factor is required, and she signs in through the provider. The authenticator's
    enrollment asks for her password; the page has none to send after the round trip to the provider, so the
    enrollment answered "your current password is required" and she was sent back. The sign-in asks for the
    password first now, and the enrollment that follows is proved by it. She is offered what an account with a
    password has always been offered there: the authenticator."""
    from app.services import sign_in
    alice = _user()
    w = World(monkeypatch, [alice])
    body, _headers = w.held(alice)
    assert body["stage"] == "password" and body["enrollment_required"] is False and body["username"] == "alice", body
    assert body["enrollment_methods"] == [] and body["access_token"] is None
    # The password stage's own route checks the password; its result is the provider's sign-in with the password.
    identity = w.identity(alice)
    outcome = sign_in.finish(w.db, sign_in.SignInResult(alice, ["pwd"], IP, provider_id=str(w.provider.id),
                                                        provider_sub=identity.subject))
    assert isinstance(outcome, sign_in.PendingStep) and outcome.body["enrollment_required"] is True
    assert outcome.body["enrollment_methods"] == ["totp"] and "passkey_required" not in outcome.body
    headers = {"Authorization": f"Bearer {outcome.body['pre_auth_token']}"}
    status, refused = _call_h(w.S, "POST", ENROLL, {"current_password": "not-it"}, headers)
    assert status == 400, refused
    status, done = w.set_an_authenticator_up(headers, password="pw")
    assert status == 200, done
    claims = _claims(done["access_token"])
    assert claims["amr"] == ["pwd", "totp"] and claims["idp"] == str(w.provider.id)
    # Where the provider's own second factor is taken (the policy trusts it and it was there), nothing is held.
    bob = _user("bob")
    trusting = World(monkeypatch, [bob], trust=True)
    assert isinstance(trusting.through_the_provider(bob, with_its_mfa=True), sign_in.SignedIn)
    assert trusting.held(bob)[0]["stage"] == "password"            # the policy trusts it; it was not there


@pytest.mark.parametrize("kind", NO_PASSWORD[:2])
def test_after_an_administrators_reset_such_an_account_sets_its_next_factor_up_at_its_provider(monkeypatch, kind):
    """No policy asks for a second factor. An administrator reset Dana's (a lost device): her next sign-in takes
    her through setting one up, whatever the policy says. It is a provider's sign-in, and she has no password: the
    set-up is proved by it, the reset is answered, and the notice she got did not speak of a password of hers."""
    from app.core import credential_changes as cc
    dana = _without_a_password(kind)
    w = World(monkeypatch, [dana], mfa_mode="optional")
    from app.services import sign_in
    assert isinstance(w.through_the_provider(dana), sign_in.SignedIn)        # nothing asked before the reset
    dana.second_factor_reset_at = datetime.utcnow()
    body, headers = w.held(dana)
    assert body["enrollment_required"] is True and "totp" in body["enrollment_methods"], body
    status, done = w.set_an_authenticator_up(headers)
    assert status == 200 and done.get("access_token"), done
    assert dana.second_factor_reset_at is None
    # The notice of the reset, for her and for an account that has a password.
    told = []
    monkeypatch.setattr(w.S, "_notify_account_change", lambda db, user, **kw: told.append((user.username, kw["change"])))
    alice = _user("alice")
    for target in (dana, alice):
        w.S._notify_credential_change(w.db, cc.SECOND_FACTOR, target, {"had_second_factor": True}, by_name="root")
    assert told[0][0] == "dana" and "with your own password" not in told[0][1]
    assert "at your next sign-in through your organisation" in told[0][1]
    assert told[1][0] == "alice" and "a new one, with your own password, at your next sign-in." in told[1][1]


STATES = ["an authenticator", "a passkey that can be used", "a reset it has not answered",
          "passkeys kept while they are switched off", "a key that can no longer be used", "nothing"]


@pytest.mark.parametrize("state", STATES)
def test_an_identity_linked_by_email_loses_the_providers_mfa_while_the_account_holds_a_factor_or_owes_one(monkeypatch, state):
    """Carol's identity was put on her account by its email address, and the provider's MFA is trusted. While she
    holds a factor she can give (an authenticator, a passkey that can be used), a sign-in through that identity
    is asked for it: the provider's word does not stand in for her own factor. Nor does it while she is to set a
    factor up again (a reset she has not answered, a key of a removed algorithm, passkeys kept while they are
    switched off): the sign-in is held for that set-up, which her provider's sign-in proves, as she has no
    password. With nothing at all she goes on as an account without a factor does, on the provider's trusted
    MFA. No new link by email reaches her in any state but the last
    (sso_sign_in.set_up_its_own_factor)."""
    from app.core.models import SecondFactorEnrollment, WebAuthnCredential
    from app.services import sign_in, sso_sign_in
    carol = _without_a_password("signs in only through its provider", name="carol")
    w = World(monkeypatch, [carol], mfa_mode="optional", trust=True, linked_by="email",
              passkeys="off" if state == "passkeys kept while they are switched off" else "optional")
    key = types.SimpleNamespace(id=uuid.uuid4(), user_id=carol.id, uv_initialized=True, retired_at=None, cose_alg=-7)
    if state == "an authenticator":
        w.db.rows_of(SecondFactorEnrollment).append(
            types.SimpleNamespace(id=uuid.uuid4(), user_id=carol.id, method="totp", status="active"))
    elif state == "a reset it has not answered":
        carol.second_factor_reset_at = datetime.utcnow()
    elif state != "nothing":
        w.db.rows_of(WebAuthnCredential).append(key)
    usable = state != "a key that can no longer be used"
    monkeypatch.setattr(w.wss, "algorithm_usable", lambda db, cose_alg, now=None: (usable, False))
    holds = state in ("an authenticator", "a passkey that can be used")
    owes = state in ("a reset it has not answered", "a key that can no longer be used",
                     "passkeys kept while they are switched off")
    identity = w.identity(carol)
    assert sign_in.holds_a_factor(w.db, carol) is holds
    assert bool(w.S._second_factor_to_set_up_again(w.db, carol)) is owes
    assert sso_sign_in.linked_on_the_providers_word(w.db, carol, identity) is (holds or owes)
    assert sso_sign_in.set_up_its_own_factor(w.db, carol) is (state != "nothing")
    outcome = w.through_the_provider(carol, with_its_mfa=True)
    if holds:
        assert isinstance(outcome, sign_in.PendingStep) and outcome.body["enrollment_required"] is False
        assert outcome.body["methods"] == (["totp", "recovery"] if state == "an authenticator" else ["passkey"])
    elif owes:
        assert isinstance(outcome, sign_in.PendingStep) and outcome.body["enrollment_required"] is True, (state, outcome)
        assert "totp" in outcome.body["enrollment_methods"] and outcome.body["stage"] == "second_factor"
        headers = {"Authorization": f"Bearer {outcome.body['pre_auth_token']}"}
        status, done = w.set_an_authenticator_up(headers)                # proved by the provider's sign-in
        assert status == 200 and done.get("access_token") and carol.second_factor_reset_at is None, done
    else:
        assert isinstance(outcome, sign_in.SignedIn), (state, outcome)
    # An identity she linked herself is trusted as the policy says, whatever she holds; and so is no identity at
    # all handed in (a caller that knows none).
    identity.linked_by = "self"
    assert sso_sign_in.linked_on_the_providers_word(w.db, carol, identity) is False
    assert sso_sign_in.linked_on_the_providers_word(w.db, carol, None) is False


@pytest.mark.parametrize("owed", ["an administrator's reset", "a key that can no longer be used"])
def test_an_account_with_a_password_linked_by_email_answers_what_it_owes_behind_its_password(monkeypatch, owed):
    """Alice has a password, and her identity at the provider was linked by her email address. An administrator
    reset her second factor (a lost phone, or a factor somebody may have planted); or her only passkey lapsed.
    Whoever holds that identity at the provider would have signed in on the provider's trusted MFA alone, with no
    password and no factor, for as long as the reset stayed unanswered: the door the reset was made to close.
    The sign-in is held now: the password first, then the set-up of the factor, proved by that password. The
    same identity linked by herself is trusted as the policy says."""
    from app.core.models import WebAuthnCredential
    from app.services import sign_in
    alice = _user()
    w = World(monkeypatch, [alice], mfa_mode="optional", trust=True, linked_by="email")
    assert isinstance(w.through_the_provider(alice, with_its_mfa=True), sign_in.SignedIn)       # nothing owed yet
    if owed == "an administrator's reset":
        alice.second_factor_reset_at = datetime.utcnow()
    else:
        w.db.rows_of(WebAuthnCredential).append(
            types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, uv_initialized=True, retired_at=None,
                                  cose_alg=-257))
        monkeypatch.setattr(w.wss, "algorithm_usable", lambda db, cose_alg, now=None: (False, False))
    body, _headers = w.held(alice, with_its_mfa=True)
    assert body["stage"] == "password" and body["enrollment_required"] is False and body["access_token"] is None, body
    identity = w.identity(alice)
    outcome = sign_in.finish(w.db, sign_in.SignInResult(alice, ["pwd"], IP, provider_id=str(w.provider.id),
                                                        provider_sub=identity.subject))
    assert isinstance(outcome, sign_in.PendingStep) and outcome.body["enrollment_required"] is True, outcome
    status, done = w.set_an_authenticator_up({"Authorization": f"Bearer {outcome.body['pre_auth_token']}"}, password="pw")
    assert status == 200 and _claims(done["access_token"])["amr"] == ["pwd", "totp"], done
    assert alice.second_factor_reset_at is None
    # Her own link: the provider's MFA is taken as the policy says, whatever she owes (she vouched for the link).
    bob = _user("bob")
    own = World(monkeypatch, [bob], mfa_mode="optional", trust=True, linked_by="self")
    bob.second_factor_reset_at = datetime.utcnow()
    assert isinstance(own.through_the_provider(bob, with_its_mfa=True), sign_in.SignedIn)


def test_a_factor_the_account_came_to_hold_since_the_hold_is_given_before_another_is_set_up(monkeypatch):
    """Alice signed in with her password and is held for the set-up of a factor. Before the wizard runs, her
    account comes to hold a passkey (she registered one elsewhere within the five minutes). The passkey's
    enrollment on that hold answers "confirm your second factor first"; so does the authenticator's now, at its
    start and again where it would be made active, so no second factor is set beside one that was never asked."""
    from app.core.models import SecondFactorEnrollment, WebAuthnCredential
    alice = _user()
    w = World(monkeypatch, [alice])
    first = "Confirm your second factor first; start the sign-in again."
    _pending, headers = w.held_with_no_provider(alice, ("pwd",))
    from app.core import second_factor as sf
    status, started = _call_h(w.S, "POST", ENROLL, {"current_password": "pw"}, headers)
    assert status == 200, started
    code = sf._totp_at_step(started["secret"], sf.current_totp_step())
    assert _call_h(w.S, "POST", CONFIRM, {"code": code}, headers)[0] == 200
    w.h.enroll(alice)                                              # a passkey, since the hold
    status, body = _call_h(w.S, "POST", ACKNOWLEDGE, None, headers)
    assert status == 401 and body["detail"] == first, body
    assert [e.status for e in w.db.rows_of(SecondFactorEnrollment)] == ["unconfirmed"]
    status, body = _call_h(w.S, "POST", ENROLL, {"current_password": "pw"}, headers)
    assert status == 401 and body["detail"] == first, body
    w.db.rows_of(WebAuthnCredential).clear()                       # without it, the same hold goes on
    assert _call_h(w.S, "POST", ACKNOWLEDGE, None, headers)[0] == 200


def test_a_reset_of_an_account_linked_by_email_is_answered_at_the_provider_when_its_mfa_is_not_there(monkeypatch):
    """The same account after a reset, on a sign-in that did not carry the provider's MFA: held for the set-up,
    which the provider's sign-in proves. Before, this account was held at an authenticator's enrollment that asked
    for a password it does not have, and nothing else was offered."""
    carol = _without_a_password("signs in only through its provider", name="carol")
    w = World(monkeypatch, [carol], mfa_mode="optional", trust=True, linked_by="email")
    carol.second_factor_reset_at = datetime.utcnow()
    for there in (True, False):                         # with the provider's MFA there too: the reset is owed
        body, headers = w.held(carol, with_its_mfa=there)
        assert body["enrollment_required"] is True and body["enrollment_methods"] == ["totp", "passkey"], (there, body)
    status, done = w.set_an_authenticator_up(headers)
    assert status == 200 and done.get("access_token") and carol.second_factor_reset_at is None, done


def test_a_key_set_up_on_the_providers_word_signs_in_after_the_provider_and_never_around_it(monkeypatch):
    """Dana's password is one nobody knows, and passwords are allowed at her provider, so her account is not one
    that signs in only through it. Her passkey was set up on the provider's sign-in alone (nothing else could
    prove it). A user-verified passkey of a user signs in by itself by default: hers would, after the provider
    refused her, after her time without a sign-in there ran out, after the provider was turned off. So it does
    not: by itself it is refused, with a message that says where to sign in, and it is her second factor after
    the provider. Once she has a password of her own (a reset link), the mark is gone and the key signs in as
    anybody's. An account with a password is not touched by any of this."""
    from app.services import sign_in
    dana, alice = _without_a_password("its password is one nobody knows"), _user("alice")
    w = World(monkeypatch, [dana, alice], mfa_mode="optional")
    auth, row = w.h.enroll(dana)
    other, _row = w.h.enroll(alice)
    failures_before = list(w.h.failures)
    status, body = w.h.sign_in(auth, username="dana")
    assert status == 403, body
    assert "through Contoso" in body["detail"] and "after that sign-in" in body["detail"], body
    assert "password reset link" in body["detail"]
    assert w.h.failures[len(failures_before):] == [("dana", sign_in.KEY_AFTER_THE_PROVIDER_REASON, "passkey")]
    assert w.h.counted == [] and row.sign_count == 1 and row.last_used_at is None        # the proof was good
    # The pipeline's own rule, whatever door: a passkey without the provider, no password among the proofs.
    for methods in (["hwk"], ["swk"]):
        with pytest.raises(sign_in.ProviderOnly):
            sign_in.finish(w.db, sign_in.SignInResult(dana, methods, IP, user_verified=True, passwordless_allowed=True))
    # The rule is about the key. A sign-in that proved a password of this account's (there is none to type; the
    # door that checks one would have refused) is not what it refuses.
    held = sign_in.finish(w.db, sign_in.SignInResult(dana, ["pwd"], IP))
    assert isinstance(held, sign_in.PendingStep) and held.body["methods"] == ["passkey"]
    # After the provider it is her second factor.
    body, _headers = w.held(dana)
    assert body["enrollment_required"] is False and body["methods"] == ["passkey"], body
    identity = w.identity(dana)
    assert isinstance(sign_in.finish(w.db, sign_in.SignInResult(
        dana, ["hwk"], IP, provider_id=str(w.provider.id), provider_sub=identity.subject)), sign_in.SignedIn)
    # An account with a password: its passkey signs in by itself, as before.
    status, body = w.h.sign_in(other, username="alice")
    assert status == 200 and body.get("access_token"), body
    # A password of her own: another hash, so the mark no longer fits, and the key is hers alone.
    dana.password_hash = "x"
    status, body = w.h.sign_in(auth, username="dana", sign_count=2)
    assert status == 200 and body.get("access_token"), body
    # An account that signs in only through its provider is refused whatever the proof, with its own reason.
    erin = _without_a_password("signs in only through its provider", name="erin")
    w2 = World(monkeypatch, [erin], mfa_mode="optional")
    with pytest.raises(sign_in.ProviderOnly):
        sign_in.finish(w2.db, sign_in.SignInResult(erin, ["pwd"], IP))
    assert w2.h.failures[-1] == ("erin", sign_in.PROVIDER_ONLY_REASON, "username")


@pytest.mark.parametrize("kind", NO_PASSWORD[:2])
def test_passkeys_made_at_another_address_are_set_up_again_at_the_providers_sign_in(monkeypatch, kind):
    """The vault moved to another host name. Dana can type no password and holds one passkey, made at the old
    name: no browser offers it at the new one. Her sign-in through her provider is held for a set-up (not for a
    key she cannot give), the page is told why, and the provider's sign-in proves the set-up: she ends with a
    session. Back at the old name the key counts again by itself, and is what she is asked for."""
    from app.core.models import WebAuthnCredential
    from app.services import sign_in
    dana = _without_a_password(kind)
    w = World(monkeypatch, [dana], mfa_mode="optional")
    here = w.wss.address_now()
    assert here
    key = types.SimpleNamespace(id=uuid.uuid4(), user_id=dana.id, uv_initialized=True, retired_at=None, cose_alg=-7,
                                rp_id="old.example.test")
    w.db.rows_of(WebAuthnCredential).append(key)
    monkeypatch.setattr(w.wss, "algorithm_usable", lambda db, cose_alg, now=None: (True, False))
    assert w.wss.usable_passkeys(w.db, dana.id) == 0 and sign_in.holds_a_factor(w.db, dana) is False
    assert w.wss.why_none_can_be_used(w.db, dana.id) == "passkeys_at_another_address"
    assert bool(w.S._second_factor_to_set_up_again(w.db, dana)) is True
    outcome = w.through_the_provider(dana)
    assert isinstance(outcome, sign_in.PendingStep) and outcome.body["enrollment_required"] is True, outcome
    assert outcome.body["set_up_again"] == "passkeys_at_another_address", outcome.body
    assert "totp" in outcome.body["enrollment_methods"] and "passkey" not in outcome.body.get("methods", [])
    # The address goes back before she sets anything up: the key is hers to give again, and nothing is owed.
    key.rp_id = here
    assert w.wss.usable_passkeys(w.db, dana.id) == 1 and w.wss.why_none_can_be_used(w.db, dana.id) is None
    again = w.through_the_provider(dana)
    assert isinstance(again, sign_in.PendingStep) and again.body["enrollment_required"] is False, again
    assert again.body["methods"] == ["passkey"] and "set_up_again" not in again.body
    # Moved again, she sets an authenticator up on the provider's sign-in, with no password asked for.
    key.rp_id = "old.example.test"
    held = w.through_the_provider(dana)
    headers = {"Authorization": f"Bearer {held.body['pre_auth_token']}"}
    status, done = w.set_an_authenticator_up(headers)
    assert status == 200 and done.get("access_token"), done
    # A key with no address on record (made before it was kept) is taken as made here.
    key.rp_id = None
    assert w.wss.usable_passkeys(w.db, dana.id) == 1


@pytest.mark.parametrize("came_to_hold", ["an authenticator", "a reset it has not answered", "nothing"])
def test_the_providers_mfa_of_an_identity_linked_by_email_is_judged_again_where_the_sign_in_is_finished(monkeypatch, came_to_hold):
    """The provider answered while Carol held no factor, so its trusted MFA stood in for one. The sign-in is
    finished up to a minute later (its handover code), or five (a held step). A factor she came to hold in that
    time, or a reset, is what counts where the sign-in is finished: she gives her own factor, or sets one up. An
    identity she linked herself keeps the provider's MFA, as the policy says."""
    from app.core.models import SecondFactorEnrollment
    from app.services import sign_in, sso_sign_in
    carol = _without_a_password("signs in only through its provider", name="carol")
    w = World(monkeypatch, [carol], mfa_mode="optional", trust=True, linked_by="email")
    identity = w.identity(carol)

    def answered():
        answer = sso_sign_in.ProviderAnswer(
            claims={}, subject=identity.subject, issuer="https://idp.example", tenant_id=None, email=None,
            email_verified=False, display_name=None, auth_time=None, amr=["mfa"])
        return sso_sign_in.pipeline_result(w.db, w.provider, carol, answer, provider_id=str(w.provider.id),
                                           client_ip=IP, identity=identity, began_at=time.time())
    result = answered()
    assert result.provider_mfa_trusted is True               # as she stood when the provider answered
    if came_to_hold == "an authenticator":
        w.db.rows_of(SecondFactorEnrollment).append(
            types.SimpleNamespace(id=uuid.uuid4(), user_id=carol.id, method="totp", status="active"))
    elif came_to_hold == "a reset it has not answered":
        carol.second_factor_reset_at = datetime.utcnow()
    outcome = sign_in.finish(w.db, result)
    if came_to_hold == "nothing":
        assert isinstance(outcome, sign_in.SignedIn) and result.provider_mfa_trusted is True
        return
    assert result.provider_mfa_trusted is False
    assert isinstance(outcome, sign_in.PendingStep), outcome
    assert outcome.body["enrollment_required"] is (came_to_hold != "an authenticator")
    if came_to_hold == "an authenticator":
        assert outcome.body["methods"] == ["totp", "recovery"]
    # The same change on an identity she linked herself: the provider's MFA is taken as the policy says.
    identity.linked_by = "self"
    own = answered()
    assert own.provider_mfa_trusted is True
    kept = sign_in.finish(w.db, own)
    assert own.provider_mfa_trusted is True and isinstance(kept, sign_in.SignedIn), kept


def test_a_sign_in_that_carries_no_trusted_mfa_is_not_asked_whether_it_still_counts(monkeypatch):
    from app.services import sign_in, sso_sign_in
    carol = _without_a_password("signs in only through its provider", name="carol")
    w = World(monkeypatch, [carol], mfa_mode="optional", trust=False)
    asked = []
    monkeypatch.setattr(sso_sign_in, "provider_mfa_still_counts", lambda db, result: asked.append(1) or True)
    assert isinstance(w.through_the_provider(carol), sign_in.SignedIn) and asked == []


def test_a_factor_set_up_at_a_providers_held_sign_in_holds_the_providers_row_before_the_accounts_turn(monkeypatch):
    """The set-up writes its factor in the account's turn, and the session that follows is written in that same
    turn. A save of the provider takes the provider's row and then each linked account's turn, so the set-up
    takes them in that order too: the row first, shared, then the turn. Taken the other way round, the two
    waited for each other."""
    from app.core.models import SsoProvider
    from app.services import sign_in
    dana = _without_a_password("signs in only through its provider")
    w = World(monkeypatch, [dana])
    pending, _headers = w.held_with(dana, [])
    pending._provider_id, pending._provider_sub = str(w.provider.id), w.identity(dana).subject
    pending._sessions_ended, pending._methods_so_far = 0, ()
    order, through = [], w.db.query

    def query(*entities):
        made = through(*entities)
        lock = made.with_for_update

        def with_for_update(**kw):
            order.append(("row", getattr(entities[0], "__tablename__", None), kw))
            return lock(**kw)
        made.with_for_update = with_for_update
        return made
    monkeypatch.setattr(w.db, "query", query)
    monkeypatch.setattr(w.S, "_sessions_turn", lambda db, user_id: order.append(("turn", str(user_id))))
    sign_in.refuse_a_factor_the_sign_in_could_not_finish(w.db, dana, pending, IP)
    assert order[:2] == [("row", SsoProvider.__tablename__, {"read": True}), ("turn", str(dana.id))], order
    # A sign-in held through no provider takes the turn, and no row (and this account, which signs in only
    # through its provider, is then refused in it).
    del order[:]
    other, _headers = w.held_with_no_provider(dana, ["pwd"])
    with pytest.raises(sign_in.ProviderOnly):
        sign_in.refuse_a_factor_the_sign_in_could_not_finish(w.db, dana, other, IP)
    assert order == [("turn", str(dana.id))], order


@pytest.mark.parametrize("changed", ["made provider-only", "turned off", "locked", "nothing"])
def test_a_factor_at_a_held_sign_in_is_judged_on_the_account_as_it_is_committed(monkeypatch, changed):
    """Whoever holds an account's password is held at a set-up. In that moment an administrator's save makes the
    account sign in only through its provider: it ends the sessions a password made and spends no sign-in under
    way. The factor's write then took the account's turn and judged the account as it had been loaded before the
    turn: the factor was stored, the sign-in itself was refused afterwards, and the factor stayed. The account is
    read again in the turn. On real rows: the request's session holds the account as it loaded it, the change is
    committed through another."""
    from datetime import datetime, timedelta
    import sqlalchemy as sa
    from fastapi import HTTPException
    from _bare_api_env import set_bare_api_env
    set_bare_api_env()
    from _kept_db import kept_database
    from app.api import api_server as api
    from app.core.models import PendingLogin, RoleEnum, User
    from app.services import sign_in
    took, the_save = [], []

    def the_turn_comes_after_the_save(db, user_id):
        # The save held the account's turn first: the factor's write gets it once the save has committed.
        took.append("the turn")
        for commit_it in the_save:
            commit_it()
    monkeypatch.setattr(api, "_sessions_turn", the_turn_comes_after_the_save)
    monkeypatch.setattr(api.AuditLogger, "log_login_failure", lambda self, *a, **k: None)
    with kept_database() as (make, _engine):
        with make() as request, make() as elsewhere:
            alice = User(username="alice", email=None, password_hash="x", role=RoleEnum.USER, is_active=True,
                         is_locked=False, sso_only=False)
            request.add(alice)
            request.flush()
            held = PendingLogin(user_id=alice.id, client_ip=IP, enrollment_required=True,
                                expires_at=datetime.utcnow() + timedelta(minutes=5))
            request.add(held)
            request.commit()
            alice, held = request.get(User, alice.id), request.get(PendingLogin, held.id)
            assert alice.sso_only is False and alice.is_active is True         # as the request loaded it
            held._methods_so_far, held._sessions_ended = ("pwd",), 0
            change = {"made provider-only": "sso_only = 1", "turned off": "is_active = 0",
                      "locked": "is_locked = 1"}.get(changed)
            if change:
                def committed():
                    elsewhere.execute(sa.text(f"UPDATE users SET {change} WHERE id = :id"), {"id": alice.id.hex})
                    elsewhere.commit()
                the_save.append(committed)

            def write_the_factor():
                sign_in.refuse_a_factor_the_sign_in_could_not_finish(request, alice, held, IP)
            if changed == "nothing":
                write_the_factor()                                # the factor may be written
            elif changed == "made provider-only":
                with pytest.raises(sign_in.ProviderOnly):
                    write_the_factor()
            else:
                with pytest.raises(HTTPException) as refused:
                    write_the_factor()
                assert refused.value.status_code in (401, 403), refused.value.detail
            assert took == ["the turn"]                           # read again in the turn, not before it


def test_the_account_is_read_again_after_the_turn_and_before_it_is_judged():
    import inspect
    from app.services import sign_in
    source = inspect.getsource(sign_in.refuse_a_factor_the_sign_in_could_not_finish)
    steps = ("with_a_short_wait(db, lambda: api._sessions_turn(db, user.id))",
             "sso_only.read_again(db, user, ACCOUNT_STATE_A_FACTOR_IS_JUDGED_ON)",
             "refuse_unless_the_account_may_sign_in(db, user, client_ip)",
             "refuse_without_the_provider(db, held)")
    order = [source.index(step) for step in steps]
    assert order == sorted(order), order
    assert sign_in.ACCOUNT_STATE_A_FACTOR_IS_JUDGED_ON == ("sso_only", "is_active", "is_locked", "locked_until")
