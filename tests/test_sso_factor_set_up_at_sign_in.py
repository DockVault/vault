"""A second factor set up at a sign-in that came through a provider, from the provider's answer to a session
(app/services/sign_in.py, app/services/sso_sign_in.py, the enrollment routes in app/api/api_server.py).

An account that can type no password (it signs in only through its provider, or its password is one nobody knows)
has nothing but the provider's sign-in to prove itself with. Held for a second factor it must set up, it sets up
an authenticator, or a passkey where one can be made, on that sign-in; an account that has a password types it
first. The cases: a factor required by the policy, an administrator's reset, an identity linked by email that is
between two factors. And the key such an account sets up serves after its provider, never around it. Offline:
the routes through the ASGI app, an in-memory database, a real provider row and identity."""
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
                                             client_ip=IP, identity=identity)
        return sign_in.finish(self.db, result)

    def held(self, user, **kw):
        from app.services import sign_in
        outcome = self.through_the_provider(user, **kw)
        assert isinstance(outcome, sign_in.PendingStep), outcome
        return outcome.body, {"Authorization": f"Bearer {outcome.body['pre_auth_token']}"}

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
    status, body = _call_h(w.S, "POST", ENROLL, {"current_password": ""}, headers)
    assert status == 400 and body["detail"] == "Your current password is required and must be correct.", body
    assert _call_h(w.S, "POST", ENROLL, {"current_password": "pw"}, headers)[0] == 200
    # No provider behind the held sign-in: nothing proves it for an account that can type no password.
    pending, headers = w.h.pending_for(dana, methods=())
    pending.enrollment_required = True
    assert _call_h(w.S, "POST", ENROLL, {"current_password": ""}, headers)[0] == 400
    assert all(p.consumed_at is None for p in w.db.rows_of(PendingLogin))
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
def test_an_identity_linked_by_email_loses_the_providers_mfa_only_while_the_account_holds_a_factor(monkeypatch, state):
    """Carol's identity was put on her account by its email address, and the provider's MFA is trusted. While she
    holds a factor she can give (an authenticator, a passkey that can be used), a sign-in through that identity
    is asked for it: the provider's word does not stand in for her own factor. Between two factors she holds none
    (a reset she has not answered, passkeys kept while they are switched off, a key of a removed algorithm):
    asked for one she could never answer. She goes on as an account without a factor does, on the provider's
    trusted MFA. No new link by email reaches her in any of these states (sso_sign_in.set_up_its_own_factor)."""
    from app.core.models import SecondFactorEnrollment, WebAuthnCredential
    from app.services import sign_in, sso_sign_in
    carol = _without_a_password("signs in only through its provider", name="carol")
    w = World(monkeypatch, [carol], mfa_mode="optional", trust=True, linked_by="email",
              passkeys="off" if state == "passkeys kept while they are switched off" else "optional")
    key = types.SimpleNamespace(id=uuid.uuid4(), user_id=carol.id, retired_at=None, cose_alg=-7)
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
    identity = w.identity(carol)
    assert sign_in.holds_a_factor(w.db, carol) is holds
    assert sso_sign_in.linked_on_the_providers_word(w.db, carol, identity) is holds
    assert sso_sign_in.set_up_its_own_factor(w.db, carol) is (state != "nothing")
    outcome = w.through_the_provider(carol, with_its_mfa=True)
    if holds:
        assert isinstance(outcome, sign_in.PendingStep) and outcome.body["enrollment_required"] is False
        assert outcome.body["methods"] == (["totp", "recovery"] if state == "an authenticator" else ["passkey"])
    else:
        assert isinstance(outcome, sign_in.SignedIn), (state, outcome)
    # An identity she linked herself is trusted as the policy says, whatever she holds; and so is no identity at
    # all handed in (a caller that knows none).
    identity.linked_by = "self"
    assert sso_sign_in.linked_on_the_providers_word(w.db, carol, identity) is False
    assert sso_sign_in.linked_on_the_providers_word(w.db, carol, None) is False


def test_a_reset_of_an_account_linked_by_email_is_answered_at_the_provider_when_its_mfa_is_not_there(monkeypatch):
    """The same account after a reset, on a sign-in that did not carry the provider's MFA: held for the set-up,
    which the provider's sign-in proves. Before, this account was held at an authenticator's enrollment that asked
    for a password it does not have, and nothing else was offered."""
    carol = _without_a_password("signs in only through its provider", name="carol")
    w = World(monkeypatch, [carol], mfa_mode="optional", trust=True, linked_by="email")
    carol.second_factor_reset_at = datetime.utcnow()
    body, headers = w.held(carol)
    assert body["enrollment_required"] is True and body["enrollment_methods"] == ["totp", "passkey"], body
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
