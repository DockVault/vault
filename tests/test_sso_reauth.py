"""The provider re-authentication step-up (app/api/sso_router.py start_reauth and finish_reauth, the callback's
step-up branch, app/services/sso_sign_in.py reauth_refusal and reauth_available, the step-up route's idp_reauth
method): offered only for a linked provider whose test carried auth_time; the callback accepts only a fresh sign-in
of the account's own identity, with the provider's MFA when trusted; the tab that started it stages the proof; the
step-up route spends it once for the password part and never for the factor part. Offline."""
import time
import types
import uuid
from datetime import datetime

import pytest

from test_oidc_client import ISSUER
from test_sso_resolution import Resolving
from test_sso_sign_in import _call, _h, _identity, _provider, _user

pytestmark = pytest.mark.unit

TESTED = {"outcome": "ok", "auth_time_present": True}


class Reauth(Resolving):
    def __init__(self, monkeypatch, users, providers, identities=(), **kw):
        super().__init__(monkeypatch, users, providers, identities=identities, **kw)
        S = self.S
        from app.core import second_factor as sf
        from app.core import security
        monkeypatch.setattr(security, "verify_password", lambda plain, hashed: plain == "pw" and hashed == "x")
        self.receipts = []
        monkeypatch.setattr(sf, "issue_step_up_receipt", lambda db, *, user_id, action, session_hash, redis=None, method="": (
            self.receipts.append((str(user_id), action, session_hash)) or f"r{len(self.receipts)}"))
        # The action asks for the password alone (the fixed policy "password_always" shape).
        monkeypatch.setattr(S, "_sf_requirement_for", lambda db, user, action: ({"otp": False, "password": True, "must_enroll": False}, False))
        monkeypatch.setattr(S, "_sf_login_methods", lambda db, user: [])
        monkeypatch.setitem(S.app.dependency_overrides, S.get_current_user, lambda: self.current_user)

    def start_reauth(self, provider, action="admin.retention.write", verifier="reauth-tab"):
        return _call(self.S, "POST", f"/users/me/identities/{provider.id}/reauth",
                     {"verifier_hash": _h(verifier), "action": action})[:2]

    def finish_reauth(self, location, verifier="reauth-tab"):
        from urllib.parse import parse_qs
        code = parse_qs(location.split("#", 1)[1])["sso-stepup"][0]
        return _call(self.S, "POST", "/users/me/identities/reauth/finish", {"code": code, "verifier": verifier})[:2]

    def step_up(self, action="admin.retention.write", **body):
        return _call(self.S, "POST", "/auth/second-factor/step-up", {"action": action, **body})[:2]


def _stepped_up_url(h, p, **claims):
    status, out = h.start_reauth(p)
    assert status == 200, out
    url = out["authorization_url"]
    assert "prompt=login" in url and "max_age=0" in url
    state, record = h.state_of(url)
    assert record["purpose"] == "step_up" and record["step_up_action"] == "admin.retention.write"
    h.claims_override = claims
    return h.callback(p, state)


def test_a_fresh_provider_sign_in_meets_the_password_part_once(monkeypatch):
    alice, p = _user(sso_only=True), _provider(last_test=TESTED)
    h = Reauth(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    # Offered: the challenge lists the method beside the password.
    status, body = _call(h.S, "POST", "/auth/second-factor/challenge", {"action": "admin.retention.write"})[:2]
    assert status == 200 and body["methods"] == ["idp_reauth", "password"], body
    status, location, _ = _stepped_up_url(h, p, auth_time=int(time.time()) - 5)
    assert status == 302 and location.startswith("/#sso-stepup="), location
    # Nothing is staged until the tab claims the code with its verifier.
    assert not [k for k in h.redis.rows if k.startswith("sso:reauth:")]
    assert h.finish_reauth(location, verifier="other-tab")[0] == 401
    status, location, _ = _stepped_up_url(h, p, auth_time=int(time.time()) - 5)
    status, body = h.finish_reauth(location)
    assert status == 200 and body == {"staged": True, "action": "admin.retention.write", "expires_in": 120}, body
    assert [k for k in h.redis.rows if k.startswith("sso:reauth:")]
    assert any(a[0] == "step_up_idp_reauth" and a[2]["step_up"] == "admin.retention.write" for a in h.audits)
    # The step-up route takes the staged proof for the password part: once.
    status, body = h.step_up(method="idp_reauth")
    assert status == 200 and body == {"receipt": "r1"}, body
    assert h.receipts == [(str(alice.id), "admin.retention.write", "sess-hash")]
    status, body = h.step_up(method="idp_reauth")
    assert status == 403 and "Confirm with your organisation" in body["detail"]
    # Staged for one action and one session: another action, or another session of the account, does not take it.
    status, location, _ = _stepped_up_url(h, p, auth_time=int(time.time()) - 5)
    h.finish_reauth(location)
    assert h.step_up(action="admin.auth_policy.write", method="idp_reauth")[0] == 403
    h.session_hash = "another-session"
    assert h.step_up(method="idp_reauth")[0] == 403
    h.session_hash = "sess-hash"
    # A provider disabled meanwhile confirms nobody; enabled again, the staged proof stands.
    p.state = "disabled"
    assert h.step_up(method="idp_reauth")[0] == 403
    p.state = "enabled"
    assert h.step_up(method="idp_reauth")[0] == 200
    # The password still works as before.
    assert h.step_up(method="password", password="pw")[0] == 200


@pytest.mark.parametrize("meanwhile", ["turned off", "unlinked"])
@pytest.mark.parametrize("when", ["before the tab claims the code", "after it was staged"])
def test_a_confirmation_counts_only_while_the_provider_it_was_made_at_still_confirms_the_account(monkeypatch, when,
                                                                                                meanwhile):
    """The account is linked to two providers. It confirms itself at the first; before the step-up spends that
    confirmation (it lives two minutes), an administrator turns the first provider off (an incident), or the
    account is unlinked from it. The second provider is still on, so a provider can confirm the account: but
    not this confirmation, which was made at the one that no longer stands. Made at a provider that still
    stands, it counts as before."""
    from app.core import sso_state
    from app.core.models import ExternalIdentity
    carol = _user("carol", sso_only=True)
    one, two = _provider(name="one", label="One", last_test=TESTED), _provider(name="two", label="Two", last_test=TESTED)
    first = _identity(carol, one, subject="at-one")
    h = Reauth(monkeypatch, [carol], [one, two], identities=[first, _identity(carol, two, subject="at-two")])
    h.current_user = carol

    def gone():
        if meanwhile == "turned off":
            one.state = "disabled"
        else:
            h.db.rows_of(ExternalIdentity).remove(first)

    status, location, _ = _stepped_up_url(h, one, sub="at-one", auth_time=int(time.time()) - 5)
    assert status == 302 and location.startswith("/#sso-stepup="), location
    if when == "before the tab claims the code":
        gone()
        status, body = h.finish_reauth(location)
        assert status == 409 and body["detail"]["reason"] == "provider_disabled", body
        assert not [k for k in h.redis.rows if k.startswith("sso:reauth:")]          # nothing was staged
    else:
        assert h.finish_reauth(location)[0] == 200
        assert sso_state.take_reauth(h.session_hash, "admin.retention.write") == str(one.id)   # names its provider
        sso_state.stage_reauth(h.session_hash, "admin.retention.write", one.id)
        gone()
    status, body = h.step_up(method="idp_reauth")
    assert status == 403 and "Confirm with your organisation" in body["detail"], body
    assert h.receipts == []
    # The other provider still confirms the account, with a confirmation of its own.
    status, location, _ = _stepped_up_url(h, two, sub="at-two", auth_time=int(time.time()) - 5)
    assert h.finish_reauth(location)[0] == 200
    assert h.step_up(method="idp_reauth")[0] == 200 and len(h.receipts) == 1
    # A stage that names no provider of the account (one from before stages named theirs) confirms nothing.
    for named in ("1", str(uuid.uuid4())):
        sso_state.stage_reauth(h.session_hash, "admin.retention.write", named)
        assert h.step_up(method="idp_reauth")[0] == 403


def test_the_provider_must_be_linked_and_tested_with_auth_time(monkeypatch):
    alice, p, q = _user(sso_only=True), _provider(last_test=TESTED), _provider(name="untested", last_test={"outcome": "ok", "auth_time_present": False})
    h = Reauth(monkeypatch, [alice], [p, q], identities=[_identity(alice, q, subject="s-q")])
    # Linked to q, whose test carried no auth_time; p untested-for-alice (no identity): neither is offered.
    status, body = _call(h.S, "POST", "/auth/second-factor/challenge", {"action": "admin.retention.write"})[:2]
    assert body["methods"] == ["password"]
    assert h.start_reauth(q)[0] == 404 and h.start_reauth(p)[0] == 404
    assert h.start_reauth(p, action="not.an.action")[0] == 404
    # A staged proof cannot be faked by calling the step-up route with the method when nothing is offered.
    assert h.step_up(method="idp_reauth")[0] == 403
    # Another account's identity on the provider is not this account's.
    from app.core.models import ExternalIdentity
    h.db.rows_of(ExternalIdentity).append(_identity(_user("other"), p, subject="s-other"))
    assert h.start_reauth(p)[0] == 404
    # Disabled provider: not offered even with the identity and the evidence.
    h.db.rows_of(ExternalIdentity).append(_identity(alice, p))
    p.state = "disabled"
    assert h.start_reauth(p)[0] == 404
    p.state = "enabled"
    assert h.start_reauth(p)[0] == 200


@pytest.mark.parametrize("arrange, reason", [
    ("stale", "reauth_stale"),
    ("no_auth_time", "reauth_stale"),
    ("just_over_a_minute_old", "reauth_stale"),
    ("future", "provider_clock_ahead"),
    ("other_identity", "not_this_account"),
    ("other_tenant", "not_this_account"),
    ("no_mfa_when_trusted", "reauth_no_mfa"),
])
def test_the_callback_accepts_only_a_fresh_sign_in_of_the_accounts_own_identity(monkeypatch, arrange, reason):
    policy = {"sso_trust_idp_mfa": True, "sso_accepted_amr": ["mfa"]} if arrange == "no_mfa_when_trusted" else None
    alice, p = _user(sso_only=True), _provider(last_test=TESTED, policy=policy)
    identity = _identity(alice, p, tenant_id="t1" if arrange == "other_tenant" else None)
    h = Reauth(monkeypatch, [alice], [p], identities=[identity])
    now = int(time.time())
    claims = {"auth_time": now - 5, "tid": "t1" if arrange == "other_tenant" else ...}
    if arrange == "stale":
        claims["auth_time"] = now - 120
    elif arrange == "no_auth_time":
        claims["auth_time"] = ...
    elif arrange == "just_over_a_minute_old":
        claims["auth_time"] = now - 70
    elif arrange == "future":
        claims["auth_time"] = now + 300
    elif arrange == "other_identity":
        claims["sub"] = "someone-else"
    elif arrange == "other_tenant":
        claims["tid"] = "t2"
    elif arrange == "no_mfa_when_trusted":
        claims["amr"] = ["pwd"]
    status, location, _ = _stepped_up_url(h, p, **{k: v for k, v in claims.items()})
    assert location == f"/#sso-error={reason}", location
    assert not [k for k in h.redis.rows if k.startswith("sso:handover:") or k.startswith("sso:reauth:")]
    if arrange == "future":
        # Refused where the provider's answer is read, before the re-authentication's own rule: for every purpose.
        assert any(a[0] == "sso_sign_in_refused" and a[2].get("reason") == reason and a[2].get("purpose") == "step_up"
                   for a in h.audits), h.audits
        return
    assert any(a[0] == "sso_sign_in_refused" and a[2].get("reason") == reason and a[2].get("step_up") == "admin.retention.write"
               for a in h.audits), h.audits
    # With the provider's MFA trusted and present, the sign-in is accepted.
    if arrange == "no_mfa_when_trusted":
        status, location, _ = _stepped_up_url(h, p, auth_time=now - 5, amr=["pwd", "mfa"])
        assert location.startswith("/#sso-stepup="), location


def test_a_sign_in_a_little_ahead_of_the_clock_here_is_a_fresh_one(monkeypatch):
    """The clock here runs behind the provider by less than the skew every token check allows: the sign-in the
    provider just made reads as a few seconds in the future. It is fresh, not stale; a sign-in further ahead than
    the skew was refused before this rule, as the provider clock being ahead."""
    alice, p = _user(sso_only=True), _provider(last_test=TESTED)
    h = Reauth(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    for ahead in (1, 30, 55):
        status, location, _ = _stepped_up_url(h, p, auth_time=int(time.time()) + ahead)
        assert location.startswith("/#sso-stepup="), (ahead, location)


def test_a_provider_never_stands_in_for_a_password_the_account_has_or_for_a_compliance_step(monkeypatch):
    """A fresh sign-in at the provider is the password part only for an account that has no password of its own.
    For an account with a password, for one with the standing of an administrator or an auditor (whatever else
    its row says), and for a compliance action, it is not offered, cannot be started, and a proof staged for it
    all the same is not taken: the step-up asks for the password of the account itself."""
    alice = _user()                                            # linked, with a password it can type
    root = _user("root", role="admin", sso_only=True)          # the standing decides, not the flag
    auditor = _user("auditor", sso_only=True)
    carol = _user("carol", sso_only=True)                      # provider-only: the one account it is for
    p = _provider(last_test=TESTED)
    h = Reauth(monkeypatch, [alice, root, auditor, carol], [p],
               identities=[_identity(u, p, subject=f"s-{u.username}") for u in (alice, root, auditor, carol)])
    from app.core import sso_state
    from app.core.models import AuditorGrant
    h.db.rows_of(AuditorGrant).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=auditor.id, status="active"))

    def refused_everywhere(user, action):
        h.current_user = user
        status, body = _call(h.S, "POST", "/auth/second-factor/challenge", {"action": action})[:2]
        assert status == 200 and "idp_reauth" not in body["methods"] and "password" in body["methods"], (user.username, body)
        status, body = h.start_reauth(p, action=action)
        assert status == 403 and body["detail"]["reason"] == "password_required", (user.username, status, body)
        assert "own password" in body["detail"]["message"]
        assert not [k for k in h.redis.rows if k.startswith("sso:state:")], user.username     # nothing was started
        sso_state.stage_reauth(h.session_hash, action, p.id)   # a proof staged all the same (an older build, a bug)
        status, body = h.step_up(action=action, method="idp_reauth")
        assert status == 403 and "Confirm with your organisation" in body["detail"], (user.username, body)
        assert sso_state.take_reauth(h.session_hash, action) == str(p.id)   # and it was not spent: nothing looked at it
        assert h.step_up(action=action, method="password", password="pw")[0] == 200

    for user in (alice, root, auditor):
        refused_everywhere(user, "admin.retention.write")
        refused_everywhere(user, "admin.auth_policy.write")
    for action in ("compliance.case.request", "compliance.case.approve"):
        refused_everywhere(carol, action)
        refused_everywhere(root, action)
    # What the page reads for Your account: a provider confirms only the account it is for.
    for user, may in ((alice, False), (root, False), (auditor, False), (carol, True)):
        h.current_user = user
        status, body = _call(h.S, "GET", "/users/me/identities")[:2]
        assert status == 200 and [x["reauth"] for x in body["providers"]] == [may], (user.username, body)
    # The account it is for, at an action that is not a compliance one: offered, started, staged and taken.
    h.current_user = carol
    h.receipts.clear()
    status, body = _call(h.S, "POST", "/auth/second-factor/challenge", {"action": "admin.retention.write"})[:2]
    assert body["methods"] == ["idp_reauth", "password"], body
    status, location, _ = _stepped_up_url(h, p, sub="s-carol", auth_time=int(time.time()) - 5)
    assert location.startswith("/#sso-stepup="), location
    assert h.finish_reauth(location)[0] == 200
    assert h.step_up(method="idp_reauth")[0] == 200 and h.receipts == [(str(carol.id), "admin.retention.write", h.session_hash)]
    # A proof made before the account gained a standing is not staged for it afterwards.
    status, location, _ = _stepped_up_url(h, p, sub="s-carol", auth_time=int(time.time()) - 5)
    h.db.rows_of(AuditorGrant).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=carol.id, status="proposed"))
    status, body = h.finish_reauth(location)
    assert status == 403 and body["detail"]["reason"] == "password_required", body
    assert not [k for k in h.redis.rows if k.startswith("sso:reauth:")]


def test_the_staged_proof_never_meets_the_factor_part(monkeypatch):
    alice, p = _user(sso_only=True), _provider(last_test=TESTED)
    h = Reauth(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    S = h.S
    # An action that asks for the factor and the password: the provider meets the password part only.
    monkeypatch.setattr(S, "_sf_requirement_for", lambda db, user, action: ({"otp": True, "password": True, "must_enroll": False}, True))
    from app.core import second_factor as sf
    monkeypatch.setattr(sf, "check_second_factor", lambda db, *, user, action, method, code: method == "totp" and code == "123456")
    from app.core.active_factors import ActiveFactors
    from app.core import active_factors as af
    monkeypatch.setattr(af, "active_factors", lambda db, user_id: ActiveFactors(code_method="totp", passkeys=0))
    status, body = _call(S, "POST", "/auth/second-factor/challenge", {"action": "admin.retention.write"})[:2]
    assert body["methods"] == ["totp", "recovery", "idp_reauth", "password"], body
    status, location, _ = _stepped_up_url(h, p, auth_time=int(time.time()) - 5)
    h.finish_reauth(location)
    # The method alone, with the factor still owed: refused as a code that is not one.
    assert h.step_up(method="idp_reauth")[0] == 403
    # The code for the factor part and the staged proof for the password part: accepted.
    status, body = h.step_up(method="totp", code="123456", password_method="idp_reauth")
    assert status == 200, body
    # Spent: the same again needs the password.
    assert h.step_up(method="totp", code="123456", password_method="idp_reauth")[0] == 403
    assert h.step_up(method="totp", code="123456", password="pw")[0] == 200


def test_the_re_authentication_is_not_offered_where_the_identities_table_is_missing():
    """A database without the identities table (one a test builds with only the tables it needs) offers nothing and
    raises nothing: the step-up route asks before every password step."""
    from _bare_api_env import set_bare_api_env
    set_bare_api_env()
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.services import sso_sign_in as sso
    db = sessionmaker(bind=create_engine("sqlite://"))()
    try:
        assert sso.reauth_available(db, types.SimpleNamespace(id=uuid.uuid4())) is False
    finally:
        db.close()
