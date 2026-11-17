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
    alice, p = _user(), _provider(last_test=TESTED)
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


def test_the_provider_must_be_linked_and_tested_with_auth_time(monkeypatch):
    alice, p, q = _user(), _provider(last_test=TESTED), _provider(name="untested", last_test={"outcome": "ok", "auth_time_present": False})
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
    ("ahead_within_the_skew", "reauth_stale"),
    ("future", "provider_clock_ahead"),
    ("other_identity", "not_this_account"),
    ("other_tenant", "not_this_account"),
    ("no_mfa_when_trusted", "reauth_no_mfa"),
])
def test_the_callback_accepts_only_a_fresh_sign_in_of_the_accounts_own_identity(monkeypatch, arrange, reason):
    policy = {"sso_trust_idp_mfa": True, "sso_accepted_amr": ["mfa"]} if arrange == "no_mfa_when_trusted" else None
    alice, p = _user(), _provider(last_test=TESTED, policy=policy)
    identity = _identity(alice, p, tenant_id="t1" if arrange == "other_tenant" else None)
    h = Reauth(monkeypatch, [alice], [p], identities=[identity])
    now = int(time.time())
    claims = {"auth_time": now - 5, "tid": "t1" if arrange == "other_tenant" else ...}
    if arrange == "stale":
        claims["auth_time"] = now - 120
    elif arrange == "no_auth_time":
        claims["auth_time"] = ...
    elif arrange == "ahead_within_the_skew":
        claims["auth_time"] = now + 30
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


def test_the_staged_proof_never_meets_the_factor_part(monkeypatch):
    alice, p = _user(), _provider(last_test=TESTED)
    h = Reauth(monkeypatch, [alice], [p], identities=[_identity(alice, p)])
    S = h.S
    # An action that asks for the factor and the password: the provider meets the password part only.
    monkeypatch.setattr(S, "_sf_requirement_for", lambda db, user, action: ({"otp": True, "password": True, "must_enroll": False}, True))
    from app.core import second_factor as sf
    monkeypatch.setattr(sf, "check_second_factor", lambda db, *, user, action, method, code: method == "totp" and code == "123456")
    from app.core.active_factors import ActiveFactors
    from app.core import active_factors as af
    monkeypatch.setattr(af, "active_factors", lambda db, user_id: ActiveFactors(code_method="totp", passkeys=0))
    status, body = _call(S, "POST", "/auth/second-factor/challenge", {"action": "compliance.case.request"})[:2]
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
