"""A passkey as the sign-in's second factor and as a step-up method, through the ASGI app with a software
authenticator: the pending login finished by a passkey (amr pwd + hwk, mfa_at), a wrong assertion counted against
the pending login, the step-up route taking method "passkey" and minting a receipt that remembers the key, a
passkey-only account proving the account.second_factor step-up, the compliance rules on the key (user verification,
not provisional, approved for the auditor's grant), the confirm route refusing a key that vouches for itself, and
the fixed policies knowing a passkey. Offline."""
import time
import types
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from _bare_api_env import set_bare_api_env
from _webauthn_softauth import FLAG, SoftAuthenticator
from test_passkey_sign_in import ORIGIN, Harness as SignInHarness, _call, _claims, _user

pytestmark = pytest.mark.unit


class Harness(SignInHarness):
    """The sign-in harness, plus a signed-in caller and the receipt helpers observed."""

    def __init__(self, monkeypatch, users, **kw):
        super().__init__(monkeypatch, users, **kw)
        S = self.S
        from app.core import second_factor as sf
        self.current_user = users[0]
        monkeypatch.setitem(S.app.dependency_overrides, S.get_current_user, lambda: self.current_user)
        monkeypatch.setattr(S, "_current_session_hash", lambda request: "sess-1")
        self.receipts = {}

        def issue(db, *, user_id, action, session_hash, redis=None, method=""):
            receipt = f"r{len(self.receipts) + 1}"
            self.receipts[receipt] = (str(user_id), action, session_hash, method)
            return receipt

        def consume_detail(db, *, user, action, receipt, session_hash, redis=None):
            row = self.receipts.pop(receipt, None)
            if row is None or row[0] != str(user.id) or row[1] != action or row[2] != session_hash:
                return None
            return row[3]
        monkeypatch.setattr(sf, "issue_step_up_receipt", issue)
        monkeypatch.setattr(sf, "consume_step_up_receipt_detail", consume_detail)
        monkeypatch.setattr(sf, "consume_step_up_receipt",
                            lambda db, *, user, action, receipt, session_hash, redis=None: consume_detail(
                                db, user=user, action=action, receipt=receipt, session_hash=session_hash) is not None)
        from app.core import security
        monkeypatch.setattr(security, "verify_password", lambda plain, hashed: plain == "pw" and hashed == "x")

    def pending_for(self, user, methods=("pwd",), provider=None, provider_mfa=False):
        from app.core.models import PendingLogin
        from app.core.security import create_access_token
        pending = types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, consumed_at=None, attempts=0,
                                        enrollment_required=False,
                                        expires_at=datetime.now(timezone.utc) + timedelta(minutes=3))
        self.db.rows_of(PendingLogin).append(pending)
        claims = {"sub": str(user.id), "username": user.username, "pre_auth": str(pending.id),
                  "stage": "second_factor", "methods_so_far": list(methods)}
        if provider is not None:
            claims["idp"] = provider            # the sign-in came through an identity provider
        if provider_mfa:
            claims["provider_mfa"] = True       # and carried the provider's trusted MFA
        token = create_access_token(claims)
        return pending, {"Authorization": f"Bearer {token}"}

    def step_up_with_passkey(self, auth, action, *, password="pw", flags=FLAG.UP | FLAG.UV, sign_count=3):
        status, body = _call(self.S, "POST", "/auth/passkeys/step-up/options")
        assert status == 200, body
        credential = auth.get_assertion(body["options"], ORIGIN, flags=flags, sign_count=sign_count)
        return _call(self.S, "POST", "/auth/second-factor/step-up",
                     {"action": action, "method": "passkey", "challenge_id": body["challenge_id"],
                      "credential": credential, "password": password})


def _call_h(S, method, path, body=None, headers=None):
    """The sign-in module's caller, with headers."""
    import json
    from _async_run import run_coroutine
    out = {}

    async def _drive():
        hdrs = [(b"content-type", b"application/json")]
        for k, v in (headers or {}).items():
            hdrs.append((k.lower().encode(), v.encode()))
        scope = {"type": "http", "http_version": "1.1", "method": method, "path": path, "raw_path": path.encode(),
                 "query_string": b"", "headers": hdrs, "client": ("203.0.113.9", 1234), "server": ("testserver", 80),
                 "scheme": "https"}
        payload = json.dumps(body).encode() if body is not None else b""
        chunks = []

        async def receive():
            return {"type": "http.request", "body": payload, "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.start":
                out["status"] = msg["status"]
            elif msg["type"] == "http.response.body":
                chunks.append(msg.get("body", b""))

        await S.app(scope, receive, send)
        out["body"] = json.loads(b"".join(chunks) or b"null")

    run_coroutine(_drive(), timeout=30)
    return out["status"], out["body"]


# --------------------------------------------------------------------------- the sign-in's second step

def test_a_passkey_finishes_the_sign_ins_second_step(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    from app.core.models import SecondFactorEnrollment
    h.db.rows_of(SecondFactorEnrollment).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, method="totp", status="active"))
    assert h.S._sf_login_methods(h.db, alice) == ["totp", "recovery", "passkey"]
    pending, headers = h.pending_for(alice)
    # Without the pre-auth token: nothing.
    assert _call_h(h.S, "POST", "/auth/second-factor/passkey/options")[0] in (401, 403)
    status, body = _call_h(h.S, "POST", "/auth/second-factor/passkey/options", None, headers)
    assert status == 200, body
    assert len(body["options"]["publicKey"]["allowCredentials"]) == 1
    credential = auth.get_assertion(body["options"], ORIGIN, sign_count=1)
    status, body = _call_h(h.S, "POST", "/auth/second-factor/passkey/verify",
                           {"challenge_id": body["challenge_id"], "credential": credential}, headers)
    assert status == 200, body
    claims = _claims(body["access_token"])
    assert claims["amr"] == ["pwd", "hwk"] and "mfa_at" in claims and body["recovery_code_used"] is False
    assert pending.consumed_at is not None and row.sign_count == 1 and row.last_used_at is not None
    assert ("success", "alice", ["pwd", "hwk"]) in h.audits


def test_a_wrong_assertion_at_the_second_step_counts_against_the_pending_login(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice, sign_count=5)
    pending, headers = h.pending_for(alice)
    status, body = _call_h(h.S, "POST", "/auth/second-factor/passkey/options", None, headers)
    # A replayed counter.
    credential = auth.get_assertion(body["options"], ORIGIN, sign_count=5)
    status, out = _call_h(h.S, "POST", "/auth/second-factor/passkey/verify",
                          {"challenge_id": body["challenge_id"], "credential": credential}, headers)
    assert status == 401 and pending.attempts == 1 and pending.consumed_at is None
    # Another person's key.
    stranger = SoftAuthenticator()
    stranger.user_handle = alice.id.bytes
    status, body = _call_h(h.S, "POST", "/auth/second-factor/passkey/options", None, headers)
    credential = stranger.get_assertion(body["options"], ORIGIN, sign_count=1)
    status, out = _call_h(h.S, "POST", "/auth/second-factor/passkey/verify",
                          {"challenge_id": body["challenge_id"], "credential": credential}, headers)
    assert status == 401 and pending.attempts == 2
    # A spent challenge.
    status, out = _call_h(h.S, "POST", "/auth/second-factor/passkey/verify",
                          {"challenge_id": body["challenge_id"], "credential": credential}, headers)
    assert status == 400
    # An account without a passkey never gets this step.
    bob = _user("bob")
    h2 = Harness(monkeypatch, [bob])
    pending2, headers2 = h2.pending_for(bob)
    assert _call_h(h2.S, "POST", "/auth/second-factor/passkey/options", None, headers2)[0] == 400


def test_the_second_step_is_refused_with_503_while_its_budget_cannot_count(monkeypatch):
    """The second step met by a passkey is on the second step's own budget, which fails closed: while the limiter
    cannot count, the challenge and the answer are refused with 503, nothing is counted against the pending sign-in
    and it is not spent; once the limiter counts again, the same answer finishes the sign-in."""
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    pending, headers = h.pending_for(alice)
    status, body = _call_h(h.S, "POST", "/auth/second-factor/passkey/options", None, headers)
    assert status == 200, body
    answer = {"challenge_id": body["challenge_id"],
              "credential": auth.get_assertion(body["options"], ORIGIN, sign_count=1)}
    from app.core.rate_limiter import rate_limiter, RateLimiterUnavailable
    counting = rate_limiter.check_rate_limit

    def _down(*a, **kw):
        if kw.get("fail_open", True):
            return True, 1, 0
        raise RateLimiterUnavailable("down")
    monkeypatch.setattr(rate_limiter, "check_rate_limit", _down)
    assert _call_h(h.S, "POST", "/auth/second-factor/passkey/verify", answer, headers) == (
        503, {"detail": "Service temporarily unavailable."})
    status, out = _call_h(h.S, "POST", "/auth/second-factor/passkey/options", None, headers)
    assert status == 503 and "temporarily unavailable" in out["detail"], out
    assert pending.attempts == 0 and pending.consumed_at is None and row.sign_count == 0
    monkeypatch.setattr(rate_limiter, "check_rate_limit", counting)
    status, out = _call_h(h.S, "POST", "/auth/second-factor/passkey/verify", answer, headers)
    assert status == 200, out
    assert pending.consumed_at is not None and row.sign_count == 1


def test_after_a_provider_sign_in_the_passkey_is_the_second_step_also_for_a_provider_only_account(monkeypatch):
    """An account that signs in only through its identity provider holds no usable password; after the provider its
    passkey finishes the second step (the provider proved who the person is), and the token names the provider. Only
    a passkey standing in for the provider is refused for such an account, never this."""
    alice = _user(sso_only=True, password_hash="unusable")
    h = Harness(monkeypatch, [alice])
    # A second factor in effect, so the sign-in table decides the step (a provider then a passkey: done).
    monkeypatch.setattr(h.S, "_login_second_factor_in_effect", lambda db, user: True)
    auth, row = h.enroll(alice)
    pending, headers = h.pending_for(alice, methods=(), provider="provider-1")
    status, body = _call_h(h.S, "POST", "/auth/second-factor/passkey/options", None, headers)
    assert status == 200, body
    credential = auth.get_assertion(body["options"], ORIGIN, sign_count=1)
    status, body = _call_h(h.S, "POST", "/auth/second-factor/passkey/verify",
                           {"challenge_id": body["challenge_id"], "credential": credential}, headers)
    assert status == 200 and body.get("access_token"), body
    claims = _claims(body["access_token"])
    assert claims["amr"] == ["hwk"] and claims["idp"] == "provider-1"
    assert pending.consumed_at is not None and row.sign_count == 1


# --------------------------------------------------------------------------- the step-up

def test_a_passkey_only_account_proves_a_step_up_with_its_passkey(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    status, body = _call(h.S, "POST", "/auth/second-factor/challenge", {"action": "account.second_factor"})
    assert status == 200 and body["methods"] == ["passkey"], body
    status, body = h.step_up_with_passkey(auth, "account.second_factor")
    assert status == 200 and "receipt" in body, body
    receipt = body["receipt"]
    assert h.receipts[receipt] == (str(alice.id), "account.second_factor", "sess-1", f"passkey:{row.id}")
    # The receipt opens the guarded route: the account removes its passkey (nothing requires a factor here).
    status, out = _call_h(h.S, "DELETE", f"/users/me/passkeys/{row.id}", None, {"X-Second-Factor": receipt})
    assert status == 200 and out == {"removed": True}
    # A receipt is spent by one use.
    status, out = _call_h(h.S, "DELETE", f"/users/me/passkeys/{row.id}", None, {"X-Second-Factor": receipt})
    assert status in (403, 404)


def test_a_provider_only_account_proves_the_step_ups_factor_part_with_its_passkey(monkeypatch):
    """The step-up never asks whether the account signs in only through its provider: its passkey proves the factor
    part as anyone's does."""
    alice = _user(sso_only=True, password_hash="unusable")
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    status, body = _call(h.S, "POST", "/auth/second-factor/challenge", {"action": "account.second_factor"})
    assert status == 200 and body["methods"] == ["passkey"], body
    status, body = h.step_up_with_passkey(auth, "account.second_factor")
    assert status == 200 and "receipt" in body, body
    assert h.receipts[body["receipt"]] == (str(alice.id), "account.second_factor", "sess-1", f"passkey:{row.id}")


def test_a_passkey_step_up_is_refused_when_the_assertion_is_wrong_or_the_method_not_offered(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    status, body = h.step_up_with_passkey(auth, "account.second_factor", flags=FLAG.UP)      # no user verification
    assert status == 403 and any(a[0] == "action" and a[1] == "second_factor_failed" for a in h.audits) or status == 403
    # The challenge and the assertion are both needed.
    status, body = _call(h.S, "POST", "/auth/second-factor/step-up", {"action": "account.second_factor", "method": "passkey"})
    assert status == 403
    # An account without a passkey cannot name the method.
    bob = _user("bob")
    h2 = Harness(monkeypatch, [bob])
    status, body = _call(h2.S, "POST", "/auth/second-factor/step-up",
                         {"action": "account.second_factor", "method": "passkey", "challenge_id": "0" * 32, "credential": {}})
    assert status == 403
    assert _call(h2.S, "POST", "/auth/passkeys/step-up/options")[0] == 400


def test_the_compliance_policy_holds_a_passkey_to_its_rules(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    from app.core import auditor_rights
    grant = types.SimpleNamespace(approved_credential_ids=[str(row.id)])
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: grant)
    from app.services import webauthn_service as ws
    # The deployment's policy may not require user verification; the compliance policy does.
    monkeypatch.setattr(h.S, "_passkey_policy", lambda db: ws.PasskeyPolicy(require_uv=False))
    status, body = _call(h.S, "POST", "/auth/second-factor/challenge", {"action": "compliance.case.request"})
    assert status == 200 and body["methods"] == ["passkey", "password"], body
    status, body = h.step_up_with_passkey(auth, "compliance.case.request", flags=FLAG.UP)
    assert status == 403, body
    assert any(a == ("action", "second_factor_failed") for a in h.audits)
    # User-verified, approved: accepted, with the password.
    status, body = h.step_up_with_passkey(auth, "compliance.case.request", sign_count=4)
    assert status == 200, body
    # The wrong password refuses even after a right passkey.
    status, body = h.step_up_with_passkey(auth, "compliance.case.request", password="not-it", sign_count=5)
    assert status == 403
    # A key the grant was not approved with cannot prove the auditor's own actions...
    grant.approved_credential_ids = []
    status, body = h.step_up_with_passkey(auth, "compliance.case.request", sign_count=6)
    assert status == 403 and "approved with" in body["detail"]
    # ...whichever compliance step it is, for anyone who is not an administrator.
    status, body = h.step_up_with_passkey(auth, "compliance.grant.propose", sign_count=7)
    assert status == 403 and "approved with" in body["detail"]
    grant.approved_credential_ids = [str(row.id)]
    # A provisional key never proves a compliance step-up.
    row.provisional_until = datetime(2999, 1, 1)
    status, body = h.step_up_with_passkey(auth, "compliance.grant.propose", sign_count=8)
    assert status == 403 and "until you confirm it" in body["detail"]
    # The other fixed policies take a passkey wherever they take a code.
    row.provisional_until = None
    status, body = h.step_up_with_passkey(auth, "admin.retention.write", sign_count=9)
    assert status == 200, body


def test_a_provisional_passkey_cannot_confirm_itself(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice, provisional=True, label="new")
    older_auth, older = h.enroll(alice, label="old")
    older.created_at = row.created_at - timedelta(days=30)
    # A receipt earned with the provisional key itself: refused.
    status, body = h.step_up_with_passkey(auth, "account.second_factor")
    assert status == 200
    status, out = _call_h(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm", None, {"X-Second-Factor": body["receipt"]})
    assert status == 409 and "older than it" in out["detail"] and row.provisional_until is not None
    # Earned with the older key: accepted.
    status, body = h.step_up_with_passkey(older_auth, "account.second_factor", sign_count=2)
    assert status == 200
    status, out = _call_h(h.S, "POST", f"/users/me/passkeys/{row.id}/confirm", None, {"X-Second-Factor": body["receipt"]})
    assert status == 200 and out["provisional"] is False and row.provisional_until is None
    # Without a receipt: the step-up is asked, with the passkey among the methods.
    other = _user("carol")
    h2 = Harness(monkeypatch, [other])
    _, prow = h2.enroll(other, provisional=True)
    status, out = _call_h(h2.S, "POST", f"/users/me/passkeys/{prow.id}/confirm")
    assert status == 403 and out["detail"]["reason"] == "step_up_required" and out["detail"]["methods"] == ["passkey"]


# --------------------------------------------------------------------------- the contracts underneath

def test_the_receipt_remembers_how_its_factor_part_was_met(monkeypatch):
    set_bare_api_env()
    from app.core import otp_service, second_factor as sf
    issued = {}
    monkeypatch.setattr(otp_service, "issue", lambda db, *, purpose, user_id, destination, ttl_minutes, redis=None: (
        issued.update(purpose=purpose, destination=destination) or "code"))
    sf.issue_step_up_receipt(None, user_id="u", action="a", session_hash="sess")
    assert issued["destination"] == "sess"
    sf.issue_step_up_receipt(None, user_id="u", action="a", session_hash="sess", method="passkey:k1")
    assert issued["destination"] == "sess|passkey:k1" and issued["purpose"] == "stepup:a"
    sf.issue_step_up_receipt(None, user_id="u", action="a", session_hash="sess", method="to|tp")
    assert issued["destination"] == "sess|totp"                       # the separator never rides in a marker
    user = types.SimpleNamespace(id="u")
    answers = {}
    monkeypatch.setattr(otp_service, "verify", lambda db, *, purpose, user_id, code, redis=None: answers[code])
    answers["r1"] = otp_service.OtpResult(True, destination="sess|passkey:k1")
    answers["r2"] = otp_service.OtpResult(True, destination="sess")
    answers["r3"] = otp_service.OtpResult(True, destination="other|totp")
    answers["r4"] = otp_service.OtpResult(False, reason="not_found")
    answers["r5"] = otp_service.OtpResult(True, destination=None)
    detail = lambda code, sess="sess": sf.consume_step_up_receipt_detail(None, user=user, action="a", receipt=code, session_hash=sess)  # noqa: E731
    assert detail("r1") == "passkey:k1" and detail("r2") == "" and detail("r3") is None
    assert detail("r4") is None and detail("r5") is None and detail("") is None and detail("r1", "") is None
    answers["r1"] = otp_service.OtpResult(True, destination="sess|passkey:k1")
    assert sf.consume_step_up_receipt(None, user=user, action="a", receipt="r1", session_hash="sess") is True
    assert sf.consume_step_up_receipt(None, user=user, action="a", receipt="r4", session_hash="sess") is False


def test_the_fixed_policies_know_a_passkey():
    set_bare_api_env()
    from app.core import second_factor_policy as pol
    assert pol.resolve_fixed_requirement(pol.POLICY_COMPLIANCE, active_method=None) == {"password": True, "otp": False, "must_enroll": True}
    assert pol.resolve_fixed_requirement(pol.POLICY_COMPLIANCE, active_method=None, has_passkey=True) == {
        "password": True, "otp": True, "must_enroll": False}
    assert pol.resolve_fixed_requirement(pol.POLICY_COMPLIANCE, active_method="email", has_passkey=False)["must_enroll"] is True
    assert pol.resolve_fixed_requirement(pol.POLICY_PASSWORD_ALWAYS, active_method=None, has_passkey=True) == {
        "password": True, "otp": True, "must_enroll": False}
    assert pol.resolve_fixed_requirement(pol.POLICY_FACTOR_WHEN_ENROLLED, active_method=None, has_passkey=True) == {
        "password": False, "otp": True, "must_enroll": False}
    assert pol.resolve_fixed_requirement(pol.POLICY_FACTOR_WHEN_ENROLLED, active_method=None) == {
        "password": False, "otp": False, "must_enroll": False}
