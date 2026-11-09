"""The passkey settings, held to their rules at every route (app/core/webauthn_settings.py, app/services/sign_in.py,
app/api/api_server.py, app/api/managed_settings_router.py): a requirement past its grace is met by a passkey and
nothing else; the mode off stops passkeys at the sign-in, the second step, the step-ups and the registration while
the rows stay; the passwordless roles; the device-bound rule in a compliance step-up; the algorithm grace at the
route; the enrolling principal; the bounds refused before the step-up; the managed-settings route knowing nothing
of the Sign-in page; direct attestation without anchors refusing registrations. Offline."""
import types
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

    # Every way the table is done without a passkey: the password with a code, a provider's trusted MFA, a provider
    # with the vault's code, a provider alone. Each stops at the passkey enrollment.
    for methods, kw in (
            (["pwd", "totp"], {}), (["pwd", "recovery"], {}),
            ([], {"provider_id": "p", "provider_mfa_trusted": True}),
            (["totp"], {"provider_id": "p"}), ([], {"provider_id": "p"})):
        outcome = finish(alice, methods, **kw)
        assert isinstance(outcome, sign_in.PendingStep), (methods, kw)
        assert outcome.body["enrollment_required"] is True and outcome.body["enrollment_methods"] == ["passkey"], (methods, kw)
        assert outcome.body["stage"] == "second_factor" and outcome.body["access_token"] is None
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
    assert rows and not [r for r in rows if r["key"] in wss.KEYS] and not [r for r in rows if r["page"] == "sign_in"]
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
