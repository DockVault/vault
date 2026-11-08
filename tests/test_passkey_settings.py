"""The passkey settings (app/core/webauthn_settings.py, app/api/sign_in_settings_router.py): the specs on the
Sign-in page, the policy they build, the role requirement with its grace window and the host operator's
clearance, the guards at save (never an administrator among the passwordless roles, a requirement needs the
public address, direct attestation needs anchors, no requirement that leaves no administrator able to sign in),
the write route under the fixed step-up, the algorithm grace, the device-bound rule, and forced enrollment through
the pipeline and the registration routes. Offline."""
import types
import uuid
from datetime import datetime, timedelta

import pytest

from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB
from _webauthn_softauth import FLAG, SoftAuthenticator
from test_passkey_routes import Harness as RouteHarness, _call as _rcall
from test_passkey_sign_in import DB, ORIGIN, _call, _claims, _user

pytestmark = pytest.mark.unit


def _mod():
    set_bare_api_env()
    from app.core import settings_registry as registry
    from app.core import webauthn_settings as ws_settings
    registry.all_specs()        # loads the spec modules
    return registry, ws_settings


def _resolving(monkeypatch, registry, values: dict):
    """The registry answers ``values`` for the keys named, its defaults for the rest."""
    real = registry.resolve
    monkeypatch.setattr(registry, "resolve", lambda key: values[key] if key in values else real(key))


# --------------------------------------------------------------------------- the specs and the policy

def test_the_nine_settings_live_on_the_sign_in_page_with_their_defaults():
    registry, wss = _mod()
    specs = {s.key: s for s in registry.all_specs() if s.group == wss.GROUP}
    assert set(specs) == set(wss.KEYS) and all(s.page == "sign_in" and s.since == "0.36.0" and s.editable == registry.ADMIN
                                              and s.lockable for s in specs.values())
    assert specs[wss.MODE].default == "optional" and specs[wss.GRACE_DAYS].default == 14
    assert specs[wss.SIGN_IN_ROLES].default == ["user", "external"] and specs[wss.SIGN_IN_ROLES].choices == ("user", "external")
    assert specs[wss.REQUIRE_UV].default is True and specs[wss.ALLOWED_ALGS].default == ["ES256", "RS256", "EdDSA"]
    assert specs[wss.ATTESTATION].default == "none" and specs[wss.ALLOWED_AAGUIDS].default == [] and specs[wss.DEVICE_BOUND_ROLES].default == []
    # The registry's own checks: 'admin' never among the passwordless roles, at least one algorithm, UUIDs only.
    assert "may hold only user, external" in registry.check_value(specs[wss.SIGN_IN_ROLES], ["admin"])
    assert registry.check_value(specs[wss.ALLOWED_ALGS], []) and registry.check_value(specs[wss.ALLOWED_ALGS], ["MD5"])
    assert registry.check_value(specs[wss.ALLOWED_AAGUIDS], ["not-a-uuid"]) and registry.check_value(specs[wss.ALLOWED_AAGUIDS], [str(uuid.uuid4())]) is None
    assert "sign_in" in registry.PAGES


def test_the_policy_is_built_from_the_settings(monkeypatch):
    registry, wss = _mod()
    policy = wss.policy()
    assert policy.require_uv is True and policy.allowed_algs == (-7, -257, -8) and policy.attestation == "none"
    _resolving(monkeypatch, registry, {wss.REQUIRE_UV: False, wss.ALLOWED_ALGS: ["RS256"], wss.ATTESTATION: "direct",
                                       wss.ALLOWED_AAGUIDS: ["0" * 32]})
    monkeypatch.setattr(wss, "trust_anchors", lambda: ())
    policy = wss.policy()
    # Direct without anchors falls back to none: the setting cannot be saved that way, and a stale one is harmless.
    assert policy.require_uv is False and policy.allowed_algs == (-257,) and policy.attestation == "none" and policy.allowed_aaguids == ()
    monkeypatch.setattr(wss, "trust_anchors", lambda: (b"der",))
    policy = wss.policy()
    assert policy.attestation == "direct" and policy.allowed_aaguids == ("0" * 32,) and policy.trust_anchors == (b"der",)
    assert wss.enabled() is True
    _resolving(monkeypatch, registry, {wss.MODE: "off"})
    assert wss.enabled() is False


def test_trust_anchors_come_from_the_operators_pem_bundle(monkeypatch, tmp_path):
    registry, wss = _mod()
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime(2020, 1, 1)).not_valid_after(datetime(2040, 1, 1)).sign(key, hashes.SHA256()))
    bundle = tmp_path / "roots.pem"
    bundle.write_bytes(cert.public_bytes(serialization.Encoding.PEM) * 2)
    from app.core.config import settings
    monkeypatch.setattr(settings, "webauthn_attestation_roots", str(bundle), raising=False)
    wss._anchors_cache.update(path=None, mtime=None, anchors=())
    anchors = wss.trust_anchors()
    assert len(anchors) == 2 and anchors[0] == cert.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(settings, "webauthn_attestation_roots", str(tmp_path / "missing.pem"), raising=False)
    assert wss.trust_anchors() == ()
    monkeypatch.setattr(settings, "webauthn_attestation_roots", "", raising=False)
    assert wss.trust_anchors() == ()


# --------------------------------------------------------------------------- the requirement and its grace

def test_the_requirement_follows_the_role_the_keys_and_the_clearance(monkeypatch):
    registry, wss = _mod()
    from app.core.models import SecondFactorEnrollment, WebAuthnCredential
    alice = _user(passkey_required_since=None, passkey_requirement_cleared_at=None)
    db = MemoryDB({SecondFactorEnrollment: [], WebAuthnCredential: []})
    now = datetime(2026, 11, 9, 12, 0, 0)
    assert wss.requirement(db, alice, now=now).required is False                  # optional mode
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["user"], wss.GRACE_DAYS: 14})
    req = wss.requirement(db, alice, now=now)
    assert req.required is True and req.since is None and req.due is None and req.overdue is False
    assert wss.mark_required(alice, now=now) is True and wss.mark_required(alice, now=now) is False
    req = wss.requirement(db, alice, now=now + timedelta(days=13))
    assert req.required and req.due == now + timedelta(days=14) and req.overdue is False
    assert wss.requirement(db, alice, now=now + timedelta(days=14, seconds=1)).overdue is True
    assert wss.requirement_public(req)["due"].startswith("2026-11-23")
    # A passkey ends it; a retired one does not count; another role is not asked; the clearance ends it.
    db.rows_of(WebAuthnCredential).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, retired_at=None))
    assert wss.requirement(db, alice, now=now).required is False
    db.rows_of(WebAuthnCredential)[0].retired_at = now
    assert wss.requirement(db, alice, now=now + timedelta(days=30)).overdue is True
    bob = _user("bob", role="external", passkey_required_since=None, passkey_requirement_cleared_at=None)
    assert wss.requirement(db, bob, now=now).required is False
    alice.passkey_requirement_cleared_at = now
    req = wss.requirement(db, alice, now=now + timedelta(days=30))
    assert req.required is False and req.cleared is True


# --------------------------------------------------------------------------- the guards at save

def test_the_guards_at_save(monkeypatch):
    registry, wss = _mod()
    from app.core.models import RoleEnum, User, WebAuthnCredential
    import app.core.public_url as public_url
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": True})
    monkeypatch.setattr(wss, "trust_anchors", lambda: ())
    root = _user("root", role="admin", passkey_required_since=None, passkey_requirement_cleared_at=None)
    db = MemoryDB({User: [root], WebAuthnCredential: []})
    assert "admin" in wss.save_refusal(db, wss.SIGN_IN_ROLES, ["user", "admin"])
    assert wss.save_refusal(db, wss.SIGN_IN_ROLES, ["user"]) is None
    assert "anchors" in wss.save_refusal(db, wss.ATTESTATION, "direct")
    monkeypatch.setattr(wss, "trust_anchors", lambda: (b"der",))
    assert wss.save_refusal(db, wss.ATTESTATION, "direct") is None
    assert "direct attestation" in wss.save_refusal(db, wss.ALLOWED_AAGUIDS, [str(uuid.uuid4())])
    _resolving(monkeypatch, registry, {wss.ATTESTATION: "direct"})
    assert wss.save_refusal(db, wss.ALLOWED_AAGUIDS, [str(uuid.uuid4())]) is None
    # A requirement needs the public address.
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": False, "rp_id": "10.0.0.5",
                                                      "origin": "https://10.0.0.5", "reason": "ip_address"})
    _resolving(monkeypatch, registry, {wss.REQUIRED_ROLES: ["user"]})
    refused = wss.save_refusal(db, wss.MODE, "required_for_roles")
    assert "public address" in refused and "reached by IP" in refused and "10.0.0.5" not in refused
    assert wss.save_refusal(db, wss.MODE, "optional") is None
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": True})
    # The last-administrator guard: refused only when every administrator's grace has already run out.
    _resolving(monkeypatch, registry, {wss.REQUIRED_ROLES: ["admin"], wss.GRACE_DAYS: 14})
    assert wss.save_refusal(db, wss.MODE, "required_for_roles") is None          # root's grace has not started
    root.passkey_required_since = datetime.utcnow() - timedelta(days=30)
    assert "no administrator" in wss.save_refusal(db, wss.MODE, "required_for_roles")
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["admin"]})
    assert "no administrator" in wss.save_refusal(db, wss.GRACE_DAYS, 7)
    assert wss.save_refusal(db, wss.GRACE_DAYS, 60) is None                      # a longer grace covers root again
    db.rows_of(WebAuthnCredential).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=root.id, retired_at=None))
    assert wss.save_refusal(db, wss.GRACE_DAYS, 7) is None                       # an administrator holds a key
    db.rows_of(WebAuthnCredential).clear()
    root.passkey_requirement_cleared_at = datetime.utcnow()
    assert wss.save_refusal(db, wss.GRACE_DAYS, 7) is None                       # or was cleared by the operator


def test_a_removed_algorithm_keeps_existing_keys_for_thirty_days(monkeypatch):
    registry, wss = _mod()
    from app.core.models import SystemSetting
    db = DB({SystemSetting: []})
    now = datetime(2026, 11, 9, 12, 0, 0)
    assert wss.algorithm_usable(db, -257, now=now) == (True, False)
    wss.record_algorithm_change(db, ["ES256", "RS256", "EdDSA"], ["ES256"], now=now)
    _resolving(monkeypatch, registry, {wss.ALLOWED_ALGS: ["ES256"]})
    assert wss.algorithm_usable(db, -257, now=now + timedelta(days=29)) == (True, True)
    assert wss.algorithm_usable(db, -257, now=now + timedelta(days=31)) == (False, False)
    assert wss.algorithm_usable(db, -7, now=now) == (True, False)
    assert wss.algorithm_usable(db, -999, now=now) == (False, False)
    # Allowed again: the record of its removal is forgotten.
    wss.record_algorithm_change(db, ["ES256"], ["ES256", "RS256"], now=now + timedelta(days=1))
    _resolving(monkeypatch, registry, {wss.ALLOWED_ALGS: ["ES256", "RS256"]})
    assert wss.algorithm_usable(db, -257, now=now + timedelta(days=40)) == (True, False)
    assert wss._removed(db) == {"EdDSA": now.isoformat()}


# --------------------------------------------------------------------------- the write route

def test_the_settings_route_lists_and_writes_under_the_step_up(monkeypatch):
    registry, wss = _mod()
    from app.api import sign_in_settings_router as router
    from app.core import setting_changes
    from app.core.database import get_db
    from app.core.models import User, WebAuthnCredential
    from app.api.user_management_api import require_interactive_admin as uma
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
    monkeypatch.setattr(wss, "trust_anchors", lambda: ())
    monkeypatch.setattr(router, "limit_statements", lambda db, timeout_ms=0: None)
    stepped, requested, refreshed, announced = [], [], [], []
    monkeypatch.setattr(router, "_step_up", lambda db, user, request: stepped.append(user.username))
    monkeypatch.setattr(setting_changes, "request", lambda db, key, value, *, actor, now=None, judge=None: (
        requested.append((key, value, actor.username)) or setting_changes.Outcome("applied", key=key, old=None, new=value)))
    monkeypatch.setattr(setting_changes, "announce_outcome", lambda outcome, by: announced.append((outcome.status, by)))
    monkeypatch.setattr(registry, "refresh", lambda *a, **k: refreshed.append(True) or True)
    recorded = []
    monkeypatch.setattr(wss, "record_algorithm_change", lambda db, old, new, now=None: recorded.append((tuple(old), tuple(new))))
    status, body = _call(S, "GET", "/settings/sign-in")
    assert status == 200 and {s["key"] for s in body["settings"]} == set(wss.KEYS) and body["readiness"]["usable"] is True
    assert body["step_up"] == "admin.auth_policy.write" and body["trust_anchors"] == 0
    # A refusal from the registry, one from the guards, an unknown key: nothing written, no step-up asked.
    assert _call(S, "PUT", "/settings/sign-in/webauthn_sign_in", {"value": ["admin"]})[0] == 400
    assert _call(S, "PUT", "/settings/sign-in/webauthn_attestation", {"value": "direct"})[0] == 400
    assert _call(S, "PUT", "/settings/sign-in/not_a_setting", {"value": 1})[0] == 404
    assert _call(S, "PUT", "/settings/sign-in/log_components", {"value": 1})[0] == 404      # another page's setting
    assert stepped == [] and requested == []
    # A good value: the step-up, the change with its audit row, the refresh, the announcement.
    status, body = _call(S, "PUT", "/settings/sign-in/webauthn_require_uv", {"value": False})
    assert status == 200, body
    assert stepped == ["root"] and requested == [("webauthn_require_uv", False, "root")] and refreshed and announced == [("applied", "root")]
    assert body["status"] == "applied" and body["setting"]["key"] == "webauthn_require_uv"
    # Removing an algorithm is remembered for the 30-day grace.
    status, body = _call(S, "PUT", "/settings/sign-in/webauthn_allowed_algs", {"value": ["ES256"]})
    assert status == 200 and recorded == [(("ES256", "RS256", "EdDSA"), ("ES256",))]
    # Back to the deployment's value is allowed too.
    assert _call(S, "PUT", "/settings/sign-in/webauthn_require_uv", {"value": None})[0] == 200


def test_the_fixed_step_up_for_the_sign_in_settings_exists():
    set_bare_api_env()
    from app.core import second_factor_actions as acts
    assert acts.FIXED_STEP_UP_ACTIONS["admin.auth_policy.write"][1] == "password_always"


# --------------------------------------------------------------------------- forced enrollment through the pipeline and the routes

def test_a_required_role_past_its_grace_is_held_for_a_passkey_enrollment(monkeypatch):
    registry, wss = _mod()
    alice = _user(passkey_required_since=datetime.utcnow() - timedelta(days=20), passkey_requirement_cleared_at=None)
    h = RouteHarness(monkeypatch, alice)
    S = h.S
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["user"], wss.GRACE_DAYS: 14})
    monkeypatch.setattr(S, "_login_second_factor_in_effect", lambda db, user: False)
    monkeypatch.setattr(S, "_second_factor_effective", lambda db, user: {"state": "not_setup", "in_effect": False, "required": False})
    from app.core.models import ActiveSession, PendingLogin
    h.db.tables.setdefault(PendingLogin, [])
    h.db.tables.setdefault(ActiveSession, [])
    from app.services import sign_in
    outcome = sign_in.finish(h.db, sign_in.SignInResult(alice, ["pwd"], "203.0.113.9", session_token="s1"))
    assert isinstance(outcome, sign_in.PendingStep)
    assert outcome.body["enrollment_required"] is True and outcome.body["enrollment_methods"] == ["passkey"]
    assert outcome.body["methods"] == [] and outcome.body["stage"] == "second_factor"
    (pending,) = h.db.rows_of(PendingLogin)
    # Registering under the pre-auth token needs no password (the form had it) and finishes the sign-in.
    monkeypatch.setitem(S.app.dependency_overrides, S.get_enrolling_principal, lambda: (alice, pending))
    status, body = _rcall(S, "POST", "/users/me/passkeys/register/options", {})
    assert status == 200, body
    auth = SoftAuthenticator()
    status, body = _rcall(S, "POST", "/users/me/passkeys/register/verify",
                          {"challenge_id": body["challenge_id"], "credential": auth.make_credential(body["options"], ORIGIN), "label": "k"})
    assert status == 201, body
    assert body["passkey"]["label"] == "k" and "access_token" in body
    claims = _claims(body["access_token"])
    assert claims["amr"] == ["pwd", "hwk"] and "mfa_at" in claims and pending.consumed_at is not None


def test_within_the_grace_the_sign_in_goes_through_and_the_profile_shows_the_date(monkeypatch):
    registry, wss = _mod()
    alice = _user(passkey_required_since=None, passkey_requirement_cleared_at=None)
    h = RouteHarness(monkeypatch, alice)
    S = h.S
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["user"], wss.GRACE_DAYS: 14})
    monkeypatch.setattr(S, "_login_second_factor_in_effect", lambda db, user: False)
    monkeypatch.setattr(S, "_second_factor_effective", lambda db, user: {"state": "not_setup", "in_effect": False, "required": False})
    from app.core.models import ActiveSession, PendingLogin
    h.db.tables.setdefault(PendingLogin, [])
    h.db.tables.setdefault(ActiveSession, [])
    from app.services import sign_in
    outcome = sign_in.finish(h.db, sign_in.SignInResult(alice, ["pwd"], "203.0.113.9"))
    assert isinstance(outcome, sign_in.SignedIn) and alice.passkey_required_since is not None   # the grace started
    status, body = _rcall(S, "GET", "/users/me/passkeys")
    assert status == 200 and body["requirement"]["required"] is True and body["requirement"]["overdue"] is False
    assert body["requirement"]["due"] is not None and body["enabled"] is True
    # Passkeys off: the routes say so, the policy hides the button, nothing is required.
    _resolving(monkeypatch, registry, {wss.MODE: "off"})
    assert _rcall(S, "POST", "/users/me/passkeys/register/options", {"current_password": "pw"})[0] == 409
    assert S._sign_in_methods(h.db)["passkeys"] is False
    assert _rcall(S, "GET", "/users/me/passkeys")[1]["requirement"]["required"] is False


def test_a_device_bound_role_refuses_a_synced_passkey_at_registration(monkeypatch):
    registry, wss = _mod()
    alice = _user()
    h = RouteHarness(monkeypatch, alice)
    _resolving(monkeypatch, registry, {wss.DEVICE_BOUND_ROLES: ["user"]})
    status, body, _auth = h.register(label="synced", flags=FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS)
    assert status == 400 and body["detail"]["reason"] == "synced_not_allowed" and h.rows() == []
    status, body, _auth = h.register(label="bound")
    assert status == 201


def test_the_host_tool_knows_the_clearance():
    set_bare_api_env()
    from app.core import host_operator
    import dockvault
    assert "clear-passkey-requirement" in host_operator.ACTIONS
    assert "clear-passkey-requirement" in dict(dockvault.ACCOUNT_ACTIONS)
