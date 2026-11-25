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


@pytest.fixture(autouse=True)
def _the_vault_has_an_address(monkeypatch):
    """A passkey counts only at the address it was made at; these tests are not about the address, so the vault
    has one, and every key here was made at it (or says nothing, which is taken as here)."""
    set_bare_api_env()
    from app.services import webauthn_service as ws
    monkeypatch.setattr(ws, "relying_party", lambda name: ws.RelyingParty(
        rp_id="vault.example.test", origin="https://vault.example.test", name=name or "DockVault"))


def _mod():
    set_bare_api_env()
    from app.core import settings_registry as registry
    from app.core import webauthn_settings as ws_settings
    registry.all_specs()        # loads the spec modules
    return registry, ws_settings


def _resolving(monkeypatch, registry, values: dict):
    """The registry answers ``values`` for the keys named, its defaults for the rest. The vault has an address a
    passkey can be made at, unless the test says otherwise afterwards (a requirement waits without one)."""
    from app.core import webauthn_settings
    real = registry.resolve
    monkeypatch.setattr(registry, "resolve", lambda key: values[key] if key in values else real(key))
    monkeypatch.setattr(webauthn_settings, "passkeys_can_be_made", lambda: True)


# --------------------------------------------------------------------------- the specs and the policy

def test_the_nine_settings_live_on_the_sign_in_page_with_their_defaults():
    registry, wss = _mod()
    specs = {s.key: s for s in registry.all_specs() if s.group == wss.GROUP}
    assert set(specs) == set(wss.KEYS) and all(s.page == "signin" and s.since == "0.36.0" and s.editable == registry.ADMIN
                                              and s.lockable for s in specs.values())
    assert specs[wss.MODE].default == "optional" and specs[wss.GRACE_DAYS].default == 14
    assert specs[wss.SIGN_IN_ROLES].default == ["user", "external"] and specs[wss.SIGN_IN_ROLES].choices == ("user", "external")
    assert specs[wss.REQUIRE_UV].default is True and specs[wss.ALLOWED_ALGS].default == ["ES256", "RS256", "EdDSA"]
    assert specs[wss.ATTESTATION].default == "none" and specs[wss.ALLOWED_AAGUIDS].default == [] and specs[wss.DEVICE_BOUND_ROLES].default == []
    # The registry's own checks: 'admin' never among the passwordless roles, at least one algorithm, UUIDs only.
    assert "may hold only user, external" in registry.check_value(specs[wss.SIGN_IN_ROLES], ["admin"])
    assert registry.check_value(specs[wss.ALLOWED_ALGS], []) and registry.check_value(specs[wss.ALLOWED_ALGS], ["MD5"])
    assert registry.check_value(specs[wss.ALLOWED_AAGUIDS], ["not-a-uuid"]) and registry.check_value(specs[wss.ALLOWED_AAGUIDS], [str(uuid.uuid4())]) is None
    assert "signin" in registry.PAGES


def test_the_policy_is_built_from_the_settings(monkeypatch):
    registry, wss = _mod()
    policy = wss.policy()
    assert policy.require_uv is True and policy.allowed_algs == (-7, -257, -8) and policy.attestation == "none"
    _resolving(monkeypatch, registry, {wss.REQUIRE_UV: False, wss.ALLOWED_ALGS: ["RS256"], wss.ATTESTATION: "direct",
                                       wss.ALLOWED_AAGUIDS: ["0" * 32]})
    monkeypatch.setattr(wss, "trust_anchors", lambda: ())
    policy = wss.policy()
    # Direct without anchors stays direct (the service refuses registrations): a bundle gone after the save never
    # turns attestation off by itself.
    assert policy.require_uv is False and policy.allowed_algs == (-257,) and policy.attestation == "direct"
    assert policy.allowed_aaguids == ("00000000-0000-0000-0000-000000000000",) and policy.trust_anchors == ()
    monkeypatch.setattr(wss, "trust_anchors", lambda: (b"der",))
    policy = wss.policy()
    assert policy.attestation == "direct" and policy.trust_anchors == (b"der",)
    assert policy.allowed_aaguids == ("00000000-0000-0000-0000-000000000000",)
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
    assert wss.trust_anchors_problem() is None
    monkeypatch.setattr(settings, "webauthn_attestation_roots", str(tmp_path / "missing.pem"), raising=False)
    assert wss.trust_anchors() == ()
    monkeypatch.setattr(settings, "webauthn_attestation_roots", "", raising=False)
    assert wss.trust_anchors() == ()


def test_the_reason_no_trust_anchors_were_found_is_told_apart_and_never_names_the_path(monkeypatch, tmp_path):
    """Unset, no file where it points, a file the server cannot read, a file with no PEM certificate in it: each is
    a different thing for the operator to fix, and the refusal of direct attestation says which, with the step
    that makes the server read .env again. The path is never repeated (the text reaches a page and the log)."""
    registry, wss = _mod()
    from app.core.config import settings
    from app.core.models import User, WebAuthnCredential
    import app.core.public_url as public_url

    def problem_with(path):
        monkeypatch.setattr(settings, "webauthn_attestation_roots", path, raising=False)
        wss._anchors_cache.update(path=None, mtime=None, anchors=())
        return wss.trust_anchors_problem()

    assert "WEBAUTHN_ATTESTATION_ROOTS is not set" in problem_with("")
    missing = str(tmp_path / "gone-roots.pem")
    said = problem_with(missing)
    assert "finds no file" in said and "gone-roots" not in said
    garbage = tmp_path / "garbage-roots.pem"
    garbage.write_bytes(b"not a certificate")
    said = problem_with(str(garbage))
    assert "holds no PEM certificate" in said and "garbage-roots" not in said
    assert wss.trust_anchors() == ()
    # A file that is there and cannot be opened (a root-owned file the app's user cannot read).
    locked = tmp_path / "locked-roots.pem"
    locked.write_bytes(b"whatever")

    def refusing(file, *args, **kwargs):
        raise PermissionError(13, "Permission denied", str(file))
    monkeypatch.setattr(wss, "open", refusing, raising=False)
    said = problem_with(str(locked))
    monkeypatch.delattr(wss, "open")
    assert "cannot read the file" in said and "locked-roots" not in said
    # The refusal names the cause and the step that makes the server read .env again.
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": True})
    problem_with(missing)
    refused = wss.save_refusal(MemoryDB({User: [], WebAuthnCredential: []}), wss.ATTESTATION, "direct")
    assert refused.startswith("Direct attestation needs trust anchors, and the server finds no file"), refused
    assert "python dockvault.py restart" in refused and ", restart, and try again" not in refused
    assert "gone-roots" not in refused


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
    key = types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, uv_initialized=True, retired_at=None, cose_alg=-7)
    db.rows_of(WebAuthnCredential).append(key)
    assert wss.requirement(db, alice, now=now).required is False
    assert wss.usable_passkeys(db, alice.id) == 1 and wss.usable_passkeys(db, alice.id, without=key.id) == 0
    # A key of an algorithm an administrator removed (its 30 days over) is refused at every use: the account
    # holds it in name only, and the requirement is not met by it.
    usable = wss.algorithm_usable
    monkeypatch.setattr(wss, "algorithm_usable", lambda db_, alg, now=None: (alg != -7, False))
    assert wss.usable_passkeys(db, alice.id) == 0 and wss.requirement(db, alice, now=now).required is True
    monkeypatch.setattr(wss, "algorithm_usable", usable)
    assert wss.requirement(db, alice, now=now).required is False
    monkeypatch.setattr(wss, "enabled", lambda: False)             # passkeys switched off: none is usable
    assert wss.usable_passkeys(db, alice.id) == 0
    monkeypatch.undo()
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["user"], wss.GRACE_DAYS: 14})
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
    db.rows_of(WebAuthnCredential).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=root.id, uv_initialized=True, retired_at=None, cose_alg=-7))
    assert wss.save_refusal(db, wss.GRACE_DAYS, 7) is None                       # an administrator holds a key
    # ...one whose algorithm still signs in: a key of an algorithm removed for good protects nobody.
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["admin"], wss.ALLOWED_ALGS: ["RS256"]})
    assert "no administrator" in wss.save_refusal(db, wss.GRACE_DAYS, 7)
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["admin"]})
    db.rows_of(WebAuthnCredential).clear()
    # ...and made at the address the vault has now: a key made at another address is never offered by the browser
    # here, and protects nobody. The same key counts again once the vault is back at its address.
    from app.services import webauthn_service as ws
    elsewhere = types.SimpleNamespace(id=uuid.uuid4(), user_id=root.id, uv_initialized=True, retired_at=None, cose_alg=-7,
                                      rp_id="old.example.test")
    db.rows_of(WebAuthnCredential).append(elsewhere)
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["admin"],
                                       wss.ALLOWED_ALGS: ["ES256"]})
    assert wss.algorithm_usable(db, -7)[0] is True                              # the key's algorithm signs in
    monkeypatch.setattr(ws, "relying_party", lambda name: ws.RelyingParty(
        rp_id="new.example.test", origin="https://new.example.test", name="DockVault"))
    assert wss.usable_passkeys(db, root.id, whatever_the_switch=True) == 0
    assert "no administrator" in wss.save_refusal(db, wss.GRACE_DAYS, 7)
    monkeypatch.setattr(ws, "relying_party", lambda name: ws.RelyingParty(
        rp_id="old.example.test", origin="https://old.example.test", name="DockVault"))
    assert wss.usable_passkeys(db, root.id, whatever_the_switch=True) == 1
    assert wss.save_refusal(db, wss.GRACE_DAYS, 7) is None
    # Asked while passkeys are switched off, about turning the requirement on: the key an administrator holds
    # counts, as it will the moment they are on.
    _resolving(monkeypatch, registry, {wss.MODE: "off", wss.REQUIRED_ROLES: ["admin"], wss.ALLOWED_ALGS: ["ES256"],
                                       wss.GRACE_DAYS: 7})
    assert wss.usable_passkeys(db, root.id) == 0
    assert wss.save_refusal(db, wss.MODE, "required_for_roles") is None
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["admin"]})
    db.rows_of(WebAuthnCredential).clear()
    # An administrator who cannot sign in (locked by an administrator) protects nobody either.
    bob = _user("bob", role="admin", passkey_required_since=None, passkey_requirement_cleared_at=None, is_locked=True,
                locked_until=None)
    db.rows_of(User).append(bob)
    # (The grace in force here is 7 days: a shorter one is what asks for more.)
    assert "no administrator" in wss.save_refusal(db, wss.GRACE_DAYS, 6)        # bob's unstarted grace does not count
    bob.is_locked = False
    assert wss.save_refusal(db, wss.GRACE_DAYS, 6) is None
    db.rows_of(User).remove(bob)
    root.passkey_requirement_cleared_at = datetime.utcnow()
    assert wss.save_refusal(db, wss.GRACE_DAYS, 6) is None                       # or was cleared by the operator


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
    # Until when a key of it is accepted, while the days run: shown beside the key.
    assert wss.algorithm_accepted_until(db, -257, now=now) == now + timedelta(days=30)
    assert wss.algorithm_accepted_until(db, -257, now=now + timedelta(days=29, hours=23)) == now + timedelta(days=30)
    assert wss.algorithm_accepted_until(db, -257, now=now + timedelta(days=30)) is None        # over: refused already
    assert wss.algorithm_accepted_until(db, -7, now=now) is None                              # allowed: no end
    assert wss.algorithm_accepted_until(db, -999, now=now) is None
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
    assert "WEBAUTHN_ATTESTATION_ROOTS is not set" in body["trust_anchors_problem"]
    assert body["why_not"] == ""                          # a passkey can be made here: nothing to change
    assert body["requirement_paused"] is False
    # A requirement saved while the address worked, and the address gone since: the page is told that it waits.
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["user"]})
    assert _call(S, "GET", "/settings/sign-in")[1]["requirement_paused"] is False
    monkeypatch.setattr(wss, "passkeys_can_be_made", lambda: False)
    assert _call(S, "GET", "/settings/sign-in")[1]["requirement_paused"] is True
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: []})
    monkeypatch.setattr(wss, "passkeys_can_be_made", lambda: False)
    assert _call(S, "GET", "/settings/sign-in")[1]["requirement_paused"] is False      # no role is named
    _resolving(monkeypatch, registry, {wss.MODE: "optional", wss.REQUIRED_ROLES: ["user"]})
    monkeypatch.setattr(wss, "passkeys_can_be_made", lambda: False)
    assert _call(S, "GET", "/settings/sign-in")[1]["requirement_paused"] is False      # nothing is required
    _resolving(monkeypatch, registry, {})
    # A refusal from the registry, one from the guards, an unknown key: nothing written, no step-up asked.
    assert _call(S, "PUT", "/settings/sign-in/webauthn_sign_in", {"value": ["admin"]})[0] == 400
    assert _call(S, "PUT", "/settings/sign-in/webauthn_attestation", {"value": "direct"})[0] == 400
    assert _call(S, "PUT", "/settings/sign-in/not_a_setting", {"value": 1})[0] == 404
    assert _call(S, "PUT", "/settings/sign-in/audit_max_days", {"value": 400})[0] == 404     # another page's setting
    assert stepped == [] and requested == []
    # A good value: the step-up, the change with its audit row, the refresh, the announcement.
    status, body = _call(S, "PUT", "/settings/sign-in/webauthn_require_uv", {"value": False})
    assert status == 200, body
    assert stepped == ["root"] and requested == [("webauthn_require_uv", False, "root")] and refreshed and announced == [("applied", "root")]
    assert body["status"] == "applied" and body["setting"]["key"] == "webauthn_require_uv"
    # Removing an algorithm is remembered for the 30-day grace, and the owners of keys of it are told at once.
    told = []
    monkeypatch.setattr(router, "_tell_the_owners_of_keys_of_a_removed_algorithm",
                        lambda db, removed: told.append(sorted(removed)))
    status, body = _call(S, "PUT", "/settings/sign-in/webauthn_allowed_algs", {"value": ["ES256"]})
    assert status == 200 and recorded == [(("ES256", "RS256", "EdDSA"), ("ES256",))]
    assert told == [["EdDSA", "RS256"]]
    # Adding one back, or saving the list as it is, removes none: nobody is told.
    del told[:]
    status, body = _call(S, "PUT", "/settings/sign-in/webauthn_allowed_algs", {"value": ["ES256", "RS256", "EdDSA"]})
    assert status == 200 and told == []
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
    sign_in.read_pre_auth(_claims(outcome.body["pre_auth_token"]), pending)      # as the token's reader does
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


def test_the_settings_routes_name_the_setting_and_no_path_parameter_reads_as_a_secret():
    """A path parameter named key, token, code, secret or claim is taken to hold a secret and must be masked in
    every log. These routes name a setting, which is no secret, so the parameter is not named as one."""
    from app.api import sign_in_settings_router
    paths = sorted({route.path for route in sign_in_settings_router.router.routes})
    assert paths == ["/settings/sign-in", "/settings/sign-in/{setting}"]


def test_a_save_that_asks_for_less_is_never_held_back_by_what_the_other_settings_need(monkeypatch):
    """Direct attestation is on with a list of makes, a role must hold a passkey, and then the file of root
    certificates is gone (a restore on a new host: the file is not in the backup) and the vault's address no
    longer carries a passkey. Every registration fails, as designed. The page must still lead back out: each
    save that asks for less goes through, and each that asks for more is refused as before."""
    registry, wss = _mod()
    from app.core import public_url
    from app.core.models import User, WebAuthnCredential
    root = _user("root", role="admin", passkey_required_since=datetime.utcnow() - timedelta(days=90),
                 passkey_requirement_cleared_at=None)
    db = MemoryDB({User: [root], WebAuthnCredential: []})
    make, other = str(uuid.uuid4()), str(uuid.uuid4())
    stuck = {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["user", "admin"], wss.GRACE_DAYS: 14,
             wss.ATTESTATION: "direct", wss.ALLOWED_AAGUIDS: [make], wss.REQUIRE_UV: True}
    _resolving(monkeypatch, registry, stuck)
    monkeypatch.setattr(wss, "trust_anchors", lambda: ())
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": False, "reason": "ip_address"})
    # The ways out, in any order.
    for key, value in ((wss.MODE, "off"), (wss.MODE, "optional"), (wss.MODE, None), (wss.ATTESTATION, "none"),
                       (wss.ATTESTATION, None), (wss.ALLOWED_AAGUIDS, []), (wss.ALLOWED_AAGUIDS, None),
                       (wss.REQUIRED_ROLES, ["admin"]), (wss.REQUIRED_ROLES, []), (wss.GRACE_DAYS, 60),
                       (wss.REQUIRE_UV, False), (wss.SIGN_IN_ROLES, ["user"]), (wss.ALLOWED_ALGS, ["ES256"]),
                       # ...and a save of what is in force already.
                       (wss.MODE, "required_for_roles"), (wss.ATTESTATION, "direct"), (wss.ALLOWED_AAGUIDS, [make]),
                       (wss.REQUIRED_ROLES, ["admin", "user"]), (wss.GRACE_DAYS, 14), (wss.REQUIRE_UV, True)):
        assert wss.save_refusal(db, key, value) is None, (key, value)
    # What asks for more is refused, each for its own reason.
    assert "anchors" in wss.save_refusal(db, wss.ALLOWED_AAGUIDS, [make, other])
    assert "public address" in wss.save_refusal(db, wss.REQUIRED_ROLES, ["user", "admin", "external"])
    assert "no administrator" in wss.save_refusal(db, wss.GRACE_DAYS, 7)
    assert "'admin' cannot be in this list" in wss.save_refusal(db, wss.SIGN_IN_ROLES, ["admin"])
    # Walked back: attestation none, then the makes list is left alone and applies to nothing; turning direct
    # attestation on again, or adding a make without it, is refused.
    _resolving(monkeypatch, registry, dict(stuck, **{wss.ATTESTATION: "none"}))
    assert wss.policy().allowed_aaguids == () and wss.policy().attestation == "none"
    assert "anchors" in wss.save_refusal(db, wss.ATTESTATION, "direct")
    assert "direct attestation" in wss.save_refusal(db, wss.ALLOWED_AAGUIDS, [make, other])
    assert wss.save_refusal(db, wss.ALLOWED_AAGUIDS, []) is None
    # The list that is kept is asked about only when it is the thing saved: another save meets its own reason.
    assert "no administrator" in wss.save_refusal(db, wss.GRACE_DAYS, 7)
    # Passkeys off, then on again as a requirement: asked for the address once more.
    _resolving(monkeypatch, registry, dict(stuck, **{wss.MODE: "off", wss.ATTESTATION: "none"}))
    assert "public address" in wss.save_refusal(db, wss.MODE, "required_for_roles")
    assert wss.save_refusal(db, wss.MODE, "optional") is None


def test_what_a_save_asks_for_beyond_what_is_in_force(monkeypatch):
    registry, wss = _mod()
    more, a, b = wss.asks_for_more, "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
    assert more(wss.MODE, "optional", "required_for_roles") and more(wss.MODE, "off", "required_for_roles")
    assert not more(wss.MODE, "required_for_roles", "required_for_roles") and not more(wss.MODE, "off", "optional")
    assert not more(wss.MODE, "required_for_roles", "off")
    assert more(wss.REQUIRED_ROLES, ["user"], ["user", "admin"]) and more(wss.REQUIRED_ROLES, None, ["user"])
    assert not more(wss.REQUIRED_ROLES, ["user", "admin"], ["admin"]) and not more(wss.REQUIRED_ROLES, ["user"], [])
    assert more(wss.REQUIRED_ROLES, ["user"], ["admin"])                          # one out, another in
    assert more(wss.GRACE_DAYS, 14, 13) and not more(wss.GRACE_DAYS, 14, 14) and not more(wss.GRACE_DAYS, 14, 15)
    assert more(wss.REQUIRE_UV, False, True) and not more(wss.REQUIRE_UV, True, True)
    assert not more(wss.REQUIRE_UV, True, False)
    assert more(wss.ATTESTATION, "none", "direct") and not more(wss.ATTESTATION, "direct", "direct")
    assert not more(wss.ATTESTATION, "direct", "none")
    assert more(wss.ALLOWED_AAGUIDS, [a], [a, b]) and not more(wss.ALLOWED_AAGUIDS, [a, b], [b])
    assert not more(wss.ALLOWED_AAGUIDS, [a], [])
    for key in (wss.SIGN_IN_ROLES, wss.ALLOWED_ALGS, wss.DEVICE_BOUND_ROLES):
        assert not more(key, ["user"], ["user", "external"])
    # A role added beside administrators asks nothing new of them: their grace having run out stops no such save.
    from app.core import public_url
    from app.core.models import User, WebAuthnCredential
    root = _user("root", role="admin", passkey_required_since=datetime.utcnow() - timedelta(days=90),
                 passkey_requirement_cleared_at=None)
    db = MemoryDB({User: [root], WebAuthnCredential: []})
    monkeypatch.setattr(public_url, "readiness", lambda: {"usable": True})
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["admin"]})
    assert wss.save_refusal(db, wss.REQUIRED_ROLES, ["admin", "user"]) is None
    # ...and administrators added to a requirement that stands is asked whether one of them can meet it.
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["user"]})
    assert "no administrator" in wss.save_refusal(db, wss.REQUIRED_ROLES, ["user", "admin"])


def test_a_make_saved_in_another_spelling_of_its_uuid_is_that_make(monkeypatch):
    """An administrator pastes an authenticator make as a tool printed it: 32 hex digits, in braces, as a urn, in
    capitals. Each is a UUID and the save takes it. The makes of the keys are compared as text, lower case with
    dashes: saved otherwise, the make matched no authenticator, every registration of it was refused and its keys
    stopped proving compliance step-ups. Read back, a make is in the one spelling, and once."""
    registry, wss = _mod()
    specs = {s.key: s for s in registry.all_specs() if s.group == wss.GROUP}
    make = "cb69481e-8ff7-4039-93ec-0a2729a154a8"
    spellings = ["cb69481e8ff7403993ec0a2729a154a8", "{cb69481e-8ff7-4039-93ec-0a2729a154a8}",
                 "urn:uuid:cb69481e-8ff7-4039-93ec-0a2729a154a8", "CB69481E-8FF7-4039-93EC-0A2729A154A8", make]
    for spelled in spellings:
        assert wss.canonical_aaguid(spelled) == make, spelled
        assert registry.check_value(specs[wss.ALLOWED_AAGUIDS], [spelled]) is None, spelled     # the save takes it
    assert wss.canonical_aaguid("  " + make + "  ") == make
    for nothing in (None, "", "not-a-uuid", 7, [], "cb69481e"):
        assert wss.canonical_aaguid(nothing) is None, nothing
    other = "2fc0579f-8113-47ea-b116-bb5a8db9202a"
    _resolving(monkeypatch, registry, {wss.ALLOWED_AAGUIDS: spellings + [other.upper()]})
    assert wss.allowed_aaguids() == (make, other)
    # What the ceremony compares a key's make against is what the setting gives: the one spelling.
    from _bare_api_env import set_bare_api_env
    set_bare_api_env()
    from app.services import webauthn_service as ws
    assert str(ws._aaguid(uuid.UUID(make).bytes)) == make
    assert str(ws._aaguid(uuid.UUID(make).bytes)) in {a.lower() for a in wss.allowed_aaguids()}


def test_a_list_of_makes_with_nothing_readable_in_it_allows_no_make(monkeypatch):
    """The deployment gives the list of makes with a typing error in every entry. The save through the panel
    refuses such an entry; a value the deployment gave was never held to that. An entry that is no UUID matches
    no authenticator, so the list allowed none. Read back without such entries, the list was empty, an empty
    list is no restriction, and every make was allowed where the deployment had meant to allow two."""
    registry, wss = _mod()
    make = "cb69481e-8ff7-4039-93ec-0a2729a154a8"
    monkeypatch.setattr(wss, "trust_anchors", lambda: (b"der",))
    _resolving(monkeypatch, registry, {wss.ATTESTATION: "direct",
                                       wss.ALLOWED_AAGUIDS: ["cb69481e-8ff7-4039-93ec", "", "yubikey 5"]})
    assert wss.allowed_aaguids() == ("cb69481e-8ff7-4039-93ec", "", "yubikey 5")
    # What the ceremony reads: a list (so the restriction applies) that holds no make of any authenticator.
    assert wss.policy().allowed_aaguids and make not in {a.lower() for a in wss.policy().allowed_aaguids}
    # Beside makes that can be read, such an entry changes nothing: it is kept, once, and matches nothing.
    _resolving(monkeypatch, registry, {wss.ALLOWED_AAGUIDS: ["not-a-uuid", make.upper(), "not-a-uuid"]})
    assert wss.allowed_aaguids() == ("not-a-uuid", make)
    # No list is no restriction, as it always was.
    _resolving(monkeypatch, registry, {wss.ALLOWED_AAGUIDS: []})
    assert wss.allowed_aaguids() == ()


def test_the_owners_of_keys_of_a_removed_algorithm_are_told_when_it_is_removed(monkeypatch):
    """The setting promised a notice to the owners of keys of a removed algorithm. It was sent only where such a
    key was used within its 30 days: an owner who signed in with a password and an authenticator code meanwhile
    met the refusal on the day after with no word before it. Each owner is told at the removal, once, with the
    day the key stops; an owner of no such key, and of a retired one, is not."""
    registry, wss = _mod()
    set_bare_api_env()
    from app.api import api_server as S
    from app.api import sign_in_settings_router as router
    from app.core.models import WebAuthnCredential
    ann, ben, cy, dee = (uuid.uuid4() for _ in range(4))
    keys = [types.SimpleNamespace(user_id=owner, cose_alg=alg, retired_at=retired) for owner, alg, retired in (
        (ann, -257, None), (ann, -257, None), (ann, -7, None),          # two keys of the removed algorithm: told once
        (ben, -8, None), (cy, -7, None), (dee, -257, datetime(2026, 11, 1)))]
    db = DB({WebAuthnCredential: keys})
    assert wss.owners_of_keys_of(db, ["RS256"]) == [ann]
    assert wss.owners_of_keys_of(db, ["RS256", "EdDSA"]) == [ann, ben]
    assert wss.owners_of_keys_of(db, []) == [] and wss.owners_of_keys_of(db, ["not-an-algorithm"]) == []
    notices = []
    monkeypatch.setattr(S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None: (
        notices.append((list(ids), ntype, title, body, dedup_prefix)) or list(ids)))
    router._tell_the_owners_of_keys_of_a_removed_algorithm(db, ["RS256"])
    (ids, kind, title, said, dedup), = notices
    until = (datetime.utcnow() + timedelta(days=30)).date().isoformat()
    assert ids == [str(ann)] and kind == "security" and title == "One of your passkeys needs replacing"
    assert f"That passkey still works until {until}; register a new passkey before then." in said
    assert dedup == f"passkey_alg_removed:RS256:{until}"
    # Nobody holds such a key: nobody is told. And a failure to tell undoes nothing.
    del notices[:]
    router._tell_the_owners_of_keys_of_a_removed_algorithm(DB({WebAuthnCredential: []}), ["RS256"])
    assert notices == []

    def broken(*a, **k):
        raise RuntimeError("down")
    monkeypatch.setattr(S, "_notify_users", broken)
    router._tell_the_owners_of_keys_of_a_removed_algorithm(db, ["RS256"])            # logged, not raised
