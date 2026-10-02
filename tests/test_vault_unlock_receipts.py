"""Unlocking a password-protected vault's names on the Activity page, offline (app/core/vault_unlock_receipts.py,
app/api/activity_unlock_router.py, app/services/activity_names.py).

A receipt is good for 15 minutes for exactly the purpose, session, case, vault and account it was given for, and
only while the vault's password is the one it was given under; nothing is stored. The password is checked once,
on the throttle every other check of that vault's password by that account counts in. With a receipt the page
shows the vault's items as the recording levels recorded them, and never for a zero-knowledge vault.
"""
import hashlib
import hmac
import struct
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import activity_unlock_router as routes  # noqa: E402
from app.core import audit_privacy as ap  # noqa: E402
from app.core import vault_unlock_receipts as vr  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import AuditLog, RoleEnum, User, Vault  # noqa: E402
from app.core.security import _runtime_settings, hash_password  # noqa: E402
from app.services import activity_names  # noqa: E402

pytestmark = pytest.mark.unit

_runtime_settings()

NOW = datetime(2026, 10, 2, 12, 0, 0)
VAULT, OTHER_VAULT, ADA, BOB, CASE = (uuid.uuid4() for _ in range(5))
CRED = vr.credential_digest("argon2-hash-of-the-password")
SECRET = "Vault-Secret-1"          # the throwaway vaults' password in these tests


def _issue(**kw):
    args = dict(purpose=vr.PURPOSE_ACTIVITY, session_hash="session-a", vault_id=VAULT, user_id=ADA, credential=CRED,
                now=NOW)
    args.update(kw)
    return vr.issue(**args)


def _verify(receipt, **kw):
    args = dict(purpose=vr.PURPOSE_ACTIVITY, session_hash="session-a", vault_id=VAULT, user_id=ADA, credential=CRED,
                now=NOW + timedelta(minutes=1))
    args.update(kw)
    return vr.verify(receipt, **args)


# --------------------------------------------------------------------------- the receipt

def test_a_receipt_serves_its_own_bindings_for_fifteen_minutes():
    receipt, expires = _issue()
    assert expires == NOW + timedelta(minutes=15) and receipt.startswith("dvr1.")
    assert _verify(receipt)
    assert _verify(receipt, now=NOW + timedelta(minutes=14, seconds=59))
    assert not _verify(receipt, now=NOW + timedelta(minutes=15))


@pytest.mark.parametrize("change", [
    {"session_hash": "session-b"}, {"vault_id": OTHER_VAULT}, {"user_id": BOB}, {"purpose": vr.PURPOSE_CASE},
    {"case_id": CASE}, {"credential": vr.credential_digest("a new hash after a password change")},
    {"credential": None}, {"session_hash": None}, {"session_hash": ""}])
def test_a_receipt_serves_nothing_else(change):
    receipt, _ = _issue()
    assert not _verify(receipt, **change)


def test_a_case_receipt_is_bound_to_its_case_and_no_other_and_never_serves_the_activity_page():
    receipt, _ = _issue(purpose=vr.PURPOSE_CASE, case_id=CASE)
    assert _verify(receipt, purpose=vr.PURPOSE_CASE, case_id=CASE)
    assert not _verify(receipt, purpose=vr.PURPOSE_CASE, case_id=uuid.uuid4())
    assert not _verify(receipt, purpose=vr.PURPOSE_ACTIVITY)


def test_a_vault_with_no_password_and_one_with_a_password_never_share_a_receipt():
    receipt, _ = _issue(credential=None)
    assert _verify(receipt, credential=None)
    assert not _verify(receipt)


@pytest.mark.parametrize("bad", ["", "dvr1", "dvr1.x.y", "dvr2.AAAAAAAAAAA.AAAA", "dvr1.AAAAAAAAAAA.AAAA.extra",
                                 None, 5])
def test_anything_malformed_is_not_a_receipt(bad):
    assert vr.verify(bad, purpose=vr.PURPOSE_ACTIVITY, session_hash="s", vault_id=VAULT, user_id=ADA,
                     credential=CRED) is False


def test_a_changed_expiry_or_mac_or_prefix_is_refused():
    receipt, _ = _issue()
    prefix, stamp, mac = receipt.split(".")
    assert not _verify(f"dvr2.{stamp}.{mac}")
    later = vr._b64(struct.pack(">q", vr._micros(NOW + timedelta(minutes=14))))
    assert not _verify(f"{prefix}.{later}.{mac}")
    flipped = vr._b64(bytes([vr._unb64(mac)[0] ^ 1]) + vr._unb64(mac)[1:])
    assert not _verify(f"{prefix}.{stamp}.{flipped}")


def test_a_receipt_needs_a_session():
    with pytest.raises(ValueError):
        _issue(session_hash="")


def test_the_encoding_is_tagged_and_length_prefixed():
    assert vr._e_null() == b"\x00"
    assert vr._e_text("ab") == b"\x01\x00\x00\x00\x02ab"
    assert vr._e_bytes(b"\x07") == b"\x02\x00\x00\x00\x01\x07"
    assert vr._e_uuid(VAULT) == b"\x04" + VAULT.bytes
    assert vr._e_timestamp(datetime(1970, 1, 1, 0, 0, 1)) == b"\x05" + struct.pack(">q", 1_000_000)
    assert vr._e_timestamp(datetime(1970, 1, 1, 1, 0, 1, tzinfo=timezone(timedelta(hours=1)))) == (
        b"\x05" + struct.pack(">q", 1_000_000))
    # Moving a byte from the session to the purpose cannot give the same input.
    one = vr._e_text("ab") + vr._e_text("c")
    two = vr._e_text("a") + vr._e_text("bc")
    assert one != two


def test_the_mac_key_is_derived_for_this_purpose_alone():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"dockvault-vault-unlock-receipt-v1",
               info=b"vault-unlock-receipt").derive(settings.encryption_key.encode())
    assert vr._key() == key and key != settings.encryption_key.encode()[:32]
    receipt, _ = _issue()
    message = (b"dvunlock-receipt-v1\x00" + vr._e_text("activity") + vr._e_text("session-a") + vr._e_null()
               + vr._e_uuid(VAULT) + vr._e_uuid(ADA) + vr._e_timestamp(NOW + timedelta(minutes=15)) + vr._e_bytes(CRED))
    assert vr._unb64(receipt.split(".")[2]) == hmac.new(key, message, hashlib.sha256).digest()


def test_the_credential_digest_is_the_password_hashs():
    assert vr.credential_digest("h") == hashlib.sha256(b"h").digest()
    assert vr.credential_digest(None) is None and vr.credential_digest("") is None


# --------------------------------------------------------------------------- the password, on the shared throttle

@pytest.fixture
def throttle(monkeypatch):
    from app.core import vault_attempt_throttle
    seen = {"burned": [], "over": False}
    monkeypatch.setattr(vault_attempt_throttle, "over_limit", lambda key, limit, window: seen["over"])
    monkeypatch.setattr(vault_attempt_throttle, "burn", lambda key, window: seen["burned"].append(key))
    return seen


def test_a_wrong_password_counts_on_the_vaults_own_throttle(throttle):
    user = SimpleNamespace(id=ADA, role=RoleEnum.ADMIN)
    vault = SimpleNamespace(id=VAULT, password_hash=hash_password("the-right-one"))
    with pytest.raises(vr.UnlockRefused) as refused:
        vr.check_password(user, vault, "a-wrong-one")
    assert refused.value.status == 403 and throttle["burned"] == [f"rate_limit:vault:{VAULT}:{ADA}"]
    vr.check_password(user, vault, "the-right-one")
    assert len(throttle["burned"]) == 1
    throttle["over"] = True
    with pytest.raises(vr.UnlockRefused) as refused:
        vr.check_password(user, vault, "the-right-one")
    assert refused.value.status == 429


def test_the_throttle_is_the_one_the_vault_gate_counts_in():
    import inspect
    from app.services import vault_service
    gate = inspect.getsource(vault_service.VaultService.get_vault)
    assert 'rate_key = f"rate_limit:vault:{vault_id}:{user.id}"' in gate
    assert vr.throttle_key("V", "U") == "rate_limit:vault:V:U"


# --------------------------------------------------------------------------- the route

@pytest.fixture
def db(monkeypatch):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'unlock.db'}")
        for model in (User, AuditLog, Vault):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture
def world(db, monkeypatch, throttle):
    admin = User(id=uuid.uuid4(), username="ada", email="ada@example.com", password_hash="x", role=RoleEnum.ADMIN,
                 is_active=True)
    db.add(admin)
    db.flush()
    vaults = {}
    for name, kind, password in (("pw", "standard", SECRET), ("open", "standard", None),
                                 ("zk", "zero_knowledge", None), ("zkpw", "zero_knowledge", SECRET)):
        v = Vault(id=uuid.uuid4(), name=name, owner_id=admin.id, type=kind,
                  password_hash=hash_password(password) if password else None)
        db.add(v)
        vaults[name] = v
    db.commit()
    readable = {"ids": {v.id for v in vaults.values()}}
    monkeypatch.setattr(activity_names, "readable_vault_ids", lambda db_, viewer, ids: set(ids) & readable["ids"])
    from app.api import api_server
    monkeypatch.setattr(api_server, "_current_session_hash", lambda request: "session-a")
    return SimpleNamespace(admin=admin, vaults=vaults, readable=readable, throttle=throttle)


def _unlock(db, world, name, password=None, request="req"):
    return routes.unlock_vault_names(world.vaults[name].id, routes.Unlock(password=password or SECRET),
                                     request=request, current_user=world.admin, db=db)


def _refused(status, fn, *a, **kw):
    with pytest.raises(HTTPException) as caught:
        fn(*a, **kw)
    assert caught.value.status_code == status, caught.value.detail
    return caught.value.detail


def _rows(db):
    db.expire_all()
    return db.query(AuditLog).filter(AuditLog.action == "activity_vault_unlocked").all()


def test_an_unlock_gives_a_receipt_for_this_session_and_records_it_without_the_password(db, world):
    out = _unlock(db, world, "pw")
    vault = world.vaults["pw"]
    assert vr.verify(out["receipt"], purpose="activity", session_hash="session-a", vault_id=vault.id,
                     user_id=world.admin.id, credential=vr.credential_digest(vault.password_hash))
    (row,) = _rows(db)
    assert (row.status, row.user_id, row.resource_id) == ("success", world.admin.id, str(vault.id))
    assert SECRET not in repr(row.details) and set(row.details) == {"vault_id", "expires_at"}


def test_an_administrator_who_cannot_read_the_vault_is_refused(db, world):
    world.readable["ids"] = set()
    detail = _refused(403, _unlock, db, world, "pw")
    assert "read the vault yourself" in detail
    assert _refused(403, routes.unlock_vault_names, uuid.uuid4(), routes.Unlock(password="x"), request="r",
                    current_user=world.admin, db=db) == detail
    assert world.throttle["burned"] == [] and _rows(db) == []


def test_a_zero_knowledge_vault_or_one_with_no_password_is_refused(db, world):
    assert "zero-knowledge" in _refused(409, _unlock, db, world, "zk")
    assert "zero-knowledge" in _refused(409, _unlock, db, world, "zkpw")
    assert "no vault password" in _refused(400, _unlock, db, world, "open")


def test_a_wrong_password_is_counted_and_recorded(db, world):
    _refused(403, _unlock, db, world, "pw", password="not-it")
    assert world.throttle["burned"] == [f"rate_limit:vault:{world.vaults['pw'].id}:{world.admin.id}"]
    (row,) = _rows(db)
    assert row.status == "failure" and row.details == {"vault_id": str(world.vaults["pw"].id),
                                                       "reason": "wrong password"}


def test_no_session_no_receipt(db, world, monkeypatch):
    from app.api import api_server
    monkeypatch.setattr(api_server, "_current_session_hash", lambda request: None)
    _refused(403, _unlock, db, world, "pw")


def test_no_receipt_without_its_audit_row(db, world, monkeypatch):
    from app.services.audit_logger import AuditLogger

    def broken(self, **kw):
        raise RuntimeError("refused")

    monkeypatch.setattr(AuditLogger, "build_row", broken)
    _refused(503, _unlock, db, world, "pw")


def test_the_route_is_a_plain_function_for_an_interactive_administrator_in_its_own_file():
    import inspect
    from app.api import api_server
    from app.api import user_management_api as um
    route = next(r for r in api_server.app.router.routes if getattr(r, "path", "") == "/activity/vaults/{vault_id}/unlock"
                 or getattr(getattr(r, "original_router", None), "routes", None) and any(
                     getattr(x, "path", "") == "/activity/vaults/{vault_id}/unlock" for x in r.original_router.routes))
    found = route if getattr(route, "path", "") else next(
        x for x in route.original_router.routes if x.path == "/activity/vaults/{vault_id}/unlock")
    assert not inspect.iscoroutinefunction(found.endpoint)
    assert um.require_interactive_admin in {d.call for d in found.dependant.dependencies}
    assert "/activity/vaults/{vault_id}/unlock" not in inspect.getsource(api_server).replace(
        "app.include_router(activity_unlock_router)", "")


# --------------------------------------------------------------------------- the names a receipt shows

class _Request:
    def __init__(self, header):
        self.headers = {activity_names.UNLOCK_HEADER: header} if header else {}


def test_only_valid_receipts_for_readable_password_vaults_unlock(db, world, monkeypatch):
    pw = world.vaults["pw"]
    good = _unlock(db, world, "pw")["receipt"]
    other_session, _ = vr.issue(purpose="activity", session_hash="session-b", vault_id=pw.id, user_id=world.admin.id,
                                credential=vr.credential_digest(pw.password_hash))
    zk = world.vaults["zkpw"]
    zk_receipt, _ = vr.issue(purpose="activity", session_hash="session-a", vault_id=zk.id, user_id=world.admin.id,
                             credential=vr.credential_digest(zk.password_hash))
    unlocked = activity_names.unlocked_vaults
    assert unlocked(db, world.admin, _Request(f"{pw.id}:{good}")) == {pw.id}
    assert unlocked(db, world.admin, _Request(f"{pw.id}:{other_session}")) == frozenset()
    assert unlocked(db, world.admin, _Request(f"{world.vaults['open'].id}:{good}")) == frozenset()
    # A vault with no password has nothing to unlock, even with a receipt issued for it as it is.
    open_receipt, _ = vr.issue(purpose="activity", session_hash="session-a", vault_id=world.vaults["open"].id,
                               user_id=world.admin.id, credential=None)
    assert unlocked(db, world.admin, _Request(f"{world.vaults['open'].id}:{open_receipt}")) == frozenset()
    assert unlocked(db, world.admin, _Request(f"{zk.id}:{zk_receipt}")) == frozenset()
    assert unlocked(db, world.admin, _Request(None)) == frozenset()
    assert unlocked(db, world.admin, None) == frozenset()
    assert unlocked(db, world.admin, _Request(f"not-a-vault:{good}, {pw.id}:")) == frozenset()
    world.readable["ids"] = set()
    assert unlocked(db, world.admin, _Request(f"{pw.id}:{good}")) == frozenset()
    world.readable["ids"] = {pw.id}
    pw.password_hash = hash_password("Changed-Secret-2")
    db.commit()
    assert unlocked(db, world.admin, _Request(f"{pw.id}:{good}")) == frozenset()


def test_at_most_twenty_vaults_a_request(db, world, monkeypatch):
    seen = []
    monkeypatch.setattr(vr, "verify", lambda receipt, **kw: seen.append(kw["vault_id"]) or True)
    pairs = ",".join(f"{uuid.uuid4()}:r" for _ in range(25))
    activity_names.unlocked_vaults(db, world.admin, _Request(pairs))
    assert seen == []                    # none of them exists
    assert activity_names.MAX_UNLOCKED == 20


def _event(vault_id, item="Name hidden: the vault has a password", recorded=None):
    return {"resource_type": "file", "resource_id": str(uuid.uuid4()), "details": {"vault_id": str(vault_id)},
            "names": {"vault": "pw", "item": item}, "recorded_names": recorded}


def test_an_unlocked_vaults_items_show_as_recorded_and_never_looked_up():
    v = uuid.uuid4()
    full = _event(v, recorded={"file_name": {"fingerprint": "fp1:a:b", "name": "q3.xlsx"}})
    fingerprint = _event(v, recorded={"file_name": {"fingerprint": "fp1:a:c"}})
    renamed = _event(v, recorded={"old_name": {"fingerprint": "fp1:a:d", "name": "a.txt"},
                                  "new_name": {"fingerprint": "fp1:a:e", "name": "b.txt"}})
    nothing = _event(v, recorded=None)
    elsewhere = _event(uuid.uuid4(), recorded={"file_name": {"name": "secret.txt"}})
    shown = _event(v, item="report.pdf", recorded={"file_name": {"name": "other.pdf"}})
    events = [full, fingerprint, renamed, nothing, elsewhere, shown]
    activity_names.show_unlocked(events, frozenset({v}))
    assert [e["names"]["item"] for e in events] == [
        "q3.xlsx", "fp1:a:c", "b.txt", activity_names.NOT_RECORDED, activity_names.PASSWORD_HIDDEN, "report.pdf"]
    again = _event(v, recorded={"file_name": {"name": "q3.xlsx"}})
    activity_names.show_unlocked([again], frozenset())
    assert again["names"]["item"] == activity_names.PASSWORD_HIDDEN


def test_with_a_receipt_a_password_vaults_sealed_names_open_but_never_a_zero_knowledge_vaults(db, world, monkeypatch):
    for key in ap.POLICY_KEYS:
        monkeypatch.setattr(settings, ap.env_field(key), "full")
    ap.use(ap.Policy(4, {**ap.POLICY_ONE, "names": "full"}))
    from app.services.audit_logger import AuditLogger
    rows = []
    for name in ("pw", "zkpw"):
        rows.append(AuditLogger(db).build_row(action="file_uploaded", status="success", resource_type="file",
                                              resource_id=str(uuid.uuid4()),
                                              details={"vault_id": str(world.vaults[name].id), "file_name": f"{name}.txt"}))
    closed = activity_names.recorded_names_for(db, world.admin, rows)
    assert "name" not in closed[0]["file_name"] and "name" not in closed[1]["file_name"]
    opened = activity_names.recorded_names_for(db, world.admin, rows,
                                               frozenset({world.vaults["pw"].id, world.vaults["zkpw"].id}))
    assert opened[0]["file_name"]["name"] == "pw.txt"
    assert "name" not in opened[1]["file_name"]
