"""Shared setup of the offline tests of reading a compliance case (test_case_access.py, test_case_reading.py,
test_case_export.py): a real (SQLite) database with every table and the kept tables, files stored encrypted as the
vault stores them, two administrators who granted uma the auditor right, olga's and otto's vaults, and a case uma
asks for and bob approves. Holds no tests."""
import hashlib
import uuid
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import admin_grants  # noqa: E402
from app.core import after_commit  # noqa: E402
from app.core import auditor_rights as rights  # noqa: E402
from app.core import case_access as ca  # noqa: E402
from app.core import cases  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import legal_holds as holds  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import owner_notices as on  # noqa: E402
from app.core import vault_unlock_receipts as receipts  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OLD = timedelta(days=400)
TEXT = dict(purpose="internal_investigation", legal_basis="legal_obligation",
            justification="Suspected exfiltration of client records, ticket SEC-2041.",
            owner_note="Your vaults are part of an internal review.")
SESSION = "session-hash-of-uma"


@pytest.fixture
def db():
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    from app.core import sftp_versions
    after_commit.handler(cases._NOTICES, lambda notices: None)
    after_commit.handler(on._NUDGES, lambda items: None)
    monkeypatch.setattr(holds, "deliver", lambda notices: None)
    monkeypatch.setattr(rights, "deliver", lambda notices: None)
    monkeypatch.setattr(on, "contact", lambda db_: None)
    monkeypatch.setattr(sftp_versions, "sftp_same_version",
                        lambda db_, **_k: sftp_versions.VersionCheck(True, sftp_versions.SAME, ("0.34.0",)))
    yield
    after_commit.handler(cases._NOTICES, cases._deliver)
    after_commit.handler(on._NUDGES, on._nudge)


@pytest.fixture
def settings(monkeypatch):
    values = {key: cs.current(key) for key in cs.KEYS}
    monkeypatch.setattr(cs, "current", lambda key: values[key])
    return values


@pytest.fixture
def storage(monkeypatch, tmp_path):
    """Stored files under tmp_path, opened by a VaultService that reads them there."""
    from app.services import vault_service
    service = vault_service.VaultService.__new__(vault_service.VaultService)
    service.storage_path = tmp_path
    opened = []
    real = vault_service.VaultService._open_stored_file

    def spy(self, file, vault, file_id, whole=True):
        opened.append(str(file_id))
        return real(self, file, vault, file_id, whole)

    monkeypatch.setattr(vault_service.VaultService, "_open_stored_file", spy)
    monkeypatch.setattr(ca, "_vault_service", lambda db_: service)
    return SimpleNamespace(root=tmp_path, opened=opened)


def user(db, name, role=m.RoleEnum.USER):
    u = m.User(username=name, email=f"{name}@example.test", password_hash="x", role=role, is_active=True,
               is_locked=False)
    db.add(u)
    db.commit()
    if role == m.RoleEnum.ADMIN:
        admin_grants.record(db, u.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR, now=rights.utcnow() - OLD)
    db.add(m.SecondFactorEnrollment(user_id=u.id, method="totp", secret_enc="sealed", status="active"))
    db.commit()
    return u


def vault(db, owner, *, kind="standard", password=None):
    v = m.Vault(id=uuid.uuid4(), name=f"Vault of {owner.username}", owner_id=owner.id, type=kind,
                password_hash=password, file_count=0, total_size_bytes=0)
    db.add(v)
    db.commit()
    return v


def folder(db, vault, parent=None, name="Board minutes"):
    f = m.Folder(id=uuid.uuid4(), vault_id=vault.id, name=name, parent_folder_id=parent.id if parent else None)
    db.add(f)
    db.commit()
    return f


def stored(root, vault_id, file_id, content: bytes) -> str:
    from app.core import security
    codec = security.GcmChunkStreamCodecV2(vault_id, file_id)
    blob = bytearray(codec.header())
    for i in range(0, max(len(content), 1), 1000):
        blob += codec.encrypt(content[i:i + 1000], i // 1000)
    blob += codec.terminal()
    rel = f"{vault_id}/{file_id}.bin"
    (root / str(vault_id)).mkdir(exist_ok=True)
    (root / rel).write_bytes(bytes(blob))
    return rel


def file(db, storage, vault, name="minutes.txt", content=b"the board met on monday", folder=None, **kw):
    fid = uuid.uuid4()
    f = m.File(id=fid, vault_id=vault.id, folder_id=folder.id if folder else None, name=name, original_name=name,
               size_bytes=len(content), mime_type="text/plain", checksum_sha256=hashlib.sha256(content).hexdigest(),
               storage_path=stored(storage.root, vault.id, fid, content), uploaded_by=vault.owner_id, **kw)
    db.add(f)
    db.commit()
    return f


@pytest.fixture
def people(db, settings):
    """ada proposed uma's auditor right and bob approved it; olga and otto own vaults; mallory is another
    auditor."""
    ada, bob = user(db, "ada", m.RoleEnum.ADMIN), user(db, "bob", m.RoleEnum.ADMIN)
    uma, olga, otto, mallory = (user(db, n) for n in ("uma", "olga", "otto", "mallory"))
    for who in (uma, mallory):
        grant = rights.propose(db, who, proposer=ada, now=rights.utcnow() - timedelta(hours=2))
        rights.approve(db, grant, approver=bob, now=rights.utcnow() - timedelta(hours=1))
    db.commit()
    return SimpleNamespace(ada=ada, bob=bob, uma=uma, olga=olga, otto=otto, mallory=mallory,
                           v1=vault(db, olga), v2=vault(db, otto))


def case(db, people, scope, **kw):
    case = cases.request_case(db, people.uma, scope=scope, **{**TEXT, **kw})
    db.commit()
    cases.approve(db, case, approver=people.bob)
    db.commit()
    return case


def vaults(*vaults):
    return [{"kind": "vault", "target_id": v.id} for v in vaults]


def rows(db, action, status="success"):
    return db.query(m.AuditLog).filter(m.AuditLog.action == action, m.AuditLog.status == status).all()


def read(db, case, file, user, **kw):
    _case_, found, download = ca.open_file(db, case.id, file.id, user, **kw)
    with download:
        return found, b"".join(download.chunks())


def refusal(fn, *args, **kwargs) -> ca.Refused:
    with pytest.raises(ca.Refused) as refused:
        fn(*args, **kwargs)
    return refused.value


def kept(db, f, *, reason="deleted"):
    """Keep the live file ``f`` as the database's trigger does when a hold stands and it is deleted (SQLite has no
    trigger): its row deleted, a held_files row with every column it had."""
    columns = {c.name: getattr(f, c.name) for c in m.HeldFile.__table__.columns if hasattr(f, c.name)}
    db.delete(f)
    db.commit()
    row = m.HeldFile(**columns, kept_at=ca.utcnow(), kept_reason=reason, kept_by="system")
    db.add(row)
    db.commit()
    return row


def receipt(case, vault, user, session=SESSION):
    """A receipt for ``vault`` in ``case``, as its unlock gives one."""
    return receipts.issue(purpose=receipts.PURPOSE_CASE, session_hash=session, case_id=case.id, vault_id=vault.id,
                          user_id=user.id, credential=receipts.credential_digest(vault.password_hash))[0]
