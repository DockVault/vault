"""Opening a file for a compliance case (app/core/case_access.py), offline on a real (SQLite) database with real
stored files: the checks in their order (the case, the file, zero-knowledge and passwords, the record, then the
file), each refusal with its reason, the record written and committed before the file is opened and a view refused
when it cannot be written, the ten-minute rule and the hourly view rate, kept files, and no side effect on the
vault. The static pins: nothing that decides access elsewhere (the permission service, VaultService.get_vault, the
SFTP server) imports the case modules, and no permission or endpoint group names a compliance capability."""
import ast
import hashlib
import inspect
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import admin_grants  # noqa: E402
from app.core import after_commit  # noqa: E402
from app.core import auditor_rights as rights  # noqa: E402
from app.core import case_access as ca  # noqa: E402
from app.core import case_rules as rules  # noqa: E402
from app.core import cases  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import legal_holds as holds  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import owner_notices as on  # noqa: E402
from app.core import vault_unlock_receipts as receipts  # noqa: E402

pytestmark = pytest.mark.unit

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


def _user(db, name, role=m.RoleEnum.USER):
    u = m.User(username=name, email=f"{name}@example.test", password_hash="x", role=role, is_active=True,
               is_locked=False)
    db.add(u)
    db.commit()
    if role == m.RoleEnum.ADMIN:
        admin_grants.record(db, u.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR, now=rights.utcnow() - OLD)
    db.add(m.SecondFactorEnrollment(user_id=u.id, method="totp", secret_enc="sealed", status="active"))
    db.commit()
    return u


def _vault(db, owner, *, kind="standard", password=None):
    v = m.Vault(id=uuid.uuid4(), name=f"Vault of {owner.username}", owner_id=owner.id, type=kind,
                password_hash=password, file_count=0, total_size_bytes=0)
    db.add(v)
    db.commit()
    return v


def _folder(db, vault, parent=None, name="Board minutes"):
    f = m.Folder(id=uuid.uuid4(), vault_id=vault.id, name=name, parent_folder_id=parent.id if parent else None)
    db.add(f)
    db.commit()
    return f


def _stored(root, vault_id, file_id, content: bytes) -> str:
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


def _file(db, storage, vault, name="minutes.txt", content=b"the board met on monday", folder=None, **kw):
    fid = uuid.uuid4()
    f = m.File(id=fid, vault_id=vault.id, folder_id=folder.id if folder else None, name=name, original_name=name,
               size_bytes=len(content), mime_type="text/plain", checksum_sha256=hashlib.sha256(content).hexdigest(),
               storage_path=_stored(storage.root, vault.id, fid, content), uploaded_by=vault.owner_id, **kw)
    db.add(f)
    db.commit()
    return f


@pytest.fixture
def people(db, settings):
    """ada proposed uma's auditor right and bob approved it; olga and otto own vaults; mallory is another
    auditor."""
    ada, bob = _user(db, "ada", m.RoleEnum.ADMIN), _user(db, "bob", m.RoleEnum.ADMIN)
    uma, olga, otto, mallory = (_user(db, n) for n in ("uma", "olga", "otto", "mallory"))
    for who in (uma, mallory):
        grant = rights.propose(db, who, proposer=ada, now=rights.utcnow() - timedelta(hours=2))
        rights.approve(db, grant, approver=bob, now=rights.utcnow() - timedelta(hours=1))
    db.commit()
    return SimpleNamespace(ada=ada, bob=bob, uma=uma, olga=olga, otto=otto, mallory=mallory,
                           v1=_vault(db, olga), v2=_vault(db, otto))


def _case(db, people, scope, **kw):
    case = cases.request_case(db, people.uma, scope=scope, **{**TEXT, **kw})
    db.commit()
    cases.approve(db, case, approver=people.bob)
    db.commit()
    return case


def _vaults(*vaults):
    return [{"kind": "vault", "target_id": v.id} for v in vaults]


def _rows(db, action, status="success"):
    return db.query(m.AuditLog).filter(m.AuditLog.action == action, m.AuditLog.status == status).all()


def _read(db, case, file, user, **kw):
    _case_, found, download = ca.open_file(db, case.id, file.id, user, **kw)
    with download:
        return found, b"".join(download.chunks())


def _refusal(fn, *args, **kwargs) -> ca.Refused:
    with pytest.raises(ca.Refused) as refused:
        fn(*args, **kwargs)
    return refused.value


# --------------------------------------------------------------------------- opening

def test_the_auditor_of_an_active_case_reads_a_file_and_its_view_is_recorded_under_the_case(db, people, storage):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    found, body = _read(db, case, f, people.uma)
    assert body == b"the board met on monday" and found.status == ca.LIVE and storage.opened == [str(f.id)]
    (row,) = _rows(db, "case_file_viewed")
    assert row.case_id == case.id and row.user_id == people.uma.id and row.resource_id == str(f.id)
    assert row.resource_type == "file" and row.details["vault_id"] == str(people.v1.id)
    assert "password_override" not in row.details


def test_the_record_is_committed_before_the_file_is_opened(db, people, storage, monkeypatch):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    order = []
    real_commit = db.commit
    monkeypatch.setattr(db, "commit", lambda: (order.append("commit"), real_commit())[1])
    real_open = ca._vault_service(db)._open_stored_file

    class Service:
        def _open_stored_file(self, *a, **k):
            order.append("open")
            return real_open(*a, **k)

    monkeypatch.setattr(ca, "_vault_service", lambda db_: Service())
    _read(db, case, f, people.uma)
    assert order == ["commit", "open"]


def test_a_view_whose_record_cannot_be_written_is_refused_and_opens_nothing(db, people, storage, monkeypatch):
    from app.services.audit_logger import AuditLogger
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))

    def broken(self, **kw):
        raise RuntimeError("the audit table is full")

    monkeypatch.setattr(AuditLogger, "build_row", broken)
    refused = _refusal(ca.open_file, db, case.id, f.id, people.uma)
    assert refused.reason == ca.RECORD_FAILED and refused.status == 503
    assert storage.opened == [], "no byte is read when the record is not written"


def test_a_view_whose_commit_fails_is_refused_and_opens_nothing(db, people, storage, monkeypatch):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))

    def failing():
        raise RuntimeError("could not commit")

    monkeypatch.setattr(db, "commit", failing)
    assert _refusal(ca.open_file, db, case.id, f.id, people.uma).reason == ca.RECORD_FAILED
    assert storage.opened == []


def test_the_checks_run_in_their_order_and_stop_at_the_first_refusal(db, people, storage, monkeypatch):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    calls = []
    for name in ("case_for", "file_for", "content_opening", "record"):
        real = getattr(ca, name)
        monkeypatch.setattr(ca, name, (lambda n, r: lambda *a, **k: (calls.append(n), r(*a, **k))[1])(name, real))
    _read(db, case, f, people.uma)
    assert calls == ["case_for", "file_for", "content_opening", "record"]
    calls.clear()
    people.v1.type = "zero_knowledge"
    db.commit()
    assert _refusal(ca.open_file, db, case.id, f.id, people.uma, now=ca.utcnow() + timedelta(minutes=11)).reason \
        == ca.ZERO_KNOWLEDGE
    assert calls == ["case_for", "file_for", "content_opening"], "nothing is recorded or opened after a refusal"


# --------------------------------------------------------------------------- 1. the case

def test_another_auditors_case_and_an_unknown_case_are_not_found(db, people, storage):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    assert _refusal(ca.open_file, db, case.id, f.id, people.mallory).reason == ca.NOT_AUDITOR
    assert _refusal(ca.open_file, db, uuid.uuid4(), f.id, people.uma).status == 404
    assert _refusal(ca.open_file, db, case.id, f.id, people.olga).status == 404, "the owner is not its auditor"
    assert storage.opened == []


def test_a_temporary_credential_is_refused(db, people, storage):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    people.uma._is_temp_session = True
    try:
        assert _refusal(ca.open_file, db, case.id, f.id, people.uma).reason == ca.TEMPORARY
    finally:
        people.uma._is_temp_session = False


@pytest.mark.parametrize("change, reason", [
    ("disabled", rules.ACCESS_OFF),
    ("revoked", rules.AUDITOR_NOT_LIVE),
    ("suspended", rules.AUDITOR_NOT_LIVE),
    ("expired", rules.AUDITOR_NOT_LIVE),
    ("deactivated", rules.AUDITOR_NOT_LIVE),
    ("locked", rules.AUDITOR_NOT_LIVE),
    ("ended", rules.ACCESS_ENDED),
    ("not_started", rules.NOT_STARTED),
    ("closed", rules.NOT_ACTIVE),
    ("pending", rules.NOT_ACTIVE),
])
def test_a_case_that_gives_no_access_now_is_refused_with_its_reason(db, people, storage, settings, change, reason):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    grant = rights.open_grant(db, people.uma.id)
    now = ca.utcnow()
    if change == "disabled":
        settings[cs.ACCESS] = cs.DISABLED
    elif change == "revoked":
        rights.revoke(db, grant, actor=people.ada)
    elif change == "suspended":
        rights.suspend(db, grant, "password_changed")
    elif change == "expired":
        grant.expires_at = now - timedelta(seconds=1)
    elif change == "deactivated":
        people.uma.is_active = False
    elif change == "locked":
        people.uma.is_locked = True
    elif change == "ended":
        now = case.access_ends_at
    elif change == "not_started":
        now = case.access_starts_at - timedelta(seconds=1)
    elif change == "closed":
        case.status = rules.CLOSED
    elif change == "pending":
        case.status = rules.PENDING
    db.commit()
    refused = _refusal(ca.open_file, db, case.id, f.id, people.uma, now=now)
    assert refused.reason == reason and refused.status == 403
    assert storage.opened == []


def test_a_case_stands_on_its_own_grant_and_a_new_grant_does_not_bring_it_back(db, people, storage):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    rights.revoke(db, rights.open_grant(db, people.uma.id), actor=people.ada)
    db.commit()
    grant = rights.propose(db, people.uma, proposer=people.ada)
    rights.approve(db, grant, approver=people.bob)
    db.commit()
    assert _refusal(ca.open_file, db, case.id, f.id, people.uma).reason == rules.AUDITOR_NOT_LIVE


# --------------------------------------------------------------------------- 2. the file

def test_a_file_outside_the_cases_vaults_is_out_of_scope(db, people, storage):
    f = _file(db, storage, people.v2)
    case = _case(db, people, _vaults(people.v1))
    refused = _refusal(ca.open_file, db, case.id, f.id, people.uma)
    assert refused.reason == ca.OUT_OF_SCOPE and refused.status == 404
    assert _refusal(ca.open_file, db, case.id, uuid.uuid4(), people.uma).reason == ca.NO_SUCH_FILE


def test_a_folder_case_covers_its_subtree_only_and_follows_the_live_tree(db, people, storage):
    board = _folder(db, people.v1)
    sub = _folder(db, people.v1, board, "2026")
    other = _folder(db, people.v1, None, "Holidays")
    inside, deeper, outside, root = (_file(db, storage, people.v1, folder=board), _file(db, storage, people.v1, folder=sub),
                                     _file(db, storage, people.v1, folder=other), _file(db, storage, people.v1))
    case = _case(db, people, [{"kind": "folder", "target_id": board.id}])
    for f in (inside, deeper):
        assert _read(db, case, f, people.uma)[1] == b"the board met on monday"
    for f in (outside, root):
        assert _refusal(ca.open_file, db, case.id, f.id, people.uma).reason == ca.OUT_OF_SCOPE
    inside.folder_id = other.id
    db.commit()
    assert _refusal(ca.open_file, db, case.id, inside.id, people.uma).reason == ca.OUT_OF_SCOPE, \
        "a file moved out of the case's folder leaves its scope"


def test_a_vault_narrowed_out_covers_nothing(db, people, storage):
    f1, f2 = _file(db, storage, people.v1), _file(db, storage, people.v2)
    case = _case(db, people, _vaults(people.v1, people.v2))
    cases.narrow(db, case, by=people.uma, scope=_vaults(people.v2))
    db.commit()
    assert _refusal(ca.open_file, db, case.id, f1.id, people.uma).reason == ca.OUT_OF_SCOPE
    assert _read(db, case, f2, people.uma)[1]


def test_the_time_range_covers_files_uploaded_or_changed_inside_it(db, people, storage):
    lo = datetime(2026, 3, 1)
    hi = datetime(2026, 3, 31)
    uploaded = _file(db, storage, people.v1, created_at=datetime(2026, 3, 5), updated_at=datetime(2026, 3, 5))
    changed = _file(db, storage, people.v1, created_at=datetime(2025, 1, 5), updated_at=datetime(2026, 3, 30))
    before = _file(db, storage, people.v1, created_at=datetime(2026, 2, 27), updated_at=datetime(2026, 2, 28))
    after = _file(db, storage, people.v1, created_at=datetime(2026, 4, 1), updated_at=datetime(2026, 4, 2))
    case = _case(db, people, _vaults(people.v1), files_from=lo, files_to=hi)
    for f in (uploaded, changed):
        assert _read(db, case, f, people.uma)[1]
    for f in (before, after):
        assert _refusal(ca.open_file, db, case.id, f.id, people.uma).reason == ca.OUT_OF_RANGE


def test_a_kept_file_opens_with_its_status_and_one_due_for_its_purge_does_not(db, people, storage):
    f = _file(db, storage, people.v1, content=b"deleted evidence")
    case = _case(db, people, _vaults(people.v1))
    columns = {c.name: getattr(f, c.name) for c in m.HeldFile.__table__.columns if hasattr(f, c.name)}
    db.delete(f)
    db.commit()
    kept = m.HeldFile(**columns, kept_at=ca.utcnow(), kept_reason="deleted", kept_by="system")
    db.add(kept)
    db.commit()
    found, body = _read(db, case, kept, people.uma)
    assert body == b"deleted evidence" and found.kept and found.status == ca.KEPT_DELETED
    kept.kept_reason = "expired"
    db.commit()
    assert ca.open_file(db, case.id, kept.id, people.uma)[1].status == ca.KEPT_EXPIRED
    kept.purge_after = ca.utcnow() - timedelta(seconds=1)
    db.commit()
    assert _refusal(ca.open_file, db, case.id, kept.id, people.uma).reason == ca.NO_SUCH_FILE


def test_a_live_file_past_its_expiry_still_opens_for_the_case_as_expired(db, people, storage):
    f = _file(db, storage, people.v1, expires_at=ca.utcnow() - timedelta(hours=1))
    case = _case(db, people, _vaults(people.v1))
    assert ca.open_file(db, case.id, f.id, people.uma)[1].status == ca.EXPIRED


# --------------------------------------------------------------------------- 3. zero-knowledge and passwords

@pytest.mark.parametrize("rule", [cs.REFUSE, cs.WITH_PASSWORD, cs.OVERRIDE])
def test_zero_knowledge_contents_are_refused_under_every_setting(db, people, storage, settings, rule):
    settings[cs.PASSWORD_VAULTS] = cs.OVERRIDE
    zk = _vault(db, people.olga, kind="zero_knowledge")
    f = _file(db, storage, zk)
    case = _case(db, people, _vaults(zk), password_override=True)
    settings[cs.PASSWORD_VAULTS] = rule
    assert _refusal(ca.open_file, db, case.id, f.id, people.uma).reason == ca.ZERO_KNOWLEDGE
    assert storage.opened == [] and _rows(db, "case_file_viewed") == []


def test_a_vault_that_became_zero_knowledge_by_its_record_at_approval_is_refused(db, people, storage):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    row = cases.vault_rows(db, case)[0]
    row.vault_type_at_approval = "zero_knowledge"
    db.commit()
    assert _refusal(ca.open_file, db, case.id, f.id, people.uma).reason == ca.ZERO_KNOWLEDGE


def _receipt(case, vault, user, session=SESSION):
    return receipts.issue(purpose=receipts.PURPOSE_CASE, session_hash=session, case_id=case.id, vault_id=vault.id,
                          user_id=user.id, credential=receipts.credential_digest(vault.password_hash))[0]


def test_with_password_a_password_vault_opens_only_with_a_receipt_of_this_case_session_and_password(db, people,
                                                                                                    storage):
    pv = _vault(db, people.olga, password="argon2-hash-1")
    f = _file(db, storage, pv)
    case = _case(db, people, _vaults(pv))
    assert _refusal(ca.open_file, db, case.id, f.id, people.uma).reason == ca.LOCKED
    good = _receipt(case, pv, people.uma)
    assert _read(db, case, f, people.uma, unlocked_given={str(pv.id): good}, session_hash=SESSION)[1]
    other = _case(db, people, _vaults(pv))
    for given, session in ((_receipt(other, pv, people.uma), SESSION),        # another case's
                           (good, "another-session"),                         # another session
                           (receipts.issue(purpose=receipts.PURPOSE_ACTIVITY, session_hash=SESSION, vault_id=pv.id,
                                           user_id=people.uma.id,
                                           credential=receipts.credential_digest(pv.password_hash))[0], SESSION)):
        assert _refusal(ca.open_file, db, case.id, f.id, people.uma, unlocked_given={str(pv.id): given},
                        session_hash=session).reason == ca.LOCKED
    pv.password_hash = "argon2-hash-2"
    db.commit()
    assert _refusal(ca.open_file, db, case.id, f.id, people.uma, unlocked_given={str(pv.id): good},
                    session_hash=SESSION).reason == ca.LOCKED, "a changed vault password voids the receipt"


def test_refuse_refuses_a_password_vault_even_with_a_receipt(db, people, storage, settings):
    pv = _vault(db, people.olga, password="argon2-hash-1")
    f = _file(db, storage, pv)
    case = _case(db, people, _vaults(pv))
    settings[cs.PASSWORD_VAULTS] = cs.REFUSE
    refused = _refusal(ca.open_file, db, case.id, f.id, people.uma,
                       unlocked_given={str(pv.id): _receipt(case, pv, people.uma)}, session_hash=SESSION)
    assert refused.reason == ca.PASSWORD_REFUSED


def test_override_opens_a_password_vault_only_when_the_case_asked_and_marks_the_row(db, people, storage, settings):
    settings[cs.PASSWORD_VAULTS] = cs.OVERRIDE
    pv = _vault(db, people.olga, password="argon2-hash-1")
    f = _file(db, storage, pv)
    asked = _case(db, people, _vaults(pv), password_override=True)
    assert _read(db, asked, f, people.uma)[1]
    (row,) = _rows(db, "case_file_viewed")
    assert row.details["password_override"] is True
    not_asked = _case(db, people, _vaults(pv))
    assert _refusal(ca.open_file, db, not_asked.id, f.id, people.uma).reason == ca.LOCKED


def test_the_stricter_of_the_recorded_and_current_rule_applies(db, people, storage, settings):
    settings[cs.PASSWORD_VAULTS] = cs.OVERRIDE
    pv = _vault(db, people.olga, password="argon2-hash-1")
    f = _file(db, storage, pv)
    case = _case(db, people, _vaults(pv), password_override=True)
    settings[cs.PASSWORD_VAULTS] = cs.WITH_PASSWORD
    assert _refusal(ca.open_file, db, case.id, f.id, people.uma).reason == ca.LOCKED, "a stricter .env applies now"
    settings[cs.PASSWORD_VAULTS] = cs.OVERRIDE
    case.password_policy = cs.WITH_PASSWORD
    db.commit()
    assert _refusal(ca.open_file, db, case.id, f.id, people.uma).reason == ca.LOCKED, \
        "changing .env to override never widens a case approved under with_password"


def test_a_file_with_its_own_password_opens_only_under_the_override(db, people, storage, settings):
    f = _file(db, storage, people.v1, password_hash="file-hash")
    case = _case(db, people, _vaults(people.v1))
    assert _refusal(ca.open_file, db, case.id, f.id, people.uma).reason == ca.FILE_PASSWORD
    settings[cs.PASSWORD_VAULTS] = cs.OVERRIDE
    over = _case(db, people, _vaults(people.v1), password_override=True)
    assert _read(db, over, f, people.uma)[1]
    assert _rows(db, "case_file_viewed")[-1].details["password_override"] is True


# --------------------------------------------------------------------------- 4. the record: ten minutes, the rate

def test_a_second_view_within_ten_minutes_writes_no_row_and_a_later_one_does(db, people, storage):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    now = ca.utcnow()
    _read(db, case, f, people.uma, now=now)
    _read(db, case, f, people.uma, now=now + timedelta(minutes=9))
    assert len(_rows(db, "case_file_viewed")) == 1
    _read(db, case, f, people.uma, now=now + timedelta(minutes=11))
    assert len(_rows(db, "case_file_viewed")) == 2


def test_a_new_view_past_the_hourly_rate_is_refused_but_a_repeat_is_not(db, people, storage, settings):
    settings[cs.VIEW_RATE] = 2
    files = [_file(db, storage, people.v1) for _ in range(3)]
    case = _case(db, people, _vaults(people.v1))
    _read(db, case, files[0], people.uma)
    _read(db, case, files[1], people.uma)
    refused = _refusal(ca.open_file, db, case.id, files[2].id, people.uma)
    assert refused.reason == ca.VIEW_RATE and refused.status == 429
    assert _read(db, case, files[0], people.uma)[1], "reading a file viewed in the last ten minutes is not a new view"


def test_the_view_rate_counts_every_case_of_the_auditor(db, people, storage, settings):
    settings[cs.VIEW_RATE] = 1
    f1, f2 = _file(db, storage, people.v1), _file(db, storage, people.v2)
    c1, c2 = _case(db, people, _vaults(people.v1)), _case(db, people, _vaults(people.v2))
    _read(db, c1, f1, people.uma)
    assert _refusal(ca.open_file, db, c2.id, f2.id, people.uma).reason == ca.VIEW_RATE


def test_record_refused_writes_case_access_refused_under_the_case_and_never_raises(db, people, storage, monkeypatch):
    f = _file(db, storage, people.v2)
    case = _case(db, people, _vaults(people.v1))
    refused = _refusal(ca.open_file, db, case.id, f.id, people.uma)
    ca.record_refused(db, case.id, people.uma, refused, resource_type="file", resource_id=f.id)
    (row,) = _rows(db, "case_access_refused", "failure")
    assert row.case_id == case.id and row.details["reason"] == ca.OUT_OF_SCOPE and row.resource_id == str(f.id)
    ca.record_refused(db, uuid.uuid4(), people.uma, ca.Refused(ca.NO_CASE))
    assert _rows(db, "case_access_refused", "failure")[-1].case_id is None

    from app.services.audit_logger import AuditLogger
    monkeypatch.setattr(AuditLogger, "build_row", lambda self, **kw: (_ for _ in ()).throw(RuntimeError("x")))
    ca.record_refused(db, case.id, people.uma, refused)


# --------------------------------------------------------------------------- no side effects

def test_reading_for_a_case_changes_nothing_of_the_vault_or_the_file(db, people, storage):
    f = _file(db, storage, people.v1)
    case = _case(db, people, _vaults(people.v1))
    people.v1.last_accessed = datetime(2026, 1, 1)
    db.commit()
    before_file = {c.name: getattr(f, c.name) for c in m.File.__table__.columns}
    before_vault = {c.name: getattr(people.v1, c.name) for c in m.Vault.__table__.columns}
    _read(db, case, f, people.uma)
    db.expire_all()
    assert {c.name: getattr(db.get(m.File, f.id), c.name) for c in m.File.__table__.columns} == before_file
    assert {c.name: getattr(db.get(m.Vault, people.v1.id), c.name) for c in m.Vault.__table__.columns} == before_vault
    assert db.execute(m.vault_views.select()).fetchall() == []


def test_the_resolver_writes_nothing_but_its_record():
    """No call or name in its code (its words aside) reaches what a read in a vault changes: the vault's last
    access, the per-user views, share and download counters, a transfer entry, the live feed."""
    tree = ast.parse(inspect.getsource(ca))
    used = ({n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            | {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)})
    for forbidden in ("get_vault", "start_operation", "burn_share_download", "log_action", "last_accessed",
                      "vault_views", "download_count", "ProgressTracker", "broadcast_event", "record_vault_view"):
        assert forbidden not in used, forbidden


# --------------------------------------------------------------------------- static pins

CASE_MODULES = ("case_access", "cases", "case_rules", "case_eligibility", "legal_holds", "auditor_rights",
                "owner_access", "compliance_router")


def _imports(path: Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            out.add(node.module or "")
            out.update(f"{node.module}.{a.name}" for a in node.names)
    return out


@pytest.mark.parametrize("path", ["app/core/authorization.py"] + sorted(
    str(p.relative_to(ROOT)).replace("\\", "/") for p in (ROOT / "app" / "sftp").glob("*.py")))
def test_the_permission_service_and_the_sftp_server_never_import_the_case_modules(path):
    imported = _imports(ROOT / path)
    assert not {i for i in imported for mod in CASE_MODULES if i.endswith("." + mod) or i == mod}, path
    assert "auditor_grants" not in (ROOT / path).read_text(encoding="utf-8"), "never reads auditor_grants"


def test_get_vault_never_reaches_the_case_modules():
    from app.services.vault_service import VaultService
    source = inspect.getsource(VaultService.get_vault)
    for mod in CASE_MODULES:
        assert mod not in source, mod


def test_only_the_compliance_routes_import_the_resolver():
    users = []
    for path in (ROOT / "app").rglob("*.py"):
        if path.name == "case_access.py":
            continue
        if any(i.endswith("case_access") for i in _imports(path)):
            users.append(str(path.relative_to(ROOT)).replace("\\", "/"))
    assert set(users) <= {"app/api/compliance_router.py", "app/services/activity_names.py",
                          "app/core/case_export.py", "app/core/case_names.py"}, users


def test_no_permission_and_no_endpoint_group_names_a_compliance_capability():
    from app.core.api_catalog import API_CATALOG
    from app.core.models import PermissionEnum, VaultPermissionEnum
    words = ("complian", "auditor", "case", "hold", "reveal", "investigat")
    for enum in (PermissionEnum, VaultPermissionEnum):
        for member in enum:
            assert not any(w in member.name.lower() or w in str(member.value).lower() for w in words), member
    assert API_CATALOG, "the endpoint groups are where this test looks for them"
    for name, group in API_CATALOG.items():
        text = (str(name) + " " + " ".join(str(e) for e in getattr(group, "endpoints", []) or [])).lower()
        assert not any(w in text for w in ("complian", "auditor", "/compliance", "reveal")), name
