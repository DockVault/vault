"""Expiry and storage under a legal hold, offline (app/services/vault_service.py, cleanup_expired_files;
GET /storage/stats; static/js/compliance.js).

For users, an expired file is gone whether or not a hold keeps it: the sweep deletes its row and writes its
file_expired row. When a hold kept it (the database's trigger copied the row into held_files in the sweep's own
transaction), the sweep reads that back and its file_expired row says held_by_case, and its stored bytes stay.
Kept bytes leave the vault's counters but are on the deployment's disk: the storage page shows "Kept for cases",
and counts them in what the vaults' files take on the disk; after the purge they drop. The deployment's storage
limit counts them too (each upload's early check and the check as its row is written, and the lowest limit an
administrator may set); a vault's own size limit does not, since nobody using the vault can remove them. SQLite has
no trigger: a test writes the kept row the trigger would write. test_legal_holds_live.py runs it on Postgres.
"""
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import kept_tables  # noqa: E402
from app.core import models as m  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def world(tmp_path):
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        db = make()
        owner = m.User(id=uuid.uuid4(), username="olga", password_hash="x", role=m.RoleEnum.USER, is_active=True)
        vault = m.Vault(id=uuid.uuid4(), name="v", owner_id=owner.id, expire_files_after_days=1,
                        expire_files_unit="days", total_size_bytes=30, file_count=2)
        db.add_all([owner, vault])
        db.commit()
        yield db, tmp_path, owner, vault
        db.close()


def _service(db, root):
    from app.services.encrypted_file_storage import EncryptedFileStorage
    from app.services.vault_service import VaultService
    svc = VaultService.__new__(VaultService)
    svc.db, svc.storage_path, svc.encrypted_storage = db, root, EncryptedFileStorage(root)
    return svc


def _file(db, root, vault, size, expired=True):
    rel = f"{vault.id}/{uuid.uuid4()}.enc"
    (root / rel).parent.mkdir(parents=True, exist_ok=True)
    (root / rel).write_bytes(b"x" * size)
    f = m.File(id=uuid.uuid4(), vault_id=vault.id, size_bytes=size, storage_path=rel,
               expires_at=datetime.utcnow() - timedelta(days=1) if expired else None)
    db.add(f)
    db.commit()
    return f.id, rel


def test_an_expired_file_a_hold_keeps_is_marked_held_by_case_and_its_bytes_stay(world, monkeypatch):
    db, root, _owner, vault = world
    kept_id, kept_rel = _file(db, root, vault, 10)
    gone_id, gone_rel = _file(db, root, vault, 20)
    # What the trigger does in the sweep's own transaction: the deleted row of a held vault is kept.
    real = kept_tables.kept_ids

    def trigger_then_read(db_, ids):
        db_.add(m.HeldFile(id=kept_id, vault_id=vault.id, storage_path=kept_rel, size_bytes=10,
                           kept_reason="expired", kept_at=datetime.utcnow()))
        db_.flush()
        return real(db_, ids)

    monkeypatch.setattr(kept_tables, "kept_ids", trigger_then_read)
    swept = _service(db, root).cleanup_expired_files()
    assert {s["file_id"] for s in swept} == {kept_id, gone_id}
    rows = {r.resource_id: r for r in db.query(m.AuditLog).filter(m.AuditLog.action == "file_expired")}
    assert rows[str(kept_id)].details.get("held_by_case") is True
    assert "held_by_case" not in rows[str(gone_id)].details
    assert db.get(m.File, kept_id) is None, "for users it is gone"
    assert (root / kept_rel).exists() and not (root / gone_rel).exists()


def test_the_sweep_says_why_its_deletions_happen(world, monkeypatch):
    db, root, _owner, vault = world
    _file(db, root, vault, 10)
    said = []
    monkeypatch.setattr(kept_tables, "mark_deletes", lambda db_, reason, actor=None: said.append((reason, actor)))
    _service(db, root).cleanup_expired_files()
    assert said == [("expired", None)]


def test_the_storage_page_counts_what_holds_keep(world):
    from _async_run import run_coroutine
    from app.api import api_server as api
    db, _root, owner, vault = world
    admin = m.User(id=uuid.uuid4(), username="ada", password_hash="x", role=m.RoleEnum.ADMIN, is_active=True)
    db.add(admin)
    db.add_all([m.HeldFile(id=uuid.uuid4(), vault_id=vault.id, storage_path=f"k{i}", size_bytes=1000 * (i + 1))
                for i in range(2)])
    db.add(m.HeldFolder(id=uuid.uuid4(), vault_id=vault.id))
    db.commit()
    stats = run_coroutine(api.storage_stats(current_user=admin, db=db))
    assert stats["kept_for_cases"] == {"files": 2, "folders": 1, "bytes": 3000}
    assert stats["used"] == 30 and stats["on_disk_bytes"] == 3030
    db.query(m.HeldFile).delete()
    db.query(m.HeldFolder).delete()
    db.commit()
    stats = run_coroutine(api.storage_stats(current_user=admin, db=db))
    assert stats["kept_for_cases"] == {"files": 0, "folders": 0, "bytes": 0} and stats["on_disk_bytes"] == 30


def _kept_file(db, vault, size):
    """A file deleted under a hold, as the trigger keeps it: in no vault's counters, its bytes on the disk."""
    db.add(m.HeldFile(id=uuid.uuid4(), vault_id=vault.id, storage_path=f"{vault.id}/{uuid.uuid4()}.enc",
                      size_bytes=size, kept_reason="deleted", kept_at=datetime.utcnow()))
    db.commit()


def test_the_deployment_limit_counts_what_holds_keep(world, monkeypatch):
    """A member of a held vault who uploads and deletes in turn leaves each file on the disk: the early check every
    upload, copy and SFTP write makes counts it against the deployment's limit."""
    from app.services import vault_service as vs
    db, _root, _owner, vault = world
    monkeypatch.setattr(vs, "deployment_storage_limit_bytes", lambda _db: 1100)
    assert vs.would_exceed_deployment_storage(db, 1000) == (False, 30, 1100)
    _kept_file(db, vault, 1000)
    assert vs.vaults_stored_bytes(db) == 30, "the vaults' counters hold only what is in them"
    assert vs.deployment_storage_used(db) == 1030
    assert vs.would_exceed_deployment_storage(db, 70) == (False, 1030, 1100)
    assert vs.would_exceed_deployment_storage(db, 71) == (True, 1030, 1100)


def _claim(db, root, vault, size, removed):
    """VaultService._claim_room for a file of ``size`` written into ``vault``: the check as its row is written."""
    svc = _service(db, root)
    svc._remove_blobs = removed.extend
    svc._claim_room({"vault_id": vault.id, "storage_path": f"{vault.id}/{uuid.uuid4()}.enc"}, size)


def test_the_check_as_a_files_row_is_written_counts_them_and_a_vaults_own_limit_does_not(world, monkeypatch):
    from app.services import vault_service as vs
    db, root, _owner, vault = world
    _kept_file(db, vault, 1000)
    removed = []
    # The vault's own size limit: what it holds (30), never what was kept of it (1000), which nobody using the
    # vault can remove.
    vault.size_limit = 100
    db.commit()
    monkeypatch.setattr(vs, "deployment_storage_limit_bytes", lambda _db: None)
    _claim(db, root, vault, 70, removed)
    db.rollback()
    with pytest.raises(vs.StorageLimitExceeded) as refused:
        _claim(db, root, vault, 71, removed)
    assert refused.value.kind == "vault" and refused.value.used == 30
    # The deployment's limit: what the vaults hold and what is kept.
    vault.size_limit = None
    db.commit()
    monkeypatch.setattr(vs, "deployment_storage_limit_bytes", lambda _db: 1100)
    _claim(db, root, vault, 70, removed)
    db.rollback()
    with pytest.raises(vs.StorageLimitExceeded) as refused:
        _claim(db, root, vault, 71, removed)
    assert (refused.value.kind, refused.value.used, refused.value.cap) == ("deployment", 1030, 1100)
    assert len(removed) == 2, "each refused file is removed"


def test_the_settings_storage_view_shows_the_kept_line():
    app_js = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    body = app_js.split("async function loadStorageStats()", 1)[1].split("\n}\n", 1)[0]
    assert "window.renderKeptForCases(stats)" in body
    assert body.index("storage-stat-allocated") < body.index("window.renderKeptForCases(stats)") \
        < body.index("} catch (error)")
    js = (ROOT / "static" / "js" / "compliance.js").read_text(encoding="utf-8")
    fn = js.split("function renderKeptForCases(stats)", 1)[1].split("\n    }\n", 1)[0]
    assert "stats.kept_for_cases" in fn and "'Kept for cases: '" in fn and "line.remove()" in fn
    assert "counted in the deployment" in fn and "in no vault" in fn
    assert "innerHTML" not in js
    assert "window.renderKeptForCases = renderKeptForCases;" in js
