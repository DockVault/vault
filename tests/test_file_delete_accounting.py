"""A deleted file's size comes off its vault's counters once, whoever deletes it.

A vault's ``total_size_bytes`` is what its size limit is checked against. Three paths delete a file
row and take its size off: a delete (web, SFTP, a folder's, a move's source), a same-name
replacement, and the expiry sweep. The sweep locks the vault row and then the file row; the other two
read the row without a lock, took its size off, then deleted it -- so when the sweep deleted the same
file in between, both took the size off, and the vault got room under its limit that it did not have.

Now each of them locks the vault row and then the file row, as the sweep does, and takes off only the
size of a row it still finds under that lock. These drive the real ``delete_file``,
``_stage_same_name_replacement`` and ``cleanup_expired_files`` against an in-memory session
(tests/_memory_db.py), with the sweep let in at the exact moment the others go for the lock.
"""
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest

from _memory_db import MemoryDB
from app.core import file_expiry
from app.core.models import File, Vault

pytestmark = pytest.mark.unit


class _Storage:
    def __init__(self, log):
        self.log = log

    def secure_delete(self, path):
        self.log.append(("destroy", path.name))
        path.unlink()


class _Allow:
    def require_vault_permission(self, user, vault_id, perm):
        return None


def _service(db, root, totals):
    from app.services.vault_service import VaultService
    svc = VaultService.__new__(VaultService)
    svc.db, svc.storage_path = db, root
    svc.encrypted_storage = _Storage(db.log)
    svc.permission_service = _Allow()

    def _record(vault_id, size_delta, count_delta):
        size, count = totals.get(vault_id, (0, 0))
        totals[vault_id] = (size + size_delta, count + count_delta)

    svc._adjust_vault_totals_by_id = _record
    return svc


def _world(tmp_path, *, expired):
    vault = SimpleNamespace(id=uuid.uuid4(), expire_files_after_days=1, expire_files_unit="days",
                            type="zero_knowledge")
    now = file_expiry.utc_now()
    f = SimpleNamespace(id=uuid.uuid4(), vault_id=vault.id, folder_id=None, size_bytes=40,
                        storage_path=f"blob-{uuid.uuid4().hex}", name_bi="bi-1",
                        expires_at=now - timedelta(minutes=1) if expired else None,
                        updated_at=now, created_at=now, vault=vault)
    (tmp_path / f.storage_path).write_bytes(b"x" * f.size_bytes)
    db = MemoryDB({Vault: [vault], File: [f]})
    return db, vault, f


def _sweep_gets_there_first(db, tmp_path, totals):
    """At the moment the path under test asks for its first lock, the sweep runs to its commit."""
    sweeper = _service(db, tmp_path, totals)
    db.on_lock.append(lambda: sweeper.cleanup_expired_files())


def _locks(db):
    return [(e[1], e[2]) for e in db.log if e[0] == "lock"]


# ---------------------------------------------------------------------------------------------
# delete_file
# ---------------------------------------------------------------------------------------------


def test_a_delete_takes_the_size_off_once_after_locking_the_vault_then_the_file(tmp_path):
    db, vault, f = _world(tmp_path, expired=False)
    totals = {}
    _service(db, tmp_path, totals).delete_file(f.id, user=object())

    assert totals == {vault.id: (-40, -1)}
    assert db.rows_of(File) == []
    assert _locks(db) == [(Vault, {"key_share": True}), (File, {})]
    order = [e[0] for e in db.log]
    assert order.index("commit") < order.index("destroy"), "bytes go only after the commit"


def test_a_delete_the_sweep_beat_takes_nothing_off_and_answers_not_found(tmp_path):
    from app.services.vault_service import FileNotFoundError as VaultFileNotFound
    db, vault, f = _world(tmp_path, expired=True)
    totals = {}
    _sweep_gets_there_first(db, tmp_path, totals)

    with pytest.raises(VaultFileNotFound):
        _service(db, tmp_path, totals).delete_file(f.id, user=object())
    # The sweep deleted the row and took its size off; the delete took nothing more.
    assert totals == {vault.id: (-40, -1)}
    assert [e for e in db.log if e[0] == "orm-delete"] == []


# ---------------------------------------------------------------------------------------------
# A same-name replacement
# ---------------------------------------------------------------------------------------------


def test_a_replacement_takes_the_old_size_off_once_under_the_same_locks(tmp_path):
    db, vault, f = _world(tmp_path, expired=False)
    totals = {}
    paths = _service(db, tmp_path, totals)._stage_same_name_replacement(
        vault, vault.id, None, name_bi="bi-1")

    assert paths == [f.storage_path]
    assert totals == {vault.id: (-40, -1)}
    assert db.rows_of(File) == [] and ("flush",) in db.log
    assert _locks(db) == [(Vault, {"key_share": True}), (File, {"of": File})]


def test_a_replacement_the_sweep_beat_takes_nothing_off(tmp_path):
    db, vault, f = _world(tmp_path, expired=True)
    totals = {}
    _sweep_gets_there_first(db, tmp_path, totals)

    paths = _service(db, tmp_path, totals)._stage_same_name_replacement(
        vault, vault.id, None, name_bi="bi-1")
    assert paths == [], "nothing of the old file is left for the replacement to remove"
    assert totals == {vault.id: (-40, -1)}
    assert [e for e in db.log if e[0] == "orm-delete"] == []
