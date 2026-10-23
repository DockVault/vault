"""The blob gate: no committed blob a legal hold keeps is destroyed (app/services/vault_service.py, _destroy_blobs).

Every destruction of a committed blob goes through VaultService._destroy_blobs (and a deleted vault's directory
through _destroy_vault_dir), which asks the kept table first and skips what a hold keeps, before secure_delete and
before delete_file's fallback overwrite. When it cannot ask, it destroys nothing. Each path is driven here against a
real (SQLite) database: delete_file, its fallback after an injected secure_delete failure, a same-name
replacement's _remove_blobs, the expiry sweep, and a vault's deletion. On SQLite no trigger fills the kept table, so
each test writes the kept row the trigger would have written; test_kept_tables_live.py has the trigger.

And the static half: every unlink, rmtree, os.remove, rmdir and secure_delete call in the application is
classified (a committed-blob destroyer, which must be the gate; upload staging; a new blob no committed row points
to; not vault content). A call that is in no class fails, so a new deletion path cannot bypass the gate unseen.
"""
import ast
import tempfile
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

# --------------------------------------------------------------------------- the classification

# (file, enclosing function) -> the destructive calls in it, by the callee's text, and why each may destroy.
GATE = "the gate: a committed blob, after the kept table is asked"
STAGING = "upload staging: never a committed blob"
NEW_BLOB = "a new blob no committed row points to (a failed upload's own)"
NOT_CONTENT = "not vault content"
SECURE_DELETE = "secure_delete itself"

CLASSIFIED = {
    ("app/services/vault_service.py", "VaultService._destroy_blobs"): (
        ["self.encrypted_storage.secure_delete", "blob.unlink", "blob.unlink"], GATE),
    ("app/services/vault_service.py", "VaultService._destroy_vault_dir"): (["shutil.rmtree"], GATE),
    ("app/api/api_server.py", "receiver_upload_chunk"): (["hash_path.unlink", "tmp_path.unlink"], STAGING),
    ("app/api/api_server.py", "receiver_complete_upload"): (["shutil.rmtree"] * 3, STAGING),
    ("app/api/api_server.py", "_sweep_orphaned_upload_chunks"): (["shutil.rmtree"], STAGING),
    ("app/api/api_server.py", "upload_chunk"): (["hash_path.unlink", "tmp_path.unlink"], STAGING),
    ("app/api/api_server.py", "_complete_chunked_upload"): (["shutil.rmtree"] * 2, STAGING),
    ("app/api/api_server.py", "cancel_chunked_upload"): (["shutil.rmtree"], STAGING),
    ("app/core/chunk_cleanup.py", "fail_chunk_session"): (["shutil.rmtree"], STAGING),
    ("app/services/streaming_upload.py", "receive_bounded"): (["dest_path.unlink"], STAGING),
    ("app/services/streaming_upload.py", "StreamingUploadContext.__exit__"): (["self.storage_path.unlink"], STAGING),
    ("app/core/upload_chunk_crypto.py", "seal_stream_to_file"): (["dest_path.unlink"], STAGING),
    ("app/sftp/sftp_server.py", "VaultSFTPHandle.close"): (["os.remove"], STAGING),
    ("app/sftp/sftp_server.py", "_sweep_sftp_tmp"): (["f.unlink"], STAGING),
    ("app/sftp/sftp_server.py", "_StreamingUpload.close"): (["orphan.unlink"], NEW_BLOB),
    ("app/sftp/sftp_server.py", "SFTPServerInterface._make_upload_finalizer._finalize"): (["orphan.unlink"], NEW_BLOB),
    # A failed write's temporary file, a new image the setting never came to name, and the slot's old one.
    ("app/api/api_server.py", "upload_brand_asset"): (["os.remove"] * 3, NOT_CONTENT),
    ("app/api/api_server.py", "reset_brand_asset"): (["os.remove"], NOT_CONTENT),
    ("app/core/admin_password_hygiene.py", "scrub_bootstrap_password_source"): (["os.remove"], NOT_CONTENT),
    ("app/core/health.py", "check_storage_status"): (["os.remove"], NOT_CONTENT),
    # The audit chain's head record: the temporary file a failed write leaves, and the restore mark once accepted;
    # and an SFTP host key's temporary copy (once the key has its path, or when it could not be synced), and a key
    # created at its path that could not be written whole.
    ("app/core/audit_head_record.py", "_write_file"): (["os.unlink"], NOT_CONTENT),
    ("app/core/audit_head_record.py", "remove_mark"): (["os.unlink"], NOT_CONTENT),
    ("app/sftp/host_key.py", "generate_ed25519_host_key"): (["os.unlink"], NOT_CONTENT),
    ("app/sftp/host_key.py", "_write_in_place"): (["os.unlink"], NOT_CONTENT),
    ("app/services/encrypted_file_storage.py", "EncryptedFileStorage.secure_delete"): (
        ["storage_path.unlink", "storage_path.unlink"], SECURE_DELETE),
}

DESTRUCTIVE = {"unlink", "rmtree", "secure_delete", "rmdir", "removedirs"}


def _is_destructive(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute):
        if func.attr in DESTRUCTIVE:
            return True
        # os.remove; a list's or a set's .remove is not a file's.
        return func.attr == "remove" and isinstance(func.value, ast.Name) and func.value.id == "os"
    return isinstance(func, ast.Name) and func.id in DESTRUCTIVE | {"remove"}


def destructive_calls(source: str) -> dict:
    """{enclosing function's dotted name: [callee text, ...]} of every destructive call in ``source``."""
    found = {}

    def visit(node, scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, scope + [child.name])
                continue
            if isinstance(child, ast.Call) and _is_destructive(child):
                found.setdefault(".".join(scope) or "<module>", []).append(ast.unparse(child.func))
            visit(child, scope)

    visit(ast.parse(source), [])
    return found


def _all_calls() -> dict:
    out = {}
    for path in sorted((ROOT / "app").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        for scope, calls in destructive_calls(path.read_text(encoding="utf-8")).items():
            out[(rel, scope)] = calls
    return out


def test_the_scan_finds_each_kind_of_call_and_ignores_a_lists_remove():
    source = ("import os, shutil\n"
              "def a(p, items):\n"
              "    p.unlink()\n    shutil.rmtree(p)\n    os.remove(p)\n    items.remove(1)\n"
              "class S:\n"
              "    def b(self, p):\n        self.store.secure_delete(p)\n        p.rmdir()\n")
    assert destructive_calls(source) == {"a": ["p.unlink", "shutil.rmtree", "os.remove"],
                                         "S.b": ["self.store.secure_delete", "p.rmdir"]}


def test_every_destructive_call_is_classified():
    found = _all_calls()
    unclassified = {k: v for k, v in found.items() if k not in CLASSIFIED}
    assert not unclassified, (
        "a call that deletes files is in no class: if it can destroy a committed blob, route it through "
        f"VaultService._destroy_blobs; otherwise classify it here: {unclassified}")
    for key, (calls, _why) in CLASSIFIED.items():
        assert sorted(found.get(key, [])) == sorted(calls), (key, found.get(key))


def test_the_committed_blob_destroyers_ask_the_kept_table_before_destroying():
    source = (ROOT / "app" / "services" / "vault_service.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    methods = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    for name, lookup in (("_destroy_blobs", "kept_rows"), ("_destroy_vault_dir", "vault_keeps")):
        body = ast.unparse(methods[name])
        first_destroy = min(body.index(word) for word in ("secure_delete(", "unlink(", "rmtree(") if word in body)
        assert body.index(f"kept_tables.{lookup}(") < first_destroy, name
    # And every path that destroys a committed blob calls them: delete_file, the replacement's _remove_blobs,
    # the expiry sweep and the vault's deletion.
    for name, gate in (("delete_file", "_destroy_blobs("), ("_remove_blobs", "_destroy_blobs("),
                       ("cleanup_expired_files", "_destroy_blobs("), ("delete_vault", "_destroy_vault_dir(")):
        assert gate in ast.unparse(methods[name]), name


# --------------------------------------------------------------------------- the gate, driven

class _Allow:
    def require_vault_permission(self, *_a, **_k):
        return None


@pytest.fixture
def world():
    from _kept_db import kept_database
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp, kept_database() as (make, _engine):
        root = Path(tmp) / "storage"
        root.mkdir()
        db = make()
        owner = m.User(id=uuid.uuid4(), username=f"o{uuid.uuid4().hex[:6]}", password_hash="x",
                       role=m.RoleEnum.USER, is_active=True)
        vault = m.Vault(id=uuid.uuid4(), name="v", owner_id=owner.id, expire_files_after_days=1,
                        expire_files_unit="days")
        db.add_all([owner, vault])
        db.commit()
        yield _World(db, root, owner, vault)
        db.close()


class _World:
    def __init__(self, db, root, owner, vault):
        self.db, self.root, self.owner, self.vault = db, root, owner, vault

    def service(self, *, secure_delete=None):
        from app.services.encrypted_file_storage import EncryptedFileStorage
        from app.services.vault_service import VaultService
        svc = VaultService.__new__(VaultService)
        svc.db, svc.storage_path, svc.permission_service = self.db, self.root, _Allow()
        svc.encrypted_storage = EncryptedFileStorage(self.root)
        if secure_delete is not None:
            svc.encrypted_storage.secure_delete = secure_delete
        return svc

    def blob(self, content=b"evidence"):
        rel = f"{self.vault.id}/{uuid.uuid4()}.enc"
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return rel

    def file(self, rel, **kw):
        f = m.File(id=uuid.uuid4(), vault_id=self.vault.id, size_bytes=8, storage_path=rel, **kw)
        self.db.add(f)
        self.db.commit()
        return f

    def keep(self, rel, file_id=None):
        """The row the database's trigger writes when a held vault's file is deleted."""
        self.db.add(m.HeldFile(id=file_id or uuid.uuid4(), vault_id=self.vault.id, storage_path=rel, size_bytes=8,
                               kept_reason="deleted", kept_at=datetime.utcnow()))
        self.db.commit()


def test_the_gate_destroys_what_no_hold_keeps_and_leaves_what_one_does(world):
    kept, gone = world.blob(), world.blob()
    world.keep(kept)
    out = world.service()._destroy_blobs([kept, gone])
    assert out == [kept]
    assert (world.root / kept).read_bytes() == b"evidence"
    assert not (world.root / gone).exists()


def test_a_kept_blob_is_recorded_as_kept(world):
    kept = world.blob()
    file_id = uuid.uuid4()
    world.keep(kept, file_id)
    world.service()._destroy_blobs([kept])
    rows = world.db.query(m.AuditLog).filter(m.AuditLog.action == "held_file_kept").all()
    assert [r.resource_id for r in rows] == [str(file_id)]


def test_when_the_kept_table_cannot_be_asked_nothing_is_destroyed(world, monkeypatch):
    a, b = world.blob(), world.blob()

    def broken(db, paths):
        raise RuntimeError("the database went away")

    monkeypatch.setattr(kept_tables, "kept_rows", broken)
    assert world.service()._destroy_blobs([a, b]) == [a, b]
    assert (world.root / a).exists() and (world.root / b).exists()


def _fail_the_transaction(world):
    """Leave the session's transaction failed, as an error inside an upload's finalize leaves it before the
    route's own rollback: a duplicate primary key on flush."""
    dup = uuid.uuid4()
    world.db.add(m.File(id=dup, vault_id=world.vault.id, size_bytes=1, storage_path="x1"))
    world.db.flush()
    world.db.expunge_all()
    world.db.add(m.File(id=dup, vault_id=world.vault.id, size_bytes=1, storage_path="x2"))
    with pytest.raises(Exception):
        world.db.flush()


def test_a_failed_uploads_new_blob_goes_although_its_transaction_had_failed(world):
    """/complete's error path removes the upload's new, never-committed blob before it rolls the session back:
    the check is asked again after a rollback, so the blob goes (nothing else would ever remove it)."""
    new_blob = world.blob(b"a new upload that failed")
    _fail_the_transaction(world)
    assert world.service()._remove_blobs([new_blob]) is None
    assert not (world.root / new_blob).exists()
    assert world.db.query(m.File).filter(m.File.storage_path.in_(["x1", "x2"])).count() == 0, "rolled back"


def test_after_a_failed_transaction_a_kept_blob_still_stays(world):
    kept, gone = world.blob(), world.blob()
    world.keep(kept)
    _fail_the_transaction(world)
    assert world.service()._destroy_blobs([kept, gone]) == [kept]
    assert (world.root / kept).read_bytes() == b"evidence" and not (world.root / gone).exists()


def test_when_the_check_fails_again_after_the_rollback_nothing_is_destroyed(world, monkeypatch):
    a = world.blob()
    asked = []

    def broken(db, paths):
        asked.append(list(paths))
        raise RuntimeError("the database went away")

    monkeypatch.setattr(kept_tables, "kept_rows", broken)
    assert world.service()._destroy_blobs([a]) == [a]
    assert (world.root / a).exists() and len(asked) == 2, "asked once more after the rollback, then kept"


def test_delete_file_leaves_a_kept_blob_and_destroys_another(world):
    kept_rel, gone_rel = world.blob(), world.blob()
    kept_file, gone_file = world.file(kept_rel), world.file(gone_rel)
    world.keep(kept_rel, kept_file.id)
    svc = world.service()
    svc.delete_file(kept_file.id, world.owner)
    svc.delete_file(gone_file.id, world.owner)
    assert (world.root / kept_rel).read_bytes() == b"evidence"
    assert not (world.root / gone_rel).exists()


def test_delete_files_fallback_after_a_secure_delete_failure_never_reaches_a_kept_blob(world):
    kept_rel, gone_rel = world.blob(), world.blob()
    kept_file, gone_file = world.file(kept_rel), world.file(gone_rel)
    world.keep(kept_rel, kept_file.id)
    attempts = []

    def failing(path):
        attempts.append(path.name)
        raise OSError("device busy")

    svc = world.service(secure_delete=failing)
    svc.delete_file(kept_file.id, world.owner)
    svc.delete_file(gone_file.id, world.owner)
    assert attempts == [Path(gone_rel).name], "secure_delete is not even tried on a kept blob"
    assert (world.root / kept_rel).read_bytes() == b"evidence"
    assert not (world.root / gone_rel).exists(), "the fallback still destroys a blob no hold keeps"


class _Disk:
    """What reached the disk, in order, from the moment it is made: each os.fsync of a file (its inode and its
    size at that moment), each unlink under the storage root (the file's name), and each commit of the world's
    session. With ``fail``, a file's sync fails as a disk that cannot write fails it."""

    def __init__(self, world, monkeypatch, *, fail=False):
        import errno
        import os
        import stat
        from sqlalchemy import event
        self.events = []
        real_fsync, real_unlink = os.fsync, Path.unlink

        def fsync(fd):
            st = os.fstat(fd)
            if stat.S_ISREG(st.st_mode):
                if fail:
                    raise OSError(errno.EIO, "Input/output error")
                self.events.append(("file", st.st_ino, st.st_size))
            return real_fsync(fd)

        def unlink(path, *a, **k):
            if Path(path).is_relative_to(world.root):
                self.events.append(("unlink", Path(path).name))
            return real_unlink(path, *a, **k)

        monkeypatch.setattr(os, "fsync", fsync)
        monkeypatch.setattr(Path, "unlink", unlink)
        event.listen(world.db, "after_commit", lambda _session: self.events.append(("commit",)))


def _secure_delete_fails(path):
    raise OSError("device busy")


def test_delete_files_fallback_overwrite_is_on_the_disk_before_the_blob_is_unlinked(world, monkeypatch):
    """The row's deletion commits first; then the fallback overwrites the blob, syncs the whole overwrite, and
    only then unlinks it: the unlink can never reach the disk ahead of the overwrite."""
    rel = world.blob(b"evidence of a deleted file")
    f = world.file(rel)
    inode, size = (world.root / rel).stat().st_ino, (world.root / rel).stat().st_size
    disk = _Disk(world, monkeypatch)
    world.service(secure_delete=_secure_delete_fails).delete_file(f.id, world.owner)
    assert disk.events == [("commit",), ("file", inode, size), ("unlink", Path(rel).name)]
    assert not (world.root / rel).exists()
    assert world.db.query(m.File).filter(m.File.id == f.id).count() == 0


def test_a_fallback_overwrite_whose_sync_fails_still_removes_the_blob_and_says_so(world, monkeypatch):
    """The row's deletion has committed, so a failed sync of the overwrite raises nothing into the request: it is
    logged as the fallback's failure, and the blob is still unlinked, as the fallback's last resort."""
    import app.services.vault_service as vs
    logged = []
    monkeypatch.setattr(vs, "safe_event", lambda code, *a, **k: logged.append(code))
    rel = world.blob()
    f = world.file(rel)
    disk = _Disk(world, monkeypatch, fail=True)
    assert world.service(secure_delete=_secure_delete_fails).delete_file(f.id, world.owner) is None
    assert logged == ["blob.secure-delete.failed-using-fallback", "blob.fallback-delete.failed"]
    assert disk.events == [("commit",), ("unlink", Path(rel).name)]
    assert not (world.root / rel).exists()


def test_a_kept_blob_is_neither_overwritten_nor_synced_nor_unlinked(world, monkeypatch):
    rel = world.blob()
    f = world.file(rel)
    world.keep(rel, f.id)
    disk = _Disk(world, monkeypatch)
    world.service(secure_delete=_secure_delete_fails).delete_file(f.id, world.owner)
    assert [e for e in disk.events if e[0] != "commit"] == []
    assert (world.root / rel).read_bytes() == b"evidence"


def test_a_blob_that_will_not_go_is_logged_under_its_paths_own_code(world, monkeypatch):
    import app.services.vault_service as vs
    logged = []
    monkeypatch.setattr(vs, "safe_event", lambda code, *a, **k: logged.append(code))

    def failing(path):
        raise OSError("device busy")

    past = datetime.utcnow() - timedelta(days=2)
    replaced, swept, plain = world.blob(), world.blob(), world.blob()
    world.file(swept, expires_at=past)
    svc = world.service(secure_delete=failing)
    svc._remove_blobs([replaced])
    svc.cleanup_expired_files()
    svc._destroy_blobs([plain])
    assert logged == ["blob.replace-cleanup.failed", "expired-blob.remove.failed", "blob.remove.failed"]
    for rel in (replaced, swept, plain):
        assert (world.root / rel).exists(), "left as an orphan, not retried"


def test_a_replacements_old_blob_is_kept_when_a_hold_keeps_it(world):
    kept, gone = world.blob(), world.blob()
    world.keep(kept)
    world.service()._remove_blobs([kept, gone])
    assert (world.root / kept).exists() and not (world.root / gone).exists()


def test_the_expiry_sweep_leaves_a_kept_blob(world):
    past = datetime.utcnow() - timedelta(days=2)
    kept_rel, gone_rel = world.blob(), world.blob()
    kept_file = world.file(kept_rel, expires_at=past)
    world.file(gone_rel, expires_at=past)
    world.keep(kept_rel, kept_file.id)
    swept = world.service().cleanup_expired_files()
    assert len(swept) == 2
    assert (world.root / kept_rel).read_bytes() == b"evidence"
    assert not (world.root / gone_rel).exists()


def test_a_deleted_vaults_directory_stays_while_anything_of_it_is_kept(world):
    rel = world.blob()
    world.keep(rel)
    vault_dir = world.root / str(world.vault.id)
    world.service()._destroy_vault_dir(world.vault.id)
    assert vault_dir.exists()
    world.db.query(m.HeldFile).delete()
    world.db.commit()
    world.service()._destroy_vault_dir(world.vault.id)
    assert not vault_dir.exists()


def test_a_deleted_vaults_directory_stays_while_a_hold_stands_on_it(world):
    world.blob()
    world.db.add(m.LegalHoldVault(case_id=uuid.uuid4(), vault_id=world.vault.id, placed_by_username="a"))
    world.db.commit()
    assert world.service()._destroy_vault_dir(world.vault.id) is False
    assert (world.root / str(world.vault.id)).exists()


def test_delete_vault_removes_its_directory_through_the_gate(world, monkeypatch):
    world.blob()
    asked = []
    real = kept_tables.vault_keeps

    def spy(db, vault_id):
        asked.append(str(vault_id))
        return real(db, vault_id)

    monkeypatch.setattr(kept_tables, "vault_keeps", spy)
    world.service().delete_vault(world.vault.id, world.owner)
    assert asked == [str(world.vault.id)]
    assert not (world.root / str(world.vault.id)).exists()


def test_when_the_vault_cannot_be_checked_its_directory_stays(world, monkeypatch):
    world.blob()

    def broken(db, vault_id):
        raise RuntimeError("the database went away")

    monkeypatch.setattr(kept_tables, "vault_keeps", broken)
    assert world.service()._destroy_vault_dir(world.vault.id) is False
    assert (world.root / str(world.vault.id)).exists()


def test_a_stand_in_session_without_a_database_keeps_nothing():
    class _NoBind:
        def get_bind(self):
            raise RuntimeError("no database")

    assert kept_tables.kept_rows(_NoBind(), ["a"]) == []
    assert kept_tables.vault_keeps(_NoBind(), uuid.uuid4()) is False
