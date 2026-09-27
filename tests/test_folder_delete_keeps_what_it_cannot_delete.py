"""A folder is deleted only once every file in it has been, each as a file delete is.

Deleting a folder row takes the file rows in it along (files.folder_id cascades), and the cascade does
none of what a file delete must: the file's stored bytes stay on disk, and its size and count stay in
the vault's counters. The web folder delete and SFTP rmdir used to delete each file, swallow a failure,
and delete the folder anyway -- so a file whose own delete failed went with the folder, its bytes
orphaned and its size still counted against the vault's limit. A file uploaded into the folder while
its files were being deleted went the same way.

Now the files go first, each through delete_file; the first one that cannot be deleted stops it, and
the folders are deleted only once they are locked and hold no file. These drive the real
delete_folder_tree, the web route and the SFTP handler against an in-memory session
(tests/_memory_db.py) in which a row somebody else holds locked makes a locking read time out, and
the failed statement leaves the transaction unusable until a rollback -- as Postgres does.
"""
import contextlib
import inspect
import json
import shutil
import subprocess
import uuid
from pathlib import Path
from types import SimpleNamespace

import paramiko
import pytest
from fastapi import HTTPException

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

set_bare_api_env()

from app.core.authorization import PermissionDeniedError  # noqa: E402
from app.core.models import File, Folder, Vault  # noqa: E402
from app.services.vault_service import FolderDeletion, FolderNotFoundError  # noqa: E402

pytestmark = pytest.mark.unit

APP_JS = Path(__file__).resolve().parent.parent / "static" / "js" / "app.js"


class _Storage:
    def __init__(self, log):
        self.log = log

    def secure_delete(self, path):
        self.log.append(("destroy", path.name))
        path.unlink()


class _Allow:
    def require_vault_permission(self, user, vault_id, perm):
        return None

    def can_access_vault(self, user, vault_id, perm):
        return True


class _Deny(_Allow):
    def require_vault_permission(self, user, vault_id, perm):
        raise PermissionDeniedError("no")


def _service(db, root, totals, permissions=None):
    from app.services.vault_service import VaultService
    svc = VaultService.__new__(VaultService)
    svc.db, svc.storage_path = db, root
    svc.encrypted_storage = _Storage(db.log)
    svc.permission_service = permissions or _Allow()

    def _record(vault_id, size_delta, count_delta):
        size, count = totals.get(vault_id, (0, 0))
        totals[vault_id] = (size + size_delta, count + count_delta)

    svc._adjust_vault_totals_by_id = _record
    return svc


def _world(tmp_path):
    """Folder A holds a1 and a2 and the subfolder B; B holds b1 and the subfolder C; C holds c1. D is
    another folder (d1), and r1 is at the vault root. The file ids sort a1 < a2 < b1 < c1, the order
    the files are deleted in."""
    vault = SimpleNamespace(id=uuid.uuid4())
    other = SimpleNamespace(id=uuid.uuid4())

    def folder(name, parent, vault_id=vault.id):
        return SimpleNamespace(id=uuid.uuid4(), vault_id=vault_id, name=name,
                               parent_folder_id=parent.id if parent else None)

    A = folder("A", None)
    B = folder("B", A)
    C = folder("C", B)
    D = folder("D", None)
    X = folder("X", None, vault_id=other.id)

    def file(n, where, size):
        f = SimpleNamespace(id=uuid.UUID(int=n), vault_id=vault.id,
                            folder_id=where.id if where else None, size_bytes=size,
                            storage_path=f"blob-{n}")
        (tmp_path / f.storage_path).write_bytes(b"x" * size)
        return f

    files = {"a1": file(1, A, 10), "a2": file(2, A, 20), "b1": file(3, B, 40),
             "c1": file(4, C, 80), "d1": file(5, D, 160), "r1": file(6, None, 320)}
    folders = {"A": A, "B": B, "C": C, "D": D, "X": X}
    db = MemoryDB({Vault: [vault, other], Folder: list(folders.values()), File: list(files.values())})
    return db, vault, folders, files


def _left(db, model):
    return {r.id for r in db.rows_of(model)}


def _ids(rows):
    return {r.id for r in rows}


def _blobs(tmp_path):
    return sorted(p.name for p in tmp_path.iterdir())


def _deletes_of(db, model):
    return [e for e in db.log if e[0] == "delete" and e[1] is model]


# ---------------------------------------------------------------------------------------------
# delete_folder_tree
# ---------------------------------------------------------------------------------------------


def test_a_folder_goes_with_its_subfolders_once_every_file_in_them_has(tmp_path):
    db, vault, folders, files = _world(tmp_path)
    totals = {}
    outcome = _service(db, tmp_path, totals).delete_folder_tree(vault.id, folders["A"].id, object())

    assert outcome == FolderDeletion(deleted=4, left=0, folder_deleted=True)
    assert _left(db, Folder) == _ids([folders["D"], folders["X"]])
    assert _left(db, File) == _ids([files["d1"], files["r1"]])
    assert totals == {vault.id: (-150, -4)}, "each file's size came off once, by its own delete"
    assert _blobs(tmp_path) == ["blob-5", "blob-6"]
    # The folders go last, in one statement, after the vault row and then every level of the tree
    # was locked -- so nothing could be added under them in between.
    last_file_commit = max(i for i, e in enumerate(db.log) if e == ("commit",) and i < len(db.log) - 1)
    tail = [e for e in db.log[last_file_commit + 1:] if e[0] in ("lock", "delete")]
    assert tail[0] == ("lock", Vault, {"key_share": True})
    assert all(e == ("lock", Folder, {}) for e in tail[1:-1]) and len(tail[1:-1]) >= 3
    assert tail[-1] == ("delete", Folder, 3)
    assert db.log[-1] == ("commit",)


def test_a_file_that_cannot_be_deleted_stops_the_delete_and_keeps_the_folder(tmp_path):
    """Somebody holds b1's row locked, past the lock timeout. a1 and a2 were deleted before it; b1,
    c1 (not reached) and every folder stay, and nothing is taken off the counters for them."""
    db, vault, folders, files = _world(tmp_path)
    db.held = {files["b1"].id}
    totals = {}
    outcome = _service(db, tmp_path, totals).delete_folder_tree(vault.id, folders["A"].id, object())

    assert outcome == FolderDeletion(deleted=2, left=2, folder_deleted=False)
    assert _left(db, Folder) == _ids(folders.values())
    assert _left(db, File) == _ids([files["b1"], files["c1"], files["d1"], files["r1"]])
    assert totals == {vault.id: (-30, -2)}
    assert _blobs(tmp_path) == ["blob-3", "blob-4", "blob-5", "blob-6"]
    assert _deletes_of(db, Folder) == []
    # The failed statement left the transaction unusable; it was rolled back, not carried on in.
    timeout = db.log.index(("lock-timeout", File))
    assert db.log[timeout + 1] == ("rollback",) and not db.aborted
    assert "2 files in it could not be removed" in outcome.refusal()


def test_a_file_uploaded_while_the_files_were_deleted_keeps_the_folder(tmp_path):
    """Every file the delete found went, but one arrived in B after it looked: the folders are
    counted again once locked, and a folder that holds a file is not deleted."""
    db, vault, folders, files = _world(tmp_path)
    totals = {}
    svc = _service(db, tmp_path, totals)
    newcomer = SimpleNamespace(id=uuid.UUID(int=99), vault_id=vault.id, folder_id=folders["B"].id,
                               size_bytes=5, storage_path="blob-99")
    (tmp_path / "blob-99").write_bytes(b"x" * 5)
    real = svc.delete_file

    def delete_then_an_upload_lands(file_id, user):
        real(file_id, user)
        if file_id == files["c1"].id:
            db.rows_of(File).append(newcomer)
    svc.delete_file = delete_then_an_upload_lands

    outcome = svc.delete_folder_tree(vault.id, folders["A"].id, object())

    assert outcome == FolderDeletion(deleted=4, left=1, folder_deleted=False)
    assert _left(db, Folder) == _ids(folders.values())
    assert newcomer.id in _left(db, File) and (tmp_path / "blob-99").exists()
    assert totals == {vault.id: (-150, -4)}
    assert _deletes_of(db, Folder) == []


def test_a_file_someone_else_deleted_meanwhile_does_not_stop_it(tmp_path):
    """b1 goes (the expiry sweep, another request) before the delete reaches it: not a failure, and
    its size is not taken off a second time."""
    db, vault, folders, files = _world(tmp_path)
    totals = {}
    db.on_lock.append(lambda: db.rows_of(File).remove(files["b1"]))
    outcome = _service(db, tmp_path, totals).delete_folder_tree(vault.id, folders["A"].id, object())

    assert outcome == FolderDeletion(deleted=3, left=0, folder_deleted=True)
    assert totals == {vault.id: (-110, -3)}
    assert _left(db, Folder) == _ids([folders["D"], folders["X"]])


def test_a_file_the_caller_may_not_delete_stops_it_and_is_raised(tmp_path):
    db, vault, folders, files = _world(tmp_path)
    totals = {}
    with pytest.raises(PermissionDeniedError):
        _service(db, tmp_path, totals, _Deny()).delete_folder_tree(vault.id, folders["A"].id, object())
    assert _left(db, File) == _ids(files.values()) and _left(db, Folder) == _ids(folders.values())
    assert totals == {}


def test_a_folder_of_another_vault_is_not_found_and_nothing_is_deleted(tmp_path):
    db, vault, folders, files = _world(tmp_path)
    totals = {}
    with pytest.raises(FolderNotFoundError):
        _service(db, tmp_path, totals).delete_folder_tree(vault.id, folders["X"].id, object())
    assert _left(db, Folder) == _ids(folders.values()) and totals == {}


# ---------------------------------------------------------------------------------------------
# The web route and SFTP rmdir
# ---------------------------------------------------------------------------------------------


class _Audit:
    def __init__(self):
        self.rows = []

    def log_action(self, **kw):
        self.rows.append(kw)


@pytest.fixture
def monitor(monkeypatch):
    import app.services.security_monitor as SM
    fed = []
    monkeypatch.setattr(SM, "get_security_monitor", lambda db: SimpleNamespace(
        record_file_deletion=lambda user_id, vault_id, file_count: fed.append(file_count)))
    return fed


def _web_delete(monkeypatch, tmp_path, *, held=()):
    import app.api.api_server as S

    db, vault, folders, files = _world(tmp_path)
    db.held = {files[name].id for name in held}
    totals = {}
    svc = _service(db, tmp_path, totals)
    svc.get_vault = lambda *a, **k: vault
    audit = _Audit()
    monkeypatch.setattr(S, "PermissionService", lambda db: _Allow())
    monkeypatch.setattr(S, "VaultService", lambda db, permissions: svc)
    monkeypatch.setattr(S, "AuditLogger", lambda db: audit)
    monkeypatch.setattr(S, "require_folder_scope", lambda *a, **k: None)
    monkeypatch.setattr(S, "get_client_ip", lambda request: "203.0.113.9")
    call = inspect.unwrap(S.delete_folder)(
        vault_id=vault.id, folder_id=folders["A"].id, request=None,
        current_user=SimpleNamespace(id=uuid.uuid4()), db=db, x_vault_password=None)
    return call, db, folders, files, totals, audit


def test_the_web_delete_answers_409_naming_the_files_left_and_keeps_the_folder(monkeypatch, tmp_path, monitor):
    call, db, folders, files, totals, audit = _web_delete(monkeypatch, tmp_path, held=("b1",))
    with pytest.raises(HTTPException) as answered:
        run_coroutine(call)

    assert answered.value.status_code == 409
    assert "2 files" in answered.value.detail
    assert _left(db, Folder) == _ids(folders.values())
    assert {files["b1"].id, files["c1"].id} <= _left(db, File)
    (row,) = audit.rows
    assert (row["action"], row["status"]) == ("folder_delete", "failure")
    assert (row["details"]["files_deleted"], row["details"]["files_left"]) == (2, 2)
    assert monitor == [2], "the two files that were deleted still reach the bulk-deletion detector"


def test_the_web_delete_of_a_folder_whose_files_all_go_succeeds(monkeypatch, tmp_path, monitor):
    call, db, folders, files, totals, audit = _web_delete(monkeypatch, tmp_path)
    assert run_coroutine(call) == {"message": 'Folder "A" deleted'}
    assert _left(db, Folder) == _ids([folders["D"], folders["X"]])
    (row,) = audit.rows
    assert (row["action"], row["status"]) == ("folder_delete", "success")
    assert monitor == [4]


def _sftp_rmdir(monkeypatch, tmp_path, *, held=()):
    from app.sftp import sftp_server as mod

    db, vault, folders, files = _world(tmp_path)
    db.held = {files[name].id for name in held}
    vault.name = "V"
    totals = {}
    svc = _service(db, tmp_path, totals)
    user = SimpleNamespace(id=uuid.uuid4())

    @contextlib.contextmanager
    def session():
        yield db
    monkeypatch.setattr(mod, "get_db_context", session)
    monkeypatch.setattr(mod, "VaultService", lambda db, permissions: svc)
    monkeypatch.setattr(mod, "PermissionService", lambda db: _Allow())
    audited = []
    interface = mod.SFTPServerInterface(server=object())
    interface._check_session_valid = lambda: True
    interface._load_principal = lambda db: user
    interface._resolve_vault = lambda service, user, segment: vault
    interface._has_cap = lambda user, vault_id, cap: True
    interface._resolve_folder = lambda db, vault_id, segments: folders["A"].id
    interface._scope_ok_folder = lambda db, user, vault_id, folder_id: True
    interface._audit = lambda user, action, resource_id, details, status="success": audited.append(
        (action, status, details))
    return interface.rmdir("/V/A"), db, folders, files, audited


def test_sftp_rmdir_fails_and_keeps_the_folder_when_a_file_cannot_be_deleted(monkeypatch, tmp_path, monitor):
    answer, db, folders, files, audited = _sftp_rmdir(monkeypatch, tmp_path, held=("b1",))

    assert answer == paramiko.SFTP_FAILURE
    assert _left(db, Folder) == _ids(folders.values())
    assert {files["b1"].id, files["c1"].id} <= _left(db, File)
    ((action, status, details),) = audited
    assert (action, status) == ("folder_delete", "failure")
    assert (details["files_deleted"], details["files_left"]) == (2, 2)
    assert monitor == [2]


def test_sftp_rmdir_of_a_folder_whose_files_all_go_succeeds(monkeypatch, tmp_path, monitor):
    answer, db, folders, files, audited = _sftp_rmdir(monkeypatch, tmp_path)

    assert answer == paramiko.SFTP_OK
    assert _left(db, Folder) == _ids([folders["D"], folders["X"]])
    assert [(a, s) for a, s, _ in audited] == [("folder_delete", "success")]
    assert monitor == [4]


# ---------------------------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------------------------


def _function(js, name):
    """One top-level function of app.js, verbatim, from its head to its closing brace."""
    for head in (f"\nasync function {name}(", f"\nfunction {name}("):
        start = js.find(head)
        if start >= 0:
            return js[start + 1:js.index("\n}\n", start) + 3]
    raise AssertionError(f"no function {name} in app.js")


def _node(harness):
    node = shutil.which("node")
    assert node, "Node is required: the shipped page code must not be skipped"
    done = subprocess.run([node, "-"], input=harness, capture_output=True, text=True,
                          encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


def test_the_page_says_why_a_folder_was_kept_and_shows_what_is_left():
    """A 409 from a folder delete carries what happened: the folder was kept, some of its files may
    be gone. The page shows that message and reloads the listing; any other failure keeps the old
    generic message, and so does a file delete's."""
    js = _function(APP_JS.read_text(encoding="utf-8"), "deleteVaultItem")
    out = _node("""
const said = []; let reloaded = 0; let answer = null;
const state = { currentVault: { id: 'V', has_password: false } };
const showConfirm = async () => true;
const showInfo = () => {};
const showSuccess = (m) => said.push(['success', m]);
const showError = (m) => said.push(['error', m]);
const loadVaultFiles = async () => { reloaded += 1; };
const apiRequest = async () => { if (answer) throw answer; return {}; };
console.error = () => {};
%s
const failing = (message, status) => { const e = new Error(message); e.status = status; return e; };
(async () => {
    const out = {};
    for (const [key, error, id, type] of [
        ['kept', failing('The folder was kept: 1 file in it could not be removed. Nothing was deleted.', 409), 'F', 'folder'],
        ['broken', failing('Server error', 500), 'F', 'folder'],
        ['file', failing('A file conflict', 409), 'A', 'file'],
    ]) {
        answer = error; said.length = 0; reloaded = 0;
        await deleteVaultItem(id, 'name', type);
        out[key] = { said: said.slice(), reloaded };
    }
    process.stdout.write(JSON.stringify(out));
})();
""" % js)
    assert out["kept"] == {"said": [["error", "The folder was kept: 1 file in it could not be removed. "
                                               "Nothing was deleted."]], "reloaded": 1}
    assert out["broken"] == {"said": [["error", "Failed to delete item"]], "reloaded": 0}
    assert out["file"] == {"said": [["error", "Failed to delete item"]], "reloaded": 0}
