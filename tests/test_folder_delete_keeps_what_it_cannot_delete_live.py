"""Live: a folder delete that cannot delete one of its files keeps the folder, and loses nothing.

Deleting a folder row takes the file rows in it along (files.folder_id cascades), leaving each such
file's stored bytes on disk and its size in the vault's counters. So a folder delete -- the web route
and SFTP rmdir -- deletes every file first, each as a file delete does, stops at the first one it
cannot delete, and deletes the folders only once they are locked and hold no file.

Two ways a file can be in the way, both made real against the stack's Postgres from a psql session:

- A file's row is held locked past the app's lock timeout, so its delete fails. The files before it
  (in id order) are deleted; that file, the ones after it and the folders stay. The web route
  answers 409 naming how many files are left; SFTP rmdir fails.
- A file is moved into the folder while its files are being deleted: the move's transaction is open
  when the delete gets to the folders, and commits while the delete waits for the folder's lock. The
  folder is kept with that file in it, instead of being deleted and taking the file's row along.

After each, what is stored must add up: the vault's file count and size equal its rows, every row's
bytes are on disk, and the bytes of every deleted file are gone. Then, with nothing in the way, the
same delete succeeds and leaves nothing behind.
"""
import os
import subprocess
import threading
import time

import pytest

from conftest import ADMIN_PASS, ADMIN_USER, unique

paramiko = pytest.importorskip("paramiko")

pytestmark = pytest.mark.integration

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_API = os.environ.get("VAULT_API_CONTAINER", "vault-api")
SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))


def _psql(sql):
    r = subprocess.run(
        ["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return (r.stdout or "").strip()


def _rows(sql):
    return [line.split("|") for line in _psql(sql).splitlines() if line]


class _OpenTransaction:
    """A psql session that runs `statements` in a transaction and keeps it open until it is
    committed or rolled back -- another client's work in flight, as the stack's Postgres sees it."""

    def __init__(self, statements):
        self.statements = statements
        self.marker = unique("held")
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            ["docker", "exec", "-i", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-q",
             "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.proc.stdin.write(f"BEGIN;\n{self.statements} /* {self.marker} */;\n".encode())
        self.proc.stdin.flush()
        deadline = time.time() + 30
        while time.time() < deadline:
            if _psql("SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction' "
                     f"AND query LIKE '%{self.marker}%'") == "1":
                return self
            if self.proc.poll() is not None:
                break
            time.sleep(0.2)
        self.end("ROLLBACK")
        raise AssertionError("the psql session never got its transaction open")

    def end(self, how):
        if self.proc is None:
            return
        try:
            self.proc.stdin.write(f"{how};\n\\q\n".encode())
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc = None

    def __exit__(self, *exc):
        self.end("ROLLBACK")


def _upload(client, vid, name, content, folder_id):
    r = client.post(f"/vaults/{vid}/files", params={"folder_id": folder_id},
                    files=[("files", (name, content, "text/plain"))])
    assert r.status_code in (200, 201), r.text
    return r.json()["files"][0]["id"]


def _folder(client, vid, name, parent=None):
    body = {"name": name}
    if parent:
        body["parent_folder_id"] = parent
    r = client.post(f"/vaults/{vid}/folders", json=body)
    assert r.status_code == 200, r.text
    return r.json()["folder"]["id"]


def _world(client):
    """A vault with folder F (two files) holding subfolder S (two files), and one file elsewhere, in
    folder O. Sizes differ so a size counted twice or not at all shows."""
    vault = client.create_vault(name=unique("fdel"))
    vid = vault["id"]
    top = _folder(client, vid, "F")
    sub = _folder(client, vid, "S", parent=top)
    other = _folder(client, vid, "O")
    for i, (where, size) in enumerate([(top, 11), (top, 222), (sub, 3333), (sub, 44444)]):
        _upload(client, vid, f"f{i}.txt", b"x" * size, where)
    outside = _upload(client, vid, "outside.txt", b"y" * 55555, other)
    return vault, top, sub, other, outside


def _tree_files(top, sub):
    """The tree's file ids in the order the delete takes them (by id), with their stored paths."""
    return _rows(f"SELECT id, storage_path FROM files WHERE folder_id IN ('{top}', '{sub}') ORDER BY id")


def _blob_exists(rel):
    return subprocess.run(["docker", "exec", _API, "test", "-e", f"storage/{rel}"],
                          capture_output=True).returncode == 0


def _assert_adds_up(vid, deleted_paths):
    """The vault's counters equal its rows, every row's bytes are on disk, and the bytes of the
    files that were deleted are not."""
    counted = _rows(f"SELECT file_count, total_size_bytes FROM vaults WHERE id = '{vid}'")[0]
    stored = _rows(f"SELECT count(*), coalesce(sum(size_bytes), 0) FROM files WHERE vault_id = '{vid}'")[0]
    assert counted == stored, f"the vault counts {counted} (files, bytes) but holds {stored}"
    for (rel,) in _rows(f"SELECT storage_path FROM files WHERE vault_id = '{vid}'"):
        assert _blob_exists(rel), "a file row whose bytes are gone"
    for rel in deleted_paths:
        assert not _blob_exists(rel), "a deleted file's bytes were left on disk"


def _folders_left(*ids):
    listed = ", ".join(f"'{i}'" for i in ids)
    return int(_psql(f"SELECT count(*) FROM folders WHERE id IN ({listed})"))


def _last_folder_delete_audit(folder_id):
    return _psql("SELECT status FROM audit_logs WHERE action = 'folder_delete' "
                 f"AND resource_id = '{folder_id}' ORDER BY timestamp DESC LIMIT 1")


@pytest.fixture
def world(admin):
    made = _world(admin)
    yield made
    admin.delete_vault(made[0]["id"])


def test_a_web_folder_delete_stops_at_a_file_it_cannot_delete_and_keeps_the_rest(admin, world):
    vault, top, sub, other, outside = world
    vid = vault["id"]
    files = _tree_files(top, sub)
    assert len(files) == 4
    (held_id, _), later = files[2], files[3]

    with _OpenTransaction(f"SELECT id FROM files WHERE id = '{held_id}' FOR UPDATE"):
        r = admin.post(f"/vaults/{vid}/folders/{top}/delete")
        assert r.status_code == 409, r.text
        assert "2 files" in r.json()["detail"], r.text

    assert _folders_left(top, sub) == 2, "the folders were deleted with a file still in them"
    left = {fid for fid, _ in _rows(f"SELECT id, 1 FROM files WHERE folder_id IN ('{top}', '{sub}')")}
    assert left == {held_id, later[0]}, "only the files before the held one were deleted"
    _assert_adds_up(vid, [files[0][1], files[1][1]])
    assert _last_folder_delete_audit(top) == "failure"

    # Nothing in the way now: the same delete goes through, and leaves nothing behind.
    r = admin.post(f"/vaults/{vid}/folders/{top}/delete")
    assert r.status_code == 200, r.text
    assert _folders_left(top, sub) == 0
    assert _psql(f"SELECT count(*) FROM files WHERE vault_id = '{vid}'") == "1"
    _assert_adds_up(vid, [rel for _, rel in files])
    assert _last_folder_delete_audit(top) == "success"


@pytest.mark.sftp
def test_sftp_rmdir_stops_at_a_file_it_cannot_delete_and_keeps_the_rest(admin, world):
    vault, top, sub, other, outside = world
    vid = vault["id"]
    files = _tree_files(top, sub)
    (held_id, _), later = files[2], files[3]

    transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    transport.banner_timeout = 30
    try:
        transport.connect(username=ADMIN_USER, password=ADMIN_PASS)
        sftp = paramiko.SFTPClient.from_transport(transport)
        with _OpenTransaction(f"SELECT id FROM files WHERE id = '{held_id}' FOR UPDATE"):
            with pytest.raises(IOError):
                sftp.rmdir(f"/{vault['name']}/F")

        assert _folders_left(top, sub) == 2, "the folders were deleted with a file still in them"
        left = {fid for fid, _ in _rows(f"SELECT id, 1 FROM files WHERE folder_id IN ('{top}', '{sub}')")}
        assert left == {held_id, later[0]}, "only the files before the held one were deleted"
        _assert_adds_up(vid, [files[0][1], files[1][1]])
        assert _last_folder_delete_audit(top) == "failure"

        sftp.rmdir(f"/{vault['name']}/F")
    finally:
        transport.close()
    assert _folders_left(top, sub) == 0
    _assert_adds_up(vid, [rel for _, rel in files])
    assert _last_folder_delete_audit(top) == "success"


def _wait_for_a_lock_wait_on_folders(worker, seconds=20):
    """Until a session other than the psql one is waiting for a lock in a statement on folders."""
    deadline = time.time() + seconds
    while time.time() < deadline and worker.is_alive():
        if _psql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                 "AND query ILIKE '%folders%' AND pid <> pg_backend_pid()") != "0":
            return True
        time.sleep(0.05)
    return False


def test_a_file_moved_in_while_the_folder_is_deleted_keeps_the_folder(admin, world):
    vault, top, sub, other, outside = world
    vid = vault["id"]
    files = _tree_files(top, sub)
    moved_blob = _psql(f"SELECT storage_path FROM files WHERE id = '{outside}'")

    answer = {}
    worker = threading.Thread(target=lambda: answer.setdefault(
        "r", admin.post(f"/vaults/{vid}/folders/{top}/delete")))
    # The statement a move within a vault runs: the file's folder changes, in a transaction that has
    # not committed when the delete starts, so the delete does not see it among the folder's files.
    with _OpenTransaction(f"UPDATE files SET folder_id = '{sub}' WHERE id = '{outside}'") as move:
        worker.start()
        waited = _wait_for_a_lock_wait_on_folders(worker)
        move.end("COMMIT")
    worker.join(60)
    assert waited, "the delete never waited on the folders while the move was open"
    r = answer["r"]
    assert r.status_code == 409, r.text
    assert "1 file" in r.json()["detail"], r.text

    assert _folders_left(top, sub) == 2, "the folder was deleted with the moved file in it"
    assert _psql(f"SELECT folder_id FROM files WHERE id = '{outside}'") == sub
    assert _blob_exists(moved_blob)
    _assert_adds_up(vid, [rel for _, rel in files])

    r = admin.post(f"/vaults/{vid}/folders/{top}/delete")
    assert r.status_code == 200, r.text
    assert _psql(f"SELECT count(*) FROM files WHERE vault_id = '{vid}'") == "0"
    _assert_adds_up(vid, [moved_blob])
