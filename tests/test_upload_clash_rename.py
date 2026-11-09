"""A file that must neither replace nor be refused: an upload through an upload link whose name the drop vault
already holds is stored as "name (2).ext", offline.

The stored name is decided inside finalize_streaming_upload (app/services/vault_service.py), under the vault's
row lock, so a same-name upload that finished while this one was written is seen; a duplicate the insert still
meets keeps the written file, and finalize tries the row again under the next free name. The uploader's receipt
names the file as they sent it: whether it was renamed would tell an anonymous uploader which names the vault
holds. tests/test_api_upload_links_collect.py proves it on a running stack.
"""
import re
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

set_bare_api_env()

import app.services.vault_service as vs  # noqa: E402
from app.core.models import File, Vault  # noqa: E402
from app.core.security import name_blind_index  # noqa: E402

pytestmark = pytest.mark.unit

API = Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py"


# --------------------------------------------------------------------------------------------- the name itself

@pytest.mark.parametrize("name,n,expected", [
    ("report.pdf", 2, "report (2).pdf"),
    ("report.pdf", 10, "report (10).pdf"),
    ("archive.tar.gz", 2, "archive.tar (2).gz"),
    ("README", 3, "README (3)"),
    (".bashrc", 2, ".bashrc (2)"),
])
def test_a_numbered_name_keeps_the_extension(name, n, expected):
    assert vs.numbered_name(name, n) == expected


@pytest.mark.parametrize("name", [
    "a" * 300 + ".txt",            # a long stem gives way
    "a." + "y" * 300,              # an over-long "extension" is part of the stem, not kept whole
    "a" * 250 + "." + "b" * 24,    # the extension and the number would not fit: the extension goes
    "x" * 255,                     # exactly at the limit before the number
])
@pytest.mark.parametrize("n", [2, 999, 4_000_000_000])
def test_every_numbered_name_fits_and_has_a_stem(name, n):
    out = vs.numbered_name(name, n)
    assert len(out) <= 255, len(out)
    assert out.endswith(f"({n})") or f"({n})." in out
    stem = out[:out.rindex(f" ({n})")]
    assert stem and stem == stem.strip(), repr(out)


# --------------------------------------------------------------------------------------- the free name, by index

def _vault():
    return SimpleNamespace(id=uuid.uuid4(), total_size_bytes=0, size_limit=None, file_count=0,
                           expire_files_after_days=None, type="standard")


def _file(vault, name, folder_id=None):
    return SimpleNamespace(id=uuid.uuid4(), vault_id=vault.id, folder_id=folder_id,
                           name_bi=name_blind_index(vault.id, name))


def _service(db, removed=None):
    svc = vs.VaultService.__new__(vs.VaultService)
    svc.db = db
    svc.storage_path = None

    def remove(paths):
        if paths:
            db.log.append(("removed",))
        if removed is not None:
            removed.extend(paths)
    svc._remove_blobs = remove
    return svc


def test_the_free_name_is_the_name_itself_when_no_file_in_the_folder_has_it():
    vault = _vault()
    db = MemoryDB({Vault: [vault], File: [_file(vault, "a.bin", folder_id=uuid.uuid4())]})
    # Same name in a folder: the root is free.
    assert _service(db).free_name_in_folder(vault.id, None, "a.bin") == "a.bin"


def test_the_free_name_skips_every_taken_number():
    vault = _vault()
    db = MemoryDB({Vault: [vault], File: [_file(vault, "a.bin"), _file(vault, "a (2).bin"), _file(vault, "a (3).bin")]})
    assert _service(db).free_name_in_folder(vault.id, None, "a.bin") == "a (4).bin"
    # A file of another vault with the same name does not count.
    other = _vault()
    db = MemoryDB({Vault: [vault, other], File: [_file(other, "a.bin")]})
    assert _service(db).free_name_in_folder(vault.id, None, "a.bin") == "a.bin"


# ---------------------------------------------------------------------------------------- finalize, under the lock

class _DB(MemoryDB):
    """A session whose commit fails as PostgreSQL fails it, with `code`, the first `fail` times. Each failure
    can also stand for the file another writer slipped in: `appears` names the files that exist afterwards."""

    def __init__(self, tables, code=None, fail=1, appears=()):
        super().__init__(tables)
        self.code = code
        self.fail = fail
        self.appears = list(appears)

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name="memory"))

    def rollback(self):
        # The counters' UPDATE is undone, as the database undoes it (MemoryDB keeps the written expression).
        for vault in self.rows_of(Vault):
            vault.total_size_bytes, vault.file_count = 0, 0
        super().rollback()

    def commit(self):
        if self.code is not None and self.fail > 0:
            self.fail -= 1
            self.log.append(("commit failed", self.code))
            if self.appears:
                self.rows_of(File).append(self.appears.pop(0))
            raise IntegrityError("INSERT INTO files ...", {}, SimpleNamespace(
                pgcode=self.code, diag=SimpleNamespace(constraint_name="uq_files_vault_folder_name_bi")))
        super().commit()


@pytest.fixture
def finish(monkeypatch):
    import app.core.security as security
    monkeypatch.setattr(vs, "_seal_named_object", lambda *a, **k: None)
    monkeypatch.setattr(vs, "_seal_file_checksum", lambda *a, **k: None)
    monkeypatch.setattr(security, "content_mac", lambda *a, **k: "mac")
    monkeypatch.setattr(vs, "deployment_storage_limit_bytes", lambda _db: None)
    removed = []

    def call(db, vault, name="a.bin", **kw):
        svc = _service(db, removed)
        info = {"id": uuid.uuid4(), "name": name, "original_name": name, "vault_id": vault.id,
                "folder_id": None, "mime_type": "application/octet-stream",
                "storage_path": f"{vault.id}/files/new", "is_encrypted": True,
                "password_hash": None, "expires_at": None, "uploaded_by": uuid.uuid4(), "vault": vault}
        return svc, (lambda: svc.finalize_streaming_upload(info, 5, "0" * 64, **kw)), info

    return call, removed


def test_the_stored_name_steps_aside_when_the_name_is_taken(finish):
    call, removed = finish
    vault = _vault()
    db = _DB({Vault: [vault], File: [_file(vault, "a.bin"), _file(vault, "a (2).bin")]})
    svc, run, info = call(db, vault, rename_on_clash=True)
    added = run()
    assert isinstance(added, File) and added.original_name == "a (3).bin" and added.name == "a (3).bin"
    assert info["original_name"] == "a (3).bin" and removed == []


def test_without_the_policy_the_name_is_stored_as_given(finish):
    call, removed = finish
    vault = _vault()
    db = _DB({Vault: [vault], File: [_file(vault, "a.bin")]})
    svc, run, info = call(db, vault)
    assert run().original_name == "a.bin"


def test_the_name_is_chosen_after_the_vaults_row_is_locked(finish):
    """So a same-name file that finished while this one was written, and committed before the lock was
    taken, is counted; one that waits for this lock reads this file's row when its turn comes."""
    call, removed = finish
    vault = _vault()
    db = _DB({Vault: [vault], File: [_file(vault, "a.bin")]})
    svc, run, info = call(db, vault, rename_on_clash=True)
    seen = {}
    real = svc.free_name_in_folder

    def chosen(vault_id, folder_id, name):
        seen["at"] = len(db.log)
        return real(vault_id, folder_id, name)
    svc.free_name_in_folder = chosen
    run()
    # Recorded as the log stood when the name was chosen: after the lock, before the row was added.
    locks = [i for i, e in enumerate(db.log) if e[0] == "lock" and e[1] is Vault]
    assert locks and locks[0] < seen["at"] <= [e[0] for e in db.log].index("add")


def test_a_duplicate_the_insert_still_meets_keeps_the_written_file_and_tries_the_next_name(finish):
    """A rename or a move does not take the vault lock, so the chosen name can still be taken by the time
    the row is inserted. The written file stays, and the row is tried again, from the lock, under the next
    free name. Without the policy a duplicate removes the file, as before."""
    call, removed = finish
    vault = _vault()
    # "a.bin" is there; "a (2).bin" is chosen; another writer lands "a (2).bin" before the insert.
    db = _DB({Vault: [vault], File: [_file(vault, "a.bin")]}, code="23505", appears=[_file(vault, "a (2).bin")])
    svc, run, info = call(db, vault, rename_on_clash=True)
    added = run()
    assert added.original_name == "a (3).bin" and removed == [], "the written file must survive a name retry"
    kinds = [e[0] for e in db.log]
    assert kinds[:kinds.index("commit failed") + 2][-3:] == ["update", "commit failed", "rollback"]
    assert kinds[kinds.index("rollback"):] == ["rollback", "lock", "add", "update", "commit"], kinds

    vault = _vault()
    db = _DB({Vault: [vault]}, code="23505")
    svc, run, info = call(db, vault)
    with pytest.raises(vs.DuplicateNameError):
        run()
    assert removed == [info["storage_path"]]


def test_the_file_is_removed_only_once_the_name_retries_are_spent(finish):
    call, removed = finish
    vault = _vault()
    db = _DB({Vault: [vault]}, code="23505", fail=10)
    svc, run, info = call(db, vault, rename_on_clash=True)
    with pytest.raises(vs.DuplicateNameError):
        run()
    assert [e[0] for e in db.log].count("commit failed") == 3, "the first try and two more"
    assert removed == [info["storage_path"]]


def test_a_gone_destination_removes_the_file_whatever_the_policy(finish):
    call, removed = finish
    vault = _vault()
    db = _DB({Vault: [vault]}, code="23503")
    svc, run, info = call(db, vault, rename_on_clash=True)
    with pytest.raises(vs.DestinationGoneError):
        run()
    assert removed == [info["storage_path"]]


# ------------------------------------------------------------------------------------------------- the route

def _handler(src: str, signature: str) -> str:
    start = src.index(signature)
    nxt = re.search(r"^@app\.[a-z]+\(", src[start:], re.M)
    return src[start:start + nxt.start()] if nxt else src[start:]


def test_the_upload_link_completion_renames_inside_finalize():
    src = API.read_text(encoding="utf-8")
    body = _handler(src, "async def receiver_complete_upload(")
    assert body.count("finalize_streaming_upload(") == 1
    assert "replace_same_name=False, rename_on_clash=True)" in body
    assert "_free_name_in_root" not in src, "the name is chosen under the lock, not before the assembly"
    # Only finalize's spent retries reach the route's duplicate branch, which removes the file it gave up on.
    spent = body[body.index("except (DuplicateNameError, DestinationGoneError)"):]
    assert "_remove_orphan_blob()" in spent[:200]


def test_the_receipt_names_the_file_as_sent_and_never_says_it_was_renamed():
    src = API.read_text(encoding="utf-8")
    body = _handler(src, "async def receiver_complete_upload(")
    receipt = body[body.index("return {'id': str(file.id)"):]
    assert "'name': fname" in receipt and "'reference'" in receipt
    assert "renamed" not in receipt and "sent_as" not in receipt and "file.original_name" not in receipt
