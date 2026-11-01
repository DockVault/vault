"""A file whose folder, or vault, was deleted while it was written is answered as that, offline.

Uploads, copies and moves write the file first and its row last, and nothing holds the folder meanwhile: a
folder deleted in between makes the row's insert fail on the folder it names. That failure used to be read as
a name clash ("A file with that name already exists in this folder"), which there was not. It is now answered
as what happened, nothing stored and the new file removed, and every route answers it 409. A vault deleted in
between is found when its row is locked, before the insert. The row also names the account it is stored for
(files.uploaded_by): an account deleted meanwhile fails the insert on that, and is said so, by the constraint
PostgreSQL names.

tests/test_upload_completion_answers_others_live.py deletes a folder while an upload into it completes, on a
running stack.
"""
import ast
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB
from app.core.models import Vault

set_bare_api_env()          # two tests import app.api.api_server, which needs it when this module runs alone

pytestmark = pytest.mark.unit

API = Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py"


class _DB(MemoryDB):
    """A session whose commit fails as PostgreSQL fails it, with `code`, naming `constraint` (psycopg2 gives it
    as the error's diag.constraint_name)."""

    def __init__(self, tables, code=None, constraint=None):
        super().__init__(tables)
        self.code = code
        self.constraint = constraint

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name="memory"))

    def commit(self):
        if self.code is not None:
            self.log.append(("commit failed", self.code))
            raise IntegrityError("INSERT INTO files ...", {}, SimpleNamespace(
                pgcode=self.code, diag=SimpleNamespace(constraint_name=self.constraint)))
        super().commit()


@pytest.fixture
def finish(monkeypatch):
    import app.core.security as security
    import app.services.vault_service as vs
    monkeypatch.setattr(vs, "_seal_named_object", lambda *a, **k: None)
    monkeypatch.setattr(vs, "_seal_file_checksum", lambda *a, **k: None)
    monkeypatch.setattr(security, "content_mac", lambda *a, **k: "mac")
    monkeypatch.setattr(vs, "deployment_storage_limit_bytes", lambda _db: None)
    removed = []

    def call(db, vault_id, folder_id=None):
        svc = vs.VaultService.__new__(vs.VaultService)
        svc.db = db
        svc.storage_path = None

        def remove(paths):
            if paths:
                db.log.append(("removed",))     # in the log, so a test sees it comes after the rollback
            removed.extend(paths)
        svc._remove_blobs = remove
        vault = SimpleNamespace(id=vault_id, type="standard")
        info = {"id": uuid.uuid4(), "name": "a.bin", "original_name": "a.bin", "vault_id": vault_id,
                "folder_id": folder_id, "mime_type": "application/octet-stream",
                "storage_path": f"{vault_id}/folders/{folder_id}/new", "is_encrypted": True,
                "password_hash": None, "expires_at": None, "uploaded_by": uuid.uuid4(), "vault": vault}
        return svc.finalize_streaming_upload(info, 5, "0" * 64)

    return call, removed


def _vault():
    return SimpleNamespace(id=uuid.uuid4(), total_size_bytes=0, size_limit=None, file_count=0,
                           expire_files_after_days=None)


def test_an_insert_that_names_a_deleted_folder_is_answered_as_that(finish):
    import app.services.vault_service as vs
    call, removed = finish
    vault = _vault()
    db = _DB({Vault: [vault]}, code="23503", constraint="files_folder_id_fkey")
    with pytest.raises(vs.DestinationGoneError) as gone:
        call(db, vault.id, folder_id=uuid.uuid4())
    assert str(gone.value) == vs._GONE["folder"]
    assert "Nothing has been stored" in str(gone.value) and "already exists" not in str(gone.value)
    # Rolled back, then the new file removed: its removal overwrites the whole file, which must not happen
    # while the transaction still holds the vault's row.
    assert [e[0] for e in db.log][-3:] == ["commit failed", "rollback", "removed"]
    assert len(removed) == 1 and removed[0].endswith("/new"), removed


@pytest.mark.parametrize("constraint, said", [
    ("files_folder_id_fkey", "folder"),
    ("files_uploaded_by_fkey", "account"),
    ("files_modified_by_fkey", "account"),
    ("files_vault_id_fkey", "vault"),
    (None, "either"),
    ("another_fkey", "either"),
])
def test_the_text_names_what_the_insert_found_gone(finish, constraint, said):
    """files names its folder and the account it is stored for (uploaded_by, modified_by), each by a foreign key:
    an account deleted while its own upload, or one through a link it made, finished is not said to be a folder.
    A constraint the database does not name, or one finalize does not know, is said as either of the two."""
    import app.services.vault_service as vs
    call, removed = finish
    vault = _vault()
    db = _DB({Vault: [vault]}, code="23503", constraint=constraint)
    with pytest.raises(vs.DestinationGoneError) as gone:
        call(db, vault.id)
    assert str(gone.value) == vs._GONE[said]
    assert str(gone.value).endswith("Nothing has been stored.")
    assert len(removed) == 1


def test_a_name_clash_is_still_a_name_clash(finish):
    import app.services.vault_service as vs
    call, removed = finish
    vault = _vault()
    db = _DB({Vault: [vault]}, code="23505")
    with pytest.raises(vs.DuplicateNameError, match="already exists"):
        call(db, vault.id, folder_id=uuid.uuid4())
    assert len(removed) == 1


def test_a_vault_deleted_before_the_row_is_answered_as_that(finish):
    """The vault's row is locked before the insert; a vault gone by then is said so there, with nothing
    written and the file removed."""
    import app.services.vault_service as vs
    call, removed = finish
    db = _DB({Vault: []})
    with pytest.raises(vs.DestinationGoneError) as gone:
        call(db, uuid.uuid4())
    assert str(gone.value) == vs._GONE["vault"]
    assert [e[0] for e in db.log] == ["lock", "rollback", "removed"], db.log
    assert len(removed) == 1


# (the route, how its handler for a name clash is written: every route answers both the same way)
UPLOAD_ROUTES = ["receiver_complete_upload", "_complete_chunked_upload", "upload_file"]


@pytest.mark.parametrize("route", UPLOAD_ROUTES)
def test_each_upload_route_answers_it_as_it_answers_a_name_clash(route):
    """The same handler: the session and its staged chunks torn down, and a 409 with the error's words. A
    handler of its own, or none, would leave the upload paths' catch-all to answer 500."""
    tree = ast.parse(API.read_text(encoding="utf-8"))
    (node,) = [n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == route]
    handlers = [h for h in ast.walk(node) if isinstance(h, ast.ExceptHandler) and h.type is not None
                and "DuplicateNameError" in ast.unparse(h.type)]
    assert len(handlers) == 1, [ast.unparse(h.type) for h in handlers]
    (handler,) = handlers
    assert ast.unparse(handler.type) == "(DuplicateNameError, DestinationGoneError)"
    assert "HTTP_409_CONFLICT" in ast.unparse(handler) and "detail=str(e)" in ast.unparse(handler)


def test_a_copy_or_a_move_into_a_deleted_folder_is_answered_409():
    """Copies and moves answer a service error through the app's handler for them."""
    from app.api.api_server import _file_service_error_handler
    from app.services.vault_service import DestinationGoneError, _GONE
    response = run_coroutine(_file_service_error_handler(None, DestinationGoneError(_GONE["folder"])))
    assert response.status_code == 409
    assert _GONE["folder"].encode() in response.body
