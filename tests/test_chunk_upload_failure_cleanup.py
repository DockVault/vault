"""A genuinely-failed chunked-upload finalize clears its plaintext working state at once.

A chunked upload keeps, for the life of the transfer, the plaintext filename/MIME on its session
row and the staged plaintext chunk files on disk. A clean finish removes both. A finalize that
FAILS used to only mark the row failed and leave the rest for the TTL sweep, so the plaintext name
and the chunks lingered. `fail_chunk_session` clears them at the moment of failure -- but only for a
genuine failure, never for a permission denial (a 403 is retained for the TTL cleanup).

These cover the helper's behaviour directly, that the model really has the columns it clears (so
the duck-typed helper cannot silently target the wrong attribute), and -- from the API source --
that both force-fail branches call it while the 403 branch does not.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from app.core.chunk_cleanup import fail_chunk_session

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


class _FakeSession:
    """Stands in for a ChunkedUploadSession: only the columns the helper touches."""
    def __init__(self):
        self.status = "active"
        self.error_message = None
        self.filename = "quarterly-secrets.pdf"
        self.mime_type = "application/pdf"


class _FakeDB:
    def __init__(self, fail_commit=False):
        self._fail_commit = fail_commit
        self.committed = False
        self.rolled_back = False

    def commit(self):
        if self._fail_commit:
            raise RuntimeError("commit boom")
        self.committed = True

    def rollback(self):
        self.rolled_back = True


def _sdir_with_chunks(tmp_path):
    sdir = tmp_path / "session-dir"
    sdir.mkdir()
    for i in range(3):
        (sdir / f"chunk_{i:06d}").write_bytes(b"x" * 16)
    return sdir


def test_it_scrubs_the_plaintext_name_and_removes_the_chunks(tmp_path):
    sdir = _sdir_with_chunks(tmp_path)
    session, db = _FakeSession(), _FakeDB()

    fail_chunk_session(db, session, sdir, ValueError("finalize exploded"))

    assert session.status == "failed"
    assert session.filename is None and session.mime_type is None, "plaintext name/MIME cleared"
    assert "finalize exploded" in session.error_message
    assert db.committed and not db.rolled_back
    assert not sdir.exists(), "the staged plaintext chunk files are removed"


def test_the_error_message_is_bounded(tmp_path):
    session, db = _FakeSession(), _FakeDB()
    fail_chunk_session(db, session, tmp_path / "missing", Exception("e" * 5000))
    assert len(session.error_message) <= 500


def test_it_tolerates_a_missing_chunk_dir(tmp_path):
    """The dir may already be gone (a racing sweep); clearing the row must still succeed."""
    session, db = _FakeSession(), _FakeDB()
    fail_chunk_session(db, session, tmp_path / "does-not-exist", RuntimeError("boom"))
    assert session.status == "failed"
    assert session.filename is None and session.mime_type is None
    assert db.committed


def test_a_failed_commit_still_clears_the_chunks(tmp_path):
    """If the row update cannot commit, the on-disk plaintext is still removed and no error escapes."""
    sdir = _sdir_with_chunks(tmp_path)
    session, db = _FakeSession(), _FakeDB(fail_commit=True)

    fail_chunk_session(db, session, sdir, RuntimeError("boom"))   # must not raise

    assert db.rolled_back and not db.committed
    assert not sdir.exists(), "chunks are cleared regardless of the commit outcome"


def test_the_model_has_the_columns_the_helper_clears():
    """Bridges the fake session above to the real one: a rename of any of these columns would make
    the helper clear the wrong attribute, which the duck-typed tests could not catch."""
    from app.core.models import ChunkedUploadSession
    for column in ("status", "error_message", "filename", "mime_type"):
        assert hasattr(ChunkedUploadSession, column), f"ChunkedUploadSession lost column {column!r}"


def _complete_upload_handlers():
    """The except-handlers of the FINALIZE try in `_complete_chunked_upload`.

    Scoped to the one try that wraps finalize -- identified by its PermissionDeniedError and
    DuplicateNameError handlers -- rather than every nested try in the function. Otherwise the
    generic `except Exception` here would be unioned with the several nested `except Exception`
    handlers elsewhere in the function, and the positive assertions would only prove that SOME
    except-of-that-type calls the scrub, not the outer one that actually guards a failed finalize.
    """
    tree = ast.parse((ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.AsyncFunctionDef) and n.name == "_complete_chunked_upload")

    def _type_names(try_node):
        return {ast.unparse(h.type) for h in try_node.handlers if h.type is not None}

    finalize_try = next(
        t for t in ast.walk(fn)
        if isinstance(t, ast.Try)
        and {"PermissionDeniedError", "DuplicateNameError"} <= _type_names(t))

    handlers = {}
    for h in finalize_try.handlers:
        name = ast.unparse(h.type) if h.type is not None else "bare"
        calls = {c.func.id for c in ast.walk(h)
                 if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
        handlers[name] = calls
    return handlers


def test_both_force_fail_branches_scrub_and_the_permission_branch_does_not():
    handlers = _complete_upload_handlers()
    assert "fail_chunk_session" in handlers.get("ValueError", set()), (
        "the ValueError finalize-failure branch must scrub the session")
    assert "fail_chunk_session" in handlers.get("Exception", set()), (
        "the generic finalize-failure branch must scrub the session")
    assert "fail_chunk_session" not in handlers.get("PermissionDeniedError", set()), (
        "a 403 is retained for the TTL cleanup, not force-failed -- it must NOT scrub")
