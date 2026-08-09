"""Source guards for the upload-resume record, in the OFFLINE lane so CI actually runs them.

These are deliberately not browser tests. They check the writer and the migration's error
containment by reading the shipped source, and marking them `ui` would mean they only run when
someone has a container up -- which is precisely when nobody is looking.

The reason a source guard is needed at all is that `get()` now strips plaintext defensively. That
is correct: a row can genuinely reach a reader unmigrated. But it costs every read-back assertion
its sensitivity to the WRITER, so the writer is checked where it cannot hide.
"""

from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

APP_JS = Path(__file__).resolve().parent.parent / "static" / "js" / "app.js"


def test_the_writer_itself_never_sends_plaintext_metadata() -> None:
    """A source guard, and the reason it is needed is worth stating.

    The defensive strip on `get()` means every assertion that reads a record back is now BLIND to
    a re-introduced on-disk leak: reinstate `fileName: it.fileName` in the persist call and the
    runtime tests above still pass, because the strip removes it on the way out. The strip is
    right -- a row can genuinely reach a reader unmigrated -- but it costs the tests their
    sensitivity to the writer, so the writer gets checked directly.
    """
    app = APP_JS.read_text(encoding="utf-8")
    marker = "const res = await zkUploadStore.put({"
    assert app.count(marker) == 1, "the resume-record writer moved; re-anchor this guard"
    call = app[app.index(marker):]
    call = call[: call.index("});") + 3]

    assert "fileName:" not in call, f"the writer persists a plaintext filename again:\n{call}"
    assert "mimeType:" not in call, f"the writer persists a plaintext MIME again:\n{call}"
    # And it must hand over a neutral blob rather than the File it holds.
    assert "blob: zkUploadStore.neutralBlob(" in call, call
    assert "blob: it.file" not in call, call


def test_a_failed_record_migration_cannot_kill_the_whole_upgrade() -> None:
    """Source guard for the sharpest failure mode this change could have introduced.

    An unhandled error on the cursor's `update()` aborts the versionchange transaction, so the
    database stays on the old schema. That alone would be tolerable -- except the open then fails,
    the memoised promise caches the failure, and both the TTL sweep and the logout wipe
    short-circuit when the database is unavailable. A leak that used to expire in a day would
    become permanent and survive logout, on exactly the storage-pressure devices where the
    migration is most likely to fail.
    """
    app = APP_JS.read_text(encoding="utf-8")
    upgrade = app[app.index("req.onupgradeneeded"):]
    upgrade = upgrade[: upgrade.index("req.onsuccess")]
    assert "cur.update(cleaned)" in upgrade, "migration moved; re-anchor this guard"
    assert upgrade.count("preventDefault()") >= 2, (
        "the cursor and its update must both contain their own errors, or one bad record aborts "
        f"the upgrade:\n{upgrade}"
    )

    # And the open's error path must not cache the failure for the page's lifetime.
    opener = app[app.index("function _open()"):]
    opener = opener[: opener.index("\n    function ")]
    err = opener[opener.index("req.onerror"):]
    err = err[: err.index("req.onblocked")]
    assert "_dbPromise = null" in err, (
        "a failed open stays memoised, which also disables the TTL sweep and the logout wipe"
    )
