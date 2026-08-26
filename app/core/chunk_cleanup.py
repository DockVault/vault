"""Immediate cleanup for a chunked-upload session that failed to finalize.

A chunked upload holds working state in plaintext for the life of the transfer: the filename/MIME
on the session row (for a Standard vault), and the staged chunk files on disk. On a clean finish
both are removed straight away. When a finalize genuinely fails, though, the row was only marked
failed and left for the TTL sweep -- so the plaintext name and the chunk files lingered until then.
This clears them at the moment of failure instead.

Kept out of the API module so it can be exercised directly against a database without importing
the whole application (which runs credential validation at import time).
"""
import shutil


def fail_chunk_session(db, session, sdir, error):
    """Mark a chunked-upload session failed and clear its at-rest working state right away.

    The row itself is kept (``status='failed'`` plus the error message) so an operator can see what
    happened and the ordinary TTL prune removes it later; only its plaintext contents are cleared:
    the filename/MIME on the row and the staged chunk files under ``sdir``.

    Not used for a permission denial -- a 403 is not a corrupt upload, so it is retained for the TTL
    cleanup rather than force-failed here.
    """
    session.status = 'failed'
    session.error_message = str(error)[:500]
    session.filename = None
    session.mime_type = None
    try:
        db.commit()
    except Exception:  # noqa: BLE001 — best-effort; the on-disk chunks are cleared regardless
        db.rollback()
    shutil.rmtree(sdir, ignore_errors=True)
