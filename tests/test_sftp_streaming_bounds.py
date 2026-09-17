"""Source + config pins for the bounded-memory SFTP streaming write.

The byte-level bound is proven behaviourally in test_sftp_upload_assembler.py (buffered_bytes never
exceeds one record on a fast sequential client; out-of-order past the reorder window is refused, not
buffered). These pin the server wiring that makes streaming the DEFAULT, clamps the reorder window to
the documented memory ceiling, drops the tmpfs >512 MB refusal on the streaming path, and keeps the
two carried rules the streaming writer already honours: authenticate-before-release and
no-transaction-across-the-stream. The live RSS proof is the live/acceptance lane.
"""
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

import _bare_api_env  # noqa: E402
_bare_api_env.set_bare_api_env()

ROOT = Path(__file__).resolve().parents[1]
SFTP = ROOT / "app" / "sftp" / "sftp_server.py"


def test_streaming_and_the_memory_ceiling_are_the_defaults():
    from app.core.config import Settings
    s = Settings()
    assert s.sftp_streaming_upload is True                 # a default deployment streams
    assert s.sftp_transfer_buffer_mb == 64                 # the documented in-process ceiling (MiB)


def test_the_reorder_window_is_clamped_to_the_memory_ceiling():
    src = SFTP.read_text(encoding="utf-8")
    body = src[src.index("def _open_write("):src.index("def _authorize_upload_persist(")]
    # The ceiling comes from the setting, and the reorder window is min()'d against it minus a record.
    assert "settings.sftp_transfer_buffer_mb" in body
    assert "_reorder_bytes = min(" in body and "_ceiling_bytes - _StreamingUpload.RECORD_SIZE" in body
    assert "reorder_bytes=_reorder_bytes" in body          # the clamped value is what the writer gets


def test_the_tmpfs_512mb_refusal_applies_only_to_the_buffered_fallback():
    src = SFTP.read_text(encoding="utf-8")
    body = src[src.index("def _open_write("):src.index("def _authorize_upload_persist(")]
    # The staging-tmpfs cap is applied ONLY when streaming is off, so the streaming default has no
    # >512 MB refusal. (mutation: drop the `if not settings.sftp_streaming_upload:` guard -> the
    # streaming path would be capped again.)
    assert "if not settings.sftp_streaming_upload:" in body
    assert "_staging_capped_max(_eff_max, settings.sftp_staging_tmpfs_mb)" in body
    guard = body.index("if not settings.sftp_streaming_upload:")
    clamp = body.index("_staging_capped_max(_eff_max", guard)
    assert clamp - guard < 120, "the tmpfs clamp is not under the streaming-off guard"


def test_the_streaming_writer_holds_no_db_transaction_across_the_byte_stream():
    src = SFTP.read_text(encoding="utf-8")
    cls = src[src.index("class _StreamingUpload:"):src.index("\nclass ", src.index("class _StreamingUpload:") + 10)]
    # No DB transaction is held across the client-paced byte stream: every session in the writer is a
    # short `with get_db_context()` block that commits/closes before the next record -- never one held
    # open across write(). The encryptor is opened in a brief session on the first record; the File-row
    # insert runs in a FRESH session at close.
    assert "with get_db_context() as db:" in cls
    # The per-record write path (_emit -> write_chunk) touches the file-handle context, not a session:
    emit = cls[cls.index("def _emit("):cls.index("def write(")]
    assert "get_db_context" not in emit and "self.db" not in emit
    assert "self._ctx.write_chunk(record)" in emit


def test_authenticate_before_release_the_file_row_is_the_commit_point():
    src = SFTP.read_text(encoding="utf-8")
    cls = src[src.index("class _StreamingUpload:"):src.index("\nclass ", src.index("class _StreamingUpload:") + 10)]
    # No plaintext byte is released to a reader before its tag verifies: the encrypted blob is only
    # committed (a File row) after the close-time re-authorization passes, and a rejected upload
    # unlinks the uncommitted blob via _abort rather than leaving an orphan or destroying the
    # same-name file. (The record codec verifies each chunk's tag on read; the commit gates exposure.)
    assert "_authorize_upload_persist(" in cls          # close-time re-authz before the File row
    assert "self._abort()" in cls                       # a failure discards the uncommitted blob


def test_the_persist_locks_the_vault_row_before_the_quota_check():
    # Two concurrent streamed uploads must not both pass the per-vault size_limit and jointly
    # overshoot it (with the tmpfs clamp gone the overshoot per upload is the per-file ceiling). The
    # persist step (_authorize_upload_persist, close-time) locks the vault row FOR NO KEY UPDATE and
    # reads the total UNDER the lock, in the SAME transaction as the File-row insert. (mutation: drop
    # the with_for_update re-read -> the quota is read unlocked and two persists both commit -> the
    # live two-upload race goes red.)
    src = SFTP.read_text(encoding="utf-8")
    fn = src[src.index("def _authorize_upload_persist("):src.index("def _make_upload_finalizer(")]
    # FOR NO KEY UPDATE (key_share=True), never FOR UPDATE (the audit-insert KEY SHARE deadlock lesson).
    assert "with_for_update(key_share=True)" in fn
    assert "populate_existing()" in fn                    # refresh the get_vault instance to the locked total
    # The lock precedes the size_limit check, so the quota is read from the locked row.
    lock_at = fn.index("with_for_update(key_share=True)")
    quota_at = fn.index("vault.total_size_bytes or 0) + size > vault.size_limit")
    assert lock_at < quota_at, "the vault row must be locked before the quota check"
    # A lock_timeout is a clean drop (blob discarded, marker removed by the caller), never a hang.
    assert "except _OperationalError:" in fn and "return None" in fn[fn.index("except _OperationalError:"):]
