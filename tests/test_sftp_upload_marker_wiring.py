"""Source-pinned wiring of the in-flight upload marker into the SFTP server.

The marker's live behaviour (a real upload publishes it, a second same-name upload is refused, close
and a killed client remove it) is proven in the live lane against a running server. This offline
contract pins the WIRING that can't run without a live SFTP server + DB, so a refactor that drops a
piece fails here: the same-name lock is claimed for EVERY upload at open, a refusal names the holder,
and the marker is removed on close and freed if the buffered open fails after the lock was taken.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

SFTP = Path(__file__).resolve().parents[1] / "app" / "sftp" / "sftp_server.py"


def _src():
    return SFTP.read_text(encoding="utf-8")


def _open_write_body():
    s = _src()
    start = s.index("def _open_write(self, segments")
    end = s.index("\n    def _authorize_upload_persist(", start)
    return s[start:end]


def test_open_write_claims_the_same_name_lock_for_every_upload():
    body = _open_write_body()
    # The lock/marker is claimed at open, keyed by (vault, folder, final name) with the principal.
    assert "upload_marker.place(vault_id, folder_id, filename, user.id)" in body
    # It runs OUTSIDE the `if not can_overwrite:` no-clobber block, so it applies to everyone: the
    # place() call is not indented under that block (16 spaces would mean nested; it sits at 12).
    assert "\n            _marker_outcome = upload_marker.place(" in body, \
        "the same-name lock must apply to EVERYONE, not only principals lacking DELETE"


def test_a_same_name_conflict_is_refused_and_names_the_holder():
    body = _open_write_body()
    # A holder id (a str) means the name is in flight: refuse, and name the member in the status.
    assert "isinstance(_marker_outcome, str)" in body
    assert "_resolve_member_name(db, _marker_outcome)" in body
    assert "is currently being uploaded by" in body
    # The refusal returns a denied status (not a silent success).
    ref = body[body.index("isinstance(_marker_outcome, str)"):]
    assert "return paramiko.SFTP_PERMISSION_DENIED" in ref[:400]


def test_the_acquired_marker_key_is_carried_on_the_handle_both_paths():
    body = _open_write_body()
    # Acquired -> remember the key so close() removes it; SKIPPED (Redis down) -> None, fail open.
    assert "_upload_marker_key = (upload_marker.marker_key(vault_id, folder_id, filename)" in body
    assert body.count("handle.upload_marker_key = _upload_marker_key") == 2  # streaming + buffered


def test_close_removes_the_marker_on_every_close_path():
    s = _src()
    close = s[s.index("    def close(self):"):]
    close = close[:close.index("\n    def ", 1)]
    assert "upload_marker.remove_key(self.upload_marker_key)" in close
    # Removal is the FIRST thing in close(), before the read/stream/buffered branches that return.
    assert close.index("upload_marker.remove_key(") < close.index("if self.reader is not None:")


def test_a_failed_buffered_open_frees_the_lock_it_took():
    body = _open_write_body()
    # If the staging tempfile can't be opened we return before a handle exists, so there is no
    # close() to remove the marker -- free it inline instead of leaking it to the TTL.
    seg = body[body.index("upload.buffer-open.failed"):]
    assert "upload_marker.remove_key(_upload_marker_key)" in seg[:400]


def test_the_write_path_heartbeats_the_marker_ttl():
    s = _src()
    # A slow-but-live transfer must not let its marker lapse mid-upload: write() refreshes it.
    assert "self._refresh_marker()" in s
    assert "upload_marker.refresh_key(self.upload_marker_key)" in s
    # ...throttled, so it is not a Redis op per write.
    assert "self._marker_last_refresh" in s
