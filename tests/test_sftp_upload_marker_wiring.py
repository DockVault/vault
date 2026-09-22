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
    assert "\n            _marker_outcome, _marker_token = upload_marker.place(" in body, \
        "the same-name lock must apply to EVERYONE, not only principals lacking DELETE"


def test_a_same_name_conflict_is_refused_and_names_the_holder():
    body = _open_write_body()
    # A holder id (a str) means the name is in flight: refuse, and name the member in the status.
    assert "isinstance(_marker_outcome, str)" in body
    assert "_resolve_member_name(db, _marker_outcome, user, vault_id)" in body   # gated on the refusing principal, for THIS vault
    assert "is currently being uploaded by" in body
    # The refusal returns a denied status (not a silent success).
    ref = body[body.index("isinstance(_marker_outcome, str)"):]
    assert "return paramiko.SFTP_PERMISSION_DENIED" in ref[:400]


def test_the_acquired_marker_key_is_carried_on_the_handle_both_paths():
    body = _open_write_body()
    # Acquired -> remember (vault, folder, name, TOKEN) so close() can compare-and-delete only its
    # own marker; SKIPPED (Redis down) -> None, fail open.
    assert "_upload_marker_ref = ((vault_id, folder_id, filename, _marker_token)" in body
    assert body.count("handle.upload_marker_ref = _upload_marker_ref") == 2  # streaming + buffered


def test_a_failed_streaming_open_frees_the_lock_it_took():
    body = _open_write_body()
    # If the streaming encryptor's constructor raises, no handle is returned, so no close() runs to
    # remove the marker -- free it inline (like the buffered-open failure), not hold it for the TTL.
    seg = body[body.index("upload.stream-open.failed"):]
    assert "upload_marker.remove(*_upload_marker_ref)" in seg[:300]
    assert "return paramiko.SFTP_FAILURE" in seg[:300]


def test_close_removes_the_marker_on_every_close_path():
    s = _src()
    close = s[s.index("    def close(self):"):]
    close = close[:close.index("\n    def ", 1)]
    assert "upload_marker.remove(*self.upload_marker_ref)" in close
    # Removal is the FIRST thing in close(), before the read/stream/buffered branches that return.
    assert close.index("upload_marker.remove(") < close.index("if self.reader is not None:")


def test_a_failed_buffered_open_frees_the_lock_it_took():
    body = _open_write_body()
    # If the staging tempfile can't be opened we return before a handle exists, so there is no
    # close() to remove the marker -- free it inline instead of leaking it to the TTL.
    seg = body[body.index("upload.buffer-open.failed"):]
    assert "upload_marker.remove(*_upload_marker_ref)" in seg[:400]


def test_the_write_path_heartbeats_the_marker_ttl():
    s = _src()
    # A slow-but-live transfer must not let its marker lapse mid-upload: write() refreshes it.
    assert "self._refresh_marker()" in s
    assert "upload_marker.refresh(*self.upload_marker_ref)" in s
    # ...throttled, so it is not a Redis op per write.
    assert "self._marker_last_refresh" in s


def test_the_same_name_refusal_names_the_holder_only_to_a_member_grade_viewer():
    # Behavioural: the refusal reveals the holder's USERNAME only to a member-grade viewer (an
    # interactive member), gated exactly like the web listing's uploader identity -- a scoped
    # credential (what most SFTP uploaders are) gets a neutral "another member", and an email is
    # NEVER used as a fallback. (mutation: drop the is_scoped gate -> scoped case red; restore the
    # email fallback -> the no-username case red.)
    import os
    import sys
    from types import SimpleNamespace
    sys.path.insert(0, os.path.dirname(__file__))
    import _bare_api_env
    _bare_api_env.set_bare_api_env()
    from app.sftp.sftp_server import SFTPServerInterface

    class _DB:
        def __init__(self, user):
            self._user = user

        def query(self, *a):
            return self

        def filter(self, *a):
            return self

        def first(self):
            return self._user

    from app.core.models import User
    resolve = SFTPServerInterface._resolve_member_name
    member = User(username="viewer")                                               # a real member row
    scoped = User(username="temp"); scoped._is_temp_session = True; scoped._temp_scope = {"pages": ["vaults"]}

    named = _DB(SimpleNamespace(username="alice", email="alice@example.com"))
    assert resolve(named, "id", member) == "alice"                 # member-grade -> username
    assert resolve(named, "id", scoped) == "another member"        # scoped -> neutral, no name
    noname = _DB(SimpleNamespace(username=None, email="bob@example.com"))
    assert resolve(noname, "id", member) == "another member"       # no username -> neutral, NEVER email
    # The SFTP door, driven with the same LEGACY credential the web door is driven with: a temp
    # session carrying no scope at all. Both doors ask one rule, so both must refuse it -- and a
    # source count of the two call sites could not tell, because `if True:` at either site keeps
    # the count. (mutation: ask is_scoped in the shared rule -> this line names alice -> red.)
    legacy = User(username="legacy"); legacy._is_temp_session = True; legacy._temp_scope = None
    assert resolve(named, "id", legacy) == "another member"


def test_a_live_upload_refreshes_its_marker_once_per_tenth_of_the_ttl(monkeypatch):
    # Behavioural, on the real handle. The interval is what bounds how long the marker is
    # guaranteed to outlive the last write (see test_upload_marker: the relation with the
    # write-progress watchdog), so it is held to the number, from both sides.
    import os
    import time
    from app.sftp import sftp_server as srv
    monkeypatch.setattr(srv.upload_marker, "marker_ttl_seconds", lambda: 300)
    refreshed = []
    monkeypatch.setattr(srv.upload_marker, "refresh", lambda *ref: refreshed.append(ref))
    handle = srv.VaultSFTPHandle(flags=os.O_WRONLY)
    handle.upload_marker_ref = ("vault", "folder", "name", "token")
    handle._marker_last_refresh = time.monotonic() - 25          # under a tenth of 300 s: not yet
    handle._refresh_marker()
    assert refreshed == []
    handle._marker_last_refresh = time.monotonic() - 31          # past it: now
    handle._refresh_marker()
    assert refreshed == [("vault", "folder", "name", "token")]
    handle._refresh_marker()                                     # and not again straight away
    assert len(refreshed) == 1
    # The interval comes from the named constant, read when the write happens -- not from a
    # literal that happens to equal it today. The invariant test computes with the constant, so a
    # literal here would let that test keep passing after the constant moved.
    monkeypatch.setattr(srv, "_MARKER_REFRESH_DIVISOR", 2)
    handle._marker_last_refresh = time.monotonic() - 149         # under half of 300 s: not yet
    handle._refresh_marker()
    assert len(refreshed) == 1
    handle._marker_last_refresh = time.monotonic() - 151
    handle._refresh_marker()
    assert len(refreshed) == 2


def test_the_watchdog_never_sleeps_longer_between_sweeps_than_the_marker_arithmetic_allows(monkeypatch):
    # However long the window, the loop sleeps at most MAX_SWEEP_SECONDS: the other number the
    # marker's refresh interval is sized against. No upload is involved; the loop is turned once.
    import threading
    import time
    from types import SimpleNamespace
    from app.sftp import sftp_server as srv
    stop = threading.Event()
    slept = []
    clock = SimpleNamespace(monotonic=time.monotonic, sleep=lambda s: (slept.append(s), stop.set()))
    monkeypatch.setattr(srv, "time", clock)
    monkeypatch.setattr(srv, "_liveness", srv._Liveness())
    monkeypatch.setattr(srv.settings, "sftp_write_progress_timeout_seconds", 86400)
    srv._WriteProgressWatchdog().run(stop)
    assert slept == [srv._WriteProgressWatchdog.MAX_SWEEP_SECONDS] and slept[0] <= 5
