"""The files the audit log's integrity chain writes reach the disk in order, offline: the head record and the
restore mark (app/core/audit_head_record.py), the seals a discard saves (app/core/audit_chain_recovery.py), and the
SFTP host key the web server writes at its start (app/sftp/host_key.py).

Each goes through app/core/durable_write.py: a file given its owner first (a host command runs as root), synced
before it is renamed into place or closed, its directory synced after, and only then the record counts as written
or the database commits what the file stands for. A sync that fails says so: the head record is then unwritable,
the restore mark's removal is not taken for done, the discard is abandoned with every seal kept, and a host key
whose bytes may not be on the disk never gets its path.

These record what reached the disk by wrapping ``os.fsync`` (a file, or a directory, and its inode), with marks
between. On Windows a directory cannot be synced, so the directory steps are absent there.
"""
from __future__ import annotations

import errno
import json
import os
import stat
from datetime import timedelta

import pytest
import sqlalchemy as sa

from _audit_chain_env import Env, T0
from app.core import audit_chain_recovery as recovery
from app.core import audit_head_record as hr
from app.core import audit_integrity as ai
from app.core.models import AuditSeal
from test_audit_chain_guards import _forge

pytestmark = pytest.mark.unit

DIRS = os.name != "nt"


class _Disk:
    """What was forced to the disk, in order, the marks between, and a kind of sync made to fail."""

    def __init__(self, monkeypatch):
        self.events = []
        self.fail_kind = None
        real = os.fsync

        def fsync(fd):
            st = os.fstat(fd)
            kind = "dir" if stat.S_ISDIR(st.st_mode) else "file"
            if kind == self.fail_kind:
                raise OSError(errno.EIO, "Input/output error")
            self.events.append((kind, st.st_ino))
            return real(fd)
        monkeypatch.setattr(os, "fsync", fsync)
        real_replace = os.replace
        monkeypatch.setattr(os, "replace", lambda a, b: (self.events.append(("replace", os.stat(a).st_ino)),
                                                         real_replace(a, b))[1])

    def mark(self, what):
        self.events.append((what,))

    def kinds(self):
        return [e[0] for e in self.events]


@pytest.fixture
def disk(monkeypatch):
    return _Disk(monkeypatch)


def _expect(*steps):
    return [s for s in steps if DIRS or s != "dir"]


def _as_root(monkeypatch, disk):
    """A host command run as root: the file is handed to the directory's owner (recorded, not done)."""
    monkeypatch.setattr(hr.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(hr.os, "chown", lambda path, uid, gid: disk.mark("chown"), raising=False)


# --------------------------------------------------------------------------- the head record and the restore mark

def test_the_head_record_is_owned_synced_renamed_and_its_directory_synced(disk, tmp_path, monkeypatch):
    path = tmp_path / "audit-chain-head.json"
    _as_root(monkeypatch, disk)
    hr._write_file(str(path), {"version": hr.VERSION, "seq": 7})
    ino = os.stat(path).st_ino
    assert disk.kinds() == _expect("chown", "file", "replace", "dir"), disk.events
    assert disk.events[1] == ("file", ino) and disk.events[2] == ("replace", ino)
    if DIRS:
        assert disk.events[3] == ("dir", os.stat(tmp_path).st_ino)
    assert json.loads(path.read_text(encoding="utf-8"))["seq"] == 7
    assert [p.name for p in tmp_path.iterdir()] == [path.name]          # no temporary file left


def test_a_head_record_in_a_new_directory_has_that_directory_synced_into_its_parent(disk, tmp_path):
    path = tmp_path / "keys" / "audit-chain-head.json"
    hr._write_file(str(path), {"version": hr.VERSION})
    assert disk.kinds() == _expect("dir", "file", "replace", "dir"), disk.events
    if DIRS:
        assert disk.events[0] == ("dir", os.stat(tmp_path).st_ino)
        assert disk.events[-1] == ("dir", os.stat(tmp_path / "keys").st_ino)


@pytest.mark.parametrize("failing", ["file"] + (["dir"] if DIRS else []))
def test_a_head_record_that_cannot_be_synced_is_unwritable(disk, tmp_path, failing):
    store = hr.HeadStore(str(tmp_path / "audit-chain-head.json"))
    disk.fail_kind = failing
    record = store.write(lambda rec: dict(rec, seq=3), T0)
    assert record["seq"] == 3                                     # kept in memory
    assert store.unwritable and store.unwritable.startswith("OSError"), store.unwritable
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".audit-chain-head.")]   # its temporary file gone
    disk.fail_kind = None
    store.write(lambda rec: rec, T0)
    assert store.unwritable is None


def test_the_restore_mark_is_written_the_same_way(disk, tmp_path, monkeypatch):
    path = str(tmp_path / "audit-chain-head.json")
    _as_root(monkeypatch, disk)
    hr.write_mark(path, {"at": "2026-10-20T09:00:00Z", "bundle": "b"})
    assert disk.kinds() == _expect("chown", "file", "replace", "dir"), disk.events
    assert hr.read_mark(path) == {"at": "2026-10-20T09:00:00Z", "bundle": "b"}


def test_the_restore_marks_removal_syncs_its_directory(disk, tmp_path):
    path = str(tmp_path / "audit-chain-head.json")
    hr.write_mark(path, {"at": "x"})
    disk.events.clear()
    hr.remove_mark(path)
    assert hr.read_mark(path) is None
    assert disk.kinds() == _expect("dir"), disk.events
    hr.remove_mark(path)                                          # none there: nothing to sync
    assert disk.kinds() == _expect("dir")


@pytest.mark.skipif(not DIRS, reason="a directory cannot be synced on Windows")
def test_a_restore_marks_removal_that_cannot_be_synced_is_not_taken_for_done(disk, tmp_path):
    path = str(tmp_path / "audit-chain-head.json")
    hr.write_mark(path, {"at": "x"})
    disk.fail_kind = "dir"
    with pytest.raises(OSError) as raised:
        hr.remove_mark(path)
    assert raised.value.errno == errno.EIO


# --------------------------------------------------------------------------- the seals a discard saves

@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def _host(env):
    st = ai.ChainState(settings=env.settings, clock=env.clock)
    st.process_kind = "host"
    return st


def _refused_on_its_face(env):
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    seq = _forge(env, "ack", {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin",
                              "user_id": None, "request": None}, sealed_at=env.clock() - timedelta(hours=3))
    env.clock.advance(minutes=30)
    assert env.seal().stopped == "after-record-invalid"
    return seq


def test_the_seals_a_discard_saves_are_on_the_disk_before_their_deletion_commits(env, disk, monkeypatch):
    seq = _refused_on_its_face(env)
    seen = recovery.after_record(env.engine, _host(env), discard=True, read=True)
    _as_root(monkeypatch, disk)
    disk.events.clear()
    sa.event.listen(env.engine, "commit", lambda conn: disk.mark("commit"))
    done = recovery.after_record(env.engine, _host(env), discard=True, expect=seen["state"])
    saved = done["saved"]
    at = disk.events.index(("file", os.stat(saved).st_ino))
    assert disk.events[at - 1] == ("chown",), disk.events               # its owner first
    synced = at
    if DIRS:
        assert disk.events[at + 1] == ("dir", os.stat(os.path.dirname(saved)).st_ino), disk.events
        synced = at + 1
    assert ("commit",) in disk.events[synced + 1:], disk.events          # the seals' deletion commits after
    with open(saved, encoding="utf-8") as fh:
        assert json.load(fh)[0]["seq"] == seq
    assert env.seals()[-1].kind == "ack"


@pytest.mark.parametrize("failing", ["file"] + (["dir"] if DIRS else []))
def test_a_discard_whose_saved_seals_cannot_be_synced_deletes_nothing(env, disk, failing):
    seq = _refused_on_its_face(env)
    seen = recovery.after_record(env.engine, _host(env), discard=True, read=True)
    disk.fail_kind = failing
    with pytest.raises(OSError):
        recovery.after_record(env.engine, _host(env), discard=True, expect=seen["state"])
    disk.fail_kind = None
    with env.session() as db:
        assert db.get(AuditSeal, seq) is not None
    assert env.seals()[-1].seq == seq and env.seals()[-1].kind == "ack"      # the forged one, still there
    assert env.st.head_store().load()["discards"] == 0


# --------------------------------------------------------------------------- the SFTP host key

def test_a_host_key_that_cannot_be_synced_is_not_left_at_its_path(disk, tmp_path):
    from app.sftp.host_key import ensure_host_key
    path = tmp_path / "keys" / "ssh_host_rsa_key"
    path.parent.mkdir()
    disk.fail_kind = "file"
    assert ensure_host_key(path) is False
    assert not path.exists() and list(path.parent.iterdir()) == []      # nor its temporary copy
    disk.fail_kind = None
    assert ensure_host_key(path) is True and path.exists()
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.skipif(not DIRS, reason="a directory cannot be synced here")
def test_a_host_key_whose_directory_cannot_be_synced_stays_as_the_key(disk, tmp_path):
    """Its bytes were on the disk before it got its path: only the name may be lost, and while it is there it is
    the key every start uses, so it is not removed (an SFTP server may already serve it)."""
    from app.sftp.host_key import ensure_host_key, load_host_key
    path = tmp_path / "keys" / "ssh_host_rsa_key"
    path.parent.mkdir()
    disk.fail_kind = "dir"
    assert ensure_host_key(path) is False
    disk.fail_kind = None
    before = path.read_bytes()
    assert load_host_key(path) is not None and list(path.parent.iterdir()) == [path]
    assert ensure_host_key(path) is False and path.read_bytes() == before
