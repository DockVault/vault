"""Stored bytes are on the disk before a row or an answer says they exist, offline.

A file closed with close() is in the kernel's page cache; the kernel writes it out some seconds
later. The database forces each commit to the disk before it answers. So a host that lost power a
few seconds after an upload had been confirmed came back with the file's row and without its bytes:
listed, and not downloadable. Every writer now syncs the file's content before it closes or renames
it, and its name (the directory) after, before the commit.

These record what reached the disk in order, by wrapping ``os.fsync``: each call is noted as the kind
of object it forced (a file, with its size at that moment, or a directory) and the inode, and a test
adds its own marks between them ("commit" where the row would be written). On Windows a directory
cannot be synced, so there the directory steps are absent and only they are.

What no test here can show: that the bytes survive a power cut. A killed process keeps everything it
wrote (the kernel still has it), so only pulling the power proves it, and that is not something a test
suite does. These show the order, and that a failed sync fails the upload with no row written.
"""
from __future__ import annotations

import contextlib
import errno
import os
import stat
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

pytestmark = pytest.mark.unit

#: Whether the directory steps exist on this platform.
DIRS = os.name != "nt"


class _Disk:
    """What was forced to the disk, in order, and the marks a test puts between."""

    def __init__(self, monkeypatch):
        self.events = []
        self.fail_kind = None
        self.on_file = None
        real = os.fsync

        def fsync(fd):
            st = os.fstat(fd)
            kind = "dir" if stat.S_ISDIR(st.st_mode) else "file"
            if kind == self.fail_kind:
                raise OSError(errno.EIO, "Input/output error")
            if kind == "file" and self.on_file is not None:
                self.on_file(fd)
            self.events.append((kind, st.st_ino, st.st_size))
            return real(fd)

        monkeypatch.setattr(os, "fsync", fsync)

    def mark(self, what):
        self.events.append((what,))

    def kinds(self):
        return [event[0] for event in self.events]


@pytest.fixture
def disk(monkeypatch):
    return _Disk(monkeypatch)


def _ino(path):
    return os.stat(path).st_ino


def _expect(*steps):
    """The steps a writer takes, with the directory ones dropped where they cannot happen."""
    return [s for s in steps if DIRS or s != "dir"]


# ---- the helpers ----------------------------------------------------------------------------------

def test_a_file_is_flushed_then_forced_to_the_disk(disk, tmp_path):
    from app.core import durable_write
    path = tmp_path / "f"
    with open(path, "wb") as handle:
        handle.write(b"x" * 1000)              # still in Python's buffer
        durable_write.sync_file(handle)
    assert disk.events == [("file", _ino(path), 1000)], "the buffer was not flushed before the sync"


def test_a_descriptor_is_forced_too(disk, tmp_path):
    from app.core import durable_write
    path = tmp_path / "f"
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        os.write(fd, b"key")
        durable_write.sync_file(fd)
    finally:
        os.close(fd)
    assert disk.events == [("file", _ino(path), 3)]


@pytest.mark.skipif(not DIRS, reason="a directory cannot be synced on Windows")
def test_a_directory_is_synced_through_a_descriptor_of_its_own(disk, tmp_path, monkeypatch):
    from app.core import durable_write
    closed = []
    real_close = os.close
    monkeypatch.setattr(os, "close", lambda fd: (closed.append(fd), real_close(fd))[1])
    durable_write.sync_directory(tmp_path)
    assert disk.events == [("dir", _ino(tmp_path), os.stat(tmp_path).st_size)]
    assert len(closed) == 1, "the directory's descriptor was not closed"


def test_only_the_directory_step_is_skipped_where_it_cannot_be_done(disk, tmp_path, monkeypatch):
    from app.core import durable_write
    assert durable_write.DIRECTORY_SYNC is (os.name != "nt")
    monkeypatch.setattr(durable_write, "DIRECTORY_SYNC", False)
    monkeypatch.setattr(os, "open", lambda *a, **k: pytest.fail("a directory was opened"))
    durable_write.sync_directory(tmp_path)
    with open(tmp_path / "f", "wb") as handle:
        handle.write(b"data")
        durable_write.sync_file(handle)
    assert disk.kinds() == ["file"], "the file itself must still be synced"


@pytest.mark.skipif(not DIRS, reason="a directory cannot be synced on Windows")
def test_a_filesystem_that_cannot_sync_a_directory_is_not_an_error(tmp_path, monkeypatch):
    """EINVAL is what a filesystem without directory sync answers (PostgreSQL ignores it too); an
    I/O error is a real failure."""
    from app.core import durable_write
    for code, raises in ((errno.EINVAL, False), (errno.EIO, True)):
        def fsync(fd, code=code):
            raise OSError(code, os.strerror(code))
        monkeypatch.setattr(os, "fsync", fsync)
        if raises:
            with pytest.raises(OSError) as caught:
                durable_write.sync_directory(tmp_path)
            assert caught.value.errno == errno.EIO
        else:
            durable_write.sync_directory(tmp_path)


def test_new_directories_are_synced_into_their_parents_from_the_top_down(disk, tmp_path):
    from app.core import durable_write
    target = tmp_path / "a" / "b" / "c"
    durable_write.make_directories(target)
    assert target.is_dir()
    parents = [tmp_path, tmp_path / "a", tmp_path / "a" / "b"]
    assert [(k, i) for k, i, _ in disk.events] == (
        [("dir", _ino(p)) for p in parents] if DIRS else [])


def test_a_directory_that_is_there_already_is_left_alone(disk, tmp_path):
    from app.core import durable_write
    (tmp_path / "a").mkdir()
    durable_write.make_directories(tmp_path / "a")
    assert disk.events == []


def test_a_directory_another_process_made_meanwhile_is_synced_too(disk, tmp_path, monkeypatch):
    from app.core import durable_write
    target = tmp_path / "raced"
    real_mkdir = Path.mkdir

    def mkdir(self, *a, **k):
        if self == target:
            real_mkdir(self)                    # the other process got there first
            raise FileExistsError(errno.EEXIST, "File exists", str(self))
        return real_mkdir(self, *a, **k)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    durable_write.make_directories(target)
    assert [(k, i) for k, i, _ in disk.events] == ([("dir", _ino(tmp_path))] if DIRS else [])


def test_a_file_in_the_way_is_refused_as_mkdir_refuses_it(tmp_path):
    from app.core import durable_write
    (tmp_path / "x").write_bytes(b"")
    with pytest.raises(FileExistsError):
        durable_write.make_directories(tmp_path / "x")
    with pytest.raises(FileExistsError):
        durable_write.make_directories(tmp_path / "x" / "y")


@pytest.mark.skipif(not DIRS, reason="a directory cannot be synced on Windows")
def test_a_directory_that_cannot_be_opened_to_read_is_skipped_as_postgresql_skips_it(tmp_path,
                                                                                     monkeypatch):
    """Permission to create entries in a directory but not to read it: there is no descriptor to sync
    it through. Any other failure to open it is raised."""
    from app.core import durable_write
    for code, raises in ((errno.EACCES, False), (errno.ENOENT, True), (errno.EIO, True)):
        def fails(path, flags, *args, code=code, **kwargs):
            raise OSError(code, os.strerror(code), path)
        monkeypatch.setattr(os, "open", fails)
        if raises:
            with pytest.raises(OSError) as caught:
                durable_write.sync_directory(tmp_path)
            assert caught.value.errno == code
        else:
            durable_write.sync_directory(tmp_path)


@pytest.mark.skipif(not DIRS, reason="a directory cannot be synced on Windows")
def test_a_directory_is_made_in_a_parent_that_cannot_be_read(tmp_path):
    from app.core import durable_write
    parent = tmp_path / "drop"
    parent.mkdir()
    parent.chmod(0o300)                         # create entries and pass through; no reading
    try:
        durable_write.make_directories(parent / "storage" / "vaults")
        assert (parent / "storage" / "vaults").is_dir()
    finally:
        parent.chmod(0o700)


def test_a_start_syncs_the_storage_and_host_key_directories_it_creates(disk, tmp_path):
    """Every process start makes them, before an upload or a host key would: a custom path that does
    not exist yet is created there, and synced into its parent like every other directory."""
    from app.core.config import Settings
    storage = tmp_path / "data" / "storage"
    key_dir = tmp_path / "keys" / "sftp"
    paths = SimpleNamespace(file_storage_path=str(storage),
                            sftp_host_key_path=str(key_dir / "ssh_host_key"))
    Settings.ensure_directories(paths)
    assert storage.is_dir() and key_dir.is_dir()
    parents = [tmp_path, tmp_path / "data", tmp_path, tmp_path / "keys"]
    assert [(k, i) for k, i, _ in disk.events] == (
        [("dir", _ino(p)) for p in parents] if DIRS else [])
    disk.events.clear()
    Settings.ensure_directories(paths)
    assert disk.events == [], "a directory that is there already is left as it is"


# ---- the upload context: every file a vault stores is written through it --------------------------

def _codecs():
    from app.core import security
    v, f = uuid.uuid4(), uuid.uuid4()
    return {"standard": (security.GcmChunkStreamCodecV2(v, f), v, f),
            "zero-knowledge": (security.IdentityChunkCodec(), v, f)}


@pytest.mark.parametrize("kind", ["standard", "zero-knowledge"])
def test_the_file_and_its_name_are_on_the_disk_when_the_context_closes(disk, tmp_path, kind):
    from app.services.streaming_upload import StreamingUploadContext
    codec, _v, file_id = _codecs()[kind]
    blob = tmp_path / "blob"
    with StreamingUploadContext(file_id, blob, codec) as ctx:
        ctx.write_chunk(b"first ")
        ctx.write_chunk(b"second")
    disk.mark("commit")                         # what every caller does next
    assert disk.kinds() == _expect("file", "dir", "commit")
    assert disk.events[0] == ("file", _ino(blob), blob.stat().st_size), (
        "the file was synced before its last bytes (the terminal) were written")
    if DIRS:
        assert disk.events[1][1] == _ino(tmp_path), "a directory other than the file's was synced"


def test_a_file_sync_that_fails_fails_the_upload_and_leaves_nothing(disk, tmp_path):
    from app.services.streaming_upload import StreamingUploadContext
    codec, _v, file_id = _codecs()["standard"]
    blob = tmp_path / "blob"
    disk.fail_kind = "file"
    with pytest.raises(OSError) as caught:
        with StreamingUploadContext(file_id, blob, codec) as ctx:
            ctx.write_chunk(b"content")
    assert caught.value.errno == errno.EIO
    assert not blob.exists(), "a file that may not be on the disk was left for a row to point at"
    assert disk.events == [], "the directory was synced after the file failed to be"


@pytest.mark.skipif(not DIRS, reason="a directory cannot be synced on Windows")
def test_a_directory_sync_that_fails_fails_the_upload_and_leaves_nothing(disk, tmp_path):
    from app.services.streaming_upload import StreamingUploadContext
    codec, _v, file_id = _codecs()["zero-knowledge"]
    blob = tmp_path / "blob"
    disk.fail_kind = "dir"
    with pytest.raises(OSError):
        with StreamingUploadContext(file_id, blob, codec) as ctx:
            ctx.write_chunk(b"opaque")
    assert not blob.exists()
    assert disk.kinds() == ["file"]


def test_nothing_is_synced_on_the_error_path(disk, tmp_path):
    from app.services.streaming_upload import StreamingUploadContext
    codec, _v, file_id = _codecs()["standard"]
    blob = tmp_path / "blob"
    with pytest.raises(RuntimeError):
        with StreamingUploadContext(file_id, blob, codec) as ctx:
            ctx.write_chunk(b"partial")
            raise RuntimeError("the upload failed")
    assert not blob.exists()
    assert disk.events == []


def test_a_second_exit_after_a_failed_one_does_nothing(disk, tmp_path):
    """The SFTP streaming path discards its upload with an error exit when the clean exit raised."""
    from app.services.streaming_upload import StreamingUploadContext
    codec, _v, file_id = _codecs()["standard"]
    blob = tmp_path / "blob"
    ctx = StreamingUploadContext(file_id, blob, codec).__enter__()
    ctx.write_chunk(b"content")
    disk.fail_kind = "file"
    with pytest.raises(OSError):
        ctx.__exit__(None, None, None)
    assert ctx.__exit__(RuntimeError, RuntimeError("discard"), None) is False
    assert not blob.exists() and disk.events == []


# ---- the vault service: a new upload, and a copy (file copy, move to another vault, folder copy) ---

class _Query:
    def __init__(self, answer):
        self._answer = answer

    def filter(self, *a, **k):
        return self

    def first(self):
        return self._answer


class _DB:
    def __init__(self, vault):
        self.vault = vault

    def query(self, *entities):
        from app.core.models import Vault
        return _Query(self.vault if entities and entities[0] is Vault else None)


def _service(tmp_path, disk):
    from app.services import vault_service as vs
    vault = SimpleNamespace(id=uuid.uuid4(), type="standard", expire_files_after_days=None,
                            expire_files_unit=None, size_limit=None, total_size_bytes=0)
    svc = vs.VaultService.__new__(vs.VaultService)
    svc.db = _DB(vault)
    svc.storage_path = tmp_path
    svc.permission_service = SimpleNamespace(require_vault_permission=lambda *a, **k: None)
    committed = []

    def finalize(file_info, total_size, checksum, **kw):
        disk.mark("commit")
        committed.append(file_info)
        return SimpleNamespace(id=file_info["id"], password_hash=None)

    svc.finalize_streaming_upload = finalize
    return svc, vault, committed


def test_an_upload_through_the_service_is_on_the_disk_before_its_row(disk, tmp_path):
    """New directories first (the vault's, then its file directory), then the file, then its name,
    then the commit."""
    svc, vault, committed = _service(tmp_path, disk)
    file_info, ctx = svc.upload_file_streaming(vault.id, "report.pdf", SimpleNamespace(id="u"))
    with ctx:
        ctx.write_chunk(b"bytes of a report")
    svc.finalize_streaming_upload(file_info, ctx.total_bytes, ctx.get_checksum())
    blob = tmp_path / file_info["storage_path"]
    files_dir = blob.parent
    assert [(k, *rest[:1]) for k, *rest in disk.events] == [
        e for e in (("dir", _ino(tmp_path)), ("dir", _ino(files_dir.parent)), ("file", _ino(blob)),
                    ("dir", _ino(files_dir)), ("commit",)) if DIRS or e[0] != "dir"]


def _reader(chunks):
    return SimpleNamespace(chunks=lambda: iter(chunks), close=lambda: None)


def test_a_copy_is_on_the_disk_before_its_row(disk, tmp_path, monkeypatch):
    """What a file copy, a move to another vault (whose source is deleted next) and a folder copy
    write: the copy's bytes are synced before the copy's row exists."""
    from app.services import vault_service as vs
    svc, vault, committed = _service(tmp_path, disk)
    monkeypatch.setattr(vs, "would_exceed_deployment_storage", lambda db, n: (False, 0, 0))
    svc.open_download_stream = lambda *a, **k: _reader([b"one ", b"two"])
    source = SimpleNamespace(id=uuid.uuid4(), size_bytes=7, original_name="a.txt", name="a.txt",
                             mime_type="text/plain", password_hash=None)
    svc._stream_copy_file_record(source, SimpleNamespace(id="u"), vault.id, None)
    (info,) = committed
    blob = tmp_path / info["storage_path"]
    assert disk.kinds() == _expect("dir", "dir", "file", "dir", "commit")
    (synced,) = [event for event in disk.events if event[0] == "file"]
    assert synced[1:] == (_ino(blob), blob.stat().st_size)


def test_a_copy_whose_sync_fails_writes_no_row_and_leaves_no_file(disk, tmp_path, monkeypatch):
    from app.services import vault_service as vs
    svc, vault, committed = _service(tmp_path, disk)
    monkeypatch.setattr(vs, "would_exceed_deployment_storage", lambda db, n: (False, 0, 0))
    svc.open_download_stream = lambda *a, **k: _reader([b"one ", b"two"])
    source = SimpleNamespace(id=uuid.uuid4(), size_bytes=7, original_name="a.txt", name="a.txt",
                             mime_type="text/plain", password_hash=None)
    disk.fail_kind = "file"
    with pytest.raises(OSError):
        svc._stream_copy_file_record(source, SimpleNamespace(id="u"), vault.id, None)
    assert committed == [] and "commit" not in disk.kinds()
    assert list((tmp_path / str(vault.id) / "files").iterdir()) == []


# ---- SFTP: the streaming write and the buffered one -----------------------------------------------

def _sftp_fakes(monkeypatch, tmp_path, disk):
    from app.sftp import sftp_server as mod
    from app.sftp.sftp_server import SFTPServerInterface

    @contextlib.contextmanager
    def no_db():
        yield object()

    monkeypatch.setattr(mod, "get_db_context", no_db)
    interface = SFTPServerInterface(server=object())
    committed = []

    def finalize(**kw):
        if vault_service.insert_error is not None:
            disk.mark("insert failed")
            raise vault_service.insert_error
        disk.mark("commit")
        committed.append(kw)
        return SimpleNamespace(id="F")

    vault_service = SimpleNamespace(storage_path=tmp_path, finalize_streaming_upload=finalize,
                                    insert_error=None)
    # The persist check locks the vault row until its session ends; "lock" marks where it starts.
    answers = []

    def authorize(db, v, f, size):
        disk.mark("lock")
        verdict = answers.pop(0) if answers else True
        return (SimpleNamespace(id="U"), SimpleNamespace(id="V"), vault_service) if verdict else None

    monkeypatch.setattr(interface, "_authorize_upload_persist", authorize)
    monkeypatch.setattr(interface, "_audit", lambda *a, **k: disk.mark("audit"))
    vault_service.answers = answers
    return mod, interface, vault_service, committed


def _streaming(monkeypatch, tmp_path, disk, insert_error=None):
    from app.services.streaming_upload import StreamingUploadContext
    from app.core import security
    from app.sftp.sftp_server import VaultSFTPHandle, _StreamingUpload
    mod, interface, _vs, committed = _sftp_fakes(monkeypatch, tmp_path, disk)
    _vs.insert_error = insert_error
    handle = VaultSFTPHandle(flags=os.O_WRONLY)
    handle._interface = interface
    stream = _StreamingUpload(handle=handle, interface=interface, vault_id="V", folder_id=None,
                              filename="report.pdf", can_overwrite=True, max_bytes=0, reorder_bytes=0)
    blob = tmp_path / "blob"
    ctx = StreamingUploadContext(uuid.uuid4(), blob, security.IdentityChunkCodec()).__enter__()
    ctx.write_chunk(b"streamed record")
    stream._ctx, stream._started = ctx, True
    stream._file_info = {"storage_path": "blob"}
    monkeypatch.setattr(stream._assembler, "finish", lambda: None)
    return stream, blob, committed


def test_a_small_sftp_streaming_upload_is_on_the_disk_before_its_row(disk, tmp_path, monkeypatch):
    """Below PRESYNC_BYTES: one sync of the file, under the lock, then its directory, then the row."""
    stream, blob, committed = _streaming(monkeypatch, tmp_path, disk)
    stream.close()
    assert disk.kinds() == _expect("lock", "file", "dir", "commit", "audit")
    assert disk.events[1][1] == _ino(blob) and len(committed) == 1
    assert blob.read_bytes() == b"streamed record", "the committed file's blob was removed"


def test_a_large_sftp_streaming_upload_is_synced_before_the_vault_lock(disk, tmp_path, monkeypatch):
    """From PRESYNC_BYTES on, what was streamed is synced before the vault row is locked; under the
    lock only the clean exit's sync (of what was written since) and the directory's, then the row."""
    from app.sftp.sftp_server import _StreamingUpload
    assert _StreamingUpload.PRESYNC_BYTES == 8 * 1024 * 1024
    stream, blob, committed = _streaming(monkeypatch, tmp_path, disk)
    monkeypatch.setattr(stream, "PRESYNC_BYTES", len(b"streamed record"))
    stream.close()
    assert disk.kinds() == _expect("file", "lock", "file", "dir", "commit", "audit")
    assert disk.events[0][1] == _ino(blob) and len(committed) == 1
    assert blob.read_bytes() == b"streamed record", "the committed file's blob was removed"


def test_an_sftp_streaming_upload_whose_sync_fails_writes_no_row(disk, tmp_path, monkeypatch, capsys):
    stream, blob, committed = _streaming(monkeypatch, tmp_path, disk)
    monkeypatch.setattr(stream, "PRESYNC_BYTES", 1)
    disk.fail_kind = "file"
    stream.close()
    assert committed == [] and not blob.exists()
    assert "lock" not in disk.kinds(), "the vault row was locked for an upload that cannot be kept"
    assert "event upload.stream.finalize-failed err=OSError" in capsys.readouterr().out


def test_a_small_sftp_streaming_upload_whose_sync_fails_writes_no_row(disk, tmp_path, monkeypatch):
    stream, blob, committed = _streaming(monkeypatch, tmp_path, disk)
    disk.fail_kind = "file"
    stream.close()
    assert committed == [] and not blob.exists() and disk.kinds() == ["lock"]


def test_an_sftp_streaming_upload_whose_final_sync_fails_writes_no_row(disk, tmp_path, monkeypatch):
    """The sync under the lock can fail too (here, the directory's): still no row, no blob."""
    if not DIRS:
        pytest.skip("a directory cannot be synced on Windows")
    stream, blob, committed = _streaming(monkeypatch, tmp_path, disk)
    disk.fail_kind = "dir"
    stream.close()
    assert committed == [] and not blob.exists()


def test_an_sftp_streaming_upload_whose_insert_fails_leaves_no_blob(disk, tmp_path, monkeypatch,
                                                                    capsys):
    """The file is complete and on the disk when the insert fails (the database went away, say):
    the written file is removed, so nothing is left on the disk that no row knows of."""
    from sqlalchemy.exc import OperationalError
    stream, blob, committed = _streaming(
        monkeypatch, tmp_path, disk,
        insert_error=OperationalError(None, None, Exception("server closed the connection")))
    stream.close()
    assert disk.kinds() == _expect("lock", "file", "dir", "insert failed")
    assert committed == [] and not blob.exists()
    assert "event upload.stream.finalize-failed err=OperationalError" in capsys.readouterr().out


def _buffered(monkeypatch, tmp_path, disk, insert_error=None):
    from app.services.streaming_upload import StreamingUploadContext
    from app.core import security
    mod, interface, vault_service, committed = _sftp_fakes(monkeypatch, tmp_path, disk)
    vault_service.insert_error = insert_error
    blob = tmp_path / "blob"

    def upload_file_streaming(**kw):
        return ({"storage_path": "blob"},
                StreamingUploadContext(uuid.uuid4(), blob, security.IdentityChunkCodec()))

    vault_service.upload_file_streaming = upload_file_streaming
    staged = tmp_path / "staged"
    staged.write_bytes(b"buffered upload")
    finalize = interface._make_upload_finalizer("V", None, "report.pdf", True)
    return finalize, staged, blob, committed, vault_service.answers


def test_an_sftp_buffered_upload_is_on_the_disk_before_its_row(disk, tmp_path, monkeypatch):
    """Checked first (before any blob is written), then encrypted, written and synced with no lock
    held, then checked again under the lock and committed."""
    finalize, staged, blob, committed, answers = _buffered(monkeypatch, tmp_path, disk)
    finalize(str(staged))
    assert disk.kinds() == _expect("lock", "file", "dir", "lock", "commit", "audit")
    assert disk.events[1][1] == _ino(blob) and len(committed) == 1
    assert blob.read_bytes() == b"buffered upload", "the committed file's blob was removed"


def test_an_sftp_buffered_upload_whose_sync_fails_writes_no_row(disk, tmp_path, monkeypatch):
    finalize, staged, blob, committed, answers = _buffered(monkeypatch, tmp_path, disk)
    disk.fail_kind = "file"
    with pytest.raises(OSError):
        finalize(str(staged))       # the handle's close() turns this into upload.finalize.failed
    assert committed == [] and not blob.exists()
    assert disk.kinds() == ["lock"], "the insert was authorized for a file that may not be on the disk"


def test_an_sftp_buffered_upload_refused_up_front_writes_nothing(disk, tmp_path, monkeypatch):
    finalize, staged, blob, committed, answers = _buffered(monkeypatch, tmp_path, disk)
    answers.append(False)
    finalize(str(staged))
    assert committed == [] and not blob.exists() and disk.kinds() == ["lock"]


def test_an_sftp_buffered_upload_refused_at_the_insert_leaves_no_blob(disk, tmp_path, monkeypatch):
    """A change while the file was written (a quota filled, a session ended) is caught at the insert,
    and the written file is removed."""
    finalize, staged, blob, committed, answers = _buffered(monkeypatch, tmp_path, disk)
    answers.extend([True, False])
    finalize(str(staged))
    assert committed == [] and not blob.exists()
    assert disk.kinds() == _expect("lock", "file", "dir", "lock")


def test_an_sftp_buffered_upload_whose_insert_fails_leaves_no_blob(disk, tmp_path, monkeypatch):
    """Authorized again under the lock, then the insert itself fails: the written file is removed
    and the failure reaches the handle's close(), which logs it."""
    from sqlalchemy.exc import OperationalError
    error = OperationalError(None, None, Exception("server closed the connection"))
    finalize, staged, blob, committed, answers = _buffered(monkeypatch, tmp_path, disk,
                                                           insert_error=error)
    with pytest.raises(OperationalError):
        finalize(str(staged))
    assert disk.kinds() == _expect("lock", "file", "dir", "lock", "insert failed")
    assert committed == [] and not blob.exists()


# ---- chunked uploads: each chunk before the answer that it was received ---------------------------

async def _pieces(*pieces):
    for piece in pieces:
        yield piece


def test_a_staged_chunk_is_whole_on_the_disk_before_it_is_renamed(disk, tmp_path):
    from app.core.upload_chunk_crypto import open_staged_chunk, seal_stream_to_file, sealed_plaintext_size
    session, part = uuid.uuid4(), tmp_path / ".chunk_000000.part"
    seen = []
    # At the sync the length field must already be back-filled, and the chunk read back whole.
    disk.on_file = lambda fd: seen.append((sealed_plaintext_size(part),
                                           b"".join(open_staged_chunk(part, session, 0))))
    written, _digest = run_coroutine(seal_stream_to_file(_pieces(b"a" * 10, b"b" * 5), part,
                                                       1000, session, 0))
    assert written == 15 and seen == [(15, b"a" * 10 + b"b" * 5)]
    assert disk.events == [("file", _ino(part), part.stat().st_size)]


def test_a_staged_chunk_whose_sync_fails_is_removed(disk, tmp_path):
    from app.core.upload_chunk_crypto import seal_stream_to_file
    part = tmp_path / ".chunk_000000.part"
    disk.fail_kind = "file"
    with pytest.raises(OSError):
        run_coroutine(seal_stream_to_file(_pieces(b"data"), part, 1000, uuid.uuid4(), 0))
    assert not part.exists()


def test_an_empty_or_oversized_chunk_is_never_synced(disk, tmp_path):
    from app.core.upload_chunk_crypto import seal_stream_to_file
    from app.services.streaming_upload import ChunkTooLarge, EmptyBody
    part = tmp_path / ".chunk_000000.part"
    with pytest.raises(EmptyBody):
        run_coroutine(seal_stream_to_file(_pieces(), part, 1000, uuid.uuid4(), 0))
    with pytest.raises(ChunkTooLarge):
        run_coroutine(seal_stream_to_file(_pieces(b"x" * 20), part, 10, uuid.uuid4(), 0))
    assert disk.events == [] and not part.exists()


def test_the_plain_bounded_receive_syncs_the_same_way(disk, tmp_path):
    from app.services.streaming_upload import EmptyBody, receive_bounded
    dest = tmp_path / "body"
    written, _ = run_coroutine(receive_bounded(_pieces(b"abc", b"def"), dest, 100))
    assert written == 6 and disk.events == [("file", _ino(dest), 6)]
    with pytest.raises(EmptyBody):
        run_coroutine(receive_bounded(_pieces(), tmp_path / "empty", 100))
    assert len(disk.events) == 1 and not (tmp_path / "empty").exists()


# ---- the SFTP host key, and the overwrite before a secure delete ----------------------------------

def test_a_new_host_key_is_on_the_disk_file_and_name(disk, tmp_path):
    """A key emptied by a power cut soon after the first start would stop every later start."""
    from app.sftp.host_key import generate_ed25519_host_key, load_host_key
    key = tmp_path / "keys" / "ssh_host_rsa_key"
    generate_ed25519_host_key(key)
    assert [(k, i) for k, i, _ in disk.events] == [
        e for e in (("dir", _ino(tmp_path)), ("file", _ino(key)), ("dir", _ino(key.parent)))
        if DIRS or e[0] != "dir"]
    assert disk.events[-2 if DIRS else -1][2] == key.stat().st_size > 0
    assert load_host_key(key) is not None


def test_a_secure_delete_syncs_its_overwrite_before_the_unlink(disk, tmp_path, monkeypatch):
    from app.services.encrypted_file_storage import EncryptedFileStorage
    blob = tmp_path / "blob"
    blob.write_bytes(b"secret" * 100)
    inode = _ino(blob)
    real_unlink = Path.unlink
    monkeypatch.setattr(Path, "unlink",
                        lambda self, *a, **k: (disk.mark("unlink"), real_unlink(self, *a, **k))[1])
    EncryptedFileStorage(tmp_path).secure_delete(blob)
    assert disk.events == [("file", inode, 600), ("unlink",)] and not blob.exists()
