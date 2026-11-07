"""The free space the storage volume keeps (MIN_FREE_SPACE_GB, app/core/free_space.py), offline.

On the shipped defaults nothing else bounds the disk: no deployment storage limit, and what legal holds keep after a
deletion is in no vault's size, so a member of a held vault could upload and delete in turn until the disk was full,
and the database, which usually shares it, with it. Every write of a file's bytes now keeps at least the floor free:
by default the larger of 2 GB and 5% of the volume (never more than half of it), 0 turns it off, any other value is
that many GB.

- before a transfer starts, when its size is known: an upload's declared length, a chunked upload's declared size, a
  chunk's, a copy's (507 with the free space and the floor);
- while its bytes are written (StreamingUploadContext's guard): at the first write and every CHECK_EVERY_BYTES, so one
  transfer of unknown size cannot run the disk to its end; the file is removed;
- as its row is written (VaultService._claim_room), with its bytes on the disk: refused, rolled back and removed;
- an SFTP write stops with the reason as its status;
- a volume that reports no size, or whose free space cannot be read, is not checked.

These stub the volume's figures (shutil.disk_usage). test_free_space_floor_live.py runs a stack whose floor is above
its disk; test_api_storage_stats.py checks the floor the storage panel reports.
"""
import uuid
from collections import namedtuple
from pathlib import Path
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import free_space  # noqa: E402
from app.core.models import Vault  # noqa: E402
from test_storage_room_at_finish import MB, _DB, _copy_service, _vault, finish, limits  # noqa: E402,F401

pytestmark = pytest.mark.unit

GIB = 1024 ** 3
ROOT = Path(__file__).resolve().parent.parent
Usage = namedtuple("Usage", "total used free")


@pytest.fixture
def volume(monkeypatch):
    """The storage volume's figures, as shutil.disk_usage gives them, and the floor setting (-1: automatic)."""
    state = {"total": 100 * GIB, "free": 50 * GIB, "configured": -1, "asked": 0}

    def usage(path):
        state["asked"] += 1
        if isinstance(state["total"], Exception):
            raise state["total"]
        return Usage(state["total"], state["total"] - state["free"], state["free"])
    monkeypatch.setattr(free_space.shutil, "disk_usage", usage)
    monkeypatch.setattr(free_space, "configured_gb", lambda: state["configured"])
    monkeypatch.setattr(free_space, "_said", type(free_space._said)())
    return state


@pytest.mark.parametrize("total, configured, floor", [
    (10 * GIB, -1, 2 * GIB),                 # 5% of a small volume is less than 2 GB
    (100 * GIB, -1, 5 * GIB),                # 5% of a large one
    (100 * GIB, None, 5 * GIB),              # unset reads as automatic
    (100 * GIB, float("nan"), 5 * GIB),
    (100 * GIB, -7, 5 * GIB),
    (100 * GIB, "not a number", 5 * GIB),
    (100 * GIB, 0, 0),                       # off
    (100 * GIB, 25, 25 * GIB),
    (100 * GIB, 2.5, int(2.5 * GIB)),
])
def test_the_floor_is_the_larger_of_2_gb_and_5_percent_unless_set(total, configured, floor):
    assert free_space.floor_bytes(total, configured=configured if configured is not None else -1) == floor


@pytest.mark.parametrize("total, floor", [
    (GIB, GIB // 2),                         # 2 GB would be more than the whole volume
    (3 * GIB, 3 * GIB // 2),
    (4 * GIB, 2 * GIB),                      # exactly half: the two rules meet
    (6 * GIB, 2 * GIB),
])
def test_the_automatic_floor_is_never_more_than_half_the_volume(total, floor):
    assert free_space.floor_bytes(total, configured=-1) == floor


def test_a_small_volume_still_takes_uploads_on_the_default(volume):
    """A 1 GB volume with 900 MB free: on the default the floor is 512 MB, not 2 GB, so a 100 MB upload is let in
    and a 500 MB one is refused (it would leave 400 MB)."""
    volume["total"], volume["free"] = GIB, 900 * MB
    assert free_space.short_of(100 * MB) is None
    short = free_space.short_of(500 * MB)
    assert short == free_space.Room(free=900 * MB, floor=GIB // 2, total=GIB)


@pytest.mark.parametrize("configured", [float("inf"), float("-inf"), "inf", "Infinity", "-inf"])
def test_a_setting_that_is_not_a_finite_number_reads_as_the_default(volume, configured):
    """'inf' is a float the settings accept; read as GB it raised in int(), and every upload would have answered
    500. It reads as the default, as NaN and text do."""
    volume["configured"], volume["free"] = configured, 6 * GIB
    assert free_space.floor_bytes(100 * GIB, configured=configured) == 5 * GIB
    assert free_space.short_of(GIB) is None
    assert free_space.short_of(GIB + 1) == free_space.Room(free=6 * GIB, floor=5 * GIB, total=100 * GIB)


@pytest.mark.parametrize("raw, starts", [("inf", True), ("nan", True), ("-1", True), ("abc", False), ("", False)])
def test_inf_or_nan_reads_as_the_default_and_a_value_that_is_no_number_stops_the_start(monkeypatch, raw, starts):
    """What .env.example says of a value that is not a finite number, held to what the settings do: inf and nan are
    floats the settings take, and read as -1; text, or an empty value, is no number at all, and the settings refuse
    it, so the server does not start, as for any other setting. It said that any value that is not a number reads as
    -1."""
    from pydantic import ValidationError
    from app.core.config import Settings
    monkeypatch.setenv("MIN_FREE_SPACE_GB", raw)
    if starts:
        assert free_space.floor_bytes(100 * GIB, configured=Settings().min_free_space_gb) == 5 * GIB
    else:
        with pytest.raises(ValidationError):
            Settings()
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    said = " ".join(line.lstrip("#").strip() for line in example.splitlines())
    assert ("any other value is that many GB (inf or nan reads as -1; a value that is not a number, or an empty one, "
            "stops the server at its start, as for any other setting)") in said


def test_a_floor_larger_than_any_volume_refuses_every_write_and_says_so(volume):
    """A finite value whose bytes overflow a float (1e300 GB) is held at MAX_FLOOR_BYTES: every write is refused, and
    the refusal can still be written."""
    volume["configured"] = 1e300
    assert free_space.floor_bytes(100 * GIB, configured=1e300) == free_space.MAX_FLOOR_BYTES
    short = free_space.short_of(0)
    assert short is not None and short.floor == free_space.MAX_FLOOR_BYTES
    assert free_space.refusal_text(short).startswith("The server's storage is nearly full: 50 GB is free")


def test_a_write_that_would_leave_less_than_the_floor_is_short(volume):
    volume["free"] = 6 * GIB                                  # floor 5 GB
    assert free_space.short_of(0) is None
    assert free_space.short_of(GIB) is None                   # leaves exactly the floor
    short = free_space.short_of(GIB + 1)
    assert short == free_space.Room(free=6 * GIB, floor=5 * GIB, total=100 * GIB)
    volume["free"] = 5 * GIB - 1
    assert free_space.short_of(0) is not None


def test_the_floor_off_never_refuses(volume):
    volume["configured"], volume["free"] = 0, 0
    assert free_space.room() is None and free_space.short_of(10 * GIB) is None


def test_a_volume_that_reports_no_size_is_not_judged(volume):
    volume["total"], volume["free"] = 0, 0
    assert free_space.short_of(GIB) is None


def test_a_volume_whose_free_space_cannot_be_read_is_not_judged_and_said_once(volume, capsys):
    volume["total"] = PermissionError("statvfs refused")
    assert free_space.short_of(GIB) is None and free_space.short_of(GIB) is None
    said = capsys.readouterr().out.strip().splitlines()
    assert said == ["Warning: the free space of the storage volume could not be read (PermissionError); uploads "
                    "are not held to MIN_FREE_SPACE_GB while it cannot"]


def test_the_refusal_says_the_free_space_and_the_floor():
    text = free_space.refusal_text(free_space.Room(free=3 * GIB, floor=5 * GIB, total=100 * GIB))
    assert text.startswith("The server's storage is nearly full: 3.00 GB is free, and it keeps at least 5.00 GB "
                           "free")
    assert "MIN_FREE_SPACE_GB" in text


def test_the_guard_looks_at_the_first_write_and_then_every_check_every_bytes(volume):
    refused = []
    guard = free_space.WriteGuard(None, refused.append)
    guard.wrote(10)
    assert volume["asked"] == 1
    for _ in range(free_space.CHECK_EVERY_BYTES // MB - 1):
        guard.wrote(MB)
    assert volume["asked"] == 1, "looked again before CHECK_EVERY_BYTES were written"
    volume["free"] = 4 * GIB
    guard.wrote(MB)
    assert volume["asked"] == 2 and len(refused) == 1


# --------------------------------------------------------------------------- as the bytes are written

def _context(tmp_path, refuse_after_bytes):
    """A StreamingUploadContext whose guard refuses once `refuse_after_bytes` have been handed to it."""
    from app.core.security import IdentityChunkCodec
    from app.services.streaming_upload import StreamingUploadContext
    seen = {"n": 0}

    class Guard:
        def wrote(self, n):
            seen["n"] += n
            if seen["n"] > refuse_after_bytes:
                raise RuntimeError("the volume is down to its floor")
    return StreamingUploadContext(uuid.uuid4(), tmp_path / "blob", IdentityChunkCodec(), guard=Guard())


def test_a_transfer_that_runs_the_volume_down_to_its_floor_stops_and_its_file_goes(tmp_path):
    ctx = _context(tmp_path, refuse_after_bytes=3 * MB)
    with pytest.raises(RuntimeError, match="down to its floor"):
        with ctx:
            for _ in range(10):
                ctx.write_chunk(b"x" * MB)
    assert not (tmp_path / "blob").exists(), "the refused file was left on the disk"
    assert ctx.total_bytes == 3 * MB, "a chunk was written after the guard refused it"


def test_an_upload_streams_through_the_guard_of_the_storage_volume(volume, tmp_path, monkeypatch):
    """upload_file_streaming hands its context the volume's guard: a refusal is StorageLimitExceeded, kind 'disk',
    with the free space and the floor, and the file goes."""
    import app.services.vault_service as vs
    svc = vs.VaultService.__new__(vs.VaultService)
    svc.storage_path = tmp_path
    svc.permission_service = SimpleNamespace(require_vault_permission=lambda *a, **k: None)
    vault = _vault(0, None)
    svc.db = _DB({Vault: [vault]})
    monkeypatch.setattr(svc, "_id_is_spent", lambda file_id: False)
    file_info, ctx = svc.upload_file_streaming(vault.id, "a.bin", SimpleNamespace(id=uuid.uuid4()))
    volume["free"] = 6 * GIB
    with pytest.raises(vs.StorageLimitExceeded) as refused:
        with ctx:
            ctx.write_chunk(b"x" * MB)
            volume["free"] = 5 * GIB - 1
            for _ in range(free_space.CHECK_EVERY_BYTES // MB + 1):
                ctx.write_chunk(b"x" * MB)
    assert (refused.value.kind, refused.value.used, refused.value.cap) == ("disk", 5 * GIB - 1, 5 * GIB)
    assert str(refused.value).startswith("The server's storage is nearly full")
    assert not (tmp_path / file_info["storage_path"]).exists()


# --------------------------------------------------------------------------- as the row is written

def test_a_file_that_left_less_than_the_floor_is_refused_as_its_row_is_written(finish, volume):
    import app.services.vault_service as vs
    call, removed = finish
    vault = _vault(0, None)
    db = _DB({Vault: [vault]})
    volume["free"] = 5 * GIB - 1
    with pytest.raises(vs.StorageLimitExceeded) as refused:
        call(db, vault, MB)
    assert refused.value.kind == "disk" and len(removed) == 1
    assert [e[0] for e in db.log if e[0] in ("add", "commit", "rollback")] == ["rollback"]
    volume["free"] = 5 * GIB
    assert call(_DB({Vault: [vault]}), vault, MB) is not None, "a file leaving exactly the floor is stored"


def test_a_copy_that_would_leave_less_than_the_floor_is_refused_before_it_is_written(monkeypatch, volume):
    import app.services.vault_service as vs
    svc, source, dest = _copy_service(monkeypatch, "vault")
    dest.size_limit = None                    # no vault limit to refuse it first
    written = []
    svc.upload_file_streaming = lambda *a, **k: written.append(True)
    source.size_bytes = GIB + 1
    volume["free"] = 6 * GIB
    with pytest.raises(vs.StorageLimitExceeded) as refused:
        svc._stream_copy_file_record(source, SimpleNamespace(id="u"), dest.id, None)
    assert refused.value.kind == "disk" and written == []


def test_a_copy_refused_as_its_row_is_written_keeps_the_volumes_words(monkeypatch):
    import app.services.vault_service as vs
    svc, source, dest = _copy_service(monkeypatch, "disk")
    with pytest.raises(vs.StorageLimitExceeded) as refused:
        svc._stream_copy_file_record(source, SimpleNamespace(id="u"), dest.id, None)
    assert refused.value.kind == "disk" and str(refused.value) == "found under the lock"


def _folder_copy(monkeypatch, files, *, under=(), size_limit=None, stored=0):
    """copy_folder over a vault's rows in memory (the filters applied as the database would): the folder "top", the
    folders ``under`` it (name, parent), and the ``files`` (folder, bytes, expired). Beside the tree, a folder of the
    vault holds a file of 100 GB the copy must not count. Returns the call, what it made and the service."""
    from datetime import datetime, timedelta, timezone
    from _memory_db import MemoryDB
    from app.core.models import File, Folder
    import app.services.vault_service as vs
    monkeypatch.setattr(vs, "would_exceed_deployment_storage", lambda db, n: (False, 0, 0))
    vault = _vault(stored, size_limit)
    folders = {}
    for name, parent in [("top", None), ("beside", None), *under]:
        folders[name] = SimpleNamespace(id=uuid.uuid4(), vault_id=vault.id, name=name,
                                        parent_folder_id=folders[parent].id if parent else None)
    an_hour_ago = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
    rows = [SimpleNamespace(id=uuid.uuid4(), vault_id=vault.id, folder_id=folders[name].id, size_bytes=size,
                            expires_at=an_hour_ago if expired else None)
            for name, size, expired in [*files, ("beside", 100 * GIB, False)]]
    svc = vs.VaultService.__new__(vs.VaultService)
    svc.storage_path = None
    svc.db = MemoryDB({Vault: [vault], Folder: list(folders.values()), File: rows})
    svc._dest_folder_or_raise = lambda *a, **k: None
    svc._assert_not_into_self_or_descendant = lambda *a, **k: None
    made = []
    svc._copy_folder_recursive = lambda folder, user, vault_id, parent, counter: made.append(folder.name) or folder
    return (lambda: svc.copy_folder(folders["top"].id, SimpleNamespace(id="u"), vault.id, None)), made, svc


def test_a_folder_copy_the_volume_has_no_room_for_is_refused_before_it_makes_a_folder(monkeypatch, volume):
    """Each file of a folder copy is held to the floor as it is copied, but a copy refused there kept the folders it
    had made: the destination gained the copied top folder, empty, beside the 507. The tree's bytes, the files of its
    subfolders too and not those that have expired, are now measured before the first folder is made. With room, it
    is copied."""
    import app.services.vault_service as vs
    files = [("top", GIB // 2, False), ("sub", GIB // 2 + 2, False), ("sub", 10 * GIB, True)]
    copy, made, _svc = _folder_copy(monkeypatch, files, under=[("sub", "top")])
    volume["free"] = 6 * GIB + 1                            # floor 5 GB: the tree's 1 GB and 2 bytes leave one less
    with pytest.raises(vs.StorageLimitExceeded) as refused:
        copy()
    assert refused.value.kind == "disk" and str(refused.value).startswith("The server's storage is nearly full: ")
    assert made == [], "a folder was made before the copy was refused"
    copy, made, _svc = _folder_copy(monkeypatch, files, under=[("sub", "top")])
    volume["free"] = 6 * GIB + 2                            # it leaves exactly the floor
    copy()
    assert made == ["top"]


def test_a_folder_copy_past_the_vaults_limit_or_the_item_limit_makes_nothing(monkeypatch, volume):
    """The vault's size limit and the item limit refused part-way too, keeping what had been made: both are asked
    before the first folder now."""
    import app.services.vault_service as vs
    copy, made, _svc = _folder_copy(monkeypatch, [("top", 10, False), ("sub", 10, False)], under=[("sub", "top")],
                                    size_limit=100, stored=81)
    with pytest.raises(vs.FileTooLargeError) as refused:
        copy()
    assert str(refused.value) == "The copy would exceed the destination vault's size limit" and made == []
    tree = dict(files=[("top", 10, False), ("a", 10, False)], under=[("a", "top"), ("b", "top")])
    copy, made, svc = _folder_copy(monkeypatch, **tree)
    svc._COPY_MAX_ITEMS = 4                                 # three folders and two files: five items
    with pytest.raises(vs.FileServiceError) as refused:
        copy()
    assert str(refused.value) == "Folder is too large to copy (item limit reached)." and made == []
    copy, made, svc = _folder_copy(monkeypatch, **tree)
    svc._COPY_MAX_ITEMS = 5
    copy()
    assert made == ["top"]


def test_a_folder_copy_of_folders_alone_is_not_held_to_the_floor(monkeypatch, volume):
    """A tree with no file to copy (an expired one is not copied) copies no bytes: it is made as before, though the
    volume is below its floor."""
    copy, made, _svc = _folder_copy(monkeypatch, [("b", 10 * GIB, True)], under=[("a", "top"), ("b", "a")])
    volume["free"] = GIB
    copy()
    assert made == ["top"]


# --------------------------------------------------------------------------- what the routes answer

def test_a_route_answers_507_with_the_free_space_and_the_floor(volume):
    from fastapi import HTTPException
    from app.api import api_server as api
    from app.services.vault_service import StorageLimitExceeded
    volume["free"] = 6 * GIB
    api._enforce_free_space(GIB)
    with pytest.raises(HTTPException) as refused:
        api._enforce_free_space(GIB + 1)
    assert refused.value.status_code == 507
    assert refused.value.detail.startswith("The server's storage is nearly full: 6.00 GB is free")
    answered = api._no_room(StorageLimitExceeded("the volume's words", kind="disk", used=1, cap=2), "unused")
    assert (answered.status_code, answered.detail) == (507, "the volume's words")


def test_a_refusal_that_reaches_the_applications_handler_is_507(volume):
    import json
    from _async_run import run_coroutine
    from app.api import api_server as api
    from app.services.vault_service import StorageLimitExceeded
    answer = run_coroutine(api._file_service_error_handler(
        SimpleNamespace(), StorageLimitExceeded("the volume's words", kind="disk", used=1, cap=2)))
    assert answer.status_code == 507 and json.loads(answer.body) == {"detail": "the volume's words"}
    vault = run_coroutine(api._file_service_error_handler(
        SimpleNamespace(), StorageLimitExceeded("no room", kind="vault", used=1, cap=2)))
    assert vault.status_code == 413


@pytest.mark.parametrize("endpoint", ["signed in", "upload link"])
def test_a_chunk_the_volume_has_no_room_for_is_refused_before_its_body_is_read(volume, tmp_path, monkeypatch,
                                                                              endpoint):
    """A chunked upload, signed in or through an upload link, is held to the floor at its start for its whole size,
    and each chunk again for its own: what other uploads (or a legal hold) took since the start is not there to stage
    it on. Refused 507 with the floor's words, before its body is read: nothing staged. With room, the same chunk is
    staged, so the refusal is the floor's."""
    from fastapi import HTTPException
    from _chunk_endpoints import ChunkWorld, SIZE, send_chunk
    world = ChunkWorld(monkeypatch, tmp_path)
    volume["free"] = 5 * GIB + SIZE - 1                      # floor 5 GB: staging it would leave one byte less
    answer, body = send_chunk(world, endpoint)
    assert isinstance(answer, HTTPException) and answer.status_code == 507, answer
    assert answer.detail.startswith("The server's storage is nearly full: ") and "MIN_FREE_SPACE_GB" in answer.detail
    assert not body.read, "the chunk's body was read before it was refused"
    assert world.staged() == []
    volume["free"] = 5 * GIB + SIZE                          # it leaves exactly the floor
    answer, body = send_chunk(world, endpoint)
    assert not isinstance(answer, HTTPException), answer
    assert answer["received"] == 1 and body.read and world.staged() == ["chunk_000000", "hash_000000"], (
        answer, world.staged())


def test_the_deployments_early_check_is_still_its_own_and_asked_after_the_bytes_land(volume, monkeypatch):
    """The direct upload asks the deployment's limit again with the file's real size once its bytes are written:
    the volume's floor is not asked there with that size, which the volume's free space counts already."""
    from app.api import api_server as api
    import app.services.vault_service as vs
    monkeypatch.setattr(vs, "would_exceed_deployment_storage", lambda db, n: (False, 0, 0))
    volume["free"] = 6 * GIB
    api._enforce_deployment_storage_quota(None, 2 * GIB)


def test_an_sftp_write_the_volume_has_no_room_for_stops_with_its_reason():
    import paramiko
    from app.services.vault_service import StorageLimitExceeded
    from app.sftp import sftp_server as S
    said = []
    upload = S._StreamingUpload.__new__(S._StreamingUpload)
    upload._failed, upload._max_bytes = False, 0
    upload._handle = SimpleNamespace(_set_status_desc=said.append)

    class Assembler:
        def feed(self, offset, data):
            raise StorageLimitExceeded("The server's storage is nearly full: 1.0 GB is free", kind="disk",
                                       used=GIB, cap=5 * GIB)
    upload._assembler = Assembler()
    assert upload.write(0, b"x" * 10) == paramiko.SFTP_FAILURE
    assert upload._failed is True
    assert said == ["upload rejected: The server's storage is nearly full: 1.0 GB is free"]


def _buffered_handle(staged_at):
    """An SFTP upload handle buffering to ``staged_at`` (the path a buffered upload stages at, SFTP_STREAMING_UPLOAD
    off), with what it would tell the client kept."""
    from app.sftp import sftp_server as S
    handle = S.VaultSFTPHandle()
    handle.writepath = str(staged_at)
    handle.writefile = open(staged_at, "wb")
    said = []
    handle._set_status_desc = said.append
    return handle, said


def test_a_buffered_sftp_upload_staged_on_the_storage_volume_stops_at_its_floor(volume, tmp_path, monkeypatch):
    """With no tmpfs over .sftp_tmp, a buffered upload stages its bytes on the storage volume itself: it is held to the
    floor as they arrive, as a streaming upload is, and marked for discard."""
    import paramiko
    monkeypatch.setattr(free_space, "storage_path", lambda: tmp_path)
    (tmp_path / ".sftp_tmp").mkdir()
    handle, said = _buffered_handle(tmp_path / ".sftp_tmp" / "up_one")
    try:
        assert handle.write(0, b"x" * MB) == paramiko.SFTP_OK
        volume["free"] = 5 * GIB - 1
        result = paramiko.SFTP_OK
        offset = MB
        for _ in range(free_space.CHECK_EVERY_BYTES // MB + 1):
            result = handle.write(offset, b"x" * MB)
            if result != paramiko.SFTP_OK:
                break
            offset += MB
    finally:
        handle.writefile.close()
    assert result == paramiko.SFTP_FAILURE
    assert handle.write_failed is True, "the upload was not marked for discard"
    assert len(said) == 1 and said[0].startswith("upload rejected: The server's storage is nearly full")
    assert (tmp_path / ".sftp_tmp" / "up_one").stat().st_size == offset, "a write was buffered after the refusal"


def test_a_buffered_sftp_upload_staged_on_another_filesystem_is_not_held_to_the_volumes_floor(volume, tmp_path,
                                                                                          monkeypatch):
    """The composes mount a tmpfs over .sftp_tmp: a buffer there is RAM, bounded by the tmpfs, and the storage volume's
    floor does not apply to it."""
    import os
    import paramiko
    from app.sftp import sftp_server as S
    storage = tmp_path / "storage"
    staging = tmp_path / "staging"
    storage.mkdir()
    staging.mkdir()
    monkeypatch.setattr(free_space, "storage_path", lambda: storage)
    real_stat = os.stat

    def stat(path, *a, **k):
        found = real_stat(path, *a, **k)
        if str(path) == str(staging):
            return SimpleNamespace(st_dev=found.st_dev + 1)
        return found
    monkeypatch.setattr(S.os, "stat", stat)
    volume["free"] = GIB                          # far below the floor of 5 GB
    handle, said = _buffered_handle(staging / "up_two")
    try:
        assert handle.write(0, b"x" * MB) == paramiko.SFTP_OK
    finally:
        handle.writefile.close()
    assert handle.write_failed is False and said == []
    assert volume["asked"] == 0, "the storage volume was looked at for a buffer that is not on it"
