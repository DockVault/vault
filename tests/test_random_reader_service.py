"""The service layer that opens a stored file for random access.

`open_random_reader` authorizes a read and hands back something that answers byte ranges. The
codec beneath it is covered elsewhere; what these cover is the part between the two, which had no
tests and where the riskiest new behaviour lives.

That behaviour is the length check on the retained format. A whole-file read verified the stored
checksum as a side effect of reading everything, which is how a truncated legacy blob used to be
caught. A reader that only decrypts what was asked for cannot do that, so the walked length is
compared against the recorded size instead. The check can REFUSE a file, and refusing a healthy one
is a data-loss bug -- this codebase has already made real objects permanently undownloadable once
by tightening a rule about the retained format.
"""

import os
import uuid

import pytest


pytestmark = pytest.mark.unit


@pytest.fixture(scope="module", autouse=True)
def _runtime_secrets():
    """The codec reads the deployment secret; the rest is bootstrap. Undone in teardown."""
    import base64
    import secrets as _secrets

    previous = {k: os.environ.get(k) for k in
                ("ENCRYPTION_KEY", "DATABASE_URL", "JWT_SECRET_KEY")}
    os.environ.setdefault("ENCRYPTION_KEY",
                          base64.urlsafe_b64encode(os.urandom(32)).decode())
    os.environ.setdefault("DATABASE_URL", "postgresql://u:p@localhost/db")
    os.environ.setdefault("JWT_SECRET_KEY", _secrets.token_hex(32))
    yield
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        from app.core import config as _config
        _config._runtime_initialized = False
    except Exception:                     # noqa: BLE001 - teardown must never fail the suite
        pass


@pytest.fixture(scope="module")
def parts(_runtime_secrets):
    from app.core import security
    from app.services import vault_service
    from app.services.download_stream import RandomAccessFile
    return security, vault_service, RandomAccessFile


class _Row:
    """The handful of columns the opener reads off a file record."""

    def __init__(self, vault_id, file_id, storage_path, size_bytes):
        self.id = file_id
        self.vault_id = vault_id
        self.storage_path = storage_path
        self.size_bytes = size_bytes
        self.original_name = "thing.bin"
        self.checksum_sha256 = "0" * 64
        self.mime_type = "application/octet-stream"


class _Vault:
    def __init__(self, kind="standard"):
        self.type = kind


def _service(parts, root):
    """A VaultService with only what the opener touches wired up."""
    _security, vault_service, _raf = parts
    service = vault_service.VaultService.__new__(vault_service.VaultService)
    service.storage_path = root
    return service


def _write(parts, root, chunks, version=2, name="blob"):
    security, _vs, _raf = parts
    vault_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    file_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    codec = (security.GcmChunkStreamCodecV2(vault_id, file_id) if version == 2
             else security.GcmChunkStreamCodec(vault_id, file_id))
    blob = bytearray(codec.header())
    for i, chunk in enumerate(chunks):
        blob += codec.encrypt(chunk, i)
    if hasattr(codec, "terminal"):
        blob += codec.terminal()
    (root / name).write_bytes(bytes(blob))
    return vault_id, file_id, b"".join(chunks)


# ------------------------------------------------- the retained format's length check

def test_a_legacy_file_whose_length_matches_is_served(parts, tmp_path):
    """The healthy case, which must not be refused."""
    _security, vault_service, _raf = parts
    vault_id, file_id, whole = _write(parts, tmp_path, [b"A" * 500, b"B" * 300], version=1)
    row = _Row(vault_id, file_id, "blob", len(whole))

    reader = _service(parts, tmp_path)._open_random(row, _Vault(), file_id)
    try:
        assert reader.size == len(whole)
        assert reader.read(0, len(whole)) == whole
    finally:
        reader.close()


def test_a_legacy_file_with_a_record_removed_is_refused(parts, tmp_path):
    """The case the check exists for: the whole-file read used to catch this by hashing."""
    _security, vault_service, _raf = parts
    vault_id, file_id, whole = _write(parts, tmp_path, [b"A" * 500, b"B" * 300], version=1)
    # The row still records the original length; the blob has lost its last record.
    truncated = (tmp_path / "blob").read_bytes()
    (tmp_path / "blob").write_bytes(truncated[:-(300 + 28 + 4)])
    row = _Row(vault_id, file_id, "blob", len(whole))

    with pytest.raises(vault_service.FileServiceError, match="does not match"):
        _service(parts, tmp_path)._open_random(row, _Vault(), file_id)


def test_a_legacy_file_with_no_recorded_length_is_still_served(parts, tmp_path):
    """A row that records nothing cannot be compared against, and must not be refused for it."""
    _security, vault_service, _raf = parts
    vault_id, file_id, whole = _write(parts, tmp_path, [b"A" * 100], version=1)

    for recorded in (0, None):
        reader = _service(parts, tmp_path)._open_random(
            _Row(vault_id, file_id, "blob", recorded), _Vault(), file_id)
        try:
            assert reader.read(0, 999) == whole
        finally:
            reader.close()


def test_the_current_format_is_not_subject_to_the_check(parts, tmp_path):
    """Its terminal authenticates the length, so a wrong row must not refuse a healthy file."""
    _security, vault_service, _raf = parts
    vault_id, file_id, whole = _write(parts, tmp_path, [b"A" * 400, b"B" * 200], version=2)
    row = _Row(vault_id, file_id, "blob", 999999)      # deliberately wrong

    reader = _service(parts, tmp_path)._open_random(row, _Vault(), file_id)
    try:
        assert reader.size == len(whole), "the size must come from the format, not the row"
        assert reader.read(0, 9999) == whole
    finally:
        reader.close()


def test_a_legacy_file_with_a_zero_plaintext_record_is_served(parts, tmp_path):
    """Legal in the retained format, and present in a frozen release fixture."""
    _security, vault_service, _raf = parts
    vault_id, file_id, whole = _write(parts, tmp_path, [b"A" * 50, b"", b"B" * 50], version=1)
    row = _Row(vault_id, file_id, "blob", len(whole))

    reader = _service(parts, tmp_path)._open_random(row, _Vault(), file_id)
    try:
        assert reader.read(0, 999) == whole
    finally:
        reader.close()


# ------------------------------------------------- what the opener refuses and releases

def test_a_zero_knowledge_vault_is_refused(parts, tmp_path):
    """The server holds no key for that blob, and there are no records to index.

    Unreachable over SFTP, which serves only standard vaults -- but this is a public method, and a
    blob whose first bytes a client controls should not be routed into a reader that will try to
    authenticate it under the deployment's own key.
    """
    _security, vault_service, _raf = parts
    vault_id, file_id, _whole = _write(parts, tmp_path, [b"A" * 100])
    row = _Row(vault_id, file_id, "blob", 100)

    with pytest.raises(vault_service.FileServiceError, match="[Zz]ero-knowledge"):
        _service(parts, tmp_path)._open_random(row, _Vault("zero_knowledge"), file_id)


def test_a_missing_blob_is_reported_as_missing(parts, tmp_path):
    _security, vault_service, _raf = parts
    row = _Row(uuid.uuid4(), uuid.uuid4(), "not-there", 10)
    with pytest.raises(vault_service.FileNotFoundError):
        _service(parts, tmp_path)._open_random(row, _Vault(), row.id)


def test_an_unreadable_blob_does_not_leave_the_file_open(parts, tmp_path):
    """Every failure path opens the blob first; none of them may leak the descriptor."""
    _security, vault_service, _raf = parts
    (tmp_path / "blob").write_bytes(b"not any known format")
    row = _Row(uuid.uuid4(), uuid.uuid4(), "blob", 20)

    before = _open_handles(tmp_path / "blob")
    with pytest.raises(Exception):
        _service(parts, tmp_path)._open_random(row, _Vault(), row.id)
    assert _open_handles(tmp_path / "blob") == before


def _open_handles(path):
    """How many objects in this process still hold `path` open. Portable enough for a test."""
    import gc
    import io as _io
    count = 0
    for obj in gc.get_objects():
        try:
            if isinstance(obj, _io.IOBase) and not obj.closed and getattr(obj, "name", None) == str(path):
                count += 1
        except Exception:      # noqa: BLE001 - some objects raise on attribute access
            continue
    return count


def test_closing_releases_the_blob(parts, tmp_path):
    _security, _vs, _raf = parts
    vault_id, file_id, _whole = _write(parts, tmp_path, [b"A" * 100])
    reader = _service(parts, tmp_path)._open_random(
        _Row(vault_id, file_id, "blob", 100), _Vault(), file_id)

    assert _open_handles(tmp_path / "blob") >= 1
    reader.close()
    assert _open_handles(tmp_path / "blob") == 0
    reader.close()      # idempotent; a handle may be closed twice


# ------------------------------------------------- the whole-file fallback

def test_the_fallback_answers_ranges_the_same_way(parts):
    """The legacy format keeps a whole-file read, and must still honour the same contract."""
    _security, _vs, RandomAccessFile = parts
    content = bytes(range(256)) * 4
    fallback = RandomAccessFile.from_bytes(content, "legacy.bin")

    assert fallback.size == len(content)
    assert fallback.read(0, 10) == content[:10]
    assert fallback.read(len(content) - 5, 100) == content[-5:]
    assert fallback.read(len(content), 10) == b""
    assert fallback.read(0, 0) == b""
    # A slice reads a negative bound from the end of the buffer; the indexed reader returns
    # nothing. Two implementations of one contract must not disagree here.
    assert fallback.read(0, -5) == b""
    assert fallback.read(-3, 10) == b""
    fallback.close()      # no descriptor to release, and must not raise
