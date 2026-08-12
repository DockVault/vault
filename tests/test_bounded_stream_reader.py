"""The bounded reader: what it can prove before decrypting, and that it reads the same bytes.

The whole-file reader decrypts every record into a list and joins it, costing about twice the file
-- 267.9 MB measured for a 128 MB download. `GcmChunkStreamReader` replaces it with a walk over the
length prefixes followed by record-at-a-time decryption.

The walk is the interesting half. A record's length field covers nonce, ciphertext and tag, so the
plaintext length of a record is `rec_len - 28` and is readable without the key. Summing that over
the file gives the record count and the total plaintext length -- which are exactly the two values
the terminal's AAD binds. So the terminal authenticates before anything is decrypted, and every
structural failure becomes an early one.

Two things these tests exist to stop:

- a reader that quietly reads record bodies during the walk, which would make it a second full pass
  and give back everything the change bought;
- a reader that rejects a file the reader it replaces accepts. The retained formats are full of
  legal shapes that look wrong: a zero-plaintext record in 0x10, a short interior record, a stray
  partial length prefix at the end of a 0x10 file.
"""

import io
import os
import struct
import uuid

import pytest


pytestmark = pytest.mark.unit

VAULT = uuid.UUID("11111111-1111-1111-1111-111111111111")
FILE = uuid.UUID("22222222-2222-2222-2222-222222222222")


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
def sec(_runtime_secrets):
    """The codec module, imported only once the deployment secret exists."""
    from app.core import security
    return security


def _build(sec, chunks, codec=None):
    """A real at-rest blob, written by the production codec."""
    codec = codec or sec.GcmChunkStreamCodecV2(VAULT, FILE)
    out = bytearray(codec.header())
    for i, chunk in enumerate(chunks):
        out += codec.encrypt(chunk, i)
    if hasattr(codec, "terminal"):
        out += codec.terminal()
    return bytes(out)


class _Counter:
    """Totals for the reads the reader actually issues."""

    def __init__(self):
        self.reads = 0
        self.bytes_read = 0


@pytest.fixture
def on_disk(tmp_path, monkeypatch, request):
    """Open a blob as a real file, counting the positional reads the reader issues.

    An earlier version of this fixture handed the reader a `BytesIO` with `fileno()` patched to
    return 0. On Windows that worked, because there is no `os.pread` and the reader falls back to
    seek-and-read on the handle. On Linux it made every read a `pread` against **file descriptor
    0** -- standard input -- which returns nothing, so sixteen of these tests failed there while
    passing here. Worse than the failure: on the platform where they passed, they exercised a code
    path production never takes.

    So the tests use real files. The counter wraps whichever primitive the platform uses.
    """
    counter = _Counter()

    if hasattr(os, "pread"):
        real_pread = os.pread

        def _counted(fd, size, offset):
            data = real_pread(fd, size, offset)
            counter.reads += 1
            counter.bytes_read += len(data)
            return data

        monkeypatch.setattr(os, "pread", _counted)

    handles = []

    def _open(data, name="blob"):
        path = tmp_path / f"{name}-{len(handles)}"
        path.write_bytes(data)
        handle = open(path, "rb")
        handles.append(handle)
        if not hasattr(os, "pread"):
            real_read = handle.read

            def _counted_read(n=-1, _real=real_read):
                data = _real(n)
                counter.reads += 1
                counter.bytes_read += len(data)
                return data

            handle.read = _counted_read          # noqa: SLF001 - the fallback path's primitive
        return handle

    _open.counter = counter
    request.addfinalizer(lambda: [h.close() for h in handles])
    return _open


# ---------------------------------------------------------------- the walk

def test_the_walk_reads_no_record_bodies(sec, on_disk):
    """The whole point. Reading bodies here would make this a second pass over the file.

    Only the terminal's 28 bytes are read, plus one 4-byte length prefix per record and one for
    the terminal's own marker.
    """
    chunks = [b"A" * 4096, b"B" * 1234, b"C" * 65536]
    handle = on_disk(_build(sec, chunks))

    reader = sec.GcmChunkStreamReader(handle, VAULT, FILE)

    header_and_prefixes = 28 + (4 * (len(chunks) + 1))
    terminal_body = 28
    read = on_disk.counter.bytes_read
    assert read == header_and_prefixes + terminal_body, (
        f"the walk read {read} bytes; it should read the header, one length prefix per record, "
        "and the terminal -- never a record body")
    assert reader.record_count == 3
    assert reader.total_length == sum(len(c) for c in chunks)


def test_the_walk_derives_the_length_the_writer_sealed(sec, on_disk):
    """Uneven records, including a short interior one, which the resumable path produces."""
    chunks = [b"x" * 1048576, b"y" * 7, b"z" * 33333]
    reader = sec.GcmChunkStreamReader(on_disk(_build(sec, chunks)), VAULT, FILE)
    assert reader.total_length == 1048576 + 7 + 33333
    assert reader.length_is_authenticated is True


def test_the_walk_costs_one_positional_read_per_record(sec, on_disk):
    """One read per length prefix, plus the header and the terminal. Nothing else.

    On the deployment platform each of these is a single `pread` and there is no seek at all. This
    counts reads rather than seeks so it measures the same property on both paths: reading through
    the handle's own buffer instead would pull 128 KiB per record from the device to obtain four
    bytes, which is 128 MiB of I/O to walk a gigabyte.
    """
    chunks = [b"q" * 512] * 50
    handle = on_disk(_build(sec, chunks))
    sec.GcmChunkStreamReader(handle, VAULT, FILE)

    # header, write id, one prefix per record, the terminal's marker, the terminal's body
    expected = 2 + len(chunks) + 2
    assert on_disk.counter.reads == expected, (
        f"{on_disk.counter.reads} reads for {len(chunks)} records; expected {expected}")


# ------------------------------------------------- early failures, before any plaintext

def test_a_truncated_final_record_is_caught_by_the_walk(sec, on_disk):
    """Seeking past the end of a file succeeds silently, so this must be arithmetic, not a seek."""
    blob = _build(sec, [b"A" * 4096, b"B" * 4096])
    with pytest.raises(sec.EncryptionError, match="Incomplete chunk"):
        sec.GcmChunkStreamReader(on_disk(blob[:-2048]), VAULT, FILE)


def test_a_missing_terminal_is_caught_by_the_walk(sec, on_disk):
    codec = sec.GcmChunkStreamCodecV2(VAULT, FILE)
    blob = codec.header() + codec.encrypt(b"A" * 100, 0)      # no terminal
    with pytest.raises(sec.EncryptionError, match="without a terminal"):
        sec.GcmChunkStreamReader(on_disk(blob), VAULT, FILE)


def test_trailing_bytes_after_the_terminal_are_caught_by_the_walk(sec, on_disk):
    blob = _build(sec, [b"A" * 100]) + b"junk"
    with pytest.raises(sec.EncryptionError, match="Trailing bytes"):
        sec.GcmChunkStreamReader(on_disk(blob), VAULT, FILE)


def test_a_dropped_record_is_caught_by_the_walk(sec, on_disk):
    """The terminal binds the count, so removing a record fails before anything is decrypted.

    Built by keeping a terminal sealed over two records on a file carrying one, which is the shape
    an attacker able to write the blob would produce.
    """
    codec = sec.GcmChunkStreamCodecV2(VAULT, FILE)
    first = codec.encrypt(b"A" * 100, 0)
    second = codec.encrypt(b"B" * 100, 1)
    terminal = codec.terminal()
    forged = codec.header() + first + terminal          # second record dropped
    assert len(forged) < len(codec.header() + first + second + terminal)

    with pytest.raises(sec.EncryptionError, match="terminal authentication"):
        sec.GcmChunkStreamReader(on_disk(forged), VAULT, FILE)


def test_a_blob_from_another_file_is_caught_by_the_walk(sec, on_disk):
    other = uuid.UUID("33333333-3333-3333-3333-333333333333")
    blob = _build(sec, [b"A" * 100], codec=sec.GcmChunkStreamCodecV2(VAULT, other))
    with pytest.raises(sec.EncryptionError, match="terminal authentication"):
        sec.GcmChunkStreamReader(on_disk(blob), VAULT, FILE)


def test_the_walk_starts_after_the_write_id(sec, on_disk):
    """Guards the 12-vs-28 trap: the 0x20 header carries a 16-byte write id.

    A reader sizing the header at 12 reads write_id[0:4] as a length prefix. The write id is
    random, so that value is almost always outside the permitted range -- the symptom is a
    plausible-looking 'record length' error on healthy files.
    """
    reader = sec.GcmChunkStreamReader(on_disk(_build(sec, [b"A" * 100])), VAULT, FILE)
    assert reader._data_start == 28, "the 0x20 walk must start after the write id"


def test_an_oversized_length_is_refused_without_allocating(sec, on_disk):
    """A corrupt prefix must not turn into a multi-gigabyte read."""
    codec = sec.GcmChunkStreamCodecV2(VAULT, FILE)
    blob = bytearray(codec.header() + codec.encrypt(b"A" * 100, 0) + codec.terminal())
    blob[28:32] = struct.pack('>I', sec.MAX_RECORD_BYTES + 1)
    with pytest.raises(sec.EncryptionError, match="outside the permitted range"):
        sec.GcmChunkStreamReader(on_disk(bytes(blob)), VAULT, FILE)


# ---------------------------------------------------------------- reading

def test_records_yields_the_same_bytes_the_whole_file_reader_returns(sec, on_disk):
    """Byte parity, which is the property a user notices if it breaks."""
    chunks = [b"A" * 4096, b"B" * 1, b"C" * 70000, b"D" * 999]
    blob = _build(sec, chunks)

    whole = sec.decrypt_gcm_chunk_stream(io.BytesIO(blob), VAULT, FILE)
    streamed = b"".join(sec.GcmChunkStreamReader(on_disk(blob), VAULT, FILE).records())

    assert streamed == whole == b"".join(chunks)


def test_a_corrupted_record_body_survives_the_walk_and_fails_when_reached(sec, on_disk):
    """The one late failure, and the reason callers need a finalization contract."""
    blob = bytearray(_build(sec, [b"A" * 4096, b"B" * 4096]))
    blob[-100] ^= 0xFF          # inside the second record's ciphertext

    reader = sec.GcmChunkStreamReader(on_disk(bytes(blob)), VAULT, FILE)   # walk passes
    stream = reader.records()
    assert next(stream) == b"A" * 4096                                       # first record is fine
    with pytest.raises(sec.EncryptionError):
        next(stream)


def test_reading_one_record_reads_one_record(sec, on_disk):
    """`records()` must not accumulate. Checked by what it read, not by inspecting internals."""
    chunks = [b"A" * 65536] * 8
    handle = on_disk(_build(sec, chunks))
    reader = sec.GcmChunkStreamReader(handle, VAULT, FILE)
    after_walk = on_disk.counter.bytes_read

    next(reader.records())
    consumed = on_disk.counter.bytes_read - after_walk
    assert consumed < 2 * (65536 + 28), (
        f"reading one record consumed {consumed} bytes; more than one record is being read")


# ---------------------------------------------------------------- retained formats

def test_the_legacy_format_reads_and_keeps_its_own_record_floor(sec, on_disk):
    """0x10 permits a zero-plaintext record; a frozen release fixture contains one.

    Applying the 0x20 floor to a 0x10 file has already made real objects permanently
    undownloadable once. The walk must not repeat it.
    """
    codec = sec.GcmChunkStreamCodec(VAULT, FILE)
    blob = codec.header() + codec.encrypt(b"", 0) + codec.encrypt(b"tail", 1)

    reader = sec.GcmChunkStreamReader(on_disk(blob), VAULT, FILE)
    assert reader.record_count == 2
    assert reader.total_length == 4
    assert reader.length_is_authenticated is False, "0x10 has no terminal to authenticate a length"
    assert b"".join(reader.records()) == b"tail"


def test_a_legacy_file_with_a_stray_partial_prefix_still_reads(sec, on_disk):
    """The whole-file reader ignores 1-3 trailing bytes on 0x10. This one must too.

    Rejecting a file the reader it replaces accepts is a data-loss bug, not a hardening win.
    """
    codec = sec.GcmChunkStreamCodec(VAULT, FILE)
    blob = codec.header() + codec.encrypt(b"payload", 0) + b"\x00\x00"

    assert b"".join(sec.GcmChunkStreamReader(on_disk(blob), VAULT, FILE).records()) == b"payload"
    assert sec.decrypt_gcm_chunk_stream(io.BytesIO(blob), VAULT, FILE) == b"payload"


def test_an_unsupported_version_says_so_distinctly(sec, on_disk):
    blob = bytearray(_build(sec, [b"A" * 100]))
    blob[9] = 0x99
    with pytest.raises(sec.EncryptionError, match="Unsupported at-rest format version"):
        sec.GcmChunkStreamReader(on_disk(bytes(blob)), VAULT, FILE)


# ------------------------------------------- a delete racing a read is not an integrity failure

@pytest.mark.skipif(os.name == "nt",
                    reason="Windows gives an open reader a consistent view; the overwrite is "
                           "invisible to it, so the phenomenon does not occur. Deployment is Linux")
def test_an_overwrite_not_yet_unlinked_is_reported_as_an_integrity_failure(sec, tmp_path):
    """The deliberate limit of the detection, pinned so it cannot drift into the unsafe direction.

    Secure deletion overwrites the inode and then unlinks it. Between those two steps the link
    count is still one, so this reader calls the failure what it looks like: an integrity failure.

    That is the choice, not an oversight. The alternatives were tried and rejected. Comparing link
    counts for inequality fires on an unrelated hard link; comparing modification times fires on
    any tool that restores an mtime -- and the container filesystem here has 10 ms granularity, so
    an overwrite in the same tick moves nothing. Either rule would report real tampering as a
    routine delete, and a false "it was only a delete" silences the alarm, while a false integrity
    failure merely raises one.
    """
    path = tmp_path / "blob"
    path.write_bytes(_build(sec, [b"A" * 4096, b"B" * 4096]))

    with open(path, "rb") as handle:
        stream = sec.GcmChunkStreamReader(handle, VAULT, FILE).records()
        assert next(stream) == b"A" * 4096

        size = path.stat().st_size
        with open(path, "wb") as shred:          # the overwrite, with the unlink not yet reached
            shred.write(os.urandom(size))
        assert os.fstat(handle.fileno()).st_nlink == 1, "the premise of this test did not hold"

        with pytest.raises(sec.EncryptionError):
            next(stream)


@pytest.mark.skipif(os.name == "nt",
                    reason="POSIX unlink-while-open; the deployment and CI are Linux")
def test_the_real_secure_delete_sequence_is_reported_as_a_replacement(sec, tmp_path):
    """Overwrite in place, then unlink -- what secure deletion actually does, in that order.

    This is the case the `st_nlink` signal exists for, and it is exact for this codebase because a
    delete and a same-name replacement both unlink the old blob.
    """
    path = tmp_path / "blob"
    path.write_bytes(_build(sec, [b"A" * 4096, b"B" * 4096]))

    with open(path, "rb") as handle:
        stream = sec.GcmChunkStreamReader(handle, VAULT, FILE).records()
        assert next(stream) == b"A" * 4096

        size = path.stat().st_size
        with open(path, "wb") as shred:
            shred.write(os.urandom(size))
        path.unlink()
        assert os.fstat(handle.fileno()).st_nlink == 0, "the premise of this test did not hold"

        with pytest.raises(sec.ObjectChangedDuringRead):
            next(stream)


@pytest.mark.skipif(os.name == "nt",
                    reason="POSIX unlink-while-open; the deployment and CI are Linux")
def test_an_unlinked_but_intact_blob_reads_to_completion(sec, tmp_path):
    """No false alarm. An unlink alone leaves the data readable through the descriptor.

    The reader only asks whether the object changed when something has already failed, so a
    transfer racing an ordinary delete finishes correctly rather than being aborted on suspicion.
    Without this, the detection above could be satisfied by a reader that refuses on nlink alone.
    """
    path = tmp_path / "blob"
    chunks = [b"A" * 4096, b"B" * 4096]
    path.write_bytes(_build(sec, chunks))

    with open(path, "rb") as handle:
        reader = sec.GcmChunkStreamReader(handle, VAULT, FILE)
        path.unlink()
        assert os.fstat(handle.fileno()).st_nlink == 0
        assert b"".join(reader.records()) == b"".join(chunks)


def test_an_untouched_blob_is_not_blamed_on_a_replacement(sec, tmp_path):
    """Non-vacuity for the test above: real corruption must still be an integrity failure."""
    path = tmp_path / "blob"
    blob = bytearray(_build(sec, [b"A" * 4096, b"B" * 4096]))
    blob[-100] ^= 0xFF
    path.write_bytes(bytes(blob))

    with open(path, "rb") as handle:
        stream = sec.GcmChunkStreamReader(handle, VAULT, FILE).records()
        next(stream)
        with pytest.raises(sec.EncryptionError):
            next(stream)


# ------------------------------------------------- gaps a mutation pass found untested

def test_the_new_error_is_catchable_as_an_encryption_error(sec):
    """Callers that do not know about it must still handle it.

    Every handler of the reader this replaces catches `EncryptionError`. If the replacement
    signalled a deleted file with something outside that hierarchy, the first file deleted during a
    download would escape as an unhandled server error.
    """
    assert issubclass(sec.ObjectChangedDuringRead, sec.EncryptionError)


def test_non_zero_reserved_header_bytes_are_refused(sec, on_disk):
    """A future version may give the reserved bytes meaning; a reader that ignored them today
    would silently misread such a file tomorrow."""
    blob = bytearray(_build(sec, [b"A" * 100]))
    blob[10] = 0x01
    with pytest.raises(sec.EncryptionError, match="Reserved header bytes"):
        sec.GcmChunkStreamReader(on_disk(bytes(blob)), VAULT, FILE)


def test_a_header_cut_inside_the_write_id_is_refused(sec, on_disk):
    """A file long enough to hold the version byte but not the write id.

    Without the length check the write id is short, every AAD built from it is wrong, and the file
    reports as an authentication failure -- which reads as tampering rather than as truncation.
    """
    blob = _build(sec, [b"A" * 100])[:20]        # 12-byte prefix plus half the write id
    with pytest.raises(sec.EncryptionError, match="Truncated header"):
        sec.GcmChunkStreamReader(on_disk(blob), VAULT, FILE)


def test_the_record_ceiling_is_enforced_before_the_read(sec, on_disk):
    """The bound must be checked against the declared length, not discovered by a short read.

    A four-gigabyte length prefix in a small file must cost nothing. Checking after the read is how
    a 48-byte file reaches a multi-gigabyte allocation.
    """
    blob = bytearray(_build(sec, [b"A" * 100]))
    blob[28:32] = struct.pack('>I', 0xFFFFFFFE)
    handle = on_disk(bytes(blob))
    before = on_disk.counter.bytes_read
    with pytest.raises(sec.EncryptionError, match="outside the permitted range"):
        sec.GcmChunkStreamReader(handle, VAULT, FILE)
    assert on_disk.counter.bytes_read - before < 100, (
        "the oversized record was read before its length was checked")


@pytest.mark.skipif(os.name == "nt",
                    reason="the Windows fallback reads through the handle's buffer, which still "
                           "holds the pre-truncation bytes; the deployment reads positionally")
def test_a_record_truncated_after_the_walk_is_not_called_corruption(sec, tmp_path):
    """A file that shrinks between the walk and the read of a record.

    The short-read branch in record decryption had no coverage. It must not report a decrypt
    failure, because nothing was decrypted.
    """
    path = tmp_path / "blob"
    full = _build(sec, [b"A" * 4096, b"B" * 4096])
    path.write_bytes(full)

    with open(path, "rb") as handle:
        reader = sec.GcmChunkStreamReader(handle, VAULT, FILE)
        stream = reader.records()
        assert next(stream) == b"A" * 4096
        with open(path, "r+b") as shrink:        # cut the second record short, in place
            shrink.truncate(len(full) - 3000)
        with pytest.raises(sec.EncryptionError, match="Incomplete chunk"):
            next(stream)


def test_a_hard_link_is_not_mistaken_for_a_replacement(sec, tmp_path):
    """The link count rising is not the link count reaching zero.

    Comparing link counts for inequality was tried and rejected: a backup or dedup pass that hard
    links the blob store would make every subsequent integrity failure look like a routine delete,
    which silences the alarm rather than dulling it.
    """
    if not hasattr(os, "link"):
        pytest.skip("no hard links on this platform")
    path = tmp_path / "blob"
    blob = bytearray(_build(sec, [b"A" * 4096, b"B" * 4096]))
    blob[-100] ^= 0xFF                            # genuine corruption in the second record
    path.write_bytes(bytes(blob))

    with open(path, "rb") as handle:
        stream = sec.GcmChunkStreamReader(handle, VAULT, FILE).records()
        next(stream)
        try:
            os.link(path, tmp_path / "backup")    # nlink 1 -> 2
        except (OSError, NotImplementedError):
            pytest.skip("hard links unavailable here")
        assert os.fstat(handle.fileno()).st_nlink == 2

        with pytest.raises(sec.EncryptionError) as caught:
            next(stream)
        assert not isinstance(caught.value, sec.ObjectChangedDuringRead), (
            "a hard link made real tampering look like a routine delete")
