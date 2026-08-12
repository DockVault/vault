"""Standard at-rest format `0x20`: the terminal record that makes truncation detectable.

`0x10` authenticates every record against its vault, its file and its position, so no record can be
swapped in or reordered. What it cannot see is a record that is simply **not there**: a file cut
short decrypts perfectly up to the cut, and the only thing that noticed was the stored plaintext
checksum — a bare hash in a column, which is not integrity against anyone able to write that column.

`0x20` closes the stream with an authenticated terminal binding the record count and the total
plaintext length, and requires the file to end there.

Offline by design. The codec needs only the deployment secret, so these run in the fast lane
against the real module rather than through a container — which matters, because a format test that
only runs when Docker is available is a format test that mostly does not run.

The format is specified in full by the comments in `app/core/security.py` around the version
constants; this file pins the wire bytes so the two cannot drift.
"""

import io
import os
import struct
import uuid

import pytest


pytestmark = pytest.mark.unit


@pytest.fixture(scope="module", autouse=True)
def _runtime_secrets():
    """Minimum viable settings. The codec only reads `encryption_key`; the rest is bootstrap."""
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
    # Restoring the environment does NOT restore the module. The first codec call runs
    # `initialize_runtime()`, which mutates `app.core.config.settings` in place and latches
    # `_runtime_initialized`, so a later module in the same session would keep these throwaway
    # values and never re-read the environment. Undone explicitly, because a teardown that looks
    # thorough and is not is worse than one that admits its limits.
    try:
        from app.core import config as _config
        _config._runtime_initialized = False
    except Exception:                     # noqa: BLE001 - teardown must never fail the suite
        pass


@pytest.fixture
def crypto():
    from app.core import security
    return security


@pytest.fixture
def ids():
    return uuid.uuid4(), uuid.uuid4()


def _write(crypto, vault_id, file_id, chunks):
    codec = crypto.GcmChunkStreamCodecV2(vault_id, file_id)
    out = [codec.header()]
    for index, chunk in enumerate(chunks):
        out.append(codec.encrypt(chunk, index))
    out.append(codec.terminal())
    return b"".join(out)


def _v2_header(crypto, write_id=None):
    """A syntactically valid v2 header, write id included.

    The header grew when the per-write random was added, and the parse-level tests below build
    blobs by hand. They never authenticate anything, so any write id will do -- what matters is
    that the reader gets the length it expects before it reaches the record it is meant to reject.
    """
    return crypto._GCM_STREAM_HEADER_V2_PREFIX + (write_id or bytes(range(16)))


def _read(crypto, blob, vault_id, file_id):
    return crypto.decrypt_gcm_chunk_stream(io.BytesIO(blob), vault_id, file_id)


# ---------------------------------------------------------------- the happy paths

@pytest.mark.parametrize("chunks, expected", [
    ([b"hello ", b"world"], b"hello world"),
    ([b"one chunk only"], b"one chunk only"),
    ([b"a" * 4096, b"b" * 4096], b"a" * 4096 + b"b" * 4096),
    # Records are NOT required to be uniform, and a rule demanding it would reject legitimate
    # uploads: the resumable path re-chunks each staged chunk file at 1 MiB, so a staged chunk
    # that is not a multiple of 1 MiB legally emits a short interior record.
    ([b"x" * 1000, b"y" * 7, b"z" * 60000], b"x" * 1000 + b"y" * 7 + b"z" * 60000),
], ids=["two-small", "single", "two-4k", "non-uniform"])
def test_a_terminated_stream_round_trips(crypto, ids, chunks, expected):
    vault_id, file_id = ids
    assert _read(crypto, _write(crypto, vault_id, file_id, chunks), vault_id, file_id) == expected


def test_an_empty_file_is_a_terminal_and_nothing_else(crypto, ids):
    """Zero records is legal and must still be terminated, or an empty file is indistinguishable
    from a file truncated to nothing."""
    vault_id, file_id = ids
    blob = _write(crypto, vault_id, file_id, [])
    assert _read(crypto, blob, vault_id, file_id) == b""
    assert len(blob) == (12 + 16) + 4 + 12 + 16      # header + write id, then the terminal


# ---------------------------------------------------------------- what the terminal is for

def test_a_truncated_file_is_refused(crypto, ids):
    """The whole reason for the version bump.

    Dropping the terminal leaves every remaining record perfectly valid — under `0x10` this reads
    back as a shorter file with no complaint.
    """
    vault_id, file_id = ids
    blob = _write(crypto, vault_id, file_id, [b"first", b"second", b"third"])
    without_terminal = blob[:-(4 + 12 + 16)]

    # Non-vacuity: the bytes that remain are genuinely intact and would have read cleanly before.
    assert _read(crypto, blob, vault_id, file_id) == b"firstsecondthird"
    with pytest.raises(crypto.EncryptionError, match="without a terminal"):
        _read(crypto, without_terminal, vault_id, file_id)


def test_dropping_only_the_last_record_is_refused(crypto, ids):
    """A subtler truncation: keep the terminal, remove the record before it.

    Caught by the count and length in the terminal's associated data, not by the terminal's
    presence — so this is the case that a "does it end with 28 bytes" check would miss.
    """
    vault_id, file_id = ids
    codec = crypto.GcmChunkStreamCodecV2(vault_id, file_id)
    header = codec.header()
    first = codec.encrypt(b"kept", 0)
    codec.encrypt(b"removed", 1)          # counted by the writer, then left out of the file
    spliced = header + first + codec.terminal()
    with pytest.raises(crypto.EncryptionError):
        _read(crypto, spliced, vault_id, file_id)


def test_trailing_bytes_after_the_terminal_are_refused(crypto, ids):
    """Strict EOF. The reader must read the terminal as exactly 28 bytes rather than to
    end-of-file, or appended data is misreported as a corrupt tag and this check never runs."""
    vault_id, file_id = ids
    blob = _write(crypto, vault_id, file_id, [b"payload"])
    with pytest.raises(crypto.EncryptionError, match="Trailing bytes"):
        _read(crypto, blob + b"\x00", vault_id, file_id)


def test_a_terminal_from_a_shorter_file_does_not_transplant(crypto, ids):
    """It authenticates a different count and length, so it cannot be lifted."""
    vault_id, file_id = ids
    long_blob = _write(crypto, vault_id, file_id, [b"a" * 100, b"b" * 100])
    short_blob = _write(crypto, vault_id, file_id, [b"a" * 100])
    terminal = short_blob[-(4 + 12 + 16):]
    spliced = long_blob[:-(4 + 12 + 16)] + terminal
    with pytest.raises(crypto.EncryptionError):
        _read(crypto, spliced, vault_id, file_id)


# ---------------------------------------------------------------- binding

def test_a_blob_does_not_open_under_another_vault_or_file(crypto, ids):
    vault_id, file_id = ids
    blob = _write(crypto, vault_id, file_id, [b"secret"])
    with pytest.raises(crypto.EncryptionError):
        _read(crypto, blob, uuid.uuid4(), file_id)
    with pytest.raises(crypto.EncryptionError):
        _read(crypto, blob, vault_id, uuid.uuid4())


def test_records_cannot_be_reordered_or_duplicated(crypto, ids):
    vault_id, file_id = ids
    codec = crypto.GcmChunkStreamCodecV2(vault_id, file_id)
    header, first, second = codec.header(), codec.encrypt(b"1" * 40, 0), codec.encrypt(b"2" * 40, 1)
    terminal = codec.terminal()
    for label, body in (("reordered", second + first), ("duplicated", first + first)):
        with pytest.raises(crypto.EncryptionError):
            _read(crypto, header + body + terminal, vault_id, file_id)


def test_a_v1_record_does_not_authenticate_inside_a_v2_file(crypto, ids):
    """The domain string advances to v2 precisely so this fails."""
    vault_id, file_id = ids
    v1 = crypto.GcmChunkStreamCodec(vault_id, file_id)
    v2 = crypto.GcmChunkStreamCodecV2(vault_id, file_id)
    spliced = v2.header() + v1.encrypt(b"lifted", 0) + v2.terminal()
    with pytest.raises(crypto.EncryptionError):
        _read(crypto, spliced, vault_id, file_id)


def test_relabelling_a_v2_file_as_v1_does_not_downgrade_it(crypto, ids):
    """Routing a terminated file to the reader that does not require a terminal."""
    vault_id, file_id = ids
    blob = _write(crypto, vault_id, file_id, [b"payload"])
    relabelled = bytearray(blob)
    relabelled[9] = crypto.GCM_STREAM_VERSION
    with pytest.raises(crypto.EncryptionError):
        _read(crypto, bytes(relabelled), vault_id, file_id)


# ---------------------------------------------------------------- header and bounds

def test_non_zero_reserved_bytes_are_refused(crypto, ids):
    """This version promotes them to a real breaking-change channel; a reader that ignored them
    would silently misread a future format that gives them meaning."""
    vault_id, file_id = ids
    blob = bytearray(_write(crypto, vault_id, file_id, [b"x" * 20]))
    blob[11] = 0x01
    with pytest.raises(crypto.EncryptionError, match="Reserved"):
        _read(crypto, bytes(blob), vault_id, file_id)


@pytest.mark.parametrize("declared", [0, 1, 12, 28])
def test_an_undersized_record_is_refused_before_allocation(crypto, ids, declared):
    """A length of 1..28 cannot hold a nonce, a tag and a byte of plaintext. Rejected on the
    number, not by failing inside the cipher."""
    vault_id, file_id = ids
    blob = (_v2_header(crypto) + struct.pack(">I", declared) + b"\x00" * max(declared, 0))
    with pytest.raises(crypto.EncryptionError, match="Record length"):
        _read(crypto, blob, vault_id, file_id)


def test_an_oversized_record_is_refused_before_allocation(crypto, ids):
    """The 48-byte file that reaches a 4 GiB read.

    The point is the ORDER: a reader that allocated first and validated second would try to read
    the claimed length from a file that does not contain it. This blob is 16 bytes long and claims
    four gigabytes.
    """
    vault_id, file_id = ids
    blob = _v2_header(crypto) + struct.pack(">I", 0xFFFFFFFE)
    with pytest.raises(crypto.EncryptionError, match="Record length"):
        _read(crypto, blob, vault_id, file_id)


def test_the_terminal_marker_can_never_be_a_legal_record_length(crypto):
    """A grammar invariant, not an arithmetic coincidence of today's numbers. If a data record
    could carry this length, no reader could tell the two apart."""
    assert crypto.MAX_RECORD_BYTES < crypto._TERMINAL_MARKER


def test_the_writer_refuses_to_exceed_what_its_reader_accepts(crypto, ids):
    """Otherwise a writer can produce an object that uploads and can never be downloaded."""
    vault_id, file_id = ids
    codec = crypto.GcmChunkStreamCodecV2(vault_id, file_id)
    with pytest.raises(crypto.EncryptionError, match="exceeds"):
        codec.encrypt(b"x" * (crypto.MAX_CHUNK_SIZE + 1), 0)


# ---------------------------------------------------------------- compatibility

def test_the_associated_data_is_exactly_what_the_document_specifies(crypto):
    """The wire contract, pinned as bytes.

    Reverting the v2 domain string to v1 changed no test result — because the version byte is
    bound too and independently blocks the attack the domain exists to stop. That is defence in
    depth working, and it is also how one of two independent separations disappears unnoticed.

    So this pins the construction rather than its consequences: the domains, the version byte, the
    field order and the widths. It is also what keeps the encoding injective — every field after
    the domain is fixed-width, so the length determines the split. A future domain must preserve
    that; a variable-width field without a length prefix would break it.
    """
    vault_id = uuid.UUID("11111111-1111-4111-8111-111111111111")
    file_id = uuid.UUID("22222222-2222-4222-8222-222222222222")

    write_id = bytes(range(16))

    data = crypto._chunk_stream_aad_v2(vault_id, file_id, write_id, 7)
    assert data == (b"dockvault-chunk-aad-v2" + bytes([0x20]) + write_id
                    + vault_id.bytes + file_id.bytes + struct.pack(">Q", 7))

    terminal = crypto._terminal_aad_v2(vault_id, file_id, write_id, 3, 4096)
    assert terminal == (b"dockvault-terminal-aad-v2" + bytes([0x20]) + write_id
                        + vault_id.bytes + file_id.bytes
                        + struct.pack(">Q", 3) + struct.pack(">Q", 4096))

    # A terminal must never be readable as a data record, or the reverse.
    assert not data.startswith(b"dockvault-terminal-aad-v2")
    assert not terminal.startswith(b"dockvault-chunk-aad-v2")
    # And neither may collide with the previous generation's.
    assert not data.startswith(crypto._CHUNK_AAD_DOMAIN + bytes([0]))


def test_the_older_format_still_reads(crypto, ids):
    """Retained, with no bulk rewrite. Existing objects are `0x10`, and dropping the reader would
    destroy them."""
    vault_id, file_id = ids
    codec = crypto.GcmChunkStreamCodec(vault_id, file_id)
    blob = codec.header() + codec.encrypt(b"older", 0) + codec.encrypt(b" format", 1)
    assert _read(crypto, blob, vault_id, file_id) == b"older format"


def test_both_versions_are_detected_as_a_chunk_stream(crypto, ids, tmp_path):
    """Detection compared the version for equality with `0x10` in exactly one place. A `0x20` file
    that failed detection would route to the Fernet reader and be reported as damaged."""
    vault_id, file_id = ids
    for name, blob in (
        ("v1.bin", crypto.GcmChunkStreamCodec(vault_id, file_id).header()),
        ("v2.bin", crypto.GcmChunkStreamCodecV2(vault_id, file_id).header()),
    ):
        path = tmp_path / name
        path.write_bytes(blob)
        assert crypto.is_gcm_chunk_stream(path), name

    other = tmp_path / "legacy.bin"
    other.write_bytes(struct.pack(">I", 40) + b"\x00" * 40)   # a Fernet-style length prefix
    assert not crypto.is_gcm_chunk_stream(other)


# ---------------------------------------------------------------- bounds nobody was checking

def test_the_record_ceiling_is_enforced_on_both_sides(crypto, monkeypatch):
    """`MAX_RECORDS` could be deleted from the reader AND the writer with every lane green.

    Neither is decorative. The reader's is the only cap on how many records a file may claim; the
    writer's exists so it cannot produce an object its own reader refuses — the "uploads fine,
    never downloads" shape. Driven with the ceiling lowered rather than by writing two million
    records.
    """
    monkeypatch.setattr(crypto, "MAX_RECORDS", 3)
    vault_id, file_id = uuid.uuid4(), uuid.uuid4()

    codec = crypto.GcmChunkStreamCodecV2(vault_id, file_id)
    body = [codec.header()]
    for i in range(3):
        body.append(codec.encrypt(b"x" * 10, i))
    with pytest.raises(crypto.EncryptionError, match="Too many records"):
        codec.encrypt(b"x" * 10, 3)

    # And the reader refuses a file that carries more than it will accept. Built with the ceiling
    # temporarily raised, so the blob itself is legitimate and only the reader's limit differs.
    monkeypatch.setattr(crypto, "MAX_RECORDS", 10)
    wide = crypto.GcmChunkStreamCodecV2(vault_id, file_id)
    blob = wide.header() + b"".join(wide.encrypt(b"y" * 10, i) for i in range(5)) + wide.terminal()
    assert _read(crypto, blob, vault_id, file_id) == b"y" * 50
    monkeypatch.setattr(crypto, "MAX_RECORDS", 3)
    with pytest.raises(crypto.EncryptionError, match="Too many records"):
        _read(crypto, blob, vault_id, file_id)


def test_the_writer_refuses_an_empty_record(crypto, ids):
    """The lower-bound twin of the chunk-size ceiling, which does have a test.

    An empty chunk produces a 28-byte record that this format's own reader rejects, so the file
    would upload and never download.
    """
    vault_id, file_id = ids
    codec = crypto.GcmChunkStreamCodecV2(vault_id, file_id)
    with pytest.raises(crypto.EncryptionError, match="empty record"):
        codec.encrypt(b"", 0)


def test_a_zero_plaintext_record_is_legal_in_the_older_format(crypto, ids):
    """The regression that reached the pinned release vectors, named directly.

    `0x20` requires at least one plaintext byte per record; `0x10` does not, and the frozen release
    fixture contains one. Applying the newer floor to the retained reader made every such object
    permanently undownloadable. Reverting that fix currently fails only the pre-existing pinned
    vector, with nothing in this file naming it — so this names it.
    """
    vault_id, file_id = ids
    v1 = crypto.GcmChunkStreamCodec(vault_id, file_id)
    blob = v1.header() + v1.encrypt(b"", 0) + v1.encrypt(b"after the empty one", 1)
    assert _read(crypto, blob, vault_id, file_id) == b"after the empty one"


def test_the_terminal_binds_the_length_and_not_only_the_count(crypto, ids):
    """The one splice that isolates the length binding.

    Dropping either the count or the length from the terminal's associated data leaves the other
    truncation tests passing, because in those the two change together. Here the record COUNT
    matches and only the total length differs.
    """
    vault_id, file_id = ids
    long_codec = crypto.GcmChunkStreamCodecV2(vault_id, file_id)
    long_blob = (long_codec.header() + long_codec.encrypt(b"a" * 100, 0)
                 + long_codec.encrypt(b"b" * 100, 1) + long_codec.terminal())
    short_codec = crypto.GcmChunkStreamCodecV2(vault_id, file_id)
    short_blob = (short_codec.header() + short_codec.encrypt(b"a" * 100, 0)
                  + short_codec.encrypt(b"b" * 20, 1) + short_codec.terminal())

    tail = 4 + 12 + 16
    spliced = long_blob[:-tail] + short_blob[-tail:]      # two records either way
    with pytest.raises(crypto.EncryptionError):
        _read(crypto, spliced, vault_id, file_id)


def test_a_terminal_cut_short_is_reported_as_such(crypto, ids):
    """Truncating INSIDE the 28-byte terminal, rather than removing it."""
    vault_id, file_id = ids
    blob = _write(crypto, vault_id, file_id, [b"payload"])
    with pytest.raises(crypto.EncryptionError, match="Truncated terminal"):
        _read(crypto, blob[:-4], vault_id, file_id)


def test_identifying_an_unreadable_file_raises_rather_than_guessing(crypto, tmp_path):
    """A transient read failure is not "some other format".

    Returning False sent a healthy object to the wrong reader and reported it damaged — the exact
    mislabel this work removes, by the cheapest possible route. A directory is the simplest thing
    that reliably fails to open as a file.
    """
    with pytest.raises(crypto.EncryptionError, match="Could not identify"):
        crypto.is_gcm_chunk_stream(tmp_path)


def test_a_readable_file_of_another_format_still_answers_false(crypto, tmp_path):
    """Non-vacuity for the test above: raising for EVERYTHING would satisfy it.

    The distinction is between a file that could not be read and a file that was read and is not
    this format. Only the first is an anomaly; a legacy Fernet blob is the second and must still
    route onward silently.

    A file that is ABSENT does not appear here on purpose. It is not this function's problem: the
    caller checks `storage_path.exists()` and raises before detection is reached, so the case is
    unreachable in production and asserting a behaviour for it would be inventing a contract.
    """
    legacy = tmp_path / "fernet.bin"
    legacy.write_bytes(struct.pack(">I", 40) + b"" * 40)
    assert crypto.is_gcm_chunk_stream(legacy) is False


# ---------------------------------------------------------------- one write, one identity

def test_two_writes_of_one_object_have_interchangeable_nothing(crypto, ids):
    """What the per-write random exists for.

    A terminal authenticates the vault, the file, the record count and the total length. Nothing
    in that set distinguishes two writes of the SAME object with the same shape, so before this
    the terminal from an earlier write was a valid terminal for a later one: an actor with disk
    access who kept the old one could cut the current object down to a matching record count,
    reattach it, and the result authenticated as a complete file.

    The object id cannot separate them — it is deliberately stable across a resumed upload,
    because the name is sealed against it. So the writer mints a value that is not.
    """
    vault_id, file_id = ids
    first = _write(crypto, vault_id, file_id, [b"a" * 64, b"b" * 64])
    second = _write(crypto, vault_id, file_id, [b"c" * 64, b"d" * 64])

    # Same object, same shape, different identity on the wire.
    assert len(first) == len(second)
    assert first[12:28] != second[12:28], "two writes were given the same write id"

    tail = 4 + 12 + 16
    for label, spliced in (
        ("terminal from the other write", first[:-tail] + second[-tail:]),
        ("header from the other write", second[:28] + first[28:]),
        ("a record from the other write",
         first[:28] + second[28:28 + 64 + 28] + first[28 + 64 + 28:]),
    ):
        with pytest.raises(crypto.EncryptionError):
            _read(crypto, spliced, vault_id, file_id)


def test_the_write_id_is_not_something_a_caller_supplies(crypto, ids):
    """A caller able to choose it could reproduce a previous write's value and reopen the replay.

    It is minted inside the writer, exactly as the attempt token is in the zero-knowledge content
    format — same hazard, same answer.
    """
    import inspect

    vault_id, file_id = ids
    signature = inspect.signature(crypto.GcmChunkStreamCodecV2.__init__)
    assert list(signature.parameters) == ["self", "vault_id", "file_id"], (
        "the writer takes something beyond the object it is writing; if that is the write id, a "
        "caller can reuse one")
    assert crypto.GcmChunkStreamCodecV2(vault_id, file_id)._write_id != \
        crypto.GcmChunkStreamCodecV2(vault_id, file_id)._write_id


def test_a_truncated_header_is_refused(crypto, ids):
    """The header is longer than it was, so it has a new way to be incomplete."""
    vault_id, file_id = ids
    blob = _write(crypto, vault_id, file_id, [b"payload"])
    with pytest.raises(crypto.EncryptionError, match="Truncated header"):
        _read(crypto, blob[:20], vault_id, file_id)
