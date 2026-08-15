"""Reading arbitrary ranges out of a stored file without holding the file.

The SFTP contract is "any offset, any order, any number of times", and it was met by keeping the
whole decrypted file in memory for as long as a client left the handle open -- not for the length
of a transfer. That made it the most expensive read in the system: a 120 MB file cost 120 MB from
open to close, and a client that opened one and walked away held it indefinitely.

`GcmChunkStreamReader.read_range` answers ranges out of the index the format walk already builds,
decrypting only the records a request touches and keeping the last two. These tests cover the
contract a caller slicing a whole-file buffer would have got -- including the boundaries that are
easy to get wrong -- and the amplification that makes the cache load-bearing rather than an
optimisation.
"""

import os
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
    from app.core import security
    return security


@pytest.fixture
def reader_for(sec, tmp_path):
    """Build a real blob with the production writer and open a reader over it."""
    made = []

    def _build(chunks, version=2):
        codec = (sec.GcmChunkStreamCodecV2(VAULT, FILE) if version == 2
                 else sec.GcmChunkStreamCodec(VAULT, FILE))
        blob = bytearray(codec.header())
        for i, chunk in enumerate(chunks):
            blob += codec.encrypt(chunk, i)
        if hasattr(codec, "terminal"):
            blob += codec.terminal()
        path = tmp_path / f"blob-{len(made)}"
        path.write_bytes(bytes(blob))
        handle = open(path, "rb")
        made.append(handle)
        return sec.GcmChunkStreamReader(handle, VAULT, FILE), b"".join(chunks)

    yield _build
    for handle in made:
        handle.close()


# ---------------------------------------------------------------- the contract

def test_every_range_matches_slicing_the_whole_file(reader_for):
    """Exhaustive against the thing it replaces, at every boundary that exists.

    A caller that used to slice a buffer must get identical bytes. The offsets below deliberately
    include record boundaries, one byte either side of them, and ranges spanning three records.
    """
    chunks = [b"A" * 100, b"B" * 250, b"C" * 7, b"D" * 300]
    reader, whole = reader_for(chunks)

    boundaries = [0, 99, 100, 101, 349, 350, 351, 356, 357, 358, 656, 657]
    for offset in boundaries:
        for length in (1, 7, 100, 350, 700):
            assert reader.read_range(offset, length) == whole[offset:offset + length], (
                f"range({offset}, {length}) differed from slicing")


def test_reads_past_and_across_the_end_behave_like_a_slice(reader_for):
    """Where a buffer returns short or empty, so must this."""
    reader, whole = reader_for([b"A" * 50, b"B" * 50])
    total = len(whole)

    assert reader.read_range(total, 10) == b""
    assert reader.read_range(total + 1000, 10) == b""
    assert reader.read_range(total - 10, 999) == whole[-10:]
    assert reader.read_range(0, 10_000) == whole


def test_degenerate_requests_return_nothing(reader_for):
    reader, _whole = reader_for([b"A" * 50])
    assert reader.read_range(0, 0) == b""
    assert reader.read_range(0, -5) == b""
    assert reader.read_range(-1, 10) == b""


def test_out_of_order_and_repeated_reads_are_stable(reader_for):
    """The contract is any order, any number of times."""
    chunks = [bytes([i]) * 1000 for i in range(1, 6)]
    reader, whole = reader_for(chunks)

    for offset in (4200, 0, 2500, 999, 4999, 0, 2500):
        assert reader.read_range(offset, 300) == whole[offset:offset + 300]


def test_the_retained_format_reads_the_same_way(reader_for):
    """0x10 has no terminal, but its framing is identical, so ranges work the same."""
    reader, whole = reader_for([b"A" * 100, b"", b"B" * 100], version=1)
    assert reader.length_is_authenticated is False
    assert reader.read_range(50, 100) == whole[50:150]
    assert reader.read_range(0, 999) == whole


# ---------------------------------------------------------------- cost

def _decrypt_count(reader, monkeypatch):
    """Count records actually decrypted, by wrapping the reader's own decrypt step."""
    calls = []
    real = reader._decrypt_at

    def _counted(index, offset):
        calls.append(index)
        return real(index, offset)

    monkeypatch.setattr(reader, "_decrypt_at", _counted)
    return calls


def test_a_sequential_read_decrypts_each_record_once(reader_for, monkeypatch):
    """The amplification the cache exists to remove.

    Clients read sequentially in small requests -- 32 KiB is typical. Without a cache each of those
    decrypts the whole record it lands in, so a 1 MiB record is decrypted about thirty times over.
    """
    record = 256 * 1024
    chunks = [bytes([65 + i]) * record for i in range(4)]
    reader, whole = reader_for(chunks)
    calls = _decrypt_count(reader, monkeypatch)

    step = 32 * 1024
    got = bytearray()
    for offset in range(0, len(whole), step):
        got += reader.read_range(offset, step)

    assert bytes(got) == whole
    assert len(calls) == len(chunks), (
        f"{len(calls)} decryptions for {len(chunks)} records over {len(whole) // step} reads; "
        "each record should be decrypted once")


def test_a_read_spanning_a_boundary_does_not_evict_what_comes_next(reader_for, monkeypatch):
    """Why the cache holds two records rather than one.

    A read straddling a boundary touches two records. With a single slot the second evicts the
    first, and a sequential client then re-decrypts on the very next read.
    """
    record = 1000
    reader, whole = reader_for([b"A" * record, b"B" * record, b"C" * record])

    reader.read_range(900, 200)          # spans records 0 and 1
    calls = _decrypt_count(reader, monkeypatch)
    reader.read_range(950, 20)           # inside record 0, which must still be cached
    reader.read_range(1100, 20)          # inside record 1, likewise

    assert calls == [], f"re-decrypted {calls} after a boundary-spanning read"


def test_a_random_read_touches_only_the_records_it_needs(reader_for, monkeypatch):
    """The bound that matters for a seeking client: no decrypt-from-start, ever."""
    record = 4096
    chunks = [bytes([65 + (i % 26)]) * record for i in range(40)]
    reader, whole = reader_for(chunks)
    calls = _decrypt_count(reader, monkeypatch)

    offset = 30 * record + 17            # deep into the file, cold
    assert reader.read_range(offset, 100) == whole[offset:offset + 100]
    assert calls == [30], (
        f"reading 100 bytes at record 30 decrypted {calls}; only that record should be touched")


def test_the_index_holds_one_number_per_record(reader_for):
    """Not four. The record number is the array position and the file offset is arithmetic.

    At the record count this format permits, the difference between one number and four is the
    difference between a few megabytes and hundreds -- and this is held per open handle.
    """
    reader, _whole = reader_for([b"x" * 100] * 20)
    reader.read_range(0, 10)             # builds the offset index

    assert reader._plain_cum.itemsize * len(reader._plain_cum) <= 8 * 21
    assert len(reader._plain_cum) == 21, "one entry per record, plus the total"


def test_the_cache_never_holds_more_than_two_records(reader_for):
    """A per-handle memory bound is only a bound if nothing can grow it."""
    reader, _whole = reader_for([bytes([65 + i]) * 500 for i in range(20)])
    for index in range(20):
        reader.read_range(index * 500, 10)
    assert len(reader._cache) <= 2, f"the cache grew to {len(reader._cache)} records"
