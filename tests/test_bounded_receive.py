"""A request body is written as it arrives, not collected and then written.

The chunk-upload handler used to accumulate its body in a bytearray and then copy it, bounded by
how much of the declared *file* was outstanding rather than by any per-request size. The bound was
real and documented; it just was not a bound on memory. A client that declared its file as a single
chunk was allowed to hold all of it, twice -- 273.7 MB for a 128 MB file, against 22.7 MB for the
same file in 5 MB pieces. The client chose the server's memory.

The property is "nothing larger than one piece is held", which is not directly observable from
outside. What is observable, and what distinguishes the two implementations, is *interleaving*: a
streaming receive has written the earlier pieces by the time it asks for a later one, and an
accumulating receive has written nothing until the stream is exhausted. These drive the receive
loop with a stream that looks at the destination as it is being read.

`tests/test_chunk_upload_memory.py` measures the resulting memory against a live deployment. This
file is the guard that runs everywhere, including where no cgroup is readable.
"""

import asyncio
import hashlib
import io

import pytest

from app.services.streaming_upload import receive_bounded, ChunkTooLarge, EmptyBody


pytestmark = pytest.mark.unit

# Larger than Python's write buffer, so a written piece has reached the file rather than sitting in
# a buffer this test would then fail to see. Derived rather than hard-coded: the buffer is 128 KiB
# on this interpreter, not the 8 KiB that is easy to assume, and a literal that silently fell under
# it would turn every interleaving reading into a zero and the test into a passing tautology.
PIECE = max(256 * 1024, io.DEFAULT_BUFFER_SIZE * 2)


def _run(coro):
    # `asyncio.run`, so the loop shuts its async generators down. Abandoning one mid-iteration is
    # exactly what the refusal path does, and a bare `run_until_complete` leaves it pending and
    # warns about it long after the test that caused it has passed.
    return asyncio.run(coro)


class _WatchingStream:
    """Yields pieces, and records the destination's size just before handing over each one."""

    def __init__(self, pieces, watch_path):
        self.pieces = pieces
        self.watch_path = watch_path
        self.sizes_seen = []
        self.pieces_pulled = 0

    def __aiter__(self):
        return self._iterate()

    async def _iterate(self):
        for piece in self.pieces:
            self.sizes_seen.append(
                self.watch_path.stat().st_size if self.watch_path.exists() else 0)
            self.pieces_pulled += 1
            yield piece


def test_each_piece_is_on_disk_before_the_next_is_asked_for(tmp_path):
    """The distinguishing observation.

    Under the old implementation every one of these readings would be zero: nothing was written
    until the whole body had been collected. Under a streaming one they climb by a piece at a time.
    """
    dest = tmp_path / "chunk.part"
    pieces = [bytes([i]) * PIECE for i in range(1, 6)]
    stream = _WatchingStream(pieces, dest)

    written, digest = _run(receive_bounded(stream, dest, limit=10 * PIECE))

    assert written == 5 * PIECE
    assert digest == hashlib.sha256(b"".join(pieces)).hexdigest()
    assert stream.sizes_seen == [0, PIECE, 2 * PIECE, 3 * PIECE, 4 * PIECE], (
        f"the destination did not grow as the body was read: {stream.sizes_seen}; "
        "the body is being collected before it is written")
    assert dest.read_bytes() == b"".join(pieces)


def test_the_limit_stops_the_read_rather_than_the_write(tmp_path):
    """Refusal has to happen while the body is arriving, not after it has all been taken.

    Otherwise the bound describes what is stored and says nothing about what was held to get there.
    """
    dest = tmp_path / "chunk.part"
    pieces = [b"x" * PIECE for _ in range(10)]
    stream = _WatchingStream(pieces, dest)

    with pytest.raises(ChunkTooLarge):
        _run(receive_bounded(stream, dest, limit=2 * PIECE + 1))

    assert stream.pieces_pulled == 3, (
        f"read {stream.pieces_pulled} of 10 pieces before refusing; the limit is being applied "
        "after the body has been consumed")


def test_a_refused_body_leaves_no_partial_file(tmp_path):
    """Streaming to disk means an over-long body is partly written before it is rejected.

    Within a live session nothing reclaims an individual temp file -- the session directory is
    removed wholesale on completion or by the periodic sweeper, neither of which helps a session
    that is still uploading -- so a refusal that leaves one behind is a slower way to fill a disk
    than the upload it refused.
    """
    dest = tmp_path / "chunk.part"
    stream = _WatchingStream([b"y" * PIECE] * 4, dest)

    with pytest.raises(ChunkTooLarge):
        _run(receive_bounded(stream, dest, limit=PIECE))

    assert not dest.exists(), "the partial file survived the refusal"


def test_a_stream_that_dies_mid_body_also_leaves_nothing(tmp_path):
    """A dropped connection is the common case, and it is not a `ChunkTooLarge`."""
    dest = tmp_path / "chunk.part"

    class _Dies:
        def __aiter__(self):
            return self._iterate()

        async def _iterate(self):
            yield b"z" * PIECE
            raise ConnectionResetError("client went away")

    with pytest.raises(ConnectionResetError):
        _run(receive_bounded(_Dies(), dest, limit=100 * PIECE))

    assert not dest.exists(), "a dropped connection left a partial chunk behind"


def test_a_body_exactly_at_the_limit_is_accepted(tmp_path):
    """The boundary, in the direction that would break real uploads if it were wrong.

    The final chunk of a file is exactly what remains, so an off-by-one here refuses every
    correctly-sized upload rather than only the abusive ones.
    """
    dest = tmp_path / "chunk.part"
    pieces = [b"w" * PIECE, b"w" * PIECE]
    written, _ = _run(receive_bounded(_WatchingStream(pieces, dest), dest, limit=2 * PIECE))
    assert written == 2 * PIECE
    assert dest.read_bytes() == b"w" * 2 * PIECE


def test_an_empty_body_is_refused_and_leaves_nothing(tmp_path):
    """Refused here rather than by the caller, so the cleanup is on one path.

    This returned zero cleanly at first and left the caller to raise the 400 and remove the file.
    Both halves of that were asserted in comments and tested nowhere, and deleting the caller's
    `unlink` changed no test -- the removal now happens where the file was opened.
    """
    dest = tmp_path / "chunk.part"
    with pytest.raises(EmptyBody):
        _run(receive_bounded(_WatchingStream([], dest), dest, limit=PIECE))
    assert not dest.exists(), "an empty body left a zero-length file behind"


def test_a_body_of_only_empty_pieces_counts_as_empty(tmp_path):
    """A stream can yield without carrying anything, and that is still nothing received."""
    dest = tmp_path / "chunk.part"
    with pytest.raises(EmptyBody):
        _run(receive_bounded(_WatchingStream([b"", b"", b""], dest), dest, limit=PIECE))
    assert not dest.exists()
