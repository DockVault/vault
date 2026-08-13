"""A download must not be able to succeed after an integrity check failed.

The at-rest walk settles almost everything before the response body exists. What it cannot settle
is the stored checksum, which is only known once the last byte has been hashed -- by which point,
naively, that byte has been sent, the response length is satisfied, and the client has a clean
success for a file the server just rejected.

`verified_stream` holds the final piece back so the check happens with bytes still owed. These
tests are about that, and about the two degenerate cases that make it easy to get wrong: a file
with no pieces at all, and a file with exactly one.
"""

import hashlib

import pytest

from app.services.download_stream import verified_stream, ChecksumMismatch, BoundedDownload


pytestmark = pytest.mark.unit


def _sha(*pieces):
    return hashlib.sha256(b"".join(pieces)).hexdigest()


def _drain(chunks, checksum):
    return list(verified_stream(iter(chunks), checksum))


def test_a_matching_file_streams_every_piece_in_order():
    pieces = [b"one", b"two", b"three"]
    assert _drain(pieces, _sha(*pieces)) == pieces


def test_the_last_piece_is_withheld_until_the_source_is_exhausted():
    """Observed at the point it matters, not inferred from the order things came out in.

    An earlier version of this test asserted only that the pieces arrived in order -- which an
    implementation with no hold-back at all also satisfies, so it survived removing the thing it
    was named after. What distinguishes them is *when*: a holding implementation has read every
    piece from the source before it releases the second-to-last, because that is how it knows the
    last one exists.
    """
    pieces = [b"a" * 8, b"b" * 8, b"c" * 8]
    pulled = []

    def _source():
        for piece in pieces:
            pulled.append(piece)
            yield piece

    stream = verified_stream(_source(), _sha(*pieces))

    assert next(stream) == pieces[0]
    assert len(pulled) == 2, (
        f"the first piece was released after pulling {len(pulled)}; a hold-back must have read "
        "the next one before releasing this one")
    assert next(stream) == pieces[1]
    assert len(pulled) == 3, "the source should be exhausted before the last piece is released"
    assert next(stream) == pieces[2]
    with pytest.raises(StopIteration):
        next(stream)


def test_a_mismatch_aborts_with_the_last_piece_still_owed():
    """The client is left short of the promised length, which is what makes the failure visible."""
    pieces = [b"a" * 8, b"b" * 8, b"c" * 8]
    stream = verified_stream(iter(pieces), _sha(b"something", b"else"))

    served = [next(stream), next(stream)]
    assert served == pieces[:2], "the earlier pieces should have been served"
    with pytest.raises(ChecksumMismatch):
        next(stream)

    total = sum(len(p) for p in pieces)
    assert sum(len(p) for p in served) < total, (
        "every byte was served before the mismatch was raised; there is nothing left to signal "
        "with and the client sees a complete response")


def test_an_empty_file_is_checked_before_anything_is_yielded():
    """A zero-length file is legal, has no piece to hold back, and no short body to signal with.

    So the check has to happen before the first yield. Without this clause a stored checksum that
    does not match an empty file produces a clean, complete, wrong response.
    """
    stream = verified_stream(iter([]), _sha(b"not empty"))
    with pytest.raises(ChecksumMismatch):
        next(stream)


def test_an_empty_file_that_matches_streams_nothing_and_succeeds():
    assert _drain([], _sha()) == []


def test_a_single_piece_file_is_checked_before_it_is_served():
    """The hold-back degenerates to buffering the whole file, which for one record is correct."""
    stream = verified_stream(iter([b"only"]), _sha(b"different"))
    with pytest.raises(ChecksumMismatch):
        next(stream)

    assert _drain([b"only"], _sha(b"only")) == [b"only"]


def test_empty_pieces_do_not_disturb_the_hold_back():
    """A reader may legitimately yield a zero-length piece; the bytes served must be unchanged."""
    pieces = [b"head", b"", b"tail"]
    assert b"".join(_drain(pieces, _sha(*pieces))) == b"headtail"


def test_a_trailing_empty_piece_does_not_defeat_the_hold_back():
    """The shape that made the hold-back withhold nothing at all.

    Holding back a *piece* rather than *bytes* meant a zero-length final piece satisfied the
    hold-back while withholding nothing: every byte went out, the declared length was met, and the
    client saw a complete success for a file whose checksum had just been rejected. A
    zero-plaintext record is legal in the retained format and a frozen release fixture contains
    one, so this is reachable rather than theoretical.
    """
    pieces = [b"A" * 100, b""]
    stream = verified_stream(iter(pieces), _sha(b"something else"))

    served = []
    with pytest.raises(ChecksumMismatch):
        for piece in stream:
            served.append(piece)

    assert sum(len(p) for p in served) < 100, (
        f"{sum(len(p) for p in served)} of 100 bytes were served before the mismatch was raised; "
        "the declared length is already satisfied and the client sees a complete response")


def test_a_run_of_trailing_empty_pieces_is_also_covered():
    """Several in a row, in case the fix only skipped one."""
    pieces = [b"A" * 60, b"", b"", b""]
    served = []
    with pytest.raises(ChecksumMismatch):
        for piece in verified_stream(iter(pieces), _sha(b"nope")):
            served.append(piece)
    assert sum(len(p) for p in served) < 60


def test_a_file_with_no_recorded_checksum_is_refused():
    """Fail closed, matching the reader this replaces.

    That reader compared the content against the stored value, and an empty one never matched, so
    such a file was refused. The column is NOT NULL so it should be unreachable -- which is why it
    must not become the one path that serves anything without checking it.
    """
    with pytest.raises(ChecksumMismatch):
        _drain([b"x", b"y"], None)
    with pytest.raises(ChecksumMismatch):
        _drain([b"x", b"y"], "")


def test_the_checksum_covers_the_bytes_actually_served():
    """Non-vacuity: a stream whose content differs by one byte must be rejected."""
    pieces = [b"a" * 16, b"b" * 16]
    tampered = [b"a" * 16, b"b" * 15 + b"c"]
    with pytest.raises(ChecksumMismatch):
        _drain(tampered, _sha(*pieces))


class _Handle:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_the_download_closes_its_handle_on_the_way_out():
    handle = _Handle()
    with BoundedDownload(handle, iter([b"x"]), 1, "n", "text/plain", _sha(b"x")) as download:
        assert list(download.chunks()) == [b"x"]
    assert handle.closed


def test_the_download_closes_its_handle_even_when_the_stream_fails():
    """A failed transfer must not leak the descriptor it was reading from."""
    handle = _Handle()
    with pytest.raises(ChecksumMismatch):
        with BoundedDownload(handle, iter([b"x"]), 1, "n", "text/plain", _sha(b"y")) as download:
            list(download.chunks())
    assert handle.closed


def test_an_unauthenticated_length_says_so():
    """Only the current format's length comes from something that was signed."""
    retained = BoundedDownload(_Handle(), iter([]), 10, "n", "m", None)
    current = BoundedDownload(_Handle(), iter([]), 10, "n", "m", None,
                              length_is_authenticated=True)
    assert retained.length_is_authenticated is False
    assert current.length_is_authenticated is True


def test_verify_now_settles_an_empty_file_before_any_response_exists():
    """A zero-length response cannot be shortened, so its check has to happen earlier.

    `verified_stream` raises for an empty file whose checksum is wrong, but under a streaming
    response that raise lands after the headers: `Content-Length: 0` is already satisfied and the
    client sees a complete success. The caller uses this instead when the response will carry no
    bytes.
    """
    good = BoundedDownload(_Handle(), iter([]), 0, "n", "m", _sha())
    good.verify_now()          # must not raise

    bad = BoundedDownload(_Handle(), iter([]), 0, "n", "m", _sha(b"not empty"))
    with pytest.raises(ChecksumMismatch):
        bad.verify_now()
