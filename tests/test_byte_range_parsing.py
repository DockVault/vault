"""Resolving a `Range` header against a known length.

Range parsing is where a download endpoint gets an off-by-one, and the wire format invites it:
`Content-Range` is inclusive at both ends while every Python slice is not. These pin the boundary
values on both sides of each rule rather than one comfortable example per branch.

The distinction that matters most here is between "serve everything" and "cannot be served". Both
are refusals to honour the request as written, they arrive as different objects, and they must
become different status codes -- 200 and 416. Collapsing them would turn a client's explicit
"only these bytes" into a silent full download.
"""
import importlib.util
import pathlib

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "download_stream_under_test",
    pathlib.Path(__file__).resolve().parents[1] / "app" / "services" / "download_stream.py",
)
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

parse_byte_range = _MODULE.parse_byte_range
ByteRange = _MODULE.ByteRange
UNSATISFIABLE = _MODULE.UNSATISFIABLE

TOTAL = 1000


@pytest.mark.unit
@pytest.mark.parametrize("header,expected", [
    ("bytes=0-499", ByteRange(0, 499, TOTAL)),
    ("bytes=500-999", ByteRange(500, 999, TOTAL)),
    ("bytes=0-0", ByteRange(0, 0, TOTAL)),                      # exactly one byte
    ("bytes=999-999", ByteRange(999, 999, TOTAL)),              # the last byte
    ("bytes=500-", ByteRange(500, 999, TOTAL)),                 # open-ended
    ("bytes=0-", ByteRange(0, 999, TOTAL)),                     # the whole thing, as a range
    ("bytes=999-", ByteRange(999, 999, TOTAL)),                 # open-ended at the last byte
    ("bytes=-1", ByteRange(999, 999, TOTAL)),                   # suffix: the final byte
    ("bytes=-500", ByteRange(500, 999, TOTAL)),                 # suffix: the final 500
    ("bytes=-1000", ByteRange(0, 999, TOTAL)),                  # suffix of exactly the length
    ("bytes=-99999", ByteRange(0, 999, TOTAL)),                 # suffix past the start, clamped
    ("bytes=0-99999", ByteRange(0, 999, TOTAL)),                # end past the end, clamped
    ("  bytes=0-499  ", ByteRange(0, 499, TOTAL)),              # surrounding whitespace
    ("BYTES=0-499", ByteRange(0, 499, TOTAL)),                  # the unit is case-insensitive
])
def test_a_satisfiable_range_resolves_to_inclusive_bounds(header, expected):
    assert parse_byte_range(header, TOTAL) == expected


@pytest.mark.unit
@pytest.mark.parametrize("header", [
    None, "", "   ",
    "0-499",                    # no unit
    "bytes",                    # no "="
    "bytes=",                   # no spec
    "bytes=abc-def",            # not numbers
    "bytes=1.5-2",              # not integers
    "bytes=-",                  # neither side given
    "bytes=--5",
    "bytes=499-0",              # last before first
    "items=0-499",              # a unit that is not bytes
    "bytes=0-499,600-700",      # multiple ranges: multipart, deliberately unsupported
    "bytes=-abc",               # a suffix that is not a number
    "bytes=+5-10",              # isdigit() rejects the sign, which is the intent
    # Characters str.isdigit() accepts and int() refuses. Pairing the two raised ValueError out
    # of a function whose contract is to ignore what it cannot parse -- which on the download
    # path became a 500 and an audit row reading "Download failed", for a header a client is
    # entitled to send badly. Found by review, not by the cases above, because every case above
    # was written by the same person who wrote the guard.
    "bytes=²-5",           # superscript two
    "bytes=0-²",
    "bytes=-²",
    "bytes=½-1",           # vulgar fraction one half
    "bytes=٥-9",           # arabic-indic five: a digit int() DOES accept, but not ASCII
])
def test_anything_unparseable_says_serve_the_whole_thing(header):
    # None, not an exception and not UNSATISFIABLE. RFC 7233 requires a recipient that cannot
    # understand a Range header to ignore it; refusing would leave a client that sends a header
    # this does not parse unable to download at all.
    assert parse_byte_range(header, TOTAL) is None


@pytest.mark.unit
@pytest.mark.parametrize("header,total", [
    ("bytes=1000-", 1000),      # starts exactly at the end
    ("bytes=1000-2000", 1000),
    ("bytes=5000-", 1000),
    ("bytes=-0", 1000),         # "the last zero bytes" is not an empty success
    ("bytes=0-", 0),            # nothing can satisfy a range over an empty representation
    ("bytes=-1", 0),
    ("bytes=0-0", 0),
])
def test_a_range_that_cannot_be_served_is_not_the_same_as_no_range(header, total):
    assert parse_byte_range(header, total) is UNSATISFIABLE


@pytest.mark.unit
def test_the_two_refusals_are_distinguishable():
    """The whole point of returning two different things, stated as its own check.

    A caller that tests truthiness, or that writes `or None`, collapses these into one and turns
    a 416 into a 200 carrying the entire file. Both are falsy-adjacent enough to invite it.
    """
    ignored = parse_byte_range("garbage", TOTAL)
    refused = parse_byte_range("bytes=99999-", TOTAL)
    assert ignored is None
    assert refused is UNSATISFIABLE
    assert ignored is not refused


@pytest.mark.unit
def test_length_and_content_range_agree_with_the_bounds():
    r = parse_byte_range("bytes=0-499", TOTAL)
    assert r.length == 500, "inclusive bounds mean 0-499 is 500 bytes, not 499"
    assert r.content_range() == "bytes 0-499/1000"

    single = parse_byte_range("bytes=7-7", TOTAL)
    assert single.length == 1
    assert single.content_range() == "bytes 7-7/1000"

    tail = parse_byte_range("bytes=-1", TOTAL)
    assert tail.length == 1
    assert tail.content_range() == "bytes 999-999/1000"


@pytest.mark.unit
def test_every_satisfiable_range_stays_inside_the_representation():
    """A property check over the whole space, because "cannot read outside the object" is the
    security-relevant claim and a table of examples does not establish it."""
    for total in (1, 2, 7, 64, 1000):
        for start in range(-2, total + 3):
            for end in range(-2, total + 3):
                for header in (f"bytes={start}-{end}", f"bytes={start}-", f"bytes=-{end}"):
                    got = parse_byte_range(header, total)
                    if not isinstance(got, ByteRange):
                        continue
                    assert 0 <= got.start <= got.last < total, (
                        f"{header!r} against {total} produced {got}, which names bytes "
                        f"outside the representation")
                    assert got.length == got.last - got.start + 1
                    assert got.total == total
