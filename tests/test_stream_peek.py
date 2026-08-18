"""Looking at a stream's first bytes without spending them.

Choosing a reader means reading the header, and reading a stream consumes it — so a caller that
peeks the obvious way has nothing left to give the reader it just chose, and a caller that avoids
peeking has to buffer the whole body to learn what it is.

The failure mode is silent and total. A replay that drops the bytes it looked at hands the reader a
file starting mid-header; one that emits them twice hands it a duplicated prefix. Both surface as
the file being damaged rather than as a bug in the plumbing, so the harness compares the replayed
bytes against the original in full rather than comparing lengths.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "stream_peek.js"


@pytest.fixture(scope="module")
def peeked() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=180,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_the_replay_is_the_whole_body_at_every_delivery_size(peeked: str) -> None:
    """Seven delivery sizes, putting the peek boundary in a different place each time.

    One byte at a time, exactly on the boundary, either side of it, and the whole body in a single
    piece. A replay can be correct for one of those and wrong for the rest.
    """
    for piece in (1, 3, 7, 8, 9, 1000, 5000):
        assert f"ok   pieces of {piece}:" in peeked, f"delivery in {piece}-byte pieces failed:\n{peeked}"
    assert "the stream is still whole" in peeked


def test_a_body_shorter_than_the_peek(peeked: str) -> None:
    """Short rather than padded — which is the answer for anything too small to hold a header."""
    assert "ok   a 3-byte body peeked for 8" in peeked, peeked
    assert "ok   an empty body peeks to nothing" in peeked, peeked


def test_a_peeked_stream_still_feeds_the_reader(peeked: str) -> None:
    """The point of the exercise, end to end: peek, recognise the format, decrypt the same stream.

    Everything above could pass while the replayed stream was subtly unusable by a real reader.
    """
    assert "ok   a peeked stream is recognised as UNSUPPORTED and still decrypts" in peeked, peeked
