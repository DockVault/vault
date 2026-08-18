"""The sliced content writer must emit exactly what the buffered one emits.

Reading a file whole to encrypt it puts the plaintext in the tab's heap, the sealed copy joins it,
and the peak lands near three times the file. Encrypting from slices holds one chunk at a time
instead -- but only if the bytes it produces are the same bytes, because a writer that frames
differently produces files that only it can open, and nothing at runtime says so until somebody
downloads one somewhere else.

The comparison runs under Node's WebCrypto against the shipped module, with entropy stubbed so
both writers see identical values. Node is required rather than skipped, for the same reason the
sibling writer harness requires it: this is the browser half of a stored format, and a green run
that quietly skipped it would be worse than no run.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "zk_content_v2_slice_parity.js"


@pytest.fixture(scope="module")
def parity() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this format must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_every_framing_edge_is_byte_identical(parity: str) -> None:
    """Empty, short of a chunk, exactly one, exactly two, and a partial tail.

    Those are the shapes the grammar treats differently: the empty file is one empty chunk rather
    than none, an exact multiple must not grow a trailing empty chunk, and only the last chunk
    carries the final marker. A writer can be right about the middle of a file and wrong about
    every one of these.
    """
    assert "every case byte-identical to the buffered writer" in parity, parity
    for case in ("empty", "short of one chunk", "exactly one chunk",
                 "exactly two chunks", "partial tail"):
        assert f"ok   {case}" in parity, f"{case} was not reported identical:\n{parity}"


def test_the_comparison_covers_more_than_one_chunk(parity: str) -> None:
    """Non-vacuity.

    A parity harness whose every case fitted in one chunk would prove nothing about framing --
    one chunk is the case where a slicing writer and a buffered one cannot disagree. At least one
    case has to have drawn several nonces.
    """
    multi = [line for line in parity.splitlines()
             if line.startswith("ok   ") and "1 nonce(s)" not in line]
    assert multi, f"every case fitted in a single chunk:\n{parity}"


def test_the_sliced_output_reads_back(parity: str) -> None:
    """Identical is not the same as correct: two writers can be identically wrong.

    Each case also decrypts its sliced output and compares it to the input, so the comparison is
    anchored to the plaintext rather than only to the other writer.
    """
    ok_lines = [line for line in parity.splitlines() if line.startswith("ok   ")]
    assert len(ok_lines) >= 5, parity
    for line in ok_lines:
        assert "decrypts back" in line, line
