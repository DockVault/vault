"""Reading a version-2 file without holding it, and refusing to finish when it is damaged.

The buffered reader hands back nothing until the chunk marked final authenticates, because
releasing records as they verify means handing over output of attacker-chosen length. A streaming
reader cannot keep that property on its own — by definition it emits as it goes — so it keeps the
half that it can: it never reports success on a damaged file, and it locates the damage.

Which puts a requirement on the caller rather than on the reader. Bytes already written when the
final record fails must be somewhere the caller can still discard. The harness measures that
directly: a bit flipped in the last record of a three-chunk file is refused *after 8192 bytes have
reached the sink*. Written to a staging file that is deleted, nothing is lost; written straight to
a downloads folder, the user keeps a truncated file that looks finished.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "zk_content_v2_stream_read.js"


@pytest.fixture(scope="module")
def streamed() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this format must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=180,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_it_agrees_with_the_buffered_reader(streamed: str) -> None:
    """Across every shape the framing treats differently.

    A streaming reader that disagrees with the buffered one is a second reader wearing the same
    name, and the disagreement would surface as a file that opens on one path and is called
    damaged on the other.
    """
    for case in ("empty", "short of one chunk", "exactly one chunk",
                 "exactly two chunks", "partial tail"):
        assert f"ok   {case}" in streamed, f"{case} did not match:\n{streamed}"
    assert "matches the buffered reader" in streamed


def test_nothing_larger_than_a_frame_reaches_the_sink(streamed: str) -> None:
    """The point of the exercise. If a whole file could arrive in one call, this would be the
    buffered reader with extra steps."""
    assert "ok   no chunk above" in streamed, streamed


def test_damage_never_reports_success(streamed: str) -> None:
    """Four kinds, because they fail at different places.

    A truncated file and a relabelled header fail on the framing before any record is read; a
    flipped bit in the first record fails immediately; a flipped bit in the LAST record fails only
    after everything before it has already been written, which is the case that decides where the
    caller must put those bytes.
    """
    for case in ("a truncated file", "a flipped bit in the final record",
                 "a flipped bit in the first record", "a relabelled header"):
        assert f"ok   {case}: refused" in streamed, f"{case} was not refused:\n{streamed}"
    assert "damage never resolves" in streamed


def test_the_last_record_fails_only_after_earlier_bytes_were_written(streamed: str) -> None:
    """Non-vacuity for the requirement this places on the caller.

    If that case happened to write nothing, the harness would pass while proving nothing about
    the discardable-staging requirement — so the number of bytes written before the refusal has
    to be greater than zero.
    """
    line = next(l for l in streamed.splitlines()
                if l.startswith("ok   a flipped bit in the final record"))
    written = int(line.split("after writing ")[1].split(" byte")[0])
    assert written > 0, (
        "the final-record failure wrote nothing, so this run does not demonstrate that a caller "
        f"can be left holding partial output: {line}")


def test_the_older_format_is_refused_rather_than_misread(streamed: str) -> None:
    """Why the caller has to look at the header before choosing a reader.

    The two formats are not interchangeable and the older one cannot be streamed at all — its tag
    covers the whole file, so nothing can be released until everything has arrived. Handing one to
    the chunked reader must therefore fail, and the same bytes must still read correctly through
    the reader meant for them, so the refusal is about the wrong reader rather than a damaged file.
    """
    assert "ok   a legacy whole-file blob is refused" in streamed, streamed
    assert "ok   the same legacy blob reads back through the buffered reader" in streamed, streamed
