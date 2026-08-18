"""Where a resumed download restarts.

The number under test goes straight into a `Range` header, so getting it wrong does not fail
loudly. An offset one byte inside a record fetches bytes that decrypt into garbage, every record
after it fails authentication, and the client reports a corrupt file — being wrong about why. So
the harness checks the offset against the real framing of a real encryption, at every record
boundary in the object rather than at a representative one.

It also refuses rather than clamps. A caller that has lost count must start over: handing it a
plausible offset produces exactly the silent damage above.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "zk_content_v2_resume_offset.js"


@pytest.fixture(scope="module")
def resumed() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=180,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_every_boundary_in_every_shape_lands_where_a_record_starts(resumed: str) -> None:
    """Five objects, chosen so the final record is full in one case and a remainder in others.

    The last record is the only one whose stored size differs, so an arithmetic that treats every
    record alike is right about all of them but the one that ends the file.
    """
    for shape in ("12288B/4096", "12289B/4096", "12287B/4096", "10B/4096", "70000B/8192"):
        assert f"ok   {shape}: all " in resumed, f"{shape} did not walk cleanly:\n{resumed}"
        assert f"ok   {shape}: nothing kept yet resumes just past the header" in resumed, resumed
        assert f"ok   {shape}: every record kept means done" in resumed, resumed


def test_an_impossible_count_is_refused_rather_than_clamped(resumed: str) -> None:
    """Including the shapes that are not integers at all.

    `NaN` matters most: it compares false against every bound, so a guard written as a pair of
    comparisons lets it through and then produces `NaN` as an offset.
    """
    for bad in ("-1", "99", "1.5", "NaN", "2", "null", "undefined"):
        assert f"ok   a record count of {bad} is refused" in resumed, resumed


def test_the_header_still_has_to_be_a_header(resumed: str) -> None:
    """A client that kept the wrong bytes is told here, not by a failure three records later."""
    assert "ok   a header of zeroes is refused" in resumed, resumed
    assert "resume offsets land on record boundaries" in resumed, resumed
