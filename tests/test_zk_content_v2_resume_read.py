"""Resuming a download, at every place it could have been interrupted.

A resumed read is sound only because each record authenticates on its own and its AAD is bound to
the record *index* — so record k verifies without records 0..k-1 ever being seen. If that stopped
being true, resuming would still appear to work at the first boundary and fail at every other one,
which is why the harness walks all of them rather than picking a representative.

Two properties are worth more than the round-trip itself. A resumed read must still refuse a body
short of the declared length, because the final record is where the size is bound. And another
object's header must not open this one, even when offered at a valid boundary.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "zk_content_v2_resume_read.js"


@pytest.fixture(scope="module")
def resumed() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=240,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_resuming_at_any_boundary_yields_the_remaining_bytes(resumed: str) -> None:
    """Three shapes, so the final record is full in one and a remainder in the others."""
    for shape in ("16384B", "16401B", "4095B"):
        assert f"ok   {shape}: resuming at each of" in resumed, (
            f"{shape} did not resume cleanly at every boundary:\n{resumed}")


def test_the_kept_head_and_the_resumed_tail_reassemble(resumed: str) -> None:
    """What the caller actually does with the two halves, rather than each half in isolation.

    Both can be individually correct while the join is off by a record.
    """
    for shape in ("16384B", "16401B"):
        assert f"ok   {shape}: the kept head and the resumed tail reassemble" in resumed, resumed


def test_a_resumed_read_refuses_what_a_whole_read_refuses(resumed: str) -> None:
    """Checked by error CODE, not by "something threw".

    That distinction is load-bearing: with a looser assertion, deleting the guard that requires the
    kept header left the header undefined, the framing raised a TypeError, and the test called it a
    pass. It was mutation testing that surfaced it, and the codes are what closed it.
    """
    assert "ok   a start beyond the last record is refused" in resumed, resumed
    assert "ok   resuming without the kept header is refused" in resumed, resumed
    assert "ok   another object's header does not open this one" in resumed, resumed
    assert "ok   a resumed read still refuses a body short of the declared length" in resumed, resumed
    assert "refuses what a whole read would refuse" in resumed
