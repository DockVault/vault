"""What the sliced content writer refuses, and whether its failures are visible.

The parity harness next to this one compares the two writers, which is a differential test: it
cannot see a defect in code they share. Hoist the nonce out of the shared loop and both writers
reuse it identically, so parity stays green — the pinned vectors catch that, through the buffered
writer. This file covers what the sliced writer does NOT share: its own input guard, and its
registration with the module's error boundary.

Both were wrong when first written. The guard accepted a Blob reporting a size of NaN, which is
the one value that makes the chunk count NaN so the loop never runs — producing a header-only file
that uploads happily, returns a valid id, and can never be opened. And the writer was missing from
the boundary table, so its failures reached no diagnostic; the repository already had a test for
that exact omission on the previous construction, which is how it was noticed here.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "zk_content_v2_slice_guards.js"


@pytest.fixture(scope="module")
def guards() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this format must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=180,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_it_refuses_everything_that_is_not_a_blob(guards: str) -> None:
    for case in ("a Uint8Array", "an ArrayBuffer", "a DataView", "a string", "null"):
        assert f"ok   {case}: refused" in guards, f"{case} was not refused:\n{guards}"


def test_it_refuses_a_blob_that_lies_about_its_size(guards: str) -> None:
    """NaN is the one that matters, and it is a real Blob subclass rather than a duck.

    A size of NaN makes the chunk count NaN, the loop never runs, and the length check that
    refuses every other bad size sits inside that loop. Fractional and negative sizes are refused
    by the same test and are included so the guard cannot be narrowed to NaN alone.
    """
    for case in ("a Blob whose size is NaN", "a Blob with a fractional size",
                 "a Blob with a negative size"):
        assert f"ok   {case}: refused" in guards, f"{case} was not refused:\n{guards}"


def test_its_failures_reach_the_diagnostic(guards: str) -> None:
    assert "ok   registered with the error boundary" in guards, guards


def test_the_shipped_call_shape_is_exercised(guards: str) -> None:
    """Production passes no options, so the default chunk size is the only one it ever uses.

    Every other test of this writer names a small chunk size to stay quick, which means the
    configuration that actually ships would otherwise go untested.
    """
    assert "ok   default chunk size round-trips" in guards, guards
