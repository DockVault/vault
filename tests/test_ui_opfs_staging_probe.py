"""Can decrypted bytes be staged on disk and handed over only once they are whole?

The design gate for bounded downloads says to prove the sink before building on it, and this is
that proof. Nothing in the application uses it yet.

Why it matters which sink is chosen: the reader hands over records as they authenticate but only
resolves once the final one verifies, so a failure arrives after bytes are already out. Written
straight to a downloads folder those bytes cannot be withdrawn and the user keeps a truncated file
that looks finished. Staged, they are deleted and nothing reaches them. This checks that the
staging half is real — that a worker can write chunk by chunk, that the finished file can be
handed over as a normal download, and that an abort leaves nothing behind.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = [pytest.mark.ui]

PROBE = Path(__file__).resolve().parents[0] / "js" / "opfs_staging_probe.js"

# Large enough that holding it whole would be a different kind of mistake, small enough to stay
# quick: 64 MiB in one-mebibyte chunks.
TOTAL = 64 * 1024 * 1024
CHUNK = 1024 * 1024


def test_a_worker_can_stage_a_file_chunk_by_chunk_and_throw_it_away(page, browser_name) -> None:
    caps = page.evaluate(
        "() => ({secure: window.isSecureContext,"
        " storage: typeof navigator.storage,"
        " opfs: !!(navigator.storage && navigator.storage.getDirectory),"
        " worker: typeof Worker === 'function'})"
    )
    assert caps["secure"], "the page is not a secure context, so this proves nothing about the sink"

    if browser_name == "webkit" and caps["storage"] == "undefined":
        # Not a statement about Safari, and it must not be read as one. This build has no
        # `navigator.storage` AT ALL — not merely no getDirectory — while shipping Safari has had
        # StorageManager for years and, per the support note, the synchronous handle since 15.2.
        # So the automation build differs from the browser materially, and skipping here says
        # "cannot be checked with this tool", not "Safari cannot do it".
        pytest.skip(
            "this WebKit build exposes no navigator.storage at all, so it cannot answer the "
            "question; Safari's own support has to be confirmed on a real device")

    assert caps["opfs"] and caps["worker"], f"this browser cannot stage at all: {caps}"

    page.add_script_tag(path=str(PROBE))
    result = page.evaluate(f"() => window.runProbe({TOTAL}, {CHUNK})")

    assert result["stage"] == "done", f"the probe did not finish: {result}"
    # Written a chunk at a time, and all of it arrived.
    assert result["chunks"] == TOTAL // CHUNK
    assert result["written"] == TOTAL and result["size"] == TOTAL, result
    # In order: the first chunk is filled with 0, the last with its own index.
    assert result["head"] == [0, 0, 0, 0], result
    assert result["tail"] == [result["chunks"] - 1] * 4, result
    # Handed over as a normal download.
    assert result["downloadable"], result
    # And the half that decides the sink: an abort leaves nothing.
    assert result["deleted"], "the staged file survived deletion"
    # Not "the counter reads zero". Engines disagree about that: one returns to 0, another keeps
    # its own filesystem bookkeeping and reported ~480 kB with the staged file demonstrably gone.
    # The question that matters is whether the STAGED BYTES went, so the assertion is about how
    # much was reclaimed, with room for an engine's own overhead.
    left_behind = result["usageAfterDelete"] - result["usageBefore"]
    assert left_behind < TOTAL // 10, (
        f"deleting the staged file reclaimed too little: {left_behind} bytes still attributed "
        f"after staging {TOTAL}. An abort that leaves the bytes behind is not an abort")
