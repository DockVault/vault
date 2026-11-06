"""How many transfers this browser runs at once.

The server cap protects the deployment. This is a different cap for a different victim: the page
starts every queued item the moment it is queued, so dropping twenty files on it opened twenty
concurrent uploads in one tab. The deployment refuses the excess and is fine; the browser has
already paid for twenty encryptions and twenty sets of buffers.

The failure worth testing is not "too many ran" — that is loud. It is **a slot never given back**,
which wedges the queue after exactly `limit` failures, and whose symptom is uploads that never
start with no error anywhere. That case is bounded rather than awaited: a leaked slot would
otherwise make the harness hang, and a hang is an absence of an answer rather than a red test.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "transfer_gate.js"


@pytest.fixture(scope="module")
def gated() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_a_queue_of_twenty_runs_five_at_a_time_and_all_complete(gated: str) -> None:
    """Peak concurrency is watched throughout, not sampled — a sample can miss the peak."""
    assert "ok   twenty tasks peak at five at once (peak was 5)" in gated, gated
    assert "ok   all twenty complete (20)" in gated, gated
    assert "ok   the gate is empty afterwards" in gated, gated


def test_the_cap_is_not_bypassed_by_mixing_uploads_and_downloads(gated: str) -> None:
    """One gate, not one per kind. Two gates of five would be a cap of ten."""
    assert "ok   mixed uploads and downloads still peak at five" in gated, gated


def test_a_failed_transfer_does_not_cost_a_slot(gated: str) -> None:
    """Five failures against a limit of five is the exact case that wedges a leaking gate.

    Checked with a bound, so a leak reports "never started" instead of hanging the run.
    """
    assert "ok   a sixth task still runs after five failures" in gated, gated
    assert "ok   the gate is empty after failures" in gated, gated


def test_waiters_are_served_in_order(gated: str) -> None:
    """So a dropped batch finishes roughly in the order it was dropped, rather than in whatever
    order the event loop happens to wake things."""
    assert "ok   waiters are served in order (1,2,3,4)" in gated, gated


def test_a_stray_release_cannot_widen_the_gate(gated: str) -> None:
    """Releasing more than was acquired must not raise the limit for everybody else."""
    assert "ok   stray releases do not widen the gate (peak was 2)" in gated, gated


def test_a_reset_frees_every_slot_and_drops_what_was_queued(gated: str) -> None:
    """A sign-out resets the page's gate. Of what the person who signed out had running, some never ends (a
    transfer waiting for their account key never settles once they have gone): without the reset, five of them
    would leave the next person on the tab a gate in which nothing starts. What does end gives nothing back to the
    new gate, so the next person's five are never joined by a sixth, and what was queued never starts (it would run
    with the next person's session)."""
    for line in (
        "ok   the first person's five run and three wait (active 5, waiting 3)",
        "ok   a reset frees every slot (active 0, waiting 0)",
        "ok   the next person's five start at once after a reset (5, waiting 1)",
        "ok   transfers from before a reset that end give nothing back (active 5, started 5)",
        "ok   the next person's sixth runs once a slot is theirs (peak 5)",
        "ok   what was queued before a reset never starts (0)",
        "ok   the gate empties afterwards (active 0, waiting 0)",
    ):
        assert line in gated, gated


def test_a_slot_handed_over_before_a_reset_is_not_given_back_after_it(gated: str) -> None:
    """A slot passed to a waiter just before a reset is the old gate's: its release after the reset is ignored."""
    assert ("ok   a slot handed over before a reset is not given back to the gate after it (active 1, waiting 1)"
            in gated), gated
    assert "ok   the next caller of the gate after a reset is served when its slot is given back" in gated, gated


def test_a_nonsense_limit_is_refused(gated: str) -> None:
    for bad in ("0", "-1", "1.5", "NaN", "5", "null"):
        assert f"ok   a limit of {bad} is refused" in gated, gated
    assert "ok   a limit of undefined is the default" in gated, gated
