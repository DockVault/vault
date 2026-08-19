"""The client's per-epoch candidate derivation, run in Node against the shipped ecc_crypto.js.

`nameBlindIndexCandidates` is what a client will send so the server can match a same-name upload
against every epoch a pre-rotation file might be sealed under. The properties that matter are that
each candidate equals the single-value index at its epoch (so a stored row's own value is always in
the set the server checks), that the set covers all epochs and not just the adjacent one, that it
fails closed on an empty input (an empty set would make every clash check pass "no clash" and
reopen the defect), and that it collapses duplicates. The Node harness asserts each and exits
non-zero on any failure; this pins those assertions from the suite.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "name_index_candidates.js"


@pytest.fixture(scope="module")
def out() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser-crypto side of this must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_candidates_are_the_per_epoch_single_value_indices(out: str) -> None:
    assert "ok   two epochs -> two candidates (got 2)" in out, out
    assert "ok   candidates are exactly the per-epoch single-value indices" in out, out
    assert "ok   the two epochs really do differ (there is something to fix)" in out, out


def test_the_set_covers_every_epoch_not_only_the_adjacent_one(out: str) -> None:
    assert "ok   a three-epoch vault covers the oldest epoch, not only the adjacent one" in out, out


def test_the_common_never_rotated_vault_costs_one_candidate(out: str) -> None:
    assert "ok   a never-rotated vault yields one candidate" in out, out


def test_duplicates_collapse(out: str) -> None:
    assert "ok   a duplicated epoch collapses (got 1)" in out, out


def test_candidates_are_keyed_by_the_name(out: str) -> None:
    assert "ok   different names give disjoint candidates" in out, out


def test_empty_or_malformed_input_fails_closed(out: str) -> None:
    """An empty candidate list would make the server's same-name check pass 'no clash' every time,
    reopening the exact bug this closes — so it is refused, not silently returned empty."""
    assert 'ok   empty/absent epochDeks is refused (null)' in out, out
    assert 'ok   empty/absent epochDeks is refused (undefined)' in out, out
    assert 'ok   empty/absent epochDeks is refused ([])' in out, out
    assert "ok   a null dek in an entry is refused, not skipped" in out, out
