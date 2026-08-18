"""A dropped connection and a bad file must not look alike.

This exists because they did, and the consequence was not a wrong error message. The reader funnels
every failure through one catch that gives it a crypto code, so a connection reset arrived as
`CONTENT_AUTH_FAILED` — indistinguishable from "these bytes do not authenticate".

A caller deciding whether to resume needs exactly the opposite: retry a dropped body, never retry a
failed authentication, because re-requesting the same range returns the same bytes and fails the
same way. With the two collapsed, the condition gating an entire resume loop could never be true.
The loop was unreachable, and a transient drop aborted a download that had already written bytes —
leaving the user a partial file where the older path would simply have failed with none.

Found by adversarial review, not by this suite, which is why the harness now pins it.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "zk_content_v2_transport_vs_content.js"


@pytest.fixture(scope="module")
def classified() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=180,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_a_failed_body_reports_as_transport(classified: str) -> None:
    """The case the resume loop exists for. Without this it is dead code."""
    assert "ok   a body that fails mid-read reports as transport" in classified, classified


def test_damage_reports_as_content(classified: str) -> None:
    """Both the tampered-bytes and wrong-key cases, since either being resumable would spin."""
    assert "ok   damaged content reports as content/CONTENT_AUTH_FAILED" in classified, classified
    assert "ok   the wrong key reports as content" in classified, classified


def test_a_clean_truncation_stays_content(classified: str) -> None:
    """A body that stops early and cleanly is a short object, not a dropped connection. Resuming
    it would ask the server for bytes it has already said are not there."""
    assert "ok   a cleanly truncated body stays content" in classified, classified


def test_the_two_are_told_apart_by_the_test_a_caller_makes(classified: str) -> None:
    """Asserted as its own case on purpose.

    Each of the checks above can pass while both kinds still classify identically — which is
    precisely the state that shipped. Only comparing them catches that.
    """
    assert "ok   a dropped body and damaged content are told apart" in classified, classified
    assert "a dropped connection and a bad file are distinguishable" in classified


def test_where_a_wrong_declared_length_is_caught(classified: str) -> None:
    """Not at the first record, which is what the docstring used to claim.

    The totals bind into the FINAL record's AAD only, so a length short by exactly one record's
    worth is a valid alternate framing: earlier records authenticate and are handed to the caller,
    and the read fails at the record the reader believes is final. Measured here at two of four
    handed over before the refusal.

    That is why the contract requires `write` to put bytes somewhere the caller can still discard.
    A consumer that releases eagerly — into a download the browser owns, say — publishes a genuine
    prefix of the object before being told anything is wrong. The claim went unchallenged because
    the docstring asserted the opposite and nothing tested it.
    """
    assert "ok   a length short by one record is refused, not accepted" in classified, classified
    assert "ok   records are handed over BEFORE the refusal" in classified, classified
