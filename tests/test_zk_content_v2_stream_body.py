"""Reading version-2 content straight from a byte stream, and what its length claim is worth.

A stream does not carry its own size, so the framing has to come from what the transfer declares —
in practice a Content-Length the server asserts. That looks like trusting the server, and it is
not: the chunk count and plaintext total are derived from the length and authenticated, so a wrong
one cannot yield a short file.

Where it is caught is the part worth knowing, and it is not where it was first assumed. The totals
are bound into the FINAL record only — deliberately, since binding them into every record would
force a writer to know the length before writing anything and foreclose a streaming producer. So a
length one byte short is refused only after everything before the last record has been written.
The file is still never accepted; the caller is simply left holding bytes it must discard, which is
the same obligation the Blob reader imposes.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "zk_content_v2_stream_body.js"


@pytest.fixture(scope="module")
def body() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this format must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=240,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_delivery_boundaries_do_not_have_to_match_record_boundaries(body: str) -> None:
    """A reader that only works when the producer chunks conveniently works only in tests.

    Four delivery sizes, chosen to disagree with the record size in different ways: far smaller,
    not a divisor, one byte over a record, and far larger.
    """
    for piece in ("7-byte", "1000-byte", "4124-byte", "65536-byte"):
        got = [line for line in body.splitlines()
               if line.startswith("ok   ") and piece in line]
        assert got, f"no case was delivered in {piece} pieces:\n{body}"
    assert "matches the buffered reader" in body


def test_a_wrong_declared_length_stops_the_read(body: str) -> None:
    """Four ways to be wrong, because they fail differently.

    One byte short and one byte long change the final record's size; a whole record short changes
    the count; halving it changes both.
    """
    for case in ("a length one byte short", "a length one byte long",
                 "a length a whole record short", "a length that halves the file"):
        assert f"ok   {case} stopped the read" in body, f"{case} did not stop the read:\n{body}"


def test_a_body_that_disagrees_with_its_length_is_refused(body: str) -> None:
    """Both directions, and both ways the surplus can be found.

    When delivery pieces straddle the declared end, the read that completes the last record
    over-reads and the surplus is already in hand. When they align with it, nothing is over-read
    and the surplus can only be found by draining afterwards. Those are separate branches, and a
    test that hit one would leave the other unproven.
    """
    assert "ok   a body that ends early is refused" in body, body
    assert "ok   a body longer than its declared length is refused" in body, body
    assert "ok   trailing bytes arriving after the declared end are refused" in body, body


def test_the_refusal_arrives_after_bytes_were_written(body: str) -> None:
    """The correction that matters, pinned so it cannot quietly become untrue either way.

    If the totals were ever bound into every record, this would start failing at zero bytes — a
    stronger property, and one that would foreclose a streaming writer. Either way the number is
    worth knowing, because it is what obliges the caller to stage what it writes.
    """
    line = next(l for l in body.splitlines()
                if l.startswith("ok   a length one byte short stopped the read"))
    written = int(re.search(r"after (\d+) byte", line).group(1))
    assert written > 0, (
        "a wrong length was caught before anything was written. That is a stronger guarantee than "
        f"this reader claims — check whether the totals moved into every record: {line}")
