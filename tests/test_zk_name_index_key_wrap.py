"""The name-index-key wrap (purpose 0x05), run in Node against the shipped ecc_crypto.js.

This is the crypto foundation for storing name indices under a per-vault key that a rekey does not
rotate: the key is wrapped to each member like the DEK. The properties that matter are that it
round-trips and that it CANNOT be confused with a DEK wrap in either direction -- the transposition
between the two key types the distinct purpose byte exists to prevent. A round-trip-only test would
pass with the purpose byte removed, so the harness asserts both rejections explicitly.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "name_index_key_wrap.js"


@pytest.fixture(scope="module")
def out() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser-crypto side of this must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_round_trips(out: str) -> None:
    assert "ok   round-trips to the same 32-byte key" in out, out
    assert "ok   wrap is 68 bytes (got 68)" in out, out


def test_cannot_be_swapped_with_a_dek_wrap(out: str) -> None:
    """The load-bearing property: the two key types are not interchangeable, in either direction."""
    assert "ok   a DEK wrap (0x01) is rejected by the index-key unwrap" in out, out
    assert "ok   an index-key wrap (0x05) is rejected by the DEK unwrap" in out, out


def test_bound_to_the_recipient_and_the_vault(out: str) -> None:
    assert "ok   a stranger's private key cannot unwrap" in out, out
    assert "ok   the wrong vault id fails (the transcript binds it)" in out, out


def test_structural_checks_before_key_work(out: str) -> None:
    assert "ok   a wrong length is rejected" in out, out
    assert "ok   a non-zero reserved byte is rejected" in out, out
