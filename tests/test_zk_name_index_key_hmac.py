"""The rotation-independent name index (HMAC under the per-vault index key), run in Node.

`nameIndexKeyBlindIndex` is what a later phase stores so same-name matching survives a rekey. Its
determinism and name/vault/key binding are the ordinary properties; the load-bearing one is that it
is a DISTINCT domain from the DEK-derived index, because during migration both are matched against
at once and a cross-domain collision would be a false same-name hit. The harness asserts that
directly, including the extreme case where the key bytes coincide.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "name_index_key_hmac.js"


@pytest.fixture(scope="module")
def out() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser-crypto side of this must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    return done.stdout


def test_deterministic_and_sized(out: str) -> None:
    assert "ok   deterministic: same key, vault and name give the same index" in out, out
    assert "ok   a 64-hex-char (256-bit) digest" in out, out


def test_bound_to_name_vault_and_key(out: str) -> None:
    assert "ok   a different name differs" in out, out
    assert "ok   a different vault differs" in out, out
    assert "ok   a different index key differs" in out, out


def test_distinct_domain_from_the_dek_index(out: str) -> None:
    """The property that keeps dual-read matching correct: no cross-domain collision, even when the
    key bytes coincide."""
    assert "ok   the K_index index is a distinct domain from the DEK-derived index" in out, out
    assert "ok   distinct even when the key bytes coincide (the salt separates them)" in out, out
