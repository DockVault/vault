"""What a member's browser concludes about the zero-knowledge key it holds (static/js/zk_key_checks.js).

The key check on the write path is the one check in the web app that stops anything: a member whose key
does not reproduce the epoch's stored check -- or, in a team vault, whose team key is not the vault's --
cannot upload, rename or create anything under it, and the owner is told. A false positive would stop an
honest member from working, so the cases that must never block are pinned here as carefully as the one
that must: an epoch made while the server was rolled back, an answer from an older server, a row with no
check, a team vault after its team key changed, an older team epoch, an owner's reset. The lineage states
are pinned too. Everything runs on real keys, with the shipped crypto module, under Node
(tests/js/zk_key_checks.js).
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "js" / "zk_key_checks.js"


@pytest.fixture(scope="module")
def run() -> str:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this must not be skipped"
    done = subprocess.run([node, str(HARNESS)], cwd=ROOT, capture_output=True, text=True, timeout=180)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.rstrip().endswith("ALL OK"), done.stdout
    return done.stdout


def _ok(out: str, line: str) -> None:
    assert f"ok   {line}\n" in out, f"not reported as passing: {line}\n{out}"


def test_a_key_that_is_not_the_vaults_is_refused_on_the_write_path(run):
    _ok(run, "direct: the key that made the check writes")
    _ok(run, "direct: a planted wrong key is refused, as a dek_check finding")
    _ok(run, "direct: the right key checked at another epoch does not pass")
    _ok(run, "team: a current team key that is not the vault's is refused, as a team_key finding")


@pytest.mark.parametrize("case", [
    "direct: an epoch rotated while rolled back (no row) never blocks",
    "direct: an older server (no key_proof) never blocks",
    "direct: a row without a key check never blocks",
    "direct: after an owner's reset the new key writes",
    "team: after a team rotation the new key writes",
    "team: an older team epoch is never checked against the current public key",
    "team: an uncompared key never blocks",
])
def test_what_must_never_block_an_honest_member(run, case):
    _ok(run, case)


def test_the_team_key_is_compared_while_it_is_unwrapped_in_both_wrap_formats(run):
    for fmt in ("v2", "legacy"):
        _ok(run, f"{fmt}: the team key unwrapped is the vault's team key")
        _ok(run, f"{fmt}: the checked key is derive-only and non-extractable")
        _ok(run, f"{fmt}: a team key that is not the vault's is told apart")
        _ok(run, f"{fmt}: the unchecked unwrap still returns the key itself")
    _ok(run, "a checked unwrap without the public key to check is refused")


@pytest.mark.parametrize("case", [
    "lineage: a rotation by a holder of the previous key",
    "lineage: a tag made with another key fails",
    "lineage: a tag over other material fails",
    "lineage: a rotation that should carry a tag and does not fails",
    "lineage: an owner's reset without the previous key is told as a reset",
    "lineage: an owner's reset with the previous key verifies",
    "lineage: an epoch set up afterwards has nothing to verify",
    "lineage: an epoch rotated while rolled back is not verifiable",
    "lineage: an older server is not verifiable",
    "lineage: a member who never held the previous key cannot verify",
    "lineage: a later epoch claiming to be the first fails",
    "lineage: the first epoch has no previous key",
    "team lineage: a team rotation by a holder verifies",
    "team lineage: a substituted team DEK wrap fails",
    "team lineage: a substituted team key fails",
    "team lineage: an epoch with no row is not verifiable",
])
def test_the_lineage_states(run, case):
    _ok(run, case)


def test_the_module_is_loaded_before_the_app_and_the_new_method_is_on_the_crypto_boundary():
    index = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    checks = index.index('<script src="/static/js/zk_key_checks.js?v=')
    assert index.index('<script src="/static/js/ecc_crypto.js?v=') < checks < index.index(
        '<script src="/static/js/app.js?v=')
    crypto = (ROOT / "static" / "js" / "ecc_crypto.js").read_text(encoding="utf-8")
    table = crypto[crypto.index("const _OPERATION_DEFAULT_CODE = Object.freeze({"):]
    assert "    unwrapTeamPrivateKeyWithCheck: CRYPTO_ERROR_CODES.WRAP_FAILED,\n" in table
