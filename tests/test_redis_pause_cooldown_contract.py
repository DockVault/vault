"""Contract: every test module that pauses the Redis container must wait out the breaker cooldown.

Pausing Redis opens the process-wide rate-limiter breaker for its cooldown. A following test in the
same pytest invocation that starts inside that window is routed to the DB fallback, which still holds
the prior module's attempts for the shared runner IP — the classic cross-module 429 at fixture setup.
Every Redis-pausing fixture calls conftest.wait_out_breaker_cooldown() after it restores Redis to
remove that hazard; this meta-test keeps a new pause site from shipping without it.
"""
import pathlib
import re

import pytest

import conftest

pytestmark = pytest.mark.unit

# A docker "pause" of the Redis container, in any of the forms the suite uses:
#   docker("pause", ...)  /  _docker("pause", ...)  /  subprocess.run(["docker", "pause", ...])
# The quote may be single or double; requiring a preceding "(" or "," keeps prose like "pauses/
# unpauses" in a docstring from matching.
_PAUSE = re.compile(r"""[(,]\s*['"]pause['"]""")
_SETTLES = "wait_out_breaker_cooldown"

# Directory parts to skip: the recursive walk must stay in the suite's OWN files, not descend into a
# vendored interpreter (the project's lane convention puts one at tests/.venv), where site-packages
# modules — a Pygments lexer, Playwright's _page.py — legitimately contain `("pause"...)` and are
# nothing to do with the Redis contract.
_SKIP_PARTS = {"site-packages", "venv", ".venv", "__pycache__", "node_modules"}


def _pause_offenders(root: pathlib.Path):
    """Files under `root` (recursively, but skipping vendored trees) that pause Redis without settling
    the breaker cooldown. Skips this contract module itself, which names "pause" only in prose."""
    this_file = pathlib.Path(__file__).name
    offenders = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if any(part.startswith(".") or part in _SKIP_PARTS for part in rel.parts):
            continue  # a vendored interpreter / cache / hidden dir, not a suite file
        if path.name == this_file:
            continue
        src = path.read_text(encoding="utf-8")
        if _PAUSE.search(src) and _SETTLES not in src:
            offenders.append(str(rel))
    return offenders


def test_every_redis_pausing_file_waits_out_the_breaker_cooldown():
    offenders = _pause_offenders(pathlib.Path(__file__).parent)
    assert not offenders, (
        "these files pause the Redis container but never call wait_out_breaker_cooldown(), so the "
        f"next test in the invocation can start on an open breaker: {offenders}")


def test_the_pause_scan_ignores_vendored_trees_but_still_catches_real_sites(tmp_path):
    # A vendored interpreter under tests/ (e.g. tests/.venv/.../site-packages) must NOT be scanned —
    # its modules legitimately contain ("pause"...) — while a genuine suite file that pauses without
    # settling the cooldown must still be caught.
    vendored = tmp_path / ".venv" / "lib" / "site-packages"
    vendored.mkdir(parents=True)
    (vendored / "lexer.py").write_text('docker("pause", "x")  # no cooldown, but vendored', encoding="utf-8")
    (tmp_path / "test_real.py").write_text(
        'docker("pause", REDIS)\n# a genuine pause site that never settles the breaker\n', encoding="utf-8")
    (tmp_path / "test_ok.py").write_text(
        'docker("pause", REDIS)\nwait_out_breaker_cooldown()\n', encoding="utf-8")

    offenders = _pause_offenders(tmp_path)
    assert not any("site-packages" in o or ".venv" in o for o in offenders), (
        f"the scan descended into a vendored interpreter: {offenders}")
    assert "test_real.py" in offenders, f"the scan missed a real pause-without-cooldown site: {offenders}"
    assert "test_ok.py" not in offenders, f"a file that settles the cooldown was flagged: {offenders}"


def test_wait_out_breaker_cooldown_sleep_is_patchable(monkeypatch):
    # The helper must sleep via the module-level `time` so the offline fast lane can patch it away
    # instead of spending the real ~11 s cooldown. This also is that consumer of the affordance.
    slept = []
    monkeypatch.setattr(conftest.time, "sleep", lambda s: slept.append(s))
    conftest.wait_out_breaker_cooldown()
    assert slept, "wait_out_breaker_cooldown did not call the module-level time.sleep (not patchable)"
    assert slept[0] >= 10, f"expected a cooldown-length sleep, got {slept}"
