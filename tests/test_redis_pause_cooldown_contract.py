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


def test_every_redis_pausing_file_waits_out_the_breaker_cooldown():
    tests_dir = pathlib.Path(__file__).parent
    this_file = pathlib.Path(__file__).name
    offenders = []
    # Scan EVERY .py under tests/ RECURSIVELY (test modules, conftest, helper modules, any subdir),
    # so a pause site the non-recursive globs would have missed cannot slip through.
    for path in sorted(tests_dir.rglob("*.py")):
        if path.name == this_file:
            continue
        src = path.read_text(encoding="utf-8")
        if _PAUSE.search(src) and _SETTLES not in src:
            offenders.append(path.name)
    assert not offenders, (
        "these files pause the Redis container but never call wait_out_breaker_cooldown(), so the "
        f"next test in the invocation can start on an open breaker: {offenders}")


def test_wait_out_breaker_cooldown_sleep_is_patchable(monkeypatch):
    # The helper must sleep via the module-level `time` so the offline fast lane can patch it away
    # instead of spending the real ~11 s cooldown. This also is that consumer of the affordance.
    slept = []
    monkeypatch.setattr(conftest.time, "sleep", lambda s: slept.append(s))
    conftest.wait_out_breaker_cooldown()
    assert slept, "wait_out_breaker_cooldown did not call the module-level time.sleep (not patchable)"
    assert slept[0] >= 10, f"expected a cooldown-length sleep, got {slept}"
