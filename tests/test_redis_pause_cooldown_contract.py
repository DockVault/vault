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

pytestmark = pytest.mark.unit

# The first argument to a docker call — `docker("pause", ...)` / `_docker("pause", ...)` — is how the
# Redis outage tests suspend the container; that is the marker for a pause site.
_PAUSE = re.compile(r'\(\s*"pause"')
_SETTLES = "wait_out_breaker_cooldown"


def test_every_redis_pausing_module_waits_out_the_breaker_cooldown():
    tests_dir = pathlib.Path(__file__).parent
    offenders = []
    for path in sorted(tests_dir.glob("test_*.py")):
        if path.name == pathlib.Path(__file__).name:
            continue  # this contract module names "pause" only in prose
        src = path.read_text(encoding="utf-8")
        if _PAUSE.search(src) and _SETTLES not in src:
            offenders.append(path.name)
    assert not offenders, (
        "these modules pause the Redis container but never call wait_out_breaker_cooldown(), so the "
        f"next test in the invocation can start on an open breaker: {offenders}")
