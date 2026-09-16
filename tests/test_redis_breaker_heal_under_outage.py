"""During a Redis outage the breaker heals in the BACKGROUND, with no victim request.

The breaker closes only when its background daemon probe pings a healthy Redis -- never on a timer,
and never on a foreground request's own re-probe. This end-to-end check proves the heal is
request-free: pause Redis so the breaker opens (a fail-open GET then reports the full limit as
remaining, because Redis is not counting), unpause, wait one cooldown + the probe timeout + a margin
WITHOUT making any request, and then the FIRST request must already be Redis-backed (its
X-RateLimit-Remaining is below the limit -- Redis counted it) and fast (it paid no discovery stall).
A timer- or first-request-driven design would leave that first request to rediscover Redis: it would
be fail-open (remaining == limit) or pay the socket timeout.

Opt-in and timed (it waits a real cooldown), so it lives with the other Redis-outage tests. The
live acceptance for the whole fix is an observer-GET measurement, against a running stack, across
several cooldown boundaries with Redis paused: no GET may see the socket timeout.
"""
import os
import subprocess
import time

import pytest

from conftest import BASE_URL, wait_out_breaker_cooldown

_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("VAULT_REDIS_OUTAGE_TEST") not in ("1", "true", "yes"),
        reason="opt-in: set VAULT_REDIS_OUTAGE_TEST=1 to run the background breaker-heal test "
               "(it pauses/unpauses the Redis container via docker and waits a real cooldown)",
    ),
]


def _docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30)


def _int_header(resp, name):
    value = resp.headers.get(name)
    return int(value) if value is not None else None


def test_the_breaker_heals_in_the_background_without_a_victim_request(admin):
    from app.core.rate_limiter import _CB_COOLDOWN_SECONDS, _CB_PROBE_TIMEOUT_SECONDS

    if _docker("version").returncode != 0:
        pytest.skip("docker not available")
    if _docker("inspect", _REDIS_CONTAINER).returncode != 0:
        pytest.skip(f"redis container {_REDIS_CONTAINER!r} not found")

    assert _docker("pause", _REDIS_CONTAINER).returncode == 0
    try:
        # The first GET during the outage pays the one-off discovery stall and opens the breaker;
        # once open, a fail-open GET is served without counting, so it reports the FULL limit.
        during = None
        for _ in range(3):
            during = admin.session.get(f"{BASE_URL}/vaults", timeout=30)
            assert during.status_code == 200, during.text
        limit = _int_header(during, "X-RateLimit-Limit")
        remaining = _int_header(during, "X-RateLimit-Remaining")
        assert limit is not None and remaining == limit, (
            f"the breaker did not open during the outage (remaining {remaining} of {limit}); rate "
            f"limiting still appears to be counting against Redis")
    finally:
        _docker("unpause", _REDIS_CONTAINER)
        for _ in range(30):
            s = _docker("inspect", "--format", "{{.State.Health.Status}}", _REDIS_CONTAINER)
            if s.returncode == 0 and s.stdout.strip() == "healthy":
                break
            time.sleep(2)

    # No request during this wait: the background probe alone must close the breaker within one
    # cooldown plus its short probe timeout of Redis coming back.
    time.sleep(_CB_COOLDOWN_SECONDS + _CB_PROBE_TIMEOUT_SECONDS + 3)

    try:
        t0 = time.time()
        healed = admin.session.get(f"{BASE_URL}/vaults", timeout=30)
        elapsed = time.time() - t0
        assert healed.status_code == 200, healed.text
        assert elapsed < _CB_PROBE_TIMEOUT_SECONDS + 1, (
            f"the first request after the idle heal took {elapsed:.2f}s -- it paid the discovery "
            f"timeout, so the breaker had not healed on its own")
        limit = _int_header(healed, "X-RateLimit-Limit")
        remaining = _int_header(healed, "X-RateLimit-Remaining")
        assert remaining is not None and limit is not None and remaining < limit, (
            f"the first request after the idle heal was not Redis-backed (remaining {remaining} of "
            f"{limit}), so the background probe did not close the breaker without a request")
    finally:
        wait_out_breaker_cooldown()
