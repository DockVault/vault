"""During a Redis outage the breaker heals in the BACKGROUND, with no victim request.

The breaker closes only when its background daemon probe pings a healthy Redis -- never on a timer,
and never on a foreground request's own re-probe. This end-to-end check proves the heal is
request-free: pause Redis so the breaker opens (a fail-open GET then reports the full limit as
remaining, because Redis is not counting), unpause, wait one cooldown + the probe timeout + a margin
WITHOUT making any request, and then the FIRST request must already be Redis-backed (its
X-RateLimit-Remaining is below the limit -- Redis counted it) and fast (it paid no discovery stall),
timed on a connection opened beforehand so the client's connection setup is not counted as the
server's time.
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


def _int_header(headers, name):
    value = headers.get(name)
    return int(value) if value is not None else None


def _timed_get(admin, path):
    """GET ``path`` as the admin on a connection opened beforehand, timing the request and its response
    only: the server's time. After the idle wait the session's kept-alive connection is gone, and a new
    one's setup is the client's time, not the server's: on Windows a connection to ``localhost`` tries
    ::1 first and takes about 2 s to fall back to 127.0.0.1, which alone used to exceed the limit below.
    Opening a connection sends nothing to the application, so the heal stays request-free.
    Returns (status, headers, body, seconds)."""
    import http.client
    import ssl
    from urllib.parse import urlsplit
    from requests.structures import CaseInsensitiveDict
    url = urlsplit(BASE_URL)
    if url.scheme == "https":
        conn = http.client.HTTPSConnection(url.hostname, url.port, timeout=30,
                                           context=ssl._create_unverified_context())
    else:
        conn = http.client.HTTPConnection(url.hostname, url.port, timeout=30)
    try:
        conn.connect()
        t0 = time.time()
        conn.request("GET", path, headers=dict(admin.session.headers))
        resp = conn.getresponse()
        body = resp.read()
        elapsed = time.time() - t0
        return resp.status, CaseInsensitiveDict(resp.getheaders()), body, elapsed
    finally:
        conn.close()


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
        limit = _int_header(during.headers, "X-RateLimit-Limit")
        remaining = _int_header(during.headers, "X-RateLimit-Remaining")
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
        status, headers, body, elapsed = _timed_get(admin, "/vaults")
        assert status == 200, body[:300]
        assert elapsed < _CB_PROBE_TIMEOUT_SECONDS + 1, (
            f"the first request after the idle heal took {elapsed:.2f}s on an open connection -- it "
            f"paid the discovery timeout, so the breaker had not healed on its own")
        limit = _int_header(headers, "X-RateLimit-Limit")
        remaining = _int_header(headers, "X-RateLimit-Remaining")
        assert remaining is not None and limit is not None and remaining < limit, (
            f"the first request after the idle heal was not Redis-backed (remaining {remaining} of "
            f"{limit}), so the background probe did not close the breaker without a request")
    finally:
        wait_out_breaker_cooldown()
