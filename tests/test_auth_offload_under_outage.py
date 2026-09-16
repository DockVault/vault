"""During a cache outage, one caller's stall must not freeze the server for everyone.

`POST /auth/login` and the two credential mints do synchronous work that, when Redis is unavailable,
blocks on a socket. Two things keep that from becoming a server-wide freeze:

  * the session-cache writes go through the same circuit breaker the rate limiter uses, so the auth
    path pays ONE socket stall per cooldown instead of one per raw call; and
  * the synchronous auth work runs off the event loop in a worker thread, with concurrency bounded
    BELOW the database pool, so concurrent outage logins run in parallel instead of queueing behind
    one event loop — and a burst of them cannot drain the connection pool and starve unrelated
    requests.

Timed, and they pause the Redis container, so they are opt-in and live in their own module. DISTINCT
real users with CORRECT passwords throughout: a successful login is what exercises the session-cache
write, and distinct users keep this about per-process concurrency rather than the single-credential
session race, which is a separate concern.
"""
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest

from conftest import ApiClient, BASE_URL, unique

_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("VAULT_REDIS_OUTAGE_TEST") not in ("1", "true", "yes"),
        reason="opt-in: set VAULT_REDIS_OUTAGE_TEST=1 to run the cache-outage offload tests "
               "(they pause/unpause the Redis container via docker)",
    ),
]


def _docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30)


@contextmanager
def _redis_paused():
    """Pause Redis for the block, then unpause and wait for it to be healthy again. Set up your test
    state (users, sessions) BEFORE entering, since the cache is down inside."""
    if _docker("version").returncode != 0:
        pytest.skip("docker not available")
    if _docker("inspect", _REDIS_CONTAINER).returncode != 0:
        pytest.skip(f"redis container {_REDIS_CONTAINER!r} not found")
    assert _docker("pause", _REDIS_CONTAINER).returncode == 0
    time.sleep(2)
    try:
        yield
    finally:
        _docker("unpause", _REDIS_CONTAINER)
        for _ in range(30):
            s = _docker("inspect", "--format", "{{.State.Health.Status}}", _REDIS_CONTAINER)
            if s.returncode == 0 and s.stdout.strip() == "healthy":
                break
            time.sleep(2)


def _timed_login(creds):
    """One CORRECT-password web login from its own client; returns (status, seconds). A success is
    what writes the session cache, which is the stall this measures."""
    username, password = creds
    t0 = time.time()
    r = ApiClient(BASE_URL).session.post(
        f"{BASE_URL}/auth/login", json={"username": username, "password": password}, timeout=120)
    return r.status_code, time.time() - t0


def _make_users(admin, n):
    users = [admin.create_user(role="user") for _ in range(n)]
    return [(u["_username"], u["_password"]) for u in users]


def _cleanup(admin, users):
    data = admin.get("/users").json()
    rows = data if isinstance(data, list) else data.get("users", [])
    wanted = {name for name, _ in users}
    for u in rows:
        if u.get("username") in wanted:
            try:
                admin.delete(f"/users/{u['id']}")
            except Exception:  # noqa: BLE001
                pass


def test_concurrent_outage_logins_do_not_serialize_behind_the_event_loop(admin):
    """Three successful logins at once during the outage must overlap, not queue. Timed against one
    login on the same paused stack: on the pre-offload code the synchronous session-cache stalls ran
    on the event loop and three logins took about three times one; offloaded (and with the cache
    write behind the breaker), the slowest of three is close to a single one."""
    users = _make_users(admin, 4)  # one for the solo timing, three for the concurrent batch
    try:
        with _redis_paused():
            _s, single = _timed_login(users[0])
            assert _s == 200, f"a correct-password login should succeed during the outage: {_s}"

            t0 = time.time()
            with ThreadPoolExecutor(max_workers=3) as pool:
                results = list(pool.map(_timed_login, users[1:4]))
            wall = time.time() - t0

        assert all(code == 200 for code, _ in results), f"logins did not all succeed: {results}"
        assert wall < max(2.0, single * 2), (
            f"three concurrent outage logins took {wall:.1f}s against a single login's {single:.1f}s "
            f"— they serialized behind the event loop instead of overlapping")
    finally:
        _cleanup(admin, users)


def test_a_login_burst_during_outage_still_serves_an_unrelated_request(admin):
    """A burst of outage logins must not drain the DB pool and starve an unrelated request. Each
    offloaded login holds a connection for its stall, so without the concurrency bound a burst larger
    than the pool would fail every request; the bound keeps the pool with headroom."""
    users = _make_users(admin, 24)  # well over the offload bound
    try:
        with _redis_paused():
            with ThreadPoolExecutor(max_workers=len(users)) as pool:
                fut = [pool.submit(_timed_login, c) for c in users]
                time.sleep(1)  # let the burst pile up and hold what connections it will
                # An unrelated, authenticated request on its own established session, mid-burst. It
                # must be served, not fail on a pool checkout timeout.
                r = admin.session.get(f"{BASE_URL}/vaults", timeout=30)
                codes = [f.result()[0] for f in fut]
        assert r.status_code == 200, (
            f"an unrelated request was starved during a login burst: {r.status_code} {r.text[:200]} "
            f"— the offload drained the DB pool instead of bounding its own concurrency")
        assert all(c == 200 for c in codes), f"some burst logins did not succeed: {set(codes)}"
    finally:
        _cleanup(admin, users)
