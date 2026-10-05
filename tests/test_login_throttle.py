"""Login brute-force throttle.

Two checks, both end-to-end over HTTP:

* test_login_throttle_enforced (always on) - repeated failed logins for one
  username from one IP must eventually return 429, i.e. the per-username login
  throttle actually fires (it isn't answering 401 forever).

* test_login_throttle_survives_redis_outage (opt-in: VAULT_REDIS_OUTAGE_TEST=1)
  - with the Redis container paused, the throttle must FAIL CLOSED to the
  DB-backed fallback: repeated failed logins still reach 429 instead of
  unlimited 401s. This proves a Redis outage no longer silently disables
  throttling.

Every attempt uses a fresh, unique junk username from a single fixed source IP,
so no real account is ever locked and each run gets its own rate-limit bucket.
"""
import os
import subprocess
import time

import pytest
import requests

from conftest import ApiClient, configured_int_setting, unique, wait_out_breaker_cooldown


def _hammer_until_429(client, username, max_attempts):
    """Send failed logins for `username` until a 429 appears (or max_attempts is
    reached). Returns the list of status codes seen."""
    codes = []
    for _ in range(max_attempts):
        r = client.post(
            "/auth/login",
            json={"username": username, "password": "wrong-pw-xyz"},
        )
        codes.append(r.status_code)
        if r.status_code == 429:
            break
    return codes


def test_login_throttle_enforced(base_url):
    """After enough failed logins for one username from one IP the server must
    return 429 (per-username login throttle), not keep answering 401 forever."""
    client = ApiClient(base_url)       # one fixed source IP for all attempts
    username = unique("throttle")      # fresh bucket; never a real account

    # The default per-username limit is small (5/window). Use generous headroom so
    # the test still trips with a moderately raised limit; if it doesn't, the
    # message points at the likely cause (rate_limit_login_attempts set high).
    max_attempts = 40
    codes = _hammer_until_429(client, username, max_attempts=max_attempts)

    if 429 not in codes:
        # A dev stack often raises the limit far above anything reachable over HTTP (2000 in
        # this suite's own environment), and then not tripping is correct. But "the throttle
        # did not engage" is also exactly what a broken throttle looks like, so skipping on it
        # unconditionally means the check quietly stops running the moment it starts mattering.
        # Ask the deployment what limit it is enforcing: below the attempts just made, it should
        # have tripped, and that is a failure rather than a deployment this cannot exercise.
        configured = configured_int_setting("RATE_LIMIT_LOGIN_ATTEMPTS")
        assert configured is None or configured > max_attempts, (
            f"per-username login throttling did not engage in {max_attempts} failed attempts "
            f"against a deployment configured to allow {configured}. Every attempt was answered "
            "as an ordinary auth failure, so the throttle is not being enforced"
        )
        pytest.skip(
            f"login throttle did not engage within {max_attempts} attempts and the configured "
            f"limit ({'unreadable' if configured is None else configured}) does not say it "
            "should have. Lower rate_limit_login_attempts to exercise this test."
        )
    # Everything before the first 429 must be a plain auth failure (401), never a
    # success or a 500 (a 500 would mean the throttle path errored out — e.g. the
    # RateLimitExceededError name-collision bug that returned 500 instead of 429).
    first = codes.index(429)
    assert all(c == 401 for c in codes[:first]), f"unexpected pre-throttle codes: {codes}"


@pytest.mark.skipif(
    os.environ.get("VAULT_REDIS_OUTAGE_TEST") not in ("1", "true", "yes"),
    reason="opt-in: set VAULT_REDIS_OUTAGE_TEST=1 to run the Redis-outage "
           "fail-closed test (it pauses/unpauses the Redis container via docker)",
)
def test_login_throttle_survives_redis_outage(base_url):
    """With Redis UNRESPONSIVE the login throttle must FAIL CLOSED to the DB-backed
    fallback: repeated failed logins still reach 429 instead of unlimited 401s."""
    container = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")

    def _docker(*args):
        return subprocess.run(["docker", *args], capture_output=True, text=True)

    def _redis_pingable():
        out = _docker("exec", container, "redis-cli", "ping").stdout.strip().upper()
        return out == "PONG"

    def _app_sees_redis():
        """True only when the APP reports Redis reconnected. /health always
        returns HTTP 200 (even degraded), so gate on the JSON 'redis' field, not
        the status code, and exercise the app's own client pool."""
        try:
            return requests.get(f"{base_url}/health", timeout=5).json().get("redis") == "connected"
        except Exception:  # noqa: BLE001
            return False

    # The pause + its assert live INSIDE the try so the finally always runs once a
    # pause has been attempted (a non-zero command can still leave the container
    # paused — we must always attempt the unpause).
    try:
        pause = _docker("pause", container)
        assert pause.returncode == 0, f"could not pause redis container: {pause.stderr}"
        # Give the app a moment to start seeing Redis as unavailable.
        time.sleep(2)
        client = ApiClient(base_url)
        username = unique("throttle-outage")
        max_attempts = 40
        codes = _hammer_until_429(client, username, max_attempts=max_attempts)
        if 429 not in codes and all(c == 401 for c in codes):
            # Same caveat as the always-on test: an absurdly high configured limit
            # can't be hit in max_attempts on an arbitrary local deployment. The
            # disposable same-commit job sets the shipped limit explicitly, so a
            # clean run of 401s there proves the DB fallback failed open.
            if os.environ.get("VAULT_SAME_COMMIT_CI", "").lower() in {"1", "true", "yes"}:
                pytest.fail(
                    "login throttle failed open during the Redis outage; "
                    f"same-commit CI saw only 401 responses in {max_attempts} attempts"
                )
            pytest.skip(
                f"throttle did not engage within {max_attempts} attempts during the "
                "outage; rate_limit_login_attempts is likely configured above that."
            )
        assert 429 in codes, (
            f"throttle FAILED OPEN during a Redis outage (saw {codes}); "
            "the DB-backed fallback did not engage"
        )
    finally:
        # Always bring Redis back, even if the assertions above failed, so the
        # rest of the suite (and the live stack) keeps working.
        _docker("unpause", container)
        # First confirm the container answers, then that the APP re-established
        # its connection pool (not merely that HTTP responded).
        for _ in range(30):
            if _redis_pingable():
                break
            time.sleep(1)
        for _ in range(30):
            if _app_sees_redis():
                break
            time.sleep(1)
        # Wait out the breaker cooldown so the next test in this invocation starts on the Redis path
        # with a closed breaker (not routed to a DB fallback still holding this outage's attempts).
        wait_out_breaker_cooldown()


@pytest.mark.skipif(
    os.environ.get("VAULT_REDIS_OUTAGE_TEST") not in ("1", "true", "yes"),
    reason="opt-in: set VAULT_REDIS_OUTAGE_TEST=1 to run the fast-fail-closed test "
           "(it pauses/unpauses the Redis container via docker)",
)
def test_login_fast_fail_closed_during_redis_outage(base_url):
    """With Redis UNRESPONSIVE, logins must fail over to the DB throttle FAST. Before the fix every
    request blocked on the 5s Redis connect timeout, so logins crawled during an outage. With
    the short connect timeout + the rate-limiter circuit breaker, the breaker trips after the first
    failure and subsequent logins skip Redis entirely — so the TAIL attempts complete quickly."""
    container = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")

    def _docker(*args):
        return subprocess.run(["docker", *args], capture_output=True, text=True)

    try:
        pause = _docker("pause", container)
        assert pause.returncode == 0, f"could not pause redis container: {pause.stderr}"
        time.sleep(2)  # let the app start seeing Redis as unavailable

        client = ApiClient(base_url)
        username = unique("fastfail")  # never a real account
        timings = []
        for _ in range(8):
            t0 = time.time()
            client.post("/auth/login", json={"username": username, "password": "wrong-pw-xyz"})
            timings.append(time.time() - t0)

        # The circuit breaker opens after the first Redis failure, so the LAST few
        # attempts must not pay any Redis stall — comfortably under the old 5s-per-request
        # floor and well within the breaker's cooldown window. (Generous bound to stay robust
        # on a busy CI host; the real expectation is ~sub-second once the breaker is open.)
        tail = timings[-3:]
        assert max(tail) < 2.5, (
            f"logins slow during the Redis outage (circuit breaker not fast-failing): {timings}"
        )
    finally:
        _docker("unpause", container)
        for _ in range(30):
            try:
                if requests.get(f"{base_url}/health", timeout=5).json().get("redis") == "connected":
                    break
            except Exception:  # noqa: BLE001
                pass
            time.sleep(1)
        # Start the next test on the Redis path with a closed breaker.
        wait_out_breaker_cooldown()


# ---- right passwords are not counted --------------------------------------------------------------
#
# A sign-in is charged before its password is checked, so guesses in parallel cannot pass the limit;
# one that succeeds gives its charges back, so the throttle counts failed attempts only. Before, the
# sixth right password in five minutes from one address was refused, and so was the eleventh account
# signing in from one address. The limit is set to the shipped 5 (10 an address) for these tests through
# the administrators' override, whatever the stack runs with.

def _sign_in_status(name, password):
    # A plain session: no X-Forwarded-For, so every attempt comes from this host's one address.
    s = requests.Session()
    s.trust_env = False
    from conftest import BASE_URL
    return s.post(f"{BASE_URL}/auth/login", json={"username": name, "password": password}, timeout=30).status_code


@pytest.fixture
def shipped_login_limit(admin):
    from _account_change_helpers import psql, reset_sign_in_throttle
    before = admin.get("/settings").json().get("max_login_attempts") or 0
    r = admin.put("/settings", json={"max_login_attempts": 5})
    assert r.status_code == 200, r.text
    reset_sign_in_throttle()
    psql("DELETE FROM rate_limit_records WHERE action IN ('login_user', 'login_ip')")
    yield 5
    admin.put("/settings", json={"max_login_attempts": before})
    reset_sign_in_throttle()


def _right_and_wrong(admin, limit):
    account = admin.create_user()
    name, pw = account["_username"], account["_password"]
    assert [_sign_in_status(name, pw) for _ in range(12)] == [200] * 12
    others = [admin.create_user() for _ in range(11)]
    assert [_sign_in_status(o["_username"], o["_password"]) for o in others] == [200] * 11
    # Wrong passwords are still counted: refused after the limit for the name,
    assert [_sign_in_status(name, "wrong-pw-xyz") for _ in range(limit + 1)] == [401] * limit + [429]
    # and after twice the limit for the address, whoever signs in.
    assert [_sign_in_status(unique("nobody"), "wrong-pw-xyz") for _ in range(limit)] == [401] * limit
    assert _sign_in_status(others[0]["_username"], others[0]["_password"]) == 429


def test_right_passwords_do_not_count_against_the_login_throttle(admin, shipped_login_limit):
    _right_and_wrong(admin, shipped_login_limit)


@pytest.mark.skipif(
    os.environ.get("VAULT_REDIS_OUTAGE_TEST") not in ("1", "true", "yes"),
    reason="opt-in: set VAULT_REDIS_OUTAGE_TEST=1 to run the Redis-outage test "
           "(it pauses/unpauses the Redis container via docker)",
)
def test_right_passwords_do_not_count_while_the_cache_is_down(admin, shipped_login_limit, base_url):
    """The same with Redis paused: the database fallback's count is given back too."""
    container = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
    account = admin.create_user()
    name, pw = account["_username"], account["_password"]
    try:
        assert subprocess.run(["docker", "pause", container], capture_output=True).returncode == 0
        time.sleep(2)
        assert [_sign_in_status(name, pw) for _ in range(7)] == [200] * 7
        assert [_sign_in_status(name, "wrong-pw-xyz") for _ in range(6)] == [401] * 5 + [429]
    finally:
        subprocess.run(["docker", "unpause", container], capture_output=True)
        for _ in range(30):
            try:
                if requests.get(f"{base_url}/health", timeout=5).json().get("redis") == "connected":
                    break
            except Exception:  # noqa: BLE001
                pass
            time.sleep(1)
        wait_out_breaker_cooldown()
