"""During a cache outage the event loop stays free while a login runs, so other requests are served.

A login does blocking work that touches Redis: the rate-limit read, the session-cache writes, and —
the one this test targets — a broadcast publish on the activity channel after the session is minted.
Two mechanisms keep a Redis outage from freezing the SERVER (not just the one login):

  * login runs its blocking auth work OFF the event loop (bounded below the DB pool by the
    auth_offload_slot dependency — see test_auth_offload.py and test_auth_offload_slot_ordering.py),
    so one caller's stall does not hold the loop; and
  * the post-auth broadcast publish also runs off the loop (fire-and-forget) and behind the
    read-through cache guard, so the publish that survives a COLD breaker — before any Redis failure
    has opened the guard — cannot block the loop either.

The freeze this proves: with Redis freshly paused (breaker COLD) and one login in flight, an unrelated
authenticated request fired a fraction of a second into that login must be served after about ONE
socket-timeout stall (its own denylist read, which a cold breaker cannot yet skip), not two. On code
that runs the login's broadcast on the loop, the unrelated request also waits behind that publish and
pays a SECOND socket timeout. Measured on a paused stack: ~2.0 s served vs ~3.8 s frozen. Opt-in and
timed, so it lives with the other outage tests; needs the raised-login-limit stack so a burst of
logins from one IP is not itself throttled.
"""
import os
import subprocess
import threading
import time
from contextlib import contextmanager

import pytest

from conftest import ApiClient, BASE_URL, configured_int_setting, unique, wait_out_breaker_cooldown

_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
_NEVER_VALID = "wrong-pw-xyz"  # noqa: S105 - deliberately-invalid probe value, never a real secret

# The single socket-timeout floor a cold breaker cannot skip. The redis client's socket timeout is
# 2.0 s, so one stall is ~2 s and two stacked stalls ~4 s. This threshold sits between the served
# (~2.0 s) and frozen (~3.8 s) cases the QA runner measured on a paused stack.
_ONE_STALL_CEILING = 3.0

# Guard on the login limit: this test fires logins from one IP, so a small shipped login limit (5)
# would 429 them before they reach the broadcast. Runs on the raised-limit offload/outage stack.
_LOGIN_LIMIT = configured_int_setting("RATE_LIMIT_LOGIN_ATTEMPTS")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("VAULT_REDIS_OUTAGE_TEST") not in ("1", "true", "yes"),
        reason="opt-in: set VAULT_REDIS_OUTAGE_TEST=1 to run the cache-outage loop-freeze test "
               "(it pauses/unpauses the Redis container via docker)",
    ),
    pytest.mark.skipif(
        _LOGIN_LIMIT is not None and _LOGIN_LIMIT <= 50,
        reason=f"needs a raised login limit so logins from one IP are not throttled mid-test; "
               f"deployment has RATE_LIMIT_LOGIN_ATTEMPTS={_LOGIN_LIMIT}. Run on the offload stack.",
    ),
]


def _docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30)


@contextmanager
def _redis_paused():
    if _docker("version").returncode != 0:
        pytest.skip("docker not available")
    if _docker("inspect", _REDIS_CONTAINER).returncode != 0:
        pytest.skip(f"redis container {_REDIS_CONTAINER!r} not found")
    assert _docker("pause", _REDIS_CONTAINER).returncode == 0
    time.sleep(2)  # let the app start seeing Redis as unavailable (breaker stays COLD until a call)
    try:
        yield
    finally:
        _docker("unpause", _REDIS_CONTAINER)
        for _ in range(30):
            s = _docker("inspect", "--format", "{{.State.Health.Status}}", _REDIS_CONTAINER)
            if s.returncode == 0 and s.stdout.strip() == "healthy":
                break
            time.sleep(2)
        # Start the next test on the Redis path with a closed breaker.
        wait_out_breaker_cooldown()


def test_the_loop_stays_free_while_a_login_runs_during_an_outage(admin):
    """With Redis freshly paused (breaker COLD) and one login in flight, an unrelated authenticated
    request fired 0.2 s into that login must be served after about ONE socket-timeout stall, not two.
    On code that runs the login's broadcast on the event loop, the unrelated request also waits behind
    that publish and pays a second timeout.

    A dedicated second account does the login, so terminating its session (one-session-per-user) does
    not disturb the admin token used for the unrelated request."""
    # A dedicated account whose login will run during the outage (created before the outage).
    login_user = admin.create_user(role="user")
    creds = {"username": login_user["_username"], "password": login_user["_password"]}

    result = {}

    def _run_login():
        c = ApiClient(BASE_URL)
        t0 = time.time()
        try:
            r = c.session.post(f"{BASE_URL}/auth/login", json=creds, timeout=30)
            result["login_status"] = r.status_code
        except Exception as exc:  # noqa: BLE001 — a login error still frees the loop; we time the GET
            result["login_error"] = repr(exc)
        result["login_elapsed"] = time.time() - t0

    try:
        with _redis_paused():
            login_thread = threading.Thread(target=_run_login, daemon=True)
            login_thread.start()
            # Let the login get into its off-loop auth work, then fire the unrelated request while it
            # is still running — this is the window that froze on the pre-fix code.
            time.sleep(0.2)

            t0 = time.time()
            r = admin.session.get(f"{BASE_URL}/vaults", timeout=30)
            elapsed = time.time() - t0

            login_thread.join(timeout=30)

        assert r.status_code == 200, r.text
        assert elapsed < _ONE_STALL_CEILING, (
            f"an unrelated authenticated request took {elapsed:.2f}s while a login ran during the "
            f"outage — it paid a second socket timeout waiting behind the login's on-loop broadcast "
            f"publish, so the loop was frozen (expected under {_ONE_STALL_CEILING}s: one stall, not "
            f"two)")
    finally:
        admin.delete_user(login_user["id"])
