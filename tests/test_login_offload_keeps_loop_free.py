"""The login offload keeps the event loop free under a burst of CPU-bound password verifies.

No Redis and no outage — this isolates the OFFLOAD itself, the one thing the cache-outage tests could
not pin (during an outage the limiter's own read opens the breaker first, leaving nothing Redis-bound
on the login path for the offload to move). authenticate_user's password verify is a deliberately
expensive Argon2 hash and it is synchronous. Run OFF the loop, a burst of concurrent logins runs its
verifies in worker threads and the loop stays free; run directly ON the loop they serialize and freeze
it for roughly one verify per login.

So: with the cache healthy, fire N concurrent correct-password logins from distinct users and, mid
burst, time one unrelated authenticated request on its own session. Offloaded it returns at baseline
(no password verify on its path); with run_offloaded replaced by a direct call on the login route it
waits behind the serialized verifies. The threshold sits well under N single verifies.

Opt-in via the login limit like its offload siblings: it fires N logins from one source IP, so it
needs a raised login limit and skips on the shipped-default throttle stack.
"""
import concurrent.futures
import time

import pytest

from conftest import ApiClient, BASE_URL, configured_int_setting

_LOGIN_LIMIT = configured_int_setting("RATE_LIMIT_LOGIN_ATTEMPTS")
_N = 8  # equal to the offload slot count: a full burst that still fits the slots

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        _LOGIN_LIMIT is not None and _LOGIN_LIMIT <= 50,
        reason=f"fires {_N} logins from one IP; needs a raised login limit (deployment has "
               f"RATE_LIMIT_LOGIN_ATTEMPTS={_LOGIN_LIMIT}). Runs on the raised-limit suite stack.",
    ),
]

# One unrelated request must return in well under the time N password verifies take when serialized
# on the loop. A single Argon2 verify is ~0.1-0.2 s on a normal box, so N of them on the loop is ~1-2
# s; offloaded, the unrelated request is a token-auth GET with no verify on its path and returns in
# milliseconds. This sits between the two.
_LOOP_FREE_CEILING = 0.3


def test_a_login_burst_does_not_freeze_the_loop(admin):
    users = [admin.create_user(role="user") for _ in range(_N)]
    try:
        def _login(u):
            return ApiClient(BASE_URL).session.post(
                f"{BASE_URL}/auth/login",
                json={"username": u["_username"], "password": u["_password"]}, timeout=30)

        with concurrent.futures.ThreadPoolExecutor(max_workers=_N) as pool:
            futures = [pool.submit(_login, u) for u in users]
            time.sleep(0.05)  # let the burst reach the server and start verifying

            t0 = time.time()
            r = admin.session.get(f"{BASE_URL}/vaults", timeout=30)
            elapsed = time.time() - t0

            logins = [f.result() for f in futures]

        assert r.status_code == 200, r.text
        # The logins themselves must succeed (else the burst was not real work on the loop/threads).
        assert all(lr.status_code == 200 for lr in logins), [lr.status_code for lr in logins]
        assert elapsed < _LOOP_FREE_CEILING, (
            f"an unrelated request took {elapsed:.2f}s during a {_N}-login burst — the password "
            f"verifies serialized on the event loop instead of running off it (expected under "
            f"{_LOOP_FREE_CEILING}s)")
    finally:
        for u in users:
            admin.delete_user(u["id"])
