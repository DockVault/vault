"""End-to-end HTTP behaviour of the device-sync pre-flight, against a running deployment.

Everything talks to routes over HTTP (and the SFTP door for the throttle case). The offline module
(test_device_sync_preflight.py) proves the mechanism; this proves the typed states are reachable and
correct over the wire, that an unauthenticated or foreign caller learns NOTHING, and that the answer
differs only by the CALLER'S OWN state. The Redis-pausing (server-not-ready) case is opt-in.

Reachability of each state:
* ok            -- a granted, ready device;
* grant-needed  -- a device with no active grant;
* cap-reached   -- a device that has filled its per-device outstanding-credential cap;
* rate-limited  -- a device whose SFTP-auth bucket is over its limit (needs the rate limit set BELOW
                   the cred cap, so the bucket trips before unspent creds fill the cap -- otherwise
                   the honest answer is legitimately cap-reached; the test skips off that stack);
* server-not-ready -- opt-in: Redis paused so the breaker is open at answer time.
"""
import os
import subprocess

import pytest

from conftest import (
    ApiClient, BASE_URL, configured_int_setting, unique, wait_out_breaker_cooldown,
)
from _device_boundary_helpers import (
    REDIS_CONTAINER, grant, mint_sync_cred, preflight, register_device, sftp_authenticates,
)

pytestmark = pytest.mark.integration

# A value that never authenticates: each attempt is meant to FAIL so the throttle counter advances,
# not a session. Not a credential.
_NEVER_VALID = "wrong-pw-xyz"  # noqa: S105 - deliberately-invalid probe value, never a real secret
_OUTAGE = os.environ.get("VAULT_REDIS_OUTAGE_TEST") == "1"


@pytest.fixture(autouse=True)
def _fresh_rate_limit_buckets():
    """Clear rate_limit:* before each test so one test's flood cannot poison the next (every client
    here shares one source IP; the device/login buckets are shared state). Best-effort: a flush
    failure is not this module's subject."""
    subprocess.run(
        ["docker", "exec", REDIS_CONTAINER, "sh", "-c",
         "redis-cli --scan --pattern 'rate_limit:*' | xargs -r redis-cli del"],
        capture_output=True, text=True, timeout=20)
    yield


def _granted_device(admin, vault):
    dev = register_device(admin)
    grant(admin, dev["device_id"], vault["id"])
    return dev


def test_a_granted_ready_device_gets_ok(admin, temp_vault):
    dev = _granted_device(admin, temp_vault)
    r = preflight(dev["secret"])
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ok"


def test_an_ungranted_device_is_told_grant_needed(admin, temp_vault):
    # A live device with NO active grant: nothing to sync. This reveals only the device's own grant
    # count (already visible via /device/grants) -- it names no vault and never says a vault exists.
    dev = register_device(admin)
    r = preflight(dev["secret"])
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "grant-needed"


def test_no_secret_and_a_foreign_secret_meet_the_same_401_as_the_mint(admin, temp_vault):
    # Non-enumeration: an unauthenticated call and a foreign/unknown secret get exactly the 401 the
    # mint gives -- same status, same typed reason -- so the pre-flight is no cheaper an oracle.
    anon = ApiClient(BASE_URL)
    no_secret = anon.session.get(f"{BASE_URL}/device/sync-preflight", timeout=30)
    assert no_secret.status_code in (401, 403)

    foreign = "dv_" + unique("foreign")  # 256-bit-shaped junk; never a stored secret
    pf = preflight(foreign)
    mint = mint_sync_cred(foreign, temp_vault["id"])
    assert pf.status_code == 401 and mint.status_code == 401, (pf.status_code, mint.status_code)
    assert pf.json()["detail"]["reason"] == mint.json()["detail"]["reason"] == "invalid-device-credential"


def test_cap_reached_when_the_device_fills_its_outstanding_cred_cap(admin, temp_vault):
    cap = configured_int_setting("MAX_DEVICE_SYNC_CREDS_PER_DEVICE") or 10
    dev = _granted_device(admin, temp_vault)
    for _ in range(cap):
        assert mint_sync_cred(dev["secret"], temp_vault["id"]).status_code in (200, 201)
    r = preflight(dev["secret"])
    assert r.status_code == 200, r.text
    # The next mint would 409 device-cred-cap; the pre-flight says so, one step early.
    assert r.json()["status"] == "cap-reached"


def test_the_answer_differs_only_by_the_callers_own_state(admin, temp_vault):
    # Two devices on the SAME account, SAME vault grant, SAME source IP -- the ONLY difference is
    # each device's own credential-cap state, and the pre-flight reflects only that.
    cap = configured_int_setting("MAX_DEVICE_SYNC_CREDS_PER_DEVICE") or 10
    dev_full = _granted_device(admin, temp_vault)
    dev_fresh = _granted_device(admin, temp_vault)
    for _ in range(cap):
        mint_sync_cred(dev_full["secret"], temp_vault["id"])
    assert preflight(dev_full["secret"]).json()["status"] == "cap-reached"
    assert preflight(dev_fresh["secret"]).json()["status"] == "ok"


def test_a_throttled_device_is_rate_limited_while_a_peer_device_stays_ok(admin, temp_vault):
    """rate-limited is the DEVICE's own bucket, not a shared IP bucket.

    Throttle device A at the SFTP door; A is then told rate-limited with a retry-after that is
    positive and bounded by the DEVICE-sync window (so an IP-bucket value -- a different key, its own
    possibly-different window -- cannot masquerade as it). A second device B -- same account, same
    vault grant, same source IP, no traffic of its own -- is told ok. If the peek keyed by IP, A's
    flood would spill into B and B would read rate-limited too."""
    device_limit = configured_int_setting("RATE_LIMIT_DEVICE_SYNC_ATTEMPTS") or 30
    cap = configured_int_setting("MAX_DEVICE_SYNC_CREDS_PER_DEVICE") or 10
    if device_limit >= cap:
        pytest.skip(
            f"needs the device-sync rate limit ({device_limit}) below the cred cap ({cap}) so the "
            f"bucket trips before unspent creds fill the cap; run on the pre-flight stack")
    device_window = configured_int_setting("RATE_LIMIT_DEVICE_SYNC_WINDOW_SECONDS") or 300

    dev_a = _granted_device(admin, temp_vault)
    dev_b = _granted_device(admin, temp_vault)  # same account, same vault, same source IP as A

    # Charge device A's SFTP-auth bucket over its limit with wrong-password attempts (each fails auth
    # but charges the DEVICE bucket before the verify), cycling two of A's own creds -- kept below the
    # cap so A's block is the rate limit, not the cap.
    names = [mint_sync_cred(dev_a["secret"], temp_vault["id"]).json()["temp_username"] for _ in range(2)]
    for i in range(device_limit + 2):
        sftp_authenticates(names[i % len(names)], _NEVER_VALID)

    ra = preflight(dev_a["secret"])
    assert ra.status_code == 200, ra.text
    body = ra.json()
    assert body["status"] == "rate-limited"
    # Positive (A is over its limit right now) and bounded by the DEVICE-sync window -- the device
    # bucket's own retry, which an IP-bucket value could not satisfy on both counts.
    assert isinstance(body.get("retry_after"), int)
    assert 0 < body["retry_after"] <= device_window

    # Device B shares A's account, vault grant, and source IP but has no traffic of its own, so it is
    # ok: the throttle bucket is keyed by device, and A's flood never touched B's. Keying the peek by
    # IP makes B read rate-limited here -- red.
    rb = preflight(dev_b["secret"])
    assert rb.status_code == 200, rb.text
    assert rb.json()["status"] == "ok"


@pytest.mark.skipif(not _OUTAGE, reason="opt-in: pauses Redis; set VAULT_REDIS_OUTAGE_TEST=1")
def test_server_not_ready_while_redis_is_paused(admin, temp_vault):
    # The baseline it replaces: today a mint during a Redis outage surfaces an untyped 500 while
    # /health already reports 'degraded'. Here the pre-flight names it.
    dev = _granted_device(admin, temp_vault)
    subprocess.run(["docker", "pause", REDIS_CONTAINER], check=True, timeout=20)
    try:
        # The general-API middleware's own rate-limit eval fails against paused Redis and trips the
        # breaker (fail-open, so the request still reaches the handler); the handler then reads the
        # OPEN breaker as a PURE read and answers server-not-ready. A few calls cover the trip.
        seen = None
        for _ in range(4):
            r = preflight(dev["secret"])
            if r.status_code == 200 and r.json().get("status") == "server-not-ready":
                seen = "server-not-ready"
                break
        assert seen == "server-not-ready"
    finally:
        subprocess.run(["docker", "unpause", REDIS_CONTAINER], check=True, timeout=20)
        # Leave the breaker closed for the next test in this invocation (it closes on the background
        # probe's next healthy ping, not a timer).
        wait_out_breaker_cooldown()
