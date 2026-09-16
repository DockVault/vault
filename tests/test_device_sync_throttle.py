"""Device-sync auth is throttled in its OWN per-device bucket, not the human's shared login bucket.

The defect: a device's sync authentication was charged to the same per-IP login bucket as a human's
web login, so a looping sync client spent the human's login budget and could lock the operator out of
the web UI. Now a credential that resolves to a device is throttled by device identity; a credential
with no device (a hand-out credential, an unknown or revoked username) still lands on the IP+username
login throttle, so junk stays bounded.

Everything here is exercised over HTTP at the web login door, where a device-minted credential
charges its device bucket and is then refused (401) — so the device bucket and the human's IP bucket
can be told apart by which one trips (429), with no reliance on SFTP timing or on X-Forwarded-For
(ignored on shipped defaults; every host client shares one source IP, which is exactly why this must
key on device identity, not IP).

Runs only where the login limit is small enough to trip over HTTP — the shipped default (5). On a
suite stack that raises it, these skip (they cannot distinguish the buckets), mirroring
test_login_throttle. Structure matches CI's dedicated throttle step.
"""
import os
import subprocess

import pytest

from conftest import ApiClient, BASE_URL, configured_int_setting, unique
from _device_boundary_helpers import grant, mint_sync_cred, register_device

# Shipped login default is 5 (IP threshold = 2x = 10); the device default is 30. These tests need the
# login bucket small enough to trip inside a few dozen HTTP calls. Skip loudly otherwise.
_LOGIN_LIMIT = configured_int_setting("RATE_LIMIT_LOGIN_ATTEMPTS")
_SKIP = _LOGIN_LIMIT is None or _LOGIN_LIMIT > 50
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        _SKIP,
        reason=f"needs a small login limit to trip over HTTP; deployment has "
               f"RATE_LIMIT_LOGIN_ATTEMPTS={_LOGIN_LIMIT}. Run on the dedicated throttle stack.",
    ),
]

_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")


@pytest.fixture(autouse=True)
def _fresh_rate_limit_buckets():
    """Clear the rate-limit keys before each test. Every client here shares ONE source IP (XFF is
    ignored on shipped defaults), so the login and device buckets are shared state with a 5-minute
    window that cannot be waited out — one test's flood would otherwise poison the next. Mirrors CI's
    FLUSHALL between throttle steps; scoped to rate_limit:* so sessions (DB-backed anyway) are left be."""
    subprocess.run(
        ["docker", "exec", _REDIS_CONTAINER, "sh", "-c",
         "redis-cli --scan --pattern 'rate_limit:*' | xargs -r redis-cli del >/dev/null 2>&1 || true"],
        capture_output=True, text=True, timeout=20)
    yield

_IP_THRESHOLD = (_LOGIN_LIMIT or 5) * 2  # the per-IP login bucket is 2x the per-account limit
# A value that never authenticates: every attempt here is meant to fail, so the throttle counter is
# what advances, not a session. Not a credential.
_NEVER_VALID = "wrong-pw-xyz"  # noqa: S105 - deliberately-invalid probe value, never a real secret


def _login_attempt(username, password):
    """One web-login attempt from a fresh client (all clients share one source IP on the stack)."""
    return ApiClient(BASE_URL).session.post(
        f"{BASE_URL}/auth/login", json={"username": username, "password": password}, timeout=30)


def _register_granted_device(admin, temp_vault):
    dev = register_device(admin)
    grant(admin, dev["device_id"], temp_vault["id"])
    return dev


def _mint_many(admin, dev, temp_vault, n):
    """Up to n live sync credentials for one device (distinct usernames, same device). Stops early if
    the per-device credential cap refuses another — the caller works with what it got."""
    names = []
    for _ in range(n):
        r = mint_sync_cred(dev["secret"], temp_vault["id"])
        if r.status_code not in (200, 201):
            break
        names.append(r.json()["temp_username"])
    return names


def test_a_looping_device_does_not_lock_out_the_human_web_login(admin, temp_vault):
    """(a) A device's sync auths — across DISTINCT single-use credentials, as a real run mints them —
    must not exhaust the human's shared per-IP login bucket. Distinct usernames are the point: each
    has its own login-username bucket, so on the pre-fix code nothing shields the shared IP bucket
    from filling, and the human is locked out. On the fixed code every one is charged to the device's
    own bucket instead, so the IP bucket is untouched."""
    dev = _register_granted_device(admin, temp_vault)
    names = _mint_many(admin, dev, temp_vault, _IP_THRESHOLD)
    assert len(names) >= _IP_THRESHOLD - 1, (
        f"could not mint enough credentials to fill the IP bucket: got {len(names)}")

    for name in names:
        r = _login_attempt(name, _NEVER_VALID)  # wrong password: charges a bucket, spends nothing
        assert r.status_code in (401, 429), r.text

    # The human's per-IP login bucket must be untouched: a fresh human login is an ordinary 401, not a
    # throttled 429. On the pre-fix code the device's distinct-username auths above filled the shared
    # IP bucket and the human came back 429 — locked out by a sync client.
    human = _login_attempt(unique("human"), _NEVER_VALID)
    assert human.status_code == 401, (
        f"the human web login was throttled after a device's sync loop: {human.status_code} "
        f"{human.text[:200]} — the device spent the human's shared login budget")


def test_a_second_device_is_unaffected_by_the_first(admin, temp_vault):
    """(b) One device's sync auths must not throttle a SECOND device on the same IP. Same mechanism as
    (a): distinct-username device-A auths fill the shared IP bucket on the pre-fix code, so device B
    is locked out; on the fixed code they go to device A's own bucket and device B is untouched."""
    dev_a = _register_granted_device(admin, temp_vault)
    dev_b = _register_granted_device(admin, temp_vault)
    names_a = _mint_many(admin, dev_a, temp_vault, _IP_THRESHOLD)
    assert len(names_a) >= _IP_THRESHOLD - 1, f"could not mint enough for device A: {len(names_a)}"
    cred_b = mint_sync_cred(dev_b["secret"], temp_vault["id"]).json()

    for name in names_a:
        _login_attempt(name, _NEVER_VALID)  # device A fills the shared IP bucket on the pre-fix code

    # Device B, untouched, is answered as an ordinary refusal — not throttled. On the pre-fix code
    # device A's loop had exhausted the shared IP bucket and device B came back 429.
    r = _login_attempt(cred_b["temp_username"], _NEVER_VALID)
    assert r.status_code == 401, (
        f"a second device was throttled by the first's activity: {r.status_code} {r.text[:200]}")


def test_the_device_bucket_bounds_a_runaway_device(admin, temp_vault):
    """The device bucket is real and bounds a runaway: past its own limit the device is throttled —
    and it took MORE than the IP threshold to get there, which is how we know it is the device bucket
    (30), not the IP bucket (10), doing the bounding."""
    dev = _register_granted_device(admin, temp_vault)
    cred = mint_sync_cred(dev["secret"], temp_vault["id"]).json()
    device_limit = configured_int_setting("RATE_LIMIT_DEVICE_SYNC_ATTEMPTS") or 30

    first_429 = None
    for i in range(device_limit + 5):
        r = _login_attempt(cred["temp_username"], _NEVER_VALID)
        if r.status_code == 429:
            first_429 = i
            break
        assert r.status_code == 401, r.text
    assert first_429 is not None, "the device bucket never bounded a runaway device"
    assert first_429 > _IP_THRESHOLD, (
        f"the device was throttled after {first_429} attempts, at or below the IP threshold "
        f"({_IP_THRESHOLD}) — that is the shared IP bucket tripping, not the per-device bucket")


def test_unknown_username_spray_is_still_bounded(admin):
    """(c) A username with no device stays on the IP bucket, so spraying unknown temp_ names from one
    IP is still bounded — the device path did not open an unthrottled hole."""
    seen_429 = False
    for _ in range(_IP_THRESHOLD + 5):
        r = _login_attempt("temp_" + unique("ghost"), _NEVER_VALID)
        if r.status_code == 429:
            seen_429 = True
            break
        assert r.status_code == 401, r.text
    assert seen_429, "unknown-username spray from one IP was never bounded"


def test_the_human_login_throttle_is_unchanged(admin):
    """(e) The human web-login throttle still trips on repeated failures for one account, exactly as
    before — the device change did not touch the non-temp login path."""
    username = unique("human-throttle")
    seen_429 = False
    for _ in range(_IP_THRESHOLD + 5):
        r = _login_attempt(username, _NEVER_VALID)
        if r.status_code == 429:
            seen_429 = True
            break
        assert r.status_code == 401, r.text
    assert seen_429, "the human login throttle did not engage on repeated failures"
