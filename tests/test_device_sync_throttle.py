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
import time

import pytest

from conftest import ApiClient, BASE_URL, configured_int_setting, unique, wait_out_breaker_cooldown
from _device_boundary_helpers import (
    grant, mint_sync_cred, register_device, sftp_authenticates, temp_login)

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
    flush = subprocess.run(
        ["docker", "exec", _REDIS_CONTAINER, "sh", "-c",
         "redis-cli --scan --pattern 'rate_limit:*' | xargs -r redis-cli del"],
        capture_output=True, text=True, timeout=20)
    if flush.returncode != 0:
        pytest.skip(f"could not clear the rate-limit buckets before the test: {flush.stderr.strip()}")
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
    # Fire STRICTLY MORE than the IP threshold of distinct-username device auths. On the reverted
    # code each charges login:<ip> once, so this many is what actually pushes the shared IP bucket
    # PAST its limit and locks the human out — at exactly _IP_THRESHOLD the reverted bucket sits at
    # the limit without tripping and the human-401 assertion would pass on the bug too (vacuous).
    fill = _IP_THRESHOLD + 1
    names = _mint_many(admin, dev, temp_vault, fill)
    assert len(names) >= fill, (
        f"could not mint enough credentials to push the IP bucket past its limit: got {len(names)}, "
        f"needed {fill}")

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
    fill = _IP_THRESHOLD + 1  # strictly past the IP threshold, so the reverted IP bucket really trips
    names_a = _mint_many(admin, dev_a, temp_vault, fill)
    assert len(names_a) >= fill, f"could not mint enough for device A: {len(names_a)}, needed {fill}"
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
    (30), not the IP bucket (10), doing the bounding.

    A trip count alone cannot tell which layer produced the 429 (a 429 is a 429). The discriminator is
    a SECOND device on the same IP: at the moment device A is throttled, device B must still
    authenticate. If the shared IP bucket were the one that tripped, B — same IP — would be 429 too.
    B answering 401 (its own empty device bucket, wrong password) proves it was A's device bucket."""
    dev = _register_granted_device(admin, temp_vault)
    dev_b = _register_granted_device(admin, temp_vault)
    cred = mint_sync_cred(dev["secret"], temp_vault["id"]).json()
    cred_b = mint_sync_cred(dev_b["secret"], temp_vault["id"]).json()
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

    # The discriminator: device B, on the SAME IP, is untouched at the moment device A is throttled.
    # A shared-IP-bucket trip would 429 B too; a per-device trip leaves B free.
    r_b = _login_attempt(cred_b["temp_username"], _NEVER_VALID)
    assert r_b.status_code == 401, (
        f"a second device on the same IP was throttled ({r_b.status_code}) while device A was at its "
        f"limit — the 429 came from the shared IP bucket, not device A's own bucket")


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


def test_a_deleted_devices_looping_client_does_not_lock_out_the_owner(admin, temp_vault):
    """Deleting a device sets its credentials' device_id to NULL (FK ON DELETE SET NULL) and
    deactivates them, but the rows remain. A client still looping those cached credentials must not
    spend the owner's shared per-IP login budget.

    Reachable form (a single orphaned credential caps at its own per-username limit, below the IP
    threshold, so it cannot lock anyone): the device minted TWO credentials before deletion, and the
    client retries EACH the login-limit number of times at the SFTP door from the owner's IP. On the
    reverted code each retry is charged to login:<ip> (the credential has no device now), so
    2 * login-limit charges fill the shared IP bucket to its threshold and the owner's own web login
    is the attempt that tips it over -- a 429. On the fixed code each known credential is charged to
    its OWN per-username bucket and never to login:<ip>, so the owner's web login is an ordinary 401."""
    dev = _register_granted_device(admin, temp_vault)
    creds = [mint_sync_cred(dev["secret"], temp_vault["id"]).json() for _ in range(2)]
    assert all("temp_username" in c and "credential" in c for c in creds), creds

    # Delete the device: revoke cascade (deactivate) + FK SET NULL. The credential rows survive with
    # device_id NULL, so the lookup still FINDS them (known credential, no live device).
    d = admin.session.delete(f"{BASE_URL}/devices/{dev['device_id']}", timeout=30)
    d.raise_for_status()

    # Retry each orphaned credential login-limit times at the SFTP door from the owner's IP. Each
    # attempt fails (the credential is inactive now) but still charges a throttle bucket. Total =
    # 2 * _LOGIN_LIMIT = _IP_THRESHOLD charges; on revert those land on login:<ip>.
    per_cred = _LOGIN_LIMIT
    for c in creds:
        for _ in range(per_cred):
            sftp_authenticates(c["temp_username"], c["credential"])  # inactive -> fails, charges a bucket

    # The owner's web login (a regular username, so the IP bucket). On revert the IP bucket is at its
    # threshold from the orphaned client's loop, so the owner's attempt is the one that trips: 429.
    # On the fix the orphaned loops never touched login:<ip>, so this is an ordinary 401.
    owner = _login_attempt(unique("owner"), _NEVER_VALID)
    assert owner.status_code == 401, (
        f"the owner's web login was throttled ({owner.status_code}) after a DELETED device's client "
        f"looped its orphaned credentials -- the orphan spent the owner's shared IP login budget")


def _first_temp_429(username, max_attempts):
    """Loop failed web logins for a temp_ `username` until a 429, returning that response (or None)."""
    for _ in range(max_attempts):
        r = _login_attempt(username, _NEVER_VALID)
        if r.status_code == 429:
            return r
    return None


def test_a_temp_429_does_not_reveal_its_bucket_kind_in_headers(admin, temp_vault):
    """A temp_ credential's 429 at the web door must not reveal WHICH bucket it hit. The
    limit VALUE is a kind oracle -- a device bucket (30), a per-username bucket (5) and the IP bucket
    (10) each carry a different X-RateLimit-Limit -- so for a temp_ username the door emits Retry-After
    only and drops X-RateLimit-Limit / X-RateLimit-Remaining; the body is the same generic message for
    every kind. The human's password-login 429 keeps its X-RateLimit headers. So two temp_ kinds are
    indistinguishable, and only the human 429 carries the limit."""
    device_limit = configured_int_setting("RATE_LIMIT_DEVICE_SYNC_ATTEMPTS") or 30

    # A per-username (hand-out) temp_ 429: a hand-out credential looped past the login limit.
    _sess, handout = temp_login(admin)
    username_429 = _first_temp_429(handout["temp_username"], _LOGIN_LIMIT + 5)
    assert username_429 is not None, "a hand-out credential's per-username bucket never tripped"

    # A device-bucket temp_ 429: a device credential looped past the device limit.
    dev = _register_granted_device(admin, temp_vault)
    device_cred = mint_sync_cred(dev["secret"], temp_vault["id"]).json()
    device_429 = _first_temp_429(device_cred["temp_username"], device_limit + 5)
    assert device_429 is not None, "the device bucket never tripped over HTTP"

    for r in (username_429, device_429):
        assert "X-RateLimit-Limit" not in r.headers, (
            f"a temp_ 429 leaked X-RateLimit-Limit ({r.headers.get('X-RateLimit-Limit')}) -- the "
            f"bucket kind is a limit oracle")
        assert "X-RateLimit-Remaining" not in r.headers, "a temp_ 429 leaked X-RateLimit-Remaining"
    # The two temp_ kinds are indistinguishable: same body, neither carrying the limit headers.
    assert username_429.text == device_429.text, (
        "two temp_ 429 kinds returned different bodies -- the message reveals the bucket")

    # The human 429 is unchanged: a regular username's IP-bucket 429 still carries the limit header.
    human_429 = None
    human = unique("human-hdr")
    for _ in range(_IP_THRESHOLD + 5):
        r = _login_attempt(human, _NEVER_VALID)
        if r.status_code == 429:
            human_429 = r
            break
    assert human_429 is not None, "the human login throttle did not engage"
    assert "X-RateLimit-Limit" in human_429.headers, (
        "the human password-login 429 lost its X-RateLimit-Limit header -- only temp_ 429s drop it")


@pytest.mark.skipif(
    os.environ.get("VAULT_REDIS_OUTAGE_TEST") not in ("1", "true", "yes"),
    reason="opt-in: set VAULT_REDIS_OUTAGE_TEST=1 to run the device-bucket DB-fallback test "
           "(it pauses/unpauses the Redis container via docker)",
)
def test_the_device_bucket_still_bounds_a_runaway_under_a_redis_outage(admin, temp_vault):
    """With Redis paused, the per-device bucket must STILL bound a runaway device, via the
    durable DB fallback keyed by device -- an outage must not silently collapse the per-device bound
    onto the IP bucket or disable it. The fallback is a coarse fixed window, so the trip count can
    differ from the Redis path; what matters is that it trips AND does so in the device's own bucket
    (proved by a second device on the same IP still authenticating)."""
    dev = _register_granted_device(admin, temp_vault)
    dev_b = _register_granted_device(admin, temp_vault)
    cred = mint_sync_cred(dev["secret"], temp_vault["id"]).json()
    cred_b = mint_sync_cred(dev_b["secret"], temp_vault["id"]).json()
    device_limit = configured_int_setting("RATE_LIMIT_DEVICE_SYNC_ATTEMPTS") or 30

    def _docker(*args):
        return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30)

    if _docker("inspect", _REDIS_CONTAINER).returncode != 0:
        pytest.skip(f"redis container {_REDIS_CONTAINER!r} not found")
    assert _docker("pause", _REDIS_CONTAINER).returncode == 0
    time.sleep(2)
    try:
        first_429 = None
        for i in range(device_limit + 10):
            r = _login_attempt(cred["temp_username"], _NEVER_VALID)
            if r.status_code == 429:
                first_429 = i
                break
            assert r.status_code == 401, r.text
        assert first_429 is not None, (
            "the device bucket failed OPEN during the Redis outage -- the DB fallback did not bound it")
        # Same-IP discriminator: device B still authenticates, so the DB fallback bounded device A's
        # OWN bucket, not a shared IP bucket.
        r_b = _login_attempt(cred_b["temp_username"], _NEVER_VALID)
        assert r_b.status_code == 401, (
            f"a second device on the same IP was throttled ({r_b.status_code}) under the outage -- the "
            f"DB fallback collapsed the per-device bound onto the IP bucket")
    finally:
        _docker("unpause", _REDIS_CONTAINER)
        for _ in range(30):
            s = _docker("inspect", "--format", "{{.State.Health.Status}}", _REDIS_CONTAINER)
            if s.returncode == 0 and s.stdout.strip() == "healthy":
                break
            time.sleep(2)
        wait_out_breaker_cooldown()
