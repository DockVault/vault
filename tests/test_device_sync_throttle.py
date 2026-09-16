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


def _attempt_from_device(admin, dev, temp_vault, n_attempts):
    """Make n_attempts web-login attempts with the device's credentials, counting ATTEMPTS not mints.

    The device bucket is charged on EVERY attempt (success or failure), so once the per-device
    credential cap (shipped default 10, not raised in CI) refuses more mints we keep attempting with
    already-minted usernames — the 11th attempt does not need an 11th mint. Distinct usernames are
    used as far as the cap allows, so on the reverted code each attempt lands a fresh charge on the
    shared IP bucket before any single username's own bucket trips. Returns the usernames minted."""
    names = _mint_many(admin, dev, temp_vault, n_attempts)
    # At least two distinct usernames, so on the reverted code the shared IP bucket really fills from
    # distinct-username charges rather than one username's own bucket tripping first and masking it.
    assert len(names) >= 2, f"expected at least 2 device credentials for the burst, got {len(names)}"
    for i in range(n_attempts):
        r = _login_attempt(names[i % len(names)], _NEVER_VALID)
        assert r.status_code in (401, 429), r.text
    return names


def test_a_looping_device_does_not_lock_out_the_human_web_login(admin, temp_vault):
    """(a) A device's sync auths — across DISTINCT single-use credentials, as a real run mints them —
    must not exhaust the human's shared per-IP login bucket. Distinct usernames are the point: each
    has its own login-username bucket, so on the pre-fix code nothing shields the shared IP bucket
    from filling, and the human is locked out. On the fixed code every one is charged to the device's
    own bucket instead, so the IP bucket is untouched."""
    dev = _register_granted_device(admin, temp_vault)
    # Make _IP_THRESHOLD device attempts. On the reverted code each charges login:<ip> once, filling
    # the shared IP bucket exactly to its limit — so the human's OWN next attempt is the one that
    # tips it over (the limit + 1) and returns 429. On the fixed code every attempt is charged to the
    # device's own bucket, so the human's is the first on login:<ip> and returns 401. Counting
    # attempts, not mints, keeps this within the per-device credential cap.
    _attempt_from_device(admin, dev, temp_vault, _IP_THRESHOLD)

    # The human's per-IP login bucket must be untouched: a fresh human login is an ordinary 401, not a
    # throttled 429. On the pre-fix code the device's auths above filled the shared IP bucket and the
    # human came back 429 — locked out by a sync client.
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
    cred_b = mint_sync_cred(dev_b["secret"], temp_vault["id"]).json()

    # Device A makes enough attempts to fill the shared IP bucket to its limit on the reverted code
    # (attempts, not mints — within the per-device cap). Device B's single attempt below is then the
    # one that would tip a shared IP bucket over.
    _attempt_from_device(admin, dev_a, temp_vault, _IP_THRESHOLD)

    # Device B, untouched, is answered as an ordinary refusal — not throttled. On the pre-fix code
    # device A's loop had filled the shared IP bucket and device B's attempt came back 429.
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


import re

# Headers that legitimately vary between two otherwise-identical 429s: a clock, a per-request id, the
# exact reset epoch, the live remaining count, and Content-Length (which tracks the countdown digits
# in the body). Excluded from the comparison. X-RateLimit-LIMIT is deliberately NOT excluded — it is
# the kind oracle (device 30 vs per-username 5 vs IP 10), so it must be equal across the kinds.
_VOLATILE_HEADERS = {
    "date", "retry-after", "x-ratelimit-reset", "x-ratelimit-remaining", "content-length",
    "x-request-id", "x-correlation-id", "cf-ray",
}


def _comparable(resp):
    return {k.lower(): v for k, v in resp.headers.items() if k.lower() not in _VOLATILE_HEADERS}


def _normalize_countdown(text):
    """Replace the "in N seconds" countdown (seeded at different moments per request) so two bodies
    that differ only by that number compare equal. Any bare integer becomes N."""
    return re.sub(r"\d+", "N", text or "")


def _first_ip_bucket_429(max_attempts):
    """Spray DISTINCT unknown temp_ names from one IP until a 429. Distinct names keep each name's own
    per-username bucket at 1, so the throttle that finally trips is the per-IP one — the leg whose
    pre-fix wording said '…from this IP…'. A single repeated name would trip its own username bucket
    (generic message) first and never exercise the IP leg."""
    for _ in range(max_attempts):
        r = _login_attempt("temp_" + unique("ghost"), _NEVER_VALID)
        if r.status_code == 429:
            return r
    return None


def test_a_temp_429_does_not_reveal_its_bucket_kind(admin, temp_vault):
    """A temp_ credential's 429 at the web door must not reveal WHICH bucket it hit. The bucket limit
    is a kind oracle -- device (30), per-username (5), IP (10) -- so a device-minted, a hand-out and
    an unknown temp_ username driven to 429 must be INDISTINGUISHABLE: identical status, identical
    body, and an identical header set once the values that legitimately vary (the clock, the seconds
    until reset) are set aside. The route drops the rate-limit headers for a temp_ username as defence
    in depth; the general rate-limit middleware then normalises X-RateLimit-* to one auth-class value
    for every response, so the observable property is EQUALITY across the kinds, not their absence."""
    device_limit = configured_int_setting("RATE_LIMIT_DEVICE_SYNC_ATTEMPTS") or 30

    # A hand-out (per-username bucket) temp_ 429.
    _sess, handout = temp_login(admin)
    handout_429 = _first_temp_429(handout["temp_username"], _LOGIN_LIMIT + 5)
    assert handout_429 is not None, "a hand-out credential's per-username bucket never tripped"

    # A device-linked temp_ 429. At the web door a device-linked name throttles in its per-username
    # bucket (not the device bucket — that is the SFTP door), so it trips like the hand-out; the point
    # here is that its body/headers are indistinguishable from the other kinds.
    dev = _register_granted_device(admin, temp_vault)
    device_cred = mint_sync_cred(dev["secret"], temp_vault["id"]).json()
    device_429 = _first_temp_429(device_cred["temp_username"], device_limit + 5)
    assert device_429 is not None, "the device-linked name never tripped a web-door throttle"

    # An unknown temp_ name driven to the per-IP leg (distinct names), the only leg whose pre-fix
    # wording differed ("…from this IP…").
    unknown_429 = _first_ip_bucket_429(_IP_THRESHOLD + 5)
    assert unknown_429 is not None, "the per-IP throttle never tripped for unknown names"

    kinds = {"device": device_429, "hand-out": handout_429, "unknown": unknown_429}
    statuses = {name: r.status_code for name, r in kinds.items()}
    assert len(set(statuses.values())) == 1, f"429 status differed across temp_ kinds: {statuses}"
    bodies = {name: _normalize_countdown(r.text) for name, r in kinds.items()}
    assert len(set(bodies.values())) == 1, f"429 body differed across temp_ kinds (countdown normalized): {bodies}"
    headers = {name: _comparable(r) for name, r in kinds.items()}
    ref = headers["device"]
    for name, h in headers.items():
        assert h == ref, (
            f"the {name} temp_ 429 headers differ from the device temp_ 429 headers, so the bucket "
            f"kind is observable: {name}={h} vs device={ref}")


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


def test_web_door_attempts_on_a_device_name_do_not_reach_the_device_bucket(admin, temp_vault):
    """At the web door a device-linked name throttles in its per-username bucket, like a hand-out
    name, and never in the device's SFTP bucket. So (1) it 429s at the login limit, not the higher
    device limit — no attempt-count classifier — and (2) wrong web attempts do not drain the device's
    sync budget, so the device still authenticates at the SFTP door afterwards.

    On the reverted code a device-linked name at the web door charges the device bucket: its first
    429 comes only after ~device_limit tries (classifier), and the burst exhausts the device bucket so
    the SFTP credential is refused."""
    device_limit = configured_int_setting("RATE_LIMIT_DEVICE_SYNC_ATTEMPTS") or 30
    dev = _register_granted_device(admin, temp_vault)
    web_cred = mint_sync_cred(dev["secret"], temp_vault["id"]).json()
    sftp_cred = mint_sync_cred(dev["secret"], temp_vault["id"]).json()

    first_429 = None
    for i in range(1, device_limit + 6):
        r = _login_attempt(web_cred["temp_username"], _NEVER_VALID)
        if r.status_code == 429:
            first_429 = i
            break
        assert r.status_code == 401, r.text
    # (1) It tripped at the LOGIN limit, not the device limit — same count as any other temp_ name.
    assert first_429 is not None and first_429 <= _LOGIN_LIMIT + 1, (
        f"a device-linked name 429'd at attempt {first_429} at the web door — that is the device "
        f"bucket ({device_limit}), not the per-username login limit ({_LOGIN_LIMIT}); its trip count "
        f"classifies it as a device-sync name")

    # Keep attempting past the trip so a reverted device bucket would be well past its limit.
    for _ in range(device_limit + 5):
        _login_attempt(web_cred["temp_username"], _NEVER_VALID)

    # (2) The device's SFTP bucket is untouched: another of its credentials still authenticates at the
    # SFTP door. On revert the web burst drained the device bucket and this is refused.
    assert sftp_authenticates(sftp_cred["temp_username"], sftp_cred["credential"]), (
        "the device's SFTP credential no longer authenticates — web-door attempts drained the "
        "device's sync budget (the cross-door lockout)")
