"""Signing in and minting must not fail, orphan, or burn a credential when the session cache is down.

The session cache (Redis) is a convenience over the committed database rows, not the source of
truth. When it is unavailable a correct-password login must still return a token — even for a user
who already holds a session, whose old session is terminated first — a valid single-use SFTP
credential must not be consumed without handing back a session, and a mint must not 500 while leaving
a committed credential nobody received counting against the caps. The throttle READS are deliberately
NOT covered by this: they have no database fallback, and quietly continuing past them would turn a
brute-force bound fail-open for the length of any outage — so they 500 (fail-closed), which is right.
"""
import os
import time

import pytest

from conftest import ApiClient, BASE_URL, unique
from _device_boundary_helpers import (REDIS_CONTAINER, cred_row, docker, grant,
                                      mint_sync_cred, register_device, sftp_authenticates)

# Opt-in, exactly like the repo's other Redis-pausing tests (test_login_throttle.py,
# test_api_rate_limit_classes.py): pausing the shared Redis mid-suite would, after unpause, leave
# the rate limiter's circuit breaker open for its cooldown, during which any throttle-shaped test
# reads differently — a red release build on a correct change. This module runs only in the
# dedicated outage CI step, which pauses and then waits for the container to be healthy again.
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("VAULT_REDIS_OUTAGE_TEST") not in ("1", "true", "yes"),
        reason="opt-in: set VAULT_REDIS_OUTAGE_TEST=1 to run the session-cache-outage tests "
               "(they pause/unpause the Redis container via docker)",
    ),
]


@pytest.fixture
def redis_outage():
    if docker("version").returncode != 0:
        pytest.skip("docker not available")
    if docker("inspect", REDIS_CONTAINER).returncode != 0:
        pytest.skip(f"redis container {REDIS_CONTAINER!r} not found")
    paused = docker("pause", REDIS_CONTAINER)
    assert paused.returncode == 0, f"could not pause redis: {paused.stderr}"
    time.sleep(2)  # let the app start seeing the cache as unavailable
    try:
        yield
    finally:
        docker("unpause", REDIS_CONTAINER)
        # Leave Redis the way we found it: a paused container cannot answer its own healthcheck, so
        # wait for the next successful probe rather than a fixed sleep — a following step declared
        # `condition: service_healthy` on redis fails while the verdict is stale. Mirrors the CI loop.
        for _ in range(30):
            status = docker("inspect", "--format", "{{.State.Health.Status}}", REDIS_CONTAINER)
            if status.returncode == 0 and status.stdout.strip() == "healthy":
                break
            time.sleep(2)


def test_web_login_returns_a_token_during_a_cache_outage(admin, temp_user, redis_outage):
    """A correct password signs in during the outage — including a user who already holds a session,
    the case that stayed broken until the terminate-session cache delete became best-effort too."""
    # 30 s, brought down from 90 now the session-cache writes go through the breaker: an outage
    # login pays about one socket stall, not one per raw call (measured ~2-4 s on a paused stack). The
    # contract is "returns a token, not a 500"; 30 s is generous margin for a slower CI runner while
    # still far below the pre-breaker worst case, and the CI run confirms the figure.
    first = ApiClient(BASE_URL)
    r1 = first.session.post(f"{BASE_URL}/auth/login",
                            json={"username": temp_user["_username"], "password": temp_user["_password"]},
                            timeout=30)
    assert r1.status_code == 200 and r1.json().get("access_token"), (
        f"first login during outage returned no token: {r1.status_code} {r1.text[:200]}")

    second = ApiClient(BASE_URL)
    r2 = second.session.post(f"{BASE_URL}/auth/login",
                             json={"username": temp_user["_username"], "password": temp_user["_password"]},
                             timeout=30)
    assert r2.status_code == 200 and r2.json().get("access_token"), (
        f"re-login for a user with an existing session failed during the outage: "
        f"{r2.status_code} {r2.text[:200]}")


@pytest.mark.sftp
def test_a_valid_sftp_credential_is_not_burned_during_a_cache_outage(admin, redis_outage):
    """A valid single-use credential over SFTP during the outage authenticates, or is left UNUSED —
    never refused-and-consumed, which would strand its holder the moment the cache went down."""
    # 90 s on every call below (not the ApiClient default): a paused cache makes each request pay
    # socket-timeout stalls, so a tight bound would be a false red rather than a real failure.
    tc = admin.session.post(f"{BASE_URL}/auth/temp-credentials", json={"note": unique("burn")}, timeout=90)
    assert tc.status_code in (200, 201), tc.text
    tc = tc.json()

    authed = sftp_authenticates(tc["temp_username"], tc["credential"])
    row = cred_row(admin, tc["temp_username"])
    assert row is not None, "the freshly minted credential is missing from the owner's list"
    assert authed or row["is_used"] is False, (
        f"a valid credential was refused AND consumed during the outage: authed={authed}, "
        f"is_used={row['is_used']}")


def test_mints_during_a_cache_outage_do_not_500_or_orphan(admin, temp_vault, redis_outage):
    """Both mint doors return a typed, usable credential during the outage — not a 500 that commits a
    row nobody receives, which counts against the caps until the cache recovers."""
    # 90 s on every call below (not the ApiClient default): a paused cache makes each request pay
    # socket-timeout stalls, so a tight bound would be a false red rather than a real failure.
    note = unique("outage")
    interactive = admin.session.post(f"{BASE_URL}/auth/temp-credentials", json={"note": note}, timeout=90)
    assert interactive.status_code in (200, 201), (
        f"interactive mint failed during the outage: {interactive.status_code} {interactive.text[:200]}")
    assert interactive.json().get("credential"), "interactive mint returned no usable credential"

    dev = register_device(admin)
    grant(admin, dev["device_id"], temp_vault["id"])
    minted = mint_sync_cred(dev["secret"], temp_vault["id"])
    try:
        assert minted.status_code in (200, 201), (
            f"device mint failed during the outage: {minted.status_code} {minted.text[:200]}")
        assert minted.json().get("credential"), "device mint returned no usable credential"
        device_username = minted.json()["temp_username"]

        # Order-proof, and still an orphan net: /temp-creds/list is deployment-wide for an admin, so
        # a bare before/after count flips under any concurrent mint. Filter to THIS test's own rows
        # instead — the interactive mint by its unique note, the device mint by the exact username it
        # returned (the list does not expose a device id at this version) — and assert exactly
        # one of each, not is_used. A failed mint that committed an orphan while returning non-500
        # would leave a SECOND row under the same note, so the "exactly one" still catches it.
        rows = admin.session.get(f"{BASE_URL}/temp-creds/list", timeout=90).json()
        by_note = [r for r in rows if r.get("note") == note]
        assert len(by_note) == 1 and by_note[0]["is_used"] is False, (
            f"interactive mint left {len(by_note)} rows under its note — orphan committed: {by_note}")
        by_user = [r for r in rows if r.get("temp_username") == device_username]
        assert len(by_user) == 1 and by_user[0]["is_used"] is False, (
            f"device mint's returned credential is not a single usable row: {by_user}")
    finally:
        # Still inside the outage (the fixture unpauses at teardown, after this runs), so bound it too.
        admin.session.delete(f"{BASE_URL}/devices/{dev['device_id']}", timeout=90)
