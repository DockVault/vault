"""Signing in and minting must not fail, orphan, or burn a credential when the session cache is down.

The session cache (Redis) is a convenience over the committed database rows, not the source of
truth. When it is unavailable a correct-password login must still return a token — even for a user
who already holds a session, whose old session is terminated first — a valid single-use SFTP
credential must not be consumed without handing back a session, and a mint must not 500 while leaving
a committed credential nobody received counting against the caps. The throttle READS are deliberately
NOT covered by this: they have no database fallback, and quietly continuing past them would turn a
brute-force bound fail-open for the length of any outage — so they 500 (fail-closed), which is right.
"""
import time

import pytest

from conftest import ApiClient, BASE_URL, unique
from _device_boundary_helpers import (REDIS_CONTAINER, cred_row, docker, grant,
                                      mint_sync_cred, register_device, sftp_authenticates)

pytestmark = pytest.mark.integration


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
        time.sleep(2)


def test_web_login_returns_a_token_during_a_cache_outage(admin, temp_user, redis_outage):
    """A correct password signs in during the outage — including a user who already holds a session,
    the case that stayed broken until the terminate-session cache delete became best-effort too."""
    first = ApiClient(BASE_URL)
    r1 = first.session.post(f"{BASE_URL}/auth/login",
                            json={"username": temp_user["_username"], "password": temp_user["_password"]},
                            timeout=15)
    assert r1.status_code == 200 and r1.json().get("access_token"), (
        f"first login during outage returned no token: {r1.status_code} {r1.text[:200]}")

    second = ApiClient(BASE_URL)
    r2 = second.session.post(f"{BASE_URL}/auth/login",
                             json={"username": temp_user["_username"], "password": temp_user["_password"]},
                             timeout=15)
    assert r2.status_code == 200 and r2.json().get("access_token"), (
        f"re-login for a user with an existing session failed during the outage: "
        f"{r2.status_code} {r2.text[:200]}")


def test_a_valid_sftp_credential_is_not_burned_during_a_cache_outage(admin, redis_outage):
    """A valid single-use credential over SFTP during the outage authenticates, or is left UNUSED —
    never refused-and-consumed, which would strand its holder the moment the cache went down."""
    tc = admin.post("/auth/temp-credentials", json={"note": unique("burn")})
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
    before = len(admin.get("/temp-creds/list").json())

    interactive = admin.post("/auth/temp-credentials", json={"note": unique("outage")})
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

        after = len(admin.get("/temp-creds/list").json())
        assert after == before + 2, (
            f"credential rows grew by {after - before}, not the 2 successful mints — orphans committed")
    finally:
        admin.delete(f"/devices/{dev['device_id']}")
