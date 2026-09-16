"""End-to-end credential lifecycle against a running deployment: the cap frees when a connection
CLOSES (not at first-auth, not at a lazy sweep), two concurrent mints at the cap boundary admit
exactly one, and a finished single-use credential no longer authenticates.

These need a real database (the per-device mint holds a row lock across its cap check + insert) and
the real SFTP door (the close hook fires in the connection-teardown finally), so they run in the live
lane. The slot predicate, the release, and the in-flight-safe backfill are unit-proven in
test_temp_cred_slot.py; this proves the wiring end to end -- QA's measured acceptance.
"""
import threading
import time

import pytest

from conftest import configured_int_setting
from _device_boundary_helpers import grant, mint_sync_cred, register_device, sftp_authenticates

pytestmark = [pytest.mark.integration, pytest.mark.sftp]

_MINT_OK = (200, 201)


def _granted_device(admin, vault):
    dev = register_device(admin)
    grant(admin, dev["device_id"], vault["id"])
    return dev


def _fill_to_cap(dev, vault, cap):
    creds = []
    for _ in range(cap):
        r = mint_sync_cred(dev["secret"], vault["id"])
        assert r.status_code in _MINT_OK, f"mint {len(creds)+1}/{cap} failed: {r.status_code} {r.text}"
        creds.append(r.json())
    return creds


def test_the_cap_frees_when_a_connection_closes(admin, temp_vault):
    cap = configured_int_setting("MAX_DEVICE_SYNC_CREDS_PER_DEVICE") or 10
    dev = _granted_device(admin, temp_vault)
    creds = _fill_to_cap(dev, temp_vault, cap)

    # At the cap: the next mint is refused with the per-device cap 409.
    assert mint_sync_cred(dev["secret"], temp_vault["id"]).status_code == 409

    # Use ONE credential over SFTP and let the connection close. The slot frees on the server's own
    # connection-close, not at first-auth -- so it is the CLOSE that lets the next mint through.
    assert sftp_authenticates(creds[0]["temp_username"], creds[0]["credential"]), \
        "the credential did not authenticate at the SFTP door"

    # The release commits server-side just after the client closes; poll briefly for the freed slot.
    freed = False
    for _ in range(20):
        r = mint_sync_cred(dev["secret"], temp_vault["id"])
        if r.status_code in _MINT_OK:
            freed = True
            break
        assert r.status_code == 409, f"unexpected mint status while waiting for the freed slot: {r.status_code}"
        time.sleep(0.5)
    assert freed, "the cap slot did not free after the credential's connection closed"


def test_two_concurrent_mints_at_the_cap_boundary_admit_exactly_one(admin, temp_vault):
    # The carried check-then-act race: 'is this device at its cap' and 'take a slot' must be one
    # atomic step (the mint holds the device row lock across its cap check and its insert), or two
    # concurrent mints at the boundary both pass the check and the cap is exceeded.
    cap = configured_int_setting("MAX_DEVICE_SYNC_CREDS_PER_DEVICE") or 10
    dev = _granted_device(admin, temp_vault)
    _fill_to_cap(dev, temp_vault, cap - 1)  # leave exactly ONE slot

    barrier = threading.Barrier(2)
    results = []

    def _mint():
        barrier.wait()  # release both threads together to maximise the overlap
        results.append(mint_sync_cred(dev["secret"], temp_vault["id"]).status_code)

    threads = [threading.Thread(target=_mint) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(90)

    admitted = sum(1 for s in results if s in _MINT_OK)
    refused = sum(1 for s in results if s == 409)
    assert admitted == 1 and refused == 1, (
        f"the cap boundary admitted {admitted} of two concurrent mints (expected exactly 1): {results}")


def test_a_finished_single_use_credential_no_longer_authenticates_at_the_sftp_door(admin, temp_vault):
    dev = _granted_device(admin, temp_vault)
    cred = mint_sync_cred(dev["secret"], temp_vault["id"]).json()
    assert sftp_authenticates(cred["temp_username"], cred["credential"]), "first use should authenticate"

    # After its connection closed the credential is finished (single-use spent + slot released): a
    # second auth at the SFTP door is refused. Poll briefly in case the close commit lags the client.
    still_authing = True
    for _ in range(10):
        if not sftp_authenticates(cred["temp_username"], cred["credential"]):
            still_authing = False
            break
        time.sleep(0.5)
    assert still_authing is False, "a finished single-use credential still authenticated at the SFTP door"
