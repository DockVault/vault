"""End-to-end HTTP behaviour of the two-section temp-credentials listing, against a running
deployment: the section split, the device DISPLAY NAME (never an id/secret), the lifecycle state
(a finished credential shows expired), and scoping (a second user's credentials never appear).

Needs a running deployment (and the SFTP door for the finished case), so it lives in the live lane;
the field contract and the browser render are pinned offline / in the UI lane respectively.
"""
import time

import pytest

from conftest import BASE_URL, unique
from _device_boundary_helpers import grant, mint_sync_cred, register_device, sftp_authenticates

pytestmark = pytest.mark.integration


def _rows(client):
    return client.session.get(f"{BASE_URL}/temp-creds/list", timeout=90).json()


def test_the_listing_splits_shared_and_per_computer_and_names_the_device(admin, temp_vault):
    handout = admin.post("/auth/temp-credentials", json={"note": unique("handout")}).json()
    dev = register_device(admin, label="my-laptop")
    grant(admin, dev["device_id"], temp_vault["id"])
    minted = mint_sync_cred(dev["secret"], temp_vault["id"]).json()

    by_name = {r["temp_username"]: r for r in _rows(admin)}
    shared = by_name[handout["temp_username"]]
    assert shared["is_device_credential"] is False and shared["device_name"] is None

    per_computer = by_name[minted["temp_username"]]
    assert per_computer["is_device_credential"] is True
    assert per_computer["device_name"] == dev["label"]         # the display NAME, not an id
    assert per_computer["lifecycle"] in ("active", "in-use", "expired")

    # Non-enumeration: the row carries no device id and no secret of any kind.
    assert "device_id" not in per_computer
    assert all("secret" not in k.lower() for k in per_computer), per_computer.keys()


def test_a_finished_device_credential_shows_expired_never_active(admin, temp_vault):
    dev = register_device(admin, label="sync-box")
    grant(admin, dev["device_id"], temp_vault["id"])
    minted = mint_sync_cred(dev["secret"], temp_vault["id"]).json()
    assert sftp_authenticates(minted["temp_username"], minted["credential"])

    # The connection closed -> the credential is finished; its row shows expired (poll for the
    # server-side close release to commit).
    expired = False
    for _ in range(20):
        row = next((r for r in _rows(admin) if r["temp_username"] == minted["temp_username"]), None)
        assert row is not None
        assert row["lifecycle"] != "active", "a finished credential briefly read active"
        if row["lifecycle"] == "expired":
            expired = True
            break
        time.sleep(0.5)
    assert expired, "a finished device credential never showed expired"


def test_a_second_user_never_sees_the_owners_device_credentials(admin, temp_vault, temp_user_client):
    dev = register_device(admin, label="owners-box")
    grant(admin, dev["device_id"], temp_vault["id"])
    minted = mint_sync_cred(dev["secret"], temp_vault["id"]).json()

    names = {r["temp_username"] for r in _rows(temp_user_client)}
    assert minted["temp_username"] not in names   # a non-admin sees only their own credentials


def test_two_concurrent_mints_at_the_per_user_cap_admit_exactly_one(admin, temp_user_client):
    # Carried pre-existing check-then-act: the per-user interactive cap. As a NON-admin (admins are
    # cap-exempt), fill to one below the cap, then fire two mints at once: the owner row lock must
    # admit exactly one and refuse the other, or the cap is exceeded.
    import threading

    pol = admin.session.get(f"{BASE_URL}/temp-passcode-policy", timeout=30).json()
    cap = pol.get("max_temp_creds_per_user") or 0
    if cap <= 0 or cap > 30:
        pytest.skip(f"per-user cap ({cap}) is unlimited or too large to race cheaply")

    def _mint(note):
        return temp_user_client.session.post(
            f"{BASE_URL}/auth/temp-credentials", json={"note": note}, timeout=60)

    first = _mint(unique("fill"))
    if first.status_code not in (200, 201):
        pytest.skip(f"this non-admin cannot mint temp credentials here ({first.status_code}); "
                    f"step-up or permissions differ on this stack")
    for _ in range(cap - 2):
        assert _mint(unique("fill")).status_code in (200, 201)

    barrier = threading.Barrier(2)
    results = []

    def _race():
        barrier.wait()
        results.append(_mint(unique("race")).status_code)

    threads = [threading.Thread(target=_race) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(90)

    admitted = sum(1 for s in results if s in (200, 201))
    refused = sum(1 for s in results if s == 409)
    assert admitted == 1 and refused == 1, (
        f"the per-user cap admitted {admitted} of two concurrent mints (expected exactly 1): {results}")
