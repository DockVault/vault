"""A device-minted sync credential is refused at the web login door, without leaking or spending it.

A sync credential is issued for one SFTP run. Presenting it at the interactive web login has no
legitimate purpose, and doing so today signs in as the owning account AND burns the one credential
the device needed. It is now refused with the SAME generic 401 as a wrong credential — so a
device-minted username cannot be told apart from any other by the response — and the refusal happens
before the one-time claim, so the credential still works at the SFTP door it was minted for.
"""
import pytest

from conftest import ApiClient, BASE_URL, unique
from _device_boundary_helpers import (cred_row, grant, mint_sync_cred, register_device,
                                      sftp_authenticates)

pytestmark = pytest.mark.integration


@pytest.mark.sftp
def test_a_device_minted_credential_is_refused_at_the_web_door_and_still_works_over_sftp(
        admin, temp_vault):
    dev = register_device(admin)
    try:
        grant(admin, dev["device_id"], temp_vault["id"])
        minted = mint_sync_cred(dev["secret"], temp_vault["id"])
        assert minted.status_code in (200, 201), minted.text
        cred = minted.json()

        web = ApiClient(BASE_URL)
        r = web.session.post(f"{BASE_URL}/auth/login",
                             json={"username": cred["temp_username"], "password": cred["credential"]},
                             timeout=15)
        assert r.status_code == 401, (
            f"a device-minted credential signed in at the web door: {r.status_code} {r.text[:200]}")

        # The refusal carries a distinct INTERNAL message (for the audit row and the security
        # monitor), but the wire body must be identical to any other failed login: a correct password
        # on a device credential must look exactly like a wrong password, or the 401 itself is an
        # oracle that a username is a sync credential.
        wrong = web.session.post(f"{BASE_URL}/auth/login",
                                 json={"username": cred["temp_username"], "password": "wrong-pw-xyz"},
                                 timeout=15)
        assert r.status_code == wrong.status_code and r.text == wrong.text, (
            "the device-credential refusal body differs from a wrong-password body — a wire oracle")

        row = cred_row(admin, cred["temp_username"])
        assert row is not None and row["is_used"] is False, (
            f"the web-door refusal spent the credential: {row}")

        assert sftp_authenticates(cred["temp_username"], cred["credential"]), (
            "the credential no longer works at the SFTP door it was minted for")
    finally:
        admin.delete(f"/devices/{dev['device_id']}")


def test_wrong_password_is_indistinguishable_across_credential_kinds(admin, temp_vault):
    """The refusal must not become an oracle: a wrong password on a device-minted username, on a
    hand-out username, and on an unknown temp_ username return the SAME status and body."""
    dev = register_device(admin)
    try:
        grant(admin, dev["device_id"], temp_vault["id"])
        device_cred = mint_sync_cred(dev["secret"], temp_vault["id"]).json()
        handout = admin.post("/auth/temp-credentials", json={"note": unique("parity")}).json()

        def login_body(username):
            web = ApiClient(BASE_URL)
            r = web.session.post(f"{BASE_URL}/auth/login",
                                 json={"username": username, "password": "definitely-wrong-xyz"},
                                 timeout=15)
            return r.status_code, r.text

        dev_status, dev_body = login_body(device_cred["temp_username"])
        ho_status, ho_body = login_body(handout["temp_username"])
        unknown_status, unknown_body = login_body("temp_" + unique("ghost"))

        assert dev_status == ho_status == unknown_status == 401, (
            f"statuses differ: device={dev_status} handout={ho_status} unknown={unknown_status}")
        assert dev_body == ho_body == unknown_body, (
            "the 401 body differs by credential kind — a device-minted username is distinguishable")
    finally:
        admin.delete(f"/devices/{dev['device_id']}")
