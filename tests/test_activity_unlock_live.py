"""Unlocking a password-protected vault's names on the Activity page, on a running stack.

An administrator who is not in the vault is refused; a wrong password is refused, counted on the vault-password
throttle and recorded; the right one gives a receipt with which the Events list shows the file's name as it was
recorded, and without which (or with another session's, or for another vault) it stays hidden. At the
fingerprint level the unlocked name is a fingerprint. The levels are set back afterwards.
"""
import os
import subprocess
import uuid

import pytest

from conftest import ApiClient
from _account_change_helpers import psql
from _recording_levels import levels_restored, store, wait_for  # noqa: F401 -- a fixture

pytestmark = pytest.mark.integration

HIDDEN = "Name hidden: the vault has a password"
REDIS = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")


@pytest.fixture
def other_admin(admin):
    user = admin.create_user(role="admin")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    yield client
    admin.delete_user(user["id"])


def _upload(admin, vault, name):
    up = admin.post(f"/vaults/{vault['id']}/files", files=[("files", (name, b"0123456789", "text/plain"))],
                    headers={"X-Vault-Password": vault["_password"]})
    assert up.status_code in (200, 201), up.text[:200]
    return wait_for(lambda: psql("SELECT id FROM audit_logs WHERE details->>'vault_id' = '%s' AND resource_type = "
                                 "'file' AND recorded->'names'->'values' ? 'file_name' ORDER BY timestamp DESC "
                                 "LIMIT 1" % vault["id"]))


def _item(client, row_id, header=None):
    r = client.get(f"/activity/events/{row_id}", headers={"X-Activity-Unlock": header} if header else {})
    assert r.status_code == 200, r.text[:200]
    return r.json()["names"]["item"]


def _throttle(vault_id, user_id):
    r = subprocess.run(["docker", "exec", REDIS, "redis-cli", "GET", f"rate_limit:vault:{vault_id}:{user_id}"],
                       capture_output=True, text=True, timeout=30)
    return (r.stdout or "").strip()


def test_an_unlock_shows_the_name_as_recorded_for_its_session_and_vault_only(admin, admin_creds, other_admin,
                                                                            temp_vault, temp_vault_pw, levels_restored):
    store(dict(levels_restored, names="full"))
    name = f"unlock-probe-{uuid.uuid4().hex}.txt"
    row_id = _upload(admin, temp_vault_pw, name)
    assert _item(admin, row_id) == HIDDEN
    vid = temp_vault_pw["id"]

    # Not in the vault: refused, whatever the password.
    refused = other_admin.post(f"/activity/vaults/{vid}/unlock", json={"password": temp_vault_pw["_password"]})
    assert refused.status_code == 403

    # A wrong password: refused, counted on the vault's throttle, recorded.
    me = admin.get("/users/me").json()
    before = _throttle(vid, me["id"]) or "0"
    wrong = admin.post(f"/activity/vaults/{vid}/unlock", json={"password": "not-the-password"})
    assert wrong.status_code == 403
    assert int(_throttle(vid, me["id"]) or 0) == int(before) + 1
    assert psql("SELECT count(*) FROM audit_logs WHERE action = 'activity_vault_unlocked' AND status = 'failure' "
                f"AND resource_id = '{vid}'") == "1"

    out = admin.post(f"/activity/vaults/{vid}/unlock", json={"password": temp_vault_pw["_password"]})
    assert out.status_code == 200, out.text[:200]
    receipt = out.json()["receipt"]
    assert temp_vault_pw["_password"] not in psql(
        f"SELECT details::text FROM audit_logs WHERE action = 'activity_vault_unlocked' AND resource_id = '{vid}' "
        "AND status = 'success'")
    assert _item(admin, row_id, f"{vid}:{receipt}") == name
    assert _item(admin, row_id) == HIDDEN                                       # without it
    assert _item(admin, row_id, f"{temp_vault['id']}:{receipt}") == HIDDEN       # for another vault
    again = ApiClient()
    again.login(admin_creds["username"], admin_creds["password"])
    assert _item(again, row_id, f"{vid}:{receipt}") == HIDDEN                    # from another session
    listed = admin.get("/activity/events", params={"ids": row_id}, headers={"X-Activity-Unlock": f"{vid}:{receipt}"})
    assert listed.json()["events"][0]["names"]["item"] == name

    # A vault with no password needs no unlock.
    assert admin.post(f"/activity/vaults/{temp_vault['id']}/unlock", json={"password": "x"}).status_code == 400


def test_a_name_recorded_as_a_fingerprint_stays_one_when_unlocked(admin, temp_vault_pw, levels_restored):
    store(dict(levels_restored, names="fingerprint"))
    row_id = _upload(admin, temp_vault_pw, f"fp-unlock-probe-{uuid.uuid4().hex}.txt")
    vid = temp_vault_pw["id"]
    receipt = admin.post(f"/activity/vaults/{vid}/unlock", json={"password": temp_vault_pw["_password"]}).json()["receipt"]
    assert _item(admin, row_id, f"{vid}:{receipt}").startswith("fp1:")
