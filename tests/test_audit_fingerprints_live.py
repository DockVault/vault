"""Fingerprints on a running stack (app/core/audit_fingerprints.py).

At the fingerprint level an upload's file name is kept only as its vault's fingerprint, and the database holds
no copy of the name; the vault's owner sees and exports the fingerprint, an administrator who is not in the
vault sees and exports nothing of it. A name typed at a failed sign-in is kept as its fingerprint too.
test_audit_fingerprints.py covers the rules offline.
"""
import uuid

import pytest
import requests

from conftest import ApiClient, BASE_URL, unique
from _account_change_helpers import psql, reset_sign_in_throttle
from _recording_levels import levels_restored, store, wait_for  # noqa: F401 -- a fixture

pytestmark = pytest.mark.integration


@pytest.fixture
def other_admin(admin):
    user = admin.create_user(role="admin")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    yield client
    admin.delete_user(user["id"])


def _events(client, **params):
    r = client.get("/activity/events", params=params)
    assert r.status_code == 200, r.text[:200]
    return {e["id"]: e for e in r.json()["events"]}


def test_a_file_name_is_kept_as_its_vaults_fingerprint_for_its_readers_only(admin, other_admin, temp_vault,
                                                                             levels_restored):
    version = store(dict(levels_restored, names="fingerprint"))
    vid = temp_vault["id"]
    name = f"fp-probe-{uuid.uuid4().hex}.txt"
    up = admin.post(f"/vaults/{vid}/files", files=[("files", (name, b"0123456789", "text/plain"))])
    assert up.status_code in (200, 201), up.text[:200]
    found = wait_for(lambda: psql(
        "SELECT id, recorded->'names'->>'vault', recorded->'names'->'values'->'file_name'->>'fp' FROM audit_logs "
        f"WHERE details->>'vault_id' = '{vid}' AND privacy_version = {version} "
        "AND recorded->'names'->'values' ? 'file_name' ORDER BY timestamp DESC LIMIT 1"))
    row_id, keyed_vault, fingerprint = found.split("|")
    assert keyed_vault == vid and fingerprint.startswith("fp1:")
    # Nowhere in the audit log, in any column.
    assert psql(f"SELECT count(*) FROM audit_logs WHERE audit_logs::text LIKE '%{name}%'") == "0"

    mine = _events(admin, ids=row_id)[row_id]
    assert mine["recorded_names"] == {"file_name": {"fingerprint": fingerprint}}
    theirs = _events(other_admin, ids=row_id)[row_id]
    assert theirs["recorded_names"] is None
    assert fingerprint not in str(theirs)

    own_export = admin.get("/activity/export", params={"format": "csv", "vault_id": vid})
    their_export = other_admin.get("/activity/export", params={"format": "csv", "vault_id": vid})
    assert own_export.status_code == their_export.status_code == 200
    assert fingerprint in own_export.text
    assert fingerprint not in their_export.text and vid in their_export.text


def test_a_typed_name_is_kept_as_its_fingerprint(admin, levels_restored):
    version = store(dict(levels_restored, signin_names="fingerprint"))
    reset_sign_in_throttle()
    agent = f"fingerprint-probe/{uuid.uuid4().hex}"
    typed = unique("ghost")
    r = requests.post(f"{BASE_URL}/auth/login", json={"username": typed, "password": "wrong-password"},
                      headers={"User-Agent": agent}, timeout=30)
    assert r.status_code in (401, 429)
    found = wait_for(lambda: psql(
        "SELECT id, coalesce(username, ''), recorded->>'signin_name', privacy_version FROM audit_logs "
        f"WHERE user_agent = '{agent}' AND action = 'login_failure'"))
    row_id, username, fingerprint, stamped = found.split("|")
    assert (username, int(stamped)) == ("", version) and fingerprint.startswith("fp1:")
    assert psql(f"SELECT count(*) FROM audit_logs WHERE audit_logs::text LIKE '%{typed}%'") == "0"
    shown = _events(admin, ids=row_id)[row_id]
    assert shown["signin_fingerprint"] == fingerprint and shown["username"] is None
    reset_sign_in_throttle()
