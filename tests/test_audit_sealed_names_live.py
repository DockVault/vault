"""Names recorded in full on a running stack: sealed per row, shown under the Activity page's name rules.

At the full level an upload's file name is in recorded.names sealed beside its fingerprint, and no column of
the audit log holds it in plaintext. The vault's owner sees it as recorded; an administrator who is not in the
vault sees nothing of it; in a vault with a vault password even the owner sees only the fingerprint.
test_audit_sealed_names.py covers the rules offline.
"""
import uuid

import pytest

from conftest import ApiClient
from _account_change_helpers import psql
from _recording_levels import levels_restored, store, wait_for  # noqa: F401 -- a fixture

pytestmark = pytest.mark.integration


@pytest.fixture
def other_admin(admin):
    user = admin.create_user(role="admin")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    yield client
    admin.delete_user(user["id"])


def _upload_row(admin, vid, version, name, headers=None):
    up = admin.post(f"/vaults/{vid}/files", files=[("files", (name, b"0123456789", "text/plain"))],
                    headers=headers or {})
    assert up.status_code in (200, 201), up.text[:200]
    return wait_for(lambda: psql(
        "SELECT id FROM audit_logs "
        f"WHERE details->>'vault_id' = '{vid}' AND privacy_version = {version} "
        "AND recorded->'names'->'values'->'file_name' ? 'sealed' ORDER BY timestamp DESC LIMIT 1"))


def _event(client, row_id):
    r = client.get(f"/activity/events/{row_id}")
    assert r.status_code == 200, r.text[:200]
    return r.json()


def test_a_full_name_is_sealed_and_shown_only_to_its_readers(admin, other_admin, temp_vault, levels_restored):
    version = store(dict(levels_restored, names="full"))
    vid = temp_vault["id"]
    name = f"sealed-probe-{uuid.uuid4().hex}.txt"
    row_id = _upload_row(admin, vid, version, name)
    assert row_id
    assert psql(f"SELECT count(*) FROM audit_logs WHERE audit_logs::text LIKE '%{name}%'") == "0"
    mine = _event(admin, row_id)
    assert mine["recorded_names"]["file_name"]["name"] == name
    assert mine["recorded_names"]["file_name"]["fingerprint"].startswith("fp1:")
    theirs = _event(other_admin, row_id)
    assert theirs["recorded_names"] is None and name not in str(theirs)


def test_in_a_vault_with_a_password_the_owner_sees_only_the_fingerprint(admin, temp_vault_pw, levels_restored):
    version = store(dict(levels_restored, names="full"))
    vid = temp_vault_pw["id"]
    name = f"sealed-pw-probe-{uuid.uuid4().hex}.txt"
    row_id = _upload_row(admin, vid, version, name, headers={"X-Vault-Password": temp_vault_pw["_password"]})
    assert row_id, "the upload into the password-protected vault wrote no row with a sealed name"
    shown = _event(admin, row_id)["recorded_names"]["file_name"]
    assert "name" not in shown and shown["fingerprint"].startswith("fp1:")
