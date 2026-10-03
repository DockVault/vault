"""Saving the recording levels on a running stack (app/api/recording_levels_router.py).

A user who is not an administrator is refused; an administrator without the password receipt is asked for it
and nothing is saved; levels that record less than earlier releases are refused while an SFTP server of another
version has reported in; a save with the password writes the next version with its audit row, which the
history lists and the SFTP server records under. The levels are set back afterwards.
"""
import os
import time
import uuid

import paramiko
import pytest

from _account_change_helpers import psql
from _recording_levels import KEYS, latest, levels_restored, wait_for  # noqa: F401 -- a fixture

pytestmark = pytest.mark.integration

ACTION = "admin.audit_privacy.write"
SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))


def _receipt(client, password):
    r = client.post("/auth/second-factor/step-up", json={"action": ACTION, "method": "password", "code": password})
    assert r.status_code == 200, r.text
    return r.json()["receipt"]


def _put(client, levels, password=None):
    headers = {"X-Second-Factor": _receipt(client, password)} if password else {}
    return client.put("/settings/recording", json={"levels": levels}, headers=headers)


def test_a_user_who_is_not_an_administrator_is_refused(temp_user_client):
    assert temp_user_client.get("/settings/recording").status_code == 403
    assert temp_user_client.put("/settings/recording", json={"levels": {"ip": "none"}}).status_code == 403


def test_without_the_password_nothing_is_saved(admin, levels_restored):
    before, _ = latest()
    r = _put(admin, {"ip": "shortened"})
    assert r.status_code == 403
    assert r.json()["detail"]["second_factor_required"] is True and r.json()["detail"]["action"] == ACTION
    assert latest()[0] == before


def test_an_older_sftp_server_that_reported_in_blocks_recording_less(admin, admin_creds, levels_restored):
    before, _ = latest()
    process = f"live-test-{uuid.uuid4().hex[:8]}"
    psql("INSERT INTO sftp_processes (id, version, host, started_at, seen_at) VALUES "
         f"('{process}', '0.30.0', 'old-sftp', now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc')")
    try:
        r = _put(admin, {"ip": "shortened"}, admin_creds["password"])
        assert r.status_code == 409 and "0.30.0" in r.json()["detail"], r.text
        assert latest()[0] == before
    finally:
        psql(f"DELETE FROM sftp_processes WHERE id = '{process}'")


def test_a_save_with_the_password_writes_a_version_the_sftp_server_records_under(admin, admin_creds, temp_user,
                                                                                levels_restored):
    before, _ = latest()
    r = _put(admin, {"ip": "shortened", "signin_names": "fingerprint"}, admin_creds["password"])
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "saved" and out["version"] == before + 1
    assert out["history"][0]["version"] == before + 1 and out["history"][0]["by"] == admin_creds["username"]
    row = psql("SELECT ip, signin_names, reason, created_by_name FROM audit_privacy_policies "
               f"WHERE version = {before + 1}")
    assert row == f"shortened|fingerprint|admin|{admin_creds['username']}"
    audit = psql("SELECT username, details->'levels'->>'ip' FROM audit_logs WHERE action = 'audit_privacy_changed' "
                 f"AND resource_id = '{before + 1}'")
    assert audit == f"{admin_creds['username']}|shortened"
    # The same levels again are no new version.
    again = _put(admin, {"ip": "shortened", "signin_names": "fingerprint"}, admin_creds["password"])
    assert again.json()["status"] == "unchanged" and latest()[0] == before + 1
    # The SFTP server reads the new version and records under it.
    started = psql("SELECT now() AT TIME ZONE 'utc'")
    time.sleep(8)
    ghost = f"ghost-{uuid.uuid4().hex[:12]}"
    for name in (ghost, temp_user["_username"]):
        t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
        t.banner_timeout = 30
        try:
            with pytest.raises(paramiko.AuthenticationException):
                t.connect(username=name, password="definitely-not-the-password")
        finally:
            t.close()

    def both():
        out = psql("SELECT privacy_version, coalesce(ip_address, ''), coalesce(recorded->>'signin_name', ''), "
                   "coalesce(username, '') FROM audit_logs WHERE action = 'login_failure' AND channel = 'sftp' "
                   f"AND timestamp >= '{started}' ORDER BY timestamp")
        return out if len(out.splitlines()) >= 2 else ""

    typed, account = [line.split("|") for line in wait_for(both).splitlines()[:2]]
    assert (int(typed[0]), typed[1], typed[3]) == (before + 1, "", "") and typed[2].startswith("fp1:")
    # A wrong password for an account names the account, whatever the level of typed names.
    assert (int(account[0]), account[1], account[2], account[3]) == (before + 1, "", "", temp_user["_username"])


def test_put_settings_refuses_the_levels(admin):
    r = admin.put("/settings", json={"recording_levels": {"ip": "none"}})
    assert r.status_code == 400 and "Activity and records" in r.json()["detail"]
