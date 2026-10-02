"""The recording levels on a running stack (app/core/audit_privacy.py).

The policies table starts at version 1 and refuses to change or lose a version. At the levels in force a
failed sign-in is recorded in full, stamped with the version. A version stored in the table (as the panel
stores one) is read by the web app and the SFTP server within seconds: at a shortened address and no typed
names, a failed web sign-in and a failed SFTP password keep only the network the address is in, and the
Events filters find such a row by its address and by a block. The table is set back afterwards with a newer
version. test_audit_privacy.py covers the rules offline.
"""
import os
import subprocess
import uuid

import paramiko
import pytest
import requests

from conftest import BASE_URL, unique
from _account_change_helpers import DB, psql, reset_sign_in_throttle
from _recording_levels import latest, levels_restored, store, wait_for  # noqa: F401 -- a fixture

pytestmark = pytest.mark.integration

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
KEYS = ("names", "signin_names", "emails", "ip", "user_agent")
POLICY_ONE = {"names": "none", "signin_names": "full", "emails": "full", "ip": "full", "user_agent": "full"}


def _psql_fails(sql):
    r = subprocess.run(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-v", "ON_ERROR_STOP=1",
                        "-Atc", sql], capture_output=True, text=True, timeout=30)
    return r.returncode != 0, r.stderr


_latest = latest
_store = store
_wait_for = wait_for


def test_the_table_starts_at_policy_one_and_only_grows():
    first = psql("SELECT " + ", ".join(KEYS) + ", reason, created_by_name FROM audit_privacy_policies "
                 "WHERE version = 1")
    assert first.split("|") == [POLICY_ONE[k] for k in KEYS] + ["initial", "server configuration"]
    for sql in ("UPDATE audit_privacy_policies SET ip = 'none' WHERE version = 1",
                "DELETE FROM audit_privacy_policies WHERE version = 1",
                "TRUNCATE audit_privacy_policies"):
        failed, err = _psql_fails(sql)
        assert failed and "only grows" in err, (sql, err)
    assert psql("SELECT ip FROM audit_privacy_policies WHERE version = 1") == "full"
    assert psql("SELECT count(*) FROM audit_logs WHERE action = 'audit_privacy_changed' AND resource_id = '1'") == "1"


def test_a_failed_sign_in_at_the_levels_in_force_is_recorded_in_full_with_the_version():
    version, levels = _latest()
    if levels["signin_names"] != "full" or levels["ip"] != "full":
        pytest.skip(f"the stack's levels are not full: {levels}")
    reset_sign_in_throttle()
    name = unique("nobody")
    r = requests.post(f"{BASE_URL}/auth/login", json={"username": name, "password": "wrong-password"}, timeout=30)
    assert r.status_code in (401, 429)
    row = _wait_for(lambda: psql("SELECT coalesce(ip_address, ''), privacy_version, recorded IS NULL FROM audit_logs "
                                 f"WHERE username = '{name}' AND action = 'login_failure'"))
    address, stamped, no_recorded = row.split("|")
    assert address and int(stamped) == version and no_recorded == "t"
    reset_sign_in_throttle()


def test_a_shortened_address_and_no_typed_name_on_web_and_sftp(admin, temp_user, levels_restored):
    stored = dict(levels_restored, ip="shortened", signin_names="none")
    version = _store(stored)
    reset_sign_in_throttle()
    agent = f"recording-levels-probe/{uuid.uuid4().hex}"
    typed = unique("ghost")
    r = requests.post(f"{BASE_URL}/auth/login", json={"username": typed, "password": "wrong-password"},
                      headers={"User-Agent": agent}, timeout=30)
    assert r.status_code in (401, 429)
    web = _wait_for(lambda: psql(
        "SELECT id, coalesce(username, ''), coalesce(ip_address, ''), recorded->>'ip', privacy_version, channel "
        f"FROM audit_logs WHERE user_agent = '{agent}' AND action = 'login_failure'"))
    row_id, username, address, network, stamped, channel = web.split("|")
    assert (username, address, int(stamped), channel) == ("", "", version, "web")
    assert network.endswith("/24") or network.endswith("/48"), network
    # The security record keeps the address in full for its window, whatever the levels.
    full_address = psql(f"SELECT address FROM security_records WHERE name = '{typed}'")
    assert full_address and typed not in psql(f"SELECT coalesce(recorded::text, '') FROM audit_logs WHERE id = '{row_id}'")

    started = psql("SELECT now() AT TIME ZONE 'utc'")
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    try:
        with pytest.raises(paramiko.AuthenticationException):
            t.connect(username=temp_user["_username"], password="definitely-not-the-password")
    finally:
        t.close()
    sftp = _wait_for(lambda: psql(
        "SELECT coalesce(username, ''), coalesce(ip_address, ''), recorded->>'ip', privacy_version FROM audit_logs "
        f"WHERE action = 'login_failure' AND channel = 'sftp' AND timestamp >= '{started}' "
        f"AND privacy_version = {version}"))
    s_username, s_address, s_network, s_stamped = sftp.splitlines()[0].split("|")
    assert (s_username, s_address, int(s_stamped)) == ("", "", version)
    assert s_network.endswith("/24") or s_network.endswith("/48"), s_network

    # The Events filters find the web row by its full address, and by a block wider than the network.
    found = admin.get("/activity/events", params={"ip": full_address, "action": "login_failure"})
    assert found.status_code == 200, found.text[:200]
    events = {e["id"]: e for e in found.json()["events"]}
    assert row_id in events, "an exact address did not find its shortened row"
    assert events[row_id]["ip_address"] == network and events[row_id]["privacy_version"] == version
    wide = full_address + ("/16" if "." in full_address else "/32")
    found = admin.get("/activity/events", params={"ip": wide, "action": "login_failure"})
    assert row_id in {e["id"] for e in found.json()["events"]}, "a wide block did not find the shortened row"
    assert found.json().get("recording_version") == version
    reset_sign_in_throttle()


def test_the_recorded_values_are_indexed_after_start():
    names = ("ix_audit_logs_recorded_ip", "ix_audit_logs_recorded_signin_name")
    found = _wait_for(lambda: psql(
        "SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
        f"WHERE c.relname IN {names} AND i.indisvalid") == "2", timeout=120, step=2)
    assert found


def test_a_row_whose_details_come_from_a_helper_keeps_them(admin):
    """The clean-up of unfinished uploads records what its helper counted: every key is classified, none
    dropped."""
    r = admin.post("/api/maintenance/upload-sessions/cleanup")
    assert r.status_code == 200, r.text[:200]
    row = wait_for(lambda: psql("SELECT details::text, coalesce(recorded::text, '') FROM audit_logs WHERE "
                                "action = 'upload_sessions_cleanup' ORDER BY timestamp DESC LIMIT 1"))
    details, recorded = row.split("|", 1)
    for key in ("scanned_dirs", "dirs_removed", "bytes_reclaimed", "rows_pruned", "active_sessions_kept"):
        assert f'"{key}"' in details, (key, details)
    assert "dropped" not in recorded
