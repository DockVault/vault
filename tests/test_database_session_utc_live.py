"""Live: on a database set to a time zone behind UTC, the app still writes and compares time in UTC.

The database's own zone is set to America/New_York (four or five hours behind UTC) and the web container
restarted, so every connection it opens is new. A plain session then runs in that zone, but the app's
sessions run in UTC: a row written with a zone-aware time (the audit log's) is within a minute of the
database's UTC clock, and a file's deadline is as far out as its vault's retention says. The zone is put
back afterwards. test_database_session_utc.py checks the option offline.
"""
import subprocess
import time
from contextlib import contextmanager

import pytest
import requests

from conftest import BASE_URL, skip_if_container_absent, unique
from _account_change_helpers import API, in_api_container, psql

pytestmark = [pytest.mark.integration, pytest.mark.disruptive]

BEHIND = "America/New_York"


def _restart_api():
    done = subprocess.run(["docker", "restart", API], capture_output=True, text=True, timeout=180)
    skip_if_container_absent(done, API)
    assert done.returncode == 0, (done.stderr or "")[:300]
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            if requests.get(f"{BASE_URL}/health", timeout=5).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    pytest.fail("the web container did not come back after a restart")


def _set_database_zone(zone):
    if zone:
        psql(f"DO $$ BEGIN EXECUTE format('ALTER DATABASE %I SET timezone TO %L', current_database(), '{zone}'); "
             "END $$")
    else:
        psql("DO $$ BEGIN EXECUTE format('ALTER DATABASE %I RESET timezone', current_database()); END $$")


@contextmanager
def _database_zone(zone):
    _set_database_zone(zone)
    try:
        _restart_api()
        yield
    finally:
        _set_database_zone(None)
        _restart_api()


def test_on_a_database_behind_utc_the_app_keeps_utc(admin):
    with _database_zone(BEHIND):
        assert psql("SHOW timezone") == BEHIND, "a plain session runs in the database's zone"
        shown = in_api_container("from sqlalchemy import text\n"
                                 "from app.core.database import SessionLocal\n"
                                 "s = SessionLocal()\n"
                                 "print(s.execute(text('SHOW timezone')).scalar())\n"
                                 "s.close()\n")
        assert shown.stdout.strip().splitlines()[-1] == "UTC", "the app's session runs in UTC"

        # A row written with a zone-aware time: the audit log's row for a failed sign-in.
        name = unique("tzprobe")
        s = requests.Session()
        s.trust_env = False
        assert s.post(f"{BASE_URL}/auth/login", json={"username": name, "password": "not-it-1"},
                      timeout=30).status_code == 401
        lag = None
        for _ in range(20):
            lag = psql("SELECT abs(extract(epoch FROM timestamp - (now() AT TIME ZONE 'utc'))) FROM audit_logs "
                       f"WHERE username = '{name}' ORDER BY timestamp DESC LIMIT 1")
            if lag:
                break
            time.sleep(0.5)
        assert lag and float(lag) < 60, f"the audit row is {lag} seconds from UTC"

        # A file's deadline: five minutes out, and the file is there now.
        v = admin.create_vault()
        try:
            r = admin.patch(f"/vaults/{v['id']}/settings",
                            json={"expire_files_after_days": 5, "expire_files_unit": "minutes"})
            assert r.status_code == 200, r.text
            r = admin.post(f"/vaults/{v['id']}/files", files=[("files", ("on-time.txt", b"x", "text/plain"))])
            assert r.status_code in (200, 201), r.text
            fid = r.json()["files"][0]["id"]
            ahead = float(psql("SELECT extract(epoch FROM expires_at - (now() AT TIME ZONE 'utc')) FROM files "
                               f"WHERE id = '{fid}'"))
            assert 240 < ahead <= 301, ahead
            listed = admin.get(f"/vaults/{v['id']}/files").json()["items"]
            assert any(it.get("id") == fid for it in listed)
        finally:
            admin.delete_vault(v["id"])
