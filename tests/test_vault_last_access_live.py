"""When a vault was last opened is written at most once a minute, off the event loop, on a running stack.

Every request that works in a vault (a listing, a download, an SFTP command) opens it through
VaultService.get_vault, which wrote the vault's last_accessed and committed each time: on the event loop, which
answers every request, a wait for the disk of 0.6 to 1.6 s when it is busy, and a wait for any transaction holding
the vault's row. It is now written by a thread of its own in each process (app/core/vault_access.py), when the
stored time is more than a minute behind; the vault list and the vault's details report the latest opening.

- A listing and the vault's details answer at once while another transaction holds the vault's row; the time
  they opened it is written once the row is free.
- Openings within a minute of the stored time are not written again; the details and the list report the latest
  one all the same.
- An SFTP listing records its opening too (the SFTP server's own writer).
tests/test_vault_last_access.py holds the rules offline.
"""
import contextlib
import os
import subprocess
import time
from datetime import datetime, timedelta

import pytest

from conftest import ADMIN_PASS, ADMIN_USER, skip_if_container_absent, unique

pytestmark = pytest.mark.integration

DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
HELD = 4.0       # seconds another transaction holds the vault's row


def _psql(sql):
    out = subprocess.run(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-v", "ON_ERROR_STOP=1",
                          "-Atc", sql], capture_output=True, text=True, timeout=60)
    skip_if_container_absent(out, DB)
    assert out.returncode == 0, out.stderr[:300]
    return out.stdout.strip()


def _stored(vid):
    value = _psql(f"SELECT coalesce(last_accessed::text, '') FROM vaults WHERE id = '{vid}'")
    return datetime.fromisoformat(value) if value else None


def _db_now():
    return datetime.fromisoformat(_psql("SELECT (now() AT TIME ZONE 'utc')::text"))


def _wait_for(predicate, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return predicate()


def _reported(admin, vid):
    """last_accessed as the vault's details and the vault list report it."""
    details = admin.get(f"/vaults/{vid}", headers={"X-Access-Check": "1"})
    assert details.status_code == 200, details.text
    listed = [v for v in admin.get("/vaults").json() if v["id"] == vid]
    assert len(listed) == 1
    return (datetime.fromisoformat(details.json()["last_accessed"]),
            datetime.fromisoformat(listed[0]["last_accessed"]))


def _set_stored(vid, ago):
    _psql(f"UPDATE vaults SET last_accessed = (now() AT TIME ZONE 'utc') - interval '{ago}' WHERE id = '{vid}'")


@contextlib.contextmanager
def _row_held(vid, seconds):
    """Another transaction holds the vault's row for `seconds`, as every writer of the row takes it (an upload's
    finish checking the vault's room, a file's delete): FOR NO KEY UPDATE."""
    sql = (f"BEGIN; SELECT id FROM vaults WHERE id = '{vid}' FOR NO KEY UPDATE; SELECT pg_sleep({seconds}); "
           "COMMIT;")
    holder = subprocess.Popen(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-Atc", sql],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        # The row lock gives the holder a transaction id: its lock shows once the row is taken.
        held = _wait_for(lambda: _psql(
            "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid "
            f"WHERE l.locktype = 'transactionid' AND l.granted AND a.query LIKE '%FOR NO KEY UPDATE; SELECT pg_sleep(%' "
            f"AND a.query LIKE '%{vid}%'") != "0", 15)
        assert held, "the row was not taken"
        yield
    finally:
        holder.wait(timeout=seconds + 30)
        assert holder.returncode == 0, holder.stderr.read()[:300]


def test_a_listing_and_the_details_answer_while_the_vaults_row_is_held(admin, temp_vault):
    vid = temp_vault["id"]
    _set_stored(vid, "10 minutes")              # more than a minute behind: this opening is written
    with _row_held(vid, HELD):
        start = time.monotonic()
        listing = admin.get(f"/vaults/{vid}/files")
        listing_took = time.monotonic() - start
        opened = _db_now()
        start = time.monotonic()
        details = admin.get(f"/vaults/{vid}")
        details_took = time.monotonic() - start
        still = _stored(vid)
    assert listing.status_code == 200 and details.status_code == 200, (listing.text, details.text)
    assert listing_took < 1.0 and details_took < 1.0, (
        f"a listing took {listing_took:.2f} s and the details {details_took:.2f} s while another transaction held "
        f"the vault's row for {HELD} s")
    # The row was held, so nothing was written yet; the details report the opening all the same.
    assert still < opened - timedelta(minutes=5), still
    reported = datetime.fromisoformat(details.json()["last_accessed"])
    assert abs(reported - opened) < timedelta(seconds=5), (reported, opened)
    # Once the row is free, the opening is written: nothing is lost.
    assert _wait_for(lambda: _stored(vid) >= opened - timedelta(seconds=5), 15), (_stored(vid), opened)


def test_openings_within_a_minute_are_written_once_and_reported_as_the_latest(admin, temp_vault):
    vid = temp_vault["id"]
    _set_stored(vid, "10 minutes")
    assert admin.get(f"/vaults/{vid}/files").status_code == 200
    first_opened = _db_now()
    assert _wait_for(lambda: _stored(vid) >= first_opened - timedelta(seconds=5), 15), _stored(vid)
    written = _stored(vid)
    for _ in range(6):
        time.sleep(1)
        assert admin.get(f"/vaults/{vid}/files").status_code == 200
    last_opened = _db_now()
    time.sleep(2)
    assert _stored(vid) == written, "opened again within the minute, and written again"
    for reported in _reported(admin, vid):
        assert reported > written + timedelta(seconds=4), (reported, written)
        assert abs(reported - last_opened) < timedelta(seconds=5), (reported, last_opened)


def test_an_sftp_listing_records_its_opening(admin, temp_vault):
    paramiko = pytest.importorskip("paramiko")
    if not ADMIN_PASS:
        pytest.skip("No admin password (set VAULT_ADMIN_PASS)")
    vid, name = temp_vault["id"], temp_vault["name"]
    marker = unique("seen") + ".txt"
    r = admin.post(f"/vaults/{vid}/files", files=[("files", (marker, b"x", "text/plain"))])
    assert r.status_code == 200, r.text
    _set_stored(vid, "10 minutes")
    transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    transport.banner_timeout = 30
    try:
        transport.connect(username=ADMIN_USER, password=ADMIN_PASS)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            opened = _db_now()
            assert marker in sftp.listdir(f"/{name}")
        finally:
            sftp.close()
    finally:
        transport.close()
    assert _wait_for(lambda: _stored(vid) >= opened - timedelta(seconds=5), 15), (_stored(vid), opened)
