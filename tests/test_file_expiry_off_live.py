"""Live: a vault whose file expiry is off never loses a file to it.

Before 0.32.6 a file's deadline was stamped at upload and never read, so an owner who once set "expire
files after 7 days" and later turned it off still had files carrying past deadlines. Enforcement would
have deleted them within a minute of the first boot. Two checks against a running stack:

* Turning a vault's expiry off takes the deadline off every file in it, including one already past
  its deadline that the sweep has not reached yet; the files survive a sweep. Turning it back on, or
  changing the value, gives no existing file a new deadline.
* A deadline an earlier version left in a vault whose expiry is off (written straight into the
  database) is never acted on by the sweep, and the startup step the web process runs before its
  first sweep takes it off.

The sweep normally runs once a minute in the web process. These tests run it on demand, inside the
web container (``file_expiry.sweep_once``), after a control file that is really due proves the run
deletes what it should. tests/test_file_expiry_off.py covers the same offline.
"""
import os
import subprocess
import time

import pytest

from conftest import unique, skip_if_container_absent

pytestmark = pytest.mark.integration

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_API = os.environ.get("VAULT_API_CONTAINER", "vault-api")


def _psql(sql):
    try:
        r = subprocess.run(
            ["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    skip_if_container_absent(r, _DB)
    assert r.returncode == 0, r.stderr[:300]
    return (r.stdout or "").strip()


def _in_web_container(source):
    """Run `source` in the web container, the way the web process runs it. Returns its last line."""
    script = ("from app.core.config import bootstrap_entrypoint\n"
              "bootstrap_entrypoint('file-expiry-test')\n"
              "from app.core import file_expiry\n" + source)
    try:
        r = subprocess.run(["docker", "exec", "-i", _API, "python", "-c", script],
                           capture_output=True, text=True, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(r, _API)
    assert r.returncode == 0, (r.stderr or r.stdout)[-600:]
    out = r.stdout.strip()
    # The expiry functions never raise; a failure shows only as its logged event.
    assert not [l for l in out.splitlines() if "file-expiry." in l and ".failed" in l], out[-600:]
    return out.splitlines()[-1] if out else ""


def _sweep_with_control(admin):
    """Run one sweep now, and prove it ran: a control file in a vault whose expiry is on, due a
    minute ago, must be gone afterwards."""
    v = admin.create_vault()
    try:
        r = admin.patch(f"/vaults/{v['id']}/settings",
                        json={"expire_files_after_days": 1, "expire_files_unit": "days"})
        assert r.status_code == 200, r.text
        control = _upload(admin, v["id"], unique("control") + ".txt", b"due")
        _psql(f"UPDATE files SET expires_at = (now() AT TIME ZONE 'utc') - interval '1 minute' "
              f"WHERE id = '{control}'")
        _in_web_container("print(file_expiry.sweep_once())")
        assert _psql(f"SELECT count(*) FROM files WHERE id = '{control}'") == "0", \
            "the control file is due and was not swept: the sweep did not run"
    finally:
        admin.delete_vault(v["id"])


def _upload(client, vid, name, content):
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))])
    assert r.status_code in (200, 201), r.text
    return r.json()["files"][0]["id"]


def _names(client, vid):
    r = client.get(f"/vaults/{vid}/files")
    assert r.status_code == 200, r.text
    return {it["name"] for it in r.json()["items"] if it.get("type") == "file"}


def _deadline(fid):
    return _psql(f"SELECT coalesce(expires_at::text, 'none') FROM files WHERE id = '{fid}'")


def _modified(fid):
    return _psql(f"SELECT updated_at::text FROM files WHERE id = '{fid}'")


class _SweepKeptOff:
    """Hold a file's row FOR KEY SHARE until released.

    The sweep locks the rows it deletes FOR UPDATE SKIP LOCKED, which KEY SHARE blocks, so it
    skips this file; clearing a deadline is an UPDATE of a column that is not a key, which takes
    FOR NO KEY UPDATE and is not blocked. So the file can be past its deadline while a request
    changes the vault's expiry, without the sweep deleting it first."""

    def __init__(self, file_id):
        self.file_id = file_id
        self.marker = unique("keyshare")
        self.proc = None

    def __enter__(self):
        self.proc = subprocess.Popen(
            ["docker", "exec", "-i", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-q",
             "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.proc.stdin.write(
            (f"BEGIN;\nSELECT /* {self.marker} */ id FROM files WHERE id = '{self.file_id}' "
             f"FOR KEY SHARE;\n").encode())
        self.proc.stdin.flush()
        deadline = time.time() + 30
        while time.time() < deadline:
            held = _psql("SELECT count(*) FROM pg_stat_activity WHERE state = 'idle in transaction' "
                         f"AND query LIKE '%{self.marker}%'")
            if held == "1":
                return self
            if self.proc.poll() is not None:
                break
            time.sleep(0.2)
        self.release()
        raise AssertionError("the holding session never took the row lock")

    def release(self):
        if self.proc is None:
            return
        try:
            self.proc.stdin.write(b"ROLLBACK;\n\\q\n")
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc = None

    def __exit__(self, *exc):
        self.release()


def test_turning_expiry_off_takes_every_deadline_off_and_the_files_survive_a_sweep(admin):
    v = admin.create_vault()
    vid = v["id"]
    try:
        r = admin.patch(f"/vaults/{vid}/settings",
                        json={"expire_files_after_days": 1, "expire_files_unit": "minutes"})
        assert r.status_code == 200, r.text
        due_name, later_name = unique("due") + ".txt", unique("later") + ".txt"
        due_bytes, later_bytes = b"past its deadline", b"not yet due"
        due = _upload(admin, vid, due_name, due_bytes)
        later = _upload(admin, vid, later_name, later_bytes)
        assert _deadline(due) != "none" and _deadline(later) != "none"
        modified = {f: _modified(f) for f in (due, later)}

        with _SweepKeptOff(due):
            _psql(f"UPDATE files SET expires_at = (now() AT TIME ZONE 'utc') - interval '1 minute' "
                  f"WHERE id = '{due}'")
            modified[due] = _modified(due)
            assert due_name not in _names(admin, vid), "past its deadline: gone from the listing"
            # The owner turns expiry off: 0 in the dialog, sent as null.
            r = admin.patch(f"/vaults/{vid}/settings",
                            json={"expire_files_after_days": None, "expire_files_unit": "days"})
            assert r.status_code == 200, r.text
            assert _deadline(due) == "none" and _deadline(later) == "none"
            assert {f: _modified(f) for f in (due, later)} == modified, \
                "removing a deadline does not change a file's modified time"
            assert {due_name, later_name} <= _names(admin, vid)

        _sweep_with_control(admin)
        for fid, content in ((due, due_bytes), (later, later_bytes)):
            got = admin.get(f"/vaults/{vid}/files/{fid}/download")
            assert got.status_code == 200 and got.content == content
        assert _psql(f"SELECT file_count || '|' || total_size_bytes FROM vaults "
                     f"WHERE id = '{vid}'") == f"2|{len(due_bytes) + len(later_bytes)}"

        # Turning expiry back on, or changing its value, gives no existing file a deadline; each
        # file uploaded from then on gets one, and keeps it when the value changes again.
        r = admin.patch(f"/vaults/{vid}/settings",
                        json={"expire_files_after_days": 5, "expire_files_unit": "days"})
        assert r.status_code == 200, r.text
        assert _deadline(due) == "none" and _deadline(later) == "none"
        fresh = _upload(admin, vid, unique("fresh") + ".txt", b"new")
        lead = float(_psql(f"SELECT extract(epoch FROM expires_at - created_at) FROM files "
                           f"WHERE id = '{fresh}'"))
        assert 5 * 86400 - 60 < lead <= 5 * 86400, lead
        stamped = _deadline(fresh)
        r = admin.patch(f"/vaults/{vid}/settings",
                        json={"expire_files_after_days": 30, "expire_files_unit": "days"})
        assert r.status_code == 200, r.text
        assert _deadline(fresh) == stamped, "a changed value does not re-date a file"
        # 0 is off, like a blank; a value below 0 is refused and changes nothing.
        r = admin.patch(f"/vaults/{vid}/settings", json={"expire_files_after_days": -1})
        assert r.status_code == 400, r.text
        assert _deadline(fresh) == stamped
        r = admin.patch(f"/vaults/{vid}/settings", json={"expire_files_after_days": 0})
        assert r.status_code == 200, r.text
        assert _deadline(fresh) == "none"
        assert _psql(f"SELECT coalesce(expire_files_after_days::text, 'off') FROM vaults "
                     f"WHERE id = '{vid}'") == "off"
    finally:
        admin.delete_vault(vid)


@pytest.mark.parametrize("stored_off", ["NULL", "0"])
def test_a_deadline_an_earlier_version_left_is_never_swept_and_is_cleared_at_startup(admin,
                                                                                  stored_off):
    v = admin.create_vault()
    vid = v["id"]
    try:
        name, content = unique("old") + ".txt", b"uploaded while expiry was on, long ago"
        fid = _upload(admin, vid, name, content)
        # As an earlier version left it: the vault's expiry turned off, the file's deadline kept.
        _psql(f"UPDATE vaults SET expire_files_after_days = {stored_off} WHERE id = '{vid}'")
        _psql(f"UPDATE files SET expires_at = (now() AT TIME ZONE 'utc') - interval '3 days' "
              f"WHERE id = '{fid}'")
        modified = _modified(fid)

        # The sweep never acts on it: its vault's expiry is off.
        _sweep_with_control(admin)
        assert _psql(f"SELECT count(*) FROM files WHERE id = '{fid}'") == "1"
        # The read paths take a deadline at its word, which is why the startup step exists.
        assert name not in _names(admin, vid)

        # The startup step, as the web process runs it at boot before the sweep's first run.
        _in_web_container("print(file_expiry.prepare_at_startup())")
        assert _deadline(fid) == "none" and _modified(fid) == modified
        assert name in _names(admin, vid)
        got = admin.get(f"/vaults/{vid}/files/{fid}/download")
        assert got.status_code == 200 and got.content == content

        _sweep_with_control(admin)
        assert _psql(f"SELECT count(*) FROM files WHERE id = '{fid}'") == "1"
        # A second boot has nothing left to clear here.
        _in_web_container("print(file_expiry.prepare_at_startup())")
        assert _deadline(fid) == "none"
    finally:
        admin.delete_vault(vid)
