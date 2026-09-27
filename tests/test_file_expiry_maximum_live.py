"""Live: a vault's file expiry is at most 100 years, and uploads keep working whatever is stored.

Before, the vault settings took 999,999,999 days, after which every upload into the vault answered
500, and 2**40 made the settings save itself answer 500. Against a running stack:

* the settings endpoint and vault creation refuse anything over 100 years in its unit with 400 and
  leave the vault as it was, and take exactly 100 years;
* an upload into a vault at the maximum gets a deadline 100 years out;
* a longer value an earlier version stored (written straight into the database) counts as 100 years:
  the upload succeeds.

tests/test_file_expiry_maximum.py covers the same offline.
"""
import os
import subprocess

import pytest

from conftest import unique, skip_if_container_absent

pytestmark = pytest.mark.integration

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_HUNDRED_YEARS = 36_500 * 86_400


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


def _setting(vid):
    return _psql(f"SELECT coalesce(expire_files_after_days::text, 'off') || ' ' || "
                 f"coalesce(expire_files_unit, '') FROM vaults WHERE id = '{vid}'")


def _upload(client, vid):
    r = client.post(f"/vaults/{vid}/files",
                    files=[("files", (unique("f") + ".txt", b"kept for a century", "text/plain"))])
    assert r.status_code in (200, 201), r.text
    return r.json()["files"][0]["id"]


def _lead_seconds(fid):
    return float(_psql(f"SELECT extract(epoch FROM expires_at - created_at) FROM files "
                       f"WHERE id = '{fid}'"))


@pytest.mark.parametrize("value,unit,shown", [
    (999_999_999, "days", "36,500 days"),
    (2**40, "days", "36,500 days"),
    (36_501, "days", "36,500 days"),
    (876_001, "hours", "876,000 hours"),
    (52_560_001, "minutes", "52,560,000 minutes"),
])
def test_the_settings_refuse_more_than_100_years(admin, value, unit, shown):
    vid = admin.create_vault()["id"]
    try:
        r = admin.patch(f"/vaults/{vid}/settings",
                        json={"expire_files_after_days": 7, "expire_files_unit": "hours"})
        assert r.status_code == 200, r.text
        r = admin.patch(f"/vaults/{vid}/settings",
                        json={"expire_files_after_days": value, "expire_files_unit": unit})
        assert r.status_code == 400, r.text
        assert r.json()["detail"] == f"File expiry can be at most 100 years ({shown}).", r.text
        assert _setting(vid) == "7 hours", "a refused change left the vault changed"
        # Uploads keep working.
        fid = _upload(admin, vid)
        assert 7 * 3600 - 60 < _lead_seconds(fid) <= 7 * 3600
    finally:
        admin.delete_vault(vid)


def test_changing_only_the_unit_cannot_make_it_longer(admin):
    vid = admin.create_vault()["id"]
    try:
        r = admin.patch(f"/vaults/{vid}/settings",
                        json={"expire_files_after_days": 50_000, "expire_files_unit": "minutes"})
        assert r.status_code == 200, r.text
        r = admin.patch(f"/vaults/{vid}/settings", json={"expire_files_unit": "days"})
        assert r.status_code == 400, r.text
        assert _setting(vid) == "50000 minutes"
    finally:
        admin.delete_vault(vid)


def test_100_years_is_taken_and_an_upload_gets_that_deadline(admin):
    vid = admin.create_vault()["id"]
    try:
        r = admin.patch(f"/vaults/{vid}/settings",
                        json={"expire_files_after_days": 36_500, "expire_files_unit": "days"})
        assert r.status_code == 200, r.text
        assert _setting(vid) == "36500 days"
        fid = _upload(admin, vid)
        assert _HUNDRED_YEARS - 60 < _lead_seconds(fid) <= _HUNDRED_YEARS
    finally:
        admin.delete_vault(vid)


def test_a_longer_value_stored_earlier_counts_as_100_years(admin):
    vid = admin.create_vault()["id"]
    try:
        _psql(f"UPDATE vaults SET expire_files_after_days = 999999999, expire_files_unit = 'days' "
              f"WHERE id = '{vid}'")
        fid = _upload(admin, vid)
        assert _HUNDRED_YEARS - 60 < _lead_seconds(fid) <= _HUNDRED_YEARS
        # The owner can still lower it.
        r = admin.patch(f"/vaults/{vid}/settings",
                        json={"expire_files_after_days": 30, "expire_files_unit": "days"})
        assert r.status_code == 200, r.text
    finally:
        admin.delete_vault(vid)


def test_vault_creation_refuses_more_than_100_years(admin):
    r = admin.post("/vaults", json={"name": unique("vault"), "expire_files_after_days": 36_501})
    assert r.status_code == 400, r.text
    assert r.json()["detail"] == "File expiry can be at most 100 years (36,500 days)."

    v = admin.create_vault(expire_files_after_days=36_500)
    try:
        assert _setting(v["id"]) == "36500 days"
    finally:
        admin.delete_vault(v["id"])
