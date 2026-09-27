"""Live: a copy, or a file moved into another vault, takes the destination vault's expiry rule.

What the operator and user documentation say (.env.example, the vault policies dialog): the server
writes a copy, and a file moved between vaults, as a new upload into the destination. So its
deadline is the destination vault's rule counted from the moment of the copy, whatever deadline the
source file had -- and a file moved into a vault whose expiry is off keeps no deadline at all.

The source file's deadline is set straight in the database to three hours out, a value no vault
rule here produces, so a deadline carried over would show.
"""
import os
import subprocess

import pytest

from conftest import unique, skip_if_container_absent

pytestmark = pytest.mark.integration

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


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


def _vault(admin, value, unit):
    vid = admin.create_vault()["id"]
    r = admin.patch(f"/vaults/{vid}/settings",
                    json={"expire_files_after_days": value, "expire_files_unit": unit})
    assert r.status_code == 200, r.text
    return vid


def _source_file(admin, vid):
    """A file whose deadline is three hours out."""
    r = admin.post(f"/vaults/{vid}/files",
                   files=[("files", (unique("f") + ".txt", b"a file on the move", "text/plain"))])
    assert r.status_code in (200, 201), r.text
    fid = r.json()["files"][0]["id"]
    _psql(f"UPDATE files SET expires_at = (now() AT TIME ZONE 'utc') + interval '3 hours' "
          f"WHERE id = '{fid}'")
    assert 3 * 3600 - 60 < _lead_seconds(fid) <= 3 * 3600 + 60
    return fid


def _lead_seconds(fid):
    """How long after it was written the file expires, or None for no deadline."""
    out = _psql(f"SELECT coalesce(extract(epoch FROM expires_at - created_at)::text, 'none') "
                f"FROM files WHERE id = '{fid}'")
    assert out, f"file {fid} not found"
    return None if out == "none" else float(out)


def _carry(admin, action, src_vid, fid, dest_vid, dest_folder=None):
    r = admin.post(f"/vaults/{src_vid}/files/{fid}/{action}",
                   json={"dest_vault_id": dest_vid, "dest_folder_id": dest_folder})
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_a_copy_or_a_move_between_vaults_takes_the_destination_rule(admin):
    source = _vault(admin, 30, "days")
    timed = _vault(admin, 7, "hours")
    off = _vault(admin, 0, "days")
    try:
        # Into a vault whose rule is 7 hours: 7 hours from the copy, not the source's 3 hours left.
        for action in ("copy", "move"):
            new = _carry(admin, action, source, _source_file(admin, source), timed)
            assert 7 * 3600 - 60 < _lead_seconds(new) <= 7 * 3600, action

        # Into a vault whose expiry is off: no deadline.
        for action in ("copy", "move"):
            assert _lead_seconds(_carry(admin, action, source, _source_file(admin, source), off)) \
                is None, f"a file {action}-ed into a vault with expiry off kept a deadline"

        # A copy within one vault is a new file too: the vault's 30 days, from the copy.
        r = admin.post(f"/vaults/{source}/folders", json={"name": unique("copies")})
        assert r.status_code == 200, r.text
        new = _carry(admin, "copy", source, _source_file(admin, source), source,
                     r.json()["folder"]["id"])
        assert 30 * 86400 - 60 < _lead_seconds(new) <= 30 * 86400
    finally:
        for vid in (source, timed, off):
            admin.delete_vault(vid)
