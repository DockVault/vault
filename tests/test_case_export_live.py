"""Exporting a compliance case's files on a running stack (app/core/case_export.py and its routes).

The auditor of a case approved with export prepares an export with the compliance code and fetches it with their
own session: a ZIP64 archive whose SHA256SUMS `sha256sum -c` accepts, whose manifest's SHA-256 is the one the end of
the export recorded, with the files' bytes as stored. The owner is told; the vault is unchanged; the export cannot
be fetched twice or by another account; a fetch stopped early is recorded as aborted. test_case_export.py covers the
rules offline.
"""
import hashlib
import io
import json
import shutil
import subprocess
import zipfile

import pytest
import requests

from _account_change_helpers import psql
from _auditor_helpers import compliance_receipt, forget_grants, grant_right, new_auditor_account, two_admins
from _owner_notice_helpers import approved_case, forget_cases, owner_with_vault, wait_for
from conftest import BASE_URL

pytestmark = pytest.mark.integration

MINUTES = b"The board met on Monday and decided nothing."
BIG = bytes(range(256)) * 40_000          # about 10 MB, many records


@pytest.fixture
def world(admin):
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, vid = owner_with_vault(admin)
        made, vaults = [], [vid]
        try:
            yield {"admins": admins, "uma": (uma, uma_c, codes), "olga": (olga, olga_c, vid), "cases": made,
                   "vaults": vaults}
        finally:
            forget_cases(made, vaults)
            forget_grants(uma["id"])


def _upload(client, vid, name, content):
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, content, "application/octet-stream"))])
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def _prepare(world, case, file_ids):
    uma, uma_c, codes = world["uma"]
    r = uma_c.post(f"/compliance/cases/{case['id']}/exports", json={"file_ids": file_ids},
                   headers=compliance_receipt(uma_c, "compliance.case.export", uma["_password"], codes))
    assert r.status_code == 201, r.text
    return r.json()["export_id"]


def _snapshot(vid):
    return psql(f"SELECT coalesce(last_accessed::text, '') || '|' || updated_at::text FROM vaults WHERE id = '{vid}'"), \
        psql(f"SELECT count(*) FROM vault_views WHERE vault_id = '{vid}'")


def test_the_auditor_exports_once_and_the_archive_checks_out(world, tmp_path):
    _uma, uma_c, _codes = world["uma"]
    olga, olga_c, vid = world["olga"]
    files = {"minutes.txt": _upload(olga_c, vid, "minutes.txt", MINUTES),
             "big.bin": _upload(olga_c, vid, "big.bin", BIG)}
    case = approved_case(world["admins"], world["uma"], [vid], can_export=True)
    world["cases"].append(case["id"])
    before = _snapshot(vid)
    export_id = _prepare(world, case, list(files.values()))
    r = uma_c.get(f"/compliance/cases/{case['id']}/exports/{export_id}")
    assert r.status_code == 200, r.text[:300]
    assert r.headers["content-type"] == "application/zip" and "no-store" in r.headers["cache-control"]
    archive = zipfile.ZipFile(io.BytesIO(r.content))
    assert archive.testzip() is None
    manifest = json.loads(archive.read("manifest.json"))
    by_name = {row["name"]: row for row in manifest["files"]}
    assert archive.read(by_name["minutes.txt"]["entry"]) == MINUTES
    assert archive.read(by_name["big.bin"]["entry"]) == BIG
    assert all(row["integrity"] == "ok" for row in manifest["files"])
    assert not any(".." in n.split("/") or n.startswith("/") for n in archive.namelist())
    if shutil.which("sha256sum"):
        archive.extractall(tmp_path)
        check = subprocess.run(["sha256sum", "-c", "SHA256SUMS"], cwd=tmp_path, capture_output=True, text=True,
                               timeout=60)
        assert check.returncode == 0, check.stdout + check.stderr
    recorded = wait_for(lambda: psql(f"SELECT details->>'manifest_sha256' FROM audit_logs WHERE action = "
                                     f"'case_export_completed' AND case_id = '{case['id']}'") or None, timeout=30)
    assert recorded == hashlib.sha256(archive.read("manifest.json")).hexdigest()
    assert psql(f"SELECT count(*) FROM compliance_notice_outbox WHERE case_id = '{case['id']}' AND kind = 'export' "
                f"AND user_id = '{olga['id']}'") == "1", "the owner is told of the export"
    assert _snapshot(vid) == before, "exporting changes nothing of the vault"
    again = uma_c.get(f"/compliance/cases/{case['id']}/exports/{export_id}")
    assert again.status_code == 410 and again.json()["detail"]["reason"] == "export_fetched"
    assert olga_c.get(f"/compliance/cases/{case['id']}/exports/{export_id}").status_code == 404
    page = olga_c.get("/me/compliance-access").json()
    assert [c["exports"] for c in page["cases"] if c["id"] == case["id"]] == [1]


def test_an_export_needs_the_session_and_one_stopped_early_is_recorded(world):
    uma, uma_c, _codes = world["uma"]
    _olga, olga_c, vid = world["olga"]
    fid = _upload(olga_c, vid, "big.bin", BIG)
    case = approved_case(world["admins"], world["uma"], [vid], can_export=True)
    world["cases"].append(case["id"])
    export_id = _prepare(world, case, [fid])
    url = f"{BASE_URL}/compliance/cases/{case['id']}/exports/{export_id}"
    assert requests.get(url, timeout=30).status_code == 401, "no link to leak: the session is needed"
    with uma_c.session.get(url, stream=True, timeout=30) as r:
        assert r.status_code == 200
        next(r.iter_content(4096))
    # Recorded as the response ends, within seconds; not whenever the stopped response happens to be collected.
    aborted = wait_for(lambda: psql(f"SELECT count(*) FROM audit_logs WHERE action = 'case_export_aborted' "
                                    f"AND case_id = '{case['id']}'") != "0" or None, timeout=10, every=0.5)
    assert aborted, "a fetch stopped before its end is recorded at once"
    assert psql(f"SELECT count(*) FROM audit_logs WHERE action = 'case_export_completed' "
                f"AND case_id = '{case['id']}'") == "0"
    assert uma_c.get(url.replace(BASE_URL, "")).status_code == 410, "a new export is needed"
