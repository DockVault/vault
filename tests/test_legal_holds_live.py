"""Legal holds on a running stack (app/core/legal_holds.py, the hold routes in app/api/compliance_router.py, the blob
gate in app/services/vault_service.py, app/core/legal_hold_marker.py).

  * the full flow: an administrator places a hold on a vault with the password and an authenticator code, an
    independent one confirms it; every way the web app deletes a file (a delete, a folder's delete, a same-name
    replacement, a cross-vault move, the expiry sweep) and the SFTP server's remove keep the row and the stored
    bytes, which still decrypt, while for the vault's people the file is gone; the owner is told; the storage page
    counts what is kept; an older release is kept from starting (the marker row, and the host's
    downgrade-blockers); release, undo, release again, then the purge secure-deletes and records each file;
  * a hold placed while a deletion holds the vault's row waits for it, and the next deletion is kept;
  * a hold nobody confirms lapses, and its placer cannot place another on that vault for 30 days; nor after
    releasing their own hold before anyone confirmed it;
  * the server's operator confirms a hold on the host (python -m app.core.host_compliance, as dockvault.py runs
    it) only while no administrator could, and a refusal is recorded;
  * the person who started a case releases its hold alone only while they stand as they did: not once demoted,
    nor once their auditor right is revoked (an administrator who placed it as an auditor too), nor after someone
    else changed their sign-in details, even once that change's own record is gone; an auditor lists only the cases
    they started;
  * a confirmation after the confirm deadline answers 409 and confirms nothing;
  * the purge leaves a vault whose row a placing or an undo holds for its next pass;
  * a hold is refused while an SFTP server of another version may be running;
  * a refused step is recorded under its case.

test_legal_holds.py, test_blob_gate.py, test_kept_storage.py and test_legal_hold_marker.py cover the rules
offline; test_kept_tables_live.py the triggers.
"""
import json
import os
import subprocess
import time
import uuid

import pytest

from _account_change_helpers import API, DB, in_api_container, notifications, psql
from _auditor_helpers import (compliance_receipt, forget_grants, grant_right, new_auditor_account, run_pass,
                              signed_in_with_code, two_admins)
from conftest import ADMIN_PASS, ADMIN_USER, unique

pytestmark = pytest.mark.integration

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
TEXT = {"purpose": "litigation_hold", "legal_basis": "legal_obligation",
        "justification": "Preserve the records named in the claim served last week.",
        "owner_note": "Files deleted from your vault are kept for a legal matter."}


def _upload(client, vid, name, content, folder_id=None):
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))],
                    params={"folder_id": folder_id} if folder_id else None)
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def _folder(client, vid, name):
    r = client.post(f"/vaults/{vid}/folders", json={"name": name, "parent_folder_id": None})
    r.raise_for_status()
    return r.json()["folder"]["id"]


def _place(who, vault_ids):
    account, client, codes = who
    return client.post("/compliance/holds", json={"vault_ids": vault_ids, **TEXT},
                       headers=compliance_receipt(client, "compliance.hold.place", account["_password"], codes))


def _decide(who, case_id, step, body=None):
    account, client, codes = who
    return client.post(f"/compliance/cases/{case_id}/hold/{step}", json=body,
                       headers=compliance_receipt(client, "compliance.hold.decide", account["_password"], codes))


def _kept(file_id):
    return psql(f"SELECT kept_reason || '|' || coalesce(kept_by, '') FROM held_files WHERE id = '{file_id}'")


_OPEN = """
import uuid
from app.core.authorization import PermissionService
from app.core.database import get_db_context
from app.core.models import HeldFile, Vault
from app.services.vault_service import VaultService
with get_db_context() as db:
    kept = db.get(HeldFile, uuid.UUID(FILE_ID))
    vault = db.get(Vault, kept.vault_id)
    data, name, _mime = VaultService(db, PermissionService(db))._open_stored_file(kept, vault, kept.id)
    print("OPEN=" + data.decode() + "|" + name)
"""


def _open_kept(file_id):
    out = in_api_container(f"FILE_ID = '{file_id}'\n" + _OPEN)
    return [ln for ln in out.stdout.splitlines() if ln.startswith("OPEN=")][0][5:]


def _blob_exists(file_id):
    path = psql(f"SELECT storage_path FROM held_files WHERE id = '{file_id}'") or \
        psql(f"SELECT storage_path FROM files WHERE id = '{file_id}'")
    return subprocess.run(["docker", "exec", API, "test", "-f", f"storage/{path}"], timeout=30).returncode == 0


def _forget(case_ids, vault_ids):
    """Release and purge, straight in the database, what a test left (its records are otherwise kept)."""
    for vid in vault_ids:
        psql(f"UPDATE legal_hold_vaults SET released_at = now() WHERE vault_id = '{vid}' AND released_at IS NULL")
        for table in ("held_files", "held_folders", "held_name_history"):
            psql(f"DELETE FROM {table} WHERE vault_id = '{vid}'")
    for cid in case_ids:
        psql(f"DELETE FROM compliance_cases WHERE id = '{cid}'")
    in_api_container("from app.core import legal_hold_marker\nlegal_hold_marker.check_at_start()\n")


@pytest.fixture
def admins(admin):
    with two_admins(admin) as people:
        yield people


@pytest.fixture
def vaults(admin):
    """Two vaults of the session's administrator: the one held, and another to move into."""
    made = [admin.create_vault(name=unique("held")), admin.create_vault(name=unique("other"))]
    cases = []
    try:
        yield made, cases
    finally:
        _forget(cases, [v["id"] for v in made])
        for v in made:
            admin.delete_vault(v["id"])


def test_the_full_flow_keeps_every_deletion_until_the_purge(admin, admins, vaults):
    made, cases = vaults
    vid, other = made[0]["id"], made[1]["id"]
    deleted = _upload(admin, vid, "deleted.txt", b"deleted bytes")
    folder = _folder(admin, vid, unique("dir"))
    inner = _upload(admin, vid, "inner.txt", b"inner bytes", folder_id=folder)
    replaced = _upload(admin, vid, "same.txt", b"first version")
    moved = _upload(admin, vid, "moved.txt", b"moved bytes")
    me = admin.get("/users/me").json()

    # Without the code and the password, nothing is placed.
    ada, ada_c, _codes = admins["ada"]
    assert ada_c.post("/compliance/holds", json={"vault_ids": [vid], **TEXT}).status_code == 403
    r = _place(admins["ada"], [vid])
    assert r.status_code == 201, r.text
    case = r.json()
    cases.append(case["id"])
    assert case["status"] == "hold_only" and case["number"].startswith("C-")
    assert case["you_may"]["confirm"]["why_not"]["reason"] == "placer"
    # The owner is told at once, with the case's number and no name or justification.
    told = [n for n in notifications(admin, "compliance_access") if case["number"] in (n.get("body") or "")]
    assert told and TEXT["justification"] not in told[0]["body"]
    r = _decide(admins["bob"], case["id"], "confirm")
    assert r.status_code == 200 and r.json()["holds"][0]["confirmed_by"] == admins["bob"][0]["_username"], r.text

    # Every way the web app deletes: for the vault's people the file is gone; the hold keeps it.
    assert admin.post(f"/vaults/{vid}/files/{deleted}/delete").status_code == 200
    assert admin.get(f"/vaults/{vid}/files/{deleted}/download").status_code == 404
    assert _kept(deleted) == f"deleted|{me['id']}"
    assert admin.post(f"/vaults/{vid}/folders/{folder}/delete").status_code == 200
    assert _kept(inner) == f"deleted|{me['id']}"
    assert psql(f"SELECT count(*) FROM held_folders WHERE id = '{folder}'") == "1"
    _upload(admin, vid, "same.txt", b"second version")
    assert _kept(replaced) == f"replaced|{me['id']}"
    r = admin.post(f"/vaults/{vid}/files/{moved}/move", json={"dest_vault_id": other})
    assert r.status_code == 200, r.text
    assert _kept(moved) == f"moved|{me['id']}"
    # The stored bytes stay, and decrypt to what was uploaded, under the kept name.
    for file_id, content, name in ((deleted, "deleted bytes", "deleted.txt"), (inner, "inner bytes", "inner.txt"),
                                   (replaced, "first version", "same.txt"), (moved, "moved bytes", "moved.txt")):
        assert _blob_exists(file_id), file_id
        assert _open_kept(file_id) == f"{content}|{name}"
    assert psql(f"SELECT count(*) FROM audit_logs WHERE action = 'held_file_kept' AND resource_id IN "
                f"('{deleted}', '{inner}', '{replaced}', '{moved}')") == "4"

    # The storage page counts what is kept; an older release is kept from starting.
    stats = admin.get("/storage/stats").json()
    assert stats["kept_for_cases"]["files"] >= 4 and stats["on_disk_bytes"] >= stats["used"] + 4 * 10
    assert psql("SELECT requires_at_least FROM data_requirements WHERE key = 'legal-holds'") != ""
    out = subprocess.run(["docker", "exec", API, "python", "-m", "app.core.host_operator", "downgrade-blockers",
                          "--target", "0.33.1"], capture_output=True, text=True, timeout=180)
    assert '"legal-holds"' in out.stdout.strip().splitlines()[-1], out.stdout[-500:]

    # The vault cannot be deleted while it keeps them; nothing of it is lost by trying.
    assert admin.delete_vault(vid).status_code != 200
    assert psql(f"SELECT count(*) FROM vaults WHERE id = '{vid}'") == "1" and _blob_exists(deleted)

    # Release, undo, release again: the purge waits for the delay.
    r = _decide(admins["ada"], case["id"], "release", {"reason": "The claim was withdrawn."})
    assert r.status_code == 200 and r.json()["status"] == "closed", r.text
    r = _decide(admins["bob"], case["id"], "undo-release")
    assert r.status_code == 200 and r.json()["holds"][0]["standing"] is True, r.text
    r = _decide(admins["bob"], case["id"], "release", {"reason": "Settled."})
    assert r.status_code == 200, r.text
    assert run_pass()["legal_holds"] is True
    assert _kept(deleted) != "" and _blob_exists(deleted), "the delay is not over"
    psql(f"UPDATE legal_hold_vaults SET purge_after = (now() AT TIME ZONE 'utc') - interval '1 minute' "
         f"WHERE case_id = '{case['id']}'")
    assert run_pass()["legal_holds"] is True
    for file_id in (deleted, inner, replaced, moved):
        assert _kept(file_id) == "" and not _blob_exists(file_id), file_id
    assert psql(f"SELECT count(*) FROM held_folders WHERE id = '{folder}'") == "0"
    assert psql(f"SELECT count(*) FROM audit_logs WHERE action = 'held_file_purged' AND resource_id IN "
                f"('{deleted}', '{inner}', '{replaced}', '{moved}')") == "4"
    assert psql("SELECT count(*) FROM data_requirements WHERE key = 'legal-holds'") == "0" or \
        psql("SELECT count(*) FROM legal_hold_vaults WHERE released_at IS NULL") != "0"
    # Every step is on record under the case.
    actions = psql(f"SELECT string_agg(DISTINCT action, ',') FROM audit_logs WHERE case_id = '{case['id']}'")
    for action in ("hold_placed", "hold_confirmed", "hold_released", "hold_release_undone", "case_closed"):
        assert action in actions.split(","), action


def test_expiry_under_a_hold_is_kept_and_marked_held_by_case(admin, admins, vaults):
    made, cases = vaults
    vid = made[0]["id"]
    r = admin.patch(f"/vaults/{vid}/settings", json={"expire_files_after_days": 1, "expire_files_unit": "days"})
    assert r.status_code == 200, r.text
    f = _upload(admin, vid, "expiring.txt", b"expiring bytes")
    r = _place(admins["ada"], [vid])
    assert r.status_code == 201, r.text
    cases.append(r.json()["id"])
    psql(f"UPDATE files SET expires_at = (now() AT TIME ZONE 'utc') - interval '1 minute' WHERE id = '{f}'")
    in_api_container("from app.core.authorization import PermissionService\n"
                     "from app.core.database import get_db_context\n"
                     "from app.services.vault_service import VaultService\n"
                     "with get_db_context() as db:\n"
                     "    print(VaultService(db, PermissionService(db)).cleanup_expired_files())\n")
    assert psql(f"SELECT count(*) FROM files WHERE id = '{f}'") == "0"
    assert _kept(f) == "expired|system"
    assert psql(f"SELECT details::jsonb ->> 'held_by_case' FROM audit_logs WHERE action = 'file_expired' "
                f"AND resource_id = '{f}'") == "true"
    assert _blob_exists(f) and _open_kept(f) == "expiring bytes|expiring.txt"


@pytest.mark.sftp
def test_the_sftp_servers_remove_and_replacement_are_kept(admin, admins, vaults):
    paramiko = pytest.importorskip("paramiko")
    if not ADMIN_PASS:
        pytest.skip("No admin password (set VAULT_ADMIN_PASS)")
    made, cases = vaults
    vid, vname = made[0]["id"], made[0]["name"]
    removed = _upload(admin, vid, "sftp-removed.txt", b"sftp removed")
    replaced = _upload(admin, vid, "sftp-same.txt", b"sftp first")
    r = _place(admins["ada"], [vid])
    assert r.status_code == 201, r.text
    cases.append(r.json()["id"])
    transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    transport.banner_timeout = 30
    try:
        transport.connect(username=ADMIN_USER, password=ADMIN_PASS)
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.remove(f"/{vname}/sftp-removed.txt")
        with sftp.open(f"/{vname}/sftp-same.txt", "wb") as fh:
            fh.write(b"sftp second")
        sftp.close()
    finally:
        transport.close()
    assert _kept(removed).startswith("deleted|") and _kept(replaced).startswith("replaced|")
    assert _open_kept(removed) == "sftp removed|sftp-removed.txt"
    assert _open_kept(replaced) == "sftp first|sftp-same.txt"


def test_a_hold_placed_while_a_delete_holds_the_vault_waits_and_the_next_delete_is_kept(admin, admins, vaults):
    made, cases = vaults
    vid = made[0]["id"]
    f = _upload(admin, vid, "after.txt", b"after the hold")
    ada, ada_c, ada_codes = admins["ada"]
    receipt = compliance_receipt(ada_c, "compliance.hold.place", ada["_password"], ada_codes)
    # A deletion's transaction holds the vault's row (FOR NO KEY UPDATE, as every deleting path takes it).
    holder = subprocess.Popen(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-Atc",
                               f"BEGIN; SELECT id FROM vaults WHERE id = '{vid}' FOR NO KEY UPDATE; "
                               "SELECT pg_sleep(3); COMMIT;"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and psql(
                "SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%pg_sleep(3)%' AND state = 'active' "
                "AND pid <> pg_backend_pid()") == "0":
            time.sleep(0.1)
        started = time.monotonic()
        r = ada_c.post("/compliance/holds", json={"vault_ids": [vid], **TEXT}, headers=receipt)
        waited = time.monotonic() - started
    finally:
        holder.wait(timeout=30)
    assert r.status_code == 201, r.text
    cases.append(r.json()["id"])
    assert waited >= 1.5, f"the placing did not wait for the deletion's lock ({waited:.2f}s)"
    assert admin.post(f"/vaults/{vid}/files/{f}/delete").status_code == 200
    assert _kept(f).startswith("deleted|")


def test_an_unconfirmed_hold_lapses_and_its_placer_waits_30_days(admin, admins, vaults):
    made, cases = vaults
    vid = made[0]["id"]
    r = _place(admins["ada"], [vid])
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    cases.append(case_id)
    psql("UPDATE legal_hold_vaults SET placed_at = (now() AT TIME ZONE 'utc') - interval '8 days', "
         "confirm_by_deadline = (now() AT TIME ZONE 'utc') - interval '1 day' "
         f"WHERE case_id = '{case_id}'")
    assert run_pass()["legal_holds"] is True
    assert psql(f"SELECT (lapsed_at IS NOT NULL) || '|' || (released_at IS NOT NULL) FROM legal_hold_vaults "
                f"WHERE case_id = '{case_id}'") == "true|true"
    assert psql(f"SELECT status FROM compliance_cases WHERE id = '{case_id}'") == "closed"
    r = _place(admins["ada"], [vid])
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "place_blocked", r.text
    assert psql("SELECT count(*) FROM audit_logs WHERE action = 'hold_placed' AND status = 'failure' "
                f"AND user_id = '{admins['ada'][0]['id']}'") != "0"
    r = _place(admins["bob"], [vid])
    assert r.status_code == 201, r.text
    cases.append(r.json()["id"])


def test_a_hold_is_refused_while_an_sftp_server_of_another_version_runs(admin, admins, vaults):
    made, cases = vaults
    vid = made[0]["id"]
    fake = str(uuid.uuid4())
    psql(f"INSERT INTO sftp_processes (id, version, host, started_at, seen_at) VALUES ('{fake}', '0.32.9', "
         "'old-sftp', now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc')")
    try:
        r = _place(admins["ada"], [vid])
        assert r.status_code == 409 and r.json()["detail"]["reason"] == "sftp_version", r.text
        assert "0.32.9" in r.json()["detail"]["text"]
        assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE vault_id = '{vid}'") == "0"
    finally:
        psql(f"DELETE FROM sftp_processes WHERE id = '{fake}'")
    # With SFTP on and no server that has said its version lately, it is refused too. (The stack's own server
    # says it again within 30 seconds; a placing that raced it is tried again.)
    for _ in range(3):
        psql("UPDATE sftp_processes SET seen_at = (now() AT TIME ZONE 'utc') - interval '10 minutes'")
        r = _place(admins["ada"], [vid])
        if r.status_code != 201:
            break
        cases.append(r.json()["id"])
        psql(f"UPDATE legal_hold_vaults SET released_at = now() WHERE case_id = '{r.json()['id']}'")
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "sftp_version", r.text
    assert "has reported its version" in r.json()["detail"]["text"]
    # This stack's own SFTP server reports this version, so once it has, the hold is placed.
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline and psql(
            "SELECT count(*) FROM sftp_processes WHERE seen_at > (now() AT TIME ZONE 'utc') - interval '1 minute'") == "0":
        time.sleep(2)
    r = _place(admins["ada"], [vid])
    assert r.status_code == 201, r.text
    cases.append(r.json()["id"])


def test_a_refused_decision_is_recorded_under_its_case(admin, admins, vaults):
    made, cases = vaults
    r = _place(admins["ada"], [made[0]["id"]])
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    cases.append(case_id)
    ada, ada_c, _codes = admins["ada"]
    r = ada_c.post(f"/compliance/cases/{case_id}/hold/confirm")
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "placer", r.text
    assert psql(f"SELECT status || '|' || (details::jsonb ->> 'reason') FROM audit_logs WHERE action = "
                f"'hold_confirmed' AND case_id = '{case_id}'") == "failure|placer"


def test_a_placer_who_releases_their_own_unconfirmed_hold_cannot_place_another_at_once(admin, admins, vaults):
    made, cases = vaults
    vid = made[0]["id"]
    r = _place(admins["ada"], [vid])
    assert r.status_code == 201, r.text
    cases.append(r.json()["id"])
    r = _decide(admins["ada"], r.json()["id"], "release", {"reason": "placing it again"})
    assert r.status_code == 200, r.text
    r = _place(admins["ada"], [vid])
    if r.status_code == 201:
        cases.append(r.json()["id"])
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "place_blocked", r.text
    r = _place(admins["bob"], [vid])
    assert r.status_code == 201, r.text
    cases.append(r.json()["id"])


def _host(*args):
    """The host's compliance tool as dockvault.py runs it: python -m, inside the web container."""
    r = subprocess.run(["docker", "exec", "-i", API, "python", "-m", "app.core.host_compliance", *args],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert lines, (r.stderr or "")[-800:]
    answer = json.loads(lines[-1])
    assert r.returncode == (0 if answer["ok"] else 2), (r.returncode, answer)
    return answer


def test_the_host_confirms_a_hold_only_when_no_administrator_can(admin, admins, vaults):
    made, cases = vaults
    r = _place(admins["ada"], [made[0]["id"]])
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    cases.append(case_id)
    reference = case_id.replace("-", "")[:8]
    bob = admins["bob"][0]
    (listed,) = [c for c in _host("list")["cases"] if c["id"] == case_id]
    assert listed["holds_to_confirm"] == 1 and listed["host_may_confirm"] is False
    assert bob["_username"] in listed["independent_confirmers"]
    answer = _host("confirm-hold", "--case", case_id, "--confirm-case", reference)
    assert answer["ok"] is False and bob["_username"] in answer["error"] and "may not" in answer["error"]
    assert psql(f"SELECT coalesce(confirmed_by_username, '') FROM legal_hold_vaults WHERE case_id = '{case_id}'") == ""
    assert psql("SELECT username || '|' || status || '|' || (details::jsonb ->> 'reason') FROM audit_logs "
                f"WHERE action = 'hold_confirmed' AND case_id = '{case_id}'") == "operator@host|failure|independent_admin"
    # bob's authenticator removed: the confirmation asks for its code, so no administrator can confirm.
    psql(f"DELETE FROM second_factor_enrollments WHERE user_id = '{bob['id']}'")
    shown = _host("show", "--case", case_id)["case"]
    assert shown["host_may_confirm"] is True and shown["independent_confirmers"] == [], shown
    answer = _host("confirm-hold", "--case", case_id, "--confirm-case", reference)
    assert answer["ok"] is True and answer["case"]["confirmed"] == 1, answer
    assert psql(f"SELECT confirmed_by_username || '|' || (confirmed_by IS NULL) FROM legal_hold_vaults "
                f"WHERE case_id = '{case_id}'") == "operator@host|true"
    assert psql("SELECT username FROM audit_logs WHERE action = 'hold_confirmed' AND status = 'success' "
                f"AND case_id = '{case_id}'") == "operator@host"


def _release_as(account, codes, case_id, reason):
    client = signed_in_with_code(account, codes)
    return client, client.post(f"/compliance/cases/{case_id}/hold/release", json={"reason": reason},
                               headers=compliance_receipt(client, "compliance.hold.decide", account["_password"],
                                                          codes))


def test_a_demoted_placer_no_longer_releases_the_hold_alone(admin, admins, vaults):
    made, cases = vaults
    ada, _ada_c, ada_codes = admins["ada"]
    r = _place(admins["ada"], [made[0]["id"]])
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    cases.append(case_id)
    r = admin.patch(f"/api/user-management/users/{ada['id']}/role", json={"new_role": "user"})
    assert r.status_code == 200, r.text
    try:
        _client, r = _release_as(ada, ada_codes, case_id, "no longer an administrator")
        assert r.status_code == 403 and r.json()["detail"]["reason"] == "not_able", r.text
    finally:
        admin.patch(f"/api/user-management/users/{ada['id']}/role", json={"new_role": "admin"})
    assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case_id}' AND released_at IS NULL") == "1"
    assert psql(f"SELECT status FROM compliance_cases WHERE id = '{case_id}'") == "hold_only"
    assert psql(f"SELECT status || '|' || (details::jsonb ->> 'reason') FROM audit_logs WHERE action = "
                f"'hold_released' AND case_id = '{case_id}'") == "failure|not_able"
    r = _decide(admins["bob"], case_id, "release", {"reason": "an independent administrator releases it"})
    assert r.status_code == 200, r.text


def test_an_auditor_whose_right_was_revoked_no_longer_releases_the_hold_alone(admin, admins, vaults):
    made, cases = vaults
    vid = made[0]["id"]
    uma, _uma_c, uma_codes = new_auditor_account(admin)
    try:
        grant_right(admins, uma["id"])
        client = signed_in_with_code(uma, uma_codes)
        r = client.post("/compliance/holds", json={"vault_ids": [vid], **TEXT},
                        headers=compliance_receipt(client, "compliance.hold.place", uma["_password"], uma_codes))
        assert r.status_code == 201, r.text
        case_id = r.json()["id"]
        cases.append(case_id)
        # An auditor lists only the cases they started: not an administrator's hold on another vault.
        r = _place(admins["ada"], [made[1]["id"]])
        assert r.status_code == 201, r.text
        cases.append(r.json()["id"])
        assert [c["id"] for c in client.get("/compliance/holds").json()["cases"]] == [case_id]
        assert r.json()["id"] in [c["id"] for c in admin.get("/compliance/holds").json()["cases"]]
        r = admin.delete(f"/users/{uma['id']}/auditor")
        assert r.status_code == 200, r.text
        client, r = _release_as(uma, uma_codes, case_id, "my right was revoked")
        assert client.get("/compliance/holds").status_code == 403
        assert r.status_code == 403 and r.json()["detail"]["reason"] == "no_grant", r.text
        assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case_id}' AND released_at IS NULL") == "1"
        assert psql(f"SELECT status FROM compliance_cases WHERE id = '{case_id}'") == "hold_only"
    finally:
        # The case names uma (its auditor): the cases go first, then the account can.
        psql(f"UPDATE legal_hold_vaults SET released_at = now() WHERE vault_id = '{vid}' AND released_at IS NULL")
        for cid in list(cases):
            psql(f"DELETE FROM compliance_cases WHERE id = '{cid}'")
        forget_grants(uma["id"])
        admin.delete_user(uma["id"])


def test_an_administrator_who_placed_a_hold_as_an_auditor_needs_the_right_once_it_is_revoked(admin, admins, vaults):
    """An administrator who also holds an auditor right places a hold as the auditor: once the right is revoked they
    no longer release it alone, though they are still an administrator able to act."""
    from _account_change_helpers import second_admin
    from _sf_helpers import enroll_totp
    made, cases = vaults
    with second_admin(admin, independent=True) as (carol, carol_c):
        _s, carol_codes = enroll_totp(carol, carol_c)
        try:
            grant_right(admins, carol["id"])
            client = signed_in_with_code(carol, carol_codes)
            r = client.post("/compliance/holds", json={"vault_ids": [made[0]["id"]], **TEXT},
                            headers=compliance_receipt(client, "compliance.hold.place", carol["_password"],
                                                       carol_codes))
            assert r.status_code == 201, r.text
            case_id = r.json()["id"]
            cases.append(case_id)
            assert psql(f"SELECT grant_id IS NOT NULL FROM compliance_cases WHERE id = '{case_id}'") == "t"
            r = admin.delete(f"/users/{carol['id']}/auditor")
            assert r.status_code == 200, r.text
            _client, r = _release_as(carol, carol_codes, case_id, "still an administrator")
            assert r.status_code == 403 and r.json()["detail"]["reason"] == "no_grant", r.text
            assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case_id}' "
                        "AND released_at IS NULL") == "1"
            r = _decide(admins["bob"], case_id, "release", {"reason": "an independent administrator releases it"})
            assert r.status_code == 200, r.text
        finally:
            for cid in list(cases):
                psql(f"DELETE FROM compliance_cases WHERE id = '{cid}'")
            del cases[:]
            forget_grants(carol["id"])


def test_a_change_to_the_placers_sign_in_details_by_someone_else_outlives_its_record(admin, admins, vaults):
    """Another administrator sets the placer's password. The placer's account then sets "its own" password, and the
    change's record goes 14 days after it applied (credential_changes.prune_done, run by the pruner; here its one
    deletion is made at once): the case kept the change, so the account still does not release the hold alone."""
    made, cases = vaults
    ada, _ada_c, ada_codes = admins["ada"]
    _bob, bob_c, _bob_codes = admins["bob"]
    r = _place(admins["ada"], [made[0]["id"]])
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    cases.append(case_id)
    chosen = "Chosen-By-Another-" + uuid.uuid4().hex[:8] + "x!"
    r = bob_c.patch(f"/users/{ada['id']}", json={"password": chosen})
    assert r.status_code == 200, r.text
    ada["_password"] = chosen
    assert psql(f"SELECT starter_changed_kind FROM compliance_cases WHERE id = '{case_id}'") == "password"
    _client, r = _release_as(ada, ada_codes, case_id, "taken over")
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "password", r.text
    own = chosen + "-own"
    client = signed_in_with_code(ada, ada_codes)
    r = client.patch("/users/me", json={"current_password": chosen, "new_password": own})
    assert r.status_code == 200, r.text
    ada["_password"] = own
    _client, r = _release_as(ada, ada_codes, case_id, "within the 14 days")
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "starter_changed", r.text
    assert psql(f"SELECT count(*) FROM credential_changes WHERE target_user_id = '{ada['id']}'") != "0"
    psql(f"DELETE FROM credential_changes WHERE target_user_id = '{ada['id']}'")
    _client, r = _release_as(ada, ada_codes, case_id, "after the record went")
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "starter_changed", r.text
    assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case_id}' AND released_at IS NULL") == "1"
    assert psql(f"SELECT status FROM compliance_cases WHERE id = '{case_id}'") == "hold_only"


def test_a_confirmation_after_the_confirm_deadline_answers_409(admin, admins, vaults):
    made, cases = vaults
    r = _place(admins["ada"], [made[1]["id"]])
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    cases.append(case_id)
    psql("UPDATE legal_hold_vaults SET confirm_by_deadline = (now() AT TIME ZONE 'utc') - interval '1 minute' "
         f"WHERE case_id = '{case_id}'")
    r = _decide(admins["bob"], case_id, "confirm")
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "confirm_too_late", r.text
    assert psql(f"SELECT coalesce(confirmed_by_username, '') FROM legal_hold_vaults WHERE case_id = '{case_id}'") == ""
    assert psql(f"SELECT status || '|' || (details::jsonb ->> 'reason') FROM audit_logs WHERE action = "
                f"'hold_confirmed' AND case_id = '{case_id}'") == "failure|confirm_too_late"


_PURGE_LEAVES_A_LOCKED_VAULT = """
import uuid
from sqlalchemy import text
from app.core import legal_holds
from app.core.database import SessionLocal

def left():
    with SessionLocal() as s:
        return s.execute(text("SELECT count(*) FROM held_files WHERE vault_id = :v"), {"v": VAULT_ID}).scalar()

holder = SessionLocal()
# As a placing or an undo holds it while it writes a hold.
holder.execute(text("SELECT id FROM vaults WHERE id = :v FOR UPDATE"), {"v": VAULT_ID})
legal_holds.purge(SessionLocal)
while_held = left()
holder.rollback()
holder.close()
legal_holds.purge(SessionLocal)
print("LEFT=%d|%d" % (while_held, left()))
"""


def test_the_purge_leaves_a_vault_whose_row_a_placing_or_an_undo_holds_for_its_next_pass(admin, admins, vaults):
    made, cases = vaults
    vid = made[0]["id"]
    f = _upload(admin, vid, "kept.txt", b"kept until the purge")
    r = _place(admins["ada"], [vid])
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    cases.append(case_id)
    assert admin.post(f"/vaults/{vid}/files/{f}/delete").status_code == 200
    assert _kept(f).startswith("deleted|") and _blob_exists(f)
    path = psql(f"SELECT storage_path FROM held_files WHERE id = '{f}'")
    r = _decide(admins["bob"], case_id, "release", {"reason": "the matter ended"})
    assert r.status_code == 200, r.text
    psql(f"UPDATE legal_hold_vaults SET purge_after = (now() AT TIME ZONE 'utc') - interval '1 minute' "
         f"WHERE case_id = '{case_id}'")
    out = in_api_container(f"VAULT_ID = '{vid}'\n" + _PURGE_LEAVES_A_LOCKED_VAULT)
    line = [ln for ln in out.stdout.splitlines() if ln.startswith("LEFT=")][0]
    assert line == "LEFT=1|0", (line, out.stderr[-1500:])
    assert subprocess.run(["docker", "exec", API, "test", "-e", f"storage/{path}"], timeout=30).returncode != 0
