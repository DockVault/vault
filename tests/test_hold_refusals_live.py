"""What a legal hold refuses, on a running stack (app/core/hold_refusals.py and the routes that ask it).

  * a vault under a hold cannot be deleted: 409 naming the case, ``hold_blocked_delete`` recorded under it, the
    vault and what it holds as they were; after the release, while what the hold kept waits for its purge, the same
    (the answer says until when); after the purge the vault is deleted;
  * a zero-knowledge vault's older key versions are not retired while a hold stands on it: 409, recorded, the old
    epoch's key still there; once the hold is released (and kept nothing) the retire runs;
  * the lowest epoch in use, read by the retire on the stack's Postgres, counts the epochs of the files, folders and
    old names a hold kept;
  * a hold that kept only the old name of something renamed (a zero-knowledge folder's, sealed under an older
    epoch, or a file's) keeps the vault and that epoch's key through the release's window, so an undone release
    finds both; after the purge both go.

test_hold_refusals.py covers the same offline; test_legal_holds_live.py the holds themselves.
"""
import base64
import time
import uuid

import pytest

from _account_change_helpers import psql
from _auditor_helpers import compliance_receipt, run_pass, two_admins
from conftest import ZK_ENC_NAME_STUB, create_zk_vault, ensure_ecc_keypair, post_zk, unique

pytestmark = pytest.mark.integration

TEXT = {"purpose": "litigation_hold", "legal_basis": "legal_obligation",
        "justification": "Preserve the records named in the claim served last week.",
        "owner_note": "Files deleted from your vault are kept for a legal matter."}


def _upload(client, vid, name, content):
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))])
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def _place(who, vault_ids):
    account, client, codes = who
    r = client.post("/compliance/holds", json={"vault_ids": vault_ids, **TEXT},
                    headers=compliance_receipt(client, "compliance.hold.place", account["_password"], codes))
    assert r.status_code == 201, r.text
    return r.json()


def _decide(who, case_id, step, body=None):
    account, client, codes = who
    return client.post(f"/compliance/cases/{case_id}/hold/{step}", json=body,
                       headers=compliance_receipt(client, "compliance.hold.decide", account["_password"], codes))


def _blocked(case_id, kind):
    return psql(f"SELECT count(*) FROM audit_logs WHERE action = 'hold_blocked_delete' AND case_id = '{case_id}' "
                f"AND status = 'failure' AND details ->> 'kind' = '{kind}'")


def _forget(case_ids, vault_ids):
    """Release and purge, straight in the database, what a test left (its records are otherwise kept)."""
    from _account_change_helpers import in_api_container
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
    made = [admin.create_vault(name=unique("held"))]
    cases = []
    try:
        yield made, cases
    finally:
        _forget(cases, [v["id"] for v in made])
        for v in made:
            admin.delete_vault(v["id"])


def test_a_held_vault_cannot_be_deleted_until_what_its_hold_kept_is_purged(admin, admins, vaults):
    made, cases = vaults
    vid = made[0]["id"]
    deleted = _upload(admin, vid, "deleted.txt", b"deleted bytes")
    live = _upload(admin, vid, "live.txt", b"live bytes")
    case = _place(admins["ada"], [vid])
    cases.append(case["id"])

    # Under the hold: 409, naming the case; recorded under it; nothing of the vault is lost by trying.
    r = admin.delete_vault(vid)
    assert r.status_code == 409, r.text
    assert case["number"] in r.json()["detail"] and "under a legal hold" in r.json()["detail"]
    assert _blocked(case["id"], "vault") == "1"
    assert psql(f"SELECT count(*) FROM vaults WHERE id = '{vid}'") == "1"
    assert admin.get(f"/vaults/{vid}/files/{live}/download").status_code == 200
    assert psql(f"SELECT count(*) FROM audit_logs WHERE action = 'vault_deleted' AND resource_id = '{vid}'") == "0"

    # Released, with a file the hold kept waiting for its purge: still refused, and the answer says until when.
    assert admin.post(f"/vaults/{vid}/files/{deleted}/delete").status_code == 200
    assert psql(f"SELECT count(*) FROM held_files WHERE id = '{deleted}'") == "1"
    r = _decide(admins["ada"], case["id"], "release", {"reason": "The claim was withdrawn."})
    assert r.status_code == 200, r.text
    r = admin.delete_vault(vid)
    assert r.status_code == 409, r.text
    assert case["number"] in r.json()["detail"] and "until they are purged after" in r.json()["detail"]
    assert _blocked(case["id"], "vault") == "2"

    # Purged: the vault is deleted as any other.
    psql(f"UPDATE legal_hold_vaults SET purge_after = (now() AT TIME ZONE 'utc') - interval '1 minute' "
         f"WHERE case_id = '{case['id']}'")
    for _ in range(5):
        assert run_pass()["legal_holds"] is True
        if psql(f"SELECT count(*) FROM held_files WHERE vault_id = '{vid}'") == "0":
            break
        time.sleep(1)
    r = admin.delete_vault(vid)
    assert r.status_code == 200, r.text
    assert psql(f"SELECT count(*) FROM vaults WHERE id = '{vid}'") == "0"
    assert _blocked(case["id"], "vault") == "2"


def _stub(prefix):
    """Opaque wrap material: the server stores it verbatim."""
    return base64.b64encode(f"{prefix}-{uuid.uuid4().hex}".encode()).decode()


def test_older_key_versions_are_kept_while_a_hold_stands_on_a_zero_knowledge_vault(admin, admins):
    ensure_ecc_keypair(admin)
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        # Nameless: a sealed name would pin epoch 1 on its own.
        vid = create_zk_vault(admin, seal_name=False)["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})
    cases = []
    try:
        r = post_zk(admin, f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [{"user_id": str(admin.user["id"]), "wrapped_dek": _stub("dek"),
                             "ephemeral_public_key": _stub("eph")}]})
        assert r.status_code == 200, r.text
        case = _place(admins["ada"], [vid])
        cases.append(case["id"])

        r = admin.post(f"/ecc/vaults/{vid}/retire-version")
        assert r.status_code == 409, r.text
        assert case["number"] in r.json()["detail"] and "older key versions are kept" in r.json()["detail"]
        assert admin.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()["has_access"] is True
        assert _blocked(case["id"], "key_versions") == "1"
        assert psql(f"SELECT count(*) FROM audit_logs WHERE action = 'zk_versions_retired' "
                    f"AND resource_id = '{vid}'") == "0"

        # Released, having kept nothing: nothing keeps the vault, and the retire runs.
        r = _decide(admins["ada"], case["id"], "release", {"reason": "The claim was withdrawn."})
        assert r.status_code == 200, r.text
        r = admin.post(f"/ecc/vaults/{vid}/retire-version")
        assert r.status_code == 200, r.text
        assert r.json()["rows_deleted"] >= 1 and r.json()["retired_below_version"] == 2
        assert admin.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()["has_access"] is False
    finally:
        _forget(cases, [vid])
        admin.delete_vault(vid)


_FLOOR = """
import uuid
from app.api.ecc_router import _lowest_epoch_in_use
from app.core.database import get_db_context
from app.core.models import Vault
with get_db_context() as db:
    vault = db.get(Vault, uuid.UUID(VAULT_ID))
    print("FLOOR=" + str(_lowest_epoch_in_use(db, vault.id, vault)))
"""


def _floor(vid):
    from _account_change_helpers import in_api_container
    out = in_api_container(f"VAULT_ID = '{vid}'\n" + _FLOOR)
    return [ln for ln in out.stdout.splitlines() if ln.startswith("FLOOR=")][0][6:]


def test_the_lowest_epoch_in_use_counts_kept_rows_on_postgres(admin):
    # A nameless zero-knowledge vault with nothing in it: no epoch is in use (a sealed name would pin one).
    ensure_ecc_keypair(admin)
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        vid = create_zk_vault(admin, seal_name=False)["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})
    try:
        assert _floor(vid) == "None"
        psql(f"INSERT INTO held_folders (id, vault_id, name_key_version, kept_reason, kept_at) "
             f"VALUES (gen_random_uuid(), '{vid}', 3, 'deleted', now() AT TIME ZONE 'utc')")
        assert _floor(vid) == "3"
        psql(f"INSERT INTO held_files (id, vault_id, encryption_metadata, kept_reason, kept_at) "
             f"VALUES (gen_random_uuid(), '{vid}', '{{\"key_version\": 2}}', 'replaced', "
             f"now() AT TIME ZONE 'utc')")
        assert _floor(vid) == "2"
        psql(f"INSERT INTO held_name_history (id, object_id, vault_id, kind, enc_name, name_key_version, renamed_at) "
             f"VALUES (gen_random_uuid(), gen_random_uuid(), '{vid}', 'folder', 'zk2:old', 1, "
             f"now() AT TIME ZONE 'utc')")
        assert _floor(vid) == "1"
    finally:
        _forget([], [vid])
        admin.delete_vault(vid)


def _purge_now(case_id, vault_id):
    """Bring the purge after the case's release forward, and run the pruner until what the hold kept is gone."""
    psql(f"UPDATE legal_hold_vaults SET purge_after = (now() AT TIME ZONE 'utc') - interval '1 minute' "
         f"WHERE case_id = '{case_id}'")
    for _ in range(5):
        assert run_pass()["legal_holds"] is True
        if psql(f"SELECT (SELECT count(*) FROM held_files WHERE vault_id = '{vault_id}') + "
                f"(SELECT count(*) FROM held_folders WHERE vault_id = '{vault_id}') + "
                f"(SELECT count(*) FROM held_name_history WHERE vault_id = '{vault_id}')") == "0":
            return
        time.sleep(1)
    pytest.fail("the purge did not take what the hold kept")


def test_a_folder_name_a_released_hold_kept_keeps_its_key_and_its_vault_until_the_purge(admin, admins):
    """A zero-knowledge folder whose name was sealed at epoch 1, the vault rotated to epoch 2, a hold placed, the
    folder renamed at epoch 2: the hold keeps its old name, sealed at epoch 1, and nothing else. After the release
    (which can be undone until the purge) the epoch-1 key is not retired and the vault is not deleted, so the undone
    release still finds the vault and the old name still opens; after the purge both go."""
    ensure_ecc_keypair(admin)
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        vid = create_zk_vault(admin, seal_name=False)["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})
    cases, gone = [], False
    try:
        r = admin.post(f"/vaults/{vid}/folders", json={"enc_name": ZK_ENC_NAME_STUB, "name_bi": "a" * 64,
                                                       "name_key_version": 1})
        assert r.status_code in (200, 201), r.text
        fid = (r.json().get("folder") or r.json())["id"]
        r = post_zk(admin, f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [{"user_id": str(admin.user["id"]), "wrapped_dek": _stub("dek"),
                             "ephemeral_public_key": _stub("eph")}]})
        assert r.status_code == 200, r.text
        case = _place(admins["ada"], [vid])
        cases.append(case["id"])
        renamed = "zk2:" + base64.urlsafe_b64encode(b"zk-folder-name-renamed-stub" * 3).decode()
        r = admin.put(f"/vaults/{vid}/files/{fid}/rename", json={"enc_name": renamed, "name_bi": "b" * 64,
                                                                  "name_key_version": 2})
        assert r.status_code == 200, r.text
        assert psql(f"SELECT name_key_version FROM folders WHERE id = '{fid}'") == "2"
        assert psql(f"SELECT name_key_version FROM held_name_history WHERE object_id = '{fid}'") == "1"
        assert psql(f"SELECT (SELECT count(*) FROM held_files WHERE vault_id = '{vid}') + "
                    f"(SELECT count(*) FROM held_folders WHERE vault_id = '{vid}')") == "0", "only the old name"
        assert _floor(vid) == "1"

        r = _decide(admins["ada"], case["id"], "release", {"reason": "The claim was withdrawn."})
        assert r.status_code == 200, r.text
        # The release's window: the retire is refused, the epoch-1 key stays, the vault cannot be deleted.
        r = admin.post(f"/ecc/vaults/{vid}/retire-version")
        assert r.status_code == 409, r.text
        assert case["number"] in r.json()["detail"] and "until they are purged after" in r.json()["detail"]
        assert admin.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()["has_access"] is True
        assert _blocked(case["id"], "key_versions") == "1"
        r = admin.delete_vault(vid)
        assert r.status_code == 409, r.text
        assert case["number"] in r.json()["detail"] and "until they are purged after" in r.json()["detail"]
        assert _blocked(case["id"], "vault") == "1"
        # The release undone: the hold stands again over the vault, and the key its old name needs is there.
        r = _decide(admins["bob"], case["id"], "undo-release")
        assert r.status_code == 200, r.text
        assert psql(f"SELECT count(*) FROM legal_hold_vaults WHERE case_id = '{case['id']}' "
                    "AND released_at IS NULL") == "1"
        assert admin.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()["has_access"] is True

        # Released again and purged: the old name goes, and with it what kept the key and the vault.
        r = _decide(admins["ada"], case["id"], "release", {"reason": "The claim was withdrawn again."})
        assert r.status_code == 200, r.text
        _purge_now(case["id"], vid)
        assert _floor(vid) == "2"
        r = admin.post(f"/ecc/vaults/{vid}/retire-version")
        assert r.status_code == 200, r.text
        assert r.json()["rows_deleted"] >= 1 and r.json()["retired_below_version"] == 2
        assert admin.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()["has_access"] is False
        r = admin.delete_vault(vid)
        assert r.status_code == 200, r.text
        gone = True
    finally:
        _forget(cases, [vid])
        if not gone:
            admin.delete_vault(vid)


def test_a_standard_vault_whose_released_hold_kept_only_a_files_old_name_is_not_deleted(admin, admins, vaults):
    """A file renamed under a hold, nothing deleted: the hold keeps the file's old name only. In the release's
    window the vault's delete is refused, naming the case and the purge date, and the undo of the release finds
    the vault as it was."""
    made, cases = vaults
    vid = made[0]["id"]
    fid = _upload(admin, vid, "before.txt", b"the bytes")
    case = _place(admins["ada"], [vid])
    cases.append(case["id"])
    r = admin.put(f"/vaults/{vid}/files/{fid}/rename", json={"new_name": "after.txt"})
    assert r.status_code == 200, r.text
    assert psql(f"SELECT kind FROM held_name_history WHERE object_id = '{fid}'") == "file"
    r = _decide(admins["ada"], case["id"], "release", {"reason": "The claim was withdrawn."})
    assert r.status_code == 200, r.text
    purge = psql(f"SELECT to_char(purge_after, 'YYYY-MM-DD') FROM legal_hold_vaults WHERE case_id = '{case['id']}'")
    r = admin.delete_vault(vid)
    assert r.status_code == 409, r.text
    assert case["number"] in r.json()["detail"] and f"until they are purged after {purge}" in r.json()["detail"]
    assert _blocked(case["id"], "vault") == "1"
    assert psql(f"SELECT count(*) FROM vaults WHERE id = '{vid}'") == "1"
    r = _decide(admins["bob"], case["id"], "undo-release")
    assert r.status_code == 200, r.text
    assert admin.get(f"/vaults/{vid}/files/{fid}/download").status_code == 200


CASE_TEXT = {"purpose": "internal_investigation", "legal_basis": "legal_obligation",
             "justification": "Suspected exfiltration of client records, ticket SEC-2041.",
             "owner_note": "Your vault is part of an internal review; nothing is changed in it."}


def test_a_custodians_account_is_kept_while_the_cases_hold_stands(admin):
    from _account_change_helpers import in_api_container
    from _auditor_helpers import forget_grants, grant_right, new_auditor_account
    from _owner_notice_helpers import owner_with_vault
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, vid = owner_with_vault(admin)
        otto = admin.create_user(username=unique("otto"))       # the custodian; owns no vault
        cid = None
        try:
            r = uma_c.post("/compliance/cases", json={
                "scope": [{"kind": "vault", "target_id": vid}, {"kind": "custodian", "target_id": otto["id"]}],
                "hold": True, **CASE_TEXT},
                headers=compliance_receipt(uma_c, "compliance.case.request", uma["_password"], codes))
            assert r.status_code == 201, r.text
            cid = r.json()["id"]
            bob, bob_c, bob_codes = admins["bob"]
            headers = compliance_receipt(bob_c, "compliance.case.approve", bob["_password"], bob_codes)
            headers["If-Match"] = '"1"'
            r = bob_c.post(f"/compliance/cases/{cid}/approve", headers=headers)
            assert r.status_code == 200, r.text
            number = r.json()["number"]
            assert psql(f"SELECT why FROM compliance_case_people WHERE case_id = '{cid}' "
                        f"AND user_id = '{otto['id']}'") == "custodian"

            # The custodian's account is kept: 409 naming the case, recorded under it, the account as it was.
            r = admin.delete_user(otto["id"])
            assert r.status_code == 409, r.text
            assert f"custodian of case {number}" in r.json()["detail"]
            assert psql(f"SELECT count(*) FROM users WHERE id = '{otto['id']}'") == "1"
            assert _blocked(cid, "account") == "1"
            assert psql(f"SELECT details ->> 'target_user_id' FROM audit_logs WHERE action = 'hold_blocked_delete' "
                        f"AND case_id = '{cid}'") == otto["id"]
            # The owner of the held vault is no custodian: her account is refused for the vault she owns, not
            # by the hold.
            r = admin.delete_user(olga["id"])
            assert r.status_code == 409 and "owns 1 vault" in r.json()["detail"], r.text
            assert _blocked(cid, "account") == "1"

            # The auditor closes the case: the hold is released, having kept nothing, and the account goes.
            r = uma_c.post(f"/compliance/cases/{cid}/close", json={"reason": "Concluded, nothing found."},
                           headers=compliance_receipt(uma_c, "compliance.hold.decide", uma["_password"], codes))
            assert r.status_code == 200 and r.json()["status"] == "closed", r.text
            r = admin.delete_user(otto["id"])
            assert r.status_code == 200, r.text
            assert psql(f"SELECT count(*) FROM users WHERE id = '{otto['id']}'") == "0"
        finally:
            if cid:
                psql(f"UPDATE legal_hold_vaults SET released_at = now() WHERE case_id = '{cid}' "
                     "AND released_at IS NULL")
                for table in ("held_files", "held_folders", "held_name_history"):
                    psql(f"DELETE FROM {table} WHERE vault_id = '{vid}'")
                psql(f"DELETE FROM compliance_cases WHERE id = '{cid}'")
                in_api_container("from app.core import legal_hold_marker\nlegal_hold_marker.check_at_start()\n")
            forget_grants(uma["id"])
            olga_c.delete_vault(vid)
            for person in (otto, olga, uma):
                admin.delete_user(person["id"])
