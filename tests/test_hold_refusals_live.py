"""What a legal hold refuses, on a running stack (app/core/hold_refusals.py and the routes that ask it).

  * a vault under a hold cannot be deleted: 409 naming the case, ``hold_blocked_delete`` recorded under it, the
    vault and what it holds as they were; after the release, while what the hold kept waits for its purge, the same
    (the answer says until when); after the purge the vault is deleted;
  * a zero-knowledge vault's older key versions are not retired while a hold stands on it: 409, recorded, the old
    epoch's key still there; once the hold is released (and kept nothing) the retire runs.

test_hold_refusals.py covers the same offline; test_legal_holds_live.py the holds themselves.
"""
import base64
import time
import uuid

import pytest

from _account_change_helpers import psql
from _auditor_helpers import compliance_receipt, run_pass, two_admins
from conftest import create_zk_vault, ensure_ecc_keypair, post_zk, unique

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
