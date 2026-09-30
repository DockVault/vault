"""Live: a member's report that a key does not match (POST /ecc/vaults/{id}/key-proof/report).

A report is recorded (zk_key_check_mismatch) and tells the vault's owner in the app, once a day for each
vault; it changes nothing about the vault's keys. Only someone who holds a key of the vault may file one;
everyone else gets the same 403 whether or not the vault exists. test_zk_key_proof_handler.py pins the
handler offline.
"""
import contextlib
import os
import subprocess
import uuid

import pytest

from conftest import ApiClient, ZK_EPHEMERAL_STUB, ZK_WRAPPED_DEK_STUB, create_zk_vault, ensure_ecc_keypair, post_zk, unique

pytestmark = pytest.mark.integration

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
TITLE = "A member's key for one of your vaults does not match"


def _psql(sql: str) -> str:
    result = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return (result.stdout or "").strip()


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


@pytest.fixture
def people(admin):
    made = []

    def make(prefix="zr"):
        user = admin.create_user(username=unique(prefix))
        client = ApiClient()
        client.login(user["_username"], user["_password"])
        ensure_ecc_keypair(client)
        made.append(user)
        return user, client

    yield make
    for user in made:
        admin.delete_user(user["id"])


def _told(client):
    rows = client.get("/notifications", params={"limit": 100}).json()["notifications"]
    return [n for n in rows if n["title"] == TITLE]


def test_a_members_report_is_recorded_and_the_owner_told_once_a_day_per_vault(admin, people):
    owner, oc = people("zrown")
    member, mc = people("zrmem")
    stranger, sc = people("zrstr")
    with _zk_enabled(admin):
        vids = [create_zk_vault(oc)["id"] for _ in range(2)]
    try:
        for vid in vids:
            post_zk(oc, f"/ecc/vaults/{vid}/members", json={
                "user_id": member["id"], "wrapped_dek": ZK_WRAPPED_DEK_STUB,
                "ephemeral_public_key": ZK_EPHEMERAL_STUB}).raise_for_status()
            oc.post(f"/vaults/{vid}/permissions", json={"user_id": member["id"], "level": "read"}).raise_for_status()
        before = _psql(f"SELECT dek_version, (SELECT count(*) FROM vault_member_keys WHERE vault_id = '{vids[0]}') "
                       f"FROM vaults WHERE id = '{vids[0]}'")

        r = mc.post(f"/ecc/vaults/{vids[0]}/key-proof/report", json={"dek_epoch": 1, "finding": "dek_check"})
        assert r.status_code == 200 and r.json()["status"] == "recorded", r.text
        again = mc.post(f"/ecc/vaults/{vids[0]}/key-proof/report", json={"dek_epoch": 1, "finding": "lineage"})
        assert again.status_code == 200, again.text
        assert len(_told(oc)) == 1, "a second report of the same vault on the same day told the owner again"
        other = mc.post(f"/ecc/vaults/{vids[1]}/key-proof/report", json={"dek_epoch": 1, "finding": "seal"})
        assert other.status_code == 200, other.text
        assert len(_told(oc)) == 2
        assert _told(mc) == [], "the member who reported was told as if they owned the vault"
        assert _psql("SELECT string_agg(details->>'finding', ',' ORDER BY timestamp) FROM audit_logs "
                     f"WHERE action = 'zk_key_check_mismatch' AND resource_id = '{vids[0]}'") == "dek_check,lineage"
        assert _psql(f"SELECT dek_version, (SELECT count(*) FROM vault_member_keys WHERE vault_id = '{vids[0]}') "
                     f"FROM vaults WHERE id = '{vids[0]}'") == before, "a report changed the vault's keys"

        # Someone with no key of the vault, and a vault that does not exist: the same refusal.
        for client, vid in ((sc, vids[0]), (mc, str(uuid.uuid4()))):
            refused = client.post(f"/ecc/vaults/{vid}/key-proof/report", json={"dek_epoch": 1, "finding": "seal"})
            assert refused.status_code == 403 and refused.json()["detail"] == "No access to this vault's keys"
        # Not a finding, or not an epoch of the vault.
        for body in ({"dek_epoch": 1, "finding": "guess"}, {"dek_epoch": 9, "finding": "seal"}):
            assert mc.post(f"/ecc/vaults/{vids[0]}/key-proof/report", json=body).status_code == 400
    finally:
        for vid in vids:
            oc.delete_vault(vid)
