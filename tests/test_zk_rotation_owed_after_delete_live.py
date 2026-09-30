"""Live: deleting an account that held a zero-knowledge vault's key leaves the vault owing a rotation.

The account's key rows go with it, so nothing else would show that someone who held the key is gone.
Direct: the key holders' /keys answer reports ``rekey_owed`` until a rotation. Hierarchical: a rotation of
the DEK alone is refused (the deleted person still has the team key it would be wrapped to) until the team
key is rotated. test_zk_rotation_owed_after_delete.py pins the recorder and the checks offline.
"""
import base64
import contextlib
import uuid

import pytest

from conftest import ApiClient, ZK_ENC_NAME_STUB, create_zk_vault, ensure_ecc_keypair, post_zk, team_public_key, unique

pytestmark = pytest.mark.integration


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _stub(prefix):
    return base64.b64encode(f"{prefix}-{uuid.uuid4().hex}".encode()).decode()


def _member(admin):
    user = admin.create_user(role="user")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    ensure_ecc_keypair(client)
    return user


def test_a_deleted_key_holder_leaves_a_direct_vault_owing_a_rotation(admin):
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    member = _member(admin)
    try:
        r = post_zk(admin, f"/ecc/vaults/{vid}/members", json={
            "user_id": str(member["id"]), "wrapped_dek": _stub("dek"), "ephemeral_public_key": _stub("eph")})
        assert r.status_code == 200, r.text
        assert admin.post(f"/vaults/{vid}/permissions",
                          json={"user_id": str(member["id"]), "level": "read"}).status_code in (200, 201)
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is False

        assert admin.delete_user(member["id"]).status_code == 200
        member = None
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is True

        r = post_zk(admin, f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [{"user_id": str(admin.user["id"]), "wrapped_dek": _stub("dek"),
                             "ephemeral_public_key": _stub("eph")}]})
        assert r.status_code == 200, r.text
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is False
    finally:
        if member is not None:
            admin.delete_user(member["id"])
        admin.delete_vault(vid)


def test_a_deleted_team_member_forces_a_team_rotation(admin):
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        r = post_zk(admin, "/vaults", json={
            "name": unique("hteam"), "type": "zero_knowledge", "enc_name": ZK_ENC_NAME_STUB,
            "name_key_version": 1, "key_wrapping_mode": "hierarchical", "team_public_key": team_public_key(),
            "team_wrapped_dek": _stub("tdek"), "team_dek_ephemeral_public_key": _stub("teph"),
            "wrapped_team_privkey": _stub("tpriv"), "team_privkey_ephemeral_public_key": _stub("tpeph")})
        assert r.status_code == 200, r.text
        vid = r.json()["id"]
    member = _member(admin)
    try:
        r = post_zk(admin, f"/ecc/vaults/{vid}/members", json={
            "user_id": str(member["id"]), "wrapped_team_privkey": _stub("tpriv"),
            "team_ephemeral_public_key": _stub("tpeph")})
        assert r.status_code == 200, r.text
        assert admin.post(f"/vaults/{vid}/permissions",
                          json={"user_id": str(member["id"]), "level": "read"}).status_code in (200, 201)

        assert admin.delete_user(member["id"]).status_code == 200
        member = None
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is True

        # A rotation of the DEK alone would wrap it to the team key the deleted person still has.
        routine = post_zk(admin, f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None, "member_keys": [],
            "team_dek_wrapped": _stub("tdek"), "team_dek_ephemeral_public_key": _stub("teph")})
        assert routine.status_code == 400, routine.text
        team = post_zk(admin, f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [{"user_id": str(admin.user["id"]), "wrapped_dek": _stub("tpriv"),
                             "ephemeral_public_key": _stub("tpeph")}],
            "team_public_key": team_public_key(),
            "team_dek_wrapped": _stub("tdek"), "team_dek_ephemeral_public_key": _stub("teph")})
        assert team.status_code == 200, team.text
        assert team.json()["team_key_version"] == 2
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["rekey_owed"] is False
    finally:
        if member is not None:
            admin.delete_user(member["id"])
        admin.delete_vault(vid)
