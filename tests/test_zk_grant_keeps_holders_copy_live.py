"""Live: a share never replaces the copy of the key that someone who already holds it has.

The server cannot tell a correct wrap from one of another key, so a share to a member who holds the
current key answers 200 with ``unchanged`` and leaves their copy as it was; a share to a member whose copy
was switched off brings it back. test_zk_key_proof_handler.py pins the same in the handler.
"""
import base64
import contextlib
import uuid

import pytest

from conftest import ApiClient, create_zk_vault, ensure_ecc_keypair, post_zk

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


def test_a_share_to_a_key_holder_leaves_their_copy_alone(admin):
    ensure_ecc_keypair(admin)
    member = admin.create_user(role="user")
    client = ApiClient()
    client.login(member["_username"], member["_password"])
    ensure_ecc_keypair(client)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        first = _stub("first")
        r = post_zk(admin, f"/ecc/vaults/{vid}/members", json={
            "user_id": str(member["id"]), "wrapped_dek": first, "ephemeral_public_key": _stub("eph")})
        assert r.status_code == 200 and "unchanged" not in r.json(), r.text
        assert admin.post(f"/vaults/{vid}/permissions",
                          json={"user_id": str(member["id"]), "level": "read"}).status_code in (200, 201)
        assert client.get(f"/ecc/vaults/{vid}/keys").json()["wrapped_dek"] == first

        again = post_zk(admin, f"/ecc/vaults/{vid}/members", json={
            "user_id": str(member["id"]), "wrapped_dek": _stub("second"), "ephemeral_public_key": _stub("eph")})
        assert again.status_code == 200, again.text
        assert again.json().get("unchanged") is True
        assert client.get(f"/ecc/vaults/{vid}/keys").json()["wrapped_dek"] == first

        # The owner's own copy is still the owner's to replace.
        own = _stub("own")
        mine = post_zk(admin, f"/ecc/vaults/{vid}/members", json={
            "user_id": str(admin.user["id"]), "wrapped_dek": own, "ephemeral_public_key": _stub("eph")})
        assert mine.status_code == 200 and "unchanged" not in mine.json(), mine.text
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["wrapped_dek"] == own
    finally:
        admin.delete_vault(vid)
        admin.delete_user(member["id"])
