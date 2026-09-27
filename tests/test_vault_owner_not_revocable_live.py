"""The owner of a vault cannot be removed from it, and removing someone who is not a member changes
nothing -- against a running deployment.

DELETE /vaults/{id}/permissions/{owner} used to answer 404, but only after it had switched off and
committed every zero-knowledge key the owner held. A Manager who was never given the key, or an
administrator, could lock an owner out of their own vault that way: nobody else may give the owner a
new key. test_vault_owner_not_revocable.py drives the handler; this file drives the route, as the
two callers who could do it, and reads the owner's key back through the route the web app uses.
"""
import contextlib

import pytest

from conftest import (
    ApiClient, ZK_EPHEMERAL_STUB, ZK_WRAPPED_DEK_STUB, create_zk_vault, ensure_ecc_keypair,
)

pytestmark = pytest.mark.integration

OWNER_REFUSED = "The vault owner's access cannot be revoked"


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _keys(client, vid):
    r = client.get(f"/ecc/vaults/{vid}/keys")
    assert r.status_code == 200, r.text
    return r.json()


def _revocations(admin, vid):
    """The vault's 'vault_permission_revoked' audit rows (by the vault's id, not a count)."""
    return [r for r in admin.get("/audit/log?action=vault_permission_revoked").json()
            if str(r.get("resource_id")) == str(vid)]


@pytest.fixture
def person(admin):
    """A new ordinary user and a signed-in client for them."""
    made = []

    def make():
        p = admin.create_user(role="user")
        c = ApiClient()
        c.login(p["_username"], p["_password"])
        made.append(p)
        return p, c

    yield make
    for p in made:
        admin.delete_user(p["id"])


@pytest.fixture
def owned_vault(admin, temp_user_client):
    """A direct zero-knowledge vault owned by an ordinary user."""
    with _zk_enabled(admin):
        vid = create_zk_vault(temp_user_client)["id"]
    try:
        yield vid
    finally:
        temp_user_client.delete_vault(vid)


def test_a_keyless_manager_and_an_admin_cannot_remove_the_owner(admin, temp_user, temp_user_client,
                                                               owned_vault, person):
    vid, owner = owned_vault, temp_user["id"]
    manager, manager_client = person()
    temp_user_client.post(f"/vaults/{vid}/permissions",
                          json={"user_id": manager["id"], "level": "manage"}).raise_for_status()
    assert manager_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False, (
        "the Manager must hold no key: that is the case this is about")

    for who, client in (("the keyless Manager", manager_client), ("the admin", admin)):
        r = client.delete(f"/vaults/{vid}/permissions/{owner}")
        assert r.status_code == 400, f"{who}: {r.status_code} {r.text}"
        assert r.json()["detail"] == OWNER_REFUSED
        keys = _keys(temp_user_client, vid)
        assert keys["has_access"] is True and keys["key_version"] == 1, (
            f"{who} was refused but the owner lost their key: {keys}")

        # The /ecc removal route refuses the owner as well.
        r = client.delete(f"/ecc/vaults/{vid}/members/{owner}")
        assert r.status_code == 400, f"{who}: {r.status_code} {r.text}"
        assert _keys(temp_user_client, vid)["has_access"] is True

    assert _revocations(admin, vid) == [], "a refused removal was recorded as a revocation"
    # The owner can still do what only a key holder may: rotate.
    r = temp_user_client.post(f"/ecc/vaults/{vid}/rekey", json={
        "from_version": 1, "to_version": 2, "member_keys": [
            {"user_id": str(owner), "wrapped_dek": ZK_WRAPPED_DEK_STUB,
             "ephemeral_public_key": ZK_EPHEMERAL_STUB}]})
    assert r.status_code == 200, r.text


def test_the_owner_of_a_standard_vault_cannot_be_removed_either(admin, temp_user, temp_user_client):
    """Standard vaults have no keys to lose, but the owner has no member row to remove on any vault
    type, and the answer is the same."""
    vid = temp_user_client.create_vault()["id"]
    try:
        r = admin.delete(f"/vaults/{vid}/permissions/{temp_user['id']}")
        assert r.status_code == 400, r.text
        assert r.json()["detail"] == OWNER_REFUSED
        assert temp_user_client.get(f"/vaults/{vid}").status_code == 200
    finally:
        temp_user_client.delete_vault(vid)


def test_removing_someone_who_is_not_a_member_leaves_their_key_alone(admin, temp_user_client,
                                                                     owned_vault, person):
    """They hold a key but have no member row: the web app shares a zero-knowledge vault by wrapping
    the key first and granting access second, and here the grant never came. There is no member row
    to remove, so the route answers 404 -- and now changes nothing, their key included. (Their key is
    still removable through DELETE /ecc/vaults/{id}/members/{user}.)"""
    vid = owned_vault
    holder, holder_client = person()
    ensure_ecc_keypair(holder_client)
    temp_user_client.post(f"/ecc/vaults/{vid}/members", json={
        "user_id": holder["id"], "wrapped_dek": ZK_WRAPPED_DEK_STUB,
        "ephemeral_public_key": ZK_EPHEMERAL_STUB}).raise_for_status()
    assert _keys(holder_client, vid)["has_access"] is True

    r = admin.delete(f"/vaults/{vid}/permissions/{holder['id']}")
    assert r.status_code == 404, r.text
    assert _keys(holder_client, vid)["has_access"] is True, "a 404 switched off their key"
    assert _revocations(admin, vid) == []

    # The control: once they are a member, the same request removes them and their key.
    temp_user_client.post(f"/vaults/{vid}/permissions",
                          json={"user_id": holder["id"], "level": "read"}).raise_for_status()
    r = admin.delete(f"/vaults/{vid}/permissions/{holder['id']}")
    assert r.status_code == 200, r.text
    assert _keys(holder_client, vid)["has_access"] is False
    assert len(_revocations(admin, vid)) == 1
