"""Only someone who holds a zero-knowledge vault's key may rotate it -- against a running deployment.

The rule itself, in both wrapping modes and at every epoch edge, is driven against the handler in
test_zk_rekey_key_holder.py. This file drives the route: a global admin who manages every vault but
was never given this one's key is refused, the owner is not, and a removal done WITHOUT a rotation
(which is what the web app now does when the person removing a member does not hold the key) leaves
the vault reporting rekey_owed to its key holder until they rotate. Minting the name-index key, which
members then use for every name they write, follows the same rule.

It also holds the vault row lock from outside, which is the only way to observe the lock: a rotation
must re-check the caller's key after it gets the lock, and the two removal routes must wait for it.
"""
import contextlib
import os
import subprocess
import time
import uuid

import pytest

from conftest import (
    ApiClient, ZK_ENC_NAME_STUB, ZK_EPHEMERAL_STUB, ZK_WRAPPED_DEK_STUB,
    create_zk_vault, ensure_ecc_keypair, unique,
)

pytestmark = pytest.mark.integration

DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
NOT_A_HOLDER = "Only someone who holds this vault's key can rotate it"


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _wrap(user_id):
    return {"user_id": str(user_id), "wrapped_dek": ZK_WRAPPED_DEK_STUB,
            "ephemeral_public_key": ZK_EPHEMERAL_STUB}


def _rotation(from_version, *remaining, revoke=None):
    """A syntactically valid direct rotation body. Its wraps are stubs: the server stores wraps
    verbatim and never opens them, and a refused rotation must not get as far as storing them."""
    return {"from_version": from_version, "to_version": from_version + 1,
            "revoke_user_id": str(revoke) if revoke else None,
            "member_keys": [_wrap(u) for u in remaining]}


def _share(owner, vid, member, member_client, level="read"):
    """Share the way the web app does: the owner wraps the key for the member, then grants access."""
    ensure_ecc_keypair(member_client)
    owner.post(f"/ecc/vaults/{vid}/members", json=_wrap(member["id"])).raise_for_status()
    owner.post(f"/vaults/{vid}/permissions",
               json={"user_id": str(member["id"]), "level": level}).raise_for_status()


def _keys(client, vid):
    r = client.get(f"/ecc/vaults/{vid}/keys")
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def owned_vault(admin, temp_user, temp_user_client):
    """A direct zero-knowledge vault owned by an ordinary user. The session's admin is a global
    admin: it may manage the vault, but it is not a member and was never given the key."""
    with _zk_enabled(admin):
        vid = create_zk_vault(temp_user_client)["id"]
    try:
        yield vid
    finally:
        temp_user_client.delete_vault(vid)


@pytest.fixture
def second_member(admin):
    person = admin.create_user(role="user")
    client = ApiClient()
    client.login(person["_username"], person["_password"])
    try:
        yield person, client
    finally:
        admin.delete_user(person["id"])


# --------------------------------------------------------------------------- the rule

def test_an_admin_without_the_key_cannot_rotate_it_and_the_owner_can(admin, temp_user,
                                                                     temp_user_client, owned_vault):
    vid = owned_vault
    r = admin.post(f"/ecc/vaults/{vid}/rekey", json=_rotation(1, temp_user["id"]))
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == NOT_A_HOLDER
    # Refused before anything was stored: still epoch 1, and the owner's key is the one they had.
    keys = _keys(temp_user_client, vid)
    assert keys["current_dek_version"] == 1 and keys["key_version"] == 1
    assert keys["wrapped_dek"] == ZK_WRAPPED_DEK_STUB and keys["has_access"] is True

    r = temp_user_client.post(f"/ecc/vaults/{vid}/rekey", json=_rotation(1, temp_user["id"]))
    assert r.status_code == 200, r.text
    assert _keys(temp_user_client, vid)["current_dek_version"] == 2


def test_an_admin_without_the_team_key_cannot_rotate_a_hierarchical_vault(admin, temp_user_client):
    """A routine hierarchical rotation needs no private key at all -- the new key is wrapped to the
    team PUBLIC key -- so without the rule anyone who may manage the vault could run one."""
    ensure_ecc_keypair(temp_user_client)
    with _zk_enabled(admin):
        r = temp_user_client.post("/vaults", json={
            "name": unique("hier"), "type": "zero_knowledge",
            "enc_name": ZK_ENC_NAME_STUB, "name_key_version": 1,
            "key_wrapping_mode": "hierarchical",
            "team_public_key": "TEAMPUB-" + uuid.uuid4().hex,
            "team_wrapped_dek": ZK_WRAPPED_DEK_STUB,
            "team_dek_ephemeral_public_key": ZK_EPHEMERAL_STUB,
            "wrapped_team_privkey": ZK_WRAPPED_DEK_STUB,
            "team_privkey_ephemeral_public_key": ZK_EPHEMERAL_STUB,
        })
        r.raise_for_status()
    vid = r.json()["id"]
    routine = {"from_version": 1, "to_version": 2, "member_keys": [],
               "team_dek_wrapped": ZK_WRAPPED_DEK_STUB,
               "team_dek_ephemeral_public_key": ZK_EPHEMERAL_STUB}
    try:
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json=routine)
        assert r.status_code == 403, r.text
        assert r.json()["detail"] == NOT_A_HOLDER
        assert _keys(temp_user_client, vid)["current_dek_version"] == 1

        r = temp_user_client.post(f"/ecc/vaults/{vid}/rekey", json=routine)
        assert r.status_code == 200, r.text
    finally:
        temp_user_client.delete_vault(vid)


def test_a_removal_without_a_rotation_is_owed_to_the_key_holder(admin, temp_user, temp_user_client,
                                                               owned_vault, second_member):
    """What the web app does when the person removing a member does not hold the key: remove the
    access alone. The vault then tells its key holder a rotation is owed, and their rotation --
    one that removes nobody, since the member is already gone -- clears it."""
    vid = owned_vault
    member, member_client = second_member
    _share(temp_user_client, vid, member, member_client)
    assert _keys(member_client, vid)["has_access"] is True
    assert _keys(temp_user_client, vid)["rekey_owed"] is False

    r = admin.delete(f"/vaults/{vid}/permissions/{member['id']}")
    assert r.status_code == 200, r.text
    assert _keys(member_client, vid)["has_access"] is False, "the removed member can still fetch the key"
    assert _keys(temp_user_client, vid)["rekey_owed"] is True

    # The admin who removed them still cannot do the rotation.
    assert admin.post(f"/ecc/vaults/{vid}/rekey",
                      json=_rotation(1, temp_user["id"])).status_code == 403

    r = temp_user_client.post(f"/ecc/vaults/{vid}/rekey", json=_rotation(1, temp_user["id"]))
    assert r.status_code == 200, r.text
    after = _keys(temp_user_client, vid)
    assert after["current_dek_version"] == 2 and after["rekey_owed"] is False


def test_a_member_cannot_be_rotated_out_by_themselves(admin, temp_user, temp_user_client,
                                                     owned_vault):
    """A global admin who IS a member and holds the key may rotate, but not to remove themselves:
    they would learn the new key and then not be given it."""
    vid = owned_vault
    ensure_ecc_keypair(admin)
    temp_user_client.post(f"/ecc/vaults/{vid}/members", json=_wrap(admin.user["id"])).raise_for_status()
    temp_user_client.post(f"/vaults/{vid}/permissions",
                          json={"user_id": str(admin.user["id"]), "level": "read"}).raise_for_status()
    r = admin.post(f"/ecc/vaults/{vid}/rekey",
                   json=_rotation(1, temp_user["id"], revoke=admin.user["id"]))
    assert r.status_code == 403, r.text
    assert "must remain a member" in r.json()["detail"]
    # Rotating with themselves among the recipients is allowed.
    r = admin.post(f"/ecc/vaults/{vid}/rekey", json=_rotation(1, temp_user["id"], admin.user["id"]))
    assert r.status_code == 200, r.text


def test_an_admin_without_the_key_cannot_mint_the_name_index_key(admin, temp_user, temp_user_client,
                                                                owned_vault):
    vid = owned_vault
    body = {"wraps": [{"user_id": str(temp_user["id"]), "encrypted_index_key": ZK_WRAPPED_DEK_STUB,
                       "ephemeral_public_key": ZK_EPHEMERAL_STUB}]}
    r = admin.put(f"/ecc/vaults/{vid}/index-key", json=body)
    assert r.status_code == 403, r.text
    assert temp_user_client.get(f"/ecc/vaults/{vid}/index-key").json()["index_key"] is None
    r = temp_user_client.put(f"/ecc/vaults/{vid}/index-key", json=body)
    assert r.status_code == 200, r.text


# --------------------------------------------------------------------------- the lock

_HOLD = 4


def _hold_vault_row(vid, before_commit=""):
    """Hold a lock that conflicts with FOR UPDATE on the vault row for _HOLD seconds, run
    `before_commit` in the same transaction, then commit. `FOR KEY SHARE` conflicts with FOR UPDATE
    but not with the foreign-key checks ordinary writes take, so a request that waits on it is one
    that asked for the row exclusively."""
    sql = (f"BEGIN; SELECT id FROM vaults WHERE id='{vid}' FOR KEY SHARE; "
           f"SELECT pg_sleep({_HOLD}); {before_commit} COMMIT;")
    try:
        holder = subprocess.Popen(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    time.sleep(1.0)  # let the holder take the lock
    return holder


def _timed(fire):
    t0 = time.time()
    r = fire()
    return r, time.time() - t0


def test_a_rotation_rechecks_the_key_after_it_gets_the_lock(temp_user, temp_user_client, owned_vault):
    """The caller's key is removed by a transaction that holds the vault row while the rotation
    waits for it. Checked on entry, the rotation would go ahead on a key that is gone by the time
    it writes; checked under the lock, the removal is visible and the rotation is refused."""
    vid, uid = owned_vault, temp_user["id"]
    holder = _hold_vault_row(vid, before_commit=(
        f"UPDATE vault_member_keys SET is_active=false WHERE vault_id='{vid}' AND user_id='{uid}';"))
    try:
        r, elapsed = _timed(lambda: temp_user_client.post(f"/ecc/vaults/{vid}/rekey",
                                                          json=_rotation(1, uid)))
    finally:
        holder.wait(timeout=_HOLD + 5)
    assert holder.returncode == 0, "the lock-holding transaction failed"
    assert elapsed >= 2.0, f"the rotation did not wait for the vault row lock ({elapsed:.2f}s)"
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == NOT_A_HOLDER


@pytest.mark.parametrize("route", ["ecc", "permissions"])
def test_removing_a_member_waits_for_the_vault_row_lock(route, admin, temp_user_client, owned_vault,
                                                       second_member):
    """Both removal routes take the lock a rotation holds, so a rotation in flight commits first
    and its new-epoch key for the member is deactivated with the rest, instead of being left
    active for someone who is no longer a member."""
    vid = owned_vault
    member, member_client = second_member
    _share(temp_user_client, vid, member, member_client)
    path = (f"/ecc/vaults/{vid}/members/{member['id']}" if route == "ecc"
            else f"/vaults/{vid}/permissions/{member['id']}")
    holder = _hold_vault_row(vid)
    try:
        r, elapsed = _timed(lambda: temp_user_client.delete(path))
    finally:
        holder.wait(timeout=_HOLD + 5)
    assert r.status_code == 200, r.text
    assert elapsed >= 2.0, f"the removal did not wait for the vault row lock ({elapsed:.2f}s)"
    assert _keys(member_client, vid)["has_access"] is False


def test_a_share_rechecks_the_key_after_it_gets_the_lock(temp_user, temp_user_client, owned_vault,
                                                        second_member):
    """Sharing hands out the key in use now, so the sharer's own key is checked under the lock too:
    removed while the share waited for the lock, it is refused rather than written."""
    vid, uid = owned_vault, temp_user["id"]
    member, member_client = second_member
    ensure_ecc_keypair(member_client)
    holder = _hold_vault_row(vid, before_commit=(
        f"UPDATE vault_member_keys SET is_active=false WHERE vault_id='{vid}' AND user_id='{uid}';"))
    try:
        r, elapsed = _timed(lambda: temp_user_client.post(f"/ecc/vaults/{vid}/members",
                                                          json=_wrap(member["id"])))
    finally:
        holder.wait(timeout=_HOLD + 5)
    assert holder.returncode == 0, "the lock-holding transaction failed"
    assert elapsed >= 2.0, f"the share did not wait for the vault row lock ({elapsed:.2f}s)"
    assert r.status_code == 403, r.text
    assert "current key" in r.json()["detail"]
    # Nothing was written for the member: they still have no key row, so no relationship at all.
    assert member_client.get(f"/ecc/vaults/{vid}/keys").status_code == 403
