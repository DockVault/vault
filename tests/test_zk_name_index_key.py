"""The per-vault name-index key: store it, read it, and never overwrite it.

This key exists so that same-name matching survives a rekey. The blind index used to be derived
from (DEK, epoch), so a rotation changed every name's index and silently switched off the guard
that stops an upload-only credential creating a hidden duplicate. The fix is a key that a rekey
does NOT rotate; this phase (N1) only stores and serves it, and later phases make the index use it.

The properties worth pinning here, because they are the ones a later phase will rely on:

* a member can read their wrapped copy, and a non-member cannot;
* `null` is the ordinary answer for a vault that has none yet, not an error, because that is the
  state every existing vault starts in and the client must be able to tell "no key yet" from
  "no access";
* it is create-once: two clients racing to mint it must not leave half the members holding a wrap
  of one key and half a wrap of another, because then every index is computed under a key some
  members do not have.
"""
import uuid

import pytest

from conftest import unique, ensure_ecc_keypair, create_zk_vault


def _wrap(user_id):
    """One member's wrapped copy of the index key -- opaque material, like a DEK wrap."""
    return {
        "user_id": str(user_id),
        "encrypted_index_key": f"idxkey-{uuid.uuid4().hex}",
        "ephemeral_public_key": f"eph-{uuid.uuid4().hex}",
    }


@pytest.fixture
def zk_vault(admin):
    ensure_ecc_keypair(admin)
    with _zk(admin):
        v = create_zk_vault(admin)
    yield v
    admin.delete_vault(v["id"])


import contextlib


@contextlib.contextmanager
def _zk(client):
    """Enable zero-knowledge vault creation for the duration, then restore."""
    before = client.get("/settings").json()
    client.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        client.put("/settings", json={
            "zero_knowledge_enabled": before.get("zero_knowledge_enabled", False)})


def test_a_vault_without_a_key_answers_null_not_404(admin, zk_vault):
    """A vault that has never been given a key returns null. Every existing vault is in this state,
    and a 404 would force every caller to treat the normal migration state as a failure."""
    r = admin.get(f"/ecc/vaults/{zk_vault['id']}/index-key")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["index_key"] is None
    assert body["index_key_version"] is None


def test_store_then_read_round_trips(admin, zk_vault):
    vid = zk_vault["id"]
    mine = _wrap(admin.user["id"])
    put = admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [mine]})
    assert put.status_code == 200, put.text
    assert put.json()["index_key_version"] == 1

    got = admin.get(f"/ecc/vaults/{vid}/index-key").json()
    assert got["index_key"] == mine["encrypted_index_key"]
    assert got["ephemeral_public_key"] == mine["ephemeral_public_key"]
    assert got["index_key_version"] == 1


def test_minting_twice_is_refused_not_overwritten(admin, zk_vault):
    """Create-once. A second mint at the same version must 409, or a race leaves members disagreeing
    about what a name hashes to -- half wrapping one key, half another, every index wrong."""
    vid = zk_vault["id"]
    first = _wrap(admin.user["id"])
    assert admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [first]}).status_code == 200

    second = admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [_wrap(admin.user["id"])]})
    assert second.status_code == 409, second.text

    # The first key is intact -- the refused second call changed nothing.
    got = admin.get(f"/ecc/vaults/{vid}/index-key").json()
    assert got["index_key"] == first["encrypted_index_key"]


def test_a_member_who_joined_after_minting_gets_their_wrap(admin, temp_user, temp_user_client, zk_vault):
    """The key is wrapped per member. A member added in the same PUT can read their own wrap and
    only their own -- the read is keyed by the caller, not the vault."""
    vid = zk_vault["id"]
    ensure_ecc_keypair(temp_user_client)
    # authz so the member may release keys at all
    admin.post(f"/vaults/{vid}/permissions",
               json={"user_id": str(temp_user["id"]), "level": "read"}).raise_for_status()

    owner_wrap = _wrap(admin.user["id"])
    member_wrap = _wrap(temp_user["id"])
    admin.put(f"/ecc/vaults/{vid}/index-key",
              json={"wraps": [owner_wrap, member_wrap]}).raise_for_status()

    seen = temp_user_client.get(f"/ecc/vaults/{vid}/index-key").json()
    assert seen["index_key"] == member_wrap["encrypted_index_key"]
    assert seen["index_key"] != owner_wrap["encrypted_index_key"], "a member must not get the owner's wrap"


def test_a_non_member_gets_no_key_material(admin, temp_user, temp_user_client, zk_vault):
    """A user with no wrap gets null, never someone else's wrap. The read is filtered by the
    caller's own id, which is the property that actually protects the key material -- the same
    posture as the DEK endpoint, which also returns a caller only their own wrapped copy. (A
    regular session is not refused outright the way a scoped temp credential is; the protection is
    that there is nothing there for them.)"""
    vid = zk_vault["id"]
    ensure_ecc_keypair(temp_user_client)
    owner_wrap = _wrap(admin.user["id"])
    admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [owner_wrap]}).raise_for_status()

    r = temp_user_client.get(f"/ecc/vaults/{vid}/index-key")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["index_key"] is None, "a non-member must get null, never the owner's wrap"
    assert owner_wrap["encrypted_index_key"] not in r.text


def test_a_non_manager_cannot_mint(admin, temp_user, temp_user_client, zk_vault):
    """Handing a member a wrap binds who can compute this vault's indices -- a management decision,
    same class as granting a DEK. A plain member with read access must not be able to mint."""
    vid = zk_vault["id"]
    ensure_ecc_keypair(temp_user_client)
    admin.post(f"/vaults/{vid}/permissions",
               json={"user_id": str(temp_user["id"]), "level": "read"}).raise_for_status()

    r = temp_user_client.put(f"/ecc/vaults/{vid}/index-key",
                             json={"wraps": [_wrap(temp_user["id"])]})
    assert r.status_code == 403, r.text


def test_a_bad_user_id_is_a_clean_400(admin, zk_vault):
    vid = zk_vault["id"]
    r = admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [
        {"user_id": "not-a-uuid", "encrypted_index_key": "k", "ephemeral_public_key": "e"}]})
    assert r.status_code == 400, r.text
