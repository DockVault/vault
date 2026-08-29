"""The per-vault name-index key: store it, read it, and never overwrite it.

This key exists so that same-name matching survives a rekey. The blind index used to be derived
from (DEK, epoch), so a rotation changed every name's index and silently switched off the guard
that stops an upload-only credential creating a hidden duplicate. The fix is a key that a rekey
does NOT rotate; this increment only stores and serves it, and later work makes the index use it.

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


def test_a_non_member_is_refused_not_handed_a_null(admin, temp_user, temp_user_client, zk_vault):
    """A user with no relationship to the vault is REFUSED (403), not handed a 200 {index_key: null}.
    Answering 200-for-existing / 404-for-absent let any account confirm which vault ids exist;
    the index key also lets its holder confirm a guessed filename (see the endpoint
    docstring), so neither it nor its vault's existence may be released to a non-member. Same
    403-whether-or-not-it-exists posture the DEK endpoint /ecc/vaults/{id}/keys already has. A
    granted member still reaches it (see the tests above); a scoped temp credential is refused too."""
    vid = zk_vault["id"]
    ensure_ecc_keypair(temp_user_client)
    owner_wrap = _wrap(admin.user["id"])
    admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [owner_wrap]}).raise_for_status()

    # Existing vault, no relationship -> 403 (was 200 {index_key: null}); no wrap ever in the body.
    r = temp_user_client.get(f"/ecc/vaults/{vid}/index-key")
    assert r.status_code == 403, r.text
    assert owner_wrap["encrypted_index_key"] not in r.text
    # A vault id that does not exist -> also 403, so 403-vs-404 cannot confirm existence.
    assert temp_user_client.get(f"/ecc/vaults/{uuid.uuid4()}/index-key").status_code == 403


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


def test_adding_a_wrap_for_a_new_member_succeeds_and_leaves_the_key(admin, temp_user, temp_user_client, zk_vault):
    """Share case: once the key is minted, a wrap can be ADDED for a member who has none, without
    replacing the key. The new member reads their wrap; the original owner's wrap is untouched."""
    vid = zk_vault["id"]
    ensure_ecc_keypair(temp_user_client)
    owner_wrap = _wrap(admin.user["id"])
    admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [owner_wrap]}).raise_for_status()

    admin.post(f"/vaults/{vid}/permissions",
               json={"user_id": str(temp_user["id"]), "level": "read"}).raise_for_status()
    member_wrap = _wrap(temp_user["id"])
    r = admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [member_wrap]})
    assert r.status_code == 200, r.text

    # The new member gets THEIR wrap; the owner still gets the original.
    assert temp_user_client.get(f"/ecc/vaults/{vid}/index-key").json()["index_key"] == member_wrap["encrypted_index_key"]
    assert admin.get(f"/ecc/vaults/{vid}/index-key").json()["index_key"] == owner_wrap["encrypted_index_key"]


def test_re_wrapping_an_existing_member_is_refused(admin, zk_vault):
    """The key is immutable at a version: a second wrap for a member who already has one is a 409,
    not an overwrite -- that would swap the key under them. (Replacing the key is a version bump,
    a separate opt-in operation.)"""
    vid = zk_vault["id"]
    first = _wrap(admin.user["id"])
    admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [first]}).raise_for_status()

    r = admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [_wrap(admin.user["id"])]})
    assert r.status_code == 409, r.text
    # Unchanged.
    assert admin.get(f"/ecc/vaults/{vid}/index-key").json()["index_key"] == first["encrypted_index_key"]


def test_a_mixed_body_touching_an_existing_member_is_refused_whole(admin, temp_user, zk_vault):
    """A body that adds a new member AND re-wraps an existing one is refused entirely -- partial
    success would leave the caller unsure which wraps landed. Neither is written."""
    vid = zk_vault["id"]
    owner_wrap = _wrap(admin.user["id"])
    admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [owner_wrap]}).raise_for_status()
    admin.post(f"/vaults/{vid}/permissions",
               json={"user_id": str(temp_user["id"]), "level": "read"}).raise_for_status()

    # owner (exists) + temp_user (new) in one body -> 409, and the new member is NOT added.
    r = admin.put(f"/ecc/vaults/{vid}/index-key",
                  json={"wraps": [_wrap(admin.user["id"]), _wrap(temp_user["id"])]})
    assert r.status_code == 409, r.text
    # Nothing was half-written: a follow-up add for ONLY the new member still succeeds, which it
    # could not if the refused body had already inserted that member's row.
    # temp_user still has no wrap (the whole body was refused).
    ok = admin.put(f"/ecc/vaults/{vid}/index-key", json={"wraps": [_wrap(temp_user["id"])]})
    assert ok.status_code == 200, ok.text
