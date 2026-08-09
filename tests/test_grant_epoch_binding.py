"""A wrapped key is only meaningful paired with the epoch it was built against.

The grant endpoint used to stamp whichever epoch the vault row happened to hold when the request
landed. The client is the only party that knows which epoch its blob actually wraps, and nobody was
asking it.

That gap is not a lost update, it is worse. The member-key table is keyed on
`(vault, user, key_version)`, so when a rotation and a share race:

  1. the rotation writes the member a correct row at epoch N+1;
  2. the share, having wrapped the OLD key, reads N+1 and stamps it;
  3. the upsert finds the rotation's row and **overwrites it**.

The member is left holding a row labelled N+1 that contains the key for N. Every file written
after the rotation stops opening for them, and nothing anywhere reports a failure at the time it
happens -- the wrap is valid, it is simply the wrong one, and the label says otherwise.

The fix is the mechanism `rekey_vault` already uses elsewhere in the same module: the client
declares the epoch it built against, the server verifies it under the vault row lock, and a
mismatch is a 409.
"""

import os
import subprocess
import time
import uuid

import pytest

from conftest import unique, ensure_ecc_keypair, create_zk_vault

DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _stub(prefix="w"):
    import base64
    return base64.b64encode(f"{prefix}-{uuid.uuid4().hex}".encode()).decode()


def _create_direct_zk_vault(admin):
    ensure_ecc_keypair(admin)
    return create_zk_vault(admin, name=unique("epochbind"))


@pytest.mark.integration
def test_a_share_declaring_a_stale_epoch_is_refused(admin, temp_user, temp_user_client):
    """A share declaring an epoch other than the live one is refused.

    Note what this does and does not establish. The rotation below commits *before* the share
    is issued, so only the client is in the stale state -- the server is not racing anything.
    It pins the 409 predicate, which is the part an operator meets in practice; the row lock
    that makes the predicate meaningful under a genuine interleaving is pinned separately, by
    `test_the_grant_serializes_against_a_held_vault_lock`, because no amount of sequencing in
    this test can reach it.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        v = _create_direct_zk_vault(admin)
        vid = v["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})

    try:
        ensure_ecc_keypair(temp_user_client)
        # Rotate so the live epoch is 2 and epoch 1 is stale.
        me = admin.get("/users/me").json()["id"]
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": None,
            "member_keys": [{"user_id": str(me), "wrapped_dek": _stub("dek"),
                             "ephemeral_public_key": _stub("eph")}],
        })
        assert r.status_code == 200, r.text

        stale = admin.post(f"/ecc/vaults/{vid}/members", json={
            "user_id": temp_user["id"], "wrapped_dek": _stub("dek"),
            "ephemeral_public_key": _stub("eph"), "dek_version": 1,
        })
        assert stale.status_code == 409, (
            "a share declaring a superseded epoch was accepted; it would have been stamped as "
            f"current and the recipient left unable to read: {stale.status_code} {stale.text}"
        )
        # `rekey_vault` emits the same "re-keyed concurrently" phrase, so match the clause that
        # only this guard produces -- otherwise the assertion cannot tell which one fired.
        assert "re-share" in stale.text

        # The same share at the live epoch succeeds, so the guard rejects staleness and not
        # sharing in general.
        good = admin.post(f"/ecc/vaults/{vid}/members", json={
            "user_id": temp_user["id"], "wrapped_dek": _stub("dek"),
            "ephemeral_public_key": _stub("eph"), "dek_version": 2,
        })
        assert good.status_code == 200, good.text
    finally:
        admin.delete_vault(vid)


@pytest.mark.integration
def test_a_refused_share_leaves_the_existing_row_untouched(admin, temp_user, temp_user_client):
    """Refusing must not be destructive.

    The whole point is that a stale share was silently *replacing* a good row. A guard that
    rejected the request but still disturbed the row would have moved the bug rather than fixed it.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        v = _create_direct_zk_vault(admin)
        vid = v["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})

    try:
        ensure_ecc_keypair(temp_user_client)
        good_blob = _stub("keepme")
        r = admin.post(f"/ecc/vaults/{vid}/members", json={
            "user_id": temp_user["id"], "wrapped_dek": good_blob,
            "ephemeral_public_key": _stub("eph"), "dek_version": 1,
        })
        assert r.status_code == 200, r.text

        before = temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()
        assert before["wrapped_dek"] == good_blob

        rejected = admin.post(f"/ecc/vaults/{vid}/members", json={
            "user_id": temp_user["id"], "wrapped_dek": _stub("clobber"),
            "ephemeral_public_key": _stub("eph"), "dek_version": 99,
        })
        assert rejected.status_code == 409, rejected.text

        after = temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()
        assert after["wrapped_dek"] == good_blob, "the refused share still overwrote the row"
    finally:
        admin.delete_vault(vid)


@pytest.mark.integration
def test_a_client_that_omits_the_epoch_still_works(admin, temp_user, temp_user_client):
    """Backward compatibility, and it is load-bearing rather than politeness.

    The client is two classic scripts behind a cache-buster, so a stale tab is a real deployment
    state. Making the field mandatory would turn every such tab's share into a hard failure. An
    omitted epoch keeps the old behaviour; it does not get the new guarantee, which is the honest
    trade and the reason the field is optional rather than required.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        v = _create_direct_zk_vault(admin)
        vid = v["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})

    try:
        ensure_ecc_keypair(temp_user_client)
        r = admin.post(f"/ecc/vaults/{vid}/members", json={
            "user_id": temp_user["id"], "wrapped_dek": _stub("dek"),
            "ephemeral_public_key": _stub("eph"),
        })
        assert r.status_code == 200, r.text
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
    finally:
        admin.delete_vault(vid)


@pytest.mark.integration
def test_the_keys_response_names_the_account_it_selected_for(admin):
    """A reader that binds the recipient into a transcript needs an authenticated source for it.

    The only client-side answer was `currentUser`, and this codebase already refuses that source
    for this purpose -- the recovery-kit writer carries a comment saying it is hydrated from
    localStorage by a loader that tolerates corrupt data. The server selects the row on the
    session's account id, so it can simply say which one it used.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        v = _create_direct_zk_vault(admin)
        vid = v["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})

    try:
        me = admin.get("/users/me").json()["id"]
        keys = admin.get(f"/ecc/vaults/{vid}/keys").json()
        assert keys["has_access"] is True
        assert keys.get("recipient_user_id") == str(me), (
            "the keys response does not name the account its row was selected for"
        )
    finally:
        admin.delete_vault(vid)


_HOLD = 4


def _assert_blocks_on_vault_lock(vid, fire):
    """Hold a conflicting lock on the vault row, then assert `fire()` had to wait for it.

    Borrowed from the retire-version suite, which needed the same proof. `FOR KEY SHARE` conflicts
    with `FOR UPDATE` but not with the foreign-key checks ordinary writes take, so a request that
    blocks here is one that genuinely asked for the row exclusively.
    """
    sql = (f"BEGIN; SELECT id FROM vaults WHERE id='{vid}' FOR KEY SHARE; "
           f"SELECT pg_sleep({_HOLD}); COMMIT;")
    try:
        holder = subprocess.Popen(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    try:
        time.sleep(1.0)  # let the holder take the lock
        t0 = time.time()
        r = fire()
        elapsed = time.time() - t0
        assert r.status_code == 200, r.text
        assert elapsed >= 2.0, (
            f"the grant did not block on the held vault lock (took {elapsed:.2f}s) -- it is not "
            "taking FOR UPDATE, so its epoch read is not serialized against a concurrent rotation"
        )
    finally:
        holder.wait(timeout=_HOLD + 5)


@pytest.mark.integration
def test_the_grant_serializes_against_a_held_vault_lock(admin, temp_user, temp_user_client):
    """The lock, pinned directly -- the 409 tests cannot see it.

    Every test that drives a rotation to completion first leaves both server reads looking at the
    same committed epoch, so the interleaving the lock exists for never occurs and the lock could
    be deleted with the suite still green. This one holds a conflicting lock from outside and
    asserts the request waits, which is the only observable the lock has.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        vid = _create_direct_zk_vault(admin)["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})

    try:
        ensure_ecc_keypair(temp_user_client)
        _assert_blocks_on_vault_lock(vid, lambda: admin.post(
            f"/ecc/vaults/{vid}/members",
            json={"user_id": temp_user["id"], "wrapped_dek": _stub("dek"),
                  "ephemeral_public_key": _stub("eph"), "dek_version": 1},
        ))
    finally:
        admin.delete_vault(vid)


@pytest.mark.integration
def test_a_hierarchical_grant_refuses_an_epoch_it_cannot_honour(admin, temp_user, temp_user_client):
    """A field that is accepted but never read is indistinguishable from one that was checked.

    Hierarchical member rows are keyed by the team epoch, so a declared DEK epoch could not be
    meaningful there even if the branch read it. Returning 200 would tell the caller their blob was
    verified against something. Refusing says plainly that it was not.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        r = admin.post("/vaults", json={
            "name": unique("hierepoch"),
            "type": "zero_knowledge",
            "key_wrapping_mode": "hierarchical",
            "team_public_key": "TEAMPUB-" + uuid.uuid4().hex,
            "team_wrapped_dek": _stub("tdek"),
            "team_dek_ephemeral_public_key": _stub("teph"),
            "wrapped_team_privkey": _stub("tpriv"),
            "team_privkey_ephemeral_public_key": _stub("tpeph"),
        })
        r.raise_for_status()
        vid = r.json()["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})

    try:
        ensure_ecc_keypair(temp_user_client)
        bad = admin.post(f"/ecc/vaults/{vid}/members", json={
            "user_id": temp_user["id"], "wrapped_team_privkey": _stub("tpriv"),
            "team_ephemeral_public_key": _stub("tpeph"), "dek_version": 1,
        })
        assert bad.status_code == 400, (
            f"a hierarchical grant accepted a DEK epoch it never reads: {bad.status_code} {bad.text}"
        )
        assert "hierarchical" in bad.text

        # Omitted, the same grant succeeds -- so the guard rejects the field, not the flow.
        ok = admin.post(f"/ecc/vaults/{vid}/members", json={
            "user_id": temp_user["id"], "wrapped_team_privkey": _stub("tpriv"),
            "team_ephemeral_public_key": _stub("tpeph"),
        })
        assert ok.status_code == 200, ok.text
        # And the echo is present on this branch too, not only the direct one.
        me = admin.get("/users/me").json()["id"]
        assert admin.get(f"/ecc/vaults/{vid}/keys").json().get("recipient_user_id") == str(me)
    finally:
        admin.delete_vault(vid)
