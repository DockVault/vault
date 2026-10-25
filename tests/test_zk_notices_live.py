"""Live: who is told about zero-knowledge keys, and when.

* A key change refused because it did not come with the account's own encryption key tells the account's
  user in the app (and by email, with a mail sink), once for a burst of attempts.
* An owner's reset of a vault's key tells every other manager, and not a plain member or the owner.
* Setting up an encryption key tells the account's user.
* The share dialog's lookup of a recipient's key says when it was set up, and whether that was within 14
  days after an administrator changed the account's sign-in details (on at 13 days, off at 15), or while its
  password was one an administrator chose (on for an account an administrator created, off once the person
  set their own).
test_zk_notices.py pins the same offline.
"""
import contextlib
import os
import subprocess
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from conftest import (
    ApiClient, ZK_EPHEMERAL_STUB, ZK_WRAPPED_DEK_STUB, create_zk_vault, ensure_ecc_keypair, post_zk, unique,
)
from _account_change_helpers import MAILPIT_URL, mail_sink, mail_to

pytestmark = pytest.mark.integration

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
REFUSED = "A change to a vault's key was refused"
RESET = "A vault's key was reset by its owner"
REGISTERED = "An encryption key was set up for your account"
needs_mailpit = pytest.mark.skipif(not MAILPIT_URL, reason="no mail sink (VAULT_MAILPIT_URL) for this run")


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

    def make(prefix="zn", key=True):
        user = admin.create_user(username=unique(prefix))
        client = ApiClient()
        client.login(user["_username"], user["_password"])
        if key:
            ensure_ecc_keypair(client)
        made.append(user)
        return user, client

    yield make
    for user in made:
        admin.delete_user(user["id"])


def _titles(client):
    r = client.get("/notifications", params={"limit": 100})
    assert r.status_code == 200, r.text
    return [n["title"] for n in r.json()["notifications"] if n["type"] == "encryption_key"]


def _share(user_id):
    return {"user_id": str(user_id), "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": ZK_EPHEMERAL_STUB}


def test_a_refused_change_without_the_accounts_key_is_told_once_for_a_burst(admin, people):
    owner, oc = people("znvic")
    target, _ = people("zntgt")
    with _zk_enabled(admin):
        vid = create_zk_vault(oc)["id"]
    try:
        assert REFUSED not in _titles(oc)
        foreign = {"identity": ec.generate_private_key(ec.SECP384R1())}
        for _ in range(3):
            r = post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share(target["id"]), roles=foreign)
            assert r.status_code == 403 and r.json()["reason"] == "zk-key-proof-failed", r.text
        assert _titles(oc).count(REFUSED) == 1
        # A refusal for another reason (the right identity key, the wrong key of the vault) tells nobody.
        r = post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share(target["id"]),
                    roles={"current": ec.generate_private_key(ec.SECP384R1())})
        assert r.status_code == 403, r.text
        assert _titles(oc).count(REFUSED) == 1
    finally:
        oc.delete_vault(vid)


@needs_mailpit
def test_the_refused_change_is_told_by_email_once(admin, people):
    with mail_sink(admin):
        owner, oc = people("znmail")
        target, _ = people("znmt")
        with _zk_enabled(admin):
            vid = create_zk_vault(oc)["id"]
        try:
            foreign = {"identity": ec.generate_private_key(ec.SECP384R1())}
            for _ in range(2):
                post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share(target["id"]), roles=foreign)
            email = f"{owner['_username']}@example.com"
            message = mail_to(email, subject_contains="About the encryption keys")
            assert message and "was refused" in message["text"], message
        finally:
            oc.delete_vault(vid)


def _damage(vid):
    stray = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    _psql(f"UPDATE vault_key_proofs SET proof_public_key = '{stray}' WHERE vault_id = '{vid}'")


def test_an_owner_reset_tells_every_other_manager_and_nobody_else(admin, people):
    owner, oc = people("znor")
    m1, c1 = people("znm1")
    m2, c2 = people("znm2")
    reader, rc = people("znrd")
    with _zk_enabled(admin):
        vid = create_zk_vault(oc)["id"]
    try:
        for user, level in ((m1, "manage"), (m2, "manage"), (reader, "read")):
            post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share(user["id"])).raise_for_status()
            oc.post(f"/vaults/{vid}/permissions", json={"user_id": user["id"], "level": level}).raise_for_status()
        _damage(vid)
        members = [owner["id"], m1["id"], m2["id"], reader["id"]]
        r = post_zk(oc, f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "owner_reset": True,
            "member_keys": [_share(u) for u in members]})
        assert r.status_code == 200, r.text
        assert _titles(c1).count(RESET) == 1 and _titles(c2).count(RESET) == 1
        assert RESET not in _titles(rc) and RESET not in _titles(oc)
        assert owner["_username"] in next(n["body"] for n in c1.get("/notifications").json()["notifications"]
                                          if n["title"] == RESET)
    finally:
        oc.delete_vault(vid)


def test_setting_up_a_key_tells_its_user(admin, people):
    user, client = people("znreg", key=False)
    assert REGISTERED not in _titles(client)
    ensure_ecc_keypair(client)
    assert _titles(client).count(REGISTERED) == 1


def _applied_change(user_id, days_ago):
    _psql("INSERT INTO credential_changes (id, target_user_id, kind, status, requested_by_name, requested_at, "
          f"applied_at) VALUES ('{uuid.uuid4()}', '{user_id}', 'password', 'made', 'admin', "
          f"(now() AT TIME ZONE 'utc') - interval '{int(days_ago)} days', "
          f"(now() AT TIME ZONE 'utc') - interval '{int(days_ago)} days')")


def _with_own_password(user):
    """The account's password made the person's own, as they would (PATCH /users/me), and a session with it. An
    account a test creates holds the password the administrator chose, which alone flags a key set up with it."""
    from _account_change_helpers import own_password
    own_password(user)
    assert _psql(f"SELECT password_set_by_other_at IS NULL FROM users WHERE id = '{user['id']}'") == "t"
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    return client


def _flag(admin, user_id):
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]      # the lookup is for people who manage a vault
    try:
        pk = admin.get(f"/ecc/users/{user_id}/public-key").json()
        assert pk["has_keypair"] is True and pk["registered_at"], pk
        return pk["registered_after_admin_change"]
    finally:
        admin.delete_vault(vid)


@pytest.mark.parametrize("days_ago,flagged", [(13, True), (15, False)])
def test_the_share_dialog_flags_a_key_set_up_soon_after_an_administrators_change(admin, people, days_ago, flagged):
    user, _ = people("znflag", key=False)
    client = _with_own_password(user)
    _applied_change(user["id"], days_ago)
    ensure_ecc_keypair(client)
    assert _flag(admin, user["id"]) is flagged


def test_a_key_set_up_with_no_administrators_change_is_not_flagged(admin, people):
    user, _ = people("znplain", key=False)
    ensure_ecc_keypair(_with_own_password(user))
    assert _flag(admin, user["id"]) is False


def test_a_key_set_up_with_the_password_an_administrator_chose_is_flagged(admin, people):
    """An administrator created the account with a password it chose, and nothing since recorded a change of its
    sign-in details: whoever chose the password can sign in as the person and set up the key first. The key set
    up with it is flagged, as one set up after a recorded change is."""
    user, client = people("znmade", key=False)
    assert _psql(f"SELECT password_set_by_other_at IS NOT NULL FROM users WHERE id = '{user['id']}'") == "t"
    assert _psql(f"SELECT count(*) FROM credential_changes WHERE target_user_id = '{user['id']}'") == "0"
    ensure_ecc_keypair(client)
    assert _flag(admin, user["id"]) is True
