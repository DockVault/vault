"""Zero-knowledge team-onboarding for keyless recipients.

A ZK DEK can't be wrapped for a user with no encryption key, so a manager can't share
directly with a keyless recipient. Instead of a dead-end, POST /ecc/vaults/{id}/invites
records the intent; the recipient sees it via GET /ecc/keys/invites and is prompted to set
up a key; registering a keypair clears the invites and the manager re-shares.

HTTP suite against the live vault (conftest).
"""
import contextlib
import subprocess

import pytest

from conftest import ApiClient, ensure_ecc_keypair, create_zk_vault, unique

DB_CONTAINER = "vault-db"


def _psql(sql: str) -> str:
    """Run SQL in the vault DB container; skip cleanly if docker/psql is absent."""
    try:
        proc = subprocess.run(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    assert proc.returncode == 0, f"psql failed: {proc.stderr}"
    return proc.stdout.strip()


@contextlib.contextmanager
def _zk_on(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _login_as(user) -> ApiClient:
    c = ApiClient()
    c.login(user["_username"], user["_password"])
    return c


def test_invite_keyless_then_register_clears(admin):
    """Full lifecycle: manager invites a keyless target -> target sees the pending invite ->
    target registers a keypair -> the invite is cleared."""
    with _zk_on(admin):
        ensure_ecc_keypair(admin)
        vault = create_zk_vault(admin, name=unique("zk"))
        vid = vault["id"]
        target = admin.create_user(role="user")
        try:
            tc = _login_as(target)
            # keyless, no invites yet
            inv = tc.get("/ecc/keys/invites").json()
            assert inv["needs_keypair"] is True and inv["count"] == 0, inv

            # the vault OWNER (admin) invites the keyless target
            r = admin.post(f"/ecc/vaults/{vid}/invites", json={"user_id": target["id"]})
            assert r.status_code == 200, r.text
            assert r.json()["status"] == "invited"

            # target now sees exactly one pending invite for this vault
            inv = tc.get("/ecc/keys/invites").json()
            assert inv["needs_keypair"] is True and inv["count"] == 1, inv
            assert inv["invites"][0]["vault_id"] == vid

            # re-inviting is idempotent (upsert), still one invite
            admin.post(f"/ecc/vaults/{vid}/invites", json={"user_id": target["id"]})
            assert tc.get("/ecc/keys/invites").json()["count"] == 1

            # target sets up a keypair -> invites resolved/cleared
            ensure_ecc_keypair(tc)
            inv = tc.get("/ecc/keys/invites").json()
            assert inv["needs_keypair"] is False and inv["count"] == 0, inv
        finally:
            admin.delete_user(target["id"])
            admin.delete_vault(vid)


def test_invite_user_with_key_rejected(admin):
    """A user who already has a key doesn't need an invite -> 400 (share directly)."""
    with _zk_on(admin):
        ensure_ecc_keypair(admin)
        vid = create_zk_vault(admin, name=unique("zk"))["id"]
        target = admin.create_user(role="user")
        try:
            tc = _login_as(target)
            ensure_ecc_keypair(tc)  # target HAS a key
            r = admin.post(f"/ecc/vaults/{vid}/invites", json={"user_id": target["id"]})
            assert r.status_code == 400, r.text
            assert "already has an encryption key" in r.text
        finally:
            admin.delete_user(target["id"])
            admin.delete_vault(vid)


def test_invite_requires_manager(admin):
    """Only the owner / a manager can invite (same gate as the grant path): a plain,
    non-member user inviting -> 403."""
    with _zk_on(admin):
        ensure_ecc_keypair(admin)
        vid = create_zk_vault(admin, name=unique("zk"))["id"]
        outsider = admin.create_user(role="user")
        target = admin.create_user(role="user")
        try:
            oc = _login_as(outsider)
            r = oc.post(f"/ecc/vaults/{vid}/invites", json={"user_id": target["id"]})
            assert r.status_code == 403, r.text
        finally:
            admin.delete_user(outsider["id"])
            admin.delete_user(target["id"])
            admin.delete_vault(vid)


def test_grant_to_keyless_still_rejected(admin):
    """The DEK-minting grant path still refuses a keyless target (no key to wrap to) — the
    invite endpoint is the actionable path, not grant."""
    with _zk_on(admin):
        ensure_ecc_keypair(admin)
        vid = create_zk_vault(admin, name=unique("zk"))["id"]
        target = admin.create_user(role="user")
        try:
            r = admin.post(f"/ecc/vaults/{vid}/members",
                           json={"user_id": target["id"], "wrapped_dek": "x", "ephemeral_public_key": "y"})
            assert r.status_code == 400, r.text
            assert "has not set up an encryption key" in r.text
        finally:
            admin.delete_user(target["id"])
            admin.delete_vault(vid)


def test_grant_clears_stale_invite(admin):
    """Belt-and-suspenders: a successful grant clears a leftover (vault, target) invite (e.g.
    from a register-cleanup that had previously failed). The endpoint only mints invites for
    KEYLESS targets, so seed the stale row via DB surgery for a KEYED, grantable target."""
    with _zk_on(admin):
        ensure_ecc_keypair(admin)
        vid = create_zk_vault(admin, name=unique("zk"))["id"]
        target = admin.create_user(role="user")
        try:
            tc = _login_as(target)
            ensure_ecc_keypair(tc)  # target keyed -> grantable
            _psql(f"INSERT INTO zk_share_invites (id, vault_id, target_user_id, created_at) "
                  f"VALUES (gen_random_uuid(), '{vid}', '{target['id']}', now())")
            assert _psql(f"SELECT count(*) FROM zk_share_invites WHERE vault_id='{vid}' "
                         f"AND target_user_id='{target['id']}'") == "1"
            r = admin.post(f"/ecc/vaults/{vid}/members",
                           json={"user_id": target["id"], "wrapped_dek": "x", "ephemeral_public_key": "y"})
            assert r.status_code == 200, r.text
            # the successful grant dropped the stale invite
            assert _psql(f"SELECT count(*) FROM zk_share_invites WHERE vault_id='{vid}' "
                         f"AND target_user_id='{target['id']}'") == "0"
        finally:
            admin.delete_user(target["id"])
            admin.delete_vault(vid)
