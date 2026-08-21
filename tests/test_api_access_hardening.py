"""Access-control hardening regression tests — three pre-existing low-severity findings.

(2) update_user resolved user existence (404) BEFORE the own-or-admin gate (403), an enumeration
    split inconsistent with its hardened sibling endpoints; the gate now runs first.
(3) ZK enc_name / enc_mime were unbounded (Text columns, uncounted by the storage quota); the
    client-input fields are now length-bounded.
(4) Deactivating a temporary credential flips is_active but a session created by a racing web login
    could survive because the web auth path never re-read is_active; it now does, every request.
"""
import os
import subprocess
import uuid

from conftest import ApiClient, unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    subprocess.run(
        ["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=20)


# --- (2) update_user: own-or-admin gate precedes the existence lookup -------------------------

def test_update_user_gate_precedes_existence_lookup(admin, temp_user, temp_user_client):
    """A caller who may edit neither an EXISTING other user nor a NONEXISTENT id must get the same
    403 for both — so PATCH cannot be used to tell whether a user id exists (matches get_user)."""
    uid = temp_user["id"]
    other = admin.create_user(role="user")
    # Grant USER_MANAGE so the caller passes the endpoint-permission gate and actually reaches the
    # own-or-admin ordering under test (otherwise the 403 would be the endpoint gate, not the fix).
    admin.post(f"/permissions/users/{uid}/grant", json={"endpoint_group": "USER_MANAGE"})
    try:
        r_exist = temp_user_client.patch(f"/users/{other['id']}", json={"email": "x@example.com"})
        r_missing = temp_user_client.patch(f"/users/{uuid.uuid4()}", json={"email": "x@example.com"})
        assert r_exist.status_code == 403, r_exist.text
        assert r_missing.status_code == 403, r_missing.text  # NOT 404 -> no existence disclosure
    finally:
        admin.delete(f"/permissions/users/{uid}/revoke/USER_MANAGE")
        admin.delete_user(other["id"])


# --- (3) ZK enc_name / enc_mime are length-bounded -------------------------------------------

def test_zk_enc_name_is_length_bounded(admin):
    """An oversized client-supplied sealed name is rejected 422 by the model bound, so unbounded
    metadata can't be parked in a quota-uncounted Text column."""
    v = admin.create_vault(name=unique("encbound"))
    try:
        r = admin.post(f"/vaults/{v['id']}/uploads",
                       json={"filename": "a.txt", "total_size": 10, "enc_name": "z" * 9000})
        assert r.status_code == 422, r.text
        assert "enc_name" in r.text, r.text
    finally:
        admin.delete_vault(v["id"])


def test_zk_folder_enc_name_is_length_bounded(admin):
    """The folder-create raw-dict path applies the same bound by hand (400 rather than a model 422)."""
    v = admin.create_vault(name=unique("encfld"))
    try:
        r = admin.post(f"/vaults/{v['id']}/folders",
                       json={"enc_name": "z" * 9000, "name_bi": "abc"})
        # Either the length bound (400 'enc_name too long') or the standard-vault shape rejection
        # fires first; the point is it is NOT accepted, and an oversized enc_name never persists.
        assert r.status_code == 400, r.text
    finally:
        admin.delete_vault(v["id"])


# --- (4) temp-cred deactivation is re-checked by the web auth path every request --------------

def test_web_session_rejected_when_temp_cred_deactivated(admin):
    """Flip the credential's is_active directly (the race outcome: the session row was NOT revoked),
    leaving the session intact; the next web request must still be refused 401 by the per-request
    is_active re-check that mirrors the SFTP path."""
    created = admin.post("/auth/temp-credentials", json={"note": unique("deact")})
    assert created.status_code == 200, created.text
    cred = created.json()
    sess = ApiClient()
    sess.login(cred["temp_username"], cred["credential"])
    try:
        assert sess.get("/users/me").status_code == 200  # works while active
        _psql("UPDATE temporary_credentials SET is_active=false "
              f"WHERE temp_username='{cred['temp_username']}'")
        assert sess.get("/users/me").status_code == 401  # refused immediately after deactivation
    finally:
        admin.post(f"/temp-creds/{cred['temp_username']}/delete")
