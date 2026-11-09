"""Sending an invitation again (POST /invites/{id}/resend), and who invited in the list.

A resend revokes the invitation and makes it anew (same name, address, role, maker and lineage) with a new
link, so the old one is dead at once on every path; it takes a fresh expiry from the policy, is recorded
without the plaintext, and is refused for anything but a pending invitation, for anyone but an interactive
administrator, and for any administrator but the one who made the invitation. The list names the inviter.
"""
import os
import subprocess

import pytest

from conftest import ApiClient, unique

pytestmark = pytest.mark.integration

DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
PW = "TestPassw0rd!123"
ACCOUNT_KEYS = ("email_requirement", "invite_enabled", "invite_ttl_hours", "signup_enabled",
                "signup_email_domain_mode", "signup_email_domains", "login_identifier",
                "email_change_requires_verification")


def _psql(sql, fetch=True):
    cmd = ["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db"]
    cmd += ["-tAc", sql] if fetch else ["-c", sql]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, f"psql failed: {out.stderr[:400]}"
    return out.stdout.strip()


def _q(v):
    return "'" + str(v).replace("'", "''") + "'"


@pytest.fixture
def invites_on(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ACCOUNT_KEYS}
    r = admin.put("/settings", json={
        "invite_enabled": True, "invite_ttl_hours": 48,
        "email_requirement": "optional", "signup_email_domain_mode": "off", "signup_email_domains": []})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


def test_resend_mints_a_new_link_and_kills_the_old_one(admin, invites_on):
    inv = admin.post("/invites", json={"username": unique("rs"), "role": "user"}).json()
    assert admin.get(f"/invites/{inv['token']}").status_code == 200
    r = admin.post(f"/invites/{inv['id']}/resend")
    assert r.status_code == 200, r.text
    again = r.json()
    assert again["id"] != inv["id"] and again["resent"] is True and again["status"] == "pending"
    assert again["token"] != inv["token"] and again["token_prefix"] != inv["token_prefix"]
    assert "invite=" + again["token"] in again["invite_url"]
    # The old link is dead at once; the new one claims the same username.
    assert admin.get(f"/invites/{inv['token']}").status_code == 404
    new = admin.get(f"/invites/{again['token']}")
    assert new.status_code == 200 and new.json()["username"] == inv["username"]
    # A fresh expiry from the policy's lifetime (48 hours here) on the new row; the old row is revoked, and the
    # new one keeps the maker.
    secs = _psql(f"SELECT EXTRACT(EPOCH FROM (expires_at - now())) FROM account_invitations WHERE id={_q(again['id'])}")
    assert 47.0 < float(secs) / 3600.0 < 49.0
    rows = {x["id"]: x for x in admin.get("/invites").json() if x["username"] == inv["username"]}
    assert set(rows) == {inv["id"], again["id"]}
    assert rows[inv["id"]]["status"] == "revoked"
    assert rows[again["id"]]["status"] == "pending" and rows[again["id"]]["token_prefix"] == again["token_prefix"]
    assert rows[again["id"]]["created_by"] == rows[inv["id"]]["created_by"]
    # Recorded, with the new and the replaced prefix, never the plaintext.
    recorded = _psql("SELECT count(*) FROM audit_logs WHERE action='account_invitation_resent' "
                     f"AND details::text LIKE {_q('%' + again['token_prefix'] + '%')} "
                     f"AND details::text LIKE {_q('%' + inv['token_prefix'] + '%')}")
    assert int(recorded) >= 1
    for tok in (inv["token"], again["token"]):
        assert int(_psql(f"SELECT count(*) FROM audit_logs WHERE details::text LIKE {_q('%' + tok + '%')}")) == 0
    admin.delete(f"/invites/{again['id']}")


def test_only_the_administrator_who_made_an_invitation_can_resend_it_and_the_old_link_dies(admin, invites_on):
    inv = admin.post("/invites", json={"username": unique("adm"), "role": "admin"}).json()
    other = admin.create_user(role="admin")
    made = None
    try:
        c = ApiClient(); c.login(other["_username"], other["_password"])
        r = c.post(f"/invites/{inv['id']}/resend")
        assert r.status_code == 403 and "Only the administrator who sent this invitation" in r.text, r.text
        assert admin.get(f"/invites/{inv['token']}").status_code == 200   # a refused resend changes nothing
        # The maker may: the invitation is made anew with the same maker and lineage, and the old link is dead.
        r = admin.post(f"/invites/{inv['id']}/resend")
        assert r.status_code == 200, r.text
        made = r.json()
        assert made["id"] != inv["id"] and made["role"] == "admin"
        assert admin.get(f"/invites/{inv['token']}").status_code == 404
        assert admin.get(f"/invites/{made['token']}").status_code == 200
        before, after = (_psql(f"SELECT created_by::text || '|' || COALESCE(inviter_lineage::text, '') "
                               f"FROM account_invitations WHERE id={_q(i)}") for i in (inv["id"], made["id"]))
        assert before == after and before.split("|")[1] != ""
        assert _psql(f"SELECT revoked_at IS NOT NULL FROM account_invitations WHERE id={_q(inv['id'])}") == "t"
    finally:
        admin.delete_user(other["id"])
        admin.delete(f"/invites/{inv['id']}")
        if made:
            admin.delete(f"/invites/{made['id']}")


def test_only_a_pending_invitation_can_be_resent(admin, invites_on):
    revoked = admin.post("/invites", json={"username": unique("rr"), "role": "user"}).json()
    admin.delete(f"/invites/{revoked['id']}")
    assert admin.post(f"/invites/{revoked['id']}/resend").status_code == 400
    expired = admin.post("/invites", json={"username": unique("re"), "role": "user"}).json()
    _psql(f"UPDATE account_invitations SET expires_at = now() - interval '1 hour' WHERE id={_q(expired['id'])}", fetch=False)
    assert admin.post(f"/invites/{expired['id']}/resend").status_code == 400
    assert admin.post("/invites/not-a-uuid/resend").status_code == 404
    assert admin.post("/invites/00000000-0000-0000-0000-000000000000/resend").status_code == 404


def test_the_list_names_who_invited(admin, admin_creds, invites_on):
    inv = admin.post("/invites", json={"username": unique("by"), "role": "user"}).json()
    try:
        row = next(x for x in admin.get("/invites").json() if x["id"] == inv["id"])
        assert row["created_by_username"] == admin_creds["username"]
        assert row["created_by"]
    finally:
        admin.delete(f"/invites/{inv['id']}")


def test_a_user_cannot_resend(admin, invites_on):
    inv = admin.post("/invites", json={"username": unique("nu"), "role": "user"}).json()
    u = admin.create_user(role="user")
    try:
        c = ApiClient()
        c.login(u["_username"], u["_password"])
        assert c.post(f"/invites/{inv['id']}/resend").status_code == 403
    finally:
        admin.delete_user(u["id"])
        admin.delete(f"/invites/{inv['id']}")


def test_an_invitation_whose_name_an_account_took_cannot_be_sent_again(admin, invites_on):
    inv = admin.post("/invites", json={"username": unique("tk"), "role": "user"}).json()
    try:
        taken = admin.create_user(username=inv["username"], role="user")
        try:
            r = admin.post(f"/invites/{inv['id']}/resend")
            assert r.status_code == 400 and "cannot be sent again" in r.text
        finally:
            admin.delete_user(taken["id"])
    finally:
        admin.delete(f"/invites/{inv['id']}")

