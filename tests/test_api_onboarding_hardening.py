"""Onboarding security-hardening acceptance (the dedicated-review fixes).

Pins: (F2) self-signup returns the SAME generic message for an already-registered email as for a
domain-blocked one, so the response is not an account-enumeration oracle; (F4) self-signup cannot
claim an address reserved by a live invitation; (created_by) a self-signed account has created_by
NULL despite an injected body value; and the email-only-login lockout guards — the switch is refused
when no admin can resolve by email, and clearing the last email-resolvable admin's address under
email login is refused (both the switch-time guard and the after-the-switch clear path).

The email-lockout tests temporarily null admin emails; each restores login_identifier FIRST (so the
username-authenticated admin fixture keeps working) and then the emails, in a finally.
"""
import os
import subprocess

import pytest

from conftest import BASE_URL, unique

pytestmark = pytest.mark.integration

DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
STRONG = "S1gnup-Passw0rd!"
ACCT = ("signup_enabled", "email_requirement", "login_identifier", "signup_email_domain_mode",
        "signup_email_domains", "invite_enabled", "invite_ttl_hours")


def _psql(sql, fetch=True):
    cmd = ["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db"]
    cmd += ["-tAc", sql] if fetch else ["-c", sql]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, f"psql failed: {out.stderr[:400]}"
    return out.stdout.strip()


def _q(v):
    return "'" + str(v).replace("'", "''") + "'"


@pytest.fixture
def restore_settings(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ACCT}
    yield snap
    admin.put("/settings", json=snap)


def _set(admin, **kw):
    assert admin.put("/settings", json=kw).status_code == 200, kw


def _enable_signup(admin, **overrides):
    payload = {"signup_enabled": True, "email_requirement": "optional", "login_identifier": "username",
               "signup_email_domain_mode": "off", "signup_email_domains": []}
    payload.update(overrides)
    _set(admin, **payload)


def _signup(admin, body):
    return admin.clone_anonymous().post("/auth/signup", json=body)


def _cleanup(admin, *names):
    rows = {u.get("username"): u.get("id") for u in admin.get("/users").json()}
    for n in names:
        if rows.get(n):
            admin.delete_user(rows[n])


# ---- F2: email-in-use is indistinguishable from domain-blocked (no enumeration oracle) ----------
def test_signup_email_in_use_uses_generic_message(admin, restore_settings):
    _enable_signup(admin)
    addr = f"{unique('own')}@example.com"
    existing = admin.create_user(role="user", email=addr)
    try:
        in_use = _signup(admin, {"username": unique("d1"), "password": STRONG, "email": addr})
        _set(admin, signup_email_domain_mode="denylist", signup_email_domains=["blocked.example"])
        blocked = _signup(admin, {"username": unique("d2"), "password": STRONG, "email": "x@blocked.example"})
        assert in_use.status_code == 400 and blocked.status_code == 400, (in_use.text, blocked.text)
        # identical body -> an attacker cannot tell "this email is registered" from "domain blocked"
        assert in_use.json().get("detail") == blocked.json().get("detail"), (in_use.text, blocked.text)
    finally:
        _cleanup(admin, existing["_username"])


# ---- F4: a live invitation reserves the address against self-signup (identity-squat) ------------
def test_signup_rejects_pending_invited_email(admin, restore_settings):
    _enable_signup(admin, invite_enabled=True, invite_ttl_hours=48)
    invited = f"{unique('inv')}@example.com"
    iv = admin.post("/invites", json={"username": unique("iu"), "email": invited, "role": "user"})
    assert iv.status_code == 200, iv.text
    squatter = unique("squat")
    try:
        r = _signup(admin, {"username": squatter, "password": STRONG, "email": invited})
        assert r.status_code == 400, r.text
        # generic message (does not reveal the address is invited) AND no account was created
        assert squatter not in [u["username"] for u in admin.get("/users").json()]
    finally:
        _cleanup(admin, squatter)
        _psql(f"DELETE FROM account_invitations WHERE lower(email)=lower({_q(invited)})", fetch=False)


# ---- created_by: a self-signed account claims no creator, despite an injected body value ---------
def test_signup_created_by_is_null_even_when_injected(admin, restore_settings):
    _enable_signup(admin)
    name = unique("cb")
    try:
        r = _signup(admin, {"username": name, "password": STRONG, "email": f"{name}@example.com",
                            "created_by": "00000000-0000-0000-0000-000000000000", "role": "admin"})
        assert r.status_code == 200, r.text
        cb = _psql(f"SELECT COALESCE(created_by::text,'NULL') FROM users WHERE username={_q(name)}")
        assert cb == "NULL", f"created_by should be NULL, got {cb!r}"
        role = _psql(f"SELECT role FROM users WHERE username={_q(name)}")
        assert role.upper() == "USER", role
    finally:
        _cleanup(admin, name)


# ---- F3 + T3: email-only-login total-lockout guards -------------------------------------------
def _admin_emails(_psql_):
    rows = _psql_("SELECT id::text || '|' || COALESCE(email,'') FROM users "
                  "WHERE role='ADMIN' AND is_active IS NOT false")
    out = []
    for line in rows.splitlines():
        line = line.strip()
        if line:
            uid, _, email = line.partition("|")
            out.append((uid, email))
    return out


def test_switch_to_email_login_refused_when_no_admin_has_email(admin, restore_settings):
    """T3 refuse direction: PUT /settings login_identifier='email' is rejected when it would strand
    every admin (no active admin can resolve by email)."""
    snapshot = _admin_emails(_psql)
    try:
        _psql("UPDATE users SET email=NULL WHERE role='ADMIN' AND is_active IS NOT false", fetch=False)
        r = admin.put("/settings", json={"login_identifier": "email"})
        assert r.status_code == 400, r.text
        assert admin.get("/settings").json().get("login_identifier") != "email"
    finally:
        # login stayed 'username' (the switch was refused), so the username-auth'd admin fixture is
        # unaffected; restore every admin's email.
        for uid, email in snapshot:
            _psql(f"UPDATE users SET email={('NULL' if not email else _q(email))} WHERE id={_q(uid)}",
                  fetch=False)


def test_clearing_last_admin_email_under_email_login_is_refused(admin, admin_creds, restore_settings):
    """F3: with email-only login active and the acting admin the sole email-resolvable admin, clearing
    that admin's own email (PATCH /users/me) is refused — the total lockout the switch guard prevents,
    previously reachable by clearing an email after the switch."""
    me = admin.get("/users/me").json()
    if not (me.get("email") or "").strip():
        pytest.skip("acting admin has no email; cannot construct the sole-email-admin state safely")
    snapshot = _admin_emails(_psql)
    switched = False
    try:
        # make the acting admin the ONLY email-resolvable admin, then switch to email login
        _psql(f"UPDATE users SET email=NULL WHERE role='ADMIN' AND is_active IS NOT false "
              f"AND id <> {_q(me['id'])}", fetch=False)
        assert admin.put("/settings", json={"login_identifier": "email"}).status_code == 200
        switched = True
        # clearing the sole email-admin's own address must be refused
        r = admin.patch("/users/me", json={"email": None, "current_password": admin_creds["password"]})
        assert r.status_code == 400, r.text
        assert (admin.get("/users/me").json().get("email") or "").strip(), "email was cleared despite the guard"
    finally:
        # restore login FIRST so the username-auth'd fixture is safe even if the rest fails
        admin.put("/settings", json={"login_identifier": "username"})
        for uid, email in snapshot:
            _psql(f"UPDATE users SET email={('NULL' if not email else _q(email))} WHERE id={_q(uid)}",
                  fetch=False)
        _ = switched


def test_clearing_admin_email_allowed_under_username_login(admin, restore_settings):
    """F3 must not over-fire: under username login, clearing an admin's email is allowed (a username
    still resolves). Uses a throwaway admin so the acting admin is untouched."""
    _set(admin, login_identifier="username")
    other = admin.create_user(role="admin", email=f"{unique('o')}@example.com")
    try:
        r = admin.patch(f"/users/{other['id']}", json={"email": None})
        assert r.status_code == 200, r.text
    finally:
        admin.delete_user(other["id"])
