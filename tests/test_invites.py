"""Live API acceptance for admin account invitations (mint / list / revoke).

Acceptance of a token (the public accept flow) is a separate phase; this covers only the admin side.
Invitations are disabled by default, so every test enables the policy via the shared fixture and
restores it. Legacy-shaped rows (a past expiry, a consumed invite, a no-'@' email) are seeded with
``docker exec psql`` since the API would refuse to create them.
"""
import os
import subprocess

import pytest
import requests

from conftest import ApiClient, unique

pytestmark = pytest.mark.integration

DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
API = os.environ.get("VAULT_API_CONTAINER", "vault-api")
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


def _invite_pepper():
    """The pepper the deployment uses: INVITE_TOKEN_PEPPER if set on the API container, else its
    JWT secret (the app's documented fallback)."""
    for name in ("INVITE_TOKEN_PEPPER", "JWT_SECRET_KEY"):
        out = subprocess.run(["docker", "exec", API, "printenv", name], capture_output=True, text=True, timeout=15)
        val = out.stdout.strip()
        if val:
            return val
    pytest.skip("could not read the invite pepper from the API container")


@pytest.fixture
def invites_on(admin):
    """Enable invitations with a permissive email policy; restore the settings row afterward."""
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ACCOUNT_KEYS}
    r = admin.put("/settings", json={
        "invite_enabled": True, "invite_ttl_hours": 48,
        "email_requirement": "optional", "signup_email_domain_mode": "off", "signup_email_domains": []})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


@pytest.fixture
def invites_off(admin):
    """Explicitly DISABLE invitations, restoring afterward — so the negative test controls its own
    precondition instead of relying on the ambient deployment default (which another test or admin
    action could have flipped)."""
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ACCOUNT_KEYS}
    admin.put("/settings", json={"invite_enabled": False})
    yield
    admin.put("/settings", json=snap)


def _mint(admin, **body):
    return admin.post("/invites", json=body)


# --- mint: happy path + show-once + at-rest hashing --------------------------
def test_mint_returns_token_once_and_stores_only_the_hash(admin, invites_on):
    from app.core import invitations
    uname = unique("inv")
    r = _mint(admin, username=uname, role="user")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "pending" and body["username"] == uname
    plaintext = body["token"]
    assert plaintext and body["invite_url"].endswith(plaintext)
    assert body["token_prefix"] == plaintext[:12]
    # only the peppered HMAC is stored — never the plaintext
    row = _psql(f"SELECT token_hash FROM account_invitations WHERE username={_q(uname)}")
    assert row and row != plaintext
    assert row == invitations.hash_invite_token(plaintext, _invite_pepper())
    # the plaintext appears NOWHERE in the persisted row (dump the whole row as text)
    whole = _psql(f"SELECT to_jsonb(account_invitations)::text FROM account_invitations WHERE username={_q(uname)}")
    assert plaintext not in whole


def test_mint_refused_when_invitations_disabled(admin, invites_off):
    r = _mint(admin, username=unique("off"), role="user")
    assert r.status_code == 400, r.text
    assert "disabled" in r.json()["detail"].lower()


# --- username validation -----------------------------------------------------
@pytest.mark.parametrize("bad", ["has@sign", "ab", "x" * 51, "no<tag>"])
def test_mint_rejects_bad_username_shape(admin, invites_on, bad):
    r = _mint(admin, username=bad, role="user")
    assert r.status_code == 422, r.text  # schema-layer reject (@, length, markup)


def test_mint_rejects_existing_username(admin, invites_on):
    u = admin.create_user(role="user")
    try:
        r = _mint(admin, username=u["_username"], role="user")
        assert r.status_code == 400 and "exists" in r.json()["detail"].lower()
    finally:
        admin.delete_user(u["id"])


def test_mint_rejects_username_equal_to_existing_email(admin, invites_on):
    # Reachable only for a legacy no-'@' email (EmailStr forbids creating one) — seed via psql.
    victim = admin.create_user(email=f"{unique('leg')}@example.com")
    legacy_addr = unique("plainaddr")  # no '@' -> passes the schema, hits the DB-state guard
    try:
        _psql(f"UPDATE users SET email={_q(legacy_addr)} WHERE id={_q(victim['id'])}", fetch=False)
        r = _mint(admin, username=legacy_addr, role="user")
        assert r.status_code == 400 and "email" in r.json()["detail"].lower()
    finally:
        admin.delete_user(victim["id"])


def test_mint_rejects_non_ascii_email(admin, invites_on):
    # ASCII-only email at invite creation, uniform with self-signup. The domain-gate config is
    # ASCII/punycode, so a unicode IDN domain would otherwise slip a denylist stored in punycode
    # (evasion). Prove it's rejected 400 BEFORE the gate even with that denylist configured.
    admin.put("/settings", json={"signup_email_domain_mode": "denylist",
                                 "signup_email_domains": ["xn--mnchen-3ya.de"]})
    r = _mint(admin, username=unique("idn"), email="user@münchen.de", role="user")
    assert r.status_code == 400, r.text


# --- live-invite dedup -------------------------------------------------------
def test_live_invite_blocks_second_but_revoked_does_not(admin, invites_on):
    uname = unique("dup")
    first = _mint(admin, username=uname, role="user")
    assert first.status_code == 200, first.text
    again = _mint(admin, username=uname, role="user")
    assert again.status_code == 400 and "pending" in again.json()["detail"].lower()
    # revoke the live one -> the username is free to invite again
    assert admin.delete(f"/invites/{first.json()['id']}").status_code == 200
    third = _mint(admin, username=uname, role="user")
    assert third.status_code == 200, third.text


def test_live_invite_blocks_second_for_the_same_email(admin, invites_on):
    # Symmetric with the username guard: one live invitation per email (case-insensitive).
    email = f"{unique('shared')}@example.com"
    first = _mint(admin, username=unique("e1"), role="user", email=email)
    assert first.status_code == 200, first.text
    dup = _mint(admin, username=unique("e2"), role="user", email=email.upper())
    assert dup.status_code == 400 and "email" in dup.json()["detail"].lower()
    # once the first is revoked, the address is free again
    assert admin.delete(f"/invites/{first.json()['id']}").status_code == 200
    third = _mint(admin, username=unique("e3"), role="user", email=email)
    assert third.status_code == 200, third.text


def test_expired_invite_does_not_block(admin, invites_on):
    uname = unique("exp")
    r = _mint(admin, username=uname, role="user")
    assert r.status_code == 200
    _psql(f"UPDATE account_invitations SET expires_at = now() - interval '1 hour' WHERE id={_q(r.json()['id'])}", fetch=False)
    again = _mint(admin, username=uname, role="user")
    assert again.status_code == 200, again.text  # expired invite is not "live"


# --- email policy + domain gate ----------------------------------------------
def test_email_required_missing_is_refused(admin, invites_on):
    assert admin.put("/settings", json={"email_requirement": "required"}).status_code == 200
    r = _mint(admin, username=unique("noemail"), role="user")
    assert r.status_code == 400 and "email" in r.json()["detail"].lower()


def test_email_optional_missing_is_allowed(admin, invites_on):
    r = _mint(admin, username=unique("oknoemail"), role="user")
    assert r.status_code == 200, r.text
    assert r.json()["email"] is None


def test_domain_allowlist_miss_and_hit(admin, invites_on):
    assert admin.put("/settings", json={
        "signup_email_domain_mode": "allowlist", "signup_email_domains": ["acme.example"]}).status_code == 200
    miss = _mint(admin, username=unique("dm"), role="user", email=f"{unique('x')}@other.example")
    assert miss.status_code == 400 and "domain" in miss.json()["detail"].lower()
    hit = _mint(admin, username=unique("dh"), role="user", email=f"{unique('y')}@acme.example")
    assert hit.status_code == 200, hit.text


def test_domain_denylist_blocks_domain_and_subdomain(admin, invites_on):
    assert admin.put("/settings", json={
        "signup_email_domain_mode": "denylist", "signup_email_domains": ["evil.example"]}).status_code == 200
    for dom in ("evil.example", "sub.evil.example"):
        r = _mint(admin, username=unique("dn"), role="user", email=f"{unique('z')}@{dom}")
        assert r.status_code == 400, (dom, r.text)
    ok = _mint(admin, username=unique("dok"), role="user", email=f"{unique('w')}@good.example")
    assert ok.status_code == 200, ok.text


def test_email_already_in_use_refused(admin, invites_on):
    u = admin.create_user(email=f"{unique('taken')}@example.com")
    try:
        r = _mint(admin, username=unique("dupemail"), role="user", email=u["email"])
        assert r.status_code == 400 and "use" in r.json()["detail"].lower()
    finally:
        admin.delete_user(u["id"])


# --- authz -------------------------------------------------------------------
def test_non_admin_cannot_mint(admin, invites_on):
    u = admin.create_user(role="user")
    c = admin.clone_anonymous()
    c.login(u["_username"], u["_password"])
    try:
        assert c.post("/invites", json={"username": unique("na"), "role": "user"}).status_code == 403
    finally:
        admin.delete_user(u["id"])


def test_temp_credential_admin_cannot_mint(admin, invites_on):
    creds = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
    c = admin.clone_anonymous()
    c.login(creds["temp_username"], creds["credential"])
    assert c.post("/invites", json={"username": unique("tc"), "role": "user"}).status_code == 403


# --- list --------------------------------------------------------------------
def test_list_derives_status_and_hides_the_hash(admin, invites_on):
    pending = _mint(admin, username=unique("lp"), role="user").json()
    revoked = _mint(admin, username=unique("lr"), role="user").json()
    admin.delete(f"/invites/{revoked['id']}")
    accepted = _mint(admin, username=unique("la"), role="user").json()
    _psql(f"UPDATE account_invitations SET accepted_at = now() WHERE id={_q(accepted['id'])}", fetch=False)
    expired = _mint(admin, username=unique("le"), role="user").json()
    _psql(f"UPDATE account_invitations SET expires_at = now() - interval '1 hour' WHERE id={_q(expired['id'])}", fetch=False)

    rows = admin.get("/invites").json()
    by_id = {r["id"]: r for r in rows}
    assert by_id[pending["id"]]["status"] == "pending"
    assert by_id[revoked["id"]]["status"] == "revoked"
    assert by_id[accepted["id"]]["status"] == "accepted"
    assert by_id[expired["id"]]["status"] == "expired"
    # never leak the hash or a token
    for r in rows:
        assert "token_hash" not in r and "token" not in r


# --- revoke ------------------------------------------------------------------
def test_revoke_is_idempotent_and_bad_ids_404(admin, invites_on):
    inv = _mint(admin, username=unique("rv"), role="user").json()
    assert admin.delete(f"/invites/{inv['id']}").status_code == 200
    assert admin.delete(f"/invites/{inv['id']}").status_code == 200  # idempotent
    # subsequent list shows revoked
    row = next(r for r in admin.get("/invites").json() if r["id"] == inv["id"])
    assert row["status"] == "revoked"
    assert admin.delete("/invites/not-a-uuid").status_code == 404
    assert admin.delete("/invites/00000000-0000-0000-0000-000000000000").status_code == 404


# --- ttl ---------------------------------------------------------------------
def test_expiry_reflects_policy_ttl(admin, invites_on):
    assert admin.put("/settings", json={"invite_ttl_hours": 6}).status_code == 200
    inv = _mint(admin, username=unique("ttl"), role="user").json()
    # expires_at ~ now + 6h; assert it lands in a generous window (5..7h ahead)
    secs = _psql(f"SELECT EXTRACT(EPOCH FROM (expires_at - now())) FROM account_invitations WHERE id={_q(inv['id'])}")
    ahead_h = float(secs) / 3600.0
    assert 5.0 < ahead_h < 7.0, ahead_h


# --- audit -------------------------------------------------------------------
def test_mint_and_revoke_are_audited_without_the_plaintext(admin, invites_on):
    inv = _mint(admin, username=unique("aud"), role="user").json()
    admin.delete(f"/invites/{inv['id']}")
    created = _psql("SELECT count(*) FROM audit_logs WHERE action='account_invitation_created' "
                    f"AND details::text LIKE {_q('%' + inv['token_prefix'] + '%')}")
    revoked = _psql("SELECT count(*) FROM audit_logs WHERE action='account_invitation_revoked' "
                    f"AND details::text LIKE {_q('%' + inv['token_prefix'] + '%')}")
    assert int(created) >= 1 and int(revoked) >= 1
    # the plaintext token never appears in any audit row
    leak = _psql(f"SELECT count(*) FROM audit_logs WHERE details::text LIKE {_q('%' + inv['token'] + '%')}")
    assert int(leak) == 0
