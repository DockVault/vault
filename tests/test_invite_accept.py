"""Live API acceptance for the PUBLIC invitation-acceptance flow.

Unauthenticated GET /invites/{token} + POST /invites/{token}/accept. The security-critical properties
are asserted here: a single generic response for every non-usable token (no enumeration oracle), a
mass-assignment-proof accept (identity comes from the invite row, never the body), single-use under
REAL concurrency (two simultaneous accepts -> exactly one account), per-IP + per-prefix rate limiting,
and audit on every outcome. Legacy/edge states are seeded with ``docker exec psql``.
"""
import concurrent.futures
import os
import subprocess

import pytest

from conftest import ApiClient, unique

pytestmark = pytest.mark.integration

DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
STRONG_PW = "AcceptPassw0rd!123"

ACCOUNT_KEYS = ("email_requirement", "invite_enabled", "invite_ttl_hours", "signup_enabled",
                "signup_email_domain_mode", "signup_email_domains", "login_identifier")
PW_KEYS = ("password_min_length", "require_uppercase", "require_lowercase",
           "require_numbers", "require_special")


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
    snap = {k: before.get(k) for k in (ACCOUNT_KEYS + PW_KEYS)}
    r = admin.put("/settings", json={
        "invite_enabled": True, "invite_ttl_hours": 48,
        "email_requirement": "optional", "signup_email_domain_mode": "off", "signup_email_domains": []})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


def _mint(admin, **body):
    r = admin.post("/invites", json=body)
    assert r.status_code == 200, r.text
    return r.json()          # includes token + token_prefix


def _anon():
    return ApiClient()       # no login


def _cleanup_user(admin, username):
    for u in admin.get("/users").json():
        if u.get("username") == username:
            admin.delete_user(u["id"])
            return


# --- GET: happy path + no leakage -------------------------------------------
def test_get_returns_form_fields_only(admin, invites_on):
    inv = _mint(admin, username=unique("g"), role="user")
    r = _anon().get(f"/invites/{inv['token']}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["username"] == inv["username"]
    assert "password_policy" in body and "min_length" in body["password_policy"]
    # never leak internals
    for leaked in ("id", "token", "token_hash", "token_prefix", "role", "created_by"):
        assert leaked not in body, f"GET leaked {leaked}"


# --- anti-enumeration: every non-usable token looks identical ----------------
def test_generic_response_for_every_bad_state(admin, invites_on):
    unknown = _anon().get(f"/invites/{'z' * 43}")
    good = _mint(admin, username=unique("exp"), role="user")
    _psql(f"UPDATE account_invitations SET expires_at = now() - interval '1 hour' WHERE id={_q(good['id'])}", fetch=False)
    expired = _anon().get(f"/invites/{good['token']}")
    rev = _mint(admin, username=unique("rev"), role="user")
    admin.delete(f"/invites/{rev['id']}")
    revoked = _anon().get(f"/invites/{rev['token']}")
    acc = _mint(admin, username=unique("acc"), role="user")
    _psql(f"UPDATE account_invitations SET accepted_at = now() WHERE id={_q(acc['id'])}", fetch=False)
    accepted = _anon().get(f"/invites/{acc['token']}")
    for r in (unknown, expired, revoked, accepted):
        assert r.status_code == 404 and r.json()["detail"] == "Invitation not found."


def test_tampered_token_is_generic_404(admin, invites_on):
    inv = _mint(admin, username=unique("tamper"), role="user")
    tok = inv["token"]
    flipped = tok[:-1] + ("a" if tok[-1] != "a" else "b")   # same prefix, wrong hash
    r = _anon().get(f"/invites/{flipped}")
    assert r.status_code == 404 and r.json()["detail"] == "Invitation not found."


# --- accept: happy path ------------------------------------------------------
def test_accept_creates_the_account_with_the_invited_role(admin, invites_on):
    uname = unique("acc")
    inv = _mint(admin, username=uname, role="user")
    try:
        r = _anon().post(f"/invites/{inv['token']}/accept", json={"password": STRONG_PW})
        assert r.status_code == 200, r.text
        # the account exists with the invited role and the invite is consumed + linked
        role = _psql(f"SELECT role FROM users WHERE username={_q(uname)}")
        assert role.lower().endswith("user") and "admin" not in role.lower()
        linked = _psql(f"SELECT (accepted_at IS NOT NULL) AND (accepted_user_id IS NOT NULL) "
                       f"FROM account_invitations WHERE id={_q(inv['id'])}")
        assert linked == "t"
    finally:
        _cleanup_user(admin, uname)


# --- mass-assignment: privileged fields in the body are ignored --------------
def test_accept_ignores_privileged_body_fields(admin, invites_on):
    uname = unique("mass")
    inv = _mint(admin, username=uname, role="user")
    try:
        r = _anon().post(f"/invites/{inv['token']}/accept", json={
            "password": STRONG_PW, "role": "admin", "username": "attacker",
            "is_locked": False, "is_active": True, "storage_quota_gb": 99999})
        assert r.status_code == 200, r.text
        # username + role come from the invite ROW, not the body
        row = _psql(f"SELECT username||'|'||role FROM users WHERE username={_q(uname)}")
        assert row and "admin" not in row.lower()
        assert _psql(f"SELECT count(*) FROM users WHERE username='attacker'") == "0"
    finally:
        _cleanup_user(admin, uname)


# --- single-use: replay + REAL concurrency ----------------------------------
def test_accept_is_single_use_on_replay(admin, invites_on):
    uname = unique("replay")
    inv = _mint(admin, username=uname, role="user")
    try:
        assert _anon().post(f"/invites/{inv['token']}/accept", json={"password": STRONG_PW}).status_code == 200
        again = _anon().post(f"/invites/{inv['token']}/accept", json={"password": STRONG_PW})
        assert again.status_code == 404 and again.json()["detail"] == "Invitation not found."
    finally:
        _cleanup_user(admin, uname)


def test_concurrent_double_accept_creates_exactly_one_account(admin, invites_on):
    uname = unique("race")
    inv = _mint(admin, username=uname, role="user")
    token = inv["token"]
    try:
        def _do(_):
            return ApiClient().post(f"/invites/{token}/accept", json={"password": STRONG_PW}).status_code
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            statuses = sorted(ex.map(_do, range(2)))
        assert statuses.count(200) == 1, statuses            # exactly one winner
        assert all(s in (200, 404, 409) for s in statuses), statuses
        assert _psql(f"SELECT count(*) FROM users WHERE username={_q(uname)}") == "1"
    finally:
        _cleanup_user(admin, uname)


# --- disabled after mint -----------------------------------------------------
def test_disabled_after_mint_is_not_acceptable(admin, invites_on):
    inv = _mint(admin, username=unique("dis"), role="user")
    admin.put("/settings", json={"invite_enabled": False})
    try:
        assert _anon().get(f"/invites/{inv['token']}").status_code == 404
        assert _anon().post(f"/invites/{inv['token']}/accept", json={"password": STRONG_PW}).status_code == 404
    finally:
        admin.put("/settings", json={"invite_enabled": True})


# --- password policy ---------------------------------------------------------
def test_weak_password_rejected_against_policy(admin, invites_on):
    admin.put("/settings", json={"password_min_length": 14, "require_uppercase": True,
                                 "require_numbers": True, "require_special": True})
    inv = _mint(admin, username=unique("pw"), role="user")
    # meets the 8-char model floor but not the stricter org policy -> 400 (not 422)
    r = _anon().post(f"/invites/{inv['token']}/accept", json={"password": "lowercaseonly"})
    assert r.status_code == 400 and "password must" in r.json()["detail"].lower()
    # GET advertises the stricter policy so the form can mirror it
    view = _anon().get(f"/invites/{inv['token']}").json()["password_policy"]
    assert view["min_length"] == 14 and view["require_special"] is True


def test_too_short_password_is_422_model_floor(admin, invites_on):
    inv = _mint(admin, username=unique("short"), role="user")
    assert _anon().post(f"/invites/{inv['token']}/accept", json={"password": "Ab1!"}).status_code == 422


# --- email per policy --------------------------------------------------------
def test_email_required_when_invite_has_none_and_policy_requires(admin, invites_on):
    inv = _mint(admin, username=unique("noemail"), role="user")   # minted while optional
    admin.put("/settings", json={"email_requirement": "required"})
    try:
        r = _anon().post(f"/invites/{inv['token']}/accept", json={"password": STRONG_PW})
        assert r.status_code == 400 and "email" in r.json()["detail"].lower()
    finally:
        admin.put("/settings", json={"email_requirement": "optional"})


def test_email_in_use_rejected_at_accept(admin, invites_on):
    existing = admin.create_user(email=f"{unique('taken')}@example.com")
    inv = _mint(admin, username=unique("dupmail"), role="user")   # no email on the invite
    try:
        r = _anon().post(f"/invites/{inv['token']}/accept",
                         json={"password": STRONG_PW, "email": existing["email"]})
        assert r.status_code == 400 and "use" in r.json()["detail"].lower()
    finally:
        admin.delete_user(existing["id"])


# --- rate limiting -----------------------------------------------------------
def test_accept_rate_limited_per_token_prefix(admin, invites_on):
    inv = _mint(admin, username=unique("rl"), role="user")
    client = ApiClient()   # one fixed IP; the per-prefix limit (5/60s) trips regardless of IP
    saw_429 = False
    try:
        for _ in range(8):
            r = client.post(f"/invites/{inv['token']}/accept", json={"password": STRONG_PW})
            if r.status_code == 429:
                saw_429 = True
                break
        assert saw_429, "per-prefix accept rate limit never fired"
    finally:
        _cleanup_user(admin, inv["username"])   # the first attempt may have created the account


# --- authz: no auth required, not admin-gated --------------------------------
def test_public_endpoints_need_no_auth(admin, invites_on):
    inv = _mint(admin, username=unique("noauth"), role="user")
    # a bare anonymous client (no Authorization header) reaches both
    assert _anon().get(f"/invites/{inv['token']}").status_code == 200
    try:
        assert _anon().post(f"/invites/{inv['token']}/accept", json={"password": STRONG_PW}).status_code == 200
    finally:
        _cleanup_user(admin, inv["username"])


# --- audit -------------------------------------------------------------------
def test_accept_success_and_failure_are_audited(admin, invites_on):
    ok = _mint(admin, username=unique("aud"), role="user")
    try:
        assert _anon().post(f"/invites/{ok['token']}/accept", json={"password": STRONG_PW}).status_code == 200
        # a failed attempt on an unknown token
        _anon().post(f"/invites/{'y' * 43}/accept", json={"password": STRONG_PW})
        acc = _psql("SELECT count(*) FROM audit_logs WHERE action='account_invitation_accepted' "
                    f"AND details::text LIKE {_q('%' + ok['token_prefix'] + '%')}")
        fail = _psql("SELECT count(*) FROM audit_logs WHERE action='account_invitation_accept_failed'")
        assert int(acc) >= 1 and int(fail) >= 1
        # the plaintext token never appears in any audit row
        leak = _psql(f"SELECT count(*) FROM audit_logs WHERE details::text LIKE {_q('%' + ok['token'] + '%')}")
        assert int(leak) == 0
    finally:
        _cleanup_user(admin, ok["username"])
