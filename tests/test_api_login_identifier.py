"""Live API acceptance for the login-identifier org policy.

`login_identifier` decides what the login form accepts:

* ``username`` (default) — exact username only; an email is rejected.
* ``email`` — the account's email, case-insensitively; the username is rejected.
* ``either`` — username tried first, then email.

The load-bearing properties, all asserted below:

* the resolver never leaks which identifier form was wrong — every miss returns the SAME 401 body as
  a wrong password, in every mode (anti-enumeration);
* a temporary credential (``temp_`` prefix) logs in unchanged in every mode;
* a NULL-email account is unreachable by email;
* a username that collides with an existing account's EMAIL is refused at creation (the '@'-syntactic
  half at the schema edge, the DB-state half in create_user) so ``either`` cannot be turned into an
  impersonation vector — and where a legacy row already holds the collision, ``either`` resolves to
  the USERNAME owner deterministically, never the email owner;
* a ``lower(email)`` duplicate (a deployment that could not build the unique index) fails closed to a
  clean 401, never a 500; and
* the login throttle still fires — proven against a finite limit, since the round harness raises the
  env limit out of reach.

Tests that flip the global settings row restore it. Tests that seed legacy rows do so with
``docker exec psql`` and reverse themselves, including rebuilding the unique index.
"""
import os
import subprocess

import pytest
import requests

from conftest import ApiClient, unique

pytestmark = pytest.mark.integration

DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
INDEX = "uq_users_email_lower"
PW = "TestPassw0rd!123"


# --- settings helpers -------------------------------------------------------
@pytest.fixture
def restore_login_policy(admin):
    """Snapshot the keys these tests mutate (the login mode and the throttle ceiling) and put them
    back — leaving a small throttle would 429 the rest of the run."""
    keys = ("login_identifier", "max_login_attempts")
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in keys}
    yield
    admin.put("/settings", json=snap)


def _set_mode(admin, mode):
    r = admin.put("/settings", json={"login_identifier": mode})
    assert r.status_code == 200, r.text


def _attempt(ident, password):
    """A raw login attempt from a fresh anonymous client. Returns the Response (never raises), so the
    caller can assert the exact status and body of a rejection."""
    return ApiClient().post("/auth/login", json={"username": ident, "password": password})


# --- psql seeding (legacy rows the API would refuse to create) --------------
def _psql(sql, fetch=True):
    cmd = ["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db"]
    cmd += ["-tAc", sql] if fetch else ["-c", sql]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, f"psql failed: {out.stderr[:400]}"
    return out.stdout.strip()


def _q(value):
    """A single-quoted SQL string literal (doubling embedded quotes)."""
    return "'" + value.replace("'", "''") + "'"


@pytest.fixture(scope="module", autouse=True)
def _email_index_intact_after_module():
    """The collision test drops the email-uniqueness index and rebuilds it in its own finally. This
    is the backstop: if a hard kill in that window ever leaves the index missing, rebuild it (best
    effort) and fail loudly at module teardown, so the guard is never silently disabled for later
    tests instead of vanishing unnoticed."""
    yield
    present = _psql(f"SELECT 1 FROM pg_indexes WHERE tablename='users' AND indexname='{INDEX}'")
    if present != "1":
        _psql(f"CREATE UNIQUE INDEX IF NOT EXISTS {INDEX} ON users (lower(email))", fetch=False)
        pytest.fail(f"{INDEX} was missing after the module — a collision test likely died mid-window; rebuilt it")


# --- mode: username ---------------------------------------------------------
def test_username_mode_username_works_email_fails(admin, restore_login_policy):
    _set_mode(admin, "username")
    email = f"{unique('umode')}@example.com"
    u = admin.create_user(email=email)
    try:
        assert ApiClient().login(u["_username"], PW)["access_token"]
        r = _attempt(email, PW)
        assert r.status_code == 401, r.text
        assert r.json()["detail"] == "Invalid username or password"
    finally:
        admin.delete_user(u["id"])


# --- mode: email ------------------------------------------------------------
def test_email_mode_email_works_username_fails_case_insensitively(admin, restore_login_policy):
    _set_mode(admin, "email")
    email = f"{unique('emode')}@example.com"
    u = admin.create_user(email=email)
    try:
        # email logs in, and case-insensitively (stored lowercased; submitted upper still resolves)
        assert ApiClient().login(email, PW)["access_token"]
        assert ApiClient().login(email.upper(), PW)["access_token"]
        # the username does NOT work in email mode
        r = _attempt(u["_username"], PW)
        assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password"
    finally:
        admin.delete_user(u["id"])


def test_email_mode_null_email_account_is_unreachable(admin, restore_login_policy):
    _set_mode(admin, "email")
    u = admin.create_user(email=None)  # no email at all
    try:
        # neither the (nonexistent) email nor the username can reach this account by email
        r = _attempt(u["_username"], PW)
        assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password"
    finally:
        admin.delete_user(u["id"])


# --- mode: either -----------------------------------------------------------
def test_either_mode_username_and_email_both_work(admin, restore_login_policy):
    _set_mode(admin, "either")
    email = f"{unique('either')}@example.com"
    u = admin.create_user(email=email)
    try:
        assert ApiClient().login(u["_username"], PW)["access_token"]
        assert ApiClient().login(email, PW)["access_token"]
    finally:
        admin.delete_user(u["id"])


# --- anti-enumeration: a miss is byte-identical to a wrong password ----------
@pytest.mark.parametrize("mode", ["username", "email", "either"])
def test_miss_matches_wrong_password_body(admin, restore_login_policy, mode):
    _set_mode(admin, mode)
    email = f"{unique('enum')}@example.com"
    u = admin.create_user(email=email)
    try:
        wrong_pw = _attempt(u["_username"] if mode != "email" else email, "definitely-wrong")
        unknown = _attempt(f"{unique('ghost')}@example.com", PW)
        assert wrong_pw.status_code == unknown.status_code == 401
        assert wrong_pw.json()["detail"] == unknown.json()["detail"] == "Invalid username or password"
    finally:
        admin.delete_user(u["id"])


# --- temp credentials stay policy-independent -------------------------------
@pytest.mark.parametrize("mode", ["username", "email", "either"])
def test_temp_credential_logs_in_in_every_mode(admin, restore_login_policy, mode):
    _set_mode(admin, mode)
    creds = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
    data = ApiClient().login(creds["temp_username"], creds["credential"])
    assert data["access_token"] and data["is_temporary"] is True


# --- creation ambiguity guards ----------------------------------------------
def test_create_user_rejects_at_sign_in_username(admin):
    r = admin.post("/users", json={"username": "has@sign", "password": PW, "role": "user"})
    assert r.status_code == 422, r.text  # schema-edge reject; @ is only ever an email shape


def test_create_user_rejects_username_colliding_with_existing_email(admin):
    """Guard (b), defense-in-depth: a username equal to an account's EMAIL is refused. Only reachable
    for a legacy no-'@' address (EmailStr forbids creating one), so seed that address via psql."""
    victim = admin.create_user(email=f"{unique('legacy')}@example.com")
    legacy_addr = unique("plainaddr")  # no '@' — bypasses guard (a) on the colliding username
    try:
        _psql(f"UPDATE users SET email = {_q(legacy_addr)} WHERE id = {_q(victim['id'])}", fetch=False)
        r = admin.post("/users", json={"username": legacy_addr, "password": PW, "role": "user"})
        assert r.status_code == 400, r.text
        assert "email" in r.json()["detail"].lower()
    finally:
        admin.delete_user(victim["id"])


# --- either-mode impersonation: username precedence is deterministic ---------
def test_either_username_precedence_over_colliding_email(admin, restore_login_policy):
    """A legacy username equal to another account's email must resolve to the USERNAME owner, and the
    email owner must NOT be reachable through it. Seed the '@'-bearing username via psql (creation
    would reject it)."""
    clash = f"{unique('clash')}@example.com"
    email_owner = admin.create_user(email=clash, password="EmailOwner-1a")   # owns the email
    uname_owner = admin.create_user(email=f"{unique('uo')}@example.com", password="UnameOwner-2b")
    try:
        # Enable 'either' BEFORE the collision exists — the enable-time guard would (correctly) refuse
        # the switch once it does. This exercises the resolver's precedence for a collision introduced
        # AFTER 'either' is live (legacy import / direct DB edit), which the save-time guard can't catch.
        _set_mode(admin, "either")
        _psql(f"UPDATE users SET username = {_q(clash)} WHERE id = {_q(uname_owner['id'])}", fetch=False)
        # username lookup wins: the username owner's password authenticates as the username owner
        data = ApiClient().login(clash, "UnameOwner-2b")
        assert data["user"]["id"] == uname_owner["id"]
        # the email owner is never reached via the collision — their password is rejected
        r = _attempt(clash, "EmailOwner-1a")
        assert r.status_code == 401 and r.json()["detail"] == "Invalid username or password"
    finally:
        admin.delete_user(email_owner["id"])
        admin.delete_user(uname_owner["id"])


# --- enable-time guard: refuse 'either' while a username shadows an email ----
def test_either_switch_refused_on_legacy_username_email_collision(admin, restore_login_policy):
    """Switching to 'either' must be refused while a legacy username equals another account's email
    (it would shadow that owner's email login). 'email' mode is unaffected. Once the collision is
    resolved, 'either' is accepted. The '@'-bearing username is seeded via psql (creation rejects it)."""
    victim_email = f"{unique('victim')}@example.com"
    victim = admin.create_user(email=victim_email)
    shadow = admin.create_user(email=f"{unique('shadow')}@example.com")
    try:
        _psql(f"UPDATE users SET username = {_q(victim_email)} WHERE id = {_q(shadow['id'])}", fetch=False)
        r = admin.put("/settings", json={"login_identifier": "either"})
        assert r.status_code == 400, r.text
        detail = r.json()["detail"].lower()
        assert "either" in detail and victim_email in detail
        # 'email' mode never consults the username, so this guard must not block it
        assert admin.put("/settings", json={"login_identifier": "email"}).status_code == 200
        admin.put("/settings", json={"login_identifier": "username"})
        # resolve the collision -> 'either' is now accepted
        _psql(f"UPDATE users SET username = {_q(unique('renamed'))} WHERE id = {_q(shadow['id'])}", fetch=False)
        assert admin.put("/settings", json={"login_identifier": "either"}).status_code == 200
    finally:
        admin.delete_user(victim["id"])
        admin.delete_user(shadow["id"])


# --- lower(email) duplicate: fail closed, never 500 -------------------------
def test_email_mode_case_collision_fails_closed(admin, restore_login_policy):
    """Two rows sharing one address (a deployment that could not build the unique index): email login
    must return a clean 401, never a 500 and never an arbitrary pick. Recreated by dropping the index,
    seeding the pair, and rebuilding — all reversed in finally."""
    local = unique("dup")
    lower_addr = f"{local}@example.com"
    upper_addr = f"{local.capitalize()}@Example.com"  # same address, different case
    a = admin.create_user(email=lower_addr, password="DupA-111aa")
    b = admin.create_user(email=f"{unique('dupb')}@example.com", password="DupB-222bb")
    dropped = False
    try:
        _psql(f"DROP INDEX IF EXISTS {INDEX}", fetch=False)
        dropped = True
        # force b's stored email to the same address in a different case (uniqueness now unenforced)
        _psql(f"UPDATE users SET email = {_q(upper_addr)} WHERE id = {_q(b['id'])}", fetch=False)
        _set_mode(admin, "email")
        # ambiguous -> resolver returns None -> generic 401, repeatably, and NOT a 500
        for _ in range(2):
            r = _attempt(lower_addr, "DupA-111aa")
            assert r.status_code == 401, r.text
            assert r.json()["detail"] == "Invalid username or password"
    finally:
        # put b back on a unique address, then rebuild the index so the rest of the run is clean
        _psql(f"UPDATE users SET email = {_q(f'{local}-restored@example.com')} WHERE id = {_q(b['id'])}", fetch=False)
        if dropped:
            _psql(f"CREATE UNIQUE INDEX IF NOT EXISTS {INDEX} ON users (lower(email))", fetch=False)
        admin.delete_user(a["id"])
        admin.delete_user(b["id"])


# --- the throttle still fires (finite-limit instance) -----------------------
def test_login_throttle_fires_with_finite_limit(admin, restore_login_policy):
    """The round harness raises the env login limit to 100000 so the hammer-until-429 test skips. The
    admin 'max_login_attempts' setting overrides the env, so set a small finite limit and prove the
    limiter still trips. Keyed on the submitted identifier (checked before user lookup), so a junk
    email in email mode is throttled without collaterally locking a real account. Restored in the
    fixture."""
    _set_mode(admin, "email")
    admin.put("/settings", json={"max_login_attempts": 5})
    junk = f"{unique('flood')}@example.com"
    client = ApiClient()  # one fixed source IP so the per-identifier window accumulates
    saw_429 = False
    for _ in range(12):
        r = client.post("/auth/login", json={"username": junk, "password": "no"})
        if r.status_code == 429:
            saw_429 = True
            break
        assert r.status_code == 401, r.text  # until the limit, a plain miss
    assert saw_429, "login throttle never fired despite a finite max_login_attempts"


# --- login-identifier readiness: resolution-based, catches the broken-index collision ----------
def test_readiness_flags_admin_whose_email_cannot_resolve(admin):
    """The lockout guard must judge "can sign in by email" by RESOLUTION, not mere presence of a
    non-blank address. On a legacy install that couldn't build the lower(email) unique index, an
    admin's email can collide case-insensitively and fail closed at login — so email-only would be a
    total lockout the guard must still see. Seed that collision and assert the admin is flagged."""
    b = admin.create_user(role="admin", email=f"{unique('dupadm')}@example.com")   # stored lowercased
    c = admin.create_user(role="user", email=f"{unique('other')}@example.com")
    dropped = False
    try:
        # sanity: with a clean index, b resolves and is NOT flagged
        assert b["_username"] not in admin.get("/settings/login-identifier-readiness").json()["admins_without_email"]
        _psql(f"DROP INDEX IF EXISTS {INDEX}", fetch=False)
        dropped = True
        # point c at a case-variant of b's address -> two rows share lower(email) -> b can't resolve
        variant = b["email"][:1].upper() + b["email"][1:]
        _psql(f"UPDATE users SET email={_q(variant)} WHERE id={_q(c['id'])}", fetch=False)
        flagged = admin.get("/settings/login-identifier-readiness").json()["admins_without_email"]
        assert b["_username"] in flagged, "an admin with an unresolvable colliding email must be flagged"
    finally:
        _psql(f"UPDATE users SET email={_q(unique('restored') + '@example.com')} WHERE id={_q(c['id'])}", fetch=False)
        if dropped:
            _psql(f"CREATE UNIQUE INDEX IF NOT EXISTS {INDEX} ON users (lower(email))", fetch=False)
        admin.delete_user(b["id"])
        admin.delete_user(c["id"])
