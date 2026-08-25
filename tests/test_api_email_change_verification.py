"""Live API acceptance for the verified self-service email-change flow.

The plaintext code only ever reaches the new mailbox, so the confirm/apply path is exercised by
seeding a code row directly (its hash computed with the server's pepper), and the request path by
its gates plus the clean SMTP-failure behaviour. Covers the closed self-email-change re-auth gap,
the policy gate on PATCH /users/me, admin-set exemption, re-auth, rate-limiting, enumeration-safety,
single-use,
expiry, and cross-user isolation. Every test restores what it changed (settings + created users).
"""
import os
import subprocess

import pytest

from conftest import ApiClient, BASE_URL, unique
from app.core.otp_service import hash_code, generate_code

pytestmark = pytest.mark.integration

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_API = os.environ.get("VAULT_API_CONTAINER", "vault-api")
_REDIS = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")


def _psql(sql):
    return subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                          capture_output=True, text=True, timeout=20)


def _rediscli(*args):
    return subprocess.run(["docker", "exec", _REDIS, "redis-cli", *args],
                          capture_output=True, text=True, timeout=20)


def _otp_key(uid):
    return f"otp:email_change:{uid}"


def _redis_has(uid):
    return _rediscli("EXISTS", _otp_key(uid)).stdout.strip() == "1"


def _pepper():
    r = subprocess.run(["docker", "exec", _API, "printenv", "JWT_SECRET_KEY"],
                       capture_output=True, text=True, timeout=20)
    return r.stdout.strip()


def _code_count(uid):
    # A minted code lives in Redis (primary); a DB row only exists during a Redis outage. Count both.
    n = int(_psql(f"SELECT count(*) FROM otp_codes WHERE user_id='{uid}' AND purpose='email_change' "
                  f"AND consumed_at IS NULL").stdout.strip() or "0")
    return n + (1 if _redis_has(uid) else 0)


def _db_rows(uid):
    return int(_psql(f"SELECT count(*) FROM otp_codes WHERE user_id='{uid}' "
                     f"AND purpose='email_change'").stdout.strip() or "0")


def _purge(uid):
    _psql(f"DELETE FROM otp_codes WHERE user_id='{uid}'")
    _rediscli("DEL", _otp_key(uid))


def _seed_code(uid, new_email, code, pepper, *, expired=False, consumed=False):
    # Seed a KNOWN code into the durable store and clear Redis, so confirm (Redis-first) finds this row.
    _rediscli("DEL", _otp_key(uid))
    h = hash_code(code, pepper)
    exp = "now() - interval '1 minute'" if expired else "now() + interval '15 minutes'"
    cons = "now()" if consumed else "NULL"
    _psql("INSERT INTO otp_codes (id, purpose, user_id, destination, code_hash, attempts, max_attempts, "
          "expires_at, consumed_at, created_at) "
          f"VALUES (gen_random_uuid(), 'email_change', '{uid}', '{new_email}', '{h}', 0, 3, {exp}, {cons}, now())")


def _client_for(admin, u):
    c = ApiClient(BASE_URL)
    c.login(u["_username"], u["_password"])
    return c


@pytest.fixture
def restore_settings(admin):
    before = admin.get("/settings").json()
    keys = ("email_change_requires_verification", "smtp_server", "from_email", "smtp_port")
    snap = {k: before.get(k) for k in keys}
    yield
    admin.put("/settings", json=snap)


def _enable(admin, *, smtp="127.0.0.1", port="1"):
    """Enable the policy. SMTP points at a closed local port so a real send fails fast+clean;
    tests that need to CONFIRM seed the code directly rather than receiving it. Two PUTs on purpose:
    the policy can only be turned ON once SMTP is already stored (the same-PUT enable is refused)."""
    r = admin.put("/settings", json={"smtp_server": smtp, "from_email": "vault@example.com",
                                     "smtp_port": port})
    assert r.status_code == 200, r.text
    r = admin.put("/settings", json={"email_change_requires_verification": True})
    assert r.status_code == 200, r.text


# ---- the self email-change hole on PATCH /users/{id} is closed --------------------------------
def test_admin_cannot_change_own_email_by_id_path(admin, restore_settings):
    me = admin.get("/users/me").json()
    r = admin.patch(f"/users/{me['id']}", json={"email": unique("x") + "@example.com"})
    assert r.status_code == 400, r.text
    assert "account settings" in r.json()["detail"].lower()


def test_admin_setting_another_users_email_is_exempt(admin):
    u = admin.create_user(role="user")
    try:
        r = admin.patch(f"/users/{u['id']}", json={"email": unique("set") + "@example.com"})
        assert r.status_code == 200, r.text
    finally:
        admin.delete_user(u["id"])


def test_admin_cannot_change_own_email_via_user_management(admin, restore_settings):
    # the parallel management route must refuse a self email change too (not just PATCH /users/{id})
    me = admin.get("/users/me").json()
    r = admin.put(f"/api/user-management/users/{me['id']}", json={"email": unique("um") + "@example.com"})
    assert r.status_code == 400, r.text
    assert "account settings" in r.json()["detail"].lower()


def test_admin_can_set_another_users_email_via_user_management(admin):
    u = admin.create_user(role="user")
    try:
        r = admin.put(f"/api/user-management/users/{u['id']}", json={"email": unique("umset") + "@example.com"})
        assert r.status_code == 200, r.text
    finally:
        admin.delete_user(u["id"])


# ---- policy gate on the direct PATCH /users/me path -------------------------------------------
def test_direct_email_change_refused_when_policy_on(admin, restore_settings):
    _enable(admin)
    u = admin.create_user(role="user")
    try:
        c = _client_for(admin, u)
        r = c.patch("/users/me", json={"email": unique("d") + "@example.com",
                                       "current_password": u["_password"]})
        assert r.status_code == 400, r.text
        assert "verification" in r.json()["detail"].lower()
    finally:
        admin.delete_user(u["id"])


def test_direct_email_change_allowed_when_policy_off(admin, restore_settings):
    admin.put("/settings", json={"email_change_requires_verification": False})
    u = admin.create_user(role="user")
    try:
        c = _client_for(admin, u)
        new = unique("ok") + "@example.com"
        r = c.patch("/users/me", json={"email": new, "current_password": u["_password"]})
        assert r.status_code == 200, r.text
        assert (c.get("/users/me").json().get("email") or "").lower() == new
    finally:
        admin.delete_user(u["id"])


# ---- request endpoint gates -------------------------------------------------------------------
def test_request_refused_when_policy_off(admin, restore_settings):
    admin.put("/settings", json={"email_change_requires_verification": False})
    u = admin.create_user(role="user")
    try:
        c = _client_for(admin, u)
        r = c.post("/users/me/request-email-change",
                   json={"new_email": unique("r") + "@example.com", "current_password": u["_password"]})
        assert r.status_code == 400, r.text
    finally:
        admin.delete_user(u["id"])


def test_request_refused_without_smtp(admin, restore_settings):
    # enable with SMTP, then clear SMTP so the policy is on but mail can't be sent
    _enable(admin)
    admin.put("/settings", json={"smtp_server": "", "from_email": ""})
    u = admin.create_user(role="user")
    try:
        c = _client_for(admin, u)
        r = c.post("/users/me/request-email-change",
                   json={"new_email": unique("r") + "@example.com", "current_password": u["_password"]})
        assert r.status_code == 400, r.text
        assert "not configured" in r.json()["detail"].lower()
    finally:
        admin.delete_user(u["id"])


def test_request_requires_current_password(admin, restore_settings):
    _enable(admin)
    u = admin.create_user(role="user")
    try:
        c = _client_for(admin, u)
        r = c.post("/users/me/request-email-change",
                   json={"new_email": unique("r") + "@example.com", "current_password": "wrong-password"})
        assert r.status_code == 400, r.text
        assert _code_count(u["id"]) == 0            # no code minted on a failed re-auth
    finally:
        admin.delete_user(u["id"])


def test_request_new_email_mints_a_code_and_smtp_failure_is_clean(admin, restore_settings):
    _enable(admin)                                  # SMTP -> 127.0.0.1:1 (closed) => send fails fast
    u = admin.create_user(role="user")
    try:
        c = _client_for(admin, u)
        r = c.post("/users/me/request-email-change",
                   json={"new_email": unique("new") + "@example.com", "current_password": u["_password"]})
        # a genuinely new address mints a code, then the send to a closed port fails CLEANLY (5xx, not 500)
        assert r.status_code in (502, 400), r.text
        assert r.status_code != 500
        assert _code_count(u["id"]) == 1            # the code row was minted before the send
    finally:
        _purge(u["id"])
        admin.delete_user(u["id"])


def test_request_for_in_use_address_is_enumeration_safe(admin, restore_settings):
    _enable(admin)
    victim = admin.create_user(role="user")        # its address is "in use"
    u = admin.create_user(role="user")
    try:
        c = _client_for(admin, u)
        r = c.post("/users/me/request-email-change",
                   json={"new_email": victim["email"], "current_password": u["_password"]})
        # in-use -> same 202, and NO code minted (can't be used to probe who is registered, no send either)
        assert r.status_code == 202, r.text
        assert _code_count(u["id"]) == 0
    finally:
        _purge(u["id"])
        admin.delete_user(u["id"])
        admin.delete_user(victim["id"])


def test_request_is_rate_limited(admin, restore_settings):
    _enable(admin)
    u = admin.create_user(role="user")
    other = admin.create_user(role="user")          # its email is in-use -> 202 with no send, still counts
    inuse = other["email"]
    try:
        c = _client_for(admin, u)
        seen = [c.post("/users/me/request-email-change",
                       json={"new_email": inuse, "current_password": u["_password"]}).status_code
                for _ in range(5)]
        assert 429 in seen, f"expected a 429 within 5 requests, got {seen}"
    finally:
        _purge(u["id"])
        admin.delete_user(u["id"])
        admin.delete_user(other["id"])


# ---- confirm endpoint (seeded codes) ----------------------------------------------------------
def test_confirm_applies_the_new_email(admin, restore_settings):
    _enable(admin)
    pepper = _pepper()
    assert pepper, "could not read the server pepper (JWT_SECRET_KEY) from the api container"
    u = admin.create_user(role="user")
    new = unique("confirmed") + "@example.com"
    code = generate_code()
    try:
        _seed_code(u["id"], new, code, pepper)
        c = _client_for(admin, u)
        r = c.post("/users/me/confirm-email-change", json={"code": code})
        assert r.status_code == 200, r.text
        assert (c.get("/users/me").json().get("email") or "").lower() == new
        # single-use: the same code cannot be replayed
        assert c.post("/users/me/confirm-email-change", json={"code": code}).status_code == 400
    finally:
        _purge(u["id"])
        admin.delete_user(u["id"])


def test_confirm_rejects_wrong_expired_and_consumed_codes(admin, restore_settings):
    _enable(admin)
    pepper = _pepper()
    u = admin.create_user(role="user")
    try:
        c = _client_for(admin, u)
        # wrong code (no row)
        assert c.post("/users/me/confirm-email-change", json={"code": "definitely-wrong"}).status_code == 400
        # expired
        _seed_code(u["id"], unique("e") + "@example.com", "expcode123456", pepper, expired=True)
        assert c.post("/users/me/confirm-email-change", json={"code": "expcode123456"}).status_code == 400
        # consumed
        _purge(u["id"])
        _seed_code(u["id"], unique("c") + "@example.com", "conscode12345", pepper, consumed=True)
        assert c.post("/users/me/confirm-email-change", json={"code": "conscode12345"}).status_code == 400
        # none of the rejected codes applied anything — the email is still the original
        assert (c.get("/users/me").json().get("email") or "").lower() == (u["email"] or "").lower()
    finally:
        _purge(u["id"])
        admin.delete_user(u["id"])


def test_confirm_rejects_a_wrong_code_against_a_valid_pending_row(admin, restore_settings):
    # The proof-of-control invariant: with a VALID (unexpired, unconsumed) pending row for THIS user,
    # a wrong code must still be refused and the email left unchanged. (The other confirm tests only
    # present a wrong code when NO row matches, so dropping the code_matches() call would slip past
    # them — this pins the actual comparison at the endpoint.)
    _enable(admin)
    pepper = _pepper()
    assert pepper
    u = admin.create_user(role="user")
    new = unique("valrow") + "@example.com"
    try:
        _seed_code(u["id"], new, "correctcode123", pepper)   # valid, unexpired, unconsumed
        c = _client_for(admin, u)
        r = c.post("/users/me/confirm-email-change", json={"code": "wrongcode99999"})
        assert r.status_code == 400, r.text
        assert (c.get("/users/me").json().get("email") or "").lower() == (u["email"] or "").lower()
        # the pending row is still unconsumed → the CORRECT code still applies after the wrong attempt
        assert c.post("/users/me/confirm-email-change", json={"code": "correctcode123"}).status_code == 200
        assert (c.get("/users/me").json().get("email") or "").lower() == new
    finally:
        _purge(u["id"])
        admin.delete_user(u["id"])


def test_confirm_will_not_accept_another_users_code(admin, restore_settings):
    _enable(admin)
    pepper = _pepper()
    a = admin.create_user(role="user")
    b = admin.create_user(role="user")
    code = generate_code()
    try:
        _seed_code(a["id"], unique("a") + "@example.com", code, pepper)   # code belongs to A
        cb = _client_for(admin, b)
        assert cb.post("/users/me/confirm-email-change", json={"code": code}).status_code == 400  # B can't use it
    finally:
        _purge(a["id"]); _purge(b["id"])
        admin.delete_user(a["id"])
        admin.delete_user(b["id"])


# ---- OTP service behaviours (3-strike, re-issue invalidation, configurable TTL) ----------------
def test_three_wrong_attempts_invalidate_the_code(admin, restore_settings):
    _enable(admin)
    pepper = _pepper()
    u = admin.create_user(role="user")
    code = generate_code()
    try:
        _seed_code(u["id"], unique("strike") + "@example.com", code, pepper)
        c = _client_for(admin, u)
        for _ in range(3):
            assert c.post("/users/me/confirm-email-change", json={"code": "wrongwrong99"}).status_code == 400
        # after the 3rd strike the correct code is dead too
        assert c.post("/users/me/confirm-email-change", json={"code": code}).status_code == 400
        assert (c.get("/users/me").json().get("email") or "").lower() == (u["email"] or "").lower()
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


def test_a_new_request_invalidates_a_prior_code(admin, restore_settings):
    _enable(admin)     # SMTP -> closed port: the send after minting fails cleanly; the mint still happens
    pepper = _pepper()
    u = admin.create_user(role="user")
    old = generate_code()
    try:
        _seed_code(u["id"], unique("old") + "@example.com", old, pepper)   # a pending code in the store
        c = _client_for(admin, u)
        # a fresh request mints a NEW code and invalidates the prior one in BOTH stores
        c.post("/users/me/request-email-change",
               json={"new_email": unique("newer") + "@example.com", "current_password": u["_password"]})
        assert c.post("/users/me/confirm-email-change", json={"code": old}).status_code == 400  # old is dead
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


def test_reissue_durably_deletes_a_prior_db_code(admin, restore_settings):
    # Pins the _db_invalidate COMMIT: a fresh request re-issues (into Redis) and must DURABLY drop any
    # prior DB-stored code — checked directly against the DB, not via confirm (which Redis would shadow).
    _enable(admin)
    u = admin.create_user(role="user")
    try:
        _seed_code(u["id"], unique("olddb") + "@example.com", generate_code(), _pepper())  # a DB code
        assert _db_rows(u["id"]) == 1
        c = _client_for(admin, u)
        c.post("/users/me/request-email-change",
               json={"new_email": unique("fresh") + "@example.com", "current_password": u["_password"]})
        assert _db_rows(u["id"]) == 0                # the prior DB code row was deleted AND committed
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


def test_otp_ttl_config_validates_and_round_trips(admin, restore_settings):
    try:
        assert admin.put("/settings", json={"email_change_otp_ttl_minutes": 0}).status_code >= 400   # too small
        assert admin.put("/settings", json={"email_change_otp_ttl_minutes": 999}).status_code >= 400  # too big
        assert admin.put("/settings", json={"email_change_otp_ttl_minutes": 7}).status_code == 200
        assert admin.get("/settings").json().get("email_change_otp_ttl_minutes") == 7
    finally:
        admin.put("/settings", json={"email_change_otp_ttl_minutes": 5})


# ---- temp credentials cannot drive the flow --------------------------------------------------
def test_temp_credential_cannot_request_or_confirm(admin, restore_settings):
    _enable(admin)
    tc = admin.post("/auth/temp-credentials", json={"note": unique("ec")}).json()
    c = ApiClient(BASE_URL)
    c.login(tc["temp_username"], tc["credential"])
    assert c.post("/users/me/request-email-change",
                  json={"new_email": unique("t") + "@example.com", "current_password": "x"}).status_code == 403
    assert c.post("/users/me/confirm-email-change", json={"code": "x"}).status_code == 403
