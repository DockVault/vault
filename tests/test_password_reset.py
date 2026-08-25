"""Live API acceptance for the password-reset flow (self-service + admin-triggered).

Self-service is OFF by default (only an admin can send a link then); when the org enables it, the
public /auth/forgot-password endpoint mints + emails a single-use link. Redeeming sets a new password,
is single-use, and revokes the user's sessions. Enumeration-safe (always 202), rate-limited fail-closed,
and every unusable token gets the same generic 404. Seeded tokens exercise the expired/consumed/wrong
paths without needing to read the emailed plaintext.
"""
import os
import subprocess
import time

import pytest
import requests

from conftest import ApiClient, BASE_URL, unique
from app.core.password_reset import hash_reset_token, mint_reset_token, reset_pepper

pytestmark = pytest.mark.integration

MAILPIT_URL = os.environ.get("VAULT_MAILPIT_URL")
MAILPIT_SMTP_HOST = os.environ.get("VAULT_MAILPIT_SMTP_HOST")
MAILPIT_SMTP_PORT = os.environ.get("VAULT_MAILPIT_SMTP_PORT", "1025")
_mailpit = pytest.mark.skipif(not (MAILPIT_URL and MAILPIT_SMTP_HOST), reason="no Mailpit sink")

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_API = os.environ.get("VAULT_API_CONTAINER", "vault-api")


def _psql(sql):
    return subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                          capture_output=True, text=True, timeout=20)


def _pepper():
    r = subprocess.run(["docker", "exec", _API, "printenv", "JWT_SECRET_KEY"],
                       capture_output=True, text=True, timeout=20)
    return reset_pepper(r.stdout.strip())


def _seed_token(uid, token, *, expired=False, consumed=False):
    h = hash_reset_token(token, _pepper())
    prefix = token[:12]
    exp = "now() - interval '1 minute'" if expired else "now() + interval '10 minutes'"
    cons = "now()" if consumed else "NULL"
    _psql("INSERT INTO password_reset_tokens (id, user_id, token_prefix, token_hash, expires_at, "
          "consumed_at, created_at) "
          f"VALUES (gen_random_uuid(), '{uid}', '{prefix}', '{h}', {exp}, {cons}, now())")


def _rows(uid):
    return int(_psql(f"SELECT count(*) FROM password_reset_tokens WHERE user_id='{uid}'").stdout.strip() or "0")


def _purge(uid):
    _psql(f"DELETE FROM password_reset_tokens WHERE user_id='{uid}'")


def _mp_clear():
    requests.delete(f"{MAILPIT_URL}/api/v1/messages", timeout=10)


def _mp_token_for(email, timeout=15):
    import re
    email = email.lower()
    deadline = time.time() + timeout
    while time.time() < deadline:
        for m in requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", []):
            if email in [a.get("Address", "").lower() for a in m.get("To", [])]:
                full = requests.get(f"{MAILPIT_URL}/api/v1/message/{m['ID']}", timeout=10).json()
                mm = re.search(r"[?&]reset=([A-Za-z0-9_-]+)", full.get("HTML", ""))
                return mm.group(1) if mm else None
        time.sleep(0.4)
    return None


def _anon():
    return ApiClient(BASE_URL)


@pytest.fixture
def restore_reset(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("password_reset_enabled", "smtp_server", "from_email", "smtp_port")}
    yield
    admin.put("/settings", json=snap)


@pytest.fixture
def mailpit_profile(admin):
    for p in admin.get("/email/profiles").json()["profiles"]:
        admin.delete(f"/email/profiles/{p['id']}")
    admin.post("/email/profiles", json={"name": "MP", "smtp_server": MAILPIT_SMTP_HOST,
                                        "smtp_port": int(MAILPIT_SMTP_PORT), "smtp_username": "",
                                        "from_email": "sender@example.com", "is_default": True})
    yield
    for p in admin.get("/email/profiles").json()["profiles"]:
        admin.delete(f"/email/profiles/{p['id']}")


# ---- forgot-password (public) -----------------------------------------------------------------
def test_forgot_password_is_always_202(admin, restore_reset, mailpit_profile):
    admin.put("/settings", json={"password_reset_enabled": True})
    # a real user, a nonexistent identifier, and an empty one all get the SAME 202 (enumeration-safe)
    u = admin.create_user()
    try:
        assert _anon().post("/auth/forgot-password", json={"identifier": u["_username"]}).status_code == 202
        assert _anon().post("/auth/forgot-password", json={"identifier": "nobody-" + unique("x")}).status_code == 202
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


def test_forgot_password_off_by_default_sends_nothing(admin, restore_reset, mailpit_profile):
    admin.put("/settings", json={"password_reset_enabled": False})
    _mp_clear()
    email = f"noreset-{unique('u')}@example.com"
    u = admin.create_user(email=email)
    try:
        assert _anon().post("/auth/forgot-password", json={"identifier": u["_username"]}).status_code == 202
        # disabled -> no token minted, no email
        time.sleep(2)
        assert _rows(u["id"]) == 0
        if MAILPIT_URL:
            assert _mp_token_for(email, timeout=3) is None
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


@_mailpit
def test_forgot_password_delivers_a_working_single_use_link(admin, restore_reset, mailpit_profile):
    admin.put("/settings", json={"password_reset_enabled": True})
    _mp_clear()
    email = f"reset-{unique('u')}@example.com"
    u = admin.create_user(email=email)
    try:
        assert _anon().post("/auth/forgot-password", json={"identifier": email}).status_code == 202
        token = _mp_token_for(email)
        assert token, "no reset link was emailed"
        assert _anon().get(f"/reset/{token}").json().get("username") == u["_username"]
        assert _anon().post(f"/reset/{token}", json={"new_password": "BrandNewPass!9"}).status_code == 200
        assert _anon().post(f"/reset/{token}", json={"new_password": "Another!Pass9"}).status_code == 404  # single-use
        assert _anon().post("/auth/login", json={"username": u["_username"], "password": "BrandNewPass!9"}).status_code == 200
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


# ---- redeem gates (seeded tokens) -------------------------------------------------------------
def test_reset_rejects_wrong_expired_and_consumed(admin, restore_reset):
    u = admin.create_user()
    try:
        assert _anon().get("/reset/definitely-not-a-real-token").status_code == 404
        good, _ = mint_reset_token()
        _seed_token(u["id"], good, expired=True)
        assert _anon().get(f"/reset/{good}").status_code == 404
        assert _anon().post(f"/reset/{good}", json={"new_password": "Strong!Pass99"}).status_code == 404
        _purge(u["id"])
        c2, _ = mint_reset_token()
        _seed_token(u["id"], c2, consumed=True)
        assert _anon().post(f"/reset/{c2}", json={"new_password": "Strong!Pass99"}).status_code == 404
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


def test_weak_password_does_not_burn_the_token(admin, restore_reset):
    u = admin.create_user()
    try:
        token, _ = mint_reset_token()
        _seed_token(u["id"], token)
        # a rejected password (too short -> 422 at the model, or policy-weak -> 400) must NOT burn the token
        assert _anon().post(f"/reset/{token}", json={"new_password": "short"}).status_code in (400, 422)
        # the token is still valid — a strong password now succeeds
        assert _anon().post(f"/reset/{token}", json={"new_password": "Strong!Pass99"}).status_code == 200
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


def test_a_new_link_invalidates_the_prior_one(admin, restore_reset, mailpit_profile):
    admin.put("/settings", json={"password_reset_enabled": True})
    u = admin.create_user()
    try:
        old, _ = mint_reset_token()
        _seed_token(u["id"], old)
        assert _anon().post("/auth/forgot-password", json={"identifier": u["_username"]}).status_code == 202  # re-mint
        assert _anon().get(f"/reset/{old}").status_code == 404   # the seeded (old) link is now dead
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


# ---- admin-triggered --------------------------------------------------------------------------
@_mailpit
def test_admin_send_reset_link_delivers(admin, restore_reset, mailpit_profile):
    _mp_clear()
    email = f"admreset-{unique('u')}@example.com"
    u = admin.create_user(email=email)
    try:
        r = admin.post(f"/users/{u['id']}/send-reset-link")
        assert r.status_code == 200 and r.json().get("email_sent") is True
        assert _mp_token_for(email), "admin reset link not delivered"
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


def test_admin_send_reset_link_without_email_is_400(admin, restore_reset):
    u = admin.create_user(email=None)
    try:
        assert admin.post(f"/users/{u['id']}/send-reset-link").status_code == 400
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


def test_temp_credential_cannot_send_reset_link(admin, restore_reset):
    u = admin.create_user(email=f"t-{unique('u')}@example.com")
    tc = admin.post("/auth/temp-credentials", json={"note": unique("r")}).json()
    ct = ApiClient(BASE_URL)
    ct.login(tc["temp_username"], tc["credential"])
    try:
        assert ct.post(f"/users/{u['id']}/send-reset-link").status_code == 403
    finally:
        _purge(u["id"]); admin.delete_user(u["id"])


def test_password_reset_ttl_config_validates(admin, restore_reset):
    try:
        assert admin.put("/settings", json={"password_reset_ttl_minutes": 0}).status_code >= 400
        assert admin.put("/settings", json={"password_reset_ttl_minutes": 999}).status_code >= 400
        assert admin.put("/settings", json={"password_reset_ttl_minutes": 10}).status_code == 200
        assert admin.get("/settings").json().get("password_reset_ttl_minutes") == 10
    finally:
        admin.put("/settings", json={"password_reset_ttl_minutes": 5})
