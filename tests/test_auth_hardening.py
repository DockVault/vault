"""Auth/throttle/session hardening (Session 2).

Covers the non-SFTP, non-outage pieces:
  * account auto-unlock TTL (a failed-login lock is time-boxed, not a permanent DoS;
    an admin lock stays permanent),
  * durable session revocation (a regular-user token is rejected via the DB `revoked`
    flag — independent of the best-effort Redis logout denylist),
  * trusted-proxy X-Forwarded-For handling (net_utils.client_ip — a direct/untrusted
    peer can't spoof its IP).

The SSH-key brute-force throttle lives in test_sftp_key_auth.py and the fast-fail-closed
Redis-outage test in test_login_throttle.py (opt-in).
"""
import os
import subprocess

import pytest

from conftest import ApiClient, BASE_URL, unique


def _db(sql: str) -> str:
    """Run SQL against the vault DB via docker exec; skip if docker/psql is unavailable."""
    container = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    assert proc.returncode == 0, f"psql failed: {proc.stderr}"
    return proc.stdout.strip()


def _raw_login(username: str, password: str):
    """Login without raising on failure (ApiClient.login raises), to assert the status."""
    c = ApiClient()
    return c.session.post(c._url("/auth/login"),
                          json={"username": username, "password": password}, timeout=30)


def test_failed_login_lock_is_time_boxed_and_auto_unlocks(admin, temp_user):
    """A failed-login auto-lock (is_locked + a future locked_until) rejects both an existing
    token and a fresh login; once the TTL has elapsed (locked_until in the past) the account
    auto-unlocks — so 5 wrong passwords can't permanently DoS a known account."""
    uid, uname, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    c = ApiClient(); c.login(uname, pw)
    assert c.get("/vaults").status_code == 200  # token works before any lock

    # Simulate the failed-login auto-lock with a FUTURE TTL.
    _db(f"UPDATE users SET is_locked=true, failed_login_attempts=99, "
        f"locked_until=now()+interval '1 hour' WHERE id='{uid}'")
    assert c.get("/vaults").status_code == 403, "locked account's existing token must be rejected"
    assert _raw_login(uname, pw).status_code in (401, 403), "login must be refused while locked"

    # TTL elapsed: the lock auto-expires (account_locked honours locked_until).
    _db(f"UPDATE users SET is_locked=true, failed_login_attempts=99, "
        f"locked_until=now()-interval '1 minute' WHERE id='{uid}'")
    assert c.get("/vaults").status_code == 200, "expired lock must not reject a valid token"
    assert _raw_login(uname, pw).status_code == 200, "login must succeed once the lock TTL elapsed"
    # The successful login clears the lock flag entirely.
    assert _db(f"SELECT is_locked FROM users WHERE id='{uid}'") in ("f", "false")


def test_admin_lock_is_permanent(admin, temp_user):
    """An ADMIN lock has no auto-unlock TTL (locked_until NULL) — it stays until an admin
    clears it, distinguishing a deliberate lock from a brute-force auto-lock."""
    uid, uname, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    assert admin.patch(f"/users/{uid}", json={"is_locked": True}).status_code == 200
    assert _db(f"SELECT coalesce(locked_until::text,'') FROM users WHERE id='{uid}'") == "", \
        "admin lock must leave locked_until NULL (permanent)"
    assert _raw_login(uname, pw).status_code in (401, 403)
    # Admin unlock restores access and clears the counter.
    assert admin.patch(f"/users/{uid}", json={"is_locked": False}).status_code == 200
    assert _raw_login(uname, pw).status_code == 200


def test_admin_toggle_lock_is_permanent_and_clears_stale_ttl(admin, temp_user):
    """The admin UI locks via POST /api/user-management/users/{id}/toggle-locked. That path must
    set locked_until=NULL (permanent admin lock) — even over a STALE past locked_until left by a
    prior failed-login auto-lock — or the cleanup sweep / account_locked would silently
    auto-unlock the admin's intended-permanent lock. Regression for the two-lock-paths divergence."""
    uid, uname, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    # Seed the leftover state the bug needed: not-locked but a stale PAST locked_until.
    _db(f"UPDATE users SET is_locked=false, locked_until=now()-interval '1 hour' WHERE id='{uid}'")

    assert admin.post(f"/api/user-management/users/{uid}/toggle-locked").status_code == 200
    # Lock must be permanent: locked_until cleared to NULL, account actually locked.
    assert _db(f"SELECT coalesce(locked_until::text,'') FROM users WHERE id='{uid}'") == "", \
        "toggle admin-lock must null locked_until (permanent), not leave a stale past TTL"
    assert _db(f"SELECT is_locked FROM users WHERE id='{uid}'") in ("t", "true")
    assert _raw_login(uname, pw).status_code in (401, 403), "permanently-locked account must refuse login"

    # Unlock via the same path restores access.
    assert admin.post(f"/api/user-management/users/{uid}/toggle-locked").status_code == 200
    assert _raw_login(uname, pw).status_code == 200


def test_disabling_sftp_does_not_revoke_web_session(admin, temp_user):
    """PATCH /users/{id} sftp_enabled=False must tear down SFTP only — it must NOT durably
    revoke the user's WEB JWT (the durable-revoke change initially over-reached here)."""
    uid, uname, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    c = ApiClient(); c.login(uname, pw)
    assert c.get("/vaults").status_code == 200

    assert admin.patch(f"/users/{uid}", json={"sftp_enabled": False}).status_code == 200
    assert c.get("/vaults").status_code == 200, "disabling SFTP must not log out the web session"
    cnt = _db(f"SELECT count(*) FROM active_sessions s JOIN users u ON u.id=s.user_id "
              f"WHERE u.username='{uname}' AND s.revoked=true")
    assert cnt == "0", "disabling SFTP must not set the durable revoked flag on the web session"


def test_session_revoked_flag_rejects_regular_token_without_redis(admin, temp_user, temp_user_client):
    """A regular-user token is rejected per-request when its session is marked `revoked` in the
    DB — the DURABLE revocation that survives a Redis outage (the Redis logout denylist is only
    a fast path). We set `revoked` directly (bypassing the denylist) to isolate the DB path."""
    uid = temp_user["id"]
    assert temp_user_client.get("/vaults").status_code == 200  # works before revocation

    # Revoke the session in the DB only (no logout -> no Redis denylist entry).
    _db(f"UPDATE active_sessions SET revoked=true WHERE user_id='{uid}' AND is_active=true")
    assert temp_user_client.get("/vaults").status_code == 401, \
        "a DB-revoked session must be rejected even without the Redis denylist"


def test_logout_sets_durable_revoked_flag(admin, temp_user):
    """Logout marks the session `revoked` in the DB (not just the Redis denylist), so the
    revocation holds even if Redis is unavailable on a later request."""
    uname, pw = temp_user["_username"], temp_user["_password"]
    c = ApiClient(); c.login(uname, pw)
    assert c.get("/vaults").status_code == 200
    assert c.post("/api/logout").status_code == 200
    # The session row is now flagged revoked, and the token is rejected.
    cnt = _db(f"SELECT count(*) FROM active_sessions s JOIN users u ON u.id=s.user_id "
              f"WHERE u.username='{uname}' AND s.revoked=true")
    assert cnt != "0", "logout must set the durable revoked flag"
    assert c.get("/vaults").status_code == 401


# Trusted-proxy X-Forwarded-For handling — exercised INSIDE the container (net_utils imports
# config, which needs the credential manager). Mirrors the docker-exec self-test pattern.
_NET_SELFTEST = r'''
import net_utils

class _Headers(dict):
    def get(self, k, d=None):
        return super().get(k, d)

class _Req:
    def __init__(self, peer, xff=None):
        self.client = type("C", (), {"host": peer})()
        self.headers = _Headers({"X-Forwarded-For": xff} if xff else {})

ci = net_utils.client_ip
# A trusted (private/loopback) peer is the reverse proxy -> honour XFF, taking the RIGHT-MOST
# UNTRUSTED entry (append-style proxies append the connecting IP, so a forged LEFT-most value
# must NOT win).
assert ci(_Req("172.18.0.5", "203.0.113.50")) == "203.0.113.50", "single-hop XFF"
assert ci(_Req("172.18.0.5", "9.9.9.9, 203.0.113.50")) == "203.0.113.50", "forged left-most XFF must be ignored"
assert ci(_Req("127.0.0.1", "1.2.3.4")) == "1.2.3.4", "loopback peer must honour XFF"
# Multiple trusted hops appended after the real client -> right-most untrusted is the client.
assert ci(_Req("172.18.0.5", "203.0.113.50, 10.0.0.9, 172.18.0.5")) == "203.0.113.50"
# An untrusted (public) peer is a direct client -> IGNORE its spoofable XFF, use the peer.
assert ci(_Req("8.8.8.8", "203.0.113.9")) == "8.8.8.8", "untrusted peer must ignore XFF"
assert ci(_Req("8.8.8.8")) == "8.8.8.8", "no XFF -> peer"
# IPv4-mapped IPv6 trusted peer is recognised as trusted (dual-stack hosts).
assert ci(_Req("::ffff:172.18.0.5", "203.0.113.50")) == "203.0.113.50", "mapped trusted peer"
# Junk / host:port tokens are skipped, not fatal.
assert ci(_Req("172.18.0.5", "garbage, 203.0.113.50")) == "203.0.113.50", "skip junk token"
assert ci(_Req("172.18.0.5", "203.0.113.50:1234")) == "203.0.113.50", "strip :port"
assert ci(_Req("127.0.0.1", "not-an-ip")) == "127.0.0.1", "all-junk XFF -> peer"
# All-trusted chain -> the originating (left-most) internal address.
assert ci(_Req("127.0.0.1", "10.0.0.7, 192.168.1.2")) == "10.0.0.7", "all-trusted -> left-most"
print("NET_OK")
'''


def test_xff_trusted_proxy_resolution():
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    try:
        proc = subprocess.run(
            ["docker", "exec", "-i", container, "python", "-"],
            input=_NET_SELFTEST, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=60,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable for net_utils self-test: {exc}")
    assert "NET_OK" in proc.stdout, (
        f"net_utils XFF self-test failed (rc={proc.returncode})\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
