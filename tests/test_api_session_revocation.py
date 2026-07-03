"""Security: token revocation on logout + lock, WITHOUT enforcing single-session.

The fix denylists a token on logout (Redis) and re-checks is_locked on every request, so a
logged-out or locked account's JWT stops working immediately — but re-login does NOT revoke
other sessions, so concurrent sessions still coexist (single-session is a separate, opt-in
per-account feature). Regression for the JWT-not-revoked-on-logout gap.
"""


def _login_as(admin, user):
    c = admin.clone_anonymous()
    c.login(user["_username"], user["_password"])
    return c


def test_logout_revokes_only_that_token_and_concurrent_sessions_coexist(admin):
    u = admin.create_user(role="user")
    try:
        c1 = _login_as(admin, u)
        c2 = _login_as(admin, u)
        # both sessions for the same user work concurrently (no single-session enforcement)
        assert c1.get(f"/permissions/users/{u['id']}").status_code == 200
        assert c2.get(f"/permissions/users/{u['id']}").status_code == 200
        # logging out c1 revokes ONLY c1's token
        assert c1.post("/api/logout").status_code in (200, 204)
        assert c1.get(f"/permissions/users/{u['id']}").status_code == 401, "logged-out token still valid"
        assert c2.get(f"/permissions/users/{u['id']}").status_code == 200, "logout wrongly revoked the other session"
    finally:
        admin.delete_user(u["id"])


def test_locking_user_revokes_existing_token(admin):
    """Locking an account rejects its already-issued token immediately, not at expiry. The
    lock both durably revokes the session (401) AND fails the per-request account-locked check
    (403); either rejection is correct, so accept both."""
    u = admin.create_user(role="user")
    try:
        c = _login_as(admin, u)
        assert c.get(f"/permissions/users/{u['id']}").status_code == 200
        # admin locks the account (fresh user starts unlocked, so toggle => locked)
        assert admin.post(f"/api/user-management/users/{u['id']}/toggle-locked").status_code == 200
        assert c.get(f"/permissions/users/{u['id']}").status_code in (401, 403), \
            "locked user's token still works"
    finally:
        admin.delete_user(u["id"])
