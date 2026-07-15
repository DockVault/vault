"""POST /users/{id}/terminate-sessions — an admin terminates a user's live sessions.

The admin per-user "Terminate Sessions" button targets this route; it durably revokes
the user's web tokens and force-closes live transports (via _revoke_sessions).
"""
import uuid


def _logged_in_user(admin):
    u = admin.create_user(role="user")
    c = admin.clone_anonymous()
    c.login(u["_username"], u["_password"])
    return u, c


def test_admin_terminates_user_sessions(admin):
    u, uc = _logged_in_user(admin)
    try:
        assert uc.get("/vaults").status_code == 200  # the user's token works
        r = admin.post(f"/users/{u['id']}/terminate-sessions")
        assert r.status_code == 200, r.text
        assert r.json()["terminated_count"] >= 1
        # durable revocation: the user's token is now rejected per-request
        assert uc.get("/vaults").status_code == 401
    finally:
        admin.delete_user(u["id"])


def test_terminate_sessions_requires_admin(admin):
    victim = admin.create_user(role="user")
    actor = admin.create_user(role="user")
    ac = admin.clone_anonymous()
    ac.login(actor["_username"], actor["_password"])
    try:
        r = ac.post(f"/users/{victim['id']}/terminate-sessions")
        assert r.status_code == 403, r.text
        # the victim's sessions are untouched (no privilege escalation)
    finally:
        admin.delete_user(victim["id"])
        admin.delete_user(actor["id"])


def test_terminate_sessions_unknown_user_404(admin):
    r = admin.post(f"/users/{uuid.uuid4()}/terminate-sessions")
    assert r.status_code == 404, r.text


def test_admin_cannot_terminate_own_sessions(admin, admin_creds):
    # self-termination would durably revoke the admin's own live session — refused (400),
    # mirroring delete_user's self-guard.
    users = admin.get("/users").json()
    me = next(u for u in users if u["username"] == admin_creds["username"])
    r = admin.post(f"/users/{me['id']}/terminate-sessions")
    assert r.status_code == 400, r.text
    # the admin's own session still works
    assert admin.get("/vaults").status_code == 200
