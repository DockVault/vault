"""A password change must durably revoke the account's live sessions, on every path that sets one.

The reset-token path already does this (test_password_reset.test_reset_revokes_existing_sessions);
these pin the same guarantee for the two remaining password-setting routes -- self-service
PATCH /users/me and admin PATCH /users/{id}. A stolen JWT is indistinguishable from the legitimate
one, so it must not outlive the password change that is the natural response to a suspected
compromise. Each would FAIL if the _revoke_sessions call were removed from its handler.
"""
import pytest

from conftest import ApiClient, BASE_URL

pytestmark = pytest.mark.integration

_STRONG = "Str0ng!Rotated#Pass9"


def test_self_service_password_change_revokes_the_session(admin):
    u = admin.create_user(role="user")
    try:
        sess = ApiClient(BASE_URL)
        sess.login(u["_username"], u["_password"])
        assert sess.get("/users/me").status_code == 200          # session is live

        r = sess.patch("/users/me", json={"current_password": u["_password"],
                                          "new_password": _STRONG})
        assert r.status_code == 200, r.text                      # the change succeeded

        # The token that made the change is now revoked -- the change evicted every session,
        # including its own.
        assert sess.get("/users/me").status_code in (401, 403), \
            "the session survived a self-service password change"
    finally:
        admin.delete_user(u["id"])


def test_admin_password_change_revokes_the_users_session(admin):
    u = admin.create_user(role="user")
    try:
        sess = ApiClient(BASE_URL)
        sess.login(u["_username"], u["_password"])
        assert sess.get("/users/me").status_code == 200

        assert admin.patch(f"/users/{u['id']}", json={"password": _STRONG}).status_code == 200

        # The user's live session is gone; the admin's own session is untouched.
        assert sess.get("/users/me").status_code in (401, 403), \
            "the user's session survived an admin password change"
        assert admin.get("/users/me").status_code == 200
    finally:
        admin.delete_user(u["id"])
