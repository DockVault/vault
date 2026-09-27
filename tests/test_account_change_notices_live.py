"""Live: every administrator's change to someone's credentials or standing tells that person, in the
app and by email.

The changes: a password set, a reset link copied or emailed, a second-factor reset, an email address
change, an SSH key added, a lock and an unlock, a deactivation and a reactivation, and a role change,
through each route that makes them. Each leaves the user an in-app notification that says what
changed, when, by whom, and what to do if it was not expected. With a mail sink (VAULT_MAILPIT_URL
and VAULT_MAILPIT_SMTP_HOST), the same arrives by email, and an email change goes to the OLD address.

test_account_change_notices.py covers the wording offline.
"""
import base64
import os
import struct

import pytest

from conftest import unique
from _account_change_helpers import MAILPIT_URL, mail_sink, mail_to, psql, signed_in
from _sf_helpers import enroll_totp

pytestmark = pytest.mark.integration


def _ssh_key():
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + os.urandom(32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def _notices(user_id):
    out = psql(f"SELECT title || '|' || coalesce(body, '') FROM notifications WHERE user_id='{user_id}' "
               "AND type='account_changed' ORDER BY created_at")
    return [line.split("|", 1) for line in out.splitlines() if line]


def _assert_told(user, title, *words):
    notices = _notices(user["id"])
    matching = [body for t, body in notices if t == title]
    assert matching, (title, notices)
    body = matching[-1]
    assert "By: admin" in body and "UTC" in body and "If you did not expect this" in body, body
    for w in words:
        assert w in body, (w, body)


@pytest.fixture(scope="module")
def mail(admin):
    with mail_sink(admin) as real:
        yield real


CHANGES = {
    "password": (lambda a, u: a.patch(f"/users/{u['id']}", json={"password": "Admin-Chosen-8x!"}),
                 "Your password was changed", ["set a new password"]),
    "email (PATCH)": (lambda a, u: a.patch(f"/users/{u['id']}", json={"email": f"{u['_username']}-n@example.com"}),
                      "Your email address was changed", ["-n@example.com"]),
    "email (PUT)": (lambda a, u: a.put(f"/api/user-management/users/{u['id']}",
                                       json={"email": f"{u['_username']}-m@example.com"}),
                    "Your email address was changed", ["-m@example.com"]),
    "reset link": (lambda a, u: a.post(f"/users/{u['id']}/reset-link"),
                   "A password reset link was created for your account", []),
    "emailed reset link": (lambda a, u: a.post(f"/users/{u['id']}/send-reset-link"),
                           "A password reset link was sent to you", []),
    "second factor": (lambda a, u: a.post(f"/users/{u['id']}/second-factor/reset"),
                      "Your second factor was reset", ["with your own password"]),
    "ssh key": (lambda a, u: a.post(f"/users/{u['id']}/ssh-keys", json={"name": "desk", "public_key": _ssh_key()}),
                "An SSH key was added to your account", ['"desk"']),
    "lock (PATCH)": (lambda a, u: a.patch(f"/users/{u['id']}", json={"is_locked": True}),
                     "Your account was locked", []),
    "lock (toggle)": (lambda a, u: a.post(f"/api/user-management/users/{u['id']}/toggle-locked"),
                      "Your account was locked", []),
    "deactivate (PATCH)": (lambda a, u: a.patch(f"/users/{u['id']}", json={"is_active": False}),
                           "Your account was deactivated", []),
    "deactivate (toggle)": (lambda a, u: a.post(f"/api/user-management/users/{u['id']}/toggle-active"),
                            "Your account was deactivated", []),
    "deactivate (PUT)": (lambda a, u: a.put(f"/api/user-management/users/{u['id']}", json={"is_active": False}),
                         "Your account was deactivated", []),
    "role (PATCH)": (lambda a, u: a.patch(f"/users/{u['id']}", json={"role": "external"}),
                     "Your role was changed", ["from user to external"]),
    "role (role route)": (lambda a, u: a.patch(f"/api/user-management/users/{u['id']}/role",
                                               json={"new_role": "external"}),
                          "Your role was changed", ["from user to external"]),
    "role (PUT)": (lambda a, u: a.put(f"/api/user-management/users/{u['id']}", json={"role": "external"}),
                   "Your role was changed", ["from user to external"]),
}


@pytest.mark.parametrize("change", sorted(CHANGES))
def test_the_user_is_told_in_the_app(admin, temp_user, mail, change):
    make, title, words = CHANGES[change]
    if change == "second factor":
        enroll_totp(temp_user, signed_in(temp_user))
    r = make(admin, temp_user)
    assert r.status_code == 200, r.text
    _assert_told(temp_user, title, *words)


def test_undoing_a_lock_and_a_deactivation_is_told_too(admin, temp_user):
    uid = temp_user["id"]
    for body in ({"is_locked": True}, {"is_locked": False}, {"is_active": False}, {"is_active": True}):
        assert admin.patch(f"/users/{uid}", json=body).status_code == 200
    titles = [t for t, _b in _notices(uid)]
    assert titles == ["Your account was locked", "Your account was unlocked",
                      "Your account was deactivated", "Your account was reactivated"]


def test_saving_the_edit_form_unchanged_tells_nobody(admin, temp_user):
    for _ in range(2):
        r = admin.patch(f"/users/{temp_user['id']}", json={"email": temp_user["email"], "role": "user",
                                                           "is_active": True})
        assert r.status_code == 200, r.text
    assert _notices(temp_user["id"]) == []


def test_a_held_change_tells_the_user_too(admin, temp_user):
    from _account_change_helpers import second_admin
    with second_admin(admin):
        assert admin.post(f"/users/{temp_user['id']}/reset-link").status_code == 200
        assert admin.patch(f"/users/{temp_user['id']}", json={"password": "Admin-Chosen-8x!"}).status_code == 202
    out = psql(f"SELECT title FROM notifications WHERE user_id='{temp_user['id']}' AND type='credential_change_held'")
    assert out == "A change to your account is waiting for approval"


needs_mailpit = pytest.mark.skipif(not MAILPIT_URL, reason="no Mailpit sink to read the email from")


@needs_mailpit
def test_the_user_is_told_by_email(admin, mail):
    address = f"{unique('told')}@example.com"
    user = admin.create_user(email=address)
    try:
        assert admin.patch(f"/users/{user['id']}", json={"password": "Admin-Chosen-8x!"}).status_code == 200
        message = mail_to(address, subject_contains="A change to your")
        assert message, "no email about the change reached the user"
        assert "set a new password" in message["text"] and "By: admin" in message["text"]
        assert "If you did not expect this" in message["text"]
    finally:
        admin.delete_user(user["id"])


@needs_mailpit
def test_an_email_change_is_told_to_the_old_address_only(admin, mail):
    old, new = f"{unique('old')}@example.com", f"{unique('new')}@example.com"
    user = admin.create_user(email=old)
    try:
        assert admin.patch(f"/users/{user['id']}", json={"email": new}).status_code == 200
        message = mail_to(old, subject_contains="A change to your")
        assert message and f"from {old} to {new}" in message["text"], message
        assert mail_to(new, subject_contains="A change to your", timeout=3) is None
    finally:
        admin.delete_user(user["id"])
