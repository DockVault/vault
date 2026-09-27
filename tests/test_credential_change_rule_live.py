"""Live: an administrator's second change to someone's sign-in credentials within 14 days waits for
another administrator.

The changes that count, and every route that makes one:
  * a password set by the administrator (PATCH /users/{id});
  * a password reset link, copied (POST /users/{id}/reset-link) or emailed (.../send-reset-link);
  * a second-factor reset (POST /users/{id}/second-factor/reset);
  * an email address change (PATCH /users/{id}, and PUT /api/user-management/users/{id});
  * an SSH key added to someone else's account (POST /users/{id}/ssh-keys).

The first change in the window is made. A second one, of any kind, by the same administrator or any
other, answers 202 and changes nothing: it is held until a DIFFERENT administrator approves it, is
denied, is withdrawn, or expires after 7 days. With nobody else to approve it, it is refused with 409
and a pointer to the host tool. Changing your own credentials is not affected. The account keeps
working while a request waits.

test_credential_change_rule.py covers the rule itself offline.
"""
import base64
import os
import struct
import uuid

import pytest

from conftest import ApiClient, BASE_URL, unique
from _account_change_helpers import (in_api_container, mail_sink, notifications, psql, second_admin,
                                     signed_in)
from _sf_helpers import enroll_totp

pytestmark = pytest.mark.integration

NEW_PASSWORD = "Chosen-By-Admin-8x!"


def _ssh_key():
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + os.urandom(32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def _prepare(kind, admin, user):
    """Anything the target needs before this kind of change can be made."""
    if kind == "second_factor":
        enroll_totp(user, signed_in(user))


# Each maker performs one credential change on `user` as `client` and returns the response.
MAKERS = {
    "patch_password": lambda c, u: c.patch(f"/users/{u['id']}", json={"password": NEW_PASSWORD}),
    "patch_email": lambda c, u: c.patch(f"/users/{u['id']}", json={"email": f"{unique('pe')}@example.com"}),
    "put_email": lambda c, u: c.put(f"/api/user-management/users/{u['id']}",
                                    json={"email": f"{unique('ue')}@example.com"}),
    "reset_link": lambda c, u: c.post(f"/users/{u['id']}/reset-link"),
    "send_reset_link": lambda c, u: c.post(f"/users/{u['id']}/send-reset-link"),
    "second_factor": lambda c, u: c.post(f"/users/{u['id']}/second-factor/reset"),
    "ssh_key": lambda c, u: c.post(f"/users/{u['id']}/ssh-keys", json={"name": "k", "public_key": _ssh_key()}),
}
PREP = {"second_factor": "second_factor"}


def _state(admin, user):
    """What the credential changes would have touched, as it stands now."""
    uid = user["id"]
    return {
        "email": admin.get(f"/users/{uid}").json()["email"],
        "password_hash": psql(f"SELECT password_hash FROM users WHERE id='{uid}'"),
        "reset_tokens": psql(f"SELECT count(*) FROM password_reset_tokens WHERE user_id='{uid}'"),
        "factors": psql(f"SELECT count(*) FROM second_factor_enrollments WHERE user_id='{uid}'"),
        "ssh_keys": psql(f"SELECT count(*) FROM user_ssh_keys WHERE user_id='{uid}'"),
    }


@pytest.fixture(scope="module")
def mail(admin):
    with mail_sink(admin) as real:
        yield real


@pytest.fixture(scope="module")
def other_admin(admin):
    """One more administrator for the module (creating one per test doubled the module's time)."""
    with second_admin(admin) as pair:
        yield pair


def _requests(client):
    r = client.get("/admin/credential-requests")
    assert r.status_code == 200, r.text
    return r.json()["requests"]


def _request_for(client, user_id):
    rows = [r for r in _requests(client) if r["target_user_id"] == user_id]
    assert len(rows) == 1, rows
    return rows[0]


@pytest.mark.parametrize("second", sorted(MAKERS))
def test_a_second_change_of_every_kind_is_held_and_changes_nothing(admin, temp_user, other_admin, mail, second):
    assert MAKERS["patch_password"](admin, temp_user).status_code == 200    # the first change is made
    if second == "second_factor":
        # Enrolled with the new password: the first change set it.
        enroll_totp({**temp_user, "_password": NEW_PASSWORD},
                    signed_in({**temp_user, "_password": NEW_PASSWORD}))
    before = _state(admin, temp_user)

    r = MAKERS[second](admin, temp_user)
    assert r.status_code == 202, r.text
    body = r.json()
    held = body["held_changes"][0] if "held_changes" in body else body
    assert held["held"] is True
    assert "14 days" in held["message"] and "approval" in held["message"]
    assert _state(admin, temp_user) == before, "a held change must change nothing"

    mine = _request_for(admin, temp_user["id"])
    assert (mine["is_mine"], mine["can_approve"], mine["requested_by"]) == (True, False, "admin")
    theirs = _request_for(other_admin[1], temp_user["id"])
    assert (theirs["is_mine"], theirs["can_approve"]) == (False, True)


@pytest.mark.parametrize("first", sorted(MAKERS))
def test_every_kind_opens_the_window(admin, temp_user, other_admin, mail, first):
    if first == "second_factor":
        enroll_totp(temp_user, signed_in(temp_user))
    r = MAKERS[first](admin, temp_user)
    assert r.status_code == 200, r.text
    # A second change, by a different administrator this time, waits.
    r = MAKERS["ssh_key"](other_admin[1], temp_user)
    assert r.status_code == 202, r.text
    assert r.json()["request"]["requested_by"] == other_admin[0]["_username"]


def test_an_address_and_a_password_saved_together_are_two_changes(admin, temp_user, other_admin):
    new_email = f"{unique('both')}@example.com"
    r = admin.patch(f"/users/{temp_user['id']}", json={"email": new_email, "password": NEW_PASSWORD,
                                                       "sftp_enabled": False})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["email"] == new_email and body["sftp_enabled"] is False, "the rest was saved"
    assert [h["request"]["kind"] for h in body["held_changes"]] == ["password"]
    # The password was not set: the user still signs in with the old one.
    assert signed_in(temp_user).token


def test_resaving_the_same_address_is_not_a_change(admin, temp_user):
    same = temp_user["email"]
    for _ in range(3):
        r = admin.patch(f"/users/{temp_user['id']}", json={"email": same, "role": "user", "is_active": True})
        assert r.status_code == 200, r.text
    assert psql(f"SELECT count(*) FROM credential_changes WHERE target_user_id='{temp_user['id']}'") == "0"


def test_another_administrator_approves_and_the_change_is_made(admin, temp_user, other_admin):
    other, other_client = other_admin
    assert admin.post(f"/users/{temp_user['id']}/reset-link").status_code == 200
    user_client = signed_in(temp_user)
    assert admin.patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD}).status_code == 202
    req = _request_for(admin, temp_user["id"])

    # The account keeps working while the request waits.
    assert user_client.get("/users/me").status_code == 200

    refused = admin.post(f"/admin/credential-requests/{req['id']}/approve")
    assert refused.status_code == 403, refused.text

    ok = other_client.post(f"/admin/credential-requests/{req['id']}/approve")
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "approved"
    assert ApiClient(BASE_URL).login(temp_user["_username"], NEW_PASSWORD)
    assert user_client.get("/users/me").status_code == 401, "setting the password ends the sessions"
    assert not [r for r in _requests(admin) if r["id"] == req["id"]], "a decided request leaves the list"

    row = psql(f"SELECT status, decided_by_name, payload IS NULL FROM credential_changes WHERE id='{req['id']}'")
    assert row == f"approved|{other['_username']}|t"
    audit = admin.get("/audit/log", params={"action": "credential_change_approved", "limit": 500}).json()
    assert [a for a in audit if a["resource_id"] == temp_user["id"] and a["username"] == other["_username"]]
    assert [n for n in notifications(admin, "credential_change_approved") if temp_user["_username"] in (n["body"] or "")]
    user_notes = notifications(signed_in({**temp_user, "_password": NEW_PASSWORD}), "credential_change_approved")
    assert user_notes and "admin" in user_notes[0]["body"]


def test_approving_a_held_reset_link_gives_the_link_to_the_approver(admin, temp_user, other_admin):
    assert admin.patch(f"/users/{temp_user['id']}", json={"email": f"{unique('x')}@example.com"}).status_code == 200
    assert admin.post(f"/users/{temp_user['id']}/reset-link").status_code == 202
    req = _request_for(admin, temp_user["id"])
    r = other_admin[1].post(f"/admin/credential-requests/{req['id']}/approve")
    assert r.status_code == 200, r.text
    token = r.json()["reset_link"].split("?reset=", 1)[1]
    assert ApiClient(BASE_URL).get(f"/reset/{token}").json()["username"] == temp_user["_username"]


def test_a_denied_or_withdrawn_request_changes_nothing(admin, temp_user, other_admin):
    other, other_client = other_admin
    assert admin.post(f"/users/{temp_user['id']}/ssh-keys", json={"name": "a", "public_key": _ssh_key()}).status_code == 200
    before = _state(admin, temp_user)

    assert admin.post(f"/users/{temp_user['id']}/ssh-keys", json={"name": "b", "public_key": _ssh_key()}).status_code == 202
    first = _request_for(admin, temp_user["id"])
    r = other_client.post(f"/admin/credential-requests/{first['id']}/deny")
    assert (r.status_code, r.json()["status"]) == (200, "denied")

    assert admin.post(f"/users/{temp_user['id']}/ssh-keys", json={"name": "c", "public_key": _ssh_key()}).status_code == 202
    second = _request_for(admin, temp_user["id"])
    r = admin.post(f"/admin/credential-requests/{second['id']}/deny")
    assert (r.status_code, r.json()["status"]) == (200, "withdrawn")

    assert _state(admin, temp_user) == before
    assert other_client.post(f"/admin/credential-requests/{first['id']}/approve").status_code == 409
    user_client = signed_in(temp_user)
    assert notifications(user_client, "credential_change_denied")
    assert notifications(user_client, "credential_change_withdrawn")
    assert [n for n in notifications(admin, "credential_change_denied") if other["_username"] in n["body"]]
    for action in ("credential_change_denied", "credential_change_withdrawn"):
        rows = admin.get("/audit/log", params={"action": action, "limit": 500}).json()
        assert [a for a in rows if a["resource_id"] == temp_user["id"]], action


def test_a_request_nobody_decides_expires_after_seven_days(admin, temp_user, other_admin):
    assert admin.patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD}).status_code == 200
    assert admin.post(f"/users/{temp_user['id']}/reset-link").status_code == 202
    req = _request_for(admin, temp_user["id"])
    psql(f"UPDATE credential_changes SET expires_at = (now() AT TIME ZONE 'utc') - interval '1 minute' "
         f"WHERE id='{req['id']}'")
    r = other_admin[1].post(f"/admin/credential-requests/{req['id']}/approve")
    assert r.status_code == 409 and "expired" in r.text, r.text

    # The periodic cleanup's own call, on the real database.
    out = in_api_container(
        "from app.core.database import get_db_context\n"
        "from app.api.api_server import _expire_held_credential_changes\n"
        "with get_db_context() as db:\n"
        "    print(_expire_held_credential_changes(db))\n").stdout.strip().splitlines()[-1]
    assert int(out) >= 1
    assert psql(f"SELECT status, payload IS NULL FROM credential_changes WHERE id='{req['id']}'") == "expired|t"
    rows = admin.get("/audit/log", params={"action": "credential_change_expired", "limit": 500}).json()
    assert [a for a in rows if a["resource_id"] == temp_user["id"]]
    assert [n for n in notifications(admin, "credential_change_expired") if temp_user["_username"] in n["body"]]
    user_client = signed_in({**temp_user, "_password": NEW_PASSWORD})
    assert notifications(user_client, "credential_change_expired")


def test_with_no_other_administrator_the_second_change_is_refused(admin, temp_user, other_admin):
    """Every other administrator is locked for the length of the test, so the session's admin is the
    only one who could approve. Their locks are lifted afterwards, and the module's second
    administrator, whose sessions the lock ended, signs in again."""
    me = admin.get("/users/me").json()["id"]
    others = [u for u in admin.get("/users").json()
              if u["role"] == "admin" and u["is_active"] and not u["is_locked"] and u["id"] != me]
    locked = []
    try:
        for u in others:
            assert admin.patch(f"/users/{u['id']}", json={"is_locked": True}).status_code == 200
            locked.append(u["id"])
        assert admin.patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD}).status_code == 200
        r = admin.post(f"/users/{temp_user['id']}/second-factor/reset")
        assert r.status_code == 409, r.text
        detail = r.json()["detail"]
        assert "no other active administrator" in detail and "dockvault.py accounts" in detail
        assert psql(f"SELECT count(*) FROM credential_changes WHERE target_user_id='{temp_user['id']}' "
                    "AND status='held'") == "0"
        rows = admin.get("/audit/log", params={"action": "credential_change_refused", "limit": 500}).json()
        assert [a for a in rows if a["resource_id"] == temp_user["id"]]
    finally:
        for uid in locked:
            admin.patch(f"/users/{uid}", json={"is_locked": False})
        other_admin[1].login(other_admin[0]["_username"], other_admin[0]["_password"])


def test_changing_your_own_credentials_is_not_affected(admin):
    me = admin.get("/users/me").json()["id"]
    added = []
    try:
        for name in ("own-a", "own-b", "own-c"):
            r = admin.post(f"/users/{me}/ssh-keys", json={"name": name, "public_key": _ssh_key()})
            assert r.status_code == 200, r.text
            added.append(r.json()["id"])
        assert psql(f"SELECT count(*) FROM credential_changes WHERE target_user_id='{me}'") == "0"
    finally:
        for key_id in added:
            admin.delete(f"/users/{me}/ssh-keys/{key_id}")


def test_the_users_list_says_when_a_further_change_needs_approval(admin, temp_user):
    assert admin.post(f"/users/{temp_user['id']}/reset-link").status_code == 200
    row = next(u for u in admin.get("/users").json() if u["id"] == temp_user["id"])
    change = row["credential_change"]
    assert (change["kind"], change["by"]) == ("reset_link", "admin")
    assert change["window_ends"] > change["at"]


def test_a_request_for_an_unknown_id_is_not_found(admin):
    assert admin.post(f"/admin/credential-requests/{uuid.uuid4()}/approve").status_code == 404
    assert admin.post(f"/admin/credential-requests/{uuid.uuid4()}/deny").status_code == 404


def test_a_user_cannot_see_or_decide_requests(temp_user_client):
    assert temp_user_client.get("/admin/credential-requests").status_code == 403
    assert temp_user_client.post(f"/admin/credential-requests/{uuid.uuid4()}/approve").status_code == 403
