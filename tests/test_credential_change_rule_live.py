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

Who may approve: an administrator independent of the change. Not the one who asked; not one who made
or approved a change to that account within 14 days of the request; not one in the asker's lineage, nor
with the asker in theirs; and one who had been an administrator for 14 days when it was asked for. An
administrator a test creates is none of that (the session's administrator made it, a moment ago), so the
module's second administrator is made independent and of long standing in the database
(make_independent). In most tests it makes the first change and asks for the second, and the session's
administrator, who changed nothing, approves.

test_credential_change_rule.py covers the rule itself offline.
"""
import base64
import os
import struct
import uuid

import pytest

from conftest import ApiClient, BASE_URL, unique
from _account_change_helpers import (in_api_container, mail_sink, make_independent, notifications, psql,
                                     second_admin, signed_in)
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
    """One more administrator for the module (creating one per test doubled the module's time), made
    independent of the session's administrator and of long standing (make_independent)."""
    with second_admin(admin, independent=True) as pair:
        yield pair


@pytest.fixture(scope="module")
def third_admin(admin):
    """A third one, likewise: for a request whose approver may be neither of the other two."""
    with second_admin(admin, independent=True) as pair:
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
    other, other_client = other_admin
    assert MAKERS["patch_password"](other_client, temp_user).status_code == 200    # the first change is made
    if second == "second_factor":
        # Enrolled with the new password: the first change set it.
        enroll_totp({**temp_user, "_password": NEW_PASSWORD},
                    signed_in({**temp_user, "_password": NEW_PASSWORD}))
    before = _state(admin, temp_user)

    r = MAKERS[second](other_client, temp_user)
    assert r.status_code == 202, r.text
    body = r.json()
    held = body["held_changes"][0] if "held_changes" in body else body
    assert held["held"] is True
    assert "14 days" in held["message"] and "approval" in held["message"]
    assert _state(admin, temp_user) == before, "a held change must change nothing"

    mine = _request_for(other_client, temp_user["id"])
    assert (mine["is_mine"], mine["can_approve"], mine["requested_by"]) == (True, False, other["_username"])
    assert mine["label"][0].isupper() and " " in mine["label"], "named by what it asks for"
    theirs = _request_for(admin, temp_user["id"])
    assert (theirs["is_mine"], theirs["can_approve"], theirs["cannot_approve"]) == (False, True, None)


@pytest.mark.parametrize("first", sorted(MAKERS))
def test_every_kind_opens_the_window(admin, temp_user, other_admin, third_admin, mail, first):
    if first == "second_factor":
        enroll_totp(temp_user, signed_in(temp_user))
    r = MAKERS[first](other_admin[1], temp_user)
    assert r.status_code == 200, r.text
    # A second change, by a different administrator this time, waits.
    r = MAKERS["ssh_key"](third_admin[1], temp_user)
    assert r.status_code == 202, r.text
    assert r.json()["request"]["requested_by"] == third_admin[0]["_username"]
    # The session's administrator changed nothing and is independent of the asker, so may approve it;
    # the one who made the first change may not.
    theirs = _request_for(admin, temp_user["id"])
    assert (theirs["is_mine"], theirs["can_approve"], theirs["cannot_approve"]) == (False, True, None)
    first_changer = _request_for(other_admin[1], temp_user["id"])
    assert first_changer["can_approve"] is False
    assert "you changed this account's sign-in details" in first_changer["cannot_approve"]


def test_an_address_and_a_password_saved_together_are_two_changes(admin, temp_user, other_admin):
    new_email = f"{unique('both')}@example.com"
    r = other_admin[1].patch(f"/users/{temp_user['id']}", json={"email": new_email, "password": NEW_PASSWORD,
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
    # The second administrator makes the first change and asks for the second; the session's
    # administrator, who changed nothing and is independent of it, may approve.
    other, other_client = other_admin
    me = admin.get("/users/me").json()["username"]
    assert other_client.post(f"/users/{temp_user['id']}/reset-link").status_code == 200
    user_client = signed_in(temp_user)
    assert other_client.patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD}).status_code == 202
    req = _request_for(admin, temp_user["id"])

    # The account keeps working while the request waits.
    assert user_client.get("/users/me").status_code == 200

    refused = other_client.post(f"/admin/credential-requests/{req['id']}/approve")
    assert refused.status_code == 403, refused.text

    ok = admin.post(f"/admin/credential-requests/{req['id']}/approve")
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "approved"
    assert ApiClient(BASE_URL).login(temp_user["_username"], NEW_PASSWORD)
    assert user_client.get("/users/me").status_code == 401, "setting the password ends the sessions"
    assert not [r for r in _requests(admin) if r["id"] == req["id"]], "a decided request leaves the list"

    row = psql(f"SELECT status, decided_by_name, payload IS NULL FROM credential_changes WHERE id='{req['id']}'")
    assert row == f"approved|{me}|t"
    audit = admin.get("/audit/log", params={"action": "credential_change_approved", "limit": 500}).json()
    assert [a for a in audit if a["resource_id"] == temp_user["id"] and a["username"] == me]
    assert [n for n in notifications(other_client, "credential_change_approved")
            if temp_user["_username"] in (n["body"] or "")]
    user_notes = notifications(signed_in({**temp_user, "_password": NEW_PASSWORD}), "credential_change_approved")
    assert user_notes and me in user_notes[0]["body"] and other["_username"] in user_notes[0]["body"]


def test_approving_a_held_reset_link_gives_the_link_to_the_approver(admin, temp_user, other_admin):
    assert other_admin[1].patch(f"/users/{temp_user['id']}",
                                json={"email": f"{unique('x')}@example.com"}).status_code == 200
    assert other_admin[1].post(f"/users/{temp_user['id']}/reset-link").status_code == 202
    req = _request_for(admin, temp_user["id"])
    r = admin.post(f"/admin/credential-requests/{req['id']}/approve")
    assert r.status_code == 200, r.text
    token = r.json()["reset_link"].split("?reset=", 1)[1]
    assert ApiClient(BASE_URL).get(f"/reset/{token}").json()["username"] == temp_user["_username"]


def test_a_denied_or_withdrawn_request_changes_nothing(admin, temp_user, other_admin):
    other, other_client = other_admin
    me = admin.get("/users/me").json()["username"]
    assert other_client.post(f"/users/{temp_user['id']}/ssh-keys",
                             json={"name": "a", "public_key": _ssh_key()}).status_code == 200
    before = _state(admin, temp_user)

    assert other_client.post(f"/users/{temp_user['id']}/ssh-keys",
                             json={"name": "b", "public_key": _ssh_key()}).status_code == 202
    first = _request_for(admin, temp_user["id"])
    r = admin.post(f"/admin/credential-requests/{first['id']}/deny")
    assert (r.status_code, r.json()["status"]) == (200, "denied")

    assert other_client.post(f"/users/{temp_user['id']}/ssh-keys",
                             json={"name": "c", "public_key": _ssh_key()}).status_code == 202
    second = _request_for(admin, temp_user["id"])
    r = other_client.post(f"/admin/credential-requests/{second['id']}/deny")
    assert (r.status_code, r.json()["status"]) == (200, "withdrawn")

    assert _state(admin, temp_user) == before
    assert admin.post(f"/admin/credential-requests/{first['id']}/approve").status_code == 409
    user_client = signed_in(temp_user)
    assert notifications(user_client, "credential_change_denied")
    assert notifications(user_client, "credential_change_withdrawn")
    assert [n for n in notifications(other_client, "credential_change_denied") if me in n["body"]]
    for action in ("credential_change_denied", "credential_change_withdrawn"):
        rows = admin.get("/audit/log", params={"action": action, "limit": 500}).json()
        assert [a for a in rows if a["resource_id"] == temp_user["id"]], action


def test_a_request_nobody_decides_expires_after_seven_days(admin, temp_user, other_admin):
    assert other_admin[1].patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD}).status_code == 200
    assert other_admin[1].post(f"/users/{temp_user['id']}/reset-link").status_code == 202
    req = _request_for(admin, temp_user["id"])
    psql(f"UPDATE credential_changes SET expires_at = (now() AT TIME ZONE 'utc') - interval '1 minute' "
         f"WHERE id='{req['id']}'")
    r = admin.post(f"/admin/credential-requests/{req['id']}/approve")
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
    assert [n for n in notifications(other_admin[1], "credential_change_expired")
            if temp_user["_username"] in n["body"]]
    user_client = signed_in({**temp_user, "_password": NEW_PASSWORD})
    assert notifications(user_client, "credential_change_expired")


def test_with_no_other_administrator_the_second_change_is_refused(admin, temp_user, other_admin, third_admin):
    """Every other administrator is locked for the length of the test, so the session's admin is the
    only one who could approve. Their locks are lifted afterwards, and the module's other
    administrators, whose sessions the lock ended, sign in again."""
    me = admin.get("/users/me").json()["id"]
    others = [u for u in admin.get("/users").json()
              if u["role"] == "admin" and u["is_active"] and not u["is_locked"] and u["id"] != me]
    locked = []
    try:
        for u in others:
            assert admin.patch(f"/users/{u['id']}", json={"is_locked": True}).status_code == 200
            locked.append(u["id"])
        assert admin.patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD}).status_code == 200
        # An administrator account the session's admin makes now is not another administrator: it
        # could only approve its maker's change, which the rule refuses, and the refusal says so.
        with second_admin(admin) as (made, _client):
            r = admin.post(f"/users/{temp_user['id']}/second-factor/reset")
        assert r.status_code == 409, r.text
        detail = r.json()["detail"]
        assert "no other administrator may approve it" in detail and "dockvault.py accounts" in detail
        assert f"you made {made['_username']} an administrator" in detail, detail
        assert psql(f"SELECT count(*) FROM credential_changes WHERE target_user_id='{temp_user['id']}' "
                    "AND status='held'") == "0"
        rows = admin.get("/audit/log", params={"action": "credential_change_refused", "limit": 500}).json()
        mine = [a for a in rows if a["resource_id"] == temp_user["id"]]
        assert mine and mine[0]["details"]["approver_refusals"] == ["made"], mine
    finally:
        for uid in locked:
            admin.patch(f"/users/{uid}", json={"is_locked": False})
        for account, client in (other_admin, third_admin):
            client.login(account["_username"], account["_password"])


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


def test_two_administrators_approving_at_once_apply_the_change_once(admin, temp_user, other_admin):
    # Approving a held reset link mints the link, which commits part-way through the approval. Two
    # approvals at the same moment must still make the change once: one is approved, the other is told
    # the request was already decided.
    import threading
    requester, requester_client = other_admin
    assert requester_client.post(f"/users/{temp_user['id']}/reset-link").status_code == 200
    with second_admin(admin, independent=True) as (_third, third_client):
        assert requester_client.post(f"/users/{temp_user['id']}/reset-link").status_code == 202
        req = _request_for(requester_client, temp_user["id"])
        start, answers = threading.Barrier(2), {}

        def approve(name, client):
            start.wait()
            answers[name] = client.post(f"/admin/credential-requests/{req['id']}/approve")

        threads = [threading.Thread(target=approve, args=(n, c)) for n, c in (("admin", admin), ("third", third_client))]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        codes = sorted(r.status_code for r in answers.values())
        assert codes == [200, 409], {n: (r.status_code, r.text[:200]) for n, r in answers.items()}
        refused = next(r for r in answers.values() if r.status_code == 409)
        assert "already" in refused.text
    approvals = admin.get("/audit/log", params={"action": "credential_change_approved", "limit": 500}).json()
    assert len([a for a in approvals if (a.get("details") or {}).get("change_id") == req["id"]]) == 1
    assert psql(f"SELECT status FROM credential_changes WHERE id='{req['id']}'") == "approved"


def test_an_administrator_the_requester_made_cannot_approve(admin, temp_user, other_admin):
    # The review's scenario: the administrator whose change is held makes a new administrator account,
    # signs in as it and approves. Refused, and so is an administrator that one made; every other
    # administrator is told of each new one; an administrator the asker did not make may approve.
    asker, asker_client = other_admin
    me = admin.get("/users/me").json()["username"]
    assert asker_client.patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD}).status_code == 200
    held = asker_client.post(f"/users/{temp_user['id']}/reset-link")
    assert held.status_code == 202, held.text
    req_id = held.json()["request"]["id"]
    with second_admin(asker_client) as (puppet, puppet_client):
        r = puppet_client.post(f"/admin/credential-requests/{req_id}/approve")
        assert r.status_code == 403, r.text
        assert f"{asker['_username']} made you an administrator" in r.json()["detail"]
        with second_admin(puppet_client) as (grandchild, grandchild_client):
            r = grandchild_client.post(f"/admin/credential-requests/{req_id}/approve")
            assert r.status_code == 403 and "made you an administrator" in r.json()["detail"], r.text
        assert psql(f"SELECT status FROM credential_changes WHERE id='{req_id}'") == "held"
        assert psql(f"SELECT count(*) FROM password_reset_tokens WHERE user_id='{temp_user['id']}'") == "0"
        refusals = admin.get("/audit/log", params={"action": "credential_change_approval_refused",
                                                   "limit": 500}).json()
        assert len([a for a in refusals if (a.get("details") or {}).get("change_id") == req_id]) == 2
        told = [n["body"] for n in notifications(admin, "administrator_added")
                if f"created the administrator account {puppet['_username']}." in n["body"]]
        assert told and told[0].startswith(f"{asker['_username']} created"), told
        assert "When:" not in told[0] and "UTC" not in told[0], told    # the notice's own time is the one shown
        assert psql(f"SELECT granted_by_name FROM admin_grants WHERE user_id='{puppet['id']}'") == asker["_username"]
    ok = admin.post(f"/admin/credential-requests/{req_id}/approve")
    assert ok.status_code == 200, ok.text
    assert psql(f"SELECT decided_by_name FROM credential_changes WHERE id='{req_id}'") == me


def test_the_administrator_who_made_the_first_change_cannot_approve_through_an_account_it_made(
        admin, temp_user, other_admin):
    # The review's mirror: the session's administrator makes the first change and an administrator
    # account, asks for the second as that account, and approves it as itself. Refused, saying why;
    # the module's independent administrator, who changed nothing, may approve.
    other, other_client = other_admin
    assert admin.post(f"/users/{temp_user['id']}/reset-link").status_code == 200       # the first change
    with second_admin(admin) as (puppet, puppet_client):
        held = puppet_client.patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD})
        assert held.status_code == 202, held.text
        req_id = held.json()["held_changes"][0]["request"]["id"]
        r = admin.post(f"/admin/credential-requests/{req_id}/approve")
        assert r.status_code == 403, r.text
        assert f"You made {puppet['_username']} an administrator" in r.json()["detail"], r.text
        row = _request_for(admin, temp_user["id"])
        assert row["can_approve"] is False and "you made" in row["cannot_approve"], row
        assert psql(f"SELECT status FROM credential_changes WHERE id='{req_id}'") == "held"
        ok = other_client.post(f"/admin/credential-requests/{req_id}/approve")
        assert ok.status_code == 200, ok.text
    refusals = admin.get("/audit/log", params={"action": "credential_change_approval_refused",
                                               "limit": 500}).json()
    mine = [a for a in refusals if (a.get("details") or {}).get("change_id") == req_id]
    assert [a["details"]["reason"] for a in mine] == ["maker"], mine


def test_who_made_or_approved_a_change_to_the_account_cannot_approve_the_next(admin, temp_user, other_admin,
                                                                             third_admin):
    # Rule 2 on its own: the module's independent administrator makes the first change, the session's
    # administrator asks for the second; the first may not approve it, a third may. Having approved it,
    # the third may not approve a further change either.
    other, other_client = other_admin
    third, third_client = third_admin
    assert other_client.patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD}).status_code == 200
    held = admin.post(f"/users/{temp_user['id']}/reset-link")
    assert held.status_code == 202, held.text
    req_id = held.json()["request"]["id"]
    r = other_client.post(f"/admin/credential-requests/{req_id}/approve")
    assert r.status_code == 403, r.text
    assert "You changed this account's sign-in details" in r.json()["detail"], r.text
    assert "you changed this account" in _request_for(other_client, temp_user["id"])["cannot_approve"]
    assert third_client.post(f"/admin/credential-requests/{req_id}/approve").status_code == 200

    # A third change: the session's administrator asked for the second and the third administrator
    # approved it, so neither may approve this one. With no other administrator on the stack who may,
    # it is refused and the refusal names them; with one, it waits and the third is refused.
    held = other_client.post(f"/users/{temp_user['id']}/ssh-keys", json={"name": "k", "public_key": _ssh_key()})
    if held.status_code == 409:
        detail = held.json()["detail"]
        assert third["_username"] in detail and "sign-in details in the last 14 days" in detail, detail
        return
    assert held.status_code == 202, held.text
    req_id = held.json()["request"]["id"]
    r = third_client.post(f"/admin/credential-requests/{req_id}/approve")
    assert r.status_code == 403 and "or approved a change to them" in r.json()["detail"], r.text
    r = admin.post(f"/admin/credential-requests/{req_id}/approve")
    assert r.status_code == 403 and "or approved a change to them" in r.json()["detail"], r.text
    assert admin.post(f"/admin/credential-requests/{req_id}/deny").status_code == 200


def test_an_approver_must_have_been_an_administrator_for_fourteen_days(admin, temp_user, other_admin):
    # Rule 4: an administrator independent in every other way, but made one 13 days before the request,
    # may not approve it; 15 days before, it may.
    other, other_client = other_admin
    assert other_client.patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD}).status_code == 200
    with second_admin(admin, independent=True) as (recent, recent_client):
        make_independent(recent["id"], days=13)
        held = other_client.post(f"/users/{temp_user['id']}/reset-link")
        assert held.status_code == 202, held.text
        req_id = held.json()["request"]["id"]
        r = recent_client.post(f"/admin/credential-requests/{req_id}/approve")
        assert r.status_code == 403 and "for less than 14 days" in r.json()["detail"], r.text
        row = _request_for(recent_client, temp_user["id"])
        assert row["can_approve"] is False and "less than 14 days" in row["cannot_approve"], row
        make_independent(recent["id"], days=15)
        assert recent_client.post(f"/admin/credential-requests/{req_id}/approve").status_code == 200


def test_an_administrator_made_after_the_request_cannot_approve_it(admin, temp_user, other_admin):
    # Made by someone other than the one who asked, but after the request: still refused.
    other, other_client = other_admin
    assert other_client.patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD}).status_code == 200
    held = other_client.post(f"/users/{temp_user['id']}/reset-link")
    assert held.status_code == 202, held.text
    req_id = held.json()["request"]["id"]
    promoted = admin.create_user(role="user")
    try:
        assert admin.patch(f"/users/{promoted['id']}", json={"role": "admin"}).status_code == 200
        late = signed_in(promoted)
        r = late.post(f"/admin/credential-requests/{req_id}/approve")
        assert r.status_code == 403 and "after this request was made" in r.json()["detail"], r.text
        row = next(q for q in _requests(late) if q["id"] == req_id)
        assert row["can_approve"] is False and "after it was asked for" in row["cannot_approve"]
        # Demoted, the record goes; the rule has nothing left to read for that account.
        assert admin.patch(f"/users/{promoted['id']}", json={"role": "user"}).status_code == 200
        assert psql(f"SELECT count(*) FROM admin_grants WHERE user_id='{promoted['id']}'") == "0"
    finally:
        admin.delete_user(promoted["id"])
    assert admin.post(f"/admin/credential-requests/{req_id}/deny").status_code == 200


@pytest.mark.parametrize("route", ["post_users", "patch_users", "put_user_management", "patch_role"])
def test_every_route_that_makes_an_administrator_records_who_did(admin, route):
    me = admin.get("/users/me").json()
    if route == "post_users":
        account = admin.create_user(role="admin")
    else:
        account = admin.create_user(role="user")
        uid = account["id"]
        r = {"patch_users": lambda: admin.patch(f"/users/{uid}", json={"role": "admin"}),
             "put_user_management": lambda: admin.put(f"/api/user-management/users/{uid}", json={"role": "admin"}),
             "patch_role": lambda: admin.patch(f"/api/user-management/users/{uid}/role",
                                               json={"new_role": "admin"})}[route]()
        assert r.status_code == 200, r.text
    try:
        row = psql(f"SELECT granted_by_name || '|' || (granted_by_id::text) || '|' || lineage::text "
                   f"FROM admin_grants WHERE user_id='{account['id']}'")
        name, by_id, lineage = row.split("|", 2)
        assert (name, by_id) == (me["username"], me["id"])
        assert me["id"] in lineage
        if route != "post_users":
            back = admin.patch(f"/api/user-management/users/{account['id']}/role", json={"new_role": "user"})
            assert back.status_code == 200, back.text
            assert psql(f"SELECT count(*) FROM admin_grants WHERE user_id='{account['id']}'") == "0"
    finally:
        admin.delete_user(account["id"])


# --------------------------------------------------------------------------- the asker gone, the account's own

def _lock_every_other_administrator(admin, keep):
    """Lock every active administrator but the session's and those in ``keep``; returns their ids, for
    _unlock. Locking one withdraws the requests it had open."""
    me = admin.get("/users/me").json()["id"]
    others = [u for u in admin.get("/users").json()
              if u["role"] == "admin" and u["is_active"] and not u["is_locked"] and u["id"] != me
              and u["id"] not in keep]
    locked = []
    for u in others:
        assert admin.patch(f"/users/{u['id']}", json={"is_locked": True}).status_code == 200
        locked.append(u["id"])
    return locked


def test_with_two_administrators_one_cannot_take_the_other_over(admin, other_admin, third_admin):
    """Only the session's administrator and bob can act. The session's administrator makes an
    administrator account, which changes bob's password and asks for a reset link for him. Bob could
    have approved that before (a change to his own account), so it was held, and demoting the account
    that asked then let its maker approve it. A change is never approved by the person it is for: with
    nobody else, the second change is refused and only the host tool can make it."""
    me = admin.get("/users/me").json()
    with second_admin(admin, independent=True) as (bob, _bob_client):
        locked = _lock_every_other_administrator(admin, keep={bob["id"]})
        try:
            with second_admin(admin) as (puppet, puppet_client):
                r = puppet_client.patch(f"/users/{bob['id']}", json={"password": NEW_PASSWORD})
                assert r.status_code == 200, r.text
                r = puppet_client.post(f"/users/{bob['id']}/reset-link")
                assert r.status_code == 409, r.text
                detail = r.json()["detail"]
                assert f"{bob['_username']} may not approve a change to their own account" in detail, detail
                assert f"{me['username']} made you an administrator" in detail, detail
                assert "dockvault.py accounts" in detail
                r = admin.post(f"/users/{bob['id']}/reset-link")
                assert r.status_code == 409, r.text
                assert "may not approve a change to their own account" in r.json()["detail"]
            assert psql(f"SELECT count(*) FROM credential_changes WHERE target_user_id='{bob['id']}' "
                        "AND status='held'") == "0", "nothing is held for bob to be taken over through"
        finally:
            for uid in locked:
                admin.patch(f"/users/{uid}", json={"is_locked": False})
            for account, client in (other_admin, third_admin):
                client.login(account["_username"], account["_password"])


LEAVING = {
    "patch_demote": lambda c, uid: c.patch(f"/users/{uid}", json={"role": "user"}),
    "patch_deactivate": lambda c, uid: c.patch(f"/users/{uid}", json={"is_active": False}),
    "patch_lock": lambda c, uid: c.patch(f"/users/{uid}", json={"is_locked": True}),
    "delete": lambda c, uid: c.post(f"/users/{uid}/delete"),
    "put_demote": lambda c, uid: c.put(f"/api/user-management/users/{uid}", json={"role": "user"}),
    "role_demote": lambda c, uid: c.patch(f"/api/user-management/users/{uid}/role", json={"new_role": "user"}),
    "toggle_active": lambda c, uid: c.post(f"/api/user-management/users/{uid}/toggle-active"),
    "toggle_locked": lambda c, uid: c.post(f"/api/user-management/users/{uid}/toggle-locked"),
}
BECAUSE = {"patch_demote": "demoted", "put_demote": "demoted", "role_demote": "demoted",
           "patch_deactivate": "deactivated", "toggle_active": "deactivated",
           "patch_lock": "locked", "toggle_locked": "locked", "delete": "deleted"}


@pytest.mark.parametrize("route", sorted(LEAVING))
def test_an_administrator_who_leaves_has_their_open_requests_withdrawn(admin, temp_user, route):
    """An administrator makes the first change to an account and asks for the second, which is held. They
    are then demoted, deactivated, locked or deleted, through every route that can: the request is
    withdrawn at once and audited, the user and the administrator who could approve it are told, and it
    can no longer be approved."""
    me = admin.get("/users/me").json()
    with second_admin(admin, independent=True) as (asker, asker_client):
        assert asker_client.patch(f"/users/{temp_user['id']}", json={"password": NEW_PASSWORD}).status_code == 200
        assert asker_client.post(f"/users/{temp_user['id']}/reset-link").status_code == 202
        req = _request_for(admin, temp_user["id"])
        assert req["can_approve"] is True, req

        r = LEAVING[route](admin, asker["id"])
        assert r.status_code == 200, r.text

        assert psql(f"SELECT status || '|' || decided_by_name FROM credential_changes "
                    f"WHERE id='{req['id']}'") == f"withdrawn|{me['username']}"
        assert not [x for x in _requests(admin) if x["id"] == req["id"]], "it leaves the list"
        refused = admin.post(f"/admin/credential-requests/{req['id']}/approve")
        assert refused.status_code == 409 and "withdrawn" in refused.json()["detail"], refused.text

        rows = admin.get("/audit/log", params={"action": "credential_change_withdrawn", "limit": 500}).json()
        mine = [a for a in rows if a["resource_id"] == temp_user["id"]]
        assert mine and mine[0]["username"] == me["username"], mine
        assert mine[0]["details"]["withdrawn_because"] == BECAUSE[route], mine[0]["details"]
        told = [n for n in notifications(admin, "credential_change_withdrawn")
                if asker["_username"] in (n["body"] or "") and temp_user["_username"] in (n["body"] or "")]
        assert told and "nothing left to approve" in told[0]["body"], told
        user_notes = notifications(signed_in({**temp_user, "_password": NEW_PASSWORD}),
                                   "credential_change_withdrawn")
        assert user_notes and "the administrator who asked" in user_notes[0]["body"], user_notes
