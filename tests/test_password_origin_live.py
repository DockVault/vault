"""Live: a password someone else set is recorded, taken back when its account is made an administrator,
and keeps an administrator from approving held changes until they set their own.

A user who manages users makes a reset link for U and sets U's password with it; an administrator
promotes U: the password stops working, U's session ends, a reset link reaches U's own inbox (with a
mail sink), and U sets their own. Without email the promoting administrator gets the link to hand over.
Each promotion route does it. An administrator whose password another administrator chose may not
approve a held change until they change it. At start, accounts from before the columns are marked from
the audit log. test_password_origin.py covers the rules offline.
"""
import re
import subprocess
import time

import pytest
import requests

from conftest import ApiClient, BASE_URL
from _account_change_helpers import (API, MAILPIT_URL, mail_sink, make_independent, psql, second_admin,
                                     signed_in)

pytestmark = pytest.mark.integration

CHOSEN = "Delegate-Chosen-Pw0rd!7"
OWN = "My-Own-Pass-Pw0rd!8"


def _signs_in(username, password):
    r = requests.post(f"{BASE_URL}/auth/login", json={"username": username, "password": password}, timeout=20)
    return r.status_code == 200


def _mark(user_id):
    """(who set the password, whether someone else did), as the database holds it."""
    by, other = psql(f"SELECT coalesce(password_set_by::text, '-'), password_set_by_other_at IS NOT NULL "
                     f"FROM users WHERE id = '{user_id}'").split("|")
    return (None if by == "-" else by), other == "t"


def _set_own_password(user):
    """The person changes their password themselves, so it is their own; returns a client signed in with it."""
    client = signed_in(user)
    r = client.patch("/users/me", json={"current_password": user["_password"], "new_password": OWN})
    assert r.status_code == 200, r.text
    user["_password"] = OWN
    return signed_in(user)


@pytest.fixture
def delegate(admin):
    """A user holding the permission to manage users, signed in."""
    account = admin.create_user(role="user")
    r = admin.post(f"/permissions/users/{account['id']}/grant", json={"endpoint_group": "USER_MANAGE"})
    assert r.status_code == 200, r.text
    try:
        yield account, signed_in(account)
    finally:
        admin.delete_user(account["id"])


@pytest.fixture
def uma(admin):
    account = admin.create_user(role="user")
    try:
        yield account
    finally:
        admin.delete_user(account["id"])


def _delegate_sets_the_password(delegate_client, user):
    r = delegate_client.post(f"/users/{user['id']}/reset-link")
    assert r.status_code == 200, r.text
    token = r.json()["reset_link"].split("?reset=")[1]
    assert requests.post(f"{BASE_URL}/reset/{token}", json={"new_password": CHOSEN}, timeout=20).status_code == 200
    user["_password"] = CHOSEN


def _reset_link_in_mail(address):
    deadline = time.time() + 20
    while time.time() < deadline:
        found = requests.get(f"{MAILPIT_URL}/api/v1/search", params={"query": f"to:{address}"},
                             timeout=10).json()["messages"]
        for m in found:
            if "Reset your password" in (m.get("Subject") or ""):
                html = requests.get(f"{MAILPIT_URL}/api/v1/message/{m['ID']}", timeout=10).json()["HTML"]
                return html
        time.sleep(0.5)
    return None


def test_a_password_a_delegate_set_is_taken_back_when_its_account_is_made_an_administrator(admin, delegate, uma):
    d_account, d_client = delegate
    assert _mark(uma["id"])[1] is True, "created by an administrator with a password"
    _set_own_password(uma)
    assert _mark(uma["id"]) == (None, False)
    _delegate_sets_the_password(d_client, uma)
    assert _mark(uma["id"]) == (d_account["id"], True)
    u_client = signed_in(uma)
    assert u_client.get("/users/me").status_code == 200

    with mail_sink(admin) as real:
        r = admin.patch(f"/users/{uma['id']}", json={"role": "admin"})
        assert r.status_code == 200, r.text
        taken = r.json()["promotion_password_reset"]
        assert not _signs_in(uma["_username"], CHOSEN), "the password the delegate chose no longer works"
        assert u_client.get("/users/me").status_code == 401, "the session ended"
        row = psql("SELECT details::json ->> 'password_set_by' FROM audit_logs WHERE action = "
                   f"'password_reset_at_promotion' AND resource_id = '{uma['id']}'")
        assert row == d_account["_username"]
        assert _mark(uma["id"]) == (d_account["id"], True), "marked until they set their own"
        if real:
            assert taken == {"emailed": True, "reset_link": None, "expires_in_minutes": None}
            html = _reset_link_in_mail(uma["email"])
            assert html is not None, "no email"
            assert "You were made an administrator" in html
            token = re.search(r"\?reset=([A-Za-z0-9_\-]+)", html).group(1)
        else:
            assert taken["emailed"] is False, taken
            token = taken["reset_link"].split("?reset=")[1]
    assert requests.post(f"{BASE_URL}/reset/{token}", json={"new_password": OWN}, timeout=20).status_code == 200
    assert _signs_in(uma["_username"], OWN)
    assert _mark(uma["id"]) == ((None, False) if real else (psql("SELECT id FROM users WHERE username = 'admin'"), True))


PROMOTE = {
    "PATCH /users/{id}": lambda a, i: a.patch(f"/users/{i}", json={"role": "admin"}),
    "PUT /api/user-management/users/{id}": lambda a, i: a.put(f"/api/user-management/users/{i}", json={"role": "admin"}),
    "PATCH /api/user-management/users/{id}/role": lambda a, i: a.patch(f"/api/user-management/users/{i}/role",
                                                                     json={"new_role": "admin"}),
}


@pytest.mark.parametrize("route", sorted(PROMOTE))
def test_each_promotion_route_takes_back_a_password_an_administrator_chose(admin, uma, route):
    r = PROMOTE[route](admin, uma["id"])
    assert r.status_code == 200, r.text
    taken = r.json()["promotion_password_reset"]
    assert taken is not None and (taken["emailed"] or taken["reset_link"]), taken
    assert not _signs_in(uma["_username"], uma["_password"])


def test_a_promotion_leaves_a_password_of_the_persons_own(admin, uma):
    _set_own_password(uma)
    r = admin.patch(f"/api/user-management/users/{uma['id']}/role", json={"new_role": "admin"})
    assert r.status_code == 200, r.text
    assert r.json()["promotion_password_reset"] is None
    assert _signs_in(uma["_username"], OWN)


def test_an_administrator_holding_a_password_another_chose_may_not_approve(admin, uma):
    with second_admin(admin, independent=True) as (fay, _fay_client), \
            second_admin(admin, independent=True) as (_quinn, _quinn_client):
        # The session's administrator sets fay's password: someone else chose it.
        chosen = "Admin-Chose-For-Fay-9x!"
        assert admin.patch(f"/users/{fay['id']}", json={"password": chosen}).status_code == 200
        fay["_password"] = chosen
        fay_client = signed_in(fay)
        assert _mark(fay["id"])[1] is True
        # The session's administrator makes the first change to uma, and asks for a second: held, since
        # quinn may approve it.
        assert admin.patch(f"/users/{uma['id']}", json={"email": f"{uma['_username']}-a@example.com"}).status_code == 200
        r = admin.post(f"/users/{uma['id']}/reset-link")
        assert r.status_code == 202, r.text
        change_id = r.json()["request"]["id"]
        listed = {q["id"]: q for q in fay_client.get("/admin/credential-requests").json()["requests"]}
        assert listed[change_id]["can_approve"] is False
        assert listed[change_id]["cannot_approve"] == "You cannot approve this: your password was set by someone else."
        refused = fay_client.post(f"/admin/credential-requests/{change_id}/approve")
        assert refused.status_code == 403 and "Your current password was set by someone else" in refused.text
        # Once fay sets her own, she may.
        fay_client = _set_own_password(fay)
        approved = fay_client.post(f"/admin/credential-requests/{change_id}/approve")
        assert approved.status_code == 200, approved.text


def _restart_web():
    r = subprocess.run(["docker", "restart", API], capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        pytest.skip(f"cannot restart the web container: {r.stderr[:200]}")
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            if requests.get(f"{BASE_URL}/health", timeout=5).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    pytest.fail("the web container did not come back")


def test_the_start_marks_existing_accounts_from_the_audit_log(admin, uma, delegate):
    d_account, d_client = delegate
    made = admin.create_user(role="user")                        # an administrator chose its password
    own = admin.create_user(role="user")
    try:
        _set_own_password(own)                                   # then changed it themselves
        _delegate_sets_the_password(d_client, uma)               # a delegate's link, used
        # As on a deployment upgraded from a release without the columns.
        psql("ALTER TABLE users DROP COLUMN password_set_by, DROP COLUMN password_set_by_other_at")
        _restart_web()
        admin.login(*admin._credentials)
        assert _mark(made["id"]) == (psql("SELECT id FROM users WHERE username = 'admin'"), True)
        assert _mark(own["id"]) == (None, False)
        assert _mark(uma["id"]) == (d_account["id"], True)
        # Filled once: what the app records afterwards is not overwritten at the next start.
        psql(f"UPDATE users SET password_set_by = NULL, password_set_by_other_at = NULL WHERE id = '{made['id']}'")
        _restart_web()
        admin.login(*admin._credentials)
        assert _mark(made["id"]) == (None, False)
    finally:
        for account in (made, own):
            admin.delete_user(account["id"])
