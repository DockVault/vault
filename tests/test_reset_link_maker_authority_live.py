"""A reset link someone made for another account is judged again when it is used, on a running stack.

The verification proved it: a user given the permission to manage users made a reset link for an
ordinary user, an administrator then promoted that user, and the link still set the new administrator's
password, so its maker signed in as an administrator. Now a promotion revokes such a link, and using a
link another account made judges its maker again, as the maker and the account stand then; a refused
link answers exactly as an unknown one. test_reset_link_maker_authority.py holds the rule offline.
"""
import pytest
import requests

from conftest import ApiClient, BASE_URL
from _account_change_helpers import psql

pytestmark = pytest.mark.integration

UNKNOWN = "This reset link is invalid or has expired."
TAKEN = "Delegate-Owns-Pw0rd!7"


@pytest.fixture
def delegate(admin):
    """A user holding the permission to manage users, signed in."""
    account = admin.create_user(role="user")
    r = admin.post(f"/permissions/users/{account['id']}/grant", json={"endpoint_group": "USER_MANAGE"})
    assert r.status_code == 200, r.text
    client = ApiClient(BASE_URL)
    client.login(account["_username"], account["_password"])
    try:
        yield account, client
    finally:
        admin.delete_user(account["id"])


@pytest.fixture
def dave(admin):
    """An ordinary user, deleted afterwards (whatever role it ends with)."""
    account = admin.create_user(role="user")
    try:
        yield account
    finally:
        admin.delete_user(account["id"])


def _link(client, user_id):
    r = client.post(f"/users/{user_id}/reset-link")
    assert r.status_code == 200 and "?reset=" in r.json()["reset_link"], r.text
    return r.json()["reset_link"].split("?reset=")[1]


def _use(token):
    return requests.post(f"{BASE_URL}/reset/{token}", json={"new_password": TAKEN}, timeout=20)


def _look_up(token):
    return requests.get(f"{BASE_URL}/reset/{token}", timeout=20)


def _signs_in(username, password):
    try:
        ApiClient(BASE_URL).login(username, password)
        return True
    except requests.HTTPError:
        return False


def _open_links(user_id):
    return int(psql(f"SELECT count(*) FROM password_reset_tokens WHERE user_id = '{user_id}' "
                    "AND consumed_at IS NULL"))


def _reasons(action, user_id):
    rows = psql(f"SELECT details->>'reason' FROM audit_logs WHERE action = '{action}' "
                f"AND resource_id = '{user_id}' ORDER BY timestamp")
    return rows.split("\n") if rows else []


def test_a_delegates_link_made_before_a_promotion_does_not_work_after_it(admin, delegate, dave):
    # The verified sequence, through the routes: link, promote, use.
    manager, as_manager = delegate
    token = _link(as_manager, dave["id"])
    assert psql(f"SELECT made_by_other FROM password_reset_tokens WHERE user_id = '{dave['id']}'") == "t"
    r = admin.patch(f"/users/{dave['id']}", json={"role": "admin"})
    assert r.status_code == 200 and admin.get(f"/users/{dave['id']}").json()["role"] == "admin", r.text

    use = _use(token)
    assert (use.status_code, use.json().get("detail")) == (404, UNKNOWN), use.text
    assert not _signs_in(dave["_username"], TAKEN), "the delegate signed in as the new administrator"
    assert _signs_in(dave["_username"], dave["_password"]), "the administrator's own password stopped working"
    # The promotion revoked it, and said so.
    assert _open_links(dave["id"]) == 0
    assert _reasons("password_reset_link_revoked", dave["id"]) == ["administrator"]
    made_by = psql("SELECT details->>'made_by' FROM audit_logs WHERE action = 'password_reset_link_revoked' "
                   f"AND resource_id = '{dave['id']}'")
    assert made_by == manager["_username"], made_by


def test_a_link_whose_account_was_promoted_behind_the_routes_is_refused_when_used(admin, delegate, dave):
    # The promotion is made in the database, so no route revoked the link: the check at use refuses it,
    # at the lookup that shows the form, answering as for an unknown link, and records why.
    _manager, as_manager = delegate
    token = _link(as_manager, dave["id"])
    assert _look_up(token).json() == {"username": dave["_username"]}, "the form is shown while it stands"
    psql(f"UPDATE users SET role = 'ADMIN' WHERE id = '{dave['id']}'")

    look = _look_up(token)
    assert (look.status_code, look.json().get("detail")) == (404, UNKNOWN), look.text
    assert _reasons("password_reset_link_refused", dave["id"]) == ["administrator"]
    assert _open_links(dave["id"]) == 0, "the refused link was left open"
    use = _use(token)
    assert (use.status_code, use.json().get("detail")) == (404, UNKNOWN), use.text
    assert not _signs_in(dave["_username"], TAKEN)


def test_a_link_is_refused_once_its_maker_loses_the_permission(admin, delegate, dave):
    manager, as_manager = delegate
    token = _link(as_manager, dave["id"])
    r = admin.delete(f"/permissions/users/{manager['id']}/revoke/USER_MANAGE")
    assert r.status_code == 200, r.text

    use = _use(token)
    assert (use.status_code, use.json().get("detail")) == (404, UNKNOWN), use.text
    assert _reasons("password_reset_link_refused", dave["id"]) == ["maker_without_permission"]
    assert _signs_in(dave["_username"], dave["_password"])


def test_a_delegates_link_still_works_while_nothing_changed(delegate, dave):
    _manager, as_manager = delegate
    token = _link(as_manager, dave["id"])
    assert _look_up(token).json() == {"username": dave["_username"]}
    r = _use(token)
    assert r.status_code == 200 and r.json() == {"ok": True}, r.text
    assert _signs_in(dave["_username"], TAKEN)
    assert _reasons("password_reset_link_refused", dave["id"]) == []
