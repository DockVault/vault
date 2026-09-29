"""A change of role resets an account's permissions to the new role's defaults, on a running stack.

An account created as an administrator holds the administrator's defaults as stored permission rows, the
permission to manage users among them, and no route that demoted it removed them: a former administrator
could still make password reset links for other people's accounts, and one made before the demotion kept
working. Each route that changes a role now resets the permissions in the same transaction, records what
was removed, and names it in the notice of the role change. test_role_change_permissions.py holds the rule
offline.
"""
import json

import pytest
import requests

from conftest import ApiClient, BASE_URL
from _account_change_helpers import psql

pytestmark = pytest.mark.integration

UNKNOWN = "This reset link is invalid or has expired."
TAKEN = "Former-Admin-Pw0rd!7"
ADMIN_ONLY = ["USER_MANAGE", "USER_VIEW"]


def _demote_patch_users(admin, user_id, role):
    return admin.patch(f"/users/{user_id}", json={"role": role})


def _demote_put_user_management(admin, user_id, role):
    return admin.put(f"/api/user-management/users/{user_id}", json={"role": role})


def _demote_patch_role(admin, user_id, role):
    return admin.patch(f"/api/user-management/users/{user_id}/role", json={"new_role": role})


ROUTES = {
    "PATCH /users/{id}": _demote_patch_users,
    "PUT /api/user-management/users/{id}": _demote_put_user_management,
    "PATCH /api/user-management/users/{id}/role": _demote_patch_role,
}


@pytest.fixture
def accounts(admin):
    """Accounts made for one test, deleted afterwards whatever role they end with."""
    made = []

    def make(role="user"):
        account = admin.create_user(role=role)
        made.append(account["id"])
        return account
    try:
        yield make
    finally:
        for user_id in made:
            admin.delete_user(user_id)


def _signed_in(account):
    client = ApiClient(BASE_URL)
    client.login(account["_username"], account["_password"])
    return client


def _change_role(admin, route, user_id, role):
    r = ROUTES[route](admin, user_id, role)
    assert r.status_code == 200, r.text
    assert admin.get(f"/users/{user_id}").json()["role"] == role


def _groups(user_id):
    rows = psql(f"SELECT endpoint_group FROM user_endpoint_permissions WHERE user_id = '{user_id}' "
                "AND endpoint_group IN ('USER_MANAGE', 'USER_VIEW') ORDER BY endpoint_group")
    return rows.split("\n") if rows else []


def _link(client, user_id):
    r = client.post(f"/users/{user_id}/reset-link")
    assert r.status_code == 200 and "?reset=" in r.json()["reset_link"], r.text
    return r.json()["reset_link"].split("?reset=")[1]


def _use(token):
    return requests.post(f"{BASE_URL}/reset/{token}", json={"new_password": TAKEN}, timeout=20)


def _signs_in(username, password):
    try:
        ApiClient(BASE_URL).login(username, password)
        return True
    except requests.HTTPError:
        return False


def _reset_rows(user_id):
    rows = psql("SELECT details->>'removed' FROM audit_logs WHERE action = 'permissions_reset_for_role' "
                f"AND resource_id = '{user_id}' ORDER BY timestamp")
    return rows.split("\n") if rows else []


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_a_demoted_administrator_loses_the_permission_to_manage_users(admin, accounts, route):
    bob = accounts("admin")
    dave = accounts("user")
    assert _groups(bob["id"]) == ADMIN_ONLY, "created as an administrator: the defaults are stored rows"
    token = _link(_signed_in(bob), dave["id"])        # made while bob was an administrator

    _change_role(admin, route, bob["id"], "user")

    assert _groups(bob["id"]) == [], "the administrator's defaults outlived the demotion"
    assert _reset_rows(bob["id"]) == ['["USER_MANAGE", "USER_VIEW"]']
    # The former administrator can make no reset link now, for anyone...
    erin = accounts("user")
    r = _signed_in(bob).post(f"/users/{erin['id']}/reset-link")
    assert r.status_code == 403, r.text
    # ...and the one made before the demotion is refused when used, exactly as an unknown one.
    use = _use(token)
    assert (use.status_code, use.json().get("detail")) == (404, UNKNOWN), use.text
    why = psql("SELECT details->>'reason' FROM audit_logs WHERE action = 'password_reset_link_refused' "
               f"AND resource_id = '{dave['id']}'")
    assert why == "maker_without_permission", why
    assert not _signs_in(dave["_username"], TAKEN)
    assert _signs_in(dave["_username"], dave["_password"])
    # The account was told, with the permissions named.
    body = psql("SELECT body FROM notifications WHERE user_id = '{0}' AND title = 'Your role was changed'"
                .format(bob["id"]))
    assert "Manage Users" in body and "View Users" in body, body


def _held(user_id):
    rows = psql(f"SELECT endpoint_group FROM user_endpoint_permissions WHERE user_id = '{user_id}' "
                "ORDER BY endpoint_group")
    return rows.split("\n") if rows else []


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_an_administrator_made_an_external_user_keeps_no_permission(admin, accounts, route):
    # The external role has no permissions of its own. Kept, the permission to manage users would reach
    # every other external account, whose role is not above the former administrator's.
    bob = accounts("admin")
    xena = accounts("external")
    held = _held(bob["id"])
    assert set(ADMIN_ONLY) <= set(held), held
    token = _link(_signed_in(bob), xena["id"])        # made while bob was an administrator

    _change_role(admin, route, bob["id"], "external")

    assert _held(bob["id"]) == [], "an external user holds no permission nobody granted them"
    (removed,) = _reset_rows(bob["id"])
    assert json.loads(removed) == held
    # No reset link for another external account now...
    yves = accounts("external")
    r = _signed_in(bob).post(f"/users/{yves['id']}/reset-link")
    assert r.status_code == 403, r.text
    # ...and the one made before is refused when used, because its maker may no longer manage users.
    use = _use(token)
    assert (use.status_code, use.json().get("detail")) == (404, UNKNOWN), use.text
    why = psql("SELECT details->>'reason' FROM audit_logs WHERE action = 'password_reset_link_refused' "
               f"AND resource_id = '{xena['id']}'")
    assert why == "maker_without_permission", why
    assert not _signs_in(xena["_username"], TAKEN)


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_a_promotion_and_a_demotion_come_back_to_a_users_permissions(admin, accounts, route):
    carol = accounts("user")
    assert _groups(carol["id"]) == []
    _change_role(admin, route, carol["id"], "admin")
    assert _groups(carol["id"]) == ADMIN_ONLY
    _change_role(admin, route, carol["id"], "user")
    assert _groups(carol["id"]) == []
    assert _reset_rows(carol["id"]) == ["[]", '["USER_MANAGE", "USER_VIEW"]']
    dave = accounts("user")
    r = _signed_in(carol).post(f"/users/{dave['id']}/reset-link")
    assert r.status_code == 403, r.text


@pytest.mark.parametrize("route", sorted(ROUTES))
def test_granting_the_permission_again_after_the_demotion_works(admin, accounts, route):
    bob = accounts("admin")
    _change_role(admin, route, bob["id"], "user")
    r = admin.post(f"/permissions/users/{bob['id']}/grant", json={"endpoint_group": "USER_MANAGE"})
    assert r.status_code == 200, r.text
    erin = accounts("user")
    token = _link(_signed_in(bob), erin["id"])
    use = _use(token)
    assert use.status_code == 200 and use.json() == {"ok": True}, use.text
    assert _signs_in(erin["_username"], TAKEN)
    # A deliberate grant outlasts a later change of role.
    _change_role(admin, route, bob["id"], "admin")
    _change_role(admin, route, bob["id"], "user")
    assert _groups(bob["id"]) == ADMIN_ONLY
