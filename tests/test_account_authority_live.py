"""Nobody who is not an administrator changes an administrator's account, on a running stack.

A user given the permission to manage users could make a password reset link for an administrator,
copy it, and take the administrator's account. Every route that changes someone else's account is
driven here as such a user: against an administrator it is refused (the two reset-link routes with the
new refusal, recorded; the others as they always were), and against an ordinary user each still answers
as it did before. test_account_authority.py holds the rule and the route sweep offline.
"""
import uuid

import pytest

from conftest import ApiClient, BASE_URL
from _account_change_helpers import psql

pytestmark = pytest.mark.integration

REFUSED = "Only an administrator can change an administrator's account."
SECRET = "Delegate-Pw0rd!456"


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
def accounts(admin):
    """An administrator and an ordinary user, each with an email address. Deleted afterwards."""
    made = [admin.create_user(role="admin"), admin.create_user(role="user")]
    try:
        yield made
    finally:
        for account in made:
            admin.delete_user(account["id"])


# (name, method, path, body). {id} is the account acted on.
ROUTES = [
    ("reset link, copied", "POST", "/users/{id}/reset-link", None),
    ("reset link, emailed", "POST", "/users/{id}/send-reset-link", None),
    ("password", "PATCH", "/users/{id}", {"password": SECRET}),
    ("email", "PATCH", "/users/{id}", {"email": "taken-over@example.com"}),
    ("role", "PATCH", "/users/{id}", {"role": "user"}),
    ("lock", "PATCH", "/users/{id}", {"is_locked": True}),
    ("unlock and clear sign-in pauses", "PATCH", "/users/{id}", {"is_locked": False}),
    ("deactivate", "PATCH", "/users/{id}", {"is_active": False}),
    ("SSH key added", "POST", "/users/{id}/ssh-keys",
     {"name": "k", "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"}),
    ("SSH key removed", "DELETE", "/users/{id}/ssh-keys/" + str(uuid.uuid4()), None),
    ("second factor reset", "POST", "/users/{id}/second-factor/reset", None),
    ("sessions ended", "POST", "/users/{id}/terminate-sessions", None),
    ("account edited", "PUT", "/api/user-management/users/{id}", {"role": "user", "is_active": False}),
    ("active toggled", "POST", "/api/user-management/users/{id}/toggle-active", None),
    ("locked toggled", "POST", "/api/user-management/users/{id}/toggle-locked", None),
    ("role changed", "PATCH", "/api/user-management/users/{id}/role", {"new_role": "user"}),
    ("temporary credential", "POST", "/api/user-management/users/{id}/temp-credentials", {}),
    ("permission granted", "POST", "/permissions/users/{id}/grant", {"endpoint_group": "USER_MANAGE"}),
    ("permission revoked", "DELETE", "/permissions/users/{id}/revoke/USER_VIEW", None),
    ("deleted", "POST", "/users/{id}/delete", None),
]
RESET_LINKS = {"reset link, copied", "reset link, emailed"}


def _call(client, method, path, body):
    kw = {"json": body} if body is not None else {}
    return getattr(client, method.lower())(path, **kw)


def _refusals(target_id):
    return int(psql("SELECT count(*) FROM audit_logs WHERE action = 'account_change_refused_role' "
                    f"AND resource_id = '{target_id}'"))


def test_a_user_who_manages_users_changes_no_administrator_account(admin, delegate, accounts):
    manager, as_manager = delegate
    ada, _carol = accounts
    for name, method, path, body in ROUTES:
        before = _refusals(ada["id"])
        r = _call(as_manager, method, path.format(id=ada["id"]), body)
        assert r.status_code == 403, (name, r.status_code, r.text[:300])
        if name in RESET_LINKS:
            assert r.json()["detail"] == REFUSED, (name, r.text)
            assert _refusals(ada["id"]) == before + 1, f"{name}: the refusal was not recorded"
    row = psql("SELECT user_id::text || '|' || (details->>'change') || '|' || (details->>'reason') "
               "FROM audit_logs WHERE action = 'account_change_refused_role' "
               f"AND resource_id = '{ada['id']}' ORDER BY timestamp DESC LIMIT 1")
    assert row == f"{manager['id']}|reset_link|administrator", row

    # The administrator's account is as it was: no reset link waits for it, it signs in with its own
    # password, and it is still an active, unlocked administrator.
    assert psql(f"SELECT count(*) FROM password_reset_tokens WHERE user_id = '{ada['id']}'") == "0"
    ApiClient(BASE_URL).login(ada["_username"], ada["_password"])
    now = admin.get(f"/users/{ada['id']}").json()
    assert (now["role"], now["is_active"], now["is_locked"], now["email"]) == (
        "admin", True, False, ada["email"]), now


def test_a_user_who_manages_users_still_answers_as_before_for_an_ordinary_user(admin, delegate, accounts):
    _manager, as_manager = delegate
    _ada, carol = accounts
    for name, method, path, body in ROUTES:
        if name in RESET_LINKS:
            continue
        r = _call(as_manager, method, path.format(id=carol["id"]), body)
        assert r.status_code == 403, (name, r.status_code, r.text[:300])
        assert r.json().get("detail") != REFUSED, (name, r.text)
    assert _refusals(carol["id"]) == 0


@pytest.mark.parametrize("name", sorted(RESET_LINKS))
def test_a_user_who_manages_users_still_makes_a_reset_link_for_an_ordinary_user(admin, delegate, name):
    # Each on an account of its own, so neither is the account's second change within 14 days.
    _manager, as_manager = delegate
    (_n, method, path, body), = [r for r in ROUTES if r[0] == name]
    dave = admin.create_user(role="user")
    try:
        r = _call(as_manager, method, path.format(id=dave["id"]), body)
        if name == "reset link, copied":
            assert r.status_code == 200 and "?reset=" in r.json()["reset_link"], r.text
        else:
            # Sent, or refused for this deployment's email set-up, as before: either way past the rule.
            assert r.status_code == 200 or (
                r.status_code == 400 and "Email is not configured" in r.json()["detail"]), r.text
        assert _refusals(dave["id"]) == 0
    finally:
        admin.delete_user(dave["id"])


def test_an_administrator_still_makes_a_reset_link_for_another_administrator(admin, accounts):
    ada, _carol = accounts
    r = admin.post(f"/users/{ada['id']}/reset-link")
    assert r.status_code == 200 and "?reset=" in r.json()["reset_link"], r.text
