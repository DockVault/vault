"""Whose word an account's address is, against a running vault (app/core/email_confirmation.py).

The Users list says for each account whether the vault itself confirmed its address: an administrator or an
invitation set it. An address the person wrote (at self sign-up, at an invitation that carried none, or by changing
their own with the current password) is their claim and reads unconfirmed, and any change of an address clears the
mark. Only a confirmed address links an account to a single sign-on provider by email, so this is the vault's half
of that rule, walked through every way an address reaches an account.
"""
import pytest

from conftest import ApiClient, unique
from test_invite_accept import STRONG_PW, _mint, invites_on   # noqa: F401  (the fixture is used by name)

pytestmark = pytest.mark.integration


def _row(admin, username):
    return next(u for u in admin.get("/users").json() if u["username"] == username)


def _confirmed(admin, username):
    row = _row(admin, username)
    return row["email_confirmed"], row["email"]


def test_an_address_an_administrator_wrote_is_confirmed_and_one_the_person_wrote_is_not(admin):
    made = admin.create_user(role="user")
    bare = admin.create_user(email=None)
    try:
        name = made["_username"]
        assert _confirmed(admin, name) == (True, f"{name}@example.com")
        assert _confirmed(admin, bare["_username"]) == (False, None)          # no address: nothing to confirm
        # The person changes it with their own password: their claim, whatever it says.
        person = ApiClient()
        person.login(name, made["_password"])
        moved = unique("moved") + "@example.com"
        r = person.patch("/users/me", json={"email": moved, "current_password": made["_password"]})
        if r.status_code == 202 or (r.status_code == 200 and r.json().get("email") != moved):
            pytest.skip("this stack asks for an emailed code before an address changes")
        assert r.status_code == 200, r.text
        assert _confirmed(admin, name) == (False, moved)
        # The same address in other letters is the same address: nothing changes either way.
        r = person.patch("/users/me", json={"email": moved.upper(), "current_password": made["_password"]})
        assert r.status_code in (200, 400), r.text
        assert _confirmed(admin, name)[0] is False
        # An administrator sets it: the vault's own word again.
        set_by_admin = unique("set") + "@example.com"
        r = admin.patch(f"/users/{made['id']}", json={"email": set_by_admin})
        assert r.status_code == 200, r.text
        assert _confirmed(admin, name) == (True, set_by_admin)
        # And the person changing it once more clears it once more.
        again = unique("again") + "@example.com"
        r = person.patch("/users/me", json={"email": again, "current_password": made["_password"]})
        assert r.status_code == 200, r.text
        assert _confirmed(admin, name) == (False, again)
    finally:
        admin.delete_user(made["id"])
        admin.delete_user(bare["id"])


def test_an_invitation_confirms_the_address_it_carried_and_not_one_typed_at_acceptance(admin, invites_on):
    carried, typed = unique("carried"), unique("typed")
    try:
        inv = _mint(admin, username=carried, role="user", email=f"{carried}@example.com")
        r = ApiClient().post(f"/invites/{inv['token']}/accept", json={"password": STRONG_PW})
        assert r.status_code == 200, r.text
        assert _confirmed(admin, carried) == (True, f"{carried}@example.com")
        inv = _mint(admin, username=typed, role="user")
        r = ApiClient().post(f"/invites/{inv['token']}/accept",
                             json={"password": STRONG_PW, "email": f"{typed}@example.com"})
        assert r.status_code == 200, r.text
        assert _confirmed(admin, typed) == (False, f"{typed}@example.com")
    finally:
        for name in (carried, typed):
            for u in admin.get("/users").json():
                if u["username"] == name:
                    admin.delete_user(u["id"])


def test_an_address_typed_at_self_sign_up_is_not_confirmed(admin):
    before = admin.get("/settings").json()
    keys = ("signup_enabled", "email_requirement", "login_identifier", "signup_email_domain_mode", "signup_email_domains")
    name = unique("signed")
    r = admin.put("/settings", json={"signup_enabled": True, "email_requirement": "optional",
                                     "login_identifier": "username", "signup_email_domain_mode": "off",
                                     "signup_email_domains": []})
    assert r.status_code == 200, r.text
    try:
        r = ApiClient().post("/auth/signup", json={"username": name, "password": STRONG_PW, "email": f"{name}@example.com"})
        assert r.status_code in (200, 201), r.text
        assert _confirmed(admin, name) == (False, f"{name}@example.com")
    finally:
        admin.put("/settings", json={k: before.get(k) for k in keys})
        for u in admin.get("/users").json():
            if u["username"] == name:
                admin.delete_user(u["id"])
