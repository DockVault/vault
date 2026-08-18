"""Changing your own password requires proving you know it.

`PATCH /users/me` demands the current password before a password or email change, and its
docstring says why: so a hijacked live session cannot take the account over. The sibling route
`PATCH /users/{user_id}` reached the same field with **no proof at all**, and admitted the caller
on `is_self` — so an attacker holding a stolen session but not the password could simply address
the account by id instead of by "me".

Found by review and reproduced against a live instance before being fixed. The two directions are
asserted separately because they are different acts: changing your own password is a self-service
change that must be re-proved, while an admin setting someone else's is a reset performed by a
party already trusted with the account, where no password of the target's exists to re-prove.
"""
from __future__ import annotations

from conftest import ApiClient


def test_you_cannot_change_your_own_password_without_proving_the_current_one(admin, admin_creds):
    """The bypass itself. The caller has a valid session and supplies no password."""
    me = admin.get("/users/me")
    assert me.status_code == 200, me.text
    my_id = me.json()["id"]

    refused = admin.patch(f"/users/{my_id}", json={"password": "Not-My-Password-1!"})
    assert refused.status_code == 400, (
        f"a session alone changed the account's own password: {refused.status_code} "
        f"{refused.text[:200]}")
    assert "current password" in refused.text.lower(), refused.text

    # The account still works with the original credential — the strongest form of the assertion,
    # since a 400 that had nonetheless written the hash would be worse than the bypass.
    check = ApiClient()
    check.login(admin_creds["username"], admin_creds["password"])
    assert check.get("/users/me").status_code == 200, (
        "the password changed despite the refusal")


def test_the_self_service_route_still_works_with_the_current_password(admin):
    """The control. If this stopped working, the fix would have removed the ability rather than
    the bypass, and the test above would pass for the wrong reason."""
    user = admin.create_user(role="user")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    try:
        new = "Fresh-Passphrase-9!"
        changed = client.patch("/users/me", json={
            "current_password": user["_password"], "new_password": new,
        })
        assert changed.status_code == 200, changed.text

        after = ApiClient()
        after.login(user["_username"], new)
        assert after.get("/users/me").status_code == 200
    finally:
        admin.delete_user(user["id"])


def test_an_admin_may_still_reset_someone_elses_password(admin):
    """Not collateral damage: a reset by a party already trusted with the account is a different
    act from changing your own, and the fix must not take it away."""
    user = admin.create_user(role="user")
    try:
        reset = admin.patch(f"/users/{user['id']}", json={"password": "Reset-By-Admin-7!"})
        assert reset.status_code == 200, reset.text

        after = ApiClient()
        after.login(user["_username"], "Reset-By-Admin-7!")
        assert after.get("/users/me").status_code == 200
    finally:
        admin.delete_user(user["id"])


def test_a_non_admin_cannot_reset_another_account(admin):
    """The gate that was already there, pinned so the change above cannot loosen it."""
    victim = admin.create_user(role="user")
    attacker = admin.create_user(role="user")
    client = ApiClient()
    client.login(attacker["_username"], attacker["_password"])
    try:
        r = client.patch(f"/users/{victim['id']}", json={"password": "Taken-Over-1!"})
        assert r.status_code in (403, 404), (
            f"a plain user reset another account: {r.status_code} {r.text[:200]}")
    finally:
        admin.delete_user(victim["id"])
        admin.delete_user(attacker["id"])
