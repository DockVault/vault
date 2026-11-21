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


def test_the_one_time_statement_writes_on_postgresql_the_mark_the_vault_reads(admin):
    """The statement that confirms, once, the accounts made from an invitation before the mark existed names
    PostgreSQL's own functions for the mark. Here it is run on the stack's database as it is written, held to
    three accounts of this test: the mark it writes for an address in mixed letters is the one the vault makes
    and reads as confirmed; an invitation that carried another address, or none, confirms nothing."""
    import uuid

    from _account_change_helpers import psql
    from app.core import email_confirmation

    made = [admin.create_user(role="user") for _ in range(3)]
    ids = [m["id"] for m in made]
    listed = ", ".join(f"'{i}'" for i in ids)
    mixed = f"MiXed.{made[0]['_username']}@Example.com"
    carried = [mixed.lower(), "another." + made[1]["_username"] + "@example.com", None]
    probes = []
    try:
        psql(f"UPDATE users SET email = '{mixed}' WHERE id = '{ids[0]}'")
        psql(f"UPDATE users SET email_confirmed_at = NULL, email_confirmed_for = NULL WHERE id IN ({listed})")
        for account, address in zip(ids, carried):
            probe = str(uuid.uuid4())
            probes.append(probe)
            psql("INSERT INTO account_invitations (id, username, email, role, token_prefix, token_hash, expires_at, "
                 "accepted_at, accepted_user_id, created_at) VALUES "
                 f"('{probe}', 'probe-{probe[:8]}', {repr(address) if address else 'NULL'}, 'user', '{probe[:12]}', "
                 f"'{uuid.uuid4().hex + uuid.uuid4().hex}', now(), '2026-03-01 10:00:00', '{account}', now())")
        psql(email_confirmation.BACKFILL + f" AND users.id IN ({listed})")
        rows = dict(line.split("|", 1) for line in psql(
            f"SELECT id, coalesce(email_confirmed_for, '') || '|' || coalesce(email_confirmed_at::text, '') "
            f"FROM users WHERE id IN ({listed})").splitlines())
        assert rows[ids[0]] == f"{email_confirmation.mark_for(mixed)}|2026-03-01 10:00:00", rows
        assert rows[ids[1]] == "|" and rows[ids[2]] == "|", rows
        assert _confirmed(admin, made[0]["_username"]) == (True, mixed)
        assert _confirmed(admin, made[1]["_username"])[0] is False and _confirmed(admin, made[2]["_username"])[0] is False
    finally:
        if probes:
            psql("DELETE FROM account_invitations WHERE id IN (" + ", ".join(f"'{p}'" for p in probes) + ")")
        for account in ids:
            admin.delete_user(account)


def _typed_address(admin):
    """An account whose address is its owner's own claim: (the account, its signed-in client, the address)."""
    made = admin.create_user(role="user")
    person = ApiClient()
    person.login(made["_username"], made["_password"])
    typed = unique("typed") + "@example.com"
    r = person.patch("/users/me", json={"email": typed, "current_password": made["_password"]})
    if r.status_code == 202 or (r.status_code == 200 and r.json().get("email") != typed):
        admin.delete_user(made["id"])
        pytest.skip("this stack asks for an emailed code before an address changes")
    assert r.status_code == 200, r.text
    return made, person, typed


def test_an_administrator_confirms_the_address_a_person_typed_and_never_their_own(admin):
    made, person, typed = _typed_address(admin)
    try:
        name = made["_username"]
        assert _confirmed(admin, name) == (False, typed)
        assert person.get("/users/me").json()["email_confirmed"] is False
        # Nobody confirms their own this way, and nobody who is no administrator confirms anybody's.
        r = person.patch(f"/users/{made['id']}", json={"email_confirmed": True})
        assert r.status_code == 403, r.text                        # not theirs to change by its id at all
        me = admin.get("/users/me").json()
        r = admin.patch(f"/users/{me['id']}", json={"email_confirmed": True})
        assert r.status_code == 400 and "Confirm your own email address" in r.text, r.text
        assert _confirmed(admin, name)[0] is False
        r = admin.patch(f"/users/{made['id']}", json={"email_confirmed": True})
        assert r.status_code == 200, r.text
        assert _confirmed(admin, name) == (True, typed)                  # the address is as it was
        assert person.get("/users/me").json()["email_confirmed"] is True
        # The owner is told, in the app, what an administrator said of their address.
        notes = person.get("/notifications").json()
        notes = notes.get("notifications", notes) if isinstance(notes, dict) else notes
        assert any("Your email address was confirmed" in (n.get("title") or "") for n in notes), notes
        # Changed by the person once more, it is their claim once more.
        again = unique("again") + "@example.com"
        r = person.patch("/users/me", json={"email": again, "current_password": made["_password"]})
        assert r.status_code == 200, r.text
        assert _confirmed(admin, name) == (False, again)
    finally:
        admin.delete_user(made["id"])


def test_a_person_confirms_their_own_address_with_a_code_and_only_with_that_code(admin):
    """The code itself only ever reaches the mailbox. So the request is held to what this stack can do (it sends
    no email: the answer says who can confirm instead), and the confirmation is run against codes written into
    the store as the vault writes them, their hash made with the server's own pepper."""
    import subprocess
    import uuid

    from _account_change_helpers import API, REDIS, psql
    from app.core.otp_service import hash_code

    made, person, typed = _typed_address(admin)
    uid = made["id"]
    pepper = subprocess.run(["docker", "exec", API, "printenv", "JWT_SECRET_KEY"], capture_output=True, text=True,
                            timeout=20).stdout.strip()
    if not pepper:
        admin.delete_user(uid)
        pytest.skip("the server's pepper cannot be read on this stack")

    def seed(purpose, destination, code):
        subprocess.run(["docker", "exec", REDIS, "redis-cli", "DEL", f"otp:{purpose}:{uid}"], capture_output=True,
                       text=True, timeout=20)
        psql(f"DELETE FROM otp_codes WHERE user_id = '{uid}'")
        psql("INSERT INTO otp_codes (id, purpose, user_id, destination, code_hash, attempts, max_attempts, "
             "expires_at, consumed_at, created_at) VALUES "
             f"('{uuid.uuid4()}', '{purpose}', '{uid}', '{destination}', '{hash_code(code, pepper)}', 0, 3, "
             "now() + interval '15 minutes', NULL, now())")

    try:
        r = person.post("/users/me/email/confirmation/request")
        if r.status_code == 202:
            pytest.skip("this stack sends email: the code went to a mailbox this test cannot read")
        assert r.status_code == 400 and "An administrator can confirm your address" in r.text, r.text
        # A code for changing an address confirms nothing here.
        seed("email_change", typed, "246810")
        r = person.post("/users/me/email/confirmation", json={"code": "246810"})
        assert r.status_code == 400, r.text
        # A code that was sent to another address than the account holds now confirms nothing.
        seed("email_confirm", "elsewhere@example.com", "135790")
        r = person.post("/users/me/email/confirmation", json={"code": "135790"})
        assert r.status_code == 409 and "changed since" in r.text, r.text
        assert _confirmed(admin, made["_username"])[0] is False
        # The code sent to the address the account holds: wrong once, then right; and it serves once.
        seed("email_confirm", typed, "112233")
        assert person.post("/users/me/email/confirmation", json={"code": "000000"}).status_code == 400
        r = person.post("/users/me/email/confirmation", json={"code": "112233"})
        assert r.status_code == 200 and r.json() == {"email": typed, "email_confirmed": True}, r.text
        assert _confirmed(admin, made["_username"]) == (True, typed)
        assert person.post("/users/me/email/confirmation", json={"code": "112233"}).status_code == 400
        r = person.post("/users/me/email/confirmation/request")
        assert r.status_code == 409 and r.json()["detail"]["reason"] == "already_confirmed", r.text
    finally:
        psql(f"DELETE FROM otp_codes WHERE user_id = '{uid}'")
        admin.delete_user(uid)
