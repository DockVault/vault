"""Whether an auditor's right is in force, on a running stack: each change to the holder's account suspends it at
once, or ends it (app/core/auditor_rights.py), every administrator and the holder are told, and the holder
reconfirms with their password and an authenticator code.

  * an administrator's change to the holder's sign-in details (an email address, a password, a reset link, an
    SSH key) suspends the right; after a password someone else set, the holder sets their own first;
  * an administrator's second-factor reset, or the holder removing their own, ends it for good;
  * deactivating suspends it; once active again, the holder reconfirms;
  * a change that bypassed every hook (made in the database) is refused by the computed check on the next
    request, and the pruner's pass writes the suspension.

test_auditor_liveness.py covers each trigger offline, with its hook and without.
"""
import base64
import os
import struct

import pytest

from conftest import unique
from _account_change_helpers import notifications, psql, signed_in
from _auditor_helpers import (audit_rows, compliance_receipt, forget_grants, grant_right, new_auditor_account,
                              run_pass, two_admins)
from _sf_helpers import step_up_receipt

pytestmark = pytest.mark.integration


@pytest.fixture
def holder(admin):
    """uma holds the right, granted by ada and bob: {"uma", "uma_c", "codes", "grant", "admins"}."""
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant = grant_right(admins, uma["id"])
        try:
            yield {"uma": uma, "uma_c": uma_c, "codes": codes, "grant": grant, "admins": admins}
        finally:
            forget_grants(uma["id"], admins["ada"][0]["id"], admins["bob"][0]["id"])
            admin.delete_user(uma["id"])


def _me(client):
    r = client.get("/compliance/me")
    assert r.status_code == 200, r.text
    return r.json()["grant"]


def _reconfirm(h, client=None):
    client = client or h["uma_c"]
    return client.post(f"/compliance/auditor-grants/{h['grant']}/reconfirm",
                       headers=compliance_receipt(client, "compliance.grant.reconfirm", h["uma"]["_password"],
                                                  h["codes"]))


def _ssh_key():
    blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + os.urandom(32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def _status(h):
    return psql(f"SELECT status || '|' || coalesce(suspend_reason, '') FROM auditor_grants WHERE id='{h['grant']}'")


@pytest.mark.parametrize("change,reason", [
    ("email", "email"), ("ssh_key", "ssh_key"), ("reset_link", "reset_link")])
def test_an_administrators_change_suspends_the_right_and_the_holder_reconfirms(admin, admin_creds, holder, change,
                                                                               reason):
    uid = holder["uma"]["id"]
    assert _me(holder["uma_c"])["live"] is True
    r = {"email": lambda: admin.patch(f"/users/{uid}", json={"email": f"{unique('aud')}@example.com"}),
         "ssh_key": lambda: admin.post(f"/users/{uid}/ssh-keys", json={"name": "k", "public_key": _ssh_key()}),
         "reset_link": lambda: admin.post(f"/users/{uid}/reset-link")}[change]()
    assert r.status_code in (200, 201), r.text
    assert _status(holder) == f"suspended|{reason}"
    me = _me(holder["uma_c"])
    assert me["live"] is False and me["reason"] == "suspended" and me["may_reconfirm"] is True
    rows = audit_rows(admin, "auditor_suspended", uid)
    assert rows and rows[0]["details"]["reason"] == reason and rows[0]["username"] == admin_creds["username"]
    for client in (holder["uma_c"], admin):
        assert "Auditor right suspended" in [n["title"] for n in notifications(client, "auditor_right")]
    # The changer joined the grant's list, which the independence rule reads while the grant stands.
    assert admin_creds["username"] in psql(f"SELECT credential_changers::text FROM auditor_grants WHERE id='{holder['grant']}'")
    r = _reconfirm(holder)
    assert r.status_code == 200 and r.json()["status"] == "active", r.text
    assert _me(holder["uma_c"])["live"] is True
    assert audit_rows(admin, "auditor_reconfirmed", uid)
    assert "Auditor right reconfirmed" in [n["title"] for n in notifications(admin, "auditor_right")]


def test_after_an_administrator_sets_the_password_the_holder_sets_their_own_first(admin, holder):
    uma = holder["uma"]
    r = admin.patch(f"/users/{uma['id']}", json={"password": "Chosen-By-Admin-8x!"})
    assert r.status_code == 200, r.text
    assert _status(holder) == "suspended|password"
    uma["_password"] = "Chosen-By-Admin-8x!"
    holder["uma_c"] = signed_in(uma)          # the change ended the holder's sessions
    me = _me(holder["uma_c"])
    assert me["may_reconfirm"] is False and me["reconfirm_problem"]["reason"] == "password_not_own"
    r = holder["uma_c"].post(f"/compliance/auditor-grants/{holder['grant']}/reconfirm")
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "password_not_own", r.text
    r = holder["uma_c"].patch("/users/me", json={"current_password": uma["_password"], "new_password": "Own-Again-9x!"})
    assert r.status_code == 200, r.text
    uma["_password"] = "Own-Again-9x!"
    r = _reconfirm(holder)
    assert r.status_code == 200 and r.json()["status"] == "active", r.text
    assert _me(holder["uma_c"])["live"] is True


def test_a_second_factor_reset_ends_the_right(admin, holder):
    uid = holder["uma"]["id"]
    r = admin.post(f"/users/{uid}/second-factor/reset")
    assert r.status_code == 200, r.text
    assert _status(holder) == "ended|second_factor_reset"
    client = signed_in(holder["uma"])
    assert client.get("/compliance/me").json() == {"grant": None}
    rows = audit_rows(admin, "auditor_suspended", uid)
    assert rows and rows[0]["details"]["outcome"] == "ended"
    assert "Auditor right ended" in [n["title"] for n in notifications(admin, "auditor_right")]


def test_removing_their_own_second_factor_ends_the_holders_right(admin, holder):
    c = holder["uma_c"]
    r = c.delete("/users/me/second-factor",
                 headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor",
                                                             recovery_codes=holder["codes"])})
    assert r.status_code == 200, r.text
    assert _status(holder) == "ended|second_factor_removed"


def test_deactivation_suspends_and_the_holder_reconfirms_once_active_again(admin, holder):
    uid = holder["uma"]["id"]
    assert admin.post(f"/api/user-management/users/{uid}/toggle-active").status_code == 200
    assert _status(holder) == "suspended|deactivated"
    assert admin.post(f"/api/user-management/users/{uid}/toggle-active").status_code == 200
    holder["uma_c"] = signed_in(holder["uma"])
    assert _me(holder["uma_c"])["reason"] == "suspended"
    r = _reconfirm(holder)
    assert r.status_code == 200 and r.json()["status"] == "active", r.text


@pytest.mark.parametrize("bypass,reason", [
    ("UPDATE users SET password_set_by_other_at = now() AT TIME ZONE 'utc' WHERE id='{uid}'", "password_not_own"),
    ("UPDATE second_factor_enrollments SET id = gen_random_uuid() WHERE user_id='{uid}'", "second_factor"),
    ("INSERT INTO credential_changes (id, target_user_id, kind, status, requested_by_name, requested_at, applied_at) "
     "VALUES (gen_random_uuid(), '{uid}', 'email', 'made', 'someone', now() AT TIME ZONE 'utc', "
     "now() AT TIME ZONE 'utc')", "credential_change"),
])
def test_a_change_that_bypassed_every_hook_is_refused_and_the_pass_writes_it(admin, holder, bypass, reason):
    uid = holder["uma"]["id"]
    psql(bypass.format(uid=uid))
    assert _status(holder) == "active|", "no hook ran"
    me = _me(holder["uma_c"])
    assert me["live"] is False and me["reason"] == reason
    assert run_pass()["auditor_grants"] is True
    expected = "ended|second_factor" if reason == "second_factor" else f"suspended|{reason}"
    assert _status(holder) == expected
