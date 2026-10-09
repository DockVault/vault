"""Live: a vault's owner is told when someone else gives a person access to their vault (app/core/access_notices.py).

On a running stack, with a real SMTP server inside the web container (_owner_notice_helpers.py):

  * an administrator creates X and grants X the vault of O: O's notification and outbox row are written by the
    grant's own transaction (the same transaction id as the member row), and the email reaches O, naming X, the
    administrator who made X's account and that the administrator set X's password;
  * the department paths: a grant to a department X is in, adding someone to that department, and removing X's own
    member row while the department may write each tell O in that change's transaction;
  * the owner's own grant tells nobody; a manager of the vault tells the owner in the app only, with no email.

test_access_notices.py covers the rules offline.
"""
import pytest

from _account_change_helpers import notifications, psql, signed_in
from _owner_notice_helpers import mail_to, owner_with_vault, sending_to_sink, wait_for
from conftest import ADMIN_USER, unique

pytestmark = pytest.mark.integration

NOTICE = "vault_access_granted"
SUBJECT = "Someone was given access to your vault"


@pytest.fixture
def made(admin):
    """The accounts and departments a test made, and their access notices' outbox rows, removed afterwards."""
    out = {"users": [], "groups": [], "owners": []}
    yield out
    for gid in out["groups"]:
        admin.delete(f"/groups/{gid}")
    for owner_id in out["owners"]:
        psql(f"DELETE FROM compliance_notice_outbox WHERE kind = 'access_granted' AND user_id = '{owner_id}'")
    for client, vid in out.get("vaults", []):
        client.delete_vault(vid)
    for uid in out["users"]:
        admin.delete_user(uid)


def _owner(admin, made):
    owner, client, vid = owner_with_vault(admin)
    made["users"].append(owner["id"])
    made["owners"].append(owner["id"])
    made.setdefault("vaults", []).append((client, vid))
    return owner, client, vid


def _person(admin, made, role="user"):
    u = admin.create_user(role=role)
    made["users"].append(u["id"])
    return u


def _access_notices(client):
    return notifications(client, NOTICE)


def _outbox_rows(owner_id):
    out = psql("SELECT status || '|' || xmin::text FROM compliance_notice_outbox "
               f"WHERE kind = 'access_granted' AND user_id = '{owner_id}' ORDER BY created_at")
    return [row.split("|") for row in out.splitlines() if row]


def _notice_xmins(owner_id):
    out = psql(f"SELECT xmin::text FROM notifications WHERE type = '{NOTICE}' AND user_id = '{owner_id}' "
               "ORDER BY created_at")
    return out.splitlines()


def test_an_administrators_grant_tells_the_owner_in_its_own_transaction_and_by_email(admin, made):
    owner, owner_c, vid = _owner(admin, made)
    x = _person(admin, made)
    with sending_to_sink(admin):
        r = admin.post(f"/vaults/{vid}/permissions", json={"user_id": x["id"], "level": "write"})
        assert r.status_code == 200, r.text
        member_xmin = psql(f"SELECT xmin::text FROM vault_members WHERE vault_id = '{vid}' AND user_id = '{x['id']}'")
        assert _notice_xmins(owner["id"]) == [member_xmin]
        [(status, row_xmin)] = _outbox_rows(owner["id"])
        assert row_xmin == member_xmin and status in ("pending", "sent")
        [n] = _access_notices(owner_c)
        assert n["target"] == f"#vault/{vid}" and n["title"] == SUBJECT
        assert f"{ADMIN_USER} gave {x['_username']} read and write access to one of your vaults." in n["body"]
        assert f"by {ADMIN_USER}" in n["body"] and f"its password was set by {ADMIN_USER}" in n["body"]
        [mail] = mail_to(owner["email"], SUBJECT)
        assert x["_username"] in mail["text"] and "not by them" in mail["text"]
    assert wait_for(lambda: _outbox_rows(owner["id"])[0][0] == "sent")
    # The bell, not the compliance banner: "Access to my vaults" counts no notice of it.
    assert owner_c.get("/me/compliance-access").json()["unseen"] == []


def test_the_department_paths_each_tell_the_owner_in_the_changes_transaction(admin, made):
    owner, owner_c, vid = _owner(admin, made)
    x, y = _person(admin, made), _person(admin, made)
    r = admin.post("/groups", json={"name": unique("dept")})
    assert r.status_code == 200, r.text
    gid = r.json()["id"]
    made["groups"].append(gid)
    # x joins a department with no access: nobody is told.
    assert admin.post(f"/groups/{gid}/members", json={"user_ids": [x["id"]]}).status_code == 200
    assert _access_notices(owner_c) == []

    # The department is given the vault: x gains it.
    assert admin.post(f"/vaults/{vid}/group-access", json={"group_id": gid, "permission": "read"}).status_code == 200
    xmin = psql(f"SELECT xmin::text FROM vault_group_access WHERE vault_id = '{vid}' AND group_id = '{gid}'")
    assert _notice_xmins(owner["id"])[-1] == xmin and _outbox_rows(owner["id"])[-1][1] == xmin
    assert f"which {x['_username']} belongs to, read access to one of your vaults" in _access_notices(owner_c)[0]["body"]

    # y joins it.
    assert admin.post(f"/groups/{gid}/members", json={"user_ids": [y["id"]]}).status_code == 200
    xmin = psql(f"SELECT xmin::text FROM user_groups WHERE group_id = '{gid}' AND user_id = '{y['id']}'")
    assert _notice_xmins(owner["id"])[-1] == xmin
    assert f"added {y['_username']} to the department" in _access_notices(owner_c)[0]["body"]

    # x is held to read by a member row while the department may write; removing the row widens x.
    assert admin.post(f"/vaults/{vid}/group-access", json={"group_id": gid, "permission": "write"}).status_code == 200
    assert owner_c.post(f"/vaults/{vid}/permissions", json={"user_id": x["id"], "level": "read"}).status_code == 200
    before = len(_notice_xmins(owner["id"]))
    assert admin.delete(f"/vaults/{vid}/permissions/{x['id']}").status_code == 200
    assert len(_notice_xmins(owner["id"])) == before + 1
    assert f"removed {x['_username']}'s own access row" in _access_notices(owner_c)[0]["body"]


def test_the_owners_own_grant_tells_nobody_and_a_managers_only_in_the_app(admin, made):
    owner, owner_c, vid = _owner(admin, made)
    mona, z = _person(admin, made), _person(admin, made)
    assert owner_c.post(f"/vaults/{vid}/permissions", json={"user_id": mona["id"], "level": "manage"}).status_code == 200
    assert _access_notices(owner_c) == [] and _outbox_rows(owner["id"]) == []
    r = signed_in(mona).post(f"/vaults/{vid}/permissions", json={"user_id": z["id"], "level": "read"})
    assert r.status_code == 200, r.text
    [n] = _access_notices(owner_c)
    assert f"{mona['_username']} gave {z['_username']} read access" in n["body"]
    assert _outbox_rows(owner["id"]) == [], "a manager of the vault is a member: no email"
    assert psql("SELECT details->>'email_status' FROM audit_logs WHERE action = 'owner_notice_written' "
                f"AND resource_id = '{owner['id']}' ORDER BY timestamp DESC LIMIT 1") == "in_app_only"
