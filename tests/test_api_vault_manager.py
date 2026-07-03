"""Vault Manager role — delegated membership/access administration.

A member granted manage_permission ("Manager") can add/remove members and
grant/revoke access (per-user + department/group). To prevent privilege
escalation, only the owner or a global admin may *assign* the manager role or
modify/revoke an existing manager — a manager cannot mint or unseat peers.
Owner-only destructive actions (delete / rotate-key / change-password) are
unaffected and covered elsewhere.
"""
import pytest

from conftest import ApiClient, unique


def _client_for(user) -> ApiClient:
    c = ApiClient()
    c.login(user["_username"], user["_password"])
    return c


def _grant(client, vid, user_id, level):
    return client.post(f"/vaults/{vid}/permissions",
                       json={"user_id": user_id, "level": level})


@pytest.fixture
def member(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def member2(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


def test_owner_assigns_manager_and_level_is_manage(admin, temp_vault, member):
    """Granting 'manage' sets full read/write/delete + manage, and the member's
    effective level (drives UI) reports 'manage'."""
    vid = temp_vault["id"]
    assert _grant(admin, vid, member["id"], "manage").status_code == 200

    mc = _client_for(member)
    assert mc.get(f"/vaults/{vid}").json()["my_permission"] == "manage"

    row = next(p for p in admin.get(f"/vaults/{vid}/permissions").json()
               if p["user_id"] == member["id"])
    assert row["manage_permission"] is True
    assert row["read_permission"] and row["write_permission"] and row["delete_permission"]


def test_manager_can_view_grant_and_revoke_regular_member(admin, temp_vault, member, member2):
    vid = temp_vault["id"]
    _grant(admin, vid, member["id"], "manage")
    mc = _client_for(member)

    # A manager may view the permission list (was owner-only before).
    assert mc.get(f"/vaults/{vid}/permissions").status_code == 200
    # ...grant a regular member...
    assert _grant(mc, vid, member2["id"], "read").status_code == 200
    assert any(p["user_id"] == member2["id"]
               for p in mc.get(f"/vaults/{vid}/permissions").json())
    # ...and revoke them.
    assert mc.delete(f"/vaults/{vid}/permissions/{member2['id']}").status_code == 200
    assert not any(p["user_id"] == member2["id"]
                   for p in admin.get(f"/vaults/{vid}/permissions").json())


def test_manager_cannot_assign_manager_role(admin, temp_vault, member, member2):
    """Escalation guard: a manager cannot mint a peer manager."""
    vid = temp_vault["id"]
    _grant(admin, vid, member["id"], "manage")
    mc = _client_for(member)
    assert _grant(mc, vid, member2["id"], "manage").status_code == 403


def test_manager_cannot_modify_or_revoke_peer_manager(admin, temp_vault, member, member2):
    """A manager cannot downgrade or unseat another manager — owner/admin only."""
    vid = temp_vault["id"]
    _grant(admin, vid, member["id"], "manage")
    _grant(admin, vid, member2["id"], "manage")
    mc = _client_for(member)
    assert _grant(mc, vid, member2["id"], "read").status_code == 403
    assert mc.delete(f"/vaults/{vid}/permissions/{member2['id']}").status_code == 403


def test_plain_member_cannot_view_or_grant(admin, temp_vault, member, member2):
    """A read-only member is not a manager: no list, no grant."""
    vid = temp_vault["id"]
    _grant(admin, vid, member["id"], "read")
    mc = _client_for(member)
    assert mc.get(f"/vaults/{vid}/permissions").status_code == 403
    assert _grant(mc, vid, member2["id"], "read").status_code == 403


def test_owner_can_revoke_manager(admin, temp_vault, member):
    vid = temp_vault["id"]
    _grant(admin, vid, member["id"], "manage")
    assert admin.delete(f"/vaults/{vid}/permissions/{member['id']}").status_code == 200
    assert not any(p["user_id"] == member["id"]
                   for p in admin.get(f"/vaults/{vid}/permissions").json())


def test_non_admin_owner_can_assign_manager(admin, member, member2):
    """The owner path is independent of the global-admin bypass: a regular user
    who owns a vault can delegate the manager role."""
    owner_client = _client_for(member)
    vault = owner_client.create_vault(name=unique("ownervault"))
    vid = vault["id"]
    try:
        assert _grant(owner_client, vid, member2["id"], "manage").status_code == 200
        mc2 = _client_for(member2)
        assert mc2.get(f"/vaults/{vid}").json()["my_permission"] == "manage"
        # The delegated manager has real manager powers: viewing the permission
        # list is owner/manager-only, so a 200 here proves the delegation took.
        assert mc2.get(f"/vaults/{vid}/permissions").status_code == 200
    finally:
        owner_client.delete_vault(vid)


def test_manager_can_manage_group_access(admin, temp_vault, member):
    """Department (group) access grant/revoke is open to managers too."""
    vid = temp_vault["id"]
    _grant(admin, vid, member["id"], "manage")
    grp = admin.post("/groups", json={"name": unique("dept")})
    assert grp.status_code in (200, 201), grp.text
    gid = grp.json()["id"]
    try:
        mc = _client_for(member)
        assert mc.post(f"/vaults/{vid}/group-access",
                       json={"group_id": gid, "permission": "read"}).status_code == 200
        assert any(g["group_id"] == gid
                   for g in mc.get(f"/vaults/{vid}/group-access").json())
        assert mc.delete(f"/vaults/{vid}/group-access/{gid}").status_code == 200
    finally:
        admin.delete(f"/groups/{gid}")
