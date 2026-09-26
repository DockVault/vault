"""Live: an administrator cannot give themselves access to another person's vault.

A regular user owns a vault with a file in it. A freshly made administrator tries every way of
reaching it themselves: a grant to themselves at each level, a grant to a department they belong to,
and joining a department that has access. Each is refused with 403, leaves them unable to list the
vault, and is written to the audit log as refused. What must keep working: a second administrator
granting the first, the first granting other people, the owner sharing, and lowering or restating
access you already hold.

test_no_self_granted_access.py covers the rule offline.
"""
import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

_REFUSED_ACTION = "vault_self_access_refused"


class _Cast:
    """The people in these tests, each logged in, all deleted afterwards (vaults first)."""

    def __init__(self, admin):
        self.admin = admin
        self.made = []

    def person(self, role="user"):
        u = self.admin.create_user(role=role)
        client = ApiClient(BASE_URL)
        client.login(u["_username"], u["_password"])
        client.account = u
        self.made.append(client)
        return client

    def cleanup(self):
        for client in self.made:
            listed = client.get("/vaults")
            for v in (listed.json() if listed.status_code == 200 else []):
                if str(v.get("owner_id")) == str(client.account["id"]):
                    client.delete_vault(v["id"])
        for client in self.made:
            r = self.admin.delete_user(client.account["id"])
            assert r.status_code == 200, f"{client.account['_username']} was left behind: {r.text}"


@pytest.fixture
def cast(admin):
    c = _Cast(admin)
    yield c
    c.cleanup()


@pytest.fixture
def groups(admin):
    made = []

    def make(creator):
        r = creator.post("/groups", json={"name": unique("dept")})
        assert r.status_code == 200, r.text
        made.append(r.json()["id"])
        return r.json()["id"]

    yield make
    for gid in made:
        admin.delete(f"/groups/{gid}")


@pytest.fixture
def scene(cast):
    """The owner's vault (holding one file), the admin who wants in, a second admin, a colleague."""
    owner = cast.person()
    vault = owner.create_vault()
    r = owner.post(f"/vaults/{vault['id']}/files",
                   files=[("files", ("private.txt", b"only the owner's", "text/plain"))])
    assert r.status_code in (200, 201), r.text
    return {"owner": owner, "vault_id": vault["id"], "actor": cast.person("admin"),
            "second_admin": cast.person("admin"), "colleague": cast.person()}


def _uid(client):
    return str(client.account["id"])


def _grant(by, vault_id, who, level="read"):
    return by.post(f"/vaults/{vault_id}/permissions", json={"user_id": _uid(who), "level": level})


def _can_list(client, vault_id):
    return client.get(f"/vaults/{vault_id}/files").status_code == 200


def _refusals(admin, resource_id, via, username):
    return [row for row in admin.get(f"/audit/log?action={_REFUSED_ACTION}").json()
            if row.get("action") == _REFUSED_ACTION and str(row.get("resource_id")) == str(resource_id)
            and (row.get("details") or {}).get("via") == via and row.get("status") == "refused"
            and row.get("username") == username]


def _members(admin, group_id):
    return {str(m["id"]) for m in admin.get(f"/groups/{group_id}").json()["members"]}


def test_an_admin_cannot_grant_themselves_another_persons_vault(admin, scene):
    actor, vid = scene["actor"], scene["vault_id"]
    assert not _can_list(actor, vid), "anchor: an admin is not a member of every vault"

    for level in ("read", "write", "delete", "manage"):
        r = _grant(actor, vid, actor, level)
        assert r.status_code == 403, (level, r.status_code, r.text)
        assert "ask its owner or another administrator" in r.json()["detail"], r.text

    assert not _can_list(actor, vid)
    listed = scene["owner"].get(f"/vaults/{vid}/permissions").json()
    assert _uid(actor) not in {str(m["user_id"]) for m in listed}, "a refused grant left a member row"
    assert len(_refusals(admin, vid, "grant_to_self", actor.account["_username"])) == 4


def test_a_second_admin_can_grant_the_first_who_may_then_lower_but_not_raise_it(admin, scene):
    actor, second, vid = scene["actor"], scene["second_admin"], scene["vault_id"]

    r = _grant(second, vid, actor, "read")
    assert r.status_code == 200, r.text
    assert _can_list(actor, vid)

    assert _grant(actor, vid, actor, "read").status_code == 200, "restating what you hold widens nothing"
    raised = _grant(actor, vid, actor, "write")
    assert raised.status_code == 403, raised.text

    assert _grant(second, vid, actor, "write").status_code == 200
    lowered = _grant(actor, vid, actor, "read")
    assert lowered.status_code == 200, lowered.text
    level = next(m for m in scene["owner"].get(f"/vaults/{vid}/permissions").json()
                 if str(m["user_id"]) == _uid(actor))
    assert level["read_permission"] and not level["write_permission"], level


def test_an_admin_can_still_grant_other_people(scene):
    actor, colleague, vid = scene["actor"], scene["colleague"], scene["vault_id"]
    assert not _can_list(colleague, vid)
    r = _grant(actor, vid, colleague, "read")
    assert r.status_code == 200, r.text
    assert _can_list(colleague, vid)
    assert not _can_list(actor, vid), "granting someone else gives the granter nothing"


def test_the_owner_can_still_share(admin, scene, groups):
    owner, colleague, vid = scene["owner"], scene["colleague"], scene["vault_id"]
    r = _grant(owner, vid, colleague, "write")
    assert r.status_code == 200, r.text
    assert _can_list(colleague, vid)

    dept = groups(admin)
    newcomer = scene["second_admin"]
    assert admin.post(f"/groups/{dept}/members", json={"user_ids": [_uid(newcomer)]}).status_code == 200
    r = owner.post(f"/vaults/{vid}/group-access", json={"group_id": dept, "permission": "read"})
    assert r.status_code == 200, r.text
    assert _can_list(newcomer, vid)


def test_an_admin_cannot_reach_a_vault_through_a_department(admin, scene, groups):
    actor, second, colleague, vid = (scene["actor"], scene["second_admin"], scene["colleague"],
                                     scene["vault_id"])
    username = actor.account["_username"]
    dept = groups(actor)

    # Joining a department with no vault access is fine; granting it this vault is not, while the
    # admin is in it.
    assert actor.post(f"/groups/{dept}/members", json={"user_ids": [_uid(actor)]}).status_code == 200
    r = actor.post(f"/vaults/{vid}/group-access", json={"group_id": dept, "permission": "read"})
    assert r.status_code == 403, r.text
    assert admin.get(f"/vaults/{vid}/group-access").json() == [], "a refused grant left a row"
    assert len(_refusals(admin, vid, "department_access", username)) == 1

    # Out of the department, granting it is allowed; joining it afterwards is not.
    assert actor.delete(f"/groups/{dept}/members/{_uid(actor)}").status_code == 200
    r = actor.post(f"/vaults/{vid}/group-access", json={"group_id": dept, "permission": "read"})
    assert r.status_code == 200, r.text
    r = actor.post(f"/groups/{dept}/members", json={"user_ids": [_uid(actor)]})
    assert r.status_code == 403, r.text
    rows = _refusals(admin, dept, "department_membership", username)
    assert len(rows) == 1 and str(vid) in rows[0]["details"]["vault_ids"], rows

    # The whole request is refused, so nobody in it is added.
    r = actor.post(f"/groups/{dept}/members", json={"user_ids": [_uid(colleague), _uid(actor)]})
    assert r.status_code == 403, r.text
    assert _members(admin, dept) == set(), "a refused request added someone"
    assert actor.post(f"/groups/{dept}/members", json={"user_ids": [_uid(colleague)]}).status_code == 200
    assert _can_list(colleague, vid)
    assert not _can_list(actor, vid)

    # Another administrator may add them.
    assert second.post(f"/groups/{dept}/members", json={"user_ids": [_uid(actor)]}).status_code == 200
    assert _can_list(actor, vid)
    # ...and from there the department cannot be widened by the admin it now includes.
    r = actor.post(f"/vaults/{vid}/group-access", json={"group_id": dept, "permission": "write"})
    assert r.status_code == 403, r.text
    access = admin.get(f"/vaults/{vid}/group-access").json()
    assert [g["permission"] for g in access if g["group_id"] == dept] == ["read"], access
