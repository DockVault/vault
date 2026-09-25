"""The vault list's member and department counts, and the reply to deleting an unlabelled
zero-knowledge vault.

Every vault card used to read "1 members": the list never sent a count and the page fell back to 1.
The list now sends `member_count` -- the owner and the people added directly, the same people the
vault's member list shows -- and `department_count`, the departments granted access, the same ones
its department list shows. Both go only to a caller who may see those lists (owner, manager or admin,
holding the member-list permission and, on a temporary credential, the see-permissions capability);
anyone else gets null, and the card shows no count rather than a made-up one.

Department members are not folded into the member count. Who is in a department, and how many, is for
admins only; a combined number would give both away to any owner or manager.

Deleting a zero-knowledge vault with no label used to answer "Vault None deleted successfully" and
record the vault name as the string "None": the real name is sealed in the browser, so the server has
none to give.
"""
import os
import subprocess

import pytest

from conftest import (ApiClient, ZK_ENC_NAME_STUB, ZK_EPHEMERAL_STUB, ZK_WRAPPED_DEK_STUB,
                      ensure_ecc_keypair, unique)

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    r = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                       capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr
    return (r.stdout or "").strip()


def _row(client, vault_id):
    r = client.get("/vaults")
    assert r.status_code == 200, r.text
    rows = [v for v in r.json() if v["id"] == vault_id]
    assert len(rows) == 1, f"the vault should be listed once for this caller: {rows}"
    return rows[0]


def _client(user):
    c = ApiClient()
    c.login(user["_username"], user["_password"])
    return c


@pytest.fixture
def people(admin):
    made = []

    def make():
        u = admin.create_user(role="user")
        made.append(u)
        return u

    yield make
    for u in made:
        admin.delete_user(u["id"])


@pytest.fixture
def departments(admin):
    made = []

    def make(parent_id=None):
        body = {"name": unique("mc-dept")}
        if parent_id:
            body["parent_id"] = parent_id
        r = admin.post("/groups", json=body)
        assert r.status_code in (200, 201), r.text
        made.append(r.json())
        return r.json()

    yield make
    for g in reversed(made):            # a sub-department before its parent
        admin.delete(f"/groups/{g['id']}")


def test_the_counts_are_the_vaults_own_member_and_department_lists(admin, temp_vault, people,
                                                                  departments):
    """Owner plus direct members, each person once; departments counted as departments. A
    sub-department of a granted one is not itself granted, so it is not counted."""
    vid = temp_vault["id"]
    direct, both, dept_only, sub_member = (people() for _ in range(4))
    for u in (direct, both):
        r = admin.post(f"/vaults/{vid}/permissions", json={"user_id": u["id"], "level": "read"})
        assert r.status_code in (200, 201), r.text
    dept = departments()
    sub = departments(parent_id=dept["id"])
    assert admin.post(f"/groups/{dept['id']}/members",
                      json={"user_ids": [dept_only["id"], both["id"]]}).status_code in (200, 201)
    assert admin.post(f"/groups/{sub['id']}/members",
                      json={"user_ids": [sub_member["id"]]}).status_code in (200, 201)
    r = admin.post(f"/vaults/{vid}/group-access", json={"group_id": dept["id"], "permission": "read"})
    assert r.status_code in (200, 201), r.text

    row = _row(admin, vid)
    assert (row["member_count"], row["department_count"]) == (3, 1), row
    # The same lists the vault's access panel shows: its members (plus the owner) and departments.
    listed = admin.get(f"/vaults/{vid}/permissions").json()
    granted = admin.get(f"/vaults/{vid}/group-access").json()
    assert row["member_count"] == 1 + len(listed) and row["department_count"] == len(granted)


def test_the_member_count_does_not_depend_on_who_is_in_a_department(admin, temp_vault, people,
                                                                    departments):
    """Adding someone directly always adds one, whether or not they are already in a granted
    department -- so the count cannot be used to find out who is in one."""
    vid = temp_vault["id"]
    insider, outsider = people(), people()
    dept = departments()
    assert admin.post(f"/groups/{dept['id']}/members",
                      json={"user_ids": [insider["id"]]}).status_code in (200, 201)
    assert admin.post(f"/vaults/{vid}/group-access",
                      json={"group_id": dept["id"], "permission": "read"}).status_code in (200, 201)
    assert _row(admin, vid)["member_count"] == 1
    for n, u in enumerate((insider, outsider), start=2):
        r = admin.post(f"/vaults/{vid}/permissions", json={"user_id": u["id"], "level": "read"})
        assert r.status_code in (200, 201), r.text
        assert _row(admin, vid)["member_count"] == n, u["_username"]


def test_only_someone_who_may_see_the_member_list_gets_the_count(admin, temp_vault, people):
    vid = temp_vault["id"]
    reader, manager = people(), people()
    assert admin.post(f"/vaults/{vid}/permissions",
                      json={"user_id": reader["id"], "level": "read"}).status_code in (200, 201)
    assert admin.post(f"/vaults/{vid}/permissions",
                      json={"user_id": manager["id"], "level": "manage"}).status_code in (200, 201)

    reader_c, manager_c = _client(reader), _client(manager)
    # A read-only member cannot see who else has access, so the list does not tell them either.
    assert reader_c.get(f"/vaults/{vid}/permissions").status_code == 403
    reader_row = _row(reader_c, vid)
    assert (reader_row["member_count"], reader_row["department_count"]) == (None, None)
    # A manager can, and gets the same numbers the owner does.
    assert manager_c.get(f"/vaults/{vid}/permissions").status_code == 200
    manager_row, owner_row = _row(manager_c, vid), _row(admin, vid)
    assert (manager_row["member_count"], manager_row["department_count"]) == (3, 0)
    assert (owner_row["member_count"], owner_row["department_count"]) == (3, 0)


def test_without_the_member_list_permission_there_is_no_count_and_no_refusal_logged(
        admin, temp_user, temp_user_client):
    """An owner without the member-list permission loads the list and gets no count. Loading the list
    is not an attempt to see the members, so it must not be logged as a refused one."""
    vault = temp_user_client.create_vault(name=unique("mc-own"))
    uid = temp_user["id"]
    try:
        assert _row(temp_user_client, vault["id"])["member_count"] == 1
        assert admin.delete(f"/permissions/users/{uid}/revoke/VAULT_PERMISSIONS").status_code == 200
        denials = ("SELECT count(*) FROM audit_logs WHERE action='endpoint_permission_denied' "
                   f"AND user_id='{uid}' AND details->>'required_group'='VAULT_PERMISSIONS'")
        before = int(_psql(denials) or "0")
        row = _row(temp_user_client, vault["id"])
        assert (row["member_count"], row["department_count"]) == (None, None)
        assert int(_psql(denials) or "0") == before, "loading the vault list was logged as a refusal"
    finally:
        admin.post(f"/permissions/users/{uid}/grant", json={"endpoint_group": "VAULT_PERMISSIONS"})
        temp_user_client.delete_vault(vault["id"])


def _temp_login(admin, vault_id, caps):
    r = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 30,
        "scope": {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": list(caps), "temp": {}},
        "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vault_id, "caps": list(caps)}],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    c = ApiClient()
    c.login(body["temp_username"], body["credential"])
    return c, body["temp_username"]


def test_a_temporary_credential_needs_the_see_permissions_capability(admin, temp_vault):
    vid = temp_vault["id"]
    names = []
    try:
        without, name = _temp_login(admin, vid, ["vault.see_info"])
        names.append(name)
        row = _row(without, vid)
        assert (row["member_count"], row["department_count"]) == (None, None)
        with_cap, name = _temp_login(admin, vid, ["vault.see_info", "vault.see_permissions"])
        names.append(name)
        row = _row(with_cap, vid)
        assert (row["member_count"], row["department_count"]) == (1, 0)
    finally:
        for name in names:
            admin.post(f"/temp-creds/{name}/delete")


@pytest.fixture
def zk_enabled(admin):
    before = admin.get("/settings").json().get("zero_knowledge_enabled", False)
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    yield
    admin.put("/settings", json={"zero_knowledge_enabled": bool(before)})


def test_deleting_an_unlabelled_zero_knowledge_vault_claims_no_name(admin, zk_enabled):
    """The browser sends a zero-knowledge vault's name sealed, with no label unless one is typed."""
    ensure_ecc_keypair(admin)
    r = admin.post("/vaults", json={
        "type": "zero_knowledge", "wrapped_dek": ZK_WRAPPED_DEK_STUB,
        "ephemeral_public_key": ZK_EPHEMERAL_STUB, "enc_name": ZK_ENC_NAME_STUB, "name_key_version": 1,
    })
    assert r.status_code in (200, 201), r.text
    vid = r.json()["id"]
    row = _row(admin, vid)
    assert (row["member_count"], row["department_count"]) == (1, 0)

    r = admin.delete_vault(vid)
    assert r.status_code == 200, r.text
    assert r.json()["message"] == "Vault deleted successfully"
    recorded = _psql("SELECT coalesce(details->>'vault_name', '<null>') FROM audit_logs "
                     f"WHERE action='vault_deleted' AND resource_id='{vid}'")
    assert recorded == "<null>", f"the audit row should record no name, not {recorded!r}"


def test_deleting_a_named_vault_still_names_it(admin):
    name = unique("mc-named")
    vault = admin.create_vault(name=name)
    r = admin.delete_vault(vault["id"])
    assert r.status_code == 200, r.text
    assert r.json()["message"] == f"Vault {name} deleted successfully"
