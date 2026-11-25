"""A provider's groups mapped to departments and roles, against a running vault and its real database: the routes
under ``/admin/sso/providers/{id}/group-mappings`` with the real step-up, the rows as PostgreSQL keeps them (one
mapping for a group, gone with its department and with its provider), and the record each write leaves.

test_sso_group_mappings.py holds every rule offline; this file shows them standing on the database's own rules.
"""
import pytest

from conftest import ApiClient, unique

pytestmark = pytest.mark.integration

ACTION = "admin.auth_policy.write"


@pytest.fixture
def boss(admin):
    """An administrator of the test's own (the step-up's budget is kept per account), with its password on the
    client; deleted on teardown, with every provider and department it made."""
    user = admin.create_user(role="admin")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    client.password = user["_password"]
    client.providers, client.departments = [], []
    yield client
    for provider_id in client.providers:
        client.delete(f"/admin/sso/providers/{provider_id}", headers=_receipt(client))
    for department_id in client.departments:
        admin.delete(f"/groups/{department_id}")
    admin.delete_user(user["id"])


def _receipt(client):
    r = client.post("/auth/second-factor/step-up", json={"action": ACTION, "password": client.password})
    assert r.status_code == 200, r.text
    return {"X-Second-Factor": r.json()["receipt"]}


def _provider(client):
    r = client.post("/admin/sso/providers", json={"name": unique("idp"), "preset": "keycloak"}, headers=_receipt(client))
    assert r.status_code == 201, r.text
    client.providers.append(r.json()["provider"]["id"])
    return r.json()["provider"]


def _department(client, admin):
    r = admin.post("/groups", json={"name": unique("dept")})
    assert r.status_code in (200, 201), r.text
    client.departments.append(r.json()["id"])
    return r.json()


def _records(client, action, provider_id):
    rows = client.get("/audit/log", params={"action": action, "limit": 100}).json()
    entries = rows.get("logs", rows) if isinstance(rows, dict) else rows
    return [e for e in entries if isinstance(e, dict) and (e.get("details") or {}).get("provider_id") == provider_id]


def test_a_group_is_mapped_changed_and_removed_under_the_step_up_and_recorded(boss, admin):
    provider, department = _provider(boss), _department(boss, admin)
    path = f"/admin/sso/providers/{provider['id']}/group-mappings"
    shown = boss.get(path).json()
    assert shown["mappings"] == [] and shown["roles"] == ["user", "external", "admin"], shown
    assert any(d["id"] == department["id"] for d in shown["departments"]), shown["departments"]
    assert shown["admin_role"]["allowed"] is False and shown["step_up"] == ACTION

    # Judged first, then the password, then written.
    r = boss.post(path, json={"provider_group": "staff"})
    assert r.status_code == 400 and r.json()["detail"]["field"] == "role", r.text
    body = {"provider_group": "staff", "department_id": department["id"], "role": "user"}
    r = boss.post(path, json=body)
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "step_up_required", r.text
    assert boss.get(path).json()["mappings"] == []
    receipt = _receipt(boss)
    r = boss.post(path, json=body, headers=receipt)
    assert r.status_code == 201, r.text
    mapping = r.json()["mapping"]
    assert (mapping["provider_group"], mapping["role"], mapping["department"]["id"]) == ("staff", "user", department["id"])
    # A receipt is used once.
    r = boss.post(path, json={"provider_group": "guests", "role": "external"}, headers=receipt)
    assert r.status_code == 403, r.text

    # One mapping for a group; the provider's spelling is the group.
    r = boss.post(path, json={"provider_group": "staff", "role": "external"}, headers=_receipt(boss))
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "group_mapped", r.text
    assert boss.get(f"/admin/sso/providers/{provider['id']}").json()["provider"]["group_mappings"] == 1

    one = f"{path}/{mapping['id']}"
    r = boss.patch(one, json={"role": "user"})                       # nothing would change: nothing is asked
    assert r.status_code == 200 and r.json()["changed"] == [], r.text
    r = boss.patch(one, json={"role": "external", "provider_group": "all-staff"}, headers=_receipt(boss))
    assert r.status_code == 200 and r.json()["changed"] == ["provider_group", "role"], r.text
    listed = boss.get(path).json()["mappings"]
    assert [(m["provider_group"], m["role"], m["department"]["name"]) for m in listed] == [
        ("all-staff", "external", department["name"])]

    added = _records(boss, "sso_group_mapping_added", provider["id"])
    changed = _records(boss, "sso_group_mapping_changed", provider["id"])
    assert len(added) == 1 and added[0]["details"]["provider_group"] == "staff", added
    assert added[0]["details"]["department"] == department["name"] and added[0]["details"]["role"] == "user"
    assert len(changed) == 1 and changed[0]["details"]["changes"] == {
        "provider_group": {"old": "staff", "new": "all-staff"}, "role": {"old": "user", "new": "external"}}, changed

    r = boss.delete(one, headers=_receipt(boss))
    assert r.status_code == 200 and r.json()["removed"] is True, r.text
    assert boss.get(path).json()["mappings"] == [] and boss.delete(one, headers=_receipt(boss)).status_code == 404
    assert len(_records(boss, "sso_group_mapping_removed", provider["id"])) == 1


def test_the_administrator_role_follows_the_providers_own_rules(boss):
    provider = _provider(boss)
    path = f"/admin/sso/providers/{provider['id']}/group-mappings"
    body = {"provider_group": "vault-admins", "role": "admin"}
    r = boss.post(path, json=body, headers=_receipt(boss))
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "admin_mapping_off", r.text
    r = boss.patch(f"/admin/sso/providers/{provider['id']}", json={"policy": {"sso_admin_mapping": True}},
                   headers=_receipt(boss))
    assert r.status_code == 200, r.text
    r = boss.post(path, json=body, headers=_receipt(boss))
    assert r.status_code == 201 and r.json()["mapping"]["does_nothing"] is None, r.text
    # The provider's people are held to no password: the mapping stays, says that it raises nothing, and another
    # group cannot be given the role.
    r = boss.patch(f"/admin/sso/providers/{provider['id']}", json={"policy": {"sso_password_login": "disabled"}},
                   headers=_receipt(boss))
    assert r.status_code == 200, r.text
    shown = boss.get(path).json()
    assert shown["admin_role"]["why_not"]["reason"] == "provider_holds_no_passwords", shown
    assert [m["does_nothing"]["reason"] for m in shown["mappings"]] == ["provider_holds_no_passwords"]
    r = boss.post(path, json={"provider_group": "other-admins", "role": "admin"}, headers=_receipt(boss))
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "provider_holds_no_passwords", r.text


def test_a_mapping_goes_with_its_department_and_with_its_provider(boss, admin):
    provider, department = _provider(boss), _department(boss, admin)
    path = f"/admin/sso/providers/{provider['id']}/group-mappings"
    r = boss.post(path, json={"provider_group": "finance", "department_id": department["id"]}, headers=_receipt(boss))
    assert r.status_code == 201, r.text
    r = boss.post(path, json={"provider_group": "staff", "role": "user"}, headers=_receipt(boss))
    assert r.status_code == 201, r.text
    # The department says how many mappings name it; deleting it takes them, and says how many went.
    r = boss.post(path, json={"provider_group": "controllers", "department_id": department["id"], "role": "user"},
                  headers=_receipt(boss))
    assert r.status_code == 201, r.text
    assert admin.get(f"/groups/{department['id']}").json()["sso_group_mappings"] == 2
    r = admin.delete(f"/groups/{department['id']}")
    assert r.status_code == 200 and r.json()["sso_group_mappings_removed"] == 2, r.text
    boss.departments.remove(department["id"])
    # A department that is gone cannot be named.
    assert [m["provider_group"] for m in boss.get(path).json()["mappings"]] == ["staff"]
    r = boss.post(path, json={"provider_group": "sales", "department_id": department["id"]}, headers=_receipt(boss))
    assert r.status_code == 400 and r.json()["detail"]["field"] == "department_id", r.text
    # The provider's removal takes its mappings.
    r = boss.delete(f"/admin/sso/providers/{provider['id']}", headers=_receipt(boss))
    assert r.status_code == 200, r.text
    boss.providers.remove(provider["id"])
    assert boss.get(path).status_code == 404
