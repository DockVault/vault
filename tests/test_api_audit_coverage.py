"""API — changes that used to leave no audit row now leave exactly one, with the request's address.

Each test makes its own change and finds the row through the Activity feed by the resource it touched,
so it does not depend on what else the audit log holds."""
import time

from conftest import unique


def _rows(admin, resource_id, action=None):
    time.sleep(0.3)
    r = admin.get("/activity/events", params={"q": str(resource_id), "limit": 50})
    assert r.status_code == 200, r.text
    rows = [e for e in r.json()["events"] if e["resource_id"] == str(resource_id)]
    return [e for e in rows if action is None or e["action"] == action]


def _one(admin, resource_id, action):
    rows = _rows(admin, resource_id, action)
    assert len(rows) == 1, [e["action"] for e in _rows(admin, resource_id)]
    row = rows[0]
    assert row["ip_address"], row          # the address comes from the request
    assert row["channel"] == "web", row
    return row


def test_a_department_is_recorded_when_created_changed_and_deleted(admin):
    name = unique("dept")
    g = admin.post("/groups", json={"name": name})
    assert g.status_code == 200, g.text
    gid = g.json()["id"]
    assert admin.patch(f"/groups/{gid}", json={"description": "renamed"}).status_code == 200
    assert admin.delete(f"/groups/{gid}").status_code == 200
    created = _one(admin, gid, "group_created")
    assert created["details"]["name"] == name and created["label"] == "Department created"
    assert _one(admin, gid, "group_updated")["details"]["fields"] == ["description"]
    assert _one(admin, gid, "group_deleted")["details"]["name"] == name


def test_a_note_is_recorded_without_its_title_and_starring_it_is_not(admin):
    title = unique("secret-title")
    n = admin.post("/notes", json={"title": title, "body": "private text"})
    assert n.status_code == 200, n.text
    nid = n.json()["id"]
    assert admin.patch(f"/notes/{nid}", json={"body": "edited"}).status_code == 200
    assert admin.patch(f"/notes/{nid}", json={"is_favorite": True}).status_code == 200
    assert admin.delete(f"/notes/{nid}").status_code == 200
    rows = _rows(admin, nid)
    assert sorted(e["action"] for e in rows) == ["note_created", "note_deleted", "note_updated"]
    assert all(e["category"] == "notes" for e in rows)
    assert title not in str(rows) and "private text" not in str(rows)


def test_a_temporary_credential_is_recorded_when_deactivated_and_deleted(admin):
    made = []
    for _ in range(2):
        r = admin.post("/auth/temp-credentials", json={"validity_minutes": 30})
        assert r.status_code == 200, r.text
        made.append(r.json())
    off, gone = made
    assert admin.post(f"/temp-creds/{off['temp_username']}/deactivate").status_code == 200
    assert admin.post(f"/temp-creds/{gone['temp_username']}/delete").status_code == 200
    time.sleep(0.3)
    for cred, action in ((off, "TEMP_CREDENTIAL_DEACTIVATED"), (gone, "TEMP_CREDENTIAL_DELETED")):
        r = admin.get("/activity/events", params={"q": cred["temp_username"], "category": "temp_credentials"})
        rows = [e for e in r.json()["events"] if e["action"] == action]
        assert len(rows) == 1, r.json()["events"]
        assert rows[0]["details"]["temp_username"] == cred["temp_username"] and rows[0]["ip_address"]


def test_a_role_change_is_recorded_as_the_admin_who_made_it(admin, temp_user):
    r = admin.patch(f"/api/user-management/users/{temp_user['id']}/role", json={"new_role": "external"})
    assert r.status_code == 200, r.text
    row = _one(admin, temp_user["id"], "role_changed")
    assert row["username"] == admin.get("/users/me").json()["username"]
    assert row["details"]["username"] == temp_user["_username"]
    assert (row["details"]["old_role"], row["details"]["new_role"]) == ("user", "external")
    assert row["ip_address"] != "admin-action"


def test_vault_settings_are_recorded_with_what_changed(admin, temp_vault):
    vid = temp_vault["id"]
    r = admin.patch(f"/vaults/{vid}/settings", json={"expire_files_after_days": 9})
    assert r.status_code == 200, r.text
    row = _one(admin, vid, "vault_settings_updated")
    assert row["details"]["fields"] == ["expire_files_after_days"]
    assert row["details"]["expire_files_after_days"] == 9


def test_exporting_the_audit_log_is_recorded(admin):
    marker = unique("nobody")
    r = admin.get("/audit/export", params={"action": marker})
    assert r.status_code == 200, r.text
    time.sleep(0.3)
    body = admin.get("/activity/events", params={"q": marker, "category": "administration"}).json()
    rows = [e for e in body["events"] if e["action"] == "audit_exported"]
    assert len(rows) == 1, body["events"]
    assert rows[0]["details"]["filters"] == {"action": marker} and rows[0]["details"]["rows"] == 0
