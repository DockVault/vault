"""API — the Activity page's Events feed, against a running vault.

Each test makes its own event (a failed sign-in under a fresh name, a ranged download of a fresh file)
and finds it through the filters, so it does not depend on what else the audit log holds."""
import time

import pytest

from conftest import unique


def _events(client, **params):
    r = client.get("/activity/events", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _failed_sign_in(anon, name):
    r = anon.post("/auth/login", json={"username": name, "password": "not-the-password-1"})
    assert r.status_code in (401, 403, 429), r.text


def test_the_catalog_offers_every_category_channel_and_status(admin):
    r = admin.get("/activity/catalog")
    assert r.status_code == 200, r.text
    body = r.json()
    keys = [c["key"] for c in body["categories"]]
    assert keys[0] == "sign_in" and "security" in keys and keys[-1] == "legacy"
    assert set(body["channels"]) == {"web", "sftp", "public_link", "upload_link", "device_sync", "unknown"}
    assert body["statuses"] == ["success", "authorized", "failed"]
    # The events the summary counts as each sign-in outcome, so a click on one filters the list to them.
    assert body["sign_in_outcomes"] == {"succeeded": ["login_success"],
                                        "failed": ["login_failure", "second_factor_failed"],
                                        "locked": ["account_auto_locked"]}


def test_only_an_administrator_reads_the_feed(temp_user_client):
    assert temp_user_client.get("/activity/events").status_code == 403
    assert temp_user_client.get("/activity/catalog").status_code == 403


def test_a_failed_sign_in_is_found_by_user_status_and_category(admin, anon):
    name = unique("ghost")
    _failed_sign_in(anon, name)
    time.sleep(0.3)
    body = _events(admin, user=name, status="failed", category="sign_in")
    assert body["total"] >= 1, body
    ev = body["events"][0]
    assert ev["username"] == name
    assert ev["label"] == "Sign-in failed" and ev["category"] == "sign_in"
    assert ev["channel"] == "web"
    assert ev["method"] == "POST" and ev["endpoint"] == "/auth/login"
    assert ev["timestamp"].endswith("+00:00")
    # The same row is not in another category, nor under a succeeded status.
    assert _events(admin, user=name, category="files")["total"] == 0
    assert _events(admin, user=name, status="success")["total"] == 0


def test_an_address_filter_matches_exactly_or_by_block(admin, anon):
    name = unique("ghost")
    _failed_sign_in(anon, name)
    time.sleep(0.3)
    row = _events(admin, user=name)["events"][0]
    ip = row["ip_address"]
    assert _events(admin, user=name, ip=ip)["total"] >= 1
    block = "0.0.0.0/0" if ":" not in ip else "::/0"
    assert _events(admin, user=name, ip=block)["total"] >= 1
    assert _events(admin, user=name, ip="not-an-address")["total"] == 0


def test_pages_continue_without_repeating_a_row(admin, anon):
    prefix = unique("pager")
    for i in range(3):
        _failed_sign_in(anon, f"{prefix}-{i}")
    time.sleep(0.3)
    first = _events(admin, user=prefix, limit=2)
    assert first["total"] == 3 and len(first["events"]) == 2 and first["next_cursor"]
    second = _events(admin, user=prefix, limit=2, cursor=first["next_cursor"])
    assert second["total"] is None and len(second["events"]) == 1 and second["next_cursor"] is None
    ids = [e["id"] for e in first["events"] + second["events"]]
    assert len(set(ids)) == 3


def test_a_ranged_download_is_recorded_without_the_file_name(admin, temp_vault):
    vid = temp_vault["id"]
    name = unique("secret-plan") + ".txt"
    up = admin.post(f"/vaults/{vid}/files", files=[("files", (name, b"0123456789" * 50, "text/plain"))])
    assert up.status_code in (200, 201), up.text
    listing = admin.get(f"/vaults/{vid}/files").json()
    items = listing if isinstance(listing, list) else next(v for v in listing.values() if isinstance(v, list))
    fid = next(i["id"] for i in items if i.get("name") == name)
    r = admin.get(f"/vaults/{vid}/files/{fid}/download", headers={"Range": "bytes=0-99"})
    assert r.status_code == 206, r.status_code
    time.sleep(0.5)
    body = _events(admin, q=fid, category="files")
    ranged = [e for e in body["events"] if e["action"] == "file_download_range"]
    assert ranged, [e["action"] for e in body["events"]]
    ev = ranged[0]
    assert ev["status"] == "success" and ev["label"] == "Part of a file downloaded"
    assert ev["details"]["range_start"] == 0 and ev["details"]["range_end"] == 99
    assert name not in str(ev["details"])


def test_an_export_holds_the_filtered_rows_and_is_itself_recorded(admin, anon):
    import csv
    import io
    import json
    prefix = unique("exporter")
    for i in range(3):
        _failed_sign_in(anon, f"{prefix}-{i}")
    time.sleep(0.3)
    r = admin.get("/activity/export", params={"user": prefix})
    assert r.status_code == 200, r.text
    assert r.headers["X-Export-Total"] == "3" and r.headers["X-Export-Rows"] == "3"
    assert r.headers["Content-Disposition"].startswith("attachment; filename=activity-")
    table = list(csv.reader(io.StringIO(r.text)))
    assert table[0][:3] == ["Time (UTC)", "Event", "Action"] and len(table) == 4
    assert sorted(row[5] for row in table[1:]) == [f"{prefix}-{i}" for i in range(3)]
    assert all(row[0].endswith("+00:00") for row in table[1:])
    nd = admin.get("/activity/export", params={"user": prefix, "format": "ndjson"})
    lines = [json.loads(line) for line in nd.text.splitlines()]
    assert len(lines) == 3 and {e["label"] for e in lines} == {"Sign-in failed"}
    time.sleep(0.3)
    recorded = _events(admin, q=prefix, category="administration")["events"]
    exports = [e for e in recorded if e["action"] == "audit_exported"]
    assert [e["details"]["format"] for e in exports] == ["ndjson", "csv"]
    assert exports[1]["details"]["filters"] == {"user": prefix} and exports[1]["details"]["rows"] == 3


def test_an_export_takes_every_filter_the_list_takes(admin, anon, temp_vault):
    """An event, a user exactly, names no account had and a vault narrow the export as they narrow the
    list, and its audit row says which filters were used."""
    import json
    prefix = unique("exportf")
    for i in range(2):
        _failed_sign_in(anon, f"{prefix}-{i}")
    for _ in range(25):
        if _events(admin, user=prefix)["total"] >= 2:
            break
        time.sleep(0.2)

    def exported(**params):
        r = admin.get("/activity/export", params={"format": "ndjson", **params})
        assert r.status_code == 200, r.text
        rows = [json.loads(line) for line in r.text.splitlines()]
        assert int(r.headers["X-Export-Total"]) == len(rows)
        return rows

    assert len(exported(user=prefix, action="login_failure")) == 2
    assert exported(user=prefix, action="login_success") == []
    assert [e["username"] for e in exported(user=f"{prefix}-1", user_match="exact")] == [f"{prefix}-1"]
    assert exported(user=prefix, user_match="exact") == []
    assert len(exported(user=prefix, no_account="true")) == 2
    vid = temp_vault["id"]
    up = admin.post(f"/vaults/{vid}/files", files=[("files", (unique("f") + ".txt", b"x", "text/plain"))])
    assert up.status_code in (200, 201), up.text
    listed = None
    for _ in range(25):
        listed = _events(admin, vault_id=vid)
        if listed["total"] >= 1:
            break
        time.sleep(0.2)
    in_vault = exported(vault_id=vid)
    assert len(in_vault) == listed["total"] >= 1
    assert all(e["resource_id"] == vid or (e["details"] or {}).get("vault_id") == vid for e in in_vault)
    assert exported(vault_id="not-an-id") == []
    time.sleep(0.3)
    recorded = _events(admin, q=prefix, action="audit_exported")["events"]
    assert [e["details"]["filters"] for e in recorded] == [
        {"user": prefix, "no_account": True},
        {"user": prefix, "user_match": "exact"},
        {"user": f"{prefix}-1", "user_match": "exact"},
        {"user": prefix, "action": ["login_success"]},
        {"user": prefix, "action": ["login_failure"]},
    ]


def test_a_date_at_the_edge_of_the_calendar_is_not_an_error(admin):
    # The calendar's last day runs to its end; an instant that is off the calendar in UTC is no date.
    for params in ({"to_date": "9999-12-31"}, {"from_date": "0001-01-01T00:00:00+01:00"},
                   {"to_date": "9999-12-31T23:30:00-01:00"}):
        assert admin.get("/activity/events", params={"limit": 1, **params}).status_code == 200, params
        assert admin.get("/activity/summary", params=params).status_code == 200, params


def test_an_export_refuses_an_unknown_format_and_a_non_admin(admin, temp_user_client):
    assert admin.get("/activity/export", params={"format": "xlsx"}).status_code == 422
    assert temp_user_client.get("/activity/export").status_code == 403


def _upload(client, vid, name, headers=None):
    up = client.post(f"/vaults/{vid}/files", files=[("files", (name, b"x" * 200, "text/plain"))],
                     headers=headers or {})
    assert up.status_code in (200, 201), up.text
    listing = client.get(f"/vaults/{vid}/files", headers=headers or {}).json()
    items = listing if isinstance(listing, list) else next(v for v in listing.values() if isinstance(v, list))
    return next(i["id"] for i in items if i.get("name") == name)


def _ranged_event(admin, client, vid, fid, headers=None):
    r = client.get(f"/vaults/{vid}/files/{fid}/download", headers={"Range": "bytes=0-9", **(headers or {})})
    assert r.status_code == 206, r.status_code
    time.sleep(0.5)
    rows = [e for e in _events(admin, q=fid, category="files")["events"] if e["action"] == "file_download_range"]
    assert len(rows) == 1, rows
    return rows[0]


def test_names_are_shown_for_a_vault_the_admin_can_open(admin, temp_vault):
    name = unique("plan") + ".txt"
    fid = _upload(admin, temp_vault["id"], name)
    ev = _ranged_event(admin, admin, temp_vault["id"], fid)
    assert ev["names"] == {"vault": temp_vault["name"], "item": name}
    assert ev["username"] == admin.get("/users/me").json()["username"]    # not "Unknown"
    assert name not in str(ev["details"])                      # shown, never stored


def test_names_are_withheld_for_a_vault_the_admin_is_not_in(admin, temp_user_client):
    from app.services.activity_names import DELETED_VAULT, NOT_SHOWN
    vault = temp_user_client.create_vault()
    fid = _upload(temp_user_client, vault["id"], unique("private") + ".txt")
    ev = _ranged_event(admin, temp_user_client, vault["id"], fid)
    assert ev["names"] == {"vault": NOT_SHOWN, "item": NOT_SHOWN}
    assert temp_user_client.delete_vault(vault["id"]).status_code == 200
    again = [e for e in _events(admin, q=fid, category="files")["events"] if e["id"] == ev["id"]][0]
    assert again["names"]["vault"] == DELETED_VAULT


def test_names_follow_a_department_grant(admin, temp_user_client):
    from app.services.activity_names import NOT_SHOWN
    vault = temp_user_client.create_vault()
    name = unique("dept-file") + ".txt"
    fid = _upload(temp_user_client, vault["id"], name)
    ev = _ranged_event(admin, temp_user_client, vault["id"], fid)
    assert ev["names"]["item"] == NOT_SHOWN
    group = admin.post("/groups", json={"name": unique("readers")}).json()
    try:
        me = admin.get("/users/me").json()["id"]
        assert admin.post(f"/groups/{group['id']}/members", json={"user_ids": [me]}).status_code == 200
        r = temp_user_client.post(f"/vaults/{vault['id']}/group-access",
                                  json={"group_id": group["id"], "permission": "read"})
        assert r.status_code == 200, r.text
        again = [e for e in _events(admin, q=fid, category="files")["events"] if e["id"] == ev["id"]][0]
        assert again["names"] == {"vault": vault["name"], "item": name}
    finally:
        admin.delete(f"/groups/{group['id']}")
        temp_user_client.delete_vault(vault["id"])


def test_file_names_stay_hidden_in_a_vault_with_a_password(admin, temp_vault_pw):
    from app.services.activity_names import PASSWORD_HIDDEN
    unlock = {"X-Vault-Password": temp_vault_pw["_password"]}
    fid = _upload(admin, temp_vault_pw["id"], unique("locked") + ".txt", headers=unlock)
    ev = _ranged_event(admin, admin, temp_vault_pw["id"], fid, headers=unlock)
    assert ev["names"] == {"vault": temp_vault_pw["name"], "item": PASSWORD_HIDDEN}


def test_zero_knowledge_file_names_are_hidden(admin):
    import os
    from conftest import create_zk_vault, ensure_ecc_keypair, zk_chunked_upload
    from app.services.activity_names import ZK_HIDDEN
    ensure_ecc_keypair(admin)
    before = admin.get("/settings").json().get("zero_knowledge_enabled", False)
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        label = unique("zk-label")
        vid = create_zk_vault(admin, name=label)["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": before})
    try:
        fid = zk_chunked_upload(admin, vid, unique("zk-secret") + ".txt", b"opaque" * 20, os.urandom(32))
        time.sleep(0.5)
        rows = [e for e in _events(admin, q=fid, category="files")["events"] if e["resource_id"] == fid]
        assert rows, "the upload wrote no row"
        assert rows[0]["names"] == {"vault": label, "item": ZK_HIDDEN}
    finally:
        admin.delete_vault(vid)
