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
