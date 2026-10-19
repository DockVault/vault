"""Live API: a HEAD to any anonymous link route answers 405 and spends nothing.

Link checkers, crawlers and chat apps' previews send HEAD to learn about a URL. With a real note link,
a real file link and a real download grant, each route the links use is sent a HEAD: the note and file
link pages, the upload link page, both redeems, and the download with its grant in the header and in
the query. Each must answer 405, and afterwards nothing may have been spent: the note's view, the file
link's use, and the grant, which still downloads the file.
"""
import os
import time

import pytest
import requests

from conftest import unique

pytestmark = pytest.mark.integration


@pytest.fixture
def links_on(admin):
    keys = ("public_note_links_enabled", "public_file_links_enabled", "public_note_link_user_cap")
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in keys}
    r = admin.put("/settings", json={"public_note_links_enabled": True, "public_file_links_enabled": True,
                                     "public_note_link_user_cap": 100})
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


def _tag(admin, cap):
    r = admin.post("/note-link-tags", json={
        "name": unique("headtag"), "min_token_len": 20, "auto_enroll_new_users": True,
        "allowed_targets": ["note", "file", "folder"], "default_ttl_hours": 24, "max_ttl_hours": 24,
        "max_uses_cap": cap, "require_secret": "none"})
    assert r.status_code in (200, 201), r.text
    return r.json()


def _counts(admin, path, link_id, fields):
    found = {l["id"]: l for l in admin.get(path).json()["links"]}[link_id]
    return tuple(found[f] for f in fields)


def test_every_link_route_refuses_head_and_nothing_is_spent(admin, base_url, links_on):
    vault = admin.create_vault(name=unique("head"))
    try:
        content = os.urandom(30_000)
        name = unique("head") + ".bin"
        up = admin.post(f"/vaults/{vault['id']}/files", files=[("files", (name, content, "application/octet-stream"))])
        assert up.status_code in (200, 201), up.text
        file_id = next(it["id"] for it in admin.get(f"/vaults/{vault['id']}/files").json()["items"]
                       if it.get("name") == name)
        file_link = admin.post("/public-links", json={
            "vault_id": vault["id"], "target_type": "file", "target_file_id": file_id,
            "tag_id": _tag(admin, 1)["id"], "ttl_hours": 1, "max_uses": 1}).json()
        note_id = admin.post("/notes", json={"title": "Head", "body": "not for a HEAD"}).json()["id"]
        note_link = admin.post("/note-links", json={"note_id": note_id, "tag_id": _tag(admin, 1)["id"],
                                                    "max_uses": 1}).json()
        # A grant, as a Download click would have redeemed one; the HEADs below must leave it unused.
        grant = requests.post(f"{base_url}/public-links/{file_link['token']}/redeem", json={}, timeout=30).json()["grant"]
        download = f"{base_url}/public-links/{file_link['token']}/download/{file_id}"

        heads = [
            (f"{base_url}/p/{file_link['token']}", {}),
            (f"{base_url}/l/{note_link['token']}", {}),
            (f"{base_url}/u/not-a-real-upload-link-token", {}),
            (f"{base_url}/public-links/{file_link['token']}/redeem", {}),
            (f"{base_url}/note-links/{note_link['token']}/redeem", {}),
            (download, {"X-Download-Grant": grant}),
            (f"{download}?grant={grant}", {}),
        ]
        for url, headers in heads:
            r = requests.head(url, headers=headers, timeout=30)
            assert r.status_code == 405, (url.replace(base_url, ""), r.status_code)
            assert not r.content
        time.sleep(0.5)
        assert _counts(admin, "/note-links", note_link["id"], ("view_count", "use_count")) == (0, 0)
        assert _counts(admin, "/public-links", file_link["id"], ("use_count", "download_count")) == (1, 0)

        # The grant was not used by any of them: it downloads the file now.
        got = requests.get(f"{download}?grant={grant}", timeout=30)
        assert got.status_code == 200 and got.content == content
        # And the note's one view is still there to be spent.
        shown = requests.post(f"{base_url}/note-links/{note_link['token']}/redeem", json={}, timeout=30)
        assert shown.status_code == 200 and shown.json()["body"] == "not for a HEAD"
    finally:
        admin.delete_vault(vault["id"])
