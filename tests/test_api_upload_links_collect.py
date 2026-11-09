"""Upload links that collect properly: a clash is renamed, the uploader gets a receipt, the owner is told,
the page knows the owner's message and the deployment's name, and the owner can copy the link again.
"""
import os
import subprocess

import pytest

from conftest import unique

pytestmark = pytest.mark.integration

_MB = 1024 * 1024
DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    out = subprocess.run(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[:300]
    return out.stdout.strip()


@pytest.fixture
def receivers_enabled(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_receivers_enabled", "public_receiver_user_cap")}
    admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50})
    yield
    admin.put("/settings", json=snap)


def _mk_tag(admin, **over):
    payload = {"name": unique("rtag"), "min_token_len": 6, "require_secret": "none",
               "max_total_bytes_cap": 100 * _MB, "auto_enroll_new_users": True}
    payload.update(over)
    r = admin.post("/receiver-tags", json=payload)
    r.raise_for_status()
    return r.json()


def _mk_receiver(admin, **over):
    body = {"tag_id": _mk_tag(admin)["id"], "max_total_bytes": 10 * _MB}
    body.update(over)
    r = admin.post("/receivers", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def _upload(anon, token, filename, content):
    o = anon.post(f"/receivers/{token}/upload-session",
                  json={"filename": filename, "total_size": len(content), "total_chunks": 1})
    assert o.status_code == 200, o.text
    sid = o.json()["session_id"]
    c = anon.put(f"/receivers/{token}/upload-session/{sid}/chunks/0", data=content,
                 headers={"Content-Type": "application/octet-stream"})
    assert c.status_code == 200, c.text
    return anon.post(f"/receivers/{token}/upload-session/{sid}/complete", json={})


def test_a_same_name_upload_is_renamed_and_the_receipt_says_so(admin, receivers_enabled):
    rec = _mk_receiver(admin, label=unique("Drop"))
    anon = admin.clone_anonymous()
    first = _upload(anon, rec["token"], "report.pdf", b"first")
    assert first.status_code == 200, first.text
    one = first.json()
    assert one["name"] == "report.pdf" and one["renamed"] is False and one["sent_as"] == "report.pdf"
    assert len(one["reference"]) == 8 and one["reference"] == one["id"][:8].upper()
    assert one["received_at"].endswith("Z") and one["size"] == 5
    second = _upload(anon, rec["token"], "report.pdf", b"second one")
    assert second.status_code == 200, second.text
    two = second.json()
    assert two["renamed"] is True and two["sent_as"] == "report.pdf" and two["name"] == "report (2).pdf"
    third = _upload(anon, rec["token"], "report.pdf", b"third").json()
    assert third["name"] == "report (3).pdf"
    # Both are in the drop vault, nothing overwritten.
    names = sorted(f["name"] for f in admin.get(f"/vaults/{rec['vault_id']}/files").json()["items"])
    assert names == ["report (2).pdf", "report (3).pdf", "report.pdf"]
    assert admin.get(f"/vaults/{rec['vault_id']}/files/{one['id']}/download").content == b"first"


def test_the_owner_is_told_once_an_hour_per_link(admin, receivers_enabled):
    label = unique("Told")
    rec = _mk_receiver(admin, label=label)
    anon = admin.clone_anonymous()
    assert _upload(anon, rec["token"], "a.txt", b"a").status_code == 200
    assert _upload(anon, rec["token"], "b.txt", b"b").status_code == 200
    notes = [n for n in admin.get("/notifications").json()["notifications"]
             if n.get("type") == "receiver_upload" and label in (n.get("title") or "")]
    assert len(notes) == 1, notes
    assert notes[0]["target"] == "#uploadlinks/drops"
    # The notice names the link's label, never the uploaded file: a file's name is sealed at rest.
    body = notes[0].get("body") or ""
    assert body.startswith(f"A file arrived on {label}.") and "a.txt" not in body and "b.txt" not in body


def test_the_message_and_the_brand_reach_the_upload_page(admin, receivers_enabled):
    rec = _mk_receiver(admin, message="  Please send the signed pages.\n\nThanks!  ")
    anon = admin.clone_anonymous()
    page = anon.get(f"/receivers/{rec['token']}/page")
    assert page.status_code == 200, page.text
    body = page.json()
    assert body["message"] == "Please send the signed pages.\n\nThanks!"
    assert body["secret_kind"] == "none" and isinstance(body["brand"], str)
    mine = next(r for r in admin.get("/receivers").json()["receivers"] if r["id"] == rec["id"])
    assert mine["message"] == "Please send the signed pages.\n\nThanks!" and mine["has_token_copy"] is False
    # A link that is not usable answers the uniform 404; a message too long is refused.
    assert anon.get("/receivers/nosuchtoken000/page").status_code == 404
    assert admin.post(f"/receivers/{rec['id']}/revoke").status_code == 200
    assert anon.get(f"/receivers/{rec['token']}/page").status_code == 404
    # A message too long is refused before anything is made: the drop vault is committed first, so a message
    # checked after it left a vault with no link behind.
    vaults_before = len(admin.get("/vaults").json())
    r = admin.post("/receivers", json={"tag_id": _mk_tag(admin)["id"], "max_total_bytes": 10 * _MB, "message": "x" * 501})
    assert r.status_code == 400 and "500" in r.text
    assert len(admin.get("/vaults").json()) == vaults_before


def test_a_protected_links_message_is_behind_its_code(admin, receivers_enabled):
    """The page of a PIN or password link shows only the brand and that a code is asked for; the owner's
    message comes with the session the accepted code opens, as the public file and note pages keep theirs."""
    tag = _mk_tag(admin, require_secret="pin", min_pin_len=4)
    rec = _mk_receiver(admin, tag_id=tag["id"], pin="4321", message="Send the signed pages.")
    anon = admin.clone_anonymous()
    page = anon.get(f"/receivers/{rec['token']}/page")
    assert page.status_code == 200, page.text
    assert page.json()["secret_kind"] == "pin" and page.json()["message"] is None
    assert "Send the signed" not in page.text
    wrong = anon.post(f"/receivers/{rec['token']}/upload-session",
                      json={"filename": "a.txt", "total_size": 1, "total_chunks": 1, "secret": "0000"})
    assert wrong.status_code == 401 and "Send the signed" not in wrong.text
    opened = anon.post(f"/receivers/{rec['token']}/upload-session",
                       json={"filename": "a.txt", "total_size": 1, "total_chunks": 1, "secret": "4321"})
    assert opened.status_code == 200, opened.text
    assert opened.json()["message"] == "Send the signed pages."


def test_the_owner_can_store_and_read_a_re_copy_of_the_link(admin, receivers_enabled):
    rec = _mk_receiver(admin)
    import base64
    # A well-formed container header ("DVZ2", version 2, kind 6), opaque beyond that: the server checks the shape only.
    raw = b"DVZ2" + bytes([0x02, 0x06, 0, 0]) + b"\x00" * 140
    blob = base64.b64encode(raw).decode()
    assert admin.get(f"/receivers/{rec['id']}/token-copy").status_code == 404
    put = admin.put(f"/receivers/{rec['id']}/token-copy", json={"token_enc": blob})
    assert put.status_code == 200, put.text
    assert admin.get(f"/receivers/{rec['id']}/token-copy").json()["token_enc"] == blob
    assert admin.put(f"/receivers/{rec['id']}/token-copy", json={"token_enc": blob}).status_code == 409   # write-once
    mine = next(r for r in admin.get("/receivers").json()["receivers"] if r["id"] == rec["id"])
    assert mine["has_token_copy"] is True
    # Replacing the link retires the re-copy with the URL it was a copy of: the card stops offering a dead
    # link, and the write-once slot is free for a copy of the new one.
    assert admin.post(f"/receivers/{rec['id']}/replace-link").status_code == 200
    assert admin.get(f"/receivers/{rec['id']}/token-copy").status_code == 404
    mine = next(r for r in admin.get("/receivers").json()["receivers"] if r["id"] == rec["id"])
    assert mine["has_token_copy"] is False
    put = admin.put(f"/receivers/{rec['id']}/token-copy", json={"token_enc": blob})
    assert put.status_code == 200, put.text
    assert admin.get(f"/receivers/{rec['id']}/token-copy").json()["token_enc"] == blob
    # Someone else gets the uniform 404; a revoked link's copy is gone.
    u = admin.create_user(role="user")
    try:
        from conftest import ApiClient
        c = ApiClient(); c.login(u["_username"], u["_password"])
        assert c.get(f"/receivers/{rec['id']}/token-copy").status_code == 404
    finally:
        admin.delete_user(u["id"])
    admin.post(f"/receivers/{rec['id']}/revoke")
    assert admin.get(f"/receivers/{rec['id']}/token-copy").status_code == 404


def test_public_and_note_links_carry_the_message_to_their_pages(admin):
    before = admin.get("/settings").json()
    admin.put("/settings", json={"public_file_links_enabled": True, "public_note_links_enabled": True})
    v = admin.create_vault(name=unique("msg"))
    try:
        fid = admin.post(f"/vaults/{v['id']}/files", files=[("files", ("a.txt", b"x", "text/plain"))]).json()["files"][0]["id"]
        ltag = admin.post("/note-link-tags", json={"name": unique("lt"), "auto_enroll_new_users": True,
                                                     "allowed_targets": ["file", "folder", "note"]})
        if ltag.status_code != 200:
            pytest.skip(f"no public-link tag here: {ltag.status_code} {ltag.text[:100]}")
        link = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "file", "target_file_id": fid,
                                                  "tag_id": ltag.json()["id"], "message": "The slides, as promised."})
        assert link.status_code == 200, link.text
        anon = admin.clone_anonymous()
        peek = anon.post(f"/public-links/{link.json()['token']}/redeem", json={"peek": True})
        assert peek.status_code == 200, peek.text
        assert peek.json()["message"] == "The slides, as promised." and "brand" in peek.json()
        mine = next(l for l in admin.get("/public-links").json()["links"] if l["id"] == link.json()["id"])
        assert mine["message"] == "The slides, as promised."
        ntag = admin.post("/note-link-tags", json={"name": unique("nt"), "auto_enroll_new_users": True})
        note = admin.post("/notes", json={"title": unique("n"), "body": "hello"}).json()
        body = {"note_id": note["id"], "message": "Read before the call."}
        if ntag.status_code == 200:
            body["tag_id"] = ntag.json()["id"]
        nlink = admin.post("/note-links", json=body)
        if nlink.status_code not in (200, 201):
            pytest.skip(f"no note link here: {nlink.status_code} {nlink.text[:100]}")
        npeek = anon.post(f"/note-links/{nlink.json()['token']}/redeem", json={"peek": True})
        assert npeek.status_code == 200 and npeek.json()["message"] == "Read before the call."
        full = anon.post(f"/note-links/{nlink.json()['token']}/redeem", json={})
        assert full.status_code == 200 and full.json()["message"] == "Read before the call." and "brand" in full.json()
    finally:
        admin.delete_vault(v["id"])
        admin.put("/settings", json={"public_file_links_enabled": before.get("public_file_links_enabled"),
                                     "public_note_links_enabled": before.get("public_note_links_enabled")})
