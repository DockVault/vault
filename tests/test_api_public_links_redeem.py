"""Live API: the anonymous READ path of public file/folder links — redeem + grant + download.

Redemption mirrors the note-link contract (rate limits, secret prompt/lockout, kill switch, uniform
404, atomic single-use consume) but returns a short-lived single-use download GRANT bound to
(link, client ip) instead of content. The download endpoint takes the grant in an X-Download-Grant
HEADER, confines file_id to the link's target subtree (id_scope), re-validates every gate, and streams
the bytes. No login is involved on the read path.
"""
import os
import subprocess

import pytest

from conftest import unique

pytestmark = pytest.mark.integration

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql):
    return subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=20)


@pytest.fixture
def files_enabled(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_file_links_enabled", "public_note_link_user_cap")}
    admin.put("/settings", json={"public_file_links_enabled": True, "public_note_link_user_cap": 50})
    yield
    admin.put("/settings", json=snap)


def _mk_tag(admin, targets=("file", "folder"), **over):
    payload = {"name": unique("pltag"), "min_token_len": 6, "require_secret": "none",
               "min_pin_len": 4, "password_min_len": 8, "auto_enroll_new_users": True,
               "allowed_targets": list(targets)}
    payload.update(over)
    r = admin.post("/note-link-tags", json=payload)
    r.raise_for_status()
    return r.json()


def _upload(client, vid, name, content=b"hello world", folder_id=None):
    params = {"folder_id": folder_id} if folder_id else None
    r = client.post(f"/vaults/{vid}/files", files=[("files", (name, content, "text/plain"))], params=params)
    assert r.status_code in (200, 201), r.text


def _file_id(client, vid, name, folder_id=None):
    for it in client.get(f"/vaults/{vid}/files", params={"folder_id": folder_id} if folder_id else None).json()["items"]:
        if it.get("name") == name and it.get("type") == "file":
            return it["id"]
    raise AssertionError(f"file {name} not found")


def _mk_folder(client, vid, name, parent=None):
    body = {"name": name}
    if parent:
        body["parent_folder_id"] = parent
    r = client.post(f"/vaults/{vid}/folders", json=body)
    r.raise_for_status()
    return r.json()["folder"]["id"]


def _mk_file_link(admin, vid, fid, tag=None, **over):
    tag = tag or _mk_tag(admin)
    body = {"vault_id": vid, "target_type": "file", "target_file_id": fid, "tag_id": tag["id"]}
    body.update(over)
    r = admin.post("/public-links", json=body)
    r.raise_for_status()
    return r.json()


def _dl(anon, token, file_id, grant):
    return anon.get(f"/public-links/{token}/download/{file_id}",
                    headers={"X-Download-Grant": grant})


# --- happy paths ------------------------------------------------------------------------------------
def test_file_redeem_and_download(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "doc.txt", b"the file body bytes")
        fid = _file_id(admin, v["id"], "doc.txt")
        link = _mk_file_link(admin, v["id"], fid)
        token = link["token"]

        anon = admin.clone_anonymous()
        r = anon.post(f"/public-links/{token}/redeem", json={})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["kind"] == "file" and body["name"] == "doc.txt" and body["size"] == len(b"the file body bytes")
        grant = body["grant"]
        assert grant and body["file_id"] == fid

        d = _dl(anon, token, fid, grant)
        assert d.status_code == 200, d.text
        assert d.content == b"the file body bytes"
        # Owner's counters advanced.
        row = next(l for l in admin.get("/public-links").json()["links"] if l["id"] == link["id"])
        assert row["download_count"] >= 1 and row["use_count"] >= 1
    finally:
        admin.delete_vault(v["id"])


def test_folder_redeem_lists_and_downloads_child(admin, files_enabled):
    v = admin.create_vault()
    try:
        folder_id = _mk_folder(admin, v["id"], unique("dir"))
        _upload(admin, v["id"], "inside.txt", b"nested bytes", folder_id=folder_id)
        fid = _file_id(admin, v["id"], "inside.txt", folder_id=folder_id)
        tag = _mk_tag(admin, targets=("folder",))
        r0 = admin.post("/public-links", json={"vault_id": v["id"], "target_type": "folder",
                                              "target_folder_id": folder_id, "tag_id": tag["id"]})
        link = r0.json()
        token = link["token"]

        anon = admin.clone_anonymous()
        r = anon.post(f"/public-links/{token}/redeem", json={})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["kind"] == "folder"
        entry = next(e for e in body["entries"] if e["id"] == fid)
        assert entry["name"] == "inside.txt" and not entry["is_folder"]
        d = _dl(anon, token, fid, body["grant"])
        assert d.status_code == 200 and d.content == b"nested bytes"
    finally:
        admin.delete_vault(v["id"])


def test_password_link_redeem_flow(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "secret.txt", b"protected file")
        fid = _file_id(admin, v["id"], "secret.txt")
        tag = _mk_tag(admin, require_secret="password", password_min_len=8)
        link = _mk_file_link(admin, v["id"], fid, tag=tag, password="hunter2x")
        token = link["token"]
        anon = admin.clone_anonymous()
        # no secret -> 401 secret_required (no consume, no grant)
        r0 = anon.post(f"/public-links/{token}/redeem", json={})
        assert r0.status_code == 401 and r0.json()["detail"]["error"] == "secret_required"
        # wrong -> 401 wrong_secret
        r1 = anon.post(f"/public-links/{token}/redeem", json={"secret": "nope1234"})
        assert r1.status_code == 401 and r1.json()["detail"]["error"] == "wrong_secret"
        # correct -> grant, then download
        r2 = anon.post(f"/public-links/{token}/redeem", json={"secret": "hunter2x"})
        assert r2.status_code == 200
        d = _dl(anon, token, fid, r2.json()["grant"])
        assert d.status_code == 200 and d.content == b"protected file"
    finally:
        admin.delete_vault(v["id"])


# --- secret lockout ---------------------------------------------------------------------------------
def test_secret_lockout(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "p.txt")
        fid = _file_id(admin, v["id"], "p.txt")
        tag = _mk_tag(admin, require_secret="pin", min_pin_len=4)
        link = _mk_file_link(admin, v["id"], fid, tag=tag, pin="4321")
        token = link["token"]
        anon = admin.clone_anonymous()
        codes = [anon.post(f"/public-links/{token}/redeem", json={"secret": "0000"}).status_code for _ in range(5)]
        assert codes[:4] == [401, 401, 401, 401], codes
        assert codes[4] == 429, codes
        # even the correct pin is refused during lockout
        assert anon.post(f"/public-links/{token}/redeem", json={"secret": "4321"}).status_code == 429
    finally:
        admin.delete_vault(v["id"])


# --- kill switch / revoke / exhaustion --------------------------------------------------------------
def test_kill_switch_stops_redeem_and_download(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "k.txt", b"kill switch")
        fid = _file_id(admin, v["id"], "k.txt")
        token = _mk_file_link(admin, v["id"], fid)["token"]
        anon = admin.clone_anonymous()
        grant = anon.post(f"/public-links/{token}/redeem", json={}).json()["grant"]
        admin.put("/settings", json={"public_file_links_enabled": False})
        try:
            assert anon.post(f"/public-links/{token}/redeem", json={}).status_code == 404
            assert _dl(anon, token, fid, grant).status_code == 404
        finally:
            admin.put("/settings", json={"public_file_links_enabled": True})
    finally:
        admin.delete_vault(v["id"])


def test_revoke_stops_redeem(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "r.txt")
        fid = _file_id(admin, v["id"], "r.txt")
        link = _mk_file_link(admin, v["id"], fid)
        assert admin.post(f"/public-links/{link['id']}/revoke").status_code == 200
        anon = admin.clone_anonymous()
        assert anon.post(f"/public-links/{link['token']}/redeem", json={}).status_code == 404
    finally:
        admin.delete_vault(v["id"])


def test_max_uses_exhaustion_atomic(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "one.txt", b"one time")
        fid = _file_id(admin, v["id"], "one.txt")
        tag = _mk_tag(admin, max_uses_cap=1)
        token = _mk_file_link(admin, v["id"], fid, tag=tag, max_uses=1)["token"]
        anon = admin.clone_anonymous()
        assert anon.post(f"/public-links/{token}/redeem", json={}).status_code == 200
        assert anon.post(f"/public-links/{token}/redeem", json={}).status_code == 404
    finally:
        admin.delete_vault(v["id"])


# --- grant hardening --------------------------------------------------------------------------------
def test_grant_is_single_use(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "g.txt", b"single use")
        fid = _file_id(admin, v["id"], "g.txt")
        token = _mk_file_link(admin, v["id"], fid)["token"]
        anon = admin.clone_anonymous()
        grant = anon.post(f"/public-links/{token}/redeem", json={}).json()["grant"]
        assert _dl(anon, token, fid, grant).status_code == 200
        # the same grant cannot be reused
        assert _dl(anon, token, fid, grant).status_code == 404
    finally:
        admin.delete_vault(v["id"])


def test_missing_or_garbage_grant_is_404(admin, files_enabled):
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "h.txt")
        fid = _file_id(admin, v["id"], "h.txt")
        token = _mk_file_link(admin, v["id"], fid)["token"]
        anon = admin.clone_anonymous()
        # no grant header at all
        assert anon.get(f"/public-links/{token}/download/{fid}").status_code == 404
        # a made-up grant
        assert _dl(anon, token, fid, "not-a-real-grant").status_code == 404
    finally:
        admin.delete_vault(v["id"])


def test_grant_bound_to_its_link(admin, files_enabled):
    # A grant minted redeeming link A must not download through link B's URL.
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "a.txt", b"file a")
        _upload(admin, v["id"], "b.txt", b"file b")
        fa = _file_id(admin, v["id"], "a.txt")
        fb = _file_id(admin, v["id"], "b.txt")
        tok_a = _mk_file_link(admin, v["id"], fa)["token"]
        tok_b = _mk_file_link(admin, v["id"], fb)["token"]
        anon = admin.clone_anonymous()
        grant_a = anon.post(f"/public-links/{tok_a}/redeem", json={}).json()["grant"]
        # grant_a used on link B's download URL -> not bound to link B -> 404
        assert _dl(anon, tok_b, fb, grant_a).status_code == 404
    finally:
        admin.delete_vault(v["id"])


def test_file_id_outside_target_subtree_is_404(admin, files_enabled):
    # A file link to A must not let its grant fetch a different file B in the same vault.
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "a.txt", b"file a")
        _upload(admin, v["id"], "b.txt", b"file b")
        fa = _file_id(admin, v["id"], "a.txt")
        fb = _file_id(admin, v["id"], "b.txt")
        token = _mk_file_link(admin, v["id"], fa)["token"]
        anon = admin.clone_anonymous()
        grant = anon.post(f"/public-links/{token}/redeem", json={}).json()["grant"]
        # the grant is valid for THIS link, but file B is outside the link's target -> 404
        assert _dl(anon, token, fb, grant).status_code == 404
    finally:
        admin.delete_vault(v["id"])


def test_password_added_after_mint_blocks_download(admin, files_enabled):
    # A file password acquired AFTER the link was minted must bite on the next request. File passwords
    # are not settable through the API (an unimplemented feature), so this defense-in-depth gate is
    # exercised by injecting a password_hash directly, proving the download re-check refuses it.
    v = admin.create_vault()
    try:
        _upload(admin, v["id"], "late.txt", b"late lock")
        fid = _file_id(admin, v["id"], "late.txt")
        token = _mk_file_link(admin, v["id"], fid)["token"]
        anon = admin.clone_anonymous()
        grant = anon.post(f"/public-links/{token}/redeem", json={}).json()["grant"]
        out = _psql(f"UPDATE files SET password_hash='x' WHERE id='{fid}';")
        assert out.returncode == 0 and "UPDATE 1" in out.stdout, out.stderr or out.stdout
        assert _dl(anon, token, fid, grant).status_code == 404
    finally:
        admin.delete_vault(v["id"])
