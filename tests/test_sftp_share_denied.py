"""a whole-vault share claim grants NOTHING over SFTP.

Share authorization is opt-in (allow_share=True) only at the recipient's WEB read endpoints;
every SFTP call site keeps the default (allow_share=False), so a recipient holding a live web
claim still cannot enumerate or open the shared vault over SFTP. This is the fail-closed
guarantee for the shared REST+SFTP service methods (get_vault / download_file / list_vaults).
"""
import os
import socket
import contextlib

import pytest

paramiko = pytest.importorskip("paramiko")

from conftest import unique  # noqa: E402

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))


def _reachable() -> bool:
    try:
        with socket.create_connection((SFTP_HOST, SFTP_PORT), timeout=5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(not _reachable(), reason=f"SFTP not reachable at {SFTP_HOST}:{SFTP_PORT}")


@contextlib.contextmanager
def _sftp(username, password):
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    try:
        t.connect(username=username, password=password)
        s = paramiko.SFTPClient.from_transport(t)
        try:
            yield s
        finally:
            s.close()
    finally:
        t.close()


def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin):
    r = admin.post("/share-tags", json={
        "name": unique("sftag"), "auto_enroll_new_users": True,
        "allowed_audiences": ["anyone_internal"], "max_recipients_cap": 10})
    assert r.status_code == 200, r.text
    return r.json()


def _make_share(admin, v, tag):
    r = admin.post("/shares", json={
        "vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
        "claim_audience": "anyone_internal"})
    assert r.status_code == 200, r.text
    return r.json()


def test_whole_vault_share_claim_grants_nothing_over_sftp(admin, temp_user, temp_user_client):
    """A recipient with a LIVE web claim (control: web access works) still cannot see or open
    the shared vault over SFTP — it is neither listed at the SFTP root nor navigable by path."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("sftpshare"))
    vname = v["name"]
    try:
        admin.post(f"/vaults/{v['id']}/files",
                   files=[("files", ("f.txt", b"secret-bytes", "application/octet-stream"))])
        share = _make_share(admin, v, _tag(admin))

        # The recipient holds an active claim...
        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
        # ...and the share is genuinely live over the WEB (positive control).
        assert temp_user_client.get(f"/vaults/{v['id']}").status_code == 200

        # ...but SFTP grants nothing.
        with _sftp(temp_user["_username"], temp_user["_password"]) as s:
            root = set(s.listdir("/"))
            assert vname not in root, "shared vault must not be enumerated over SFTP"
            with pytest.raises((IOError, OSError)):
                s.listdir(f"/{vname}")  # opening the shared vault by path is denied
    finally:
        admin.delete_vault(v["id"])


def test_folder_share_claim_grants_nothing_over_sftp(admin, temp_user, temp_user_client):
    """Subtree-share SFTP denial: a folder-share recipient with a LIVE web claim still gets nothing
    over SFTP — the vault is neither enumerated nor navigable, and neither is the shared folder."""
    _enable_sharing(admin, True)
    v = admin.create_vault(name=unique("sftpfld"))
    vname = v["name"]
    try:
        fld = admin.post(f"/vaults/{v['id']}/folders", json={"name": "shared-dir"}).json()["folder"]["id"]
        admin.post(f"/vaults/{v['id']}/files", params={"folder_id": fld},
                   files=[("files", ("in.txt", b"secret", "application/octet-stream"))])
        r = admin.post("/shares", json={"vault_id": v["id"], "tag_id": _tag(admin)["id"],
                                        "target_type": "folder", "target_folder_id": fld,
                                        "claim_audience": "anyone_internal"})
        assert r.status_code == 200, r.text
        share = r.json()

        assert temp_user_client.post("/shares/claim", json={"token": share["link_token"]}).status_code == 200
        # the recipient can list the shared folder over the WEB (positive control)
        assert temp_user_client.get(f"/vaults/{v['id']}/files", params={"folder_id": fld}).status_code == 200

        with _sftp(temp_user["_username"], temp_user["_password"]) as s:
            assert vname not in set(s.listdir("/")), "shared folder's vault must not be enumerated over SFTP"
            with pytest.raises((IOError, OSError)):
                s.listdir(f"/{vname}")            # the vault is not navigable
            with pytest.raises((IOError, OSError)):
                s.listdir(f"/{vname}/shared-dir")  # nor the shared folder
    finally:
        admin.delete_vault(v["id"])
