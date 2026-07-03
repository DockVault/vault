"""Security: cross-vault file access is rejected (vault-password gate bypass regression).

A file may only be reached through ITS OWN vault's path. Routing a file_id through a
DIFFERENT vault's path (one the caller can open — e.g. their own unprotected vault) must
NOT serve, delete, or rename it. The vault password is checked against the *path* vault, so
if the file could belong to another vault the password second factor would be bypassed.
"""
from conftest import unique


def _upload(client, vault_id, name, content, password=None):
    files = [("files", (name, content, "text/plain"))]
    headers = {"X-Vault-Password": password} if password else None
    return client.post(f"/vaults/{vault_id}/files", files=files, headers=headers)


def test_download_rejects_file_from_a_different_vault(admin):
    a = admin.create_vault()
    b = admin.create_vault()
    try:
        fid = _upload(admin, b["id"], unique("f") + ".txt", b"vault-B-secret").json()["files"][0]["id"]
        # legit: through B's own path it downloads
        assert admin.get(f"/vaults/{b['id']}/files/{fid}/download").status_code == 200
        # cross-vault: through A's path it must NOT serve B's file
        r = admin.get(f"/vaults/{a['id']}/files/{fid}/download")
        assert r.status_code == 404, f"file in B downloadable via A's path (got {r.status_code})"
    finally:
        admin.delete_vault(a["id"])
        admin.delete_vault(b["id"])


def test_vault_password_not_bypassed_via_foreign_vault_path(admin):
    pw = "Vault-Secret-123"
    a = admin.create_vault()             # no password
    b = admin.create_vault(password=pw)  # password-protected
    try:
        fid = _upload(admin, b["id"], unique("f") + ".txt", b"protected", password=pw).json()["files"][0]["id"]
        # Through A (password-less) with NO vault password: must be denied, NOT served.
        r = admin.get(f"/vaults/{a['id']}/files/{fid}/download")
        assert r.status_code == 404, f"password vault B bypassed via A's path (got {r.status_code})"
        # The legit path still REQUIRES B's password...
        assert admin.get(f"/vaults/{b['id']}/files/{fid}/download").status_code in (401, 403)
        # ...and works with it.
        ok = admin.get(f"/vaults/{b['id']}/files/{fid}/download", headers={"X-Vault-Password": pw})
        assert ok.status_code == 200 and ok.content == b"protected"
    finally:
        admin.delete_vault(a["id"])
        admin.delete_vault(b["id"], vault_password=pw)


def test_delete_rejects_file_from_a_different_vault(admin):
    a = admin.create_vault()
    b = admin.create_vault()
    try:
        fid = _upload(admin, b["id"], unique("f") + ".txt", b"keep me").json()["files"][0]["id"]
        r = admin.post(f"/vaults/{a['id']}/files/{fid}/delete")
        assert r.status_code == 404, f"file in B deletable via A's path (got {r.status_code})"
        # the file must still be there
        assert admin.get(f"/vaults/{b['id']}/files/{fid}/download").status_code == 200, "file was wrongly deleted"
    finally:
        admin.delete_vault(a["id"])
        admin.delete_vault(b["id"])


def test_rename_rejects_file_from_a_different_vault(admin):
    a = admin.create_vault()
    b = admin.create_vault()
    try:
        fid = _upload(admin, b["id"], unique("f") + ".txt", b"data").json()["files"][0]["id"]
        r = admin.put(f"/vaults/{a['id']}/files/{fid}/rename", json={"new_name": unique("x") + ".txt"})
        assert r.status_code == 404, f"file in B renamable via A's path (got {r.status_code})"
    finally:
        admin.delete_vault(a["id"])
        admin.delete_vault(b["id"])
