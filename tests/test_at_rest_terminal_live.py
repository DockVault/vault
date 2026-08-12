"""Format `0x20` reaching disk through the real upload path.

Separate from the offline format tests because it needs a running deployment, and the repository
forbids one module being both unit and integration.

Everything offline builds blobs by calling the codec directly. That proves the format and proves
nothing about whether the write path uses it -- or, more to the point, whether it remembers to
write the terminal. A writer that never terminated would pass every offline test and produce files
no reader will ever accept.
"""

import os

import pytest


pytestmark = pytest.mark.integration

def test_a_real_upload_is_written_in_the_terminated_format(admin):
    """The format reaching disk through the actual write path.

    Everything above builds blobs by calling the codec directly, which proves the format and
    proves nothing about whether the upload path uses it -- or, more importantly, whether it
    remembers to write the terminal. A writer that never terminated would pass every test above
    and produce files that no reader will ever accept.
    """
    import subprocess
    from conftest import unique

    vault = admin.post("/vaults", json={"name": unique("terminal")})
    vault.raise_for_status()
    vid = vault.json()["id"]
    try:
        body = bytes((i * 17 + 3) % 256 for i in range(300_000))    # several records
        made = admin.post(f"/vaults/{vid}/files",
                          files=[("files", ("blob.bin", body, "application/octet-stream"))])
        assert made.status_code == 200, made.text
        fid = made.json()["files"][0]["id"]

        got = admin.get(f"/vaults/{vid}/files/{fid}/download")
        assert got.status_code == 200 and got.content == body, "the file did not round trip"

        container = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
        sql = "SELECT storage_path FROM files WHERE id = '%s'" % fid
        rel = subprocess.run(
            ["docker", "exec", container, "sh", "-c",
             'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc "%s"' % sql],
            capture_output=True, text=True, timeout=60).stdout.strip()
        assert rel, "no storage_path recorded"

        api = os.environ.get("VAULT_API_CONTAINER", "vault-api")
        head = subprocess.run(
            ["docker", "exec", api, "sh", "-c",
             "head -c 12 '/app/storage/%s' | od -An -tx1" % rel],
            capture_output=True, text=True, timeout=60).stdout.split()
        assert head, "could not read the stored header"
        assert bytes.fromhex("".join(head))[:9] == b"DockVault"
        assert bytes.fromhex("".join(head))[9] == 0x20, (
            f"the write path did not use the terminated format: version byte {head[9]}")

        tail = subprocess.run(
            ["docker", "exec", api, "sh", "-c",
             "tail -c 32 '/app/storage/%s' | od -An -tx1" % rel],
            capture_output=True, text=True, timeout=60).stdout.split()
        assert bytes.fromhex("".join(tail))[:4] == b"\xff\xff\xff\xff", (
            "the stream does not end with a terminal record")

        # More than one data record actually reached disk. Without this the payload could shrink
        # back under the read size and the multi-record case would silently stop being covered --
        # a writer binding a fixed count of one would then round trip and look correct.
        size = int(subprocess.run(
            ["docker", "exec", api, "sh", "-c", "wc -c < '/app/storage/%s'" % rel],
            capture_output=True, text=True, timeout=60).stdout.strip())
        assert size > len(body) + 12 + 28 + 28, (
            f"{size} stored bytes for {len(body)} plaintext implies a single record; the "
            "multi-record path is not being exercised")
    finally:
        admin.delete_vault(vid)
