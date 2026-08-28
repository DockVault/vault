"""A zero-knowledge download must not cost the file either.

The bounded-download work was measured against standard vaults, and a figure taken there says
nothing about this path: the two share an endpoint but not a reader. A zero-knowledge blob is the
client's ciphertext stored verbatim -- one opaque object with no record structure, no terminal, and
no key on the server -- so it is served in fixed windows rather than records, and the only integrity
statement the server can make about it is the stored checksum, which is over the ciphertext.

Without these, a budget run against a standard vault would pass while this path still cost twice
the file, and nothing would say so.
"""

import contextlib
import hashlib
import os
import subprocess

import pytest

from memory_probe import CgroupSampler
from conftest import (
    create_zk_vault, ensure_ecc_keypair, skip_if_container_absent, unique,
    zk_chunked_upload, ZK_WRAPPED_DEK_STUB,
)


MB = 1024 * 1024
DEK = b"zk-download-budget-dek-32-bytes!"[:32]


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


@pytest.mark.slow
def test_a_zero_knowledge_download_does_not_cost_the_file(admin):
    """The measurement the standard-vault budget cannot stand in for.

    The threshold is loose -- a third of the file -- because this distinguishes "scales with the
    file" from "does not". Before the download work this path held the whole ciphertext for the
    length of the response, so the rise was the file.

    Sampled continuously, not before-and-after. A peak only exists while the transfer is in
    flight; reading either side of it measures the residue instead, which is small whatever the
    server did. The first version of this test did that and passed against a build that held the
    whole file.
    """
    size = 48 * MB
    body = bytes((i * 17 + 11) % 256 for i in range(65536)) * (size // 65536)

    with _zk_enabled(admin):
        ensure_ecc_keypair(admin)
        vault = create_zk_vault(admin, name=unique("zkbudget"))
        try:
            file_id = zk_chunked_upload(
                admin, vault["id"], unique("blob") + ".bin", body, DEK,
                mime="application/octet-stream", chunk_size=MB)

            with CgroupSampler() as sampler:
                got = admin.get(f"/vaults/{vault['id']}/files/{file_id}/download")
            rise = sampler.rise

            assert got.status_code == 200, got.text
            assert got.content == body, (
                "the ciphertext did not round trip, so this measured nothing")

            assert rise < size // 3, (
                f"a {size // MB} MB zero-knowledge download raised allocated memory by "
                f"{rise / MB:.1f} MB; the blob is being held rather than streamed")
        finally:
            admin.delete_vault(vault["id"])


def test_a_zero_knowledge_download_returns_the_stored_ciphertext(admin):
    """Byte parity, at sizes either side of the window the server reads in.

    The server has no key here: whatever the client stored is what must come back, exactly. A
    window-sized file, one a byte over, and one a byte under all take different paths through the
    final-window hold-back.
    """
    with _zk_enabled(admin):
        ensure_ecc_keypair(admin)
        vault = create_zk_vault(admin, name=unique("zkparity"))
        try:
            for size in (1, MB - 1, MB, MB + 1, 3 * MB + 7):
                body = bytes((i * 29 + 3) % 256 for i in range(min(size, 65536)))
                body = (body * (size // len(body) + 1))[:size]
                file_id = zk_chunked_upload(
                    admin, vault["id"], unique("p") + ".bin", body, DEK,
                    mime="application/octet-stream", chunk_size=MB)

                got = admin.get(f"/vaults/{vault['id']}/files/{file_id}/download")
                assert got.status_code == 200, got.text
                assert hashlib.sha256(got.content).hexdigest() == \
                    hashlib.sha256(body).hexdigest(), f"round trip differed at {size} bytes"
                assert got.headers.get("Content-Length") == str(size)
        finally:
            admin.delete_vault(vault["id"])


def test_a_zero_knowledge_download_never_serves_a_plaintext_name_or_type(admin):
    """The server holds an encrypted name and must not offer a guess at the real one.

    Not a memory property, but it shares the code path that was rewritten, and a regression here
    would leak exactly what a zero-knowledge vault exists to keep.
    """
    with _zk_enabled(admin):
        ensure_ecc_keypair(admin)
        vault = create_zk_vault(admin, name=unique("zkname"))
        try:
            body = b"opaque" * 100
            file_id = zk_chunked_upload(
                admin, vault["id"], "secret-invoice.pdf", body, DEK,
                mime="application/pdf", chunk_size=MB)

            got = admin.get(f"/vaults/{vault['id']}/files/{file_id}/download")
            assert got.status_code == 200
            assert got.headers.get("Content-Type", "").startswith("application/octet-stream"), (
                f"the response advertised {got.headers.get('Content-Type')!r}")
            disposition = got.headers.get("Content-Disposition", "")
            assert "secret-invoice" not in disposition, (
                f"the encrypted name leaked through the response: {disposition!r}")
            assert "pdf" not in disposition.lower()
        finally:
            admin.delete_vault(vault["id"])


def test_a_corrupted_zero_knowledge_blob_is_not_served_as_a_success(admin):
    """The stored checksum is the only integrity statement available here, so it has to hold.

    It is over the ciphertext, and the hold-back withholds the final window until it has been
    checked -- so a client is left short of the declared length rather than given a complete
    response for a blob that no longer matches what was stored.
    """
    with _zk_enabled(admin):
        ensure_ecc_keypair(admin)
        vault = create_zk_vault(admin, name=unique("zkbad"))
        try:
            body = b"Z" * (2 * MB + 12345)
            file_id = zk_chunked_upload(
                admin, vault["id"], unique("bad") + ".bin", body, DEK,
                mime="application/octet-stream", chunk_size=MB)

            db = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
            broke = subprocess.run(
                ["docker", "exec", db, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc",
                 f"UPDATE files SET checksum_sha256 = repeat('d', 64), enc_checksum = NULL WHERE id = '{file_id}';"],
                capture_output=True, text=True, timeout=60)
            skip_if_container_absent(broke, db)
            assert broke.returncode == 0 and "UPDATE 1" in broke.stdout, (
                "did not rewrite the checksum of exactly one row, so the blob below still "
                f"matches its stored checksum and would be served legitimately: "
                f"rc={broke.returncode} out={broke.stdout.strip()[:120]} "
                f"err={broke.stderr.strip()[:120]}")

            import requests
            url = f"{admin.base_url}/vaults/{vault['id']}/files/{file_id}/download"
            try:
                served = len(admin.session.get(url, timeout=60).content)
            except requests.exceptions.ChunkedEncodingError:
                served = -1
            assert served != len(body), (
                "a blob whose checksum no longer matches was served in full")
        finally:
            admin.delete_vault(vault["id"])
