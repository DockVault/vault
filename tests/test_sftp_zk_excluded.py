"""Zero-knowledge vaults are excluded from ALL SFTP paths (regression lock).

SFTP serves ONLY Standard vaults: a zero-knowledge vault has no server-side key, so the
server can neither list it nor open/upload/download its contents. This test LOCKS that
(already-correct) behavior against a future SFTP regression — a ZK vault must be invisible
in the SFTP root and unreachable by path, while a Standard vault the same user owns is
visible. (Root skip: app/sftp/sftp_server.py; _resolve_vault returns None for non-standard vaults,
which every file/dir op routes through.)
"""
import contextlib
import os

import pytest

paramiko = pytest.importorskip("paramiko")

from conftest import unique, ensure_ecc_keypair, create_zk_vault  # noqa: E402

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))


pytestmark = pytest.mark.sftp


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


@contextlib.contextmanager
def _zk_on(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def test_zk_vault_invisible_and_unreachable_over_sftp(admin, temp_user, temp_user_client):
    std_name = unique("sftpstd")
    zk_name = unique("sftpzk")
    ensure_ecc_keypair(temp_user_client)
    with _zk_on(admin):
        std = temp_user_client.create_vault(name=std_name)          # SFTP-visible
        zk = create_zk_vault(temp_user_client, name=zk_name)         # must be hidden over SFTP
    try:
        with _sftp(temp_user["_username"], temp_user["_password"]) as s:
            root = s.listdir("/")
            # The Standard vault IS listed (proves SFTP works + the ZK exclusion isn't just
            # "nothing is listed"); the ZK vault is NOT — its plaintext name would otherwise show.
            assert std_name in root, f"Standard vault should be visible over SFTP: {root}"
            assert zk_name not in root, f"ZK vault leaked into the SFTP root listing: {root}"
            # Every path op on the ZK vault fails (resolve -> None -> no such file), so there is
            # no list / stat / open(write) path to its contents over SFTP.
            with pytest.raises(IOError):
                s.listdir(f"/{zk_name}")
            with pytest.raises(IOError):
                s.stat(f"/{zk_name}")
            with pytest.raises(IOError):
                s.open(f"/{zk_name}/leak.txt", "w")
    finally:
        temp_user_client.delete_vault(std["id"])
        temp_user_client.delete_vault(zk["id"])
