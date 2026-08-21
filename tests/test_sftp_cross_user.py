"""SFTP cross-USER isolation for regular accounts, with a positive control.

Existing SFTP cross-tenant tests cover temp-credential principals, or the empty case (a freshly-keyed
user who owns nothing -- which passes even with no per-user filtering at all). This asserts the real
property: two REGULAR users each with a vault, connecting over SFTP with their own key -- user A sees
ONLY A's vault and never B's.
"""
import contextlib
import os

import pytest

paramiko = pytest.importorskip("paramiko")

from conftest import unique  # noqa: E402

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))

pytestmark = pytest.mark.sftp


def _gen_rsa():
    k = paramiko.RSAKey.generate(2048)
    return k, f"{k.get_name()} {k.get_base64()}"


@contextlib.contextmanager
def _key_conn(username, pkey):
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    try:
        t.connect(username=username, pkey=pkey)
        yield t
    finally:
        t.close()


def _ls_root(transport):
    s = paramiko.SFTPClient.from_transport(transport)
    try:
        return s.listdir("/")
    finally:
        s.close()


def test_regular_user_cannot_see_another_users_vault_over_sftp(admin):
    a = admin.create_user(role="user")
    b = admin.create_user(role="user")
    va = admin.create_vault(name=unique("sftpA"))
    vb = admin.create_vault(name=unique("sftpB"))
    admin.post(f"/vaults/{va['id']}/permissions", json={"user_id": a["id"], "level": "read"})
    admin.post(f"/vaults/{vb['id']}/permissions", json={"user_id": b["id"], "level": "read"})
    pk, pub = _gen_rsa()
    assert admin.post(f"/users/{a['id']}/ssh-keys",
                      json={"name": "isolation-key", "public_key": pub}).status_code == 200
    try:
        with _key_conn(a["_username"], pk) as t:
            root = _ls_root(t)
        # positive control: A really does see their own vault (so an EMPTY listing can't pass by accident)
        assert va["name"] in root, "user A must see their OWN vault over SFTP (got %r)" % root
        # the actual isolation property
        assert vb["name"] not in root, "user A must NOT see user B's vault over SFTP (got %r)" % root
    finally:
        admin.delete_vault(va["id"])
        admin.delete_vault(vb["id"])
        admin.delete_user(a["id"])
        admin.delete_user(b["id"])
