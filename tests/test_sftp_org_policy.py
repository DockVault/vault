"""Org-admin SFTP-auth policy (design §5): require a temporary credential for SFTP
for members of designated groups. Per-group by design (a global force would break
SSH-key automation). Stored in the admin Settings store under the key
'sftp_require_temp_cred_groups'; enforced in the SFTP auth path.
"""
import os
import contextlib

import pytest

paramiko = pytest.importorskip("paramiko")

from conftest import unique  # noqa: E402

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))


pytestmark = pytest.mark.sftp
_AUTH_ERR = (paramiko.SSHException, EOFError, OSError)


@contextlib.contextmanager
def _pw_conn(username, password):
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    try:
        t.connect(username=username, password=password)
        yield t
    finally:
        t.close()


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


def test_org_policy_group_requires_temp_cred(admin, temp_user):
    """A user in a 'require temp credential' group cannot use password or SSH-key
    SFTP. (Temp credentials bypass the policy by construction — the temp_ auth path
    never consults it — and are exercised by the other temp-cred SFTP tests.)"""
    uid, uname, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    gid = admin.post("/groups", json={"name": unique("highsec")}).json()["id"]
    assert admin.post(f"/groups/{gid}/members", json={"user_ids": [uid]}).status_code == 200
    assert admin.put("/settings", json={"sftp_require_temp_cred_groups": [gid]}).status_code == 200
    try:
        # direct password SFTP refused
        with pytest.raises(_AUTH_ERR):
            with _pw_conn(uname, pw):
                pass
        # SSH-key SFTP refused too
        pk = paramiko.RSAKey.generate(2048)
        admin.post(f"/users/{uid}/ssh-keys",
                   json={"name": "k", "public_key": f"{pk.get_name()} {pk.get_base64()}"})
        with pytest.raises(_AUTH_ERR):
            with _key_conn(uname, pk):
                pass
    finally:
        admin.put("/settings", json={"sftp_require_temp_cred_groups": []})


def test_org_policy_does_not_affect_other_groups(admin, temp_user):
    """A user who is NOT in a flagged group keeps normal password SFTP while the
    policy targets a different (here, empty) group."""
    gid = admin.post("/groups", json={"name": unique("hs")}).json()["id"]
    assert admin.put("/settings", json={"sftp_require_temp_cred_groups": [gid]}).status_code == 200
    try:
        # temp_user is not a member of gid -> unaffected
        with _pw_conn(temp_user["_username"], temp_user["_password"]) as t:
            _ls_root(t)
    finally:
        admin.put("/settings", json={"sftp_require_temp_cred_groups": []})
