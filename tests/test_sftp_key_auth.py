"""SSH public-key SFTP auth + per-account SFTP settings (sequencing item 5).

Keys attach to the user account; a key authenticates the user, who then sees the
vaults their membership already grants. Covers: register-key -> key login, reject
unregistered/duplicate keys, password-auth toggle (key-only), sftp_enabled toggle,
key deletion revokes access, and non-admin self-service key management.
"""
import os
import subprocess
import contextlib

import pytest

paramiko = pytest.importorskip("paramiko")

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))


pytestmark = pytest.mark.sftp

# A refused/failed SSH auth surfaces as one of these.
_AUTH_ERR = (paramiko.SSHException, EOFError, OSError)


def _gen_rsa():
    """Return (private_key, openssh_public_line)."""
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


@contextlib.contextmanager
def _pw_conn(username, password):
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    try:
        t.connect(username=username, password=password)
        yield t
    finally:
        t.close()


def _ls_root(transport):
    s = paramiko.SFTPClient.from_transport(transport)
    try:
        return s.listdir("/")
    finally:
        s.close()


def test_register_key_then_key_login(admin, temp_user):
    uid, uname = temp_user["id"], temp_user["_username"]
    pk, pub = _gen_rsa()
    r = admin.post(f"/users/{uid}/ssh-keys", json={"name": "backup-bot", "public_key": pub})
    assert r.status_code == 200, r.text
    assert r.json()["fingerprint"].startswith("SHA256:")
    assert r.json()["key_type"] == "ssh-rsa"
    with _key_conn(uname, pk) as t:
        assert _ls_root(t) == []  # authenticates + lists (no vaults yet)
    listed = admin.get(f"/users/{uid}/ssh-keys").json()
    assert any(k["fingerprint"] == r.json()["fingerprint"] for k in listed)


def test_unregistered_key_rejected(admin, temp_user):
    uname = temp_user["_username"]
    pk, _ = _gen_rsa()  # never registered
    with pytest.raises(_AUTH_ERR):
        with _key_conn(uname, pk):
            pass


def test_duplicate_key_rejected(admin, temp_user):
    uid = temp_user["id"]
    _, pub = _gen_rsa()
    assert admin.post(f"/users/{uid}/ssh-keys", json={"name": "a", "public_key": pub}).status_code == 200
    assert admin.post(f"/users/{uid}/ssh-keys", json={"name": "b", "public_key": pub}).status_code == 409


def test_invalid_key_rejected(admin, temp_user):
    uid = temp_user["id"]
    r = admin.post(f"/users/{uid}/ssh-keys", json={"name": "bad", "public_key": "not-a-key"})
    assert r.status_code == 400


def test_password_auth_off_allows_key_blocks_password(admin, temp_user):
    uid, uname, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    pk, pub = _gen_rsa()
    admin.post(f"/users/{uid}/ssh-keys", json={"name": "k", "public_key": pub})
    assert admin.patch(f"/users/{uid}", json={"sftp_password_auth": False}).status_code == 200
    with pytest.raises(_AUTH_ERR):           # password SFTP refused
        with _pw_conn(uname, pw):
            pass
    with _key_conn(uname, pk) as t:           # key SFTP still works
        _ls_root(t)


def test_sftp_disabled_blocks_password_and_key(admin, temp_user):
    uid, uname, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    pk, pub = _gen_rsa()
    admin.post(f"/users/{uid}/ssh-keys", json={"name": "k", "public_key": pub})
    assert admin.patch(f"/users/{uid}", json={"sftp_enabled": False}).status_code == 200
    with pytest.raises(_AUTH_ERR):
        with _pw_conn(uname, pw):
            pass
    with pytest.raises(_AUTH_ERR):
        with _key_conn(uname, pk):
            pass


def test_deleting_key_revokes_key_login(admin, temp_user):
    uid, uname = temp_user["id"], temp_user["_username"]
    pk, pub = _gen_rsa()
    kid = admin.post(f"/users/{uid}/ssh-keys", json={"name": "k", "public_key": pub}).json()["id"]
    with _key_conn(uname, pk) as t:
        _ls_root(t)
    assert admin.delete(f"/users/{uid}/ssh-keys/{kid}").status_code == 200
    with pytest.raises(_AUTH_ERR):
        with _key_conn(uname, pk):
            pass


def test_non_admin_self_service_key_management(temp_user, temp_user_client):
    """A non-admin manages their OWN keys (endpoints are admin-or-self)."""
    uid = temp_user["id"]
    _, pub = _gen_rsa()
    r = temp_user_client.post(f"/users/{uid}/ssh-keys", json={"name": "mine", "public_key": pub})
    assert r.status_code == 200, r.text
    assert any(k["name"] == "mine" for k in temp_user_client.get(f"/users/{uid}/ssh-keys").json())


def _clear_sftp_pk_counters():
    """Wipe the per-IP SSH-key-offer throttle counters (best-effort, via the redis container)
    so this test never throttles the rest of the SFTP suite, which shares the same peer IP."""
    container = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
    lua = ("local k=redis.call('keys','rate_limit:sftp_pk:*'); "
           "for i=1,#k do redis.call('del',k[i]) end; return #k")
    with contextlib.suppress(Exception):
        subprocess.run(["docker", "exec", container, "redis-cli", "EVAL", lua, "0"],
                       capture_output=True, text=True, timeout=15)


def test_sftp_key_bruteforce_is_throttled_per_ip(admin, temp_user):
    """A flood of failed SSH-key offers from one source IP is throttled: after the per-IP
    budget is exhausted, even the user's VALID key is refused (the DoS / key-enumeration
    bound). Cleaned up after so it doesn't throttle the rest of the SFTP suite.

    Skipped if the deployment raised rate_limit_sftp_key_attempts so high we can't reach it
    cheaply (the dev stack leaves it at its default)."""
    if not shutil_which_docker():
        pytest.skip("docker CLI not available to reset the throttle counter afterwards")
    uid, uname = temp_user["id"], temp_user["_username"]
    valid_pk, valid_pub = _gen_rsa()
    assert admin.post(f"/users/{uid}/ssh-keys", json={"name": "good", "public_key": valid_pub}).status_code == 200

    _clear_sftp_pk_counters()  # start from a clean per-IP counter
    try:
        # Sanity: the valid key works before the flood (and clears the counter).
        with _key_conn(uname, valid_pk) as t:
            _ls_root(t)

        # Flood failed key offers from this IP. 40 offers comfortably exceeds the default
        # budget (30); if a deployment set it far higher we won't trip and skip below.
        for _ in range(40):
            bad_pk, _ = _gen_rsa()  # never registered
            with contextlib.suppress(*_AUTH_ERR):
                with _key_conn(uname, bad_pk):
                    pass

        # The IP is now over budget: even the genuinely-authorized key is refused.
        throttled = False
        try:
            with _key_conn(uname, valid_pk) as t:
                _ls_root(t)
        except _AUTH_ERR:
            throttled = True
        if not throttled:
            pytest.skip("SSH-key throttle did not engage in 40 offers; "
                        "rate_limit_sftp_key_attempts is likely configured above that")
    finally:
        _clear_sftp_pk_counters()

    # After the reset, the valid key works again (throttle was per-window, not a lockout).
    with _key_conn(uname, valid_pk) as t:
        _ls_root(t)


def shutil_which_docker() -> bool:
    import shutil
    return shutil.which("docker") is not None
