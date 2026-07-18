"""Redeeming a temporary vault passcode over REST (the get_vault chokepoint, X-Vault-Passcode header).

A temp-credential holder opens a password-protected STANDARD vault with the PASSCODE instead of the
real vault password: download a file with X-Vault-Passcode; wrong / expired / used-up passcodes are
rejected; a one-time passcode burns after one use; multi-use works; the passcode does not widen the
credential's caps; and the real-password path is unaffected (no downgrade).
"""
import os
import subprocess
import uuid

import pytest

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_PW = "Sup3r-Secret-PW-9!"


def _u(p):
    return f"{p}_{uuid.uuid4().hex[:8]}"


def _psql(sql):
    return subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=20).stdout.strip()


_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")


def _redis_get(key):
    return subprocess.run(["docker", "exec", _REDIS_CONTAINER, "redis-cli", "get", key],
                          capture_output=True, text=True, timeout=20).stdout.strip()


def _use_count(temp_username, vault_id):
    q = ("SELECT tcva.passcode_use_count FROM temp_credential_vault_access tcva "
         "JOIN temporary_credentials tc ON tc.id = tcva.temp_credential_id "
         f"WHERE tc.temp_username = '{temp_username}' AND tcva.vault_id = '{vault_id}';")
    v = _psql(q)
    return int(v) if v else None


@pytest.fixture
def restore_policy(admin):
    before = admin.get("/settings").json()
    yield
    admin.put("/settings", json={k: before[k] for k in
              ("temp_passcodes_enabled", "temp_passcode_one_time_default") if k in before})


def _pw_vault_with_file(admin):
    v = admin.create_vault(name=_u("rv"), password=_PW)
    content = b"secret-bytes-" + uuid.uuid4().hex.encode()
    files = [("files", (_u("f") + ".txt", content, "text/plain"))]
    r = admin.post(f"/vaults/{v['id']}/files", files=files, headers={"X-Vault-Password": _PW})
    r.raise_for_status()
    return v["id"], r.json()["files"][0]["id"], content


def _mint(admin, vault_id, one_time=None, caps=("vault.see_files", "file.download")):
    caps = list(caps)
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}}
    sv = {"vault_id": vault_id, "caps": caps, "password": _PW, "issue_passcode": True}
    if one_time is not None:
        sv["one_time"] = one_time
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected", "selected_vaults": [sv]}).json()
    client = admin.clone_anonymous()
    client.login(body["temp_username"], body["credential"])
    return client, body["passcodes"][0]["passcode"], body["temp_username"]


def _dl(client, vid, fid, passcode=None, password=None):
    headers = {}
    if passcode:
        headers["X-Vault-Passcode"] = passcode
    if password:
        headers["X-Vault-Password"] = password
    return client.get(f"/vaults/{vid}/files/{fid}/download", headers=headers or None)


def test_download_with_passcode(admin, restore_policy):
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": False})
    vid, fid, content = _pw_vault_with_file(admin)
    try:
        client, passcode, _ = _mint(admin, vid)
        r = _dl(client, vid, fid, passcode=passcode)         # passcode opens the vault (no real password)
        assert r.status_code == 200, r.text
        assert r.content == content
        assert _dl(client, vid, fid).status_code in (400, 401, 403)                    # no proof -> denied
        assert _dl(client, vid, fid, passcode="wrong-passcode-zzz").status_code in (400, 401, 403)  # wrong -> denied
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_one_time_passcode_burns_after_one_use(admin, restore_policy):
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": True})
    vid, fid, content = _pw_vault_with_file(admin)
    try:
        client, passcode, tu = _mint(admin, vid)  # one-time by policy default
        r1 = _dl(client, vid, fid, passcode=passcode)
        assert r1.status_code == 200, r1.text
        assert _use_count(tu, vid) == 1
        r2 = _dl(client, vid, fid, passcode=passcode)  # second use -> burned
        assert r2.status_code in (400, 401, 403), r2.text
        assert _use_count(tu, vid) == 1                 # not incremented past the cap
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_multi_use_passcode_allows_repeat(admin, restore_policy):
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": False})
    vid, fid, content = _pw_vault_with_file(admin)
    try:
        client, passcode, tu = _mint(admin, vid, one_time=False)
        assert _dl(client, vid, fid, passcode=passcode).status_code == 200
        assert _dl(client, vid, fid, passcode=passcode).status_code == 200  # reusable
        assert _use_count(tu, vid) == 2  # each redemption is counted
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_expired_passcode_denied(admin, restore_policy):
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": False})
    vid, fid, content = _pw_vault_with_file(admin)
    try:
        client, passcode, tu = _mint(admin, vid)
        # force the passcode's expiry into the past
        _psql("UPDATE temp_credential_vault_access tcva SET passcode_expires_at = now() - interval '1 hour' "
              "FROM temporary_credentials tc WHERE tc.id = tcva.temp_credential_id "
              f"AND tc.temp_username = '{tu}' AND tcva.vault_id = '{vid}';")
        r = _dl(client, vid, fid, passcode=passcode)
        assert r.status_code in (400, 401, 403), r.text
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_passcode_does_not_widen_caps(admin, restore_policy):
    """The passcode opens the vault gate but grants no cap beyond the credential's scope: a
    download-only holder still can't upload (the cap check precedes the passcode gate)."""
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": False})
    vid, fid, content = _pw_vault_with_file(admin)
    try:
        client, passcode, _ = _mint(admin, vid, caps=("vault.see_files", "file.download"))  # no file.upload
        up = client.post(f"/vaults/{vid}/files",
                         files=[("files", ("x.txt", b"nope", "text/plain"))],
                         headers={"X-Vault-Passcode": passcode})
        assert up.status_code == 403, up.text  # upload cap not granted
        assert _dl(client, vid, fid, passcode=passcode).status_code == 200  # download still works
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_real_password_path_unaffected(admin, restore_policy):
    """No downgrade: the owner can still open the vault with the real password (passcode feature on)."""
    admin.put("/settings", json={"temp_passcodes_enabled": True})
    vid, fid, content = _pw_vault_with_file(admin)
    try:
        assert _dl(admin, vid, fid, password=_PW).status_code == 200          # real password works
        assert _dl(admin, vid, fid, password="wrong").status_code in (400, 401, 403)  # wrong real password denied
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_passcode_scoped_to_its_own_vault(admin, restore_policy):
    """A passcode minted for vault A must NOT open vault B, even when the credential holds both."""
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": False})
    va, fa, _ = _pw_vault_with_file(admin)
    vb, fb, _ = _pw_vault_with_file(admin)
    try:
        caps = ["vault.see_files", "file.download"]
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}}
        body = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
            "selected_vaults": [
                {"vault_id": va, "caps": caps, "password": _PW, "issue_passcode": True},
                {"vault_id": vb, "caps": caps, "password": _PW}]}).json()  # B: no passcode
        pc_a = [p["passcode"] for p in body["passcodes"] if p["vault_id"] == va][0]
        assert not any(p["vault_id"] == vb for p in body["passcodes"])
        client = admin.clone_anonymous()
        client.login(body["temp_username"], body["credential"])
        assert _dl(client, va, fa, passcode=pc_a).status_code == 200                 # opens its own vault
        assert _dl(client, vb, fb, passcode=pc_a).status_code in (400, 401, 403)     # not vault B
    finally:
        admin.delete_vault(va, vault_password=_PW)
        admin.delete_vault(vb, vault_password=_PW)


def test_wrong_passcode_increments_rate_counter(admin, restore_policy):
    """A wrong passcode records a failure on the SAME fixed-window counter as the real password, so
    the passcode gate isn't an unthrottled brute-force bypass."""
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": False})
    uid = admin.get("/users/me").json()["id"]  # a temp session runs as the owning (admin) account
    vid, fid, _ = _pw_vault_with_file(admin)
    try:
        client, passcode, _ = _mint(admin, vid)
        key = f"rate_limit:vault:{vid}:{uid}"
        assert not _redis_get(key)  # fresh
        assert _dl(client, vid, fid, passcode="definitely-wrong-000").status_code in (400, 401, 403)
        assert _redis_get(key) == "1"  # the wrong passcode burned one attempt
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_passcode_denied_after_credential_revoked(admin, restore_policy):
    """T-A5 (revoke half): deleting the temp credential stops its passcode from working."""
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": False})
    vid, fid, _ = _pw_vault_with_file(admin)
    try:
        client, passcode, tu = _mint(admin, vid)
        assert _dl(client, vid, fid, passcode=passcode).status_code == 200
        admin.post(f"/temp-creds/{tu}/delete")  # revoke
        assert _dl(client, vid, fid, passcode=passcode).status_code in (401, 403)  # session gone
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_one_time_passcode_concurrent_single_success(admin, restore_policy):
    """T-A4 (race): two concurrent redemptions of a one-time passcode yield EXACTLY one success
    (the atomic conditional-UPDATE burn), not a double-spend."""
    import concurrent.futures
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": True})
    vid, fid, _ = _pw_vault_with_file(admin)
    try:
        client, passcode, tu = _mint(admin, vid)
        # a second client sharing the SAME session token (a temp cred can only authenticate once)
        c2 = admin.clone_anonymous()
        c2.session.headers.update({"Authorization": f"Bearer {client.token}"})
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            codes = list(ex.map(lambda c: _dl(c, vid, fid, passcode=passcode).status_code, [client, c2]))
        assert codes.count(200) == 1, codes          # exactly one wins the burn
        assert _use_count(tu, vid) == 1              # never double-counted
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_disabling_feature_blocks_redemption(admin, restore_policy):
    """Master kill-switch: turning the feature off stops an already-minted passcode from redeeming."""
    admin.put("/settings", json={"temp_passcodes_enabled": True, "temp_passcode_one_time_default": False})
    vid, fid, _ = _pw_vault_with_file(admin)
    try:
        client, passcode, _ = _mint(admin, vid)
        assert _dl(client, vid, fid, passcode=passcode).status_code == 200  # works while enabled
        admin.put("/settings", json={"temp_passcodes_enabled": False})      # kill-switch
        assert _dl(client, vid, fid, passcode=passcode).status_code in (400, 401, 403)
    finally:
        admin.delete_vault(vid, vault_password=_PW)
