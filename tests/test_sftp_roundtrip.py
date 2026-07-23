"""
SFTP layer: web<->SFTP sync + per-vault/temp-credential authorization.

These run on the HOST against the live containers: the API at
http://localhost:8200 and the SFTP server at localhost:2322 (they share the
same Postgres + storage volume, which is what makes web<->SFTP sync possible).

RED->GREEN note: before the Standard-vault SFTP build, every file op returned
SFTP_OP_UNSUPPORTED and the principal was never wired in (``self.user = None``),
so the round-trip tests below could not even open a file — `sftp.open(... , "wb")`
raised immediately. They are GREEN only once SFTP I/O is routed through
VaultService with the authenticated `self.server.user`.

Auth model: SFTP logs in with the account username/password (or a temp
credential's ``temp_*`` username + credential). The per-vault *web* password is
not re-prompted over SFTP (see app/sftp/sftp_server.py header) — access is gated by
account auth + vault membership + temp-credential scope.
"""
import io
import os
import socket
import time
import contextlib
import uuid

import pytest

paramiko = pytest.importorskip("paramiko")

from conftest import ADMIN_USER, ADMIN_PASS, unique, ensure_ecc_keypair, create_zk_vault  # noqa: E402

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
# The vault's Postgres container. Env-overridable so the suite can be pointed at a second
# stack instead of silently targeting whatever "vault-db" happens to be running.
_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


# After a revocation, the next op may either be cleanly denied (SFTP status ->
# IOError) or hit an already-force-closed transport (SSHException/EOFError),
# depending on whether the async Redis force-close has landed yet — both are valid.
_REVOKED_EXC = (IOError, OSError, paramiko.SSHException, EOFError)


pytestmark = pytest.mark.sftp


def _wait_until(predicate, timeout=10.0, interval=0.2):
    """Poll predicate() until true or timeout (for async Redis-driven effects)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


@contextlib.contextmanager
def raw_transport(username: str, password: str):
    """A connected paramiko Transport (not auto-closed) for force-close tests."""
    transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    transport.banner_timeout = 30
    try:
        transport.connect(username=username, password=password)
        yield transport
    finally:
        transport.close()


@contextlib.contextmanager
def sftp_session(username: str, password: str):
    """Open a paramiko SFTP client to the live SFTP server."""
    transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    transport.banner_timeout = 30
    try:
        transport.connect(username=username, password=password)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            yield sftp
        finally:
            sftp.close()
    finally:
        transport.close()


# -- web helpers ------------------------------------------------------------
def _web_upload(client, vault_id, name, content, password=None):
    files = [("files", (name, content, "application/octet-stream"))]
    headers = {"X-Vault-Password": password} if password else None
    r = client.post(f"/vaults/{vault_id}/files", files=files, headers=headers)
    r.raise_for_status()
    return r.json()["files"][0]["id"]


def _web_list(client, vault_id, password=None):
    headers = {"X-Vault-Password": password} if password else None
    r = client.get(f"/vaults/{vault_id}/files", headers=headers)
    r.raise_for_status()
    return r.json()["items"]


def _web_download(client, vault_id, file_id, password=None):
    headers = {"X-Vault-Password": password} if password else None
    return client.get(f"/vaults/{vault_id}/files/{file_id}/download", headers=headers)


def _sftp_read(sftp, path) -> bytes:
    with sftp.open(path, "rb") as fh:
        return fh.read()


def _sftp_write(sftp, path, data: bytes) -> None:
    with sftp.open(path, "wb") as fh:
        fh.write(data)


@pytest.fixture(autouse=True)
def _need_admin_pw():
    if not ADMIN_PASS:
        pytest.skip("No admin password (set VAULT_ADMIN_PASS or ../.env ADMIN_PASSWORD)")


# ---------------------------------------------------------------------------
# Web <-> SFTP round trip (the core sync goal)
# ---------------------------------------------------------------------------
def test_web_upload_then_sftp_get_is_identical(admin, temp_vault):
    """A file written by the web path is byte-identical when fetched over SFTP."""
    vid, vname = temp_vault["id"], temp_vault["name"]
    content = b"web->sftp canonical roundtrip\n" * 200
    name = unique("w2s") + ".bin"

    _web_upload(admin, vid, name, content)

    with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
        assert name in sftp.listdir(f"/{vname}")
        got = _sftp_read(sftp, f"/{vname}/{name}")
    assert got == content


def test_sftp_put_then_web_get_is_identical_and_creates_row(admin, temp_vault):
    """A file written over SFTP shows up as a real File row and downloads
    byte-identically from the web path — same store, same encryption."""
    vid, vname = temp_vault["id"], temp_vault["name"]
    content = b"sftp->web canonical roundtrip\n" * 200
    name = unique("s2w") + ".bin"

    with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
        _sftp_write(sftp, f"/{vname}/{name}", content)

    items = _web_list(admin, vid)
    match = [it for it in items if it["type"] == "file" and it["name"] == name]
    assert match, f"SFTP-written file missing from web listing: {[it['name'] for it in items]}"
    assert match[0]["size"] == len(content)

    r = _web_download(admin, vid, match[0]["id"])
    assert r.status_code == 200, r.text
    assert r.content == content


def test_sftp_roundtrip_into_subfolder(admin, temp_vault):
    """SFTP honours the folder tree: a put into /vault/<folder>/ lands in that
    folder and is visible to the web listing scoped to the folder."""
    vid, vname = temp_vault["id"], temp_vault["name"]
    folder_name = unique("dir")
    folder_id = admin.post(f"/vaults/{vid}/folders", json={"name": folder_name}).json()["folder"]["id"]
    content = b"nested-over-sftp" * 64
    name = unique("nested") + ".bin"

    with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
        assert folder_name in sftp.listdir(f"/{vname}")
        _sftp_write(sftp, f"/{vname}/{folder_name}/{name}", content)
        assert _sftp_read(sftp, f"/{vname}/{folder_name}/{name}") == content

    items = admin.get(f"/vaults/{vid}/files", params={"folder_id": folder_id}).json()["items"]
    assert any(it["type"] == "file" and it["name"] == name for it in items)


def _mint_vault_cred(admin, vault_id, caps, password=None):
    """POST a self temp credential scoped to one vault; returns the RAW response so the
    caller can assert success or the 400 password-proof gate. Includes the vault password
    per-vault (selected_vaults[].password) when given."""
    scope = {
        "v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
        "temp": {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False},
    }
    sv = {"vault_id": vault_id, "caps": caps}
    if password is not None:
        sv["password"] = password
    return admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [sv],
    })


def test_password_vault_requires_password_proof_over_sftp(admin, temp_vault_pw):
    """A password-protected Standard vault must NOT be reachable over SFTP by account auth
    alone (same two-factor bar as the web). It is reachable only via a temp credential
    MINTED WITH the vault password (proof of knowledge); minting without — or with a wrong —
    password is refused, and that proven credential can round-trip files."""
    vid, vname, pw = temp_vault_pw["id"], temp_vault_pw["name"], temp_vault_pw["_password"]
    content = b"pw-vault sftp proof\n" * 50
    fname = unique("pwproof") + ".bin"
    _web_upload(admin, vid, fname, content, password=pw)

    # 1) Direct account SFTP can neither see nor open the password-protected vault.
    with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
        assert vname not in sftp.listdir("/"), "password vault must be hidden from direct SFTP"
        with pytest.raises((IOError, OSError)):
            sftp.listdir(f"/{vname}")

    caps = ["vault.see_info", "vault.see_files", "file.download", "file.upload", "file.delete"]
    # 2) Minting a vault-scoped credential WITHOUT the password is refused (proof gate).
    assert _mint_vault_cred(admin, vid, caps).status_code == 400
    # 3) ...and WITH the wrong password.
    assert _mint_vault_cred(admin, vid, caps, password="wrong-" + pw).status_code == 400

    # 4) WITH the correct password it mints, and that credential round-trips over SFTP.
    body = _mint_vault_cred(admin, vid, caps, password=pw)
    assert body.status_code in (200, 201), body.text
    tuser, tcred = body.json()["temp_username"], body.json()["credential"]
    with sftp_session(tuser, tcred) as sftp:
        assert vname in sftp.listdir("/"), "proven temp cred should see the vault"
        assert _sftp_read(sftp, f"/{vname}/{fname}") == content       # web -> sftp read
        nb = unique("pw_s2w") + ".bin"
        _sftp_write(sftp, f"/{vname}/{nb}", content)                  # sftp -> web write
    items = _web_list(admin, vid, password=pw)
    assert any(it["type"] == "file" and it["name"] == nb for it in items), \
        "proven temp-cred SFTP write missing from the vault listing"


def test_password_rotation_voids_sftp_temp_cred_proof(admin):
    """Rotating a vault's password VOIDS a temp credential's SFTP proof — the proof binds to
    the live password hash (re-checked per op), not frozen at mint. Done mid-session (temp
    creds are single-login) so the same connection sees the vault before and after the
    rotation, exactly as the web's per-request gate would."""
    v = admin.create_vault(name=unique("rotvault"), password="OrigPass123!")
    try:
        vid, vname = v["id"], v["name"]
        caps = ["vault.see_info", "vault.see_files", "file.download"]
        body = _mint_vault_cred(admin, vid, caps, password="OrigPass123!")
        assert body.status_code in (200, 201), body.text
        tuser, tcred = body.json()["temp_username"], body.json()["credential"]
        with sftp_session(tuser, tcred) as sftp:
            assert vname in sftp.listdir("/")             # proven: visible
            r = admin.put(f"/vaults/{vid}/password",      # rotate mid-session (web)
                          json={"current_password": "OrigPass123!", "new_password": "NewPass456!"})
            assert r.status_code == 200, r.text
            assert vname not in sftp.listdir("/"), "rotation must void the SFTP proof"
            with pytest.raises((IOError, OSError)):
                sftp.listdir(f"/{vname}")
    finally:
        admin.delete_vault(v["id"], vault_password="NewPass456!")


def test_password_added_after_mint_voids_sftp_temp_cred(admin):
    """A vault that GAINS a password after a temp credential was minted (while it had none)
    is no longer reachable by that credential over SFTP — a no-password mint carries no
    proof. Done mid-session so one connection sees it before and after the password add."""
    v = admin.create_vault(name=unique("addpw"))          # no password at mint
    try:
        vid, vname = v["id"], v["name"]
        caps = ["vault.see_info", "vault.see_files", "file.download"]
        body = _mint_vault_cred(admin, vid, caps)         # no password required at mint
        assert body.status_code in (200, 201), body.text
        tuser, tcred = body.json()["temp_username"], body.json()["credential"]
        with sftp_session(tuser, tcred) as sftp:
            assert vname in sftp.listdir("/")             # works while unprotected
            r = admin.put(f"/vaults/{vid}/password",      # add a password mid-session
                          json={"current_password": None, "new_password": "AddedPass789!"})
            assert r.status_code == 200, r.text
            assert vname not in sftp.listdir("/"), "adding a password must void the cred"
            with pytest.raises((IOError, OSError)):
                sftp.listdir(f"/{vname}")
    finally:
        admin.delete_vault(v["id"], vault_password="AddedPass789!")


def test_sftp_host_key_fingerprint_endpoint_matches_server(admin):
    """GET /sftp/host-key returns the SHA256 fingerprint of the ACTUAL serving host key, so
    a customer can verify it out-of-band against their SFTP client's first-connect prompt."""
    import hashlib
    import base64
    r = admin.get("/sftp/host-key").json()
    assert r.get("available") is True, r
    fp = r.get("fingerprint_sha256", "")
    assert fp.startswith("SHA256:") and len(fp) > 10, fp

    # It must match the key the server actually presents during the SSH handshake.
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 20
    try:
        t.start_client(timeout=20)
        hk = t.get_remote_server_key()
    finally:
        t.close()
    actual = "SHA256:" + base64.b64encode(hashlib.sha256(hk.asbytes()).digest()).decode().rstrip("=")
    assert fp == actual, f"endpoint fingerprint {fp} != serving host key {actual}"


# ---------------------------------------------------------------------------
# Authorization: isolation + temp-credential scope
# ---------------------------------------------------------------------------
def test_non_member_cannot_see_get_or_put_foreign_vault(admin, temp_vault, temp_user):
    """A user who is not a member of a vault cannot list it, read from it, or
    write into it over SFTP."""
    vid, vname = temp_vault["id"], temp_vault["name"]
    secret = b"members only"
    fname = unique("secret") + ".txt"
    _web_upload(admin, vid, fname, secret)

    pw = temp_user["_password"]
    uname = temp_user["_username"]
    with sftp_session(uname, pw) as sftp:
        # The foreign vault is not even visible at the root.
        assert vname not in sftp.listdir("/")
        # Reading a known path is denied (no such file for this principal).
        with pytest.raises((IOError, OSError)):
            _sftp_read(sftp, f"/{vname}/{fname}")
        # Writing into it is denied.
        with pytest.raises((IOError, OSError)):
            _sftp_write(sftp, f"/{vname}/{unique('evil')}.txt", b"x")

    # And nothing the intruder attempted created a row.
    names = [it["name"] for it in _web_list(admin, vid)]
    assert fname in names and not any(n.startswith("evil") for n in names)


def test_sftp_excludes_zero_knowledge_vault(admin):
    """ZK vaults are never served over SFTP (no server key): hidden from the root
    listing and not resolvable as a path."""
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        v = create_zk_vault(admin, name=unique("zksftp"))  # browser-wrapped DEK supplied
        try:
            with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
                assert v["name"] not in sftp.listdir("/")     # hidden at root
                with pytest.raises((IOError, OSError)):
                    sftp.listdir(f"/{v['name']}")             # not resolvable
        finally:
            admin.delete_vault(v["id"])
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _make_scoped_cred(admin, vault_id, caps):
    """Create a self temp credential scoped to one vault with the given caps."""
    scope = {
        "v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
        "temp": {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False},
    }
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vault_id, "caps": caps}],
    }).json()
    return body["temp_username"], body["credential"]


def test_sftp_temp_cred_see_info_only_hides_file_listing(admin):
    """A temp credential with vault.see_info but NOT vault.see_files can see the
    vault at the root but is denied when listing its contents over SFTP."""
    va = admin.create_vault(name=unique("scopeSFTP"))
    try:
        vname = va["name"]
        _web_upload(admin, va["id"], unique("hidden") + ".txt", b"do not list me")

        # see_info only — deliberately no see_files.
        tuser, tcred = _make_scoped_cred(admin, va["id"], ["vault.see_info"])
        with sftp_session(tuser, tcred) as sftp:
            # The vault is visible at root (see_info granted)...
            assert vname in sftp.listdir("/")
            # ...but its file listing is denied (see_files withheld).
            with pytest.raises((IOError, OSError)):
                sftp.listdir(f"/{vname}")
    finally:
        admin.delete_vault(va["id"])


def test_sftp_temp_cred_download_cap_required(admin):
    """see_files lets a temp credential list a vault, but downloading still
    requires file.download — a read-without-download cred is refused."""
    va = admin.create_vault(name=unique("dlcap"))
    try:
        vname = va["name"]
        name = unique("f") + ".txt"
        _web_upload(admin, va["id"], name, b"payload")

        # see_info + see_files but NO file.download
        tuser, tcred = _make_scoped_cred(admin, va["id"], ["vault.see_info", "vault.see_files"])
        with sftp_session(tuser, tcred) as sftp:
            assert name in sftp.listdir(f"/{vname}")  # listing allowed
            with pytest.raises((IOError, OSError)):    # download denied
                _sftp_read(sftp, f"/{vname}/{name}")
    finally:
        admin.delete_vault(va["id"])


# ---------------------------------------------------------------------------
# Regression guards for the adversarial-review fixes
# ---------------------------------------------------------------------------
def test_sftp_overwrite_replaces_not_duplicates(admin, temp_vault):
    """A second SFTP put of the same name overwrites atomically: exactly one row
    remains and reads return the NEW content (no duplicate, no stale read)."""
    vid, vname = temp_vault["id"], temp_vault["name"]
    name = unique("ow") + ".bin"
    with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
        _sftp_write(sftp, f"/{vname}/{name}", b"version-A")
        _sftp_write(sftp, f"/{vname}/{name}", b"version-B-final")
        assert _sftp_read(sftp, f"/{vname}/{name}") == b"version-B-final"
    same = [it for it in _web_list(admin, vid) if it["type"] == "file" and it["name"] == name]
    assert len(same) == 1, f"overwrite left {len(same)} rows (expected 1)"
    r = _web_download(admin, vid, same[0]["id"])
    assert r.status_code == 200 and r.content == b"version-B-final"


def test_web_then_sftp_overwrite_is_unified(admin, temp_vault):
    """Cross-interface replace parity: a web upload then an SFTP put of the same
    name leaves exactly one row with the SFTP content (one canonical file)."""
    vid, vname = temp_vault["id"], temp_vault["name"]
    name = unique("xiface") + ".bin"
    _web_upload(admin, vid, name, b"from-web")
    with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
        _sftp_write(sftp, f"/{vname}/{name}", b"from-sftp-wins")
    same = [it for it in _web_list(admin, vid) if it["type"] == "file" and it["name"] == name]
    assert len(same) == 1, f"expected one row after cross-interface overwrite, got {len(same)}"
    r = _web_download(admin, vid, same[0]["id"])
    assert r.status_code == 200 and r.content == b"from-sftp-wins"


def test_sftp_stat_respects_see_files(admin):
    """stat/lstat must not leak file existence/size to a see_info-only cred
    (parity with list_folder and the web list path)."""
    va = admin.create_vault(name=unique("statgate"))
    try:
        vname = va["name"]
        name = unique("hidden") + ".txt"
        _web_upload(admin, va["id"], name, b"do not stat me")
        tuser, tcred = _make_scoped_cred(admin, va["id"], ["vault.see_info"])
        with sftp_session(tuser, tcred) as sftp:
            # vault root is visible (see_info), file metadata is not (no see_files)
            with pytest.raises((IOError, OSError)):
                sftp.stat(f"/{vname}/{name}")
    finally:
        admin.delete_vault(va["id"])


def test_sftp_upload_only_cred_cannot_clobber_existing(admin):
    """An upload-only credential (file.upload, no file.delete) can CREATE new
    files but must NOT silently replace an existing one (no hidden duplicate)."""
    va = admin.create_vault(name=unique("noclobber"))
    try:
        vname = va["name"]
        existing = unique("keep") + ".txt"
        _web_upload(admin, va["id"], existing, b"original")
        caps = ["vault.see_info", "vault.see_files", "file.upload"]
        tuser, tcred = _make_scoped_cred(admin, va["id"], caps)
        with sftp_session(tuser, tcred) as sftp:
            # overwriting an existing file is denied without file.delete
            with pytest.raises((IOError, OSError)):
                _sftp_write(sftp, f"/{vname}/{existing}", b"clobbered")
            # but creating a brand-new file is allowed
            fresh = unique("new") + ".txt"
            _sftp_write(sftp, f"/{vname}/{fresh}", b"created")
        # the original is intact and the new file landed
        names = {it["name"]: it for it in _web_list(admin, va["id"]) if it["type"] == "file"}
        assert names[existing]["size"] == len(b"original")
        assert fresh in names
    finally:
        admin.delete_vault(va["id"])


def test_sftp_deactivated_temp_cred_is_revoked_mid_session(admin):
    """Deactivating a temp credential revokes its live SFTP session: the next op
    on the already-open connection is denied."""
    va = admin.create_vault(name=unique("revoke"))
    try:
        vname = va["name"]
        tuser, tcred = _make_scoped_cred(admin, va["id"], ["vault.see_info", "vault.see_files"])
        with sftp_session(tuser, tcred) as sftp:
            sftp.listdir(f"/{vname}")  # works while active
            assert admin.post(f"/temp-creds/{tuser}/deactivate").status_code == 200
            with pytest.raises(_REVOKED_EXC):
                sftp.listdir(f"/{vname}")  # revoked on the open connection
    finally:
        admin.delete_vault(va["id"])


def _backdate_deactivate_at(temp_username):
    """Push a temp credential's validity window (deactivate_at) into the past via the
    vault-db container, so its stated window is closed while the hard expiry is hours out.
    Returns False if docker/vault-db isn't reachable (test skips)."""
    import shutil
    import subprocess
    if not shutil.which("docker"):
        return False
    try:
        u = subprocess.run(["docker", "exec", _DB_CONTAINER, "printenv", "POSTGRES_USER"],
                           capture_output=True, text=True, timeout=10)
        d = subprocess.run(["docker", "exec", _DB_CONTAINER, "printenv", "POSTGRES_DB"],
                           capture_output=True, text=True, timeout=10)
        if u.returncode != 0 or d.returncode != 0:
            return False
        r = subprocess.run(
            ["docker", "exec", _DB_CONTAINER, "psql", "-U", u.stdout.strip(), "-d", d.stdout.strip(),
             "-c", "UPDATE temporary_credentials SET deactivate_at = NOW() - INTERVAL '5 minutes' "
                   f"WHERE temp_username = '{temp_username}';"],
            capture_output=True, text=True, timeout=15)
        return r.returncode == 0 and "UPDATE 1" in r.stdout
    except Exception:  # noqa: BLE001
        return False


def test_sftp_temp_cred_past_validity_window_denied_mid_session(admin):
    """A temp credential whose validity window (deactivate_at) has closed must stop working
    over SFTP too — the per-op gate honors the credential's stated lifetime, not just the web
    per-request check. (The hard expiry is hours out, so only the window closed.)"""
    va = admin.create_vault(name=unique("window"))
    try:
        vname = va["name"]
        tuser, tcred = _make_scoped_cred(admin, va["id"], ["vault.see_info", "vault.see_files"])
        with sftp_session(tuser, tcred) as sftp:
            sftp.listdir(f"/{vname}")  # works inside the validity window
            if not _backdate_deactivate_at(tuser):
                pytest.skip("cannot backdate deactivate_at (docker/vault-db unavailable)")
            with pytest.raises(_REVOKED_EXC):
                sftp.listdir(f"/{vname}")  # past the window -> denied on the live session
    finally:
        admin.delete_vault(va["id"])


def test_sftp_locked_account_denied_mid_session(admin, temp_user):
    """Locking a user account revokes their already-open SFTP connection at the
    next operation (parity with the web get_current_user is_locked re-check)."""
    uname, pw, uid = temp_user["_username"], temp_user["_password"], temp_user["id"]
    with sftp_session(uname, pw) as sftp:
        sftp.listdir("/")  # works while active (empty is fine)
        assert admin.patch(f"/users/{uid}", json={"is_locked": True}).status_code == 200
        with pytest.raises(_REVOKED_EXC):
            sftp.listdir("/")  # locked account is rejected on the open connection
    # unlock so other state stays clean (teardown deletes the user regardless)
    admin.patch(f"/users/{uid}", json={"is_locked": False})


# ---------------------------------------------------------------------------
# Instant revocation: locking/deactivating force-closes the live transport
# (proactive teardown via the session_terminations Redis channel — not merely a
# denial at the connection's next operation).
# ---------------------------------------------------------------------------
def test_sftp_lock_force_closes_live_transport(admin, temp_user):
    uname, pw, uid = temp_user["_username"], temp_user["_password"], temp_user["id"]
    with raw_transport(uname, pw) as transport:
        sftp = paramiko.SFTPClient.from_transport(transport)
        sftp.listdir("/")                       # registers the transport server-side
        assert transport.is_active()
        assert admin.patch(f"/users/{uid}", json={"is_locked": True}).status_code == 200
        # the SFTP server should tear the connection down on its own
        assert _wait_until(lambda: not transport.is_active()), \
            "transport was not force-closed after the account was locked"
    admin.patch(f"/users/{uid}", json={"is_locked": False})


def test_sftp_deactivate_force_closes_live_transport(admin):
    va = admin.create_vault(name=unique("forceclose"))
    try:
        tuser, tcred = _make_scoped_cred(admin, va["id"], ["vault.see_info", "vault.see_files"])
        with raw_transport(tuser, tcred) as transport:
            sftp = paramiko.SFTPClient.from_transport(transport)
            sftp.listdir(f"/{va['name']}")
            assert transport.is_active()
            assert admin.post(f"/temp-creds/{tuser}/deactivate").status_code == 200
            assert _wait_until(lambda: not transport.is_active()), \
                "transport was not force-closed after the temp credential was deactivated"
    finally:
        admin.delete_vault(va["id"])


# ---------------------------------------------------------------------------
# SFTP surface hardening: recursive-delete authority, session lifetime, upload
# bound, filename sanitization, weak-cipher rejection.
# ---------------------------------------------------------------------------
def _psql(sql):
    import shutil
    import subprocess
    if not shutil.which("docker"):
        return None
    try:
        u = subprocess.run(["docker", "exec", _DB_CONTAINER, "printenv", "POSTGRES_USER"],
                           capture_output=True, text=True, timeout=10)
        d = subprocess.run(["docker", "exec", _DB_CONTAINER, "printenv", "POSTGRES_DB"],
                           capture_output=True, text=True, timeout=10)
        if u.returncode != 0 or d.returncode != 0:
            return None
        return subprocess.run(
            ["docker", "exec", _DB_CONTAINER, "psql", "-U", u.stdout.strip(), "-d", d.stdout.strip(),
             "-c", sql], capture_output=True, text=True, timeout=15)
    except Exception:  # noqa: BLE001
        return None


def test_sftp_rmdir_requires_delete_not_just_write(admin, temp_user):
    """A write-but-no-delete member cannot rmdir a folder over SFTP: the subtree (the owner's
    DELETE-protected file) survives. The old gate (folder.delete cap + WRITE RBAC, swallowed
    per-file check) let a write-only member destroy it — the SFTP twin of the web recursive-delete
    authority fix."""
    uname, pw, uid = temp_user["_username"], temp_user["_password"], temp_user["id"]
    va = admin.create_vault(name=unique("rmdirguard"))
    try:
        vname = va["name"]
        assert admin.post(f"/vaults/{va['id']}/folders", json={"name": "sub"}).status_code == 200
        # Owner places a file inside the subfolder.
        with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
            _sftp_write(sftp, f"/{vname}/sub/keep.txt", b"owner data")
        # Grant the member WRITE but NOT delete.
        assert admin.post(f"/vaults/{va['id']}/permissions",
                          json={"user_id": uid, "level": "write"}).status_code == 200
        with sftp_session(uname, pw) as sftp:
            with pytest.raises((IOError, OSError)):
                sftp.rmdir(f"/{vname}/sub")   # denied — recursive delete needs DELETE
        # The owner's file (and folder) must survive the blocked rmdir.
        with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
            assert "keep.txt" in sftp.listdir(f"/{vname}/sub")
        # And the owner (with DELETE) can still remove it.
        with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
            sftp.remove(f"/{vname}/sub/keep.txt")
            sftp.rmdir(f"/{vname}/sub")
    finally:
        admin.delete_vault(va["id"])


def test_sftp_session_past_hard_expiry_denied_mid_session(admin):
    """A live SFTP session whose ActiveSession.expires_at has passed is denied on the next op —
    the SFTP per-op gate now honors the session's hard expiry (was only checked on the web)."""
    va = admin.create_vault(name=unique("hardexp"))
    try:
        vname = va["name"]
        tuser, tcred = _make_scoped_cred(admin, va["id"], ["vault.see_info", "vault.see_files"])
        with sftp_session(tuser, tcred) as sftp:
            sftp.listdir(f"/{vname}")  # works while the session is live
            r = _psql(
                "UPDATE active_sessions SET expires_at = NOW() - INTERVAL '5 minutes' "
                "WHERE is_active = true AND temp_credential_id = "
                f"(SELECT id FROM temporary_credentials WHERE temp_username = '{tuser}');")
            if r is None or r.returncode != 0 or "UPDATE 1" not in (r.stdout or ""):
                pytest.skip("cannot backdate ActiveSession.expires_at (docker/vault-db)")
            with pytest.raises(_REVOKED_EXC):
                sftp.listdir(f"/{vname}")  # past the hard expiry -> denied
    finally:
        admin.delete_vault(va["id"])


def test_sftp_upload_over_max_file_size_is_rejected(admin, temp_vault):
    """An SFTP write past the per-file max is rejected in-stream (SFTP_FAILURE) and the upload is
    discarded — so a client can't fill the shared .sftp_tmp volume before the close-time size
    check. A 1-byte write at a 1 TiB offset exceeds ANY sane deployment max deterministically
    (the server rejects on offset+len > max_bytes, before it ever touches disk), so this exercises
    the in-stream bound regardless of the configured max_file_size (prod default is 1 GiB)."""
    vname = temp_vault["name"]
    huge_offset = 1024 ** 4  # 1 TiB — beyond any realistic max_file_size
    rejected = False
    with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
        try:
            with sftp.open(f"/{vname}/toobig.bin", "wb") as fh:
                fh.seek(huge_offset)
                fh.write(b"x")
        except (IOError, OSError):
            rejected = True  # the write was refused in-stream (SFTP_FAILURE)
    with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
        present = "toobig.bin" in sftp.listdir(f"/{vname}")
    assert rejected, "an over-max SFTP write must be rejected in-stream (SFTP_FAILURE)"
    assert not present, "a rejected over-max SFTP upload must not be persisted"


def test_sftp_put_strips_control_chars_from_filename(admin, temp_vault):
    """A CR/LF-laden filename put over SFTP is stored with the control chars stripped from
    original_name (the source guard behind the web download-header sink)."""
    vname = temp_vault["name"]
    with sftp_session(ADMIN_USER, ADMIN_PASS) as sftp:
        # confirm=False: the post-upload stat would 404 because the server stores the
        # control-char-stripped name, not the CRLF path we wrote to — which is the point.
        sftp.putfo(io.BytesIO(b"payload"), f"/{vname}/clean\r\nInjected.txt", confirm=False)
    items = _web_list(admin, temp_vault["id"])
    f = next((x for x in items if x.get("type") == "file" and "Injected" in x.get("name", "")), None)
    assert f is not None, f"uploaded file not found in {[i.get('name') for i in items]}"
    assert "\r" not in f["name"] and "\n" not in f["name"], "control chars not stripped at the SFTP sink"
    # And it still downloads (the header sink is safe).
    assert _web_download(admin, temp_vault["id"], f["id"]).status_code == 200


def test_sftp_rejects_weak_3des_cbc_cipher():
    """The transport refuses SWEET32-vulnerable 3des-cbc: a client offering ONLY 3des-cbc fails
    to negotiate. (The strong defaults still connect — every other test here proves that.)"""
    sock = socket.create_connection((SFTP_HOST, SFTP_PORT), timeout=10)
    t = paramiko.Transport(sock)
    try:
        t.get_security_options().ciphers = ("3des-cbc",)
        with pytest.raises(paramiko.SSHException):
            t.start_client(timeout=10)
    finally:
        t.close()
        with contextlib.suppress(Exception):
            sock.close()


def test_download_only_cred_gets_known_file_but_cannot_enumerate(admin):
    """A temp credential scoped to file.download (which now implies vault.see_info but NOT
    vault.see_files) can DOWNLOAD a known file over SFTP through the high-level get()/getfo()
    path -- paramiko stat()s a file before opening it -- yet CANNOT enumerate the vault
    (listdir inside the vault requires see_files). This is the 'download this known file,
    no enumeration' credential working over SFTP, not just REST."""
    pw = "DlOnlySftp!123long"
    v = admin.create_vault(name=unique("dlsftp"), password=pw)
    try:
        vid, vname = v["id"], v["name"]
        content = b"download-only sftp get\n" * 40
        fname = unique("known") + ".bin"
        _web_upload(admin, vid, fname, content, password=pw)
        body = _mint_vault_cred(admin, vid, ["file.download"], password=pw)  # download-only, proven
        assert body.status_code in (200, 201), body.text
        tuser, tcred = body.json()["temp_username"], body.json()["credential"]
        with sftp_session(tuser, tcred) as sftp:
            # enumeration of the vault's contents is blocked (no see_files)
            with pytest.raises((IOError, OSError)):
                sftp.listdir(f"/{vname}")
            # ...but get()/getfo() of the KNOWN file works (it stat()s, then open()s)
            buf = io.BytesIO()
            sftp.getfo(f"/{vname}/{fname}", buf)
            assert buf.getvalue() == content
    finally:
        admin.delete_vault(vid)
