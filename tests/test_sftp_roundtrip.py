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
not re-prompted over SFTP (see sftp_server.py header) — access is gated by
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

# After a revocation, the next op may either be cleanly denied (SFTP status ->
# IOError) or hit an already-force-closed transport (SSHException/EOFError),
# depending on whether the async Redis force-close has landed yet — both are valid.
_REVOKED_EXC = (IOError, OSError, paramiko.SSHException, EOFError)


def _sftp_reachable() -> bool:
    try:
        with socket.create_connection((SFTP_HOST, SFTP_PORT), timeout=5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _sftp_reachable(),
    reason=f"SFTP server not reachable at {SFTP_HOST}:{SFTP_PORT}",
)


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
