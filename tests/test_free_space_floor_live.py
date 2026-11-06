"""A deployment whose storage volume is down to the free space it keeps refuses uploads, SFTP writes, copies and
moves, on a running stack (app/core/free_space.py).

Run against a deployment started with MIN_FREE_SPACE_GB above its volume's free space (the CI step "Exercise the
free-space floor set above the disk's size" sets it, recreates the API and SFTP containers, runs this with
VAULT_FREE_SPACE_FLOOR_ABOVE_THE_DISK=1, and puts the shipped value back): every write of a file's bytes would leave
less than the floor free.

- the storage panel reports the floor, above the free space;
- a direct upload is answered 507, saying the free space and the floor, and stores nothing;
- a chunked upload is refused at its start, before a byte is sent;
- an upload link's upload is refused at its start, and reserves nothing of the link's room;
- a copy and a move into another vault are answered 507, and the file stays where it was;
- an SFTP write is refused at its open, with the reason as its status, and stores nothing.

tests/test_free_space.py covers the rules offline (the check as the bytes are written and as the row is written, the
copies, the routes' answers); test_api_storage_stats.py the floor a deployment with the shipped value reports.
"""
import os
import subprocess

import pytest

from _account_change_helpers import API, psql
from conftest import ADMIN_PASS, ADMIN_USER, unique

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("VAULT_FREE_SPACE_FLOOR_ABOVE_THE_DISK") != "1",
                       reason="needs a deployment whose MIN_FREE_SPACE_GB is above its volume's free space"),
]

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
NEARLY_FULL = "The server's storage is nearly full: "

# A file stored through the application's own upload path, in a process of the web container whose floor is off: no
# request can store one while the server's floor is above the disk. Run as the user the server drops to, so the
# server can read and remove what it writes.
_STORE = """
import uuid
from app.core.config import bootstrap_entrypoint, settings
bootstrap_entrypoint("free-space-test")
settings.min_free_space_gb = 0
from app.core.authorization import PermissionService
from app.core.database import get_db_context
from app.core.models import User
from app.services.vault_service import VaultService
with get_db_context() as db:
    user = db.query(User).filter(User.username == USERNAME).one()
    service = VaultService(db, PermissionService(db))
    info, stream = service.upload_file_streaming(uuid.UUID(VAULT_ID), NAME, user, mime_type="text/plain")
    with stream as ctx:
        ctx.write_chunk(b"a few bytes")
    made = service.finalize_streaming_upload(info, ctx.get_total_size(), ctx.get_checksum())
    print("STORED=" + str(made.id))
"""


def _names(admin, vault_id):
    r = admin.get(f"/vaults/{vault_id}/files")
    assert r.status_code == 200, r.text
    return [item.get("name") for item in r.json()["items"]]


def _stored(vault_id, name):
    script = f"USERNAME = {ADMIN_USER!r}\nVAULT_ID = {vault_id!r}\nNAME = {name!r}\n" + _STORE
    try:
        r = subprocess.run(["docker", "exec", "-i", "-u", "10001:10001", API, "python", "-c", script],
                           capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"the command did not finish within {exc.timeout} s")
    assert r.returncode == 0, (r.stderr or r.stdout)[-1500:]
    return [ln for ln in r.stdout.splitlines() if ln.startswith("STORED=")][0][len("STORED="):]


@pytest.fixture
def two_vaults(admin, temp_vault):
    """``temp_vault`` with a file in it, and a second vault of the administrator's."""
    name = unique("floor") + ".txt"
    file_id = _stored(temp_vault["id"], name)
    assert _names(admin, temp_vault["id"]) == [name]
    other = admin.create_vault(name=unique("floor-dest"))
    try:
        yield temp_vault, file_id, name, other
    finally:
        admin.delete_vault(other["id"])


@pytest.fixture
def upload_links_on(admin):
    before = admin.get("/settings").json()
    kept = {k: before.get(k) for k in ("public_receivers_enabled", "public_receiver_user_cap")}
    r = admin.put("/settings", json={"public_receivers_enabled": True, "public_receiver_user_cap": 50})
    assert r.status_code == 200, r.text
    try:
        yield
    finally:
        admin.put("/settings", json=kept)


def test_the_storage_panel_reports_a_floor_above_the_free_space(admin):
    body = admin.get("/storage/stats").json()
    assert body["free_space_floor_bytes"] > body["available"] > 0, body


def test_a_direct_upload_is_refused_507_saying_the_free_space_and_the_floor(admin, temp_vault):
    r = admin.post(f"/vaults/{temp_vault['id']}/files",
                   files=[("files", (unique("floor") + ".txt", b"a few bytes", "text/plain"))])
    assert r.status_code == 507, r.text
    detail = r.json()["detail"]
    assert detail.startswith(NEARLY_FULL) and "MIN_FREE_SPACE_GB" in detail
    assert _names(admin, temp_vault["id"]) == []


def test_a_chunked_upload_is_refused_at_its_start(admin, temp_vault):
    r = admin.post(f"/vaults/{temp_vault['id']}/uploads", json={
        "file_name": unique("floor") + ".bin", "total_size": 1024, "total_chunks": 1, "chunk_size": 1024})
    assert r.status_code == 507, r.text
    assert r.json()["detail"].startswith(NEARLY_FULL)
    sessions = admin.get(f"/vaults/{temp_vault['id']}/uploads")
    assert sessions.status_code == 200 and sessions.json() == [], sessions.text


def test_an_upload_links_upload_is_refused_at_its_start_and_reserves_nothing(admin, upload_links_on):
    tag = admin.post("/receiver-tags", json={
        "name": unique("floor-tag"), "min_token_len": 6, "require_secret": "none", "min_pin_len": 4,
        "password_min_len": 8, "auto_enroll_new_users": True, "kind_floor": "standard",
        "max_total_bytes_cap": 50 * 1024 * 1024, "max_file_bytes_cap": 10 * 1024 * 1024,
        "retention_max_days": 30, "retention_default_days": 7})
    assert tag.status_code in (200, 201), tag.text
    link = admin.post("/receivers", json={"tag_id": tag.json()["id"], "max_total_bytes": 10 * 1024 * 1024})
    assert link.status_code in (200, 201), link.text
    link = link.json()
    try:
        anon = admin.clone_anonymous()
        r = anon.post(f"/receivers/{link['token']}/upload-session",
                      json={"filename": unique("floor") + ".txt", "total_size": 1000, "total_chunks": 1})
        assert r.status_code == 507, r.text
        assert r.json()["detail"].startswith(NEARLY_FULL)
        assert psql(f"SELECT reserved_bytes FROM receivers WHERE id = '{link['id']}'") == "0"
        assert psql(f"SELECT count(*) FROM receiver_upload_sessions WHERE receiver_id = '{link['id']}'") == "0"
    finally:
        admin.post(f"/receivers/{link['id']}/revoke")


@pytest.mark.parametrize("verb", ["copy", "move"])
def test_a_copy_or_a_move_into_another_vault_is_refused_507_and_the_file_stays(admin, two_vaults, verb):
    source, file_id, name, dest = two_vaults
    r = admin.post(f"/vaults/{source['id']}/files/{file_id}/{verb}", json={"dest_vault_id": dest["id"]})
    assert r.status_code == 507, r.text
    detail = r.json()["detail"]
    assert detail.startswith(NEARLY_FULL) and "MIN_FREE_SPACE_GB" in detail
    assert _names(admin, dest["id"]) == []
    assert _names(admin, source["id"]) == [name]


def test_an_sftp_write_is_refused_at_its_open_with_the_reason(admin, temp_vault):
    paramiko = pytest.importorskip("paramiko")
    transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    transport.banner_timeout = 30
    try:
        transport.connect(username=ADMIN_USER, password=ADMIN_PASS)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            with pytest.raises(IOError) as refused:
                with sftp.open(f"/{temp_vault['name']}/{unique('floor')}.txt", "wb") as fh:
                    fh.write(b"a few bytes")
            assert "The server's storage is nearly full" in str(refused.value), refused.value
        finally:
            sftp.close()
    finally:
        transport.close()
    assert _names(admin, temp_vault["id"]) == []
