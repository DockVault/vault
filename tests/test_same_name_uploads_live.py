"""Live lane: the same-name lock every upload door shares, against a running stack (API + SFTP + Redis).

A name that one upload is still writing is refused to every other upload that would replace it by
name: an SFTP upload, another member's browser upload, and a direct upload. Between one account's
own browser uploads the uploader's tray decides, so those do not block each other. The lock follows
the upload: kept while it moves, taken back after a pause, dropped when it lands or is cancelled.

The rule is pinned offline (test_upload_marker) and so is where each door takes it
(test_same_name_lock_wiring); this is the same rule run for real, including the Redis script itself.
"""
import os
import subprocess

import paramiko
import pytest

from conftest import unique
from _device_boundary_helpers import register_device, grant, mint_sync_cred, SFTP_HOST, SFTP_PORT

pytestmark = pytest.mark.integration

_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
_BODY = b"x" * 64


def _open(client, vault_id, name, size=len(_BODY)):
    """Open a resumable Standard upload (one chunk)."""
    return client.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": size, "total_chunks": 1, "chunk_size": size,
        "mime_type": "application/octet-stream"})


def _session(response):
    assert response.status_code == 200, response.text
    return response.json()["session_id"]


def _send(client, vault_id, sid, body=_BODY):
    r = client.put(f"/vaults/{vault_id}/uploads/{sid}/chunks/0", data=body,
                   headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 200, r.text


def _complete(client, vault_id, sid):
    return client.post(f"/vaults/{vault_id}/uploads/{sid}/complete", json={})


def _cancel(client, vault_id, sid):
    client.delete(f"/vaults/{vault_id}/uploads/{sid}")


def _refused(response):
    assert response.status_code == 409, response.text
    assert "is currently being uploaded by" in str(response.json().get("detail")), response.text


def _in_flight(client, vault_id, name):
    items = client.get(f"/vaults/{vault_id}/files").json().get("items", [])
    return next((i for i in items if i.get("in_progress") and i.get("name") == name), None)


@pytest.fixture
def member(admin, temp_vault, temp_user, temp_user_client):
    """A second member who may write to the vault -- a different person from its owner."""
    r = admin.post(f"/vaults/{temp_vault['id']}/permissions",
                   json={"user_id": temp_user["id"], "level": "write"})
    assert r.status_code in (200, 201), r.text
    return temp_user_client


def _sftp(admin, vault):
    """An SFTP session under a device credential the vault's owner minted."""
    dev = register_device(admin, label="same-name-box")
    grant(admin, dev["device_id"], vault["id"])
    minted = mint_sync_cred(dev["secret"], vault["id"]).json()
    transport = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    transport.banner_timeout = 30
    transport.connect(username=minted["temp_username"], password=minted["credential"])
    return transport, paramiko.SFTPClient.from_transport(transport)


# --------------------------------------------------------------------------------------------------
def test_another_members_browser_upload_of_a_live_name_is_refused(admin, temp_vault, member):
    vid, name = temp_vault["id"], unique("held") + ".bin"
    sid = _session(_open(admin, vid, name))
    try:
        _refused(_open(member, vid, name))
    finally:
        _cancel(admin, vid, sid)
    # Cancelled: the name is free at once, not when the lock would have lapsed.
    _cancel(member, vid, _session(_open(member, vid, name)))


def test_the_same_members_second_browser_upload_is_not_refused(admin, temp_vault):
    # Between one account's own uploads the tray decides (it asks, and cancels what it replaces).
    vid, name = temp_vault["id"], unique("mine") + ".bin"
    first = _session(_open(admin, vid, name))
    second = _session(_open(admin, vid, name))
    assert first != second
    _cancel(admin, vid, first)
    _cancel(admin, vid, second)


def test_sftp_is_refused_while_a_browser_upload_holds_the_name(admin, temp_vault):
    vid, name = temp_vault["id"], unique("webfirst") + ".bin"
    sid = _session(_open(admin, vid, name))
    transport, sftp = _sftp(admin, temp_vault)
    try:
        # Refused even though the SFTP credential is the same member's: SFTP never takes over.
        with pytest.raises(IOError) as caught:
            sftp.open("/%s/%s" % (temp_vault["name"], name), "wb")
        assert "being uploaded" in str(caught.value).lower()
        _cancel(admin, vid, sid)
        with sftp.open("/%s/%s" % (temp_vault["name"], name), "wb") as fh:   # free now
            fh.write(b"sftp")
    finally:
        transport.close()


def test_a_browser_upload_is_refused_while_sftp_holds_the_name(admin, temp_vault, member):
    vid, name = temp_vault["id"], unique("sftpfirst") + ".bin"
    transport, sftp = _sftp(admin, temp_vault)
    try:
        fh = sftp.open("/%s/%s" % (temp_vault["name"], name), "wb")
        fh.write(b"in flight")
        fh.flush()
        _refused(_open(admin, vid, name))          # not even its own member takes over an SFTP upload
        _refused(_open(member, vid, name))
        fh.close()
    finally:
        transport.close()
    _cancel(member, vid, _session(_open(member, vid, name)))


def test_a_direct_upload_is_refused_while_a_browser_upload_holds_the_name(admin, temp_vault, member):
    vid, name = temp_vault["id"], unique("direct") + ".txt"
    sid = _session(_open(admin, vid, name))
    try:
        for client in (member, admin):              # a direct upload takes over nothing
            _refused(client.post(f"/vaults/{vid}/files", files=[("files", (name, b"direct", "text/plain"))]))
    finally:
        _cancel(admin, vid, sid)
    r = member.post(f"/vaults/{vid}/files", files=[("files", (name, b"direct", "text/plain"))])
    assert r.status_code in (200, 201), r.text
    # ... and it let go of the name when it landed.
    _cancel(admin, vid, _session(_open(admin, vid, name)))


def test_the_listing_shows_another_members_browser_upload_and_not_your_own(admin, temp_vault, member):
    vid, name = temp_vault["id"], unique("listed") + ".bin"
    sid = _session(_open(admin, vid, name))
    try:
        row = _in_flight(member, vid, name)
        assert row is not None, "another member's live browser upload is not in the listing"
        assert row.get("uploading_by"), "a member-grade viewer sees who is uploading"
        assert _in_flight(admin, vid, name) is None, "the uploader's own tray row came back as a locked file"
    finally:
        _cancel(admin, vid, sid)
    assert _in_flight(member, vid, name) is None


def test_a_landed_upload_frees_its_name(admin, temp_vault, member):
    vid, name = temp_vault["id"], unique("landed") + ".bin"
    sid = _session(_open(admin, vid, name))
    _send(admin, vid, sid)
    done = _complete(admin, vid, sid)
    assert done.status_code == 200, done.text
    assert _in_flight(member, vid, name) is None
    _cancel(member, vid, _session(_open(member, vid, name)))


def _redis_cli(*args):
    return subprocess.run(["docker", "exec", _REDIS_CONTAINER, "redis-cli", *args],
                          capture_output=True, text=True, timeout=30)


def test_a_commit_is_refused_when_another_member_took_the_name_during_a_pause(admin, temp_vault, member):
    """A paused upload's lock lapses; if another member starts the name meanwhile, the paused one may
    not land on top of that live upload -- and may once it is gone."""
    if _redis_cli("PING").returncode != 0:
        pytest.skip("needs the stack's Redis container to stand in for a lapsed lock")
    vid, name = temp_vault["id"], unique("paused") + ".bin"
    sid = _session(_open(admin, vid, name))
    _send(admin, vid, sid)
    # The pause outlasted the lock: drop this vault's markers, as their TTL would have.
    listed = _redis_cli("--scan", "--pattern", "upload_marker:v=%s:*" % vid)
    assert listed.returncode == 0, listed.stderr
    keys = [k for k in listed.stdout.split() if k]
    assert keys, "the paused upload held no marker to lapse -- the test would prove nothing"
    assert _redis_cli("DEL", *keys).returncode == 0
    theirs = _session(_open(member, vid, name))        # free again: another member takes it
    _refused(_complete(admin, vid, sid))
    _cancel(member, vid, theirs)
    done = _complete(admin, vid, sid)                   # theirs is gone: this one may land now
    assert done.status_code == 200, done.text
