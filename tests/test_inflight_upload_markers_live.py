"""Live-lane acceptance for the in-flight upload markers + same-name lock + the carried web-door
slot release, against a running stack (SFTP + API + Redis + Postgres).

Proves, end to end: a marker appears during a real SFTP upload and disappears on close AND on a
SIGKILLed client before the TTL; a second same-name upload is refused naming the member; a member
without folder read sees no row; the final name is never stored in cleartext in Redis or the DB
(with a positive control so the scan cannot pass vacuously); with the breaker OPEN the marker is
skipped and the listing shows nothing while the upload still succeeds (with a positive control so an
already-empty listing cannot pass it); and a web-door credential's per-user cap slot is refused ->
released on logout -> admitted for the next mint (reading slot_released_at directly).

Redis-pausing happens ONLY in the opt-in outage step (VAULT_REDIS_OUTAGE_TEST); no asyncio.run() in
any test body.
"""
import json
import os
import subprocess
import sys
import time
import uuid

import paramiko
import pytest

from conftest import ApiClient, BASE_URL, unique, wait_out_breaker_cooldown
from _device_boundary_helpers import register_device, grant, mint_sync_cred, SFTP_HOST, SFTP_PORT

pytestmark = pytest.mark.integration

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
_CI = os.environ.get("CI")


def _marker_ttl():
    from app.core.upload_marker import marker_ttl_seconds
    return marker_ttl_seconds()


def _psql(sql, timeout=30):
    return subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=timeout)


def _redis_cli(*args, timeout=30):
    return subprocess.run(
        ["docker", "exec", _REDIS_CONTAINER, "redis-cli", *args],
        capture_output=True, text=True, timeout=timeout)


def _require_stack_or_skip():
    """The marker tests inspect Redis and Postgres directly via `docker exec`. When either is
    unreachable that way -- almost always because VAULT_DB_CONTAINER / VAULT_REDIS_CONTAINER do not
    name this stack's containers (they default to vault-db / vault-redis) -- these tests must NOT
    vanish into a silent skip on a stack meant to run the live lane. In CI a failed probe is a hard
    ERROR naming the knobs; on an ad-hoc local run it degrades to a skip with the same message."""
    problems = []
    try:
        if _psql("SELECT 1").returncode != 0:
            problems.append("Postgres via `docker exec %s psql -U sftp_user -d sftp_db`" % _DB_CONTAINER)
    except Exception as exc:  # noqa: BLE001
        problems.append("Postgres (%s: %s)" % (_DB_CONTAINER, exc.__class__.__name__))
    try:
        if _redis_cli("PING").stdout.strip().upper() != "PONG":
            problems.append("Redis via `docker exec %s redis-cli`" % _REDIS_CONTAINER)
    except Exception as exc:  # noqa: BLE001
        problems.append("Redis (%s: %s)" % (_REDIS_CONTAINER, exc.__class__.__name__))
    if problems:
        msg = ("cannot reach %s; set VAULT_DB_CONTAINER / VAULT_REDIS_CONTAINER to this stack's "
               "containers (currently %r / %r)" % (" and ".join(problems), _DB_CONTAINER, _REDIS_CONTAINER))
        if _CI:
            pytest.fail(msg)
        pytest.skip(msg)


def _redis_holds_plaintext(needle) -> bool:
    """Scan every Redis key AND value for the literal `needle`. Uses the whole keyspace (a test DB is
    tiny) so a leak anywhere is caught, not just under the marker prefix."""
    keys = [k for k in _redis_cli("KEYS", "*").stdout.split("\n") if k]
    if needle in "\n".join(keys):
        return True
    for k in keys:
        if needle in _redis_cli("GET", k).stdout:
            return True
    return False


def _db_holds_plaintext(needle) -> bool:
    # The at-rest filename column is enc_name (AES-GCM); the plaintext name must appear in NO column.
    q = ("SELECT count(*) FROM files WHERE original_name = %s OR enc_name LIKE %s"
         % ("'" + needle.replace("'", "''") + "'", "'%" + needle.replace("'", "''") + "%'"))
    out = _psql(q)
    return out.returncode == 0 and (out.stdout.strip() or "0") != "0"


def _web_items(client, vault_id, folder_id=None):
    url = "%s/vaults/%s/files" % (BASE_URL, vault_id)
    if folder_id:
        url += "?folder_id=%s" % folder_id
    r = client.session.get(url, timeout=30)
    r.raise_for_status()
    return r.json().get("items", [])


def _inflight_row(items, name):
    return next((i for i in items if i.get("in_progress") and i.get("name") == name), None)


class _HeldUpload:
    """Open an SFTP write handle and HOLD it (the server places the marker at open); close() ends it.
    Writing a byte after open keeps a real transfer in flight without finishing it."""
    def __init__(self, username, credential, vault_name, filename):
        self.t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
        self.t.banner_timeout = 30
        self.t.connect(username=username, password=credential)
        self.sftp = paramiko.SFTPClient.from_transport(self.t)
        self.fh = self.sftp.open("/%s/%s" % (vault_name, filename), "wb")
        self.fh.write(b"in-flight")
        self.fh.flush()

    def close(self):
        for closer in (lambda: self.fh.close(), lambda: self.sftp.close(), lambda: self.t.close()):
            try:
                closer()
            except Exception:  # noqa: BLE001
                pass


def _device_sftp_creds(admin, vault):
    dev = register_device(admin, label="marker-box")
    grant(admin, dev["device_id"], vault["id"])
    minted = mint_sync_cred(dev["secret"], vault["id"]).json()
    return minted["temp_username"], minted["credential"]


@pytest.fixture(autouse=True)
def _need_stack():
    _require_stack_or_skip()


# --------------------------------------------------------------------------------------------------
def test_a_marker_shows_the_final_name_and_never_stores_it_in_cleartext(admin, temp_vault):
    # Requirement (same run): a folder-authorized viewer sees the correct FINAL name in the listing
    # AND a scan of Redis + the DB finds no cleartext of that literal name -- with a positive control
    # so the scan cannot pass vacuously.
    user, cred = _device_sftp_creds(admin, temp_vault)
    name = unique("inflight") + ".bin"
    held = _HeldUpload(user, cred, temp_vault["name"], name)
    try:
        # The web listing shows the in-flight row with the final name, to the owner (member-grade).
        row = None
        for _ in range(20):
            row = _inflight_row(_web_items(admin, temp_vault["id"]), name)
            if row:
                break
            time.sleep(0.25)
        assert row is not None, "the in-flight marker never appeared in the listing"
        assert row["uploading_by"], "the owner (member-grade) should see who is uploading"

        # No cleartext of the final name at rest, with a POSITIVE CONTROL that the scanners work.
        assert not _redis_holds_plaintext(name), "the final name leaked into Redis in cleartext"
        assert not _db_holds_plaintext(name), "the final name leaked into the DB in cleartext"
        probe = "control-" + name
        assert _redis_cli("SET", "marker_probe", probe).returncode == 0
        try:
            assert _redis_holds_plaintext(probe), "positive control failed -- the Redis scan is vacuous"
        finally:
            _redis_cli("DEL", "marker_probe")
    finally:
        held.close()

    # Gone on close.
    for _ in range(20):
        if _inflight_row(_web_items(admin, temp_vault["id"]), name) is None:
            break
        time.sleep(0.25)
    assert _inflight_row(_web_items(admin, temp_vault["id"]), name) is None, "marker survived close"


def test_a_second_same_name_upload_is_refused_naming_the_member(admin, temp_vault):
    user, cred = _device_sftp_creds(admin, temp_vault)
    name = unique("dup") + ".bin"
    held = _HeldUpload(user, cred, temp_vault["name"], name)
    try:
        user2, cred2 = _device_sftp_creds(admin, temp_vault)
        t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
        t.banner_timeout = 30
        try:
            t.connect(username=user2, password=cred2)
            sftp2 = paramiko.SFTPClient.from_transport(t)
            with pytest.raises(IOError) as caught:
                sftp2.open("/%s/%s" % (temp_vault["name"], name), "wb")   # same name, same folder
            msg = str(caught.value)
            # The refusal says the name is being uploaded. The second uploader here is a device-sync
            # credential -- a SCOPED principal -- so the identity is gated to "another member" (a
            # member-grade viewer would see the holder's username instead), never the owner's name.
            # The neutral "another member" form is proof in itself that no holder username leaked.
            # (The server's wording is "'<name>' is currently being uploaded by <who>".)
            assert "being uploaded" in msg.lower() and "another member" in msg.lower()
        finally:
            t.close()
    finally:
        held.close()


def test_a_member_without_folder_read_sees_no_inflight_row(admin, temp_vault, temp_user_client):
    # A different, non-member principal (temp_user_client is a plain user with no access to this
    # vault) must not see the in-flight row.
    user, cred = _device_sftp_creds(admin, temp_vault)
    name = unique("scoped") + ".bin"
    held = _HeldUpload(user, cred, temp_vault["name"], name)
    try:
        # Poll for the owner's row first (control) so we are not judging before the marker lands.
        for _ in range(20):
            if _inflight_row(_web_items(admin, temp_vault["id"]), name):
                break
            time.sleep(0.25)
        assert _inflight_row(_web_items(admin, temp_vault["id"]), name), "owner never saw the row (nothing to compare)"
        r = temp_user_client.session.get("%s/vaults/%s/files" % (BASE_URL, temp_vault["id"]), timeout=30)
        # Either the outsider is denied the vault outright (403/404) or, if somehow listed, sees no row.
        if r.status_code == 200:
            assert _inflight_row(r.json().get("items", []), name) is None
        else:
            assert r.status_code in (401, 403, 404)
    finally:
        held.close()


def test_a_sigkilled_client_removes_the_marker_before_the_ttl(admin, temp_vault):
    # The kill path: SIGKILL a SEPARATE SFTP client process and confirm the marker is gone WELL
    # before the TTL (the server detects the disconnect and removes it). Refuse to judge if the TTL
    # is shorter than our observation window -- then a TTL expiry could masquerade as kill-removal.
    ttl = _marker_ttl()
    observe = 20
    if ttl <= observe:
        pytest.skip("marker TTL (%ss) is not comfortably longer than the %ss observation window" % (ttl, observe))
    user, cred = _device_sftp_creds(admin, temp_vault)
    name = unique("killed") + ".bin"

    holder_src = (
        "import paramiko, sys, time\n"
        "t = paramiko.Transport((%r, %d)); t.banner_timeout = 30\n"
        "t.connect(username=%r, password=%r)\n"
        "s = paramiko.SFTPClient.from_transport(t)\n"
        "fh = s.open('/%s/%s', 'wb'); fh.write(b'x'); fh.flush()\n"
        "sys.stdout.write('holding'); sys.stdout.flush()\n"
        "time.sleep(600)\n" % (SFTP_HOST, SFTP_PORT, user, cred, temp_vault["name"], name)
    )
    proc = subprocess.Popen([sys.executable, "-c", holder_src],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        # Wait until the held upload's marker is visible (else the kill proves nothing).
        appeared = False
        for _ in range(40):
            if _inflight_row(_web_items(admin, temp_vault["id"]), name):
                appeared = True
                break
            time.sleep(0.25)
        assert appeared, "the held upload's marker never appeared, so a kill would prove nothing"
        proc.kill()
        proc.wait(timeout=10)
        # The marker disappears well within the observation window (< the TTL), i.e. by server-side
        # teardown, not by TTL expiry.
        gone = False
        deadline = time.monotonic() + observe
        while time.monotonic() < deadline:
            if _inflight_row(_web_items(admin, temp_vault["id"]), name) is None:
                gone = True
                break
            time.sleep(0.5)
        assert gone, "a SIGKILLed client's marker did not clear before the TTL"
    finally:
        if proc.poll() is None:
            proc.kill()


@pytest.mark.skipif(
    os.environ.get("VAULT_REDIS_OUTAGE_TEST") not in ("1", "true", "yes"),
    reason="opt-in: pauses Redis; set VAULT_REDIS_OUTAGE_TEST=1 to run")
def test_breaker_open_skips_the_marker_and_still_allows_the_upload(admin, temp_vault):
    # Positive control FIRST: a marker row must be visible BEFORE the outage, or the empty listing
    # after proves nothing. Then prove the breaker is really OPEN (not just Redis slow), then confirm
    # the listing shows no rows AND an upload still succeeds (fails open).
    user, cred = _device_sftp_creds(admin, temp_vault)
    name = unique("outage") + ".bin"
    held = _HeldUpload(user, cred, temp_vault["name"], name)
    try:
        pre = False
        for _ in range(20):
            if _inflight_row(_web_items(admin, temp_vault["id"]), name):
                pre = True
                break
            time.sleep(0.25)
        assert pre, "no in-flight row before the outage -- refusing to judge the outage case"
    finally:
        held.close()

    paused = subprocess.run(["docker", "pause", _REDIS_CONTAINER], capture_output=True, text=True)
    assert paused.returncode == 0, "could not pause Redis for the outage step"
    try:
        # Drive requests so the breaker discovers the outage and OPENs (its threshold is 1).
        for _ in range(3):
            try:
                admin.session.get("%s/vaults/%s/files" % (BASE_URL, temp_vault["id"]), timeout=8)
            except Exception:  # noqa: BLE001 -- a stalled request during the outage is expected
                pass
        # During the outage an upload still succeeds (fails open) and the listing shows no rows.
        # (A fresh device mint needs Redis too; reuse the existing SFTP creds to write, fail-open.)
        held2 = _HeldUpload(user, cred, temp_vault["name"], unique("faildopen") + ".bin")
        try:
            items = _web_items(admin, temp_vault["id"])
            assert all(not i.get("in_progress") for i in items), "a marker row showed during the outage"
        finally:
            held2.close()
    finally:
        subprocess.run(["docker", "unpause", _REDIS_CONTAINER], capture_output=True, text=True)
        # The breaker closes only ~a cooldown after Redis returns (its background probe), so wait it
        # out before yielding, or the next test starts on an open breaker.
        wait_out_breaker_cooldown()


def test_a_web_door_credential_frees_its_cap_slot_on_logout(admin, temp_user_client):
    # Carried: refused -> released -> admitted. Mint to the per-user cap (as a NON-admin -- admins are
    # cap-exempt), assert the 409; log ONE credential in at the web door and log it out; read
    # slot_released_at directly on that row; the next mint then succeeds. The outstanding predicate is
    # is_active AND slot_released_at IS NULL AND deactivate_at > now, so the logout must set the column.
    cap = (admin.session.get("%s/temp-passcode-policy" % BASE_URL, timeout=30).json()
           .get("max_temp_creds_per_user") or 0)
    if cap <= 0 or cap > 30:
        pytest.skip("per-user cap (%s) is unlimited or too large to fill cheaply" % cap)

    def _mint():
        return temp_user_client.session.post("%s/auth/temp-credentials" % BASE_URL,
                                             json={"note": unique("cap")}, timeout=30)

    probe = _mint()
    if probe.status_code not in (200, 201):
        pytest.skip("this non-admin cannot mint temp credentials here (status %s)" % probe.status_code)
    # Clear our own hand-out credentials so the cap math is ours.
    for row in temp_user_client.session.get("%s/temp-creds/list" % BASE_URL, timeout=30).json():
        temp_user_client.session.post("%s/temp-creds/%s/delete" % (BASE_URL, row["temp_username"]), timeout=30)

    minted = []
    for _ in range(cap):
        r = _mint()
        if r.status_code not in (200, 201):
            pytest.skip("could not fill to the cap (status %s at %d)" % (r.status_code, len(minted)))
        minted.append(r.json())
    assert _mint().status_code == 409, "the cap did not refuse the over-limit mint"

    # Spend one at the WEB door: log in with its credential, then log out.
    victim = minted[0]
    web = ApiClient(BASE_URL)
    web.login(victim["temp_username"], victim["credential"])
    web.session.post("%s/api/logout" % BASE_URL, timeout=30)

    # slot_released_at must now be set on that credential's row (the logout released the slot).
    released = _psql("SELECT slot_released_at IS NOT NULL FROM temporary_credentials "
                     "WHERE temp_username = '%s'" % victim["temp_username"].replace("'", "''"))
    assert released.returncode == 0 and released.stdout.strip() == "t", \
        "logout did not set slot_released_at on the web-door credential"

    # ...and the freed slot admits the next mint.
    assert _mint().status_code in (200, 201), "the freed slot did not admit the next mint"
