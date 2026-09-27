"""Live: smart lockout over the web and SFTP.

Wrong passwords count per account and source address, and across all addresses. Here the limits are
set small for the test (3 per address, 3 x 2 = 6 account-wide) so real failures arm the locks, and the
second and third source addresses are requests sent from inside the stack's own containers.

  * failures from one address pause new sign-ins from that address only; the owner signs in from
    another, and a sign-in from the paused address is refused before its password is checked;
  * failures from several addresses reaching the account-wide limit pause sign-ins from everywhere;
  * an automatic lock never ends a session, a live-monitor socket, a device's sync or an open SFTP
    session; an administrator's lock still ends them all;
  * SFTP password and key sign-ins follow the same locks, and SFTP failures count toward them;
  * an administrator's unlock clears the automatic locks;
  * a name that is no account is refused at the same point as an account.

test_sign_in_lockout.py covers the same offline.
"""
import json
import os
import time
import uuid

import paramiko
import pytest

from conftest import ApiClient, BASE_URL, unique
from _account_change_helpers import (SFTP_CONTAINER, arm_lock, host_address, lock_rows, psql,
                                     reset_sign_in_throttle, sign_in_from_inside, signed_in)
from _device_boundary_helpers import grant, mint_sync_cred, register_device

pytestmark = pytest.mark.integration

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
THRESHOLD, MULTIPLE = 3, 2
WRONG = "definitely-not-the-password"


@pytest.fixture
def small_limits(admin):
    """3 failed sign-ins per address, 6 across addresses. The previous values are put back after; the
    SFTP server reads settings through a cache of a few seconds, which is waited out both ways."""
    before = admin.get("/settings").json()
    snap = {k: before.get(k) or 0 for k in ("max_login_attempts", "lockout_backstop_multiplier")}
    r = admin.put("/settings", json={"max_login_attempts": THRESHOLD, "lockout_backstop_multiplier": MULTIPLE})
    assert r.status_code == 200, r.text
    reset_sign_in_throttle()
    yield
    admin.put("/settings", json=snap)
    reset_sign_in_throttle()


def _web(username, password):
    return ApiClient(BASE_URL).session.post(f"{BASE_URL}/auth/login", timeout=30,
                                            json={"username": username, "password": password})


def _from_sftp_container(username, password):
    return sign_in_from_inside(username, password, container=SFTP_CONTAINER, url="http://vault-api:8000")


def _audit(admin, action, uid):
    rows = admin.get("/audit/log", params={"action": action, "user_id": uid, "limit": 200}).json()
    return [r for r in rows if r["action"] == action]


def test_failures_from_one_address_pause_only_that_address(admin, temp_user, small_limits):
    uid, name, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    for _ in range(THRESHOLD):
        assert _web(name, WRONG).status_code == 401
    here = host_address(admin, name)
    assert lock_rows(uid)[here] == (THRESHOLD, True)
    reset_sign_in_throttle()

    for attempt in (pw, "one-more-guess"):
        r = _web(name, attempt)
        assert r.status_code == 403, r.text
        assert "from your network address" in r.json()["detail"]
        assert int(r.headers.get("Retry-After", "0")) > 0
    assert lock_rows(uid)[here] == (THRESHOLD, True), "a refused attempt is not counted"

    status, body, _ = sign_in_from_inside(name, pw)
    assert status == 200 and body["access_token"], body

    (row,) = _audit(admin, "account_auto_locked", uid)
    assert (row["details"]["scope"], row["details"]["address"]) == ("address", here)


def test_failures_from_several_addresses_pause_every_address(admin, temp_user, small_limits):
    uid, name, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    for _ in range(THRESHOLD):
        assert _web(name, WRONG).status_code == 401                 # this host: paused
    for _ in range(THRESHOLD - 1):
        assert _from_sftp_container(name, WRONG)[0] == 401          # a second address, not paused
    assert sign_in_from_inside(name, WRONG)[0] == 401               # a third: the sixth failure

    rows = lock_rows(uid)
    assert rows["*"] == (THRESHOLD * MULTIPLE, True)
    assert rows["127.0.0.1"] == (1, False), "this address has no lock of its own"
    status, body, retry = sign_in_from_inside(name, pw)
    assert status == 403 and "from different places" in body["detail"] and int(retry) > 0, body
    status, body, _ = _from_sftp_container(name, pw)
    assert status == 403, body
    scopes = sorted(r["details"]["scope"] for r in _audit(admin, "account_auto_locked", uid))
    assert scopes == ["account", "address"]


def _sftp_session(username, password):
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    t.connect(username=username, password=password)
    return t, paramiko.SFTPClient.from_transport(t)


def _ws_open(token):
    websocket = pytest.importorskip("websocket")
    ws = websocket.create_connection(BASE_URL.replace("http://", "ws://").replace("https://", "wss://")
                                     + "/ws/monitor", timeout=10)
    ws.send(json.dumps({"type": "auth", "token": token}))
    return ws


def _ws_alive(ws):
    """True if the socket still answers a ping."""
    try:
        ws.send(json.dumps({"type": "ping"}))
        ws.settimeout(5)
        for _ in range(20):
            frame = ws.recv()
            if frame and json.loads(frame).get("type") in ("pong", "error"):
                return json.loads(frame).get("type") == "pong"
        return False
    except Exception:  # noqa: BLE001 - a closed socket
        return False


def test_an_automatic_lock_keeps_sessions_and_devices_an_administrators_lock_does_not(admin, temp_user):
    uid, name, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    reset_sign_in_throttle()
    session = signed_in(temp_user)
    vault = session.create_vault(name=unique("lockout"))
    device = register_device(session)
    grant(session, device["device_id"], vault["id"])
    transport, sftp = _sftp_session(name, pw)
    ws = _ws_open(session.token)
    try:
        arm_lock(uid, "*")                                   # account-wide: every new sign-in refused
        # And the kind of automatic lock a release before this one left on the account row: timed,
        # so also not an administrator's. Neither may end what is already signed in.
        psql(f"UPDATE users SET is_locked=true, locked_until=(now() AT TIME ZONE 'utc') + interval "
             f"'10 minutes' WHERE id='{uid}'")
        assert _web(name, pw).status_code == 403

        assert session.get("/users/me").status_code == 200, "the session carries on"
        assert mint_sync_cred(device["secret"], vault["id"]).status_code == 200, "the device syncs"
        sftp.listdir("/")                                     # the open SFTP session carries on
        second = _ws_open(session.token)                      # a new socket for the same session opens
        assert _ws_alive(second)
        second.close()
        time.sleep(6)                                         # past the socket's periodic re-check
        assert _ws_alive(ws), "the live socket carries on"

        assert admin.patch(f"/users/{uid}", json={"is_locked": True}).status_code == 200
        assert session.get("/users/me").status_code in (401, 403), "an administrator's lock ends it"
        refused = mint_sync_cred(device["secret"], vault["id"])
        assert refused.status_code == 401 and "account-inactive" in refused.text, refused.text
        with pytest.raises((OSError, EOFError, paramiko.SSHException)):
            sftp.listdir("/")
        deadline = time.time() + 15
        while time.time() < deadline and _ws_alive(ws):
            time.sleep(1)
        assert not _ws_alive(ws), "an administrator's lock closes the live socket"
    finally:
        for closing in (ws.close, sftp.close, transport.close):
            try:
                closing()
            except Exception:  # noqa: BLE001
                pass
        admin.patch(f"/users/{uid}", json={"is_locked": False})
        admin.delete_vault(vault["id"])


def _gen_rsa():
    k = paramiko.RSAKey.generate(2048)
    return k, f"{k.get_name()} {k.get_base64()}"


def _sftp_signs_in(username, *, password=None, pkey=None):
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    try:
        t.connect(username=username, password=password, pkey=pkey)
        return True
    except (paramiko.SSHException, EOFError, OSError):
        return False
    finally:
        t.close()


def test_sftp_sign_ins_follow_the_same_locks(admin, temp_user, small_limits):
    uid, name, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    key, public = _gen_rsa()
    assert admin.post(f"/users/{uid}/ssh-keys", json={"name": "k", "public_key": public}).status_code == 200
    time.sleep(6)                          # the SFTP server's settings cache takes up the small limits
    for _ in range(THRESHOLD):
        assert not _sftp_signs_in(name, password=WRONG)
    paused = [src for src, (count, locked) in lock_rows(uid).items() if src != "*" and locked]
    assert len(paused) == 1, lock_rows(uid)

    reset_sign_in_throttle()               # the throttle fires at the same count; step past it
    assert not _sftp_signs_in(name, password=pw), "the right password is refused from the paused address"
    assert not _sftp_signs_in(name, pkey=key), "and so is the account's key"
    status, body, _ = sign_in_from_inside(name, pw)
    assert status == 200, body

    assert admin.patch(f"/users/{uid}", json={"is_locked": False}).status_code == 200
    assert lock_rows(uid) == {}, "an administrator's unlock clears the automatic locks"
    assert _sftp_signs_in(name, pkey=key)
    assert _sftp_signs_in(name, password=pw)


def test_the_account_wide_lock_refuses_an_sftp_key(admin, temp_user):
    uid, name = temp_user["id"], temp_user["_username"]
    key, public = _gen_rsa()
    assert admin.post(f"/users/{uid}/ssh-keys", json={"name": "k", "public_key": public}).status_code == 200
    assert _sftp_signs_in(name, pkey=key)
    arm_lock(uid, "*")
    assert not _sftp_signs_in(name, pkey=key)
    assert admin.patch(f"/users/{uid}", json={"is_locked": False}).status_code == 200
    assert _sftp_signs_in(name, pkey=key)


def test_the_users_list_shows_a_paused_account_and_unlock_is_told(admin, temp_user):
    uid = temp_user["id"]
    arm_lock(uid, "*")
    row = next(u for u in admin.get("/users").json() if u["id"] == uid)
    assert row["is_locked"] is False and row["sign_in_block"]["scope"] == "account"
    assert admin.patch(f"/users/{uid}", json={"is_locked": False}).status_code == 200
    row = next(u for u in admin.get("/users").json() if u["id"] == uid)
    assert row["sign_in_block"] is None
    told = psql(f"SELECT title FROM notifications WHERE user_id='{uid}' AND type='account_changed'")
    assert told == "Your account was unlocked"


def test_a_name_that_is_no_account_is_refused_at_the_same_point(admin, temp_user, small_limits):
    nobody = f"nobody-{uuid.uuid4().hex[:10]}"
    for name in (temp_user["_username"], nobody):
        seen = []
        for _ in range(THRESHOLD):
            seen.append(_web(name, WRONG).status_code)
        reset_sign_in_throttle()               # the throttle fires at the same count; step past it
        refused = _web(name, WRONG)
        seen.append(refused.status_code)
        assert seen == [401] * THRESHOLD + [403], (name, seen)
        assert "from your network address" in refused.json()["detail"]
