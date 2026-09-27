"""The Activity signal over the live socket, against a running vault.

A committed audit row sends its id and category to administrators' own sessions, and nothing that
names anyone. Everyone else's socket stays quiet, and a temporary credential no longer hears the other
credentials of its account sign in."""
import json
import time

import pytest

from conftest import ApiClient, unique

websocket = pytest.importorskip("websocket")  # websocket-client

pytestmark = pytest.mark.websocket


def _ws_url(base_url):
    return base_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws/monitor"


def _open(base_url, token):
    ws = websocket.create_connection(_ws_url(base_url), timeout=10)
    ws.send(json.dumps({"type": "auth", "token": token}))
    ws.settimeout(8)
    assert json.loads(ws.recv()).get("type") == "connected"
    return ws


def _frames(ws, seconds, until=None):
    """The raw frames the socket receives within `seconds`, stopping early when `until(frames)`."""
    ws.settimeout(0.5)
    out, deadline = [], time.time() + seconds
    while time.time() < deadline:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            continue
        if raw:
            out.append(raw)
            if until and until(out):
                break
    return out


def _signalled(frames):
    return [e for raw in frames for e in (json.loads(raw).get("events") or [])
            if json.loads(raw).get("type") == "activity"]


def _failed_sign_in(name):
    r = ApiClient().post("/auth/login", json={"username": name, "password": "not-the-password-1"})
    assert r.status_code in (401, 403, 429), r.text


def _row_id(admin, name):
    for _ in range(20):
        body = admin.get("/activity/events", params={"user": name}).json()
        if body["events"]:
            return body["events"][0]["id"]
        time.sleep(0.2)
    raise AssertionError(f"no audit row for {name}")


def _close(*sockets):
    for ws in sockets:
        try:
            ws.close()
        except Exception:
            pass


def test_an_administrator_hears_a_new_row_by_id_and_category_only(base_url, admin):
    name = unique("signal")
    ws = _open(base_url, admin.token)
    try:
        _failed_sign_in(name)
        row = _row_id(admin, name)
        frames = _frames(ws, 8, until=lambda fs: any(e["id"] == row for e in _signalled(fs)))
        hits = [e for e in _signalled(frames) if e["id"] == row]
        assert hits == [{"id": row, "category": "sign_in"}], frames
        # Nothing the row says travels: not the name typed at sign-in, not the address.
        assert not any(name in raw for raw in frames)
        for raw in frames:
            data = json.loads(raw)
            if data.get("type") == "activity":
                assert set(data) == {"type", "events"}
                assert all(set(e) == {"id", "category"} for e in data["events"])
    finally:
        _close(ws)


def test_nobody_but_an_administrators_own_session_hears_it(base_url, admin, temp_user_client):
    # Control: an administrator's socket hears the row. A user's socket and a temporary credential made
    # by the administrator (which keeps the admin role) hear nothing of it.
    tc = admin.post("/auth/temp-credentials", json={"note": unique("sig-iso")}).json()
    tclient = ApiClient()
    tclient.login(tc["temp_username"], tc["credential"])
    aws = _open(base_url, admin.token)
    uws = _open(base_url, temp_user_client.token)
    tws = _open(base_url, tclient.token)
    try:
        name = unique("signal")
        _failed_sign_in(name)
        row = _row_id(admin, name)
        seen = _frames(aws, 8, until=lambda fs: any(e["id"] == row for e in _signalled(fs)))
        assert any(e["id"] == row for e in _signalled(seen)), "control: the administrator hears it"
        assert _signalled(_frames(uws, 2)) == []
        assert _signalled(_frames(tws, 1)) == []
    finally:
        _close(aws, uws, tws)
        admin.post(f"/temp-creds/{tc['temp_username']}/delete")


def test_an_administrator_whose_role_is_taken_away_stops_hearing_it(base_url, admin):
    other = admin.create_user(role="admin")
    c = ApiClient()
    c.login(other["_username"], other["_password"])
    ws = _open(base_url, c.token)
    try:
        first = unique("signal")
        _failed_sign_in(first)
        row = _row_id(admin, first)
        got = _frames(ws, 8, until=lambda fs: any(e["id"] == row for e in _signalled(fs)))
        assert any(e["id"] == row for e in _signalled(got)), "control: an administrator hears it"
        r = admin.patch(f"/users/{other['id']}", json={"role": "user"})
        assert r.status_code == 200, r.text
        _frames(ws, 7)                               # the socket re-checks its session every ~5 s
        _failed_sign_in(unique("signal"))
        assert _signalled(_frames(ws, 3)) == []
    finally:
        _close(ws)
        admin.delete_user(other["id"])


def test_the_deployment_wide_feed_no_longer_reaches_an_administrator(base_url, admin):
    # Another person signing in and uploading used to reach every administrator's socket with their
    # name, address and file names. Now it is a signal and nothing more.
    user = admin.create_user(role="user")
    ws = _open(base_url, admin.token)
    try:
        c = ApiClient()
        c.login(user["_username"], user["_password"])
        vault = c.create_vault(name=unique("sig-vault"))
        r = c.post(f"/vaults/{vault['id']}/files", files=[("files", ("sig-private.txt", b"hello", "text/plain"))])
        assert r.status_code in (200, 201), r.text
        frames = _frames(ws, 4)
        assert _signalled(frames), "control: the administrator hears that something happened"
        joined = "\n".join(frames)
        for secret in (user["_username"], "sig-private", vault["name"]):
            assert secret not in joined
        assert all(json.loads(raw).get("type") in ("activity", "pong") for raw in frames), frames
        c.delete_vault(vault["id"])
    finally:
        _close(ws)
        admin.delete_user(user["id"])


def test_a_temporary_credential_does_not_hear_another_credential_of_its_account_sign_in(base_url, admin):
    user = admin.create_user(role="user")
    uc = ApiClient()
    uc.login(user["_username"], user["_password"])
    first = uc.post("/auth/temp-credentials", json={"note": unique("sig-a")}).json()
    second = uc.post("/auth/temp-credentials", json={"note": unique("sig-b")}).json()
    fc = ApiClient()
    fc.login(first["temp_username"], first["credential"])
    uws = _open(base_url, uc.token)
    fws = _open(base_url, fc.token)
    try:
        ApiClient().login(second["temp_username"], second["credential"])

        def sign_in_of_second(fs):
            return any(second["temp_username"] in raw for raw in fs)

        # Control: the account's own session is told, with the credential's name.
        assert sign_in_of_second(_frames(uws, 8, until=sign_in_of_second)), "control: the account hears it"
        assert not sign_in_of_second(_frames(fws, 3)), "another credential must not learn its name and address"
    finally:
        _close(uws, fws)
        for tc in (first, second):
            uc.post(f"/temp-creds/{tc['temp_username']}/delete")
        admin.delete_user(user["id"])
