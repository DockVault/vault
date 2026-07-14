"""The live-monitor websocket at /ws/monitor.

Auth handshake: the first client message must be {"type":"auth","token":JWT}.
A missing/invalid token closes the socket (code 1008)."""
import json

import pytest

websocket = pytest.importorskip("websocket")  # websocket-client


def _ws_url(base_url: str) -> str:
    return base_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws/monitor"


@pytest.mark.websocket
def test_ws_auth_success(base_url, admin):
    ws = websocket.create_connection(_ws_url(base_url), timeout=10)
    try:
        ws.send(json.dumps({"type": "auth", "token": admin.token}))
        # ping/pong keepalive should work once authenticated
        ws.send(json.dumps({"type": "ping"}))
        ws.settimeout(8)
        got_message = False
        for _ in range(5):
            try:
                msg = ws.recv()
            except Exception:
                break
            if msg:
                got_message = True
                break
        assert got_message, "expected at least one frame after authenticating"
    finally:
        ws.close()


@pytest.mark.websocket
def test_ws_temp_cred_isolated_from_others_activity(base_url, admin):
    # Temp-cred isolation: /ws/monitor must give a temp credential ONLY its own activity, never the
    # deployment-wide feed. Connect an admin WS (control) and a temp-cred WS, trigger a fresh user's
    # login (an activity event owned by that user), and assert the admin WS surfaces it while the temp
    # WS does not.
    import time as _t
    from conftest import unique, ApiClient

    tc = admin.post("/auth/temp-credentials", json={"note": unique("ws-iso")}).json()
    tclient = ApiClient()
    tclient.login(tc["temp_username"], tc["credential"])
    other = admin.create_user(role="user")

    def _drain(ws):
        ws.settimeout(1)
        for _ in range(5):
            try:
                ws.recv()
            except Exception:
                break

    def _saw(ws, uname, seconds):
        ws.settimeout(1)
        deadline = _t.time() + seconds
        while _t.time() < deadline:
            try:
                msg = ws.recv()
            except Exception:
                continue
            if msg and uname in msg:
                return True
        return False

    aws = websocket.create_connection(_ws_url(base_url), timeout=10)
    tws = websocket.create_connection(_ws_url(base_url), timeout=10)
    try:
        aws.send(json.dumps({"type": "auth", "token": admin.token}))
        tws.send(json.dumps({"type": "auth", "token": tclient.token}))
        _drain(aws)
        _drain(tws)
        # Trigger another user's activity (login broadcasts an activity event owned by them).
        ApiClient().login(other["_username"], other["_password"])
        # Control (non-vacuous guard): the admin WS should see it — proves the event was broadcast.
        assert _saw(aws, other["_username"], 6), "admin WS should see the other user's activity (control)"
        # Isolation: the temp-cred WS must NOT see another user's activity.
        assert not _saw(tws, other["_username"], 3), "temp cred WS must not see another user's activity"
    finally:
        try:
            aws.close()
        except Exception:
            pass
        try:
            tws.close()
        except Exception:
            pass
        admin.delete_user(other["id"])


@pytest.mark.websocket
def test_ws_invalid_token_closed(base_url):
    ws = websocket.create_connection(_ws_url(base_url), timeout=10)
    try:
        ws.send(json.dumps({"type": "auth", "token": "bogus-token"}))
        ws.settimeout(8)
        with pytest.raises(Exception):
            # server should close the connection rather than stream events
            while True:
                ws.recv()
    finally:
        try:
            ws.close()
        except Exception:
            pass
