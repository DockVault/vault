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
