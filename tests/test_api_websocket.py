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


@pytest.mark.websocket
def test_ws_revoked_token_closed(base_url, admin):
    # A *syntactically valid* token whose session has been revoked (here: logout, which denylists
    # the session token) must be rejected at the /ws/monitor handshake -- not merely a bogus token.
    # Otherwise a logged-out (or, worse, a revoked admin) token could stream the live feed until its
    # natural expiry. verify_access_token only checks signature+exp, so the handshake must re-check
    # revocation state itself.
    from conftest import ApiClient

    user = admin.create_user(role="user")
    try:
        client = ApiClient()
        client.login(user["_username"], user["_password"])
        token = client.token

        # Control: while the session is live the token authenticates (a "connected" frame),
        # proving the token is otherwise valid (so the rejection below is due to revocation).
        live = websocket.create_connection(_ws_url(base_url), timeout=10)
        try:
            live.send(json.dumps({"type": "auth", "token": token}))
            live.settimeout(8)
            first = json.loads(live.recv())
            assert first.get("type") == "connected", \
                "control: a live-session token should authenticate onto /ws/monitor"
        finally:
            try:
                live.close()
            except Exception:
                pass

        # Revoke the session: logout denylists the session token.
        assert client.post("/api/logout").status_code == 200

        # The now-revoked token must be rejected (an error frame) and the socket closed -- never
        # authenticated, never streamed events.
        ws = websocket.create_connection(_ws_url(base_url), timeout=10)
        try:
            ws.send(json.dumps({"type": "auth", "token": token}))
            ws.settimeout(8)
            first = json.loads(ws.recv())
            assert first.get("type") == "error", \
                "a revoked token must be rejected at the handshake, not authenticated"
            with pytest.raises(Exception):
                # after the error frame the server closes rather than streaming events
                while True:
                    ws.recv()
        finally:
            try:
                ws.close()
            except Exception:
                pass
    finally:
        admin.delete_user(user["id"])


@pytest.mark.websocket
def test_ws_revoked_temp_cred_closed(base_url, admin):
    # A temp credential whose session was force-closed by INVALIDATING the credential must be
    # rejected at the /ws/monitor handshake. Invalidation flips its ActiveSession.is_active to False
    # (see _revoke_sessions) but does NOT denylist the token, so the handshake must apply the same
    # still-active-session check get_current_user does for temp sessions -- otherwise a revoked temp
    # credential's JWT keeps opening the live-monitor socket until its natural expiry.
    from conftest import unique, ApiClient

    tc = admin.post("/auth/temp-credentials", json={"note": unique("ws-rev")}).json()
    tclient = ApiClient()
    tclient.login(tc["temp_username"], tc["credential"])
    token = tclient.token

    # Control: while the session is live the temp token authenticates (a "connected" frame),
    # proving the token is otherwise valid (so the rejection below is due to revocation).
    live = websocket.create_connection(_ws_url(base_url), timeout=10)
    try:
        live.send(json.dumps({"type": "auth", "token": token}))
        live.settimeout(8)
        first = json.loads(live.recv())
        assert first.get("type") == "connected", \
            "control: a live temp-credential token should authenticate onto /ws/monitor"
    finally:
        try:
            live.close()
        except Exception:
            pass

    # Invalidate the credential: _revoke_sessions flips its ActiveSession.is_active to False.
    assert admin.post(f"/temp-creds/{tc['temp_username']}/deactivate").status_code == 200

    # The now-revoked temp token must be rejected (an error frame) and the socket closed.
    ws = websocket.create_connection(_ws_url(base_url), timeout=10)
    try:
        ws.send(json.dumps({"type": "auth", "token": token}))
        ws.settimeout(8)
        first = json.loads(ws.recv())
        assert first.get("type") == "error", \
            "a revoked temp credential must be rejected at the handshake, not authenticated"
        with pytest.raises(Exception):
            while True:
                ws.recv()
    finally:
        try:
            ws.close()
        except Exception:
            pass


@pytest.mark.websocket
def test_ws_temp_cred_past_validity_window_closed(base_url, admin):
    # Parity with get_current_user: a temp credential PAST its own validity window (deactivate_at)
    # must be refused at the handshake even though its ActiveSession row is still nominally active
    # and the token is not denylisted. Temp JWTs keep a fixed life decoupled from validity_minutes,
    # so a credential minted with a short validity has a window where HTTP already rejects it but the
    # socket would otherwise still open. Backdate deactivate_at directly (leaving the session row
    # active) to land squarely in that window.
    import os
    import subprocess
    from conftest import unique, ApiClient

    _DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    tc = admin.post("/auth/temp-credentials", json={"note": unique("ws-window")}).json()
    tclient = ApiClient()
    tclient.login(tc["temp_username"], tc["credential"])
    token = tclient.token

    subprocess.run(
        ["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-c",
         "UPDATE temporary_credentials SET deactivate_at = NOW() - INTERVAL '1 hour' "
         "WHERE temp_username = '%s'" % tc["temp_username"]],
        check=True, capture_output=True, text=True, timeout=20)

    ws = websocket.create_connection(_ws_url(base_url), timeout=10)
    try:
        ws.send(json.dumps({"type": "auth", "token": token}))
        ws.settimeout(8)
        first = json.loads(ws.recv())
        assert first.get("type") == "error", \
            "a temp credential past its validity window must be refused at the handshake"
    finally:
        try:
            ws.close()
        except Exception:
            pass
