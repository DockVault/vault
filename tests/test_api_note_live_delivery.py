"""Live delivery: sending a note pushes a per-recipient nudge over /ws/monitor so the recipient's
bell (and an open Notes list) can refresh without a page reload. The nudge is per-user filtered and
carries no note content."""
import json
import time

import pytest

from conftest import ApiClient, unique

websocket = pytest.importorskip("websocket")  # websocket-client

pytestmark = pytest.mark.websocket


def _ws_url(base_url: str) -> str:
    return base_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws/monitor"


def _drain(ws):
    ws.settimeout(1)
    for _ in range(5):
        try:
            ws.recv()
        except Exception:
            break


def _await_note_nudge(ws, seconds):
    """Return the first note-received notification nudge frame seen within `seconds`, else None."""
    ws.settimeout(1)
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            raw = ws.recv()
        except Exception:
            continue
        if not raw:
            continue
        try:
            data = json.loads(raw)
        except Exception:
            continue
        ev = data.get("event", data) if isinstance(data, dict) else {}
        if ev.get("type") == "notification" and ev.get("target") == "#notes":
            return ev
    return None


def _closed_within(ws, seconds):
    """True if the socket is torn down (a non-timeout recv error) within `seconds`."""
    ws.settimeout(1)
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            ws.recv()
        except websocket.WebSocketTimeoutException:
            continue
        except Exception:
            return True  # connection closed / errored
    return False


def test_revoked_session_closes_live_socket(base_url, admin):
    # A logged-out (denylisted) session's LIVE socket must be torn down by the periodic re-check,
    # not keep streaming until the token's natural expiry.
    user = admin.create_user(role="user")
    c = ApiClient(); c.login(user["_username"], user["_password"])
    ws = websocket.create_connection(_ws_url(base_url), timeout=10)
    try:
        ws.send(json.dumps({"type": "auth", "token": c.token}))
        ws.settimeout(8)
        assert json.loads(ws.recv()).get("type") == "connected", "control: session should authenticate"
        # Revoke the session (logout denylists the token).
        assert c.post("/api/logout").status_code == 200
        # The periodic re-check (~5s) should notice and close the socket.
        assert _closed_within(ws, 15), "a revoked session's live socket must be closed, not kept open"
    finally:
        try:
            ws.close()
        except Exception:
            pass
        admin.delete_user(user["id"])


def test_temp_credential_socket_gets_no_notification_nudge(base_url, admin):
    # A temp credential's socket must not receive the PARENT account's notification nudges (they'd
    # leak the owner's live notification metadata to a scoped credential). Control: the user's own
    # regular socket DOES receive it.
    user = admin.create_user(role="user")
    uc = ApiClient(); uc.login(user["_username"], user["_password"])
    tc = uc.post("/auth/temp-credentials", json={"note": unique("nl-ws")}).json()
    tclient = ApiClient(); tclient.login(tc["temp_username"], tc["credential"])
    note = admin.post("/notes", json={"title": unique("T"), "body": "b"}).json()

    uws = websocket.create_connection(_ws_url(base_url), timeout=10)
    tws = websocket.create_connection(_ws_url(base_url), timeout=10)
    try:
        uws.send(json.dumps({"type": "auth", "token": uc.token}))
        tws.send(json.dumps({"type": "auth", "token": tclient.token}))
        _drain(uws)
        _drain(tws)
        admin.post(f"/notes/{note['id']}/send",
                   json={"recipient_user_id": user["id"]}).raise_for_status()
        # Control: the regular socket receives the nudge (proves it was broadcast).
        assert _await_note_nudge(uws, 8) is not None, "the user's own socket should get the nudge (control)"
        # The temp socket must NOT receive it.
        assert _await_note_nudge(tws, 3) is None, "a temp credential's socket must not get the nudge"
    finally:
        for w in (uws, tws):
            try:
                w.close()
            except Exception:
                pass
        try:
            admin.post(f"/temp-creds/{tc['temp_username']}/delete")
        except Exception:
            pass
        admin.delete_user(user["id"])


def test_sent_note_pushes_nudge_to_recipient_only(base_url, admin):
    recipient = admin.create_user(role="user")
    other = admin.create_user(role="user")
    rc = ApiClient(); rc.login(recipient["_username"], recipient["_password"])
    oc = ApiClient(); oc.login(other["_username"], other["_password"])
    note = admin.post("/notes", json={"title": unique("Live"), "body": "live body"}).json()

    rws = websocket.create_connection(_ws_url(base_url), timeout=10)
    ows = websocket.create_connection(_ws_url(base_url), timeout=10)
    try:
        rws.send(json.dumps({"type": "auth", "token": rc.token}))
        ows.send(json.dumps({"type": "auth", "token": oc.token}))
        _drain(rws)
        _drain(ows)
        # Admin sends the note to the recipient.
        admin.post(f"/notes/{note['id']}/send",
                   json={"recipient_user_id": recipient["id"]}).raise_for_status()
        # The recipient's socket receives the #notes nudge...
        nudge = _await_note_nudge(rws, 8)
        assert nudge is not None, "recipient WS should receive a note-received nudge"
        assert str(nudge.get("owner_user_id")) == str(recipient["id"])
        # ...and the nudge carries NO note content.
        blob = json.dumps(nudge)
        assert "live body" not in blob and note["title"] not in blob, "nudge must not leak content"
        # An unrelated user's socket must NOT receive it.
        assert _await_note_nudge(ows, 3) is None, "another user's WS must not receive the nudge"
    finally:
        for w in (rws, ows):
            try:
                w.close()
            except Exception:
                pass
        admin.delete_user(recipient["id"])
        admin.delete_user(other["id"])
