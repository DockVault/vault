"""What the app-wide web socket passes to which connection (app/core/socket_frames.py).

Only three things travel: the Activity signal, to an administrator's own session; a notification nudge,
to the person it is for; and "your temporary credential signed in", to the account that made it. A
temporary credential's socket gets none of them, and nobody gets the deployment-wide feed the Live
Monitor page used to show."""
import json
import re
import uuid
from pathlib import Path

import pytest

from app.core import audit_signal
from app.core import socket_frames as sf

pytestmark = pytest.mark.unit

OWNER = str(uuid.uuid4())
OTHER = str(uuid.uuid4())

ADMIN = sf.Viewer(user_id=OWNER, is_temporary=False, sees_activity=True)
USER = sf.Viewer(user_id=OWNER, is_temporary=False, sees_activity=False)
OTHER_ADMIN = sf.Viewer(user_id=OTHER, is_temporary=False, sees_activity=True)
# A temporary credential signs in as its account, so its socket has the account's id.
TEMP = sf.Viewer(user_id=OWNER, is_temporary=True, sees_activity=False)

ROW = str(uuid.uuid4())
SIGNAL = json.loads(audit_signal.message([(ROW, "sign_in")]))

NUDGE = {"event": {"type": "notification", "notification_type": "note_received", "target": "#notes",
                   "owner_user_id": OWNER}}
TEMP_SIGN_IN = {"event": {"type": "login", "title": "User logged in", "description": "alex logged in (temporary)",
                          "user": "alex", "ip": "203.0.113.9", "is_temporary": True,
                          "temp_username": "temp_contractor", "owner_user_id": OWNER,
                          "timestamp": "2026-09-27T08:00:00+00:00"}}
FLEET = [
    {"event": {"type": "upload", "title": "Upload completed", "user": "maria", "user_id": OTHER,
               "file_name": "q3-report.pdf", "vault_name": "Finance", "ip": "203.0.113.7"}},
    {"event": {"type": "download", "user": "maria", "owner_user_id": OTHER, "file_name": "a.pdf"}},
    {"event": {"type": "login", "user": "maria", "ip": "203.0.113.7", "is_temporary": False}},
    # A sign-in of the account itself, even marked as its own, is not one of its credentials signing in.
    {"event": {"type": "login", "user": "alex", "ip": "203.0.113.8", "is_temporary": False,
               "owner_user_id": OWNER}},
    {"event": {"type": "logout", "user": "maria"}},
    {"event": {"type": "security_incident", "title": "Failed second factor", "user": "maria"}},
    {"type": "operation_start", "user_id": OTHER, "file_name": "a.pdf"},
]


def test_an_administrator_gets_the_signal_with_only_ids_and_categories():
    assert sf.frame_for(ADMIN, sf.SIGNAL_CHANNEL, SIGNAL) == {
        "type": "activity", "events": [{"id": ROW, "category": "sign_in"}]}


@pytest.mark.parametrize("viewer", [USER, TEMP], ids=["user", "temporary credential"])
def test_nobody_else_gets_the_signal(viewer):
    assert sf.frame_for(viewer, sf.SIGNAL_CHANNEL, SIGNAL) is None


def test_a_signal_carrying_more_than_it_should_is_cut_back():
    loud = {"events": [{"id": ROW, "category": "files", "username": "maria", "vault_name": "Finance"}]}
    assert sf.frame_for(ADMIN, sf.SIGNAL_CHANNEL, loud) == {
        "type": "activity", "events": [{"id": ROW, "category": "files"}]}


def test_an_empty_signal_sends_no_frame():
    assert sf.frame_for(ADMIN, sf.SIGNAL_CHANNEL, {"events": []}) is None


@pytest.mark.parametrize("frame", FLEET, ids=lambda f: (f.get("event") or f)["type"])
@pytest.mark.parametrize("viewer", [ADMIN, OTHER_ADMIN, USER, TEMP],
                         ids=["admin", "other admin", "user", "temporary credential"])
def test_the_deployment_wide_feed_reaches_nobody(frame, viewer):
    assert sf.frame_for(viewer, sf.EVENTS_CHANNEL, frame) is None
    assert sf.worth_publishing(frame) is False


def test_a_nudge_reaches_only_the_person_it_is_for():
    assert sf.frame_for(USER, sf.EVENTS_CHANNEL, NUDGE) == NUDGE
    assert sf.frame_for(ADMIN, sf.EVENTS_CHANNEL, NUDGE) == NUDGE
    assert sf.frame_for(OTHER_ADMIN, sf.EVENTS_CHANNEL, NUDGE) is None
    assert sf.worth_publishing(NUDGE) is True


def test_a_temporary_credential_gets_no_nudge_for_its_account():
    assert sf.frame_for(TEMP, sf.EVENTS_CHANNEL, NUDGE) is None


def test_the_account_hears_when_its_temporary_credential_signs_in():
    frame = sf.frame_for(USER, sf.EVENTS_CHANNEL, TEMP_SIGN_IN)
    assert frame["event"] == {"type": "login", "is_temporary": True, "temp_username": "temp_contractor",
                              "ip": "203.0.113.9", "owner_user_id": OWNER,
                              "timestamp": "2026-09-27T08:00:00+00:00"}
    assert sf.worth_publishing(TEMP_SIGN_IN) is True


def test_another_temporary_credential_of_the_account_does_not():
    # It would learn the other credential's name and the address it signed in from.
    assert sf.frame_for(TEMP, sf.EVENTS_CHANNEL, TEMP_SIGN_IN) is None


def test_nobody_else_hears_it():
    assert sf.frame_for(OTHER_ADMIN, sf.EVENTS_CHANNEL, TEMP_SIGN_IN) is None


def test_a_frame_on_a_channel_the_socket_does_not_know_goes_nowhere():
    assert sf.frame_for(ADMIN, "security_alerts", SIGNAL) is None
    assert sf.frame_for(USER, "session_terminations", NUDGE) is None


def test_unknown_fields_on_a_forwarded_frame_are_left_out():
    loud = {"event": dict(NUDGE["event"], title="Note from maria: salary review", body="the text")}
    assert sf.frame_for(USER, sf.EVENTS_CHANNEL, loud) == NUDGE


# --- The socket itself ------------------------------------------------------------------------------

def _endpoint_source():
    src = (Path(__file__).resolve().parent.parent / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    start = src.index('@app.websocket("/ws/monitor")')
    return src[start:src.index("\n@app.", start + 1)]


def _send_events_body():
    handler = _endpoint_source()
    body = handler[handler.index("async def send_events():"):]
    return body[:body.index("async def receive_messages():")]


def test_the_socket_sends_every_published_message_through_the_rules():
    body = _send_events_body()
    sends = re.findall(r"websocket\.send_(?:json|text|bytes)\(", body)
    assert len(sends) == 1, sends
    assert re.search(r"frame = _socket_frames\.frame_for\(viewer, message\.get\('channel'\),", body)
    assert "await websocket.send_json(frame)" in body


def test_the_socket_listens_to_both_channels():
    assert "pubsub.subscribe, *_socket_frames.CHANNELS" in _endpoint_source()
    assert set(sf.CHANNELS) == {"activity_events", "audit_signal"}
