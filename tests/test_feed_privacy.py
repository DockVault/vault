"""The live activity feed gives a watching admin someone else's activity without names.

Admins are not members of every vault, and vault and file names are encrypted at rest. Another
person's event keeps only a fixed list of safe fields and its title as its description; the viewer's
own events pass through unchanged."""
import re
from pathlib import Path

import pytest

from app.core import feed_privacy as fp

pytestmark = pytest.mark.unit

UPLOAD = {"event": {"type": "upload", "title": "Upload completed", "user": "maria", "ip": "203.0.113.9",
                    "description": "q3-report.pdf (1,024 bytes) uploaded successfully",
                    "file_name": "q3-report.pdf", "vault_id": "v1", "vault_name": "Finance",
                    "vault_type": "standard", "operation_id": "op1", "completed": True,
                    "timestamp": "2026-09-26T08:00:00+00:00"},
          "metrics": {"activeOperations": 1}, "traffic": {"upload": 1024, "download": 0}}


def test_the_safe_list_is_exactly_these_fields():
    # Written out, so adding a field to the list is a deliberate change here too.
    assert fp.SAFE_KEYS == {
        "type", "title", "timestamp", "user", "username", "user_id", "owner_user_id", "ip",
        "is_temporary", "temp_username", "temp_credential_id", "severity",
        "operation_id", "operation_type", "completed", "cancelled", "worker_stopped",
        "bytes_uploaded", "total_size", "vault_id", "vault_type",
    }


def test_someone_elses_upload_loses_its_names():
    out = fp.for_viewer(UPLOAD, "admin-id", "alex")
    assert out["event"] == {"type": "upload", "title": "Upload completed", "user": "maria",
                            "ip": "203.0.113.9", "description": "Upload completed", "vault_id": "v1",
                            "vault_type": "standard", "operation_id": "op1", "completed": True,
                            "timestamp": "2026-09-26T08:00:00+00:00"}
    assert out["metrics"] == UPLOAD["metrics"] and out["traffic"] == UPLOAD["traffic"]
    assert UPLOAD["event"]["file_name"] == "q3-report.pdf"          # the original is not changed


def test_a_download_names_its_file_only_in_the_description():
    ev = {"event": {"type": "download", "title": "File downloaded", "user": "maria",
                    "description": "q3-report.pdf (1,024 bytes)", "operation_id": "op2"}}
    out = fp.for_viewer(ev, "admin-id", "alex")["event"]
    assert out["description"] == "File downloaded" and "q3-report" not in str(out)


@pytest.mark.parametrize("key", ["file_name", "folder_name", "vault_name", "old_name", "new_name",
                                 "filename", "note_title", "link_label", "path", "name"])
def test_any_field_not_on_the_safe_list_is_left_out(key):
    ev = {"event": {"type": "rename", "title": "Renamed", "user": "maria", key: "secret"}}
    assert "secret" not in str(fp.for_viewer(ev, "admin-id", "alex"))


def test_the_viewers_own_upload_keeps_its_names():
    assert fp.for_viewer(UPLOAD, "maria-id", "maria") is UPLOAD


@pytest.mark.parametrize("key", ["owner_user_id", "user_id"])
def test_an_event_is_the_viewers_own_by_id(key):
    ev = {"type": "operation_start", key: "u7", "username": "someone", "file_name": "a.txt"}
    assert fp.for_viewer(ev, "u7", "someone-else") is ev
    other = fp.for_viewer(ev, "u8", "alex")
    assert "file_name" not in other and other["type"] == "operation_start"


def test_an_event_without_an_actor_is_nobodys_own():
    ev = {"event": {"type": "error", "title": "Upload failed",
                    "description": "Upload error: could not write q3-report.pdf"}}
    assert fp.for_viewer(ev, "admin-id", None)["event"]["description"] == "Upload failed"
    assert fp.for_viewer(ev, "admin-id", "")["event"]["description"] == "Upload failed"


def test_another_persons_sign_in_keeps_who_and_where():
    login = {"event": {"type": "login", "title": "User logged in", "user": "maria", "ip": "203.0.113.9",
                       "description": "maria logged in"}}
    out = fp.for_viewer(login, "admin-id", "alex")["event"]
    assert (out["user"], out["ip"], out["description"]) == ("maria", "203.0.113.9", "User logged in")


def _send_events_body():
    src = (Path(__file__).resolve().parent.parent / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    start = src.index('@app.websocket("/ws/monitor")')
    handler = src[start:src.index("\n@app.", start + 1)]
    body = handler[handler.index("async def send_events():"):]
    return body[:body.index("async def receive_messages():")]


def test_the_socket_sends_every_event_through_the_filter():
    body = _send_events_body()
    sends = re.findall(r"websocket\.send_(?:json|text|bytes)\(", body)
    assert len(sends) == 1, sends
    assert re.search(r"websocket\.send_json\(\s*_feed_privacy\.for_viewer\(event_data, user_id, username\)\)", body)
