"""The notice of what this vault records, on a running stack.

The notice and its page need no sign-in and show the levels in force only; the earlier versions need sign-in. A
save of new levels notifies a user, whose status then asks for the banner; saying it was read records an audit
row and ends the banner. The levels are set back afterwards. test_recording_notice.py covers the rules offline.
"""
import pytest
import requests

from conftest import BASE_URL
from _account_change_helpers import psql
from _recording_levels import latest, levels_restored, wait_for  # noqa: F401 -- a fixture

pytestmark = pytest.mark.integration

ACTION = "admin.audit_privacy.write"


def _save(admin, password, levels):
    receipt = admin.post("/auth/second-factor/step-up",
                         json={"action": ACTION, "method": "password", "code": password}).json()["receipt"]
    r = admin.put("/settings/recording", json={"levels": levels}, headers={"X-Second-Factor": receipt})
    assert r.status_code == 200, r.text
    return r.json()


def test_the_notice_and_its_page_need_no_sign_in_and_show_no_earlier_version():
    r = requests.get(f"{BASE_URL}/privacy/recording", timeout=30)
    assert r.status_code == 200
    data = r.json()
    assert [item["key"] for item in data["levels"]] == ["names", "signin_names", "emails", "ip", "user_agent"]
    assert {"audit_logs", "security_records", "active_sessions"} <= {s["key"] for s in data["stores"]}
    assert "versions" not in data and "history" not in data
    page = requests.get(f"{BASE_URL}/recording", timeout=30)
    assert page.status_code == 200 and "What this vault records" in page.text
    policy = page.headers.get("Content-Security-Policy", "")
    assert "script-src 'self'" in policy and "script-src 'self' 'unsafe-inline'" not in policy
    assert requests.get(f"{BASE_URL}/privacy/recording/history", timeout=30).status_code in (401, 403)


def test_a_change_notifies_a_user_whose_banner_shows_until_it_is_read(admin, admin_creds, temp_user_client,
                                                                     temp_user, levels_restored):
    before, _ = latest()
    out = _save(admin, admin_creds["password"], dict(levels_restored, user_agent="none"))
    version = out["version"]
    assert version == before + 1
    notes = wait_for(lambda: [n for n in temp_user_client.get("/notifications").json().get("notifications", [])
                              if n["type"] == "recording_levels_changed" and f"version {version}" in (n["body"] or "")])
    assert len(notes) == 1 and notes[0]["target"] == "#recording"
    status = temp_user_client.get("/privacy/recording/status").json()
    assert status["show"] is True and status["version"] == version
    assert temp_user_client.post("/privacy/recording/seen", json={"version": version + 1}).status_code == 400
    seen = temp_user_client.post("/privacy/recording/seen", json={"version": version})
    assert seen.status_code == 200 and seen.json()["show"] is False
    assert temp_user_client.get("/privacy/recording/status").json()["show"] is False
    rows = psql("SELECT count(*) FROM audit_logs WHERE action = 'privacy_notice_seen' "
                f"AND user_id = '{temp_user['id']}' AND details->>'version' = '{version}'")
    assert rows == "1"
    history = temp_user_client.get("/privacy/recording/history").json()["versions"]
    assert history[0]["version"] == version
