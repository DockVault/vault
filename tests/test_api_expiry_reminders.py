"""Reminders before an expiry (app/core/expiry_reminders.py, run by the web process).

A share or a link made for longer than two days earns its maker one in-app notice per thing and expiry date
once it is in its last two days; one made for less is not reminded at all; a second sweep writes nothing
more; moving the expiry to another day earns one more. The sweep is run here through the API container's own
interpreter, as the loop runs it. What is due, and how it is named, is tested offline in
tests/test_expiry_reminders_unit.py.
"""
import os
import subprocess
from datetime import datetime, timedelta

import pytest

from conftest import ApiClient, unique

pytestmark = pytest.mark.integration

API = os.environ.get("VAULT_API_CONTAINER", "vault-api")
_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _sweep():
    out = subprocess.run(["docker", "exec", API, "python", "-c",
                          "from app.api.api_server import _expiry_reminders_once as f; print(f())"],
                         capture_output=True, text=True, timeout=180)
    assert out.returncode == 0, out.stderr[-600:]
    return int(out.stdout.strip().splitlines()[-1])


def _psql(sql):
    out = subprocess.run(["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                         capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr[-600:]
    return out.stdout


def _iso(dt):
    return dt.replace(microsecond=0).isoformat() + "Z"


@pytest.fixture
def sharing_on(admin):
    before = admin.get("/settings").json().get("sharing_enabled")
    admin.put("/settings", json={"sharing_enabled": True})
    yield
    admin.put("/settings", json={"sharing_enabled": before})


def _reminders(client):
    return [n for n in client.get("/notifications").json()["notifications"] if n["type"] == "expiry_reminder"]


def test_the_maker_is_reminded_once_per_expiry_date(admin, sharing_on):
    tag = admin.post("/share-tags", json={"name": unique("rem"), "allowed_audiences": ["anyone_internal"],
                                          "max_recipients_cap": 10, "auto_enroll_new_users": True,
                                          "max_lifetime_minutes": 30 * 24 * 60, "default_lifetime_minutes": 60}).json()
    owner = admin.create_user(role="user")
    co = ApiClient(); co.login(owner["_username"], owner["_password"])
    v = co.create_vault(name=unique("Remind"))
    try:
        share = co.post("/shares", json={"vault_id": v["id"], "tag_id": tag["id"], "target_type": "vault",
                                         "claim_audience": "anyone_internal", "lifetime_minutes": 60}).json()
        # A share made for an hour expires within the window, and is not reminded: its maker chose that.
        _sweep()
        assert _reminders(co) == []
        # The same share, had it been made three days ago for a little over three days: in its last two days.
        _psql(f"UPDATE shares SET created_at = (now() AT TIME ZONE 'utc') - interval '3 days', "
              f"expires_at = (now() AT TIME ZONE 'utc') + interval '5 hours' WHERE id = '{share['id']}'")
        _sweep()
        mine = _reminders(co)
        assert len(mine) == 1, mine
        # Named by its kind, never by the vault's sealed name; leads to the maker's own shares.
        assert mine[0]["title"].startswith("Your share of a vault expires ") and mine[0]["target"] == "#shared/by-me"
        assert v["name"] not in mine[0]["title"] and v["name"] not in (mine[0].get("body") or "")
        # The next sweep adds nothing for the same thing and date.
        _sweep()
        assert len(_reminders(co)) == 1
        # Extended to another day within the window: reminded once more.
        r = co.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(datetime.utcnow() + timedelta(hours=30))})
        assert r.status_code == 200, r.text
        _sweep()
        again = _reminders(co)
        assert len(again) == 2, again
        # Dismissed from the bell, the reminder does not come back on the next sweep.
        assert co.delete(f"/notifications/{again[0]['id']}").status_code == 200
        _sweep()
        assert len(_reminders(co)) == 1
        # Extended far beyond the window: nothing due.
        r = co.post(f"/shares/{share['id']}/extend", json={"expires_at": _iso(datetime.utcnow() + timedelta(days=20))})
        assert r.status_code in (200, 403), r.text   # 403 only when this account has a second factor enrolled
        if r.status_code == 200:
            _sweep()
            assert len(_reminders(co)) == 1
    finally:
        co.delete_vault(v["id"])
        admin.delete_user(owner["id"])
