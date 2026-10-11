"""Settings levels on a running stack (app/api/settings_catalogue_router.py, app/core/settings_catalogue.py).

GET /settings/catalogue gives every setting of the Settings pages with its page, level and release, once each,
to an administrator only; "New" counts from the running release and from the release at which this
administrator last opened the pages, which POST /settings/catalogue/seen keeps with their preferences, where
PUT /users/me/preferences can neither set it nor lose it. Inside the web container, with SETTINGS_LOCKED_KEYS
set for one process, the catalogue the real configuration builds folds what is locked with its value and
reason. test_settings_levels.py covers the registry, the markup and the routes offline.
"""
import json
import re

import pytest

from _account_change_helpers import in_api_container
from conftest import ApiClient

pytestmark = pytest.mark.integration

LEVELS = {"essential", "advanced"}
PAGES = {"general", "branding", "security", "storage", "email", "sftp", "sharing", "notelinks", "uploadlinks",
         "accounts", "logs", "records"}
VERSION = re.compile(r"\d+\.\d+\.\d+")


@pytest.fixture
def fresh_admin(admin):
    account = admin.create_user(role="admin")
    client = ApiClient()
    client.login(account["_username"], account["_password"])
    yield client
    admin.delete_user(account["id"])


def test_the_catalogue_places_every_setting_once(admin, anon):
    r = admin.get("/settings/catalogue")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["version"] == admin.get("/version").json()["version"]
    keys = [e["key"] for e in data["entries"]]
    assert len(keys) == len(set(keys)) > 100
    for e in data["entries"]:
        assert e["level"] in LEVELS and e["page"] in PAGES and VERSION.fullmatch(e["since"]), e
        assert isinstance(e["new"], bool) and isinstance(e["locked"], bool), e
    kinds = {e["key"]: e["kind"] for e in data["entries"]}
    assert (kinds["app_name"], kinds["audit_hot_days"], kinds["rate_limit_vault_attempts"], kinds["audit_levels"]) \
        == ("field", "setting", "listed", "group")
    assert sorted(data["levels"]) == sorted(LEVELS) and set(data["pages"]) == PAGES
    assert anon.get("/settings/catalogue").status_code == 401


def test_only_an_administrator_reads_it_or_marks_it_seen(temp_user_client):
    assert temp_user_client.get("/settings/catalogue").status_code == 403
    assert temp_user_client.post("/settings/catalogue/seen").status_code == 403


def test_the_release_last_opened_at_is_kept_with_the_preferences(fresh_admin):
    first = fresh_admin.get("/settings/catalogue").json()
    assert first["seen"] is None
    running = first["version"]
    new_first = {e["key"] for e in first["entries"] if e["new"]}
    assert fresh_admin.put("/users/me/preferences", json={"ui": "v1"}).status_code == 200
    r = fresh_admin.post("/settings/catalogue/seen")
    assert r.status_code == 200 and r.json() == {"seen": running}
    again = fresh_admin.get("/settings/catalogue").json()
    assert again["seen"] == running
    # Opened at this release: "New" is what the release lines give, as it was before (never seen).
    assert {e["key"] for e in again["entries"] if e["new"]} == new_first
    prefs = fresh_admin.get("/users/me/preferences").json()
    assert prefs.get("settings_seen") == running and prefs.get("ui") == "v1"
    # PUT /users/me/preferences cannot set it, and saving another preference keeps it.
    assert fresh_admin.put("/users/me/preferences", json={"settings_seen": "0.1.0", "ui": "v2"}).status_code == 200
    prefs = fresh_admin.get("/users/me/preferences").json()
    assert prefs.get("settings_seen") == running and prefs.get("ui") == "v2"


_LOCKED = """
import json
from app.core import settings_registry as R
from app.core import settings_catalogue as C
from app.core import rate_limit_settings as L
from app.core.config import settings
R.all_entries()
settings.settings_locked_keys = "audit_hot_days, rate_limits, audit_levels, session_records_days, app_name"
rows = {r["key"]: r for r in C.entries(current="0.34.0")}
print(json.dumps({"locked": sorted(k for k, r in rows.items() if r["locked"]),
                  "hot": rows["audit_hot_days"], "limit": rows["rate_limit_vault_attempts"],
                  "levels": rows["audit_levels"], "unknown": R.unknown_locked_tokens(),
                  "limit_value": L.deployment_default("rate_limit_vault_attempts")}))
"""


def test_inside_the_container_a_locked_setting_carries_its_value_and_reason():
    out = json.loads(in_api_container(_LOCKED).stdout.strip().splitlines()[-1])
    assert "audit_hot_days" in out["locked"] and "audit_levels" in out["locked"]
    assert "rate_limit_vault_attempts" in out["locked"] and "rate_limit_api_poll" in out["locked"]
    assert "session_records_days" not in out["locked"] and "app_name" not in out["locked"]
    assert out["unknown"] == ["app_name"]
    hot, limit, levels = out["hot"], out["limit"], out["levels"]
    assert re.fullmatch(r"\d+ days", hot["value"]) and "AUDIT_HOT_DAYS" in hot["reason"]
    assert limit["value"] == f"{out['limit_value']} attempts"
    assert "RATE_LIMIT_VAULT_ATTEMPTS" in limit["reason"]
    assert "AUDIT_MAX_IP" in levels["reason"] and "IP addresses: " in levels["value"]
    for row in (hot, limit, levels):
        assert row["reason"].startswith("Set by your provider") and "SETTINGS_LOCKED_KEYS" in row["reason"]
