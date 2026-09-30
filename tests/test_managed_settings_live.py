"""The managed-settings routes on a running stack (app/api/managed_settings_router.py).

An administrator reads every managed setting; a user, and a request with no session, are refused; a key
the registry does not hold is a 404 on write. test_managed_settings_routes.py covers the routes' rules
offline.
"""
import pytest

pytestmark = pytest.mark.integration


def test_an_administrator_reads_every_managed_setting(admin):
    r = admin.get("/settings/managed")
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body["settings"], list) and isinstance(body["locked"], list)
    for row in body["settings"]:
        assert {"key", "value", "source", "floor", "ceiling", "env", "editable", "locked"} <= set(row), row


def test_a_user_and_no_session_are_refused(temp_user_client, anon):
    assert temp_user_client.get("/settings/managed").status_code == 403
    assert temp_user_client.put("/settings/managed/anything", json={"value": 1}).status_code == 403
    assert anon.get("/settings/managed").status_code in (401, 403)
    assert anon.put("/settings/managed/anything", json={"value": 1}).status_code in (401, 403)


def test_a_key_the_registry_does_not_hold_is_not_found(admin):
    r = admin.put("/settings/managed/not_a_managed_setting", json={"value": 1})
    assert r.status_code == 404, r.text
    assert r.json()["detail"] == "not_a_managed_setting is not a managed setting"
