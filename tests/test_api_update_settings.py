"""HTTP tests for the admin update-check settings: the live interval override (PUT
/api/update-settings) + the interval_minutes field on GET /api/update-status. The endpoints work
regardless of whether the update check is enabled (they don't hit the network)."""
from conftest import skip_for_older_deployment


def _present(admin):
    return admin.get("/api/update-status").status_code == 200


def test_update_endpoints_admin_only(admin, temp_user_client):
    if not _present(admin):
        skip_for_older_deployment("update-status endpoint not present in this image")
    assert temp_user_client.get("/api/update-status").status_code == 403
    assert temp_user_client.put("/api/update-settings", json={"interval_minutes": 60}).status_code == 403


def test_update_status_reports_interval(admin):
    if not _present(admin):
        skip_for_older_deployment("update-status endpoint not present in this image")
    body = admin.get("/api/update-status").json()
    assert isinstance(body.get("interval_minutes"), int)
    assert "enabled" in body


def test_update_interval_clamps_and_persists(admin):
    if not _present(admin):
        skip_for_older_deployment("update-status endpoint not present in this image")
    original = admin.get("/api/update-status").json().get("interval_minutes", 360)
    try:
        # below the floor -> clamped up to 15
        r = admin.put("/api/update-settings", json={"interval_minutes": 1})
        assert r.status_code == 200 and r.json()["interval_minutes"] == 15
        assert admin.get("/api/update-status").json().get("interval_minutes") == 15
        # a valid value round-trips and the GET reflects it live (no restart)
        assert admin.put("/api/update-settings", json={"interval_minutes": 720}).json()["interval_minutes"] == 720
        assert admin.get("/api/update-status").json().get("interval_minutes") == 720
        # a missing value is a clean 400
        assert admin.put("/api/update-settings", json={}).status_code == 400
    finally:
        admin.put("/api/update-settings", json={"interval_minutes": int(original)})
