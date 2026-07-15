"""GET /monitor/stats and GET /storage/stats — the Live Monitor + Storage panels.

Both endpoints were missing (the frontend 404'd and fell back to 0 / N/A). Admin-only.
"""


def test_monitor_stats_shape_and_counts(admin):
    r = admin.get("/monitor/stats")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"active_users", "active_sessions"}
    assert isinstance(body["active_users"], int) and isinstance(body["active_sessions"], int)
    # the admin fixture is logged in, so at least one active user + session
    assert body["active_users"] >= 1
    assert body["active_sessions"] >= 1


def test_storage_stats_shape(admin):
    r = admin.get("/storage/stats")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"total", "used", "available"}
    assert all(isinstance(body[k], int) for k in body)
    assert body["used"] >= 0
    # if the storage volume could be stat'd, capacity is coherent
    if body["total"]:
        assert body["available"] <= body["total"]


def test_stats_endpoints_require_admin(admin):
    u = admin.create_user(role="user")
    c = admin.clone_anonymous()
    c.login(u["_username"], u["_password"])
    try:
        assert c.get("/monitor/stats").status_code == 403
        assert c.get("/storage/stats").status_code == 403
    finally:
        admin.delete_user(u["id"])
