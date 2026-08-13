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
    # Disk capacity, then the limit picture the Storage panel renders: what is STORED (the only
    # thing the deployment limit counts), what vaults have been ALLOCATED (reported, never
    # enforced against that limit), the live limit, and the deployment's own ceiling.
    assert set(body) == {"total", "used", "available",
                         "allocated_bytes", "limit_bytes", "max_bytes", "vault_count"}
    for key in ("total", "used", "available", "allocated_bytes", "vault_count"):
        assert isinstance(body[key], int) and body[key] >= 0
    # A null limit/ceiling means "unlimited", which is the shipped default.
    for key in ("limit_bytes", "max_bytes"):
        assert body[key] is None or (isinstance(body[key], int) and body[key] >= 0)
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
