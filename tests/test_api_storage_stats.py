"""GET /storage/stats, the Settings -> Storage panel, and the routes removed with the pages they served.

/storage/stats was missing once (the panel fell back to N/A). Admin-only. /monitor/stats served only
the Live Monitor page and /audit/export only the Settings -> Audit Log tab; both pages were removed in
0.33.0, and the Activity page's /activity/summary and /activity/export replace them.
"""


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


def test_storage_stats_require_admin(admin):
    u = admin.create_user(role="user")
    c = admin.clone_anonymous()
    c.login(u["_username"], u["_password"])
    try:
        assert c.get("/storage/stats").status_code == 403
    finally:
        admin.delete_user(u["id"])


def test_the_routes_of_the_removed_pages_are_gone(admin):
    assert admin.get("/monitor/stats").status_code == 404
    assert admin.get("/audit/export").status_code == 404
    # What replaced them answers.
    assert admin.get("/activity/summary").status_code == 200
    assert admin.get("/activity/export", params={"q": "no-such-event-text"}).status_code == 200
