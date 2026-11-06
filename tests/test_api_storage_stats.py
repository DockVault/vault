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
    # What legal holds keep after a deletion is on the disk too, in no vault's counters: shown beside it, with
    # what the vaults' files take on the disk altogether.
    assert set(body) == {"total", "used", "available", "kept_for_cases", "on_disk_bytes", "limit_counts_bytes",
                         "free_space_floor_bytes", "allocated_bytes", "limit_bytes", "max_bytes", "vault_count"}
    for key in ("total", "used", "available", "on_disk_bytes", "limit_counts_bytes", "free_space_floor_bytes",
                "allocated_bytes", "vault_count"):
        assert isinstance(body[key], int) and body[key] >= 0
    kept = body["kept_for_cases"]
    assert set(kept) == {"files", "folders", "bytes"}
    assert all(isinstance(kept[k], int) and kept[k] >= 0 for k in kept)
    # `used` is the vaults' bytes alone; the deployment's limit counts the kept ones too, and says so by name.
    assert body["on_disk_bytes"] == body["limit_counts_bytes"] == body["used"] + kept["bytes"]
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


def test_the_storage_panel_reports_the_free_space_the_volume_keeps(admin):
    """MIN_FREE_SPACE_GB unset (the shipped .env leaves it commented): the larger of 2 GB and 5% of the volume."""
    import subprocess
    import os
    api = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    try:
        set_to = subprocess.run(["docker", "exec", api, "printenv", "MIN_FREE_SPACE_GB"], capture_output=True,
                                text=True, timeout=30)
    except FileNotFoundError:
        import pytest
        pytest.skip("docker is not available to read the deployment's setting")
    body = admin.get("/storage/stats").json()
    if set_to.returncode != 0 and body["total"]:
        assert body["free_space_floor_bytes"] == max(2 * 1024 ** 3, int(body["total"] * 0.05)), body
    elif set_to.returncode == 0:
        configured = float(set_to.stdout.strip())
        expected = max(2 * 1024 ** 3, int(body["total"] * 0.05)) if configured < 0 else int(configured * 1024 ** 3)
        assert body["free_space_floor_bytes"] == expected, body
