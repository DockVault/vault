"""The deployment-wide storage limit: what an administrator may set it to, and what it stops.

Two layers. MAX_STORAGE_GB is the deployment's hard ceiling, set by whoever runs the deployment;
the admin panel then chooses any live limit between 0 and that ceiling. Only STORED bytes count
toward it — allocating a vault size spends the owner's own quota, never the deployment's — so a
deployment full of empty vaults is not full at all.
"""
import math

import pytest

from conftest import unique

GIB = 1024 ** 3


def _settings(admin):
    r = admin.get("/settings")
    assert r.status_code == 200, r.text
    return r.json()


def _set_limit(admin, value):
    return admin.put("/settings", json={"deployment_storage_limit_gb": value})


def _stats(admin):
    r = admin.get("/storage/stats")
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture(autouse=True)
def _restore_limit(admin):
    """Always hand the shared instance back with no admin limit saved (i.e. running at the
    deployment's own ceiling) — a stranded low limit would 413 every later upload test."""
    yield
    _set_limit(admin, None)


# --- what the panel is told ---------------------------------------------------------------------

def test_settings_reports_the_ceiling_the_live_limit_and_usage(admin):
    s = _settings(admin)
    assert "deployment_storage_max_gb" in s          # null when the deployment sets no ceiling
    assert "deployment_storage_limit_bytes" in s
    assert s["deployment_storage_used_bytes"] >= 0
    if s["deployment_storage_max_gb"] is not None:
        assert s["deployment_storage_max_gb"] > 0


def test_storage_stats_separates_stored_from_allocated(admin):
    """Allocated is reported for operators but never enforced against the limit, so the panel can
    show 'promised 40 GB, stored 2 GB' without either number being mistaken for the other."""
    before = _stats(admin)
    v = admin.post("/vaults", json={"name": unique("dep"), "size_limit_gb": 2}).json()
    try:
        after = _stats(admin)
        assert after["allocated_bytes"] == before["allocated_bytes"] + 2 * GIB
        assert after["vault_count"] == before["vault_count"] + 1
        assert after["used"] == before["used"]        # an empty vault stores nothing
        for key in ("total", "available", "limit_bytes", "max_bytes"):
            assert key in after
    finally:
        admin.delete_vault(v["id"])


def test_an_empty_vault_never_consumes_the_deployment_limit(admin):
    """The property the whole design rests on: allocation is a promise against the OWNER's
    quota, so a limit pinned exactly at what is stored still permits new vaults."""
    used = _stats(admin)["used"]
    assert _set_limit(admin, max(1, math.ceil(used / GIB))).status_code in (200, 204)
    v = admin.post("/vaults", json={"name": unique("dep-empty"), "size_limit_gb": 5})
    try:
        assert v.status_code == 200, v.text
    finally:
        if v.status_code == 200:
            admin.delete_vault(v.json()["id"])


# --- setting the limit --------------------------------------------------------------------------

def test_admin_can_lower_and_clear_the_limit(admin):
    used_gb = math.ceil(_stats(admin)["used"] / GIB)
    target = max(1, used_gb + 1)
    assert _set_limit(admin, target).status_code in (200, 204)
    assert _stats(admin)["limit_bytes"] == target * GIB
    assert _settings(admin)["deployment_storage_limit_gb"] == target

    # Clearing the override returns the deployment to its configured ceiling.
    assert _set_limit(admin, None).status_code in (200, 204)
    s = _settings(admin)
    assert s["deployment_storage_limit_gb"] is None
    expected = (s["deployment_storage_max_gb"] * GIB) if s["deployment_storage_max_gb"] else None
    assert _stats(admin)["limit_bytes"] == expected


def test_the_limit_cannot_exceed_the_deployment_ceiling(admin):
    s = _settings(admin)
    if s["deployment_storage_max_gb"] is None:
        pytest.skip("this deployment sets no MAX_STORAGE_GB ceiling to test against")
    over = _set_limit(admin, s["deployment_storage_max_gb"] + 1)
    assert over.status_code == 400, over.text
    assert "MAX_STORAGE_GB" in over.text
    # exactly the ceiling is allowed
    assert _set_limit(admin, s["deployment_storage_max_gb"]).status_code in (200, 204)


def test_the_limit_cannot_be_set_below_what_is_already_stored(admin, temp_vault):
    """The rule an operator most needs: files already on disk are never stranded above a limit
    that no amount of configuration can satisfy."""
    content = b"z" * 200_000
    up = admin.post(f"/vaults/{temp_vault['id']}/files",
                    files=[("files", (unique("f") + ".txt", content, "text/plain"))])
    assert up.status_code == 200, up.text
    used = _stats(admin)["used"]
    assert used > 0

    # A limit below the stored bytes is refused (a GB below what is stored, floored at 0).
    too_small = max(0, math.floor(used / GIB) - 1) if used >= GIB else 0
    refused = _set_limit(admin, too_small)
    assert refused.status_code == 400, refused.text
    assert "already" in refused.text
    # ...and a limit at or above it is accepted.
    assert _set_limit(admin, math.ceil(used / GIB) + 1).status_code in (200, 204)


@pytest.mark.parametrize("bad", ["abc", True, -5, [], {}])
def test_malformed_limits_are_refused(admin, bad):
    r = _set_limit(admin, bad)
    assert r.status_code == 400, r.text


def _pin_limit_at_current_usage(admin):
    """Pin the live limit as close to what is already stored as a GB-denominated setting allows,
    and return (limit_bytes, used_bytes). On a deployment that has stored nothing this is the
    literal 0 GB freeze; on one that has, it is the same stop one byte higher. Float truncation
    can land the computed GB value a byte BELOW what is stored, which the server rightly refuses,
    so nudge upward until it takes."""
    used = _stats(admin)["used"]
    gb = used / GIB
    for _ in range(5):
        if _set_limit(admin, gb).status_code in (200, 204):
            break
        gb = math.nextafter(gb, math.inf)
    else:
        pytest.fail("could not pin the deployment limit at the current usage")
    limit = _stats(admin)["limit_bytes"]
    assert limit is not None and limit >= used
    return limit, used


def test_a_reached_limit_blocks_the_next_upload(admin, temp_vault):
    """0 GB is a real answer, distinct from 'unset': stop accepting bytes. Whatever is already
    stored, an upload that would cross the limit is refused rather than half-written."""
    limit, used = _pin_limit_at_current_usage(admin)
    payload = b"y" * ((limit - used) + 4096)      # guaranteed to cross the line

    r = admin.post(f"/vaults/{temp_vault['id']}/files",
                   files=[("files", (unique("f") + ".txt", payload, "text/plain"))])
    assert r.status_code == 413, r.text
    assert "storage limit" in r.text.lower()
    # nothing was stored by the refused upload
    assert _stats(admin)["used"] == used


def test_a_full_deployment_still_allows_reading_and_deleting(admin, temp_vault):
    """Hitting the limit must not brick the deployment — an operator has to be able to free space."""
    vid = temp_vault["id"]
    up = admin.post(f"/vaults/{vid}/files",
                    files=[("files", (unique("f") + ".txt", b"w" * 8192, "text/plain"))])
    assert up.status_code == 200, up.text
    file_id = up.json()["files"][0]["id"]

    _pin_limit_at_current_usage(admin)

    assert admin.get(f"/vaults/{vid}/files").status_code == 200
    assert admin.post(f"/vaults/{vid}/files/{file_id}/delete").status_code in (200, 204)


# --- who may change it ---------------------------------------------------------------------------

def test_a_non_admin_cannot_read_or_change_the_deployment_limit(admin):
    u = admin.create_user(role="user")
    client = admin.clone_anonymous()
    client.login(u["_username"], u["_password"])
    try:
        assert client.get("/settings").status_code == 403
        assert _set_limit(client, 1).status_code == 403
        assert client.get("/storage/stats").status_code == 403
    finally:
        admin.delete_user(u["id"])


def test_an_anonymous_caller_cannot_change_the_deployment_limit(anon):
    assert _set_limit(anon, 1).status_code in (401, 403)
    assert anon.get("/storage/stats").status_code in (401, 403)
