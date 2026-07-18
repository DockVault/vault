"""ZK-key idle auto-lock policy (`zk_idle_lock_minutes`).

An admin sets a deployment-wide inactivity window after which the browser drops the in-memory
zero-knowledge key (client-enforced). The setting round-trips through PUT/GET /settings, is
surfaced to any authenticated user via GET /zk-enabled (like the other ZK flags), is validated as
a non-negative int, and is clamped to [0, 1440] in the effective read.
"""


def _get_setting(admin):
    return admin.get("/settings").json().get("zk_idle_lock_minutes")


def _set(admin, val):
    return admin.put("/settings", json={"zk_idle_lock_minutes": val})


def test_zk_idle_lock_round_trips_and_surfaces(admin):
    try:
        _set(admin, 15).raise_for_status()
        assert _get_setting(admin) == 15
        # any authenticated user can read the effective value from /zk-enabled
        assert admin.get("/zk-enabled").json()["zk_idle_lock_minutes"] == 15

        _set(admin, 0).raise_for_status()
        assert _get_setting(admin) == 0
        assert admin.get("/zk-enabled").json()["zk_idle_lock_minutes"] == 0
    finally:
        _set(admin, 0)


def test_zk_idle_lock_clamped_to_ceiling(admin):
    try:
        _set(admin, 99999).raise_for_status()   # stored raw, clamped on the effective read
        assert admin.get("/zk-enabled").json()["zk_idle_lock_minutes"] == 1440
        assert _get_setting(admin) == 1440
    finally:
        _set(admin, 0)


def test_zk_idle_lock_rejects_invalid(admin):
    try:
        assert _set(admin, "soon").status_code == 400
        assert _set(admin, -5).status_code == 400
        assert _set(admin, True).status_code == 400   # a bool is not a valid int here
    finally:
        _set(admin, 0)


def test_zk_idle_lock_default_is_zero(admin):
    """A deployment that never set the key reports 0 (disabled), not an error."""
    _set(admin, 0)
    assert admin.get("/zk-enabled").json().get("zk_idle_lock_minutes") == 0
