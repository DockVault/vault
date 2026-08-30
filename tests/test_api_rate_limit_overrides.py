"""Settings API: the login / vault / SFTP throttles now expose a read-only deployment value plus an
editable custom override, resolved fail-safe. The deployment value is never writable."""
import pytest

from conftest import ApiClient, BASE_URL  # noqa: F401

pytestmark = pytest.mark.integration


def _rows(admin):
    return {r["key"]: r for r in admin.get("/settings").json()["rate_limit_settings"]}


def test_settings_expose_deployment_custom_effective_for_all_groups(admin):
    rows = _rows(admin)
    # The extension surface the throttle rework is about.
    for key in ("max_login_attempts", "rate_limit_login_window_seconds", "lockout_duration",
                "rate_limit_vault_attempts", "rate_limit_vault_attempts_admin",
                "rate_limit_vault_window_seconds", "rate_limit_sftp_key_attempts",
                "rate_limit_api_default"):
        assert key in rows, key
        r = rows[key]
        assert set(r) >= {"deployment", "custom", "effective", "min", "max", "unit",
                          "label", "description", "when", "group"}
        assert isinstance(r["deployment"], int)
        # With no override set, effective mirrors the deployment value.
        if r["custom"] is None:
            assert r["effective"] == r["deployment"]
    assert {r["group"] for r in rows.values()} >= {"login", "vault", "sftp", "api"}


def test_deployment_value_is_read_only(admin):
    # The server-computed structured field and the deployment-defaults dict are both refused as writes.
    assert admin.put("/settings", json={"rate_limit_settings": [{"key": "x"}]}).status_code == 400
    assert admin.put("/settings",
                     json={"rate_limit_api_deployment_defaults": {"rate_limit_api_default": 1}}
                     ).status_code == 400
    assert admin.put("/settings", json={"rate_limit_api_enabled": False}).status_code == 400


def test_custom_override_persists_and_clears_without_touching_deployment(admin):
    key = "rate_limit_vault_attempts"
    dep = _rows(admin)[key]["deployment"]
    try:
        # Set a valid custom override.
        assert admin.put("/settings", json={key: 9}).status_code == 200
        r = _rows(admin)[key]
        assert r["custom"] == 9 and r["effective"] == 9
        assert r["deployment"] == dep  # deployment value is untouched by a custom write

        # Clearing with the sentinel 0 restores the deployment default.
        assert admin.put("/settings", json={key: 0}).status_code == 200
        r2 = _rows(admin)[key]
        assert r2["custom"] is None and r2["effective"] == dep
    finally:
        admin.put("/settings", json={key: 0})


def test_out_of_bounds_custom_is_refused(admin):
    # Below the floor, above the ceiling, non-int, and bool are all 400 — the value never reaches the
    # store, so a limit can't be nudged out of range or coerced off.
    assert admin.put("/settings", json={"rate_limit_login_window_seconds": 1}).status_code == 400   # < 10
    assert admin.put("/settings", json={"rate_limit_vault_attempts": 10**9}).status_code == 400      # > max
    assert admin.put("/settings", json={"rate_limit_sftp_key_attempts": True}).status_code == 400    # bool
    assert admin.put("/settings", json={"rate_limit_vault_attempts": "5"}).status_code == 400         # str
