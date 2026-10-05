"""The boundary of compliance access on a running stack (app/core/compliance_settings.py).

The panel lists the fifteen settings as set by the deployment, refuses to change them, and the general
settings store refuses them too. In the web container's own image and configuration, the settings registry
refuses to start while COMPLIANCE_RECORD_MIN_DAYS is longer than PLAN_LOG_MAX_DAYS, and while a setting is out
of its bounds, and starts with the defaults. test_compliance_settings.py covers the bounds, the stricter
value and the tool offline.
"""
import subprocess

import pytest

from _account_change_helpers import API
from conftest import skip_if_container_absent

KEYS = ("compliance_access", "compliance_password_vaults", "compliance_export", "compliance_max_access_days",
        "compliance_max_total_days", "compliance_max_case_vaults", "compliance_export_ttl_hours",
        "compliance_hold_confirm_days", "compliance_hold_purge_delay_days", "compliance_hold_review_days",
        "compliance_view_rate", "compliance_reveals_per_day", "compliance_auditor_not_admin",
        "compliance_auditor_grant_days", "compliance_record_min_days")


def test_the_panel_lists_them_as_set_by_the_deployment_and_refuses_to_change_them(admin):
    r = admin.get("/settings/managed")
    assert r.status_code == 200, r.text
    rows = {row["key"]: row for row in r.json()["settings"] if row["group"] == "compliance"}
    assert set(rows) == set(KEYS)
    for key, row in rows.items():
        assert (row["editable"], row["env"], row["lockable"]) == ("env_only", key.upper(), True), row
    assert rows["compliance_access"]["value"] == "enabled"
    assert rows["compliance_record_min_days"]["value"] == 2190
    r = admin.put("/settings/managed/compliance_view_rate", json={"value": 60})
    assert r.status_code == 400, r.text
    assert "set by the deployment" in r.text
    after = {row["key"]: row for row in admin.get("/settings/managed").json()["settings"]}
    assert after["compliance_view_rate"]["value"] == 600
    r = admin.put("/settings", json={"compliance_access": "disabled"})
    assert r.status_code == 400, r.text
    assert "compliance_access" in r.text


_START = ("from app.core.config import bootstrap_entrypoint\n"
          "bootstrap_entrypoint('compliance-settings-test')\n"
          "from app.core import settings_registry as R\n"
          "try:\n"
          "    R.start(lambda: None, load_now=False)\n"
          "except R.SettingsContractError as exc:\n"
          "    print('REFUSED:', exc)\n"
          "else:\n"
          "    R.stop()\n"
          "    print('STARTED')\n")


def _start_with(**env):
    args = ["docker", "exec"]
    for name, value in env.items():
        args += ["-e", f"{name}={value}"]
    try:
        r = subprocess.run(args + ["-i", API, "python", "-c", _START], capture_output=True, text=True, timeout=90)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(r, API)
    assert r.returncode == 0, (r.stderr or r.stdout)[-800:]
    return r.stdout


def test_the_server_starts_with_the_defaults():
    assert "STARTED" in _start_with()


def test_the_server_refuses_to_start_while_case_records_outlast_the_audit_logs_ceiling():
    out = _start_with(PLAN_LOG_MAX_DAYS="365")
    assert "REFUSED:" in out and "COMPLIANCE_RECORD_MIN_DAYS (2190) is longer than PLAN_LOG_MAX_DAYS (365)" in out
    assert "STARTED" in _start_with(PLAN_LOG_MAX_DAYS="365", COMPLIANCE_RECORD_MIN_DAYS="365")


@pytest.mark.parametrize("name,value", [("COMPLIANCE_ACCESS", "maybe"), ("COMPLIANCE_VIEW_RATE", "5"),
                                        ("COMPLIANCE_AUDITOR_GRANT_DAYS", "400")])
def test_the_server_refuses_to_start_with_a_setting_out_of_its_bounds(name, value):
    out = _start_with(**{name: value})
    assert "REFUSED:" in out and f"{name} is not valid" in out
