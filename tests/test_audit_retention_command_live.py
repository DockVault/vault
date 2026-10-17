"""`dockvault.py audit retention` on a running stack: what the host tool runs in the web container
(``python -m app.core.audit_integrity retention``) answers with every setting of how long records are kept as the
server has it, the same values the panel shows; and for --set lines it checks them without writing anything: a
line that is not one of these settings is refused, a value the server would not start with is named, and a
change that deletes sooner is said to. test_retention_report.py and test_dockvault_audit_retention.py cover the
rules offline.
"""
import json
import subprocess

import pytest

from _account_change_helpers import API, psql
from test_retention_live import chain_started  # noqa: F401

pytestmark = pytest.mark.integration


def _retention(*args):
    try:
        r = subprocess.run(["docker", "exec", API, "python", "-m", "app.core.audit_integrity", "retention", *args],
                           capture_output=True, text=True, timeout=180)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert lines, r.stderr[-2000:]
    return r.returncode, json.loads(lines[-1])


def test_the_command_shows_what_the_panel_shows(admin):
    code, out = _retention()
    assert code == 0 and out["ok"] is True, out
    assert out["chain_started"] is True
    rows = {r["key"]: r for r in out["settings"]}
    assert {"audit_max_days", "logs_hold", "security_record_days", "audit_hot_days", "notification_retention_days",
            "log_pull_sink_max_mb", "ended_invitation_days"} <= set(rows)
    assert (rows["audit_max_days"]["env"], rows["audit_max_days"]["ceiling_env"]) == ("AUDIT_LOG_RETENTION_DAYS",
                                                                                      "PLAN_LOG_MAX_DAYS")
    panel = {r["key"]: r for r in admin.get("/settings/managed").json()["settings"]}
    for key, row in rows.items():
        assert row["value"] == panel[key]["value"], key
    assert [p["key"] for p in out["pending"]] == [p["key"] for p in admin.get("/settings/managed").json()["pending"]]


def test_lines_are_checked_and_nothing_is_written():
    version = psql("SELECT coalesce(max(version), 0) FROM managed_settings")
    code, out = _retention("--set", "AUDIT_LOG_RETENTION_DAYS=30", "--set", "NOTIFICATION_RETENTION_DAYS=60")
    assert code == 0 and out["ok"] is True, out
    check = out["check"]
    assert check["problems"] == []
    assert {"audit_max_days", "notification_retention_days"} <= set(check["deletes_sooner"]), check
    code, out = _retention("--set", "SECURITY_RECORD_MIN_DAYS=400")
    assert code == 0 and any("the floor (400) is above the ceiling (365)" in p for p in out["check"]["problems"]), out
    code, out = _retention("--set", "ENCRYPTION_KEY=x")
    assert code == 2 and out["ok"] is False and "is not a .env line" in out["error"]
    code, out = _retention("--set", "AUDIT_LOG_RETENTION_DAYS=soon")
    assert code == 2 and "is not a whole number" in out["error"]
    assert psql("SELECT coalesce(max(version), 0) FROM managed_settings") == version
