"""How long audit rows are kept, on a running stack (app/core/audit_retention.py).

The preview route says what the audit job deletes, and the job, run in the web container with the same
numbers, deletes exactly that; a 7-day maximum leaves administration rows younger than 365 days; the size cap,
measured as Postgres stores the rows, deletes the oldest plain rows and never an administration row; and
after an upgrade a positive AUDIT_LOG_RETENTION_DAYS with older rows waits, as a change the server
schedules. test_audit_retention.py covers the rules offline.
"""
import json
import subprocess
import uuid

import pytest

from _account_change_helpers import API, psql

pytestmark = pytest.mark.integration

PREFIX = "from app.core.config import bootstrap_entrypoint\nbootstrap_entrypoint('audit-retention-test')\n"


def _python(source, env=None):
    args = ["docker", "exec", "-i"] + [f"-e{k}={v}" for k, v in (env or {}).items()] + [API, "python", "-c",
                                                                                         PREFIX + source]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, (r.stderr or r.stdout)[-1500:]
    return r.stdout.strip().splitlines()[-1]


def _prune(numbers):
    return int(_python("from app.core import audit_retention as ar, retention\n"
                       "from app.core.database import SessionLocal\n"
                       f"print(ar.prune(retention.Pass(SessionLocal), ar.Numbers(*{list(numbers)!r})).deleted)\n"))


def _seed(tag, days, action, n=1, pad_kb=0):
    """``n`` audit rows ``days`` old carrying ``tag``; with ``pad_kb`` of hard-to-compress details."""
    pad = (f"(SELECT string_agg(md5(random()::text || g::text), '') FROM generate_series(1, {pad_kb * 32}) g)"
           if pad_kb else "''")
    psql("INSERT INTO audit_logs (id, action, status, timestamp, details) "
         f"SELECT gen_random_uuid(), '{action}', 'success', now() AT TIME ZONE 'utc' - interval '{days} days' "
         f"- (g || ' minutes')::interval, json_build_object('tag', '{tag}', 'pad', {pad}) "
         f"FROM generate_series(1, {n}) g")


def _count(tag, action=None):
    extra = f" AND action = '{action}'" if action else ""
    return int(psql(f"SELECT count(*) FROM audit_logs WHERE details->>'tag' = '{tag}'{extra}"))


def _cleanup(tag):
    psql(f"DELETE FROM audit_logs WHERE details->>'tag' = '{tag}'")


def test_the_preview_is_what_the_job_deletes(admin):
    tag = uuid.uuid4().hex
    _seed(tag, 400, "file_upload", n=5)
    _seed(tag, 400, "settings_updated", n=2)
    _seed(tag, 100, "file_upload", n=3)
    try:
        r = admin.get("/settings/managed/audit/preview", params={"max_days": 300, "admin_min_days": 500})
        assert r.status_code == 200, r.text
        shown = r.json()
        assert shown["numbers"] == {"audit_max_days": 300, "audit_min_days": 0, "audit_admin_min_days": 500,
                                    "audit_max_mb": 0}
        assert shown["by_size"]["rows"] == 0
        deleted = _prune([300, 0, 500, 0])
        assert deleted == shown["by_age"]["rows"] >= 5
        assert (_count(tag, "file_upload"), _count(tag, "settings_updated")) == (3, 2)
        assert admin.get("/settings/managed/audit/preview", params={"admin_min_days": 10}).status_code == 400
    finally:
        _cleanup(tag)


def test_a_seven_day_maximum_leaves_administration_rows_younger_than_365_days():
    tag = uuid.uuid4().hex
    _seed(tag, 100, "settings_updated")
    _seed(tag, 100, "access_denied")
    _seed(tag, 100, "file_upload")
    _seed(tag, 400, "settings_updated")
    try:
        _prune([7, 0, 365, 0])
        assert (_count(tag, "settings_updated"), _count(tag, "access_denied"), _count(tag, "file_upload")) == (1, 1, 0)
    finally:
        _cleanup(tag)


def test_the_size_cap_deletes_the_oldest_plain_rows_and_never_administration_rows():
    tag = uuid.uuid4().hex
    _seed(tag, 30, "settings_updated", n=2, pad_kb=300)
    _seed(tag, 40, "file_upload", n=6, pad_kb=300)
    try:
        before = _count(tag, "file_upload")
        _prune([0, 0, 365, 1])
        assert _count(tag, "settings_updated") == 2
        left = _count(tag, "file_upload")
        assert 0 < before - left <= before
        size = int(psql("SELECT coalesce(sum(pg_column_size(a.*)), 0) FROM audit_logs a WHERE "
                        "timestamp < (now() AT TIME ZONE 'utc') - interval '7 days'"))
        assert size <= 1024 * 1024 or left == 0
    finally:
        _cleanup(tag)


def test_after_an_upgrade_a_retention_set_in_env_waits_as_a_change_the_server_schedules():
    tag = uuid.uuid4().hex
    marker = psql("SELECT value FROM system_settings WHERE key = 'audit_env_retention_scheduled'")
    _seed(tag, 400, "file_upload", n=2)
    psql("DELETE FROM system_settings WHERE key = 'audit_env_retention_scheduled'")
    try:
        out = json.loads(_python(
            "import json\nfrom app.core import retention\n"
            "done = None\n"
            "for _ in range(30):\n"
            "    done = retention.run_pass()\n"
            "    if done is not None: break\n"
            "    import time; time.sleep(1)\n"
            "print(json.dumps({n: (r.deleted if r else None) for n, r in done}))\n",
            env={"AUDIT_LOG_RETENTION_DAYS": "30"}))
        assert out["audit_logs"] == 0 and _count(tag) == 2, out
        assert psql("SELECT value FROM managed_settings WHERE key = 'audit_max_days'") == "0"
        change = psql("SELECT status || '|' || coalesce(setting::text, 'null') || '|' || requested_by_name "
                      "FROM managed_setting_changes WHERE key = 'audit_max_days' ORDER BY requested_at DESC LIMIT 1")
        assert change == "pending|null|the server (AUDIT_LOG_RETENTION_DAYS in .env)"
        assert psql("SELECT count(*) FROM audit_logs WHERE action = 'setting_change_scheduled' "
                    "AND timestamp > (now() AT TIME ZONE 'utc') - interval '5 minutes'") == "1"
        assert json.loads(psql("SELECT value FROM system_settings WHERE key = 'audit_env_retention_scheduled'"))[
            "scheduled"] is True
    finally:
        _cleanup(tag)
        psql("UPDATE managed_setting_changes SET status = 'cancelled', reason = 'test cleanup' "
             "WHERE key = 'audit_max_days' AND status = 'pending'")
        psql("UPDATE managed_settings SET value = NULL, version = (SELECT max(version) + 1 FROM managed_settings) "
             "WHERE key = 'audit_max_days'")
        psql("DELETE FROM system_settings WHERE key = 'audit_env_retention_scheduled'")
        if marker:
            psql("INSERT INTO system_settings (key, value) VALUES ('audit_env_retention_scheduled', "
                 f"'{marker}'::json)")
