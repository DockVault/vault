"""How long audit rows are kept, on a running stack's Postgres (app/core/audit_retention.py).

The preview route answers on the stack itself. The job runs the web image's code in the web container against
a throwaway database of its own per test, seeded with old rows before the audit chain starts there (rows dated
before the chain's first hour are never sealed, so never pruned: the stack's own log cannot be seeded with old
rows). The audit job deletes through the chain: the preview says what it deletes, and it deletes exactly that;
a 7-day maximum leaves administration rows younger than 365 days; the size cap, measured as Postgres stores the
rows, deletes the oldest plain rows and never an administration row; and at the first start a positive
AUDIT_LOG_RETENTION_DAYS waits, as a change the server schedules and seals. test_audit_retention.py covers the
rules offline.
"""
import json
import subprocess
import uuid

import pytest

from _account_change_helpers import API, psql

pytestmark = pytest.mark.integration

HEAD = r'''
import json, os, sys, uuid
from datetime import datetime, timedelta, timezone
name = sys.argv[1]
os.environ["DATABASE_URL"] = os.environ["DATABASE_URL"].rsplit("/", 1)[0] + "/" + name
os.environ["AUDIT_CHAIN_HEAD_FILE"] = "/tmp/" + name + "-head.json"
from app.core.config import bootstrap_entrypoint
bootstrap_entrypoint("audit-retention-test")
from sqlalchemy import text
from app.core.database import SessionLocal, _require_engine, init_db
init_db()
from app.core import audit_integrity as ai, audit_retention as ar, retention
from app.core.models import AuditLog
engine = _require_engine()
now = datetime.now(timezone.utc).replace(tzinfo=None)
with engine.begin() as c:
    c.execute(text("INSERT INTO system_settings (key, value) VALUES ('audit_name_redaction_purged', '{}') "
                   "ON CONFLICT DO NOTHING"))

def seed(tag, days, action, n=1, pad_kb=0):
    pad = ("(SELECT string_agg(md5(random()::text || g::text), '') FROM generate_series(1, %d) g)" % (pad_kb * 32)
           if pad_kb else "''")
    with engine.begin() as c:
        c.execute(text(
            "INSERT INTO audit_logs (id, action, status, timestamp, details, seal_nonce) "
            "SELECT gen_random_uuid(), '%s', 'success', now() AT TIME ZONE 'utc' - interval '%d days' "
            "- (g || ' minutes')::interval, json_build_object('tag', '%s', 'pad', %s), "
            "decode(md5(random()::text || g::text), 'hex') FROM generate_series(1, %d) g"
            % (action, days, tag, pad, n)))

def count(tag, action=None):
    extra = " AND action = '%s'" % action if action else ""
    with engine.begin() as c:
        return c.execute(text("SELECT count(*) FROM audit_logs WHERE details->>'tag' = '%s'%s" % (tag, extra))).scalar()

st = ai.ChainState()
ai.set_state(st)

def seal_all():
    for _ in range(100):
        r = ai.seal_pass(SessionLocal, st=st, now=now)
        if r.stopped or not r.sealed:
            return r.stopped

def prune(numbers):
    return ar.prune(retention.Pass(SessionLocal, now=now), ar.Numbers(*numbers)).deleted
'''


@pytest.fixture
def throwaway():
    name = "retain_" + uuid.uuid4().hex[:12]
    psql(f"CREATE DATABASE {name}")
    try:
        yield name
    finally:
        psql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}'")
        psql(f"DROP DATABASE IF EXISTS {name}")
        subprocess.run(["docker", "exec", API, "sh", "-c", f"rm -f /tmp/{name}-head.json /tmp/{name}-head.json.lock"],
                       capture_output=True, timeout=30)


def _run(name, body, env=None):
    args = ["docker", "exec", "-i"] + [f"-e{k}={v}" for k, v in (env or {}).items()] + [API, "python", "-", name]
    r = subprocess.run(args, input=HEAD + body, capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, (r.stderr or r.stdout)[-3000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def test_the_preview_route_answers_for_administrators(admin):
    r = admin.get("/settings/managed/audit/preview", params={"max_days": 300, "admin_min_days": 500})
    assert r.status_code == 200, r.text
    assert r.json()["numbers"] == {"audit_max_days": 300, "audit_min_days": 0, "audit_admin_min_days": 500,
                                   "audit_max_mb": 0}
    assert admin.get("/settings/managed/audit/preview", params={"admin_min_days": 10}).status_code == 400


def test_the_preview_is_what_the_job_deletes(throwaway):
    out = _run(throwaway, r'''
tag = uuid.uuid4().hex
seed(tag, 400, "file_upload", n=5)
seed(tag, 400, "settings_updated", n=2)
seed(tag, 100, "file_upload", n=3)
stopped = seal_all()
numbers = [300, 0, 500, 0]
db = SessionLocal()
shown = ar.preview(db, now, ar.Numbers(*numbers))
db.close()
deleted = prune(numbers)
print(json.dumps({"stopped": stopped, "shown": shown, "deleted": deleted, "plain": count(tag, "file_upload"),
                  "admin": count(tag, "settings_updated")}))
''')
    assert out["stopped"] is None, out
    assert out["shown"]["by_size"]["rows"] == 0
    assert out["deleted"] == out["shown"]["by_age"]["rows"] >= 5
    assert (out["plain"], out["admin"]) == (3, 2)


def test_a_seven_day_maximum_leaves_administration_rows_younger_than_365_days(throwaway):
    out = _run(throwaway, r'''
tag = uuid.uuid4().hex
seed(tag, 100, "settings_updated")
seed(tag, 100, "access_denied")
seed(tag, 100, "file_upload")
seed(tag, 400, "settings_updated")
seal_all()
prune([7, 0, 365, 0])
print(json.dumps([count(tag, "settings_updated"), count(tag, "access_denied"), count(tag, "file_upload")]))
''')
    assert out == [1, 1, 0]


def test_the_size_cap_deletes_the_oldest_plain_rows_and_never_administration_rows(throwaway):
    out = _run(throwaway, r'''
tag = uuid.uuid4().hex
seed(tag, 30, "settings_updated", n=2, pad_kb=300)
seed(tag, 40, "file_upload", n=6, pad_kb=300)
seal_all()
before = count(tag, "file_upload")
prune([0, 0, 365, 1])
with engine.begin() as c:
    size = c.execute(text("SELECT coalesce(sum(pg_column_size(a.*)), 0) FROM audit_logs a WHERE "
                          "timestamp < (now() AT TIME ZONE 'utc') - interval '7 days'")).scalar()
print(json.dumps({"admin": count(tag, "settings_updated"), "before": before, "left": count(tag, "file_upload"),
                  "size": size}))
''')
    assert out["admin"] == 2
    assert 0 < out["before"] - out["left"] <= out["before"]
    assert out["size"] <= 1024 * 1024 or out["left"] == 0


def test_at_the_first_start_a_retention_set_in_env_waits_as_a_change_the_server_schedules(throwaway):
    out = _run(throwaway, r'''
tag = uuid.uuid4().hex
seed(tag, 400, "file_upload", n=2)
done = retention.run_pass(SessionLocal, engine=engine, now=now)
with engine.begin() as c:
    stored = c.execute(text("SELECT value::text FROM managed_settings WHERE key = 'audit_max_days'")).scalar()
    change = c.execute(text("SELECT status || '|' || coalesce(setting::text, 'null') || '|' || requested_by_name "
                            "FROM managed_setting_changes WHERE key = 'audit_max_days'")).scalar()
    scheduled = c.execute(text("SELECT count(*) FROM audit_logs WHERE action = 'setting_change_scheduled'")).scalar()
    seals = [r[0] for r in c.execute(text("SELECT kind FROM audit_seals ORDER BY seq LIMIT 3"))]
    request = c.execute(text("SELECT detail::text FROM audit_seals WHERE seq = 3")).scalar()
print(json.dumps({"audit_logs": dict((n, r.deleted if r else None) for n, r in done)["audit_logs"],
                  "left": count(tag), "stored": stored, "change": change, "scheduled": scheduled, "seals": seals,
                  "request": json.loads(request)}))
''', env={"AUDIT_LOG_RETENTION_DAYS": "30"})
    assert out["audit_logs"] == 0 and out["left"] == 2, out
    assert out["stored"] == "0"
    assert out["change"] == "pending|30|the server (AUDIT_LOG_RETENTION_DAYS in .env)"
    assert out["scheduled"] == 1
    assert out["seals"] == ["genesis", "policy", "request"]
    assert (out["request"]["by"], out["request"]["setting"], out["request"]["new"]) == ("server", "audit_max_days", 30)
