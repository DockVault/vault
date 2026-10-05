"""The audit log's integrity chain on a running stack (app/core/audit_integrity.py).

On the stack's own database: the web process's pruner writes genesis and its policy seal by itself, the
Activity page's status route shows the head, the host command (``python -m app.core.audit_integrity verify``,
what ``dockvault.py audit verify`` runs) checks the chain and prints the head, and an export carries it.

On a throwaway database in the same Postgres, with the web image's code, where the clock and the rows can be
set: hours sealed from real Postgres rows (JSON and JSONB text, pg_column_size, uuid order), every class of
tampering found, a respelled JSON value not, rows without a nonce, a prune that keeps the chain valid, a
trigger planted on the table found by the hooks check, and the chain's lock held by another session making a
writer wait. test_audit_integrity*.py cover the rules offline.
"""
import json
import subprocess
import time
import uuid

import pytest

from _account_change_helpers import API, DB, psql

pytestmark = pytest.mark.integration


def _wait_for(check, timeout=180.0, step=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(step)
    return check()


def _tool(*args):
    r = subprocess.run(["docker", "exec", "-i", API, "python", "-m", "app.core.audit_integrity", *args],
                       capture_output=True, text=True, encoding="utf-8", timeout=600)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    return r.returncode, (json.loads(lines[-1]) if lines else None), r.stderr


# --------------------------------------------------------------------------- the stack's own chain

def _status(admin):
    r = admin.get("/activity/integrity")
    assert r.status_code == 200, r.text
    return r.json()


def test_the_running_server_starts_the_chain_and_shows_its_head(admin):
    status = _wait_for(lambda: (_status(admin).get("head") and _status(admin)))
    assert status, "the pruner never wrote the chain's first seal"
    assert status["head"].startswith("dvchain1:")
    assert "not against the server's operator" in status["claim"]
    kinds = psql("SELECT string_agg(kind, ',' ORDER BY seq) FROM audit_seals WHERE seq <= 2")
    assert kinds == "genesis,policy"
    # The key: setup's AUDIT_CHAIN_KEY is not in the test stack's .env, so it is derived from ENCRYPTION_KEY.
    assert status["key_shared"] is True


def test_the_host_command_verifies_the_chain_and_prints_the_head(admin):
    _wait_for(lambda: _status(admin).get("head"))
    code, answer, err = _tool("verify", "--json")
    assert answer is not None and answer["ok"] is True, err[-1500:]
    failures = [f for f in answer["findings"] if f["severity"] == "failure"]
    assert failures == [], failures
    assert answer["head"].startswith("dvchain1:")
    seq = int(answer["head"].split(":")[1])
    link = psql(f"SELECT encode(link, 'hex') FROM audit_seals WHERE seq = {seq}")
    assert answer["head"].endswith(link)
    code, answer, err = _tool("head")
    assert code == 0


def test_an_export_carries_the_head(admin):
    _wait_for(lambda: _status(admin).get("head"))
    r = admin.get("/activity/export", params={"format": "csv"})
    assert r.status_code == 200, r.text
    last = [ln for ln in r.text.splitlines() if ln.strip()][-1]
    assert last.startswith("# Audit chain head when this export started: dvchain1:"), last
    r = admin.get("/activity/export", params={"format": "ndjson"})
    assert json.loads(r.text.strip().splitlines()[-1])["audit_chain_head"].startswith("dvchain1:")


def test_the_status_is_for_administrators_only(temp_user_client, anon):
    assert temp_user_client.get("/activity/integrity").status_code == 403
    assert anon.get("/activity/integrity").status_code in (401, 403)


# --------------------------------------------------------------------------- a throwaway database

PROBE = r'''
import json, os, sys, threading, uuid
from datetime import datetime, timedelta, timezone
name = sys.argv[1]
os.environ["DATABASE_URL"] = os.environ["DATABASE_URL"].rsplit("/", 1)[0] + "/" + name
os.environ["AUDIT_CHAIN_HEAD_FILE"] = "/tmp/" + name + "-head.json"
os.environ["AUDIT_CHAIN_KEY"] = "k" * 64
from app.core.config import bootstrap_entrypoint
bootstrap_entrypoint("audit-chain-live-test")
from sqlalchemy import text
from app.core.database import SessionLocal, _require_engine, init_db
init_db()
from app.core import audit_chain_format as fmt, audit_chain_prune, audit_chain_verify as v
from app.core import audit_integrity as ai, retention
from app.core.models import AuditLog, SystemSetting
engine = _require_engine()
out = {}
now = datetime.now(timezone.utc).replace(tzinfo=None)
base = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=6)

with engine.begin() as c:
    c.execute(text("INSERT INTO system_settings (key, value) VALUES ('audit_name_redaction_purged', '{}')"))
    for i in range(12):
        nonce = None if i % 4 == 0 else os.urandom(16)
        c.execute(text(
            "INSERT INTO audit_logs (id, action, status, timestamp, username, ip_address, details, recorded, "
            "seal_nonce, privacy_version) VALUES (:id, :a, 'success', :t, :u, '203.0.113.5', CAST(:d AS json), "
            "CAST(:r AS jsonb), :n, 3)"),
            {"id": uuid.uuid4(), "a": "settings_updated" if i == 5 else "file_uploaded",
             "t": base + timedelta(minutes=17 * i), "u": "user%d" % (i % 3),
             "d": json.dumps({"size": i * 1.5, "name": "résumé", "deep": {"b": [1, 2.0, None]}}),
             "r": json.dumps({"ip": "full", "n": i}), "n": nonce})

st = ai.ChainState()
ai.set_state(st)
for _ in range(50):
    r = ai.seal_pass(SessionLocal, st=st, now=now)
    if r.stopped or not r.sealed:
        break
out["stopped"] = r.stopped
out["kinds"] = [k for (k,) in SessionLocal().execute(text("SELECT kind FROM audit_seals ORDER BY seq"))]
out["salted"] = SessionLocal().execute(text("SELECT count(*) FROM audit_seals WHERE legacy_salt IS NOT NULL")).scalar()

def report():
    db = SessionLocal()
    try:
        held = {k: c.key for k, c in st.keys_held().items()}
        rep = v.verify(db, record=st.head_store().load(), held=held, current_key_id=st.current_key().key_id, now=now)
        return [f.kind for f in rep.findings if f.severity == "failure"], rep
    finally:
        db.close()

out["clean"], rep = report()
out["head"] = rep.head
out["rows_checked"] = rep.rows_checked

def tamper(sql, restore):
    with engine.begin() as c:
        c.execute(text(sql))
    kinds, _ = report()
    with engine.begin() as c:
        c.execute(text(restore))
    return kinds

one = SessionLocal().execute(text("SELECT id::text, details::text, recorded::text, username FROM audit_logs "
                                  "WHERE action = 'file_uploaded' ORDER BY timestamp LIMIT 1 OFFSET 1")).first()
rid, details, recorded, username = one
q = lambda s: s.replace("'", "''")
out["respelled"] = tamper(
    "UPDATE audit_logs SET details = CAST('" + q(details.replace(",", " , ")) + "' AS json) WHERE id = '" + rid + "'",
    "UPDATE audit_logs SET details = CAST('" + q(details) + "' AS json) WHERE id = '" + rid + "'")
out["status"] = tamper("UPDATE audit_logs SET status = 'failure' WHERE id = '" + rid + "'",
                       "UPDATE audit_logs SET status = 'success' WHERE id = '" + rid + "'")
out["username"] = tamper("UPDATE audit_logs SET username = 'mallory' WHERE id = '" + rid + "'",
                         "UPDATE audit_logs SET username = '" + q(username) + "' WHERE id = '" + rid + "'")
out["recorded"] = tamper(
    "UPDATE audit_logs SET recorded = jsonb_set(recorded, '{n}', '99') WHERE id = '" + rid + "'",
    "UPDATE audit_logs SET recorded = CAST('" + q(recorded) + "' AS jsonb) WHERE id = '" + rid + "'")
with engine.begin() as c:
    keep = c.execute(text("SELECT row_to_json(a)::text FROM audit_logs a WHERE id = '" + rid + "'")).scalar()
out["deleted"] = tamper("DELETE FROM audit_logs WHERE id = '" + rid + "'",
                        "INSERT INTO audit_logs SELECT * FROM json_populate_record(NULL::audit_logs, CAST('" +
                        q(keep) + "' AS json))")
out["after_restore"], _ = report()

with engine.begin() as c:
    c.execute(text("CREATE FUNCTION audit_planted() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"))
    c.execute(text("CREATE TRIGGER audit_planted BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION audit_planted()"))
db = SessionLocal()
out["hooks"] = v.db_hooks(db)
db.close()
with engine.begin() as c:
    c.execute(text("DROP TRIGGER audit_planted ON audit_logs"))
    c.execute(text("DROP FUNCTION audit_planted()"))
db = SessionLocal()
out["hooks_after"] = v.db_hooks(db)
db.close()

holder = engine.connect()
holder.execute(text("SELECT pg_advisory_lock(%d, %d)" % ai.CHAIN_LOCK))
holder.commit()
try:
    with ai.ChainWriter(engine, st, wait=1):
        out["busy"] = False
except ai.ChainBusy:
    out["busy"] = True
holder.execute(text("SELECT pg_advisory_unlock(%d, %d)" % ai.CHAIN_LOCK))
holder.commit()
holder.close()

p = retention.Pass(SessionLocal, now=now)
done = audit_chain_prune.prune(p, [AuditLog.timestamp < base + timedelta(hours=1, minutes=30),
                                   AuditLog.action == "file_uploaded"], reason="retention")
out["pruned"] = done.deleted
out["after_prune"], rep = report()
out["prune_seals"] = SessionLocal().execute(text("SELECT count(*) FROM audit_seals WHERE kind = 'prune'")).scalar()
print(json.dumps(out, default=str))
'''


@pytest.fixture
def throwaway():
    name = "chain_" + uuid.uuid4().hex[:12]
    psql(f"CREATE DATABASE {name}")
    try:
        yield name
    finally:
        psql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}'")
        psql(f"DROP DATABASE IF EXISTS {name}")
        subprocess.run(["docker", "exec", API, "sh", "-c", f"rm -f /tmp/{name}-head.json /tmp/{name}-head.json.lock"],
                       capture_output=True, timeout=30)


def test_the_chain_on_real_postgres_rows(throwaway):
    r = subprocess.run(["docker", "exec", "-i", API, "python", "-", throwaway], input=PROBE,
                       capture_output=True, text=True, encoding="utf-8", timeout=600)
    assert r.returncode == 0, (r.stderr or r.stdout)[-3000:]
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["stopped"] is None, out
    assert out["kinds"][:2] == ["genesis", "policy"] and "hour" in out["kinds"]
    assert out["salted"] >= 1                         # rows written without a nonce got their hour's salt
    assert out["clean"] == [], out
    assert out["rows_checked"] >= 12
    assert out["respelled"] == []                     # the same JSON value spelled differently
    assert "rows-altered" in out["status"] and "rows-altered" in out["username"]
    assert "rows-altered" in out["recorded"]          # a JSONB value changed
    assert "rows-missing" in out["deleted"]
    assert out["after_restore"] == [], out
    assert any("audit_planted" in h for h in out["hooks"]) and out["hooks_after"] == []
    assert out["busy"] is True
    assert out["pruned"] >= 1 and out["prune_seals"] >= 1 and out["after_prune"] == [], out
