"""A throwaway database on a running stack's Postgres, for a scenario that must not touch the stack's own data:
the web image's code runs in the web container against a database created for the test and dropped after it,
with the audit chain's head record under /tmp in the container (removed with the database).

A scenario that changes what the stack's audit chain honours (turning the hold switch on, which only a waiting
change turns off again) runs here, so the stack's own pruner and its integrity status stay as they were.
"""
import json
import subprocess
import uuid

from _account_change_helpers import API, psql

# The start of every scenario: sys.argv[1] names the database. It defines engine, SessionLocal, now (naive UTC)
# and st, the chain state of this process, set as the process's state.
PREAMBLE = r'''
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
from app.core import audit_integrity as ai, retention
engine = _require_engine()
now = datetime.now(timezone.utc).replace(tzinfo=None)
with engine.begin() as c:
    c.execute(text("INSERT INTO system_settings (key, value) VALUES ('audit_name_redaction_purged', '{}') "
                   "ON CONFLICT DO NOTHING"))
st = ai.ChainState()
ai.set_state(st)
'''


def throwaway_database():
    """A test module's throwaway fixture: ``yield from throwaway_database()`` yields the database's name."""
    name = "retain_" + uuid.uuid4().hex[:12]
    psql(f"CREATE DATABASE {name}")
    try:
        yield name
    finally:
        psql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{name}'")
        psql(f"DROP DATABASE IF EXISTS {name}")
        subprocess.run(["docker", "exec", API, "sh", "-c", f"rm -f /tmp/{name}-head.json /tmp/{name}-head.json.lock"],
                       capture_output=True, timeout=30)


def run_in(name, script, env=None):
    """Run ``script`` (which starts with PREAMBLE) in the web container against the throwaway database
    ``name``; return the JSON its last printed line holds."""
    args = ["docker", "exec", "-i"] + [f"-e{k}={v}" for k, v in (env or {}).items()] + [API, "python", "-", name]
    r = subprocess.run(args, input=script, capture_output=True, text=True, encoding="utf-8", timeout=600)
    assert r.returncode == 0, (r.stderr or r.stdout)[-3000:]
    return json.loads(r.stdout.strip().splitlines()[-1])
