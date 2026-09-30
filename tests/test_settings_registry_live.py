"""The settings registry's table on a running stack (app/core/settings_registry.py).

managed_settings exists with the columns the registry reads and writes, and the web app still saves an
ordinary key through PUT /settings. What only Postgres runs is checked here too: store() takes the table's
lock, so two stores at once get versions one after the other, and refresh() limits how long its statements
may take before it reads anything. test_settings_registry.py covers resolving, the copy each process keeps,
the refusals and the startup contract offline.
"""
import json
import uuid

from _account_change_helpers import in_api_container, psql

# Two throwaway keys registered in a process of their own inside the web container, which never registers
# them itself. The first store holds its transaction open for a while; the second starts once the first
# has stored, so without the table's lock it would read the same highest version.
_TWO_STORES = """
import json, sys, threading, time
from sqlalchemy import event
from app.core import settings_registry as R
from app.core.database import SessionLocal, _require_engine
a, b = sys.argv[1], sys.argv[2]
for key in (a, b):
    R.register(R.SettingSpec(key=key, kind="int", default=1, minimum=0, maximum=100))
out = {}
first_stored = threading.Event()

def first():
    db = SessionLocal()
    try:
        out["a"] = R.store(db, a, 5, by_name="probe")
        first_stored.set()
        time.sleep(1.5)
        out["a_commit"] = time.monotonic()
        db.commit()
    finally:
        db.close()

def second():
    first_stored.wait(20)
    db = SessionLocal()
    try:
        out["b_start"] = time.monotonic()
        out["b"] = R.store(db, b, 6, by_name="probe")
        out["b_stored"] = time.monotonic()
        db.commit()
    finally:
        db.close()

threads = [threading.Thread(target=first), threading.Thread(target=second)]
for t in threads:
    t.start()
for t in threads:
    t.join(30)

seen = []
def capture(conn, cursor, statement, parameters, context, executemany):
    seen.append(statement)
engine = _require_engine()
event.listen(engine, "before_cursor_execute", capture)
try:
    out["reloaded"] = R.refresh()
finally:
    event.remove(engine, "before_cursor_execute", capture)
out["statements"] = seen
out["stamp"] = R.stamp()
out["held"] = {k: v for k, (v, _) in R._cache.rows.items() if k in (a, b)}
print("RESULT=" + json.dumps(out))
"""


def test_the_table_is_there_with_its_columns():
    rows = psql("SELECT column_name, data_type, is_nullable FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = 'managed_settings' ORDER BY column_name")
    found = {name: (data_type, nullable) for name, data_type, nullable in (r.split("|") for r in rows.splitlines())}
    assert found == {
        "key": ("character varying", "NO"),
        "value": ("json", "YES"),
        "version": ("bigint", "NO"),
        "updated_by": ("uuid", "YES"),
        "updated_by_name": ("character varying", "YES"),
        "updated_at": ("timestamp without time zone", "NO"),
    }
    fk = psql("SELECT confdeltype FROM pg_constraint WHERE conrelid = 'managed_settings'::regclass "
              "AND contype = 'f'")
    assert fk == "n"          # ON DELETE SET NULL: deleting the account keeps the row and its name


def test_an_ordinary_setting_is_still_saved_through_put_settings(admin):
    before = admin.get("/settings").json()
    r = admin.put("/settings", json={"sharing_enabled": bool(before.get("sharing_enabled"))})
    assert r.status_code == 200, r.text


def test_two_stores_at_once_get_one_version_after_the_other_and_a_refresh_limits_its_statements():
    tag = uuid.uuid4().hex[:10]
    a, b = f"probe_{tag}_a", f"probe_{tag}_b"
    try:
        r = in_api_container(_TWO_STORES.replace("sys.argv[1], sys.argv[2]", f"{a!r}, {b!r}"))
        (line,) = [l for l in r.stdout.splitlines() if l.startswith("RESULT=")]
        out = json.loads(line.split("=", 1)[1])
        # The second store waited for the first to commit, and then read its version: the highest version
        # moves on every change, which is what every other process's copy watches.
        assert out["b"] == out["a"] + 1, out
        assert out["b_stored"] >= out["a_commit"] > out["b_start"], out
        stored = psql(f"SELECT key, version FROM managed_settings WHERE key IN ('{a}', '{b}') ORDER BY version")
        assert stored.splitlines() == [f"{a}|{out['a']}", f"{b}|{out['b']}"], stored
        # A refresh limits its statements before it reads anything, and then picks up both.
        assert out["statements"][0] == "SET LOCAL statement_timeout = 5000", out["statements"]
        assert out["reloaded"] is True and out["stamp"] >= out["b"], out
        assert out["held"] == {a: 5, b: 6}, out
    finally:
        psql(f"DELETE FROM managed_settings WHERE key IN ('{a}', '{b}')")
