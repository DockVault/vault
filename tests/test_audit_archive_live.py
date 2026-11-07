"""The audit log's archive on a running stack's Postgres (app/core/audit_archive.py): each case runs on a throwaway
database of its own, with the web image's code in the web container (tests/_throwaway_db.py), the server's passes
run as scripts whose clock can be set, and the host's commands as ``python -m app.core.audit_integrity`` in a
process of their own, in their two phases:

- a sealed day older than the row window moves into a block: stored without Postgres's compression once the
  background step has run (its length read without reading it), the data marker kept while a block exists (also
  by the once-a-day check beside a pass writing the first block), the chain clean; ``audit unarchive`` puts back rows identical in every column, JSON text and JSONB included, and the
  marker goes with the last block;
- the audit job deletes archived rows through the block-rewrite primitive (the conditions run over a temporary
  table shaped like audit_logs), keeping the protected ones; the size cap counts an archived part by its bound
  length once a delay of sealing has passed, and verify recomputes a size-cap prune's total;
- a block changed, removed or added in the database, and a row put back into an archived hour, are found;
- what a database writer cannot make the size cap do: raise the share it may never delete, or make an hour the
  chain keeps whole one it cuts at;
- verify and the daily check read one state, and the head record that goes with it, while the archive, an
  unarchive, or a host command's process between its commit and its record write, commits;
- ``audit compact`` runs VACUUM FULL over both audit tables; ``df`` in the database container gives the free space
  dockvault.py checks before an unarchive.

test_audit_archive.py covers the rules offline.
"""
import json
import subprocess

import pytest

from _account_change_helpers import API, DB
from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

KEY = "k" * 64

SCRIPT = PREAMBLE + r'''
import hashlib
from app.core import audit_archive as arc, audit_chain_format as fmt, audit_chain_verify as v
from app.core import audit_retention as ar, background_maintenance as bm
out = {}
real_now = now
clock = [real_now]
st = ai.ChainState(clock=lambda: clock[0])
ai.set_state(st)
DAY = (real_now - timedelta(days=100)).date()


def at(hour, minute=0, day=None):
    d = day or DAY
    return datetime(d.year, d.month, d.day, hour, minute)


def add_row(t, nonce=True, details=None, action="file_uploaded", recorded=None, agent="Mozilla/5.0 test"):
    rid = uuid.uuid4()
    with engine.begin() as c:
        c.execute(text(
            "INSERT INTO audit_logs (id, action, status, timestamp, username, ip_address, user_agent, endpoint, "
            "details, recorded, seal_nonce, privacy_version) VALUES (:id, :a, 'success', :t, 'carol', "
            "'203.0.113.5', :ua, '/api/files/{id}', CAST(:d AS json), CAST(:r AS jsonb), :n, 3)"),
            {"id": rid, "a": action, "t": t, "ua": agent, "d": details or json.dumps({"n": 1}),
             "r": recorded, "n": os.urandom(16) if nonce else None})
    return str(rid)


def passes(when=None):
    clock[0] = when or clock[0]
    r = None
    for _ in range(400):
        r = ai.seal_pass(SessionLocal, st=st, now=clock[0])
        if r.stopped or not r.sealed:
            break
    return r.stopped if r else None


def run_days(days):
    end = clock[0] + timedelta(days=days)
    while clock[0] + timedelta(hours=6) <= end:
        clock[0] += timedelta(hours=6)
        passes()


def report(**kw):
    db = SessionLocal()
    try:
        held = {k: c.key for k, c in st.keys_held().items()}
        rep = v.verify(db, record=st.head_store().load(), held=held, current_key_id=st.current_key().key_id,
                       now=clock[0], **kw)
        return {s: sorted({f.kind for f in rep.findings if f.severity == s})
                for s in ("failure", "warning", "information")}
    finally:
        db.close()


def archive():
    return arc.archive_job(retention.Pass(SessionLocal, now=clock[0]))


def q(sql, **params):
    with engine.begin() as c:
        res = c.execute(text(sql), params)
        return [list(r) for r in res] if res.returns_rows else []


def dump():
    """Every column of every row of the archived day, as the database gives its text."""
    return q("SELECT id::text, user_id::text, username, action, resource_type, resource_id, "
             "to_char(timestamp, 'YYYY-MM-DD HH24:MI:SS.US'), ip_address, user_agent, method, endpoint, channel, "
             "status, details::text, error_message, encode(seal_nonce, 'hex'), privacy_version, recorded::text, "
             "ip_via, case_id::text FROM audit_logs WHERE timestamp < :end ORDER BY timestamp, id",
             end=at(0) + timedelta(days=1))
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def _script(name, body):
    return run_in(name, SCRIPT + body + "\nprint(json.dumps(out, default=str))\n",
                  env={"AUDIT_CHAIN_KEY": KEY, "AUDIT_ARCHIVE_START_AFTER_DAYS": "0"})


def _url(name):
    base = subprocess.run(["docker", "exec", API, "printenv", "DATABASE_URL"], capture_output=True, text=True,
                          timeout=60).stdout.strip()
    return base.rsplit("/", 1)[0] + "/" + name


def _cli(name, *args):
    """The host's command in a process of its own in the web container, on the throwaway database."""
    env = {"DATABASE_URL": _url(name), "AUDIT_CHAIN_HEAD_FILE": f"/tmp/{name}-head.json", "AUDIT_CHAIN_KEY": KEY,
           "AUDIT_ARCHIVE_START_AFTER_DAYS": "0"}
    cmd = ["docker", "exec", "-i"] + [f"-e{k}={v}" for k, v in env.items()] + \
        [API, "python", "-m", "app.core.audit_integrity", *args]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=900)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    answer = json.loads(lines[-1]) if lines and lines[-1].startswith("{") else None
    return r.returncode, answer, r.stderr


def _two(name, *args):
    code, seen, err = _cli(name, *args, "--read")
    assert code == 0 and seen and seen["ok"], (seen, err[-3000:])
    code, done, err = _cli(name, *args, "--expect", seen["state"])
    assert code == 0 and done and done["ok"], (done, err[-3000:])
    return seen, done


def test_a_day_moves_into_a_block_on_postgres_and_comes_back_identical(throwaway):
    first = _script(throwaway, r'''
for h in (3, 4, 6):
    for i in range(3):
        add_row(at(h, i), nonce=(i != 1), details='{ "b" : [1, 2.50, "x"],  "a": null }' if i == 0 else None,
                recorded='{"ip": "shortened", "n": [1, 2.5]}' if i == 2 else None,
                agent="Mozilla/5.0 (X11; Linux x86_64) é" if h == 4 else "curl/8.5")
out["stopped"] = passes()
out["before"] = dump()
out["storage"] = bm.run_steps(engine, [s for s in bm.STEPS if s.name == "audit_archive_blocks_storage"])
archive()
out["after_rows"] = q("SELECT count(*) FROM audit_logs WHERE timestamp < :t", t=at(0) + timedelta(days=1))[0][0]
out["blocks"] = q("SELECT day::text, part, row_count, octet_length(payload), encode(sha256(payload), 'hex') "
                  "FROM audit_archive_blocks ORDER BY day, part")
out["attstorage"] = q("SELECT a.attstorage FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid "
                      "WHERE c.relname = 'audit_archive_blocks' AND a.attname = 'payload'")[0][0]
out["seal"] = q("SELECT detail::text FROM audit_seals WHERE kind = 'archive' ORDER BY seq")
out["marker"] = q("SELECT key, requires_at_least FROM data_requirements")
out["report"] = report()
''')
    assert first["stopped"] is None, first
    assert first["storage"] == {"audit_archive_blocks_storage": "applied"} and first["attstorage"] == "e"
    assert first["after_rows"] == 0 and len(first["before"]) == 9
    ((day, part, rows, length, digest),) = first["blocks"]
    (detail,) = [json.loads(d[0]) for d in first["seal"]]
    assert detail["parts"] == [[1, detail["parts"][0][1], detail["parts"][0][2], 9, length, digest]] and rows == 9
    assert detail["complete"] is True and day == detail["day"]
    assert any(m[0] == "archived-audit-history" for m in first["marker"]), first["marker"]
    assert first["report"]["failure"] == [], first["report"]
    seen, done = _two(throwaway, "unarchive")
    assert seen["estimate"]["rows"] == 9 and done["rows"] == 9 and done["days"] == [day]
    second = _script(throwaway, r'''
out["after"] = dump()
out["blocks"] = q("SELECT count(*) FROM audit_archive_blocks")[0][0]
out["marker"] = q("SELECT key FROM data_requirements")
out["report"] = report()
''')
    assert second["after"] == first["before"]
    assert second["blocks"] == 0 and ["archived-audit-history"] not in second["marker"]
    assert second["report"]["failure"] == [], second["report"]
    assert "unarchived" in second["report"]["information"]


def test_archived_rows_are_pruned_through_their_blocks_and_counted_by_the_size_cap(throwaway):
    # The chain starts nine days back, so that a delay of sealing has passed after the archived hours' seals by the
    # time the clock reaches now (the rows the app writes itself are dated now).
    done = _script(throwaway, r'''
protected = ar.protected_actions()[0]
for h in (3, 9):
    add_row(at(h), details=json.dumps({"blob": os.urandom(15000).hex()}))
keep = add_row(at(10), action=protected)
add_row(at(11))
clock[0] = real_now - timedelta(days=9)
out["stopped"] = passes()
archive()
run_days(9)
db = SessionLocal()
try:
    from app.core import audit_chain_size as size
    start = size.window_start(st.view, st.known_record(), clock[0], timedelta(days=7))
    hot, parts = size.counted(st.view, start, size.held_back(st.view, st.known_record(), start))
finally:
    db.close()
(_d, part, counted, hours), = parts
out["counted"] = [counted, part.length, sum(hours.values())]
p = retention.Pass(SessionLocal, now=clock[0])
ar.prune(p, ar.Numbers(95, 0, 365, 0))
out["kept"] = q("SELECT count(*) FROM audit_archive_blocks")[0][0]
db = SessionLocal()
try:
    from app.core.models import AuditArchiveBlock
    from app.core import audit_archive_format as af
    payload = db.query(AuditArchiveBlock.payload).scalar()
    out["rows"] = [str(r["id"]) for r in af.open_block(payload).rows()]
finally:
    db.close()
out["keep"] = keep
out["last"] = q("SELECT kind, detail->>'cause' FROM audit_seals ORDER BY seq DESC LIMIT 2")
out["report"] = report()
''')
    assert done["stopped"] is None, done
    counted, length, lagged = done["counted"]
    assert counted == min(length, lagged) and 0 < counted
    assert done["rows"] == [done["keep"]] and done["kept"] == 1
    assert done["last"] == [["archive", "rewrite"], ["prune", None]]
    assert done["report"]["failure"] == [], done["report"]


def test_a_changed_removed_or_added_block_and_a_row_put_back_are_found(throwaway):
    done = _script(throwaway, r'''
for h in (3, 4):
    add_row(at(h))
out["stopped"] = passes()
archive()
q("UPDATE audit_archive_blocks SET payload = overlay(payload placing decode('00', 'hex') from 20 for 1)")
out["altered"] = report()["failure"]
q("DELETE FROM audit_archive_blocks")
out["missing"] = report()["failure"]
q("INSERT INTO audit_archive_blocks (day, part, first_hour, last_hour, row_count, codec, format, payload, "
  "raw_bytes, aggregates, created_at) VALUES (:d, 7, :f, :l, 0, 'zstd', 1, 'x', 0, '{}', now())",
  d=DAY, f=at(0), l=at(1))
out["unsealed"] = report()["failure"]
add_row(at(3, 30))
out["put_back"] = report()["failure"]
''')
    assert done["stopped"] is None, done
    assert "block-altered" in done["altered"]
    assert "block-missing" in done["missing"]
    assert "block-unsealed" in done["unsealed"]
    assert "row-in-archived-day" in done["put_back"]


def test_compact_runs_and_unarchive_with_nothing_archived_is_refused(throwaway):
    _script(throwaway, 'add_row(at(5)); out["stopped"] = passes()\n')
    code, answer, err = _cli(throwaway, "compact")
    assert code == 0 and answer["ok"], (answer, err[-2000:])
    assert [t["table"] for t in answer["tables"]] == ["audit_logs", "audit_archive_blocks"]
    assert all(isinstance(t["before_bytes"], int) and isinstance(t["after_bytes"], int) for t in answer["tables"])
    code, refused, _err = _cli(throwaway, "unarchive", "--read")
    assert code == 2 and "no archived day" in refused["error"], refused


MARKER_RACE = PREAMBLE + r'''
import threading, time
from app.core import audit_archive as arc
out = {}
BLOCK = ("INSERT INTO audit_archive_blocks (day, part, first_hour, last_hour, row_count, codec, format, payload, "
         "raw_bytes, aggregates, created_at) VALUES (:day, 1, :t, :t, 0, 'none', 1, '\\x00', 0, '{}', :t)")


def marked():
    with engine.connect() as c:
        return c.execute(text("SELECT count(*) FROM data_requirements WHERE key = :k"), {"k": arc.MARKER_KEY}).scalar()


# The marker a block wrote earlier is there, and no block is: the last one went (an unarchive) a moment ago.
with SessionLocal() as s:
    arc.sync_marker(s, now, True)
    s.commit()
out["before"] = marked()
# An archiving pass writes the first block of a day and the marker, and is still open.
writer = SessionLocal()
writer.execute(text(BLOCK), {"day": (now - timedelta(days=100)).date(), "t": now})
out["writer_said"] = arc.sync_marker(writer, now, True)
# Meanwhile the once-a-day check, outside the chain's lock, brings the marker in line in a transaction of its own.
said = {}


def daily():
    with SessionLocal() as s:
        said["there"] = arc.sync_marker(s, now)
        s.commit()


check = threading.Thread(target=daily)
check.start()
time.sleep(1.5)
writer.commit()
writer.close()
check.join(30)
out["check_said"] = said.get("there")
out["after"] = marked()
with engine.connect() as c:
    out["blocks"] = c.execute(text("SELECT count(*) FROM audit_archive_blocks")).scalar()
print(json.dumps(out, default=str))
'''


def test_the_daily_marker_check_beside_a_pass_writing_the_first_block_keeps_the_marker_on_postgres(throwaway):
    """The once-a-day marker check runs outside the audit chain's lock, beside an archiving pass that writes the first
    block and the marker and has not committed yet. The check locks the marker's row before it looks for blocks, so it
    waits for the pass and then sees its block. Looking first, it found none, waited for the row at its removal, and
    removed the marker the pass had just committed: a block an earlier release cannot read, and nothing to stop that
    release starting."""
    done = run_in(throwaway, MARKER_RACE)
    assert done["before"] == 1 and done["writer_said"] is True, done
    assert done["check_said"] is True and done["after"] == 1 and done["blocks"] == 1, done


def test_the_database_containers_free_space_is_read_as_dockvault_reads_it():
    import dockvault
    r = subprocess.run(["docker", "exec", DB, "df", "-Pk", "/var/lib/postgresql/data"], capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 0, r.stderr
    free = dockvault.parse_df_available(r.stdout)
    assert isinstance(free, int) and free > 0, r.stdout


SIZE_CAP = r'''
ar.MB = 1
from app.core import audit_chain_size as size
from app.core import audit_archive_format as af
from app.core.models import AuditArchiveBlock, AuditLog
protected = ar.protected_actions()[0]


def counted():
    start = size.window_start(st.view, st.known_record(), clock[0], timedelta(days=7))
    return size.counted(st.view, start, size.held_back(st.view, st.known_record(), start))


def plan(cap):
    db = SessionLocal()
    try:
        p = ar.chain_size_plan(db, AuditLog, st.view, st.known_record(), clock[0], ar.Numbers(0, 0, 0, cap),
                               timedelta(days=7))
        return [str(p.cutoff), p.protected_bytes]
    finally:
        db.close()


def blob():
    return json.dumps({"blob": os.urandom(15000).hex()})
'''


@pytest.mark.parametrize("edited", [False, True])
def test_aggregates_edited_in_the_database_never_make_the_size_cap_delete_a_newer_archived_row_on_postgres(
        throwaway, edited):
    """Two archived days of one row each and a cap with room for the newer only. Edited to say the older day's row
    is protected, its block's aggregates would move the cutoff a day newer: the protected share never exceeds what
    the chain binds, so the plan is the honest one and the newer day's row stays."""
    done = _script(throwaway, f"EDITED = {edited}\n" + SIZE_CAP + r'''
older_day = DAY - timedelta(days=1)
older = add_row(at(3, day=older_day), details=blob())
newer = add_row(at(3), details=blob())
clock[0] = real_now - timedelta(days=9)
out["stopped"] = passes()
archive()
out["blocks"] = q("SELECT count(*) FROM audit_archive_blocks")[0][0]
run_days(9)
_hot, ((_d1, _p1, ca, _h1), (_d2, _p2, cb, _h2)) = counted()
cap = cb + 1000
out["fits"] = cap < ca + cb
out["honest"] = plan(cap)
if EDITED:
    with engine.begin() as c:
        agg = c.execute(text("SELECT aggregates::text FROM audit_archive_blocks WHERE day = :d"),
                        {"d": older_day}).scalar()
        agg = json.loads(agg)
        agg["by"] = [[protected] + list(r[1:]) for r in agg["by"]]
        c.execute(text("UPDATE audit_archive_blocks SET aggregates = CAST(:a AS json) WHERE day = :d"),
                  {"a": json.dumps(agg), "d": older_day})
    arc._figures.clear()                     # read again, as a process does after a restart
out["planned"] = plan(cap)
ar.prune(retention.Pass(SessionLocal, now=clock[0]), ar.Numbers(0, 0, 0, cap))
left = {}
for d, payload in q("SELECT day::text, payload FROM audit_archive_blocks"):
    left[d] = [str(r["id"]) for r in af.open_block(bytes(payload)).rows()]
out["left"], out["older"], out["newer"] = left, older, newer
out["older_day"], out["newer_day"] = str(older_day), str(DAY)
out["report"] = report()
''')
    assert done["stopped"] is None and done["blocks"] == 2 and done["fits"], done
    assert done["planned"] == done["honest"], done
    assert done["left"].get(done["newer_day"]) == [done["newer"]], done
    assert done["left"].get(done["older_day"], []) == ([done["older"]] if edited else []), done
    assert ("block-altered" in done["report"]["failure"]) is edited, done["report"]


@pytest.mark.parametrize("added", [False, True])
def test_a_protected_row_added_to_an_old_hour_never_makes_the_size_cap_delete_a_newer_row_on_postgres(
        throwaway, added):
    done = _script(throwaway, f"ADDED = {added}\n" + SIZE_CAP + r'''
older = add_row(at(3), details=blob())
newer = add_row(at(9), details=blob())
clock[0] = real_now - timedelta(days=9)
out["stopped"] = passes()
run_days(9)
hot, _parts = counted()
cap = hot[at(9)] + 1000
out["fits"] = cap < hot[at(3)] + hot[at(9)]
out["honest"] = plan(cap)
if ADDED:
    add_row(at(3, 30), action=protected, details=blob())
out["planned"] = plan(cap)
ar.prune(retention.Pass(SessionLocal, now=clock[0]), ar.Numbers(0, 0, 0, cap))
out["left"] = sorted(r[0] for r in q("SELECT id::text FROM audit_logs WHERE id IN (:a, :b)", a=older, b=newer))
out["older"], out["newer"] = older, newer
out["protected_bytes"] = q("SELECT (detail->>'protected_bytes')::bigint, row_bytes FROM audit_seals "
                           "WHERE kind = 'hour' AND period_start = :h", h=at(3))
out["report"] = report()
''')
    assert done["stopped"] is None and done["fits"], done
    assert done["planned"] == done["honest"], done
    assert done["left"] == sorted([done["older"], done["newer"]] if added else [done["newer"]]), done
    assert ("rows-added" in done["report"]["failure"]) is added, done["report"]
    assert done["protected_bytes"] and done["protected_bytes"][0][0] == 0 < done["protected_bytes"][0][1], done


def test_a_block_planted_with_the_days_next_part_number_leaves_that_day_and_archives_the_next_on_postgres(
        throwaway):
    done = _script(throwaway, r'''
arc.PART_ROWS = 3
for h in (2, 9):
    for i in range(3):
        add_row(at(h, i))
later = DAY + timedelta(days=1)
add_row(at(5, day=later))
out["stopped"] = passes()
ai.ROW_BUDGET = 3
archive()
out["first"] = q("SELECT day::text, part FROM audit_archive_blocks ORDER BY day, part")
q("INSERT INTO audit_archive_blocks (day, part, first_hour, last_hour, row_count, codec, format, payload, "
  "raw_bytes, aggregates, created_at) SELECT day, 2, first_hour, last_hour, row_count, codec, format, payload, "
  "raw_bytes, aggregates, created_at FROM audit_archive_blocks WHERE part = 1")
ai.ROW_BUDGET = 100000
archive()
archive()
out["blocks"] = q("SELECT day::text, part FROM audit_archive_blocks ORDER BY day, part")
out["hot"] = q("SELECT count(*) FROM audit_logs WHERE timestamp < :e", e=at(0) + timedelta(days=1))[0][0]
out["failures"] = sorted(ai.open_failures(st.head_store().load()))
out["later"] = str(later)
''')
    assert done["stopped"] is None and len(done["first"]) == 1 and done["first"][0][1] == 1, done
    assert [done["later"], 1] in done["blocks"] and done["hot"] == 3, done
    assert "block-unsealed" in done["failures"], done


ONE_STATE = r'''
def during_the_check(change):
    """audit verify (and the daily check) with ``change`` committed by another connection between the walk over
    the seals and the reading of the blocks."""
    real = arc.check_block_set
    done = []

    def first_the_change(db, view, report_):
        if not done:
            done.append(1)
            change()
        return real(db, view, report_)

    arc.check_block_set = first_the_change
    try:
        return report()
    finally:
        arc.check_block_set = real


def unarchive_both_phases(day):
    seen = arc.unarchive(engine, st, day, day, read=True)
    arc.unarchive(engine, st, day, day, expect=seen["state"])
'''


def test_verify_and_the_daily_check_read_one_state_while_the_archive_and_unarchive_commit_on_postgres(throwaway):
    """audit verify while the archive job commits a day, and while the host's unarchive commits one, and the daily
    check (its rolling part included) while an unarchive commits: each reads the state its walk read, so nothing
    shows and the daily check records nothing in the head record."""
    done = _script(throwaway, ONE_STATE + r'''
other = DAY - timedelta(days=1)
for h in (3, 4):
    add_row(at(h))
    add_row(at(h, day=other))
clock[0] = real_now - timedelta(days=9)
out["stopped"] = passes()
run_days(9)
out["archived_during"] = during_the_check(archive)
out["blocks"] = q("SELECT count(*) FROM audit_archive_blocks")[0][0]
out["unarchived_during"] = during_the_check(lambda: unarchive_both_phases(other))
out["hot"] = q("SELECT count(*) FROM audit_logs WHERE timestamp >= :s AND timestamp < :e", s=at(0, day=other),
               e=at(0))[0][0]
out["left"] = q("SELECT count(*) FROM audit_archive_blocks")[0][0]
real = arc.check_block_set
calls = []


def unarchive_first(db, view, report_):
    if not calls:
        calls.append(1)
        unarchive_both_phases(DAY)
    return real(db, view, report_)


arc.check_block_set = unarchive_first
v.ROLLING_DAYS = 1                           # the rolling part reads every hour and part in this check
try:
    daily = v.daily_check(SessionLocal, st, now=clock[0], force=True)
finally:
    arc.check_block_set = real
out["daily"] = sorted(f.kind for f in daily.findings if f.severity == v.FAILURE)
out["daily_rows"] = daily.rows_checked
out["recorded"] = sorted(ai.open_failures(st.head_store().load()))
out["after"] = report()
out["blocks_after"] = q("SELECT count(*) FROM audit_archive_blocks")[0][0]
''')
    assert done["stopped"] is None, done
    assert done["archived_during"]["failure"] == [] and done["blocks"] == 2, done
    assert done["unarchived_during"]["failure"] == [] and done["hot"] == 2 and done["left"] == 1, done
    assert done["daily"] == [] and done["recorded"] == [] and done["daily_rows"] >= 2, done
    assert done["after"]["failure"] == [] and done["blocks_after"] == 0, done


@pytest.mark.parametrize("deleted", [False, True])
def test_a_row_deleted_from_an_hour_the_chain_keeps_whole_never_moves_the_size_caps_cutoff_newer_on_postgres(
        throwaway, deleted):
    """The protected rows alone exceed the cap. An older hour holds an unprotected row, which the cap takes; a newer
    hour held one protected row when sealed and has since had a late unprotected row sealed into it, which counts
    only once a delay of sealing has passed; a newer hour still holds one protected row. Deleted in the database,
    that row would make its hour look partly unprotected and move the cutoff to it: the chain alone says which hours
    the cap keeps whole, so the plan is the honest one and the late row stays."""
    done = _script(throwaway, f"DELETED = {deleted}\n" + SIZE_CAP + r'''
os.environ["AUDIT_LOG_MAX_MB"] = "1"
from app.core.config import settings as _settings
_settings.audit_log_max_mb = 1
from app.core import audit_chain_host as host
older_day = DAY - timedelta(days=5)
older = add_row(at(1, day=older_day), details=blob())
add_row(at(9), action=protected, details=blob())
newest = add_row(at(15), action=protected, details=blob())
clock[0] = real_now - timedelta(days=10)
out["stopped"] = passes()
run_days(9)
late = add_row(at(9, 30), details=blob())
seen = host.seal_late_rows(engine, st, at(9), read=True)
host.seal_late_rows(engine, st, at(9), expect=seen["state"])
run_days(1)
out["honest"] = plan(1000)
if DELETED:
    q("DELETE FROM audit_logs WHERE id = :i", i=newest)
out["planned"] = plan(1000)
ar.prune(retention.Pass(SessionLocal, now=clock[0]), ar.Numbers(0, 0, 0, 1000))
out["left"] = sorted(r[0] for r in q("SELECT id::text FROM audit_logs WHERE id IN (:a, :b)", a=older, b=late))
out["older"], out["late"], out["cut"] = older, late, str(at(2, day=older_day))
out["report"] = report()
''')
    assert done["stopped"] is None and done["honest"][0] == done["cut"], done
    assert done["planned"] == done["honest"], done
    assert done["left"] == [done["late"]], done
    assert ("rows-missing" in done["report"]["failure"]) is deleted, done["report"]


SLOW_HOST = r'''
import subprocess
import time


def host_command(*args, slow=0):
    """The host's command in a process of its own, as dockvault.py runs it, that waits ``slow`` seconds between its
    commit and its head record write (a slow disk, a busy host)."""
    code = ("import sys, time\n"
            "from app.core import audit_head_record as hr\n"
            "real = hr.HeadStore.write\n"
            "def write(self, change, now):\n"
            f"    time.sleep({slow})\n"
            "    return real(self, change, now)\n"
            "hr.HeadStore.write = write\n"
            "from app.core.audit_chain_verify import main\n"
            "sys.exit(main())\n")
    return subprocess.Popen([sys.executable, "-c", code, *args], env=dict(os.environ), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)


def answer(proc):
    stdout, stderr = proc.communicate(timeout=600)
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    return proc.returncode, (json.loads(lines[-1]) if lines and lines[-1].startswith("{") else None), stderr[-1500:]


def unarchive_slowly(day, slow):
    """The host's unarchive of ``day``: the read, then the write, which commits and waits ``slow`` seconds before it
    writes the head record. Returns its process once its seal is committed."""
    d = day.isoformat()
    code, seen, err = answer(host_command("unarchive", "--from", d, "--to", d, "--read"))
    assert code == 0 and seen and seen.get("ok"), (code, seen, err)
    before = q("SELECT max(seq) FROM audit_seals")[0][0]
    proc = host_command("unarchive", "--from", d, "--to", d, "--expect", seen["state"], slow=slow)
    deadline = time.time() + 120
    while q("SELECT max(seq) FROM audit_seals")[0][0] == before and time.time() < deadline:
        time.sleep(0.1)
    assert proc.poll() is None, answer(proc)
    return proc
'''


def test_the_daily_check_and_audit_verify_read_the_head_record_that_goes_with_their_snapshot_on_postgres(throwaway):
    """A host command runs in a process of its own and writes the head record file after its commit. The daily
    check, with this process's older copy of the record, and ``audit verify`` in a process of its own, each run while
    such a command has committed and not yet written its record: each takes its snapshot and reads the record under
    the chain lock, so it waits for the command and reports nothing; the daily check records nothing."""
    done = _script(throwaway, SLOW_HOST + r'''
other = DAY - timedelta(days=1)
for h in (3, 4):
    add_row(at(h))
    add_row(at(h, day=other))
clock[0] = real_now - timedelta(days=9)
out["stopped"] = passes()
run_days(9)
clock[0] = datetime.now(timezone.utc).replace(tzinfo=None)
archive()
passes()
out["blocks"] = q("SELECT count(*) FROM audit_archive_blocks")[0][0]
out["clean_before"] = report()["failure"]
proc = unarchive_slowly(other, 6)
started = time.time()
daily = v.daily_check(SessionLocal, st, now=clock[0], force=True)
out["daily_waited"] = time.time() - started
out["daily"] = sorted(f.kind for f in daily.findings if f.severity == v.FAILURE)
out["daily_after_record"] = "after-record" in daily.kinds(v.WARNING)
out["recorded"] = sorted(ai.open_failures(st.head_store().load()))
out["first_unarchive"] = answer(proc)[:2]
proc = unarchive_slowly(DAY, 6)
started = time.time()
code, verified, err = answer(host_command("verify", "--json"))
out["verify_waited"] = time.time() - started
out["verify"] = [code, sorted({f["kind"] for f in (verified or {}).get("findings", [])
                               if f["severity"] in ("failure", "warning")}), err[-500:]]
out["second_unarchive"] = answer(proc)[:2]
out["blocks_after"] = q("SELECT count(*) FROM audit_archive_blocks")[0][0]
out["after"] = report()
''')
    assert done["stopped"] is None and done["blocks"] == 2 and done["clean_before"] == [], done
    assert done["first_unarchive"][0] == 0 and done["second_unarchive"][0] == 0, done
    assert done["daily"] == [] and not done["daily_after_record"] and done["recorded"] == [], done
    assert done["daily_waited"] >= 3, done
    assert done["verify"][0] == 0 and done["verify"][1] == [], done
    assert done["verify_waited"] >= 3, done
    assert done["blocks_after"] == 0 and done["after"]["failure"] == [], done
