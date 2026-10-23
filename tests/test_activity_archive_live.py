"""Reading archived days on a running stack's Postgres (app/services/activity_archive.py): each case runs on a
throwaway database of its own with the web image's code in the web container (tests/_throwaway_db.py), a corpus of
rows over archived and kept days, sealed and archived by the server's own passes:

- random filter combinations (every filter, address blocks and shortened addresses, text in JSON details, a
  credential by name) return the same rows, in the same order, from the rows before archiving and from rows and
  archive after it; the search's temporary table exists only while it runs;
- the summary band across the boundary (through summarize, under filters the archive's summaries answer, in three
  time zones) counts what it counted from the rows before archiving;
- the routes: the Events list says what it read of the archive, pages across the boundary and refuses a range
  beyond its bound; the export holds the archived rows, records how many archived days it read, and says when it
  left them out; the readers of rows only send the archive's span in their headers.

tests/test_activity_archive.py covers the rules offline.
"""
import pytest

from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

KEY = "k" * 64

SCRIPT = PREAMBLE + r'''
import asyncio, random
from sqlalchemy import func
from app.core import audit_archive as arc
from app.core.models import AuditLog, User, RoleEnum, TemporaryCredential
from app.services import activity_archive as archive, activity_events as ev, activity_summary as summary
out = {}
clock = [now]
st = ai.ChainState(clock=lambda: clock[0])
ai.set_state(st)
ARCHIVED = [(now - timedelta(days=d)).date() for d in (100, 99, 98, 97)]
HOT = [(now - timedelta(days=d)).date() for d in (3, 2)]
V1 = "5f0c8a1e-2b3d-4c6f-9a7b-1d2e3f4a5b6c"
TC1 = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"


def at(day, hour, minute=0):
    return datetime(day.year, day.month, day.day, hour, minute)


def q(sql, **params):
    with engine.begin() as c:
        res = c.execute(text(sql), params)
        return [list(r) for r in res] if res.returns_rows else []


def passes():
    r = None
    for _ in range(400):
        r = ai.seal_pass(SessionLocal, st=st, now=clock[0])
        if r.stopped or not r.sealed:
            break
    return r.stopped if r else None


ACTIONS = ("file_uploaded", "file_upload", "login_success", "login_failure", "vault_created", "legacy_thing")
STATUSES = ("success", "failure", "error", "authorized", "refused")
CHANNELS = ("web", "sftp", None, "public_link")


def add_user(name, role):
    db = SessionLocal()
    try:
        u = User(id=uuid.uuid4(), username=name, password_hash="x", role=role)
        db.add(u)
        db.commit()
        return u.id
    finally:
        db.close()


def corpus():
    rnd = random.Random(20261010)
    uid = str(add_user("dana", RoleEnum.USER))
    for day in ARCHIVED + HOT:
        for hour in (1, 5, 9, 13, 17, 22):
            for k in range(3):
                user_id, username = None, rnd.choice(("alice", "bob", "carol", None))
                if rnd.random() < 0.25:
                    user_id, username = uid, "dana"
                ip, recorded = rnd.choice((("203.0.113.9", None), ("198.51.100.7", None), (None, None),
                                           (None, '{"ip": "192.0.2.0/24"}')))
                tc = rnd.choice((None, None, TC1))
                q("INSERT INTO audit_logs (id, action, status, channel, timestamp, username, user_id, ip_address, "
                  "recorded, details, error_message, temp_credential_id, temp_credential_name, user_agent, "
                  "endpoint, seal_nonce, privacy_version) VALUES (:id, :a, :s, :c, :t, :u, :uid, :ip, "
                  "CAST(:r AS jsonb), CAST(:d AS json), :e, :tc, :tcn, :ua, '/api/files/{id}', :n, 3)",
                  id=str(uuid.uuid4()), a=rnd.choice(ACTIONS), s=rnd.choice(STATUSES), c=rnd.choice(CHANNELS),
                  t=at(day, hour, 7 * k + 1), u=username, uid=user_id, ip=ip, r=recorded,
                  d=rnd.choice(('{"n": 1}', '{"vault_id": "%s"}' % V1, '{"file": "upload café"}')),
                  e=rnd.choice((None, "error: refused upload")), tc=tc, tcn="contractor" if tc else None,
                  ua=rnd.choice(("Mozilla/5.0 test", "curl/8.5")), n=os.urandom(16))
    return uid


def archive_all():
    for _ in range(4):
        arc.archive_job(retention.Pass(SessionLocal, now=clock[0]))
    return sorted(r[0] for r in q("SELECT DISTINCT day::text FROM audit_archive_blocks"))


POOL = dict(
    categories=([], ["files"], ["sign_in"], ["legacy"], ["files", "legacy"], ["no-such-category"]),
    channels=([], ["web"], ["unknown"], ["sftp", "unknown"]),
    statuses=([], ["failed"], ["success"], ["authorized"]),
    actions=([], ["login_failure"], ["file_upload", "vault_created"], ["legacy_thing"]),
    username=(None, "ali", "DANA"),
    user_exact=(False, True),
    no_account=(False, True),
    ip=(None, "203.0.113.9", "198.51.100.0/24", "203.0.0.0/8", "192.0.2.77", "192.0.2.0/22", "not-an-ip"),
    text=(None, "upload", "bob", "café", "curl"),
    vault_id=(None, V1),
    temp_credential_id=(None, TC1),
    temp_credential=(None, "contract"),
)


def filters(rnd):
    f = {k: rnd.choice(v) for k, v in POOL.items()}
    for k in list(f):
        if rnd.random() < 0.6:
            f[k] = POOL[k][0]
    return f


def ids_of(db, entity, f):
    return [str(r[0]) for r in ev.build_events_query(db.query(entity.id), entity, **f)
            .order_by(entity.timestamp.desc(), entity.id.desc()).all()]
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def _script(name, body):
    return run_in(name, SCRIPT + body + "\nprint(json.dumps(out, default=str))\n",
                  env={"AUDIT_CHAIN_KEY": KEY, "AUDIT_ARCHIVE_START_AFTER_DAYS": "0"})


def test_random_filters_and_the_band_read_the_same_from_rows_and_from_the_archive_on_postgres(throwaway):
    got = _script(throwaway, r'''
corpus()
out["stopped"] = passes()
rnd = random.Random(11)
ranges = [(at(ARCHIVED[0], 0), None), (at(ARCHIVED[1], 6), at(HOT[0], 12)), (at(ARCHIVED[2], 0), at(ARCHIVED[3], 9))]
cases = []
db = SessionLocal()
for i in range(150):
    f = filters(rnd)
    f["start"], f["end"] = ranges[i % len(ranges)]
    cases.append((f, ids_of(db, AuditLog, f)))
# The band before archiving: every hour is rows.
lo = at(ARCHIVED[0], 0) - timedelta(days=2)
band_sets = [{}, {"categories": ["files", "legacy"]}, {"statuses": ["failed"], "channels": ["web", "unknown"]},
             {"actions": ["login_failure", "login_success"]}, {"categories": ["sign_in"], "start": at(ARCHIVED[1], 0),
                                                               "end": at(HOT[0], 0)}]
KEEP = ("buckets", "total", "failed", "categories", "sign_ins", "from", "to")
def band(s, f, offset):
    win = summary.custom_window(lo, now, tz_offset_minutes=offset)
    full = dict(categories=[], channels=[], statuses=[], actions=[], username=None, user_exact=False,
                no_account=False, ip=None, text=None, temp_credential_id=None, temp_credential=None, vault_id=None,
                start=None, end=None)
    full.update(f)
    b = summary.summarize(s, AuditLog, win, full, since=lo, now=now)
    return {k: b[k] for k in KEEP}, b.get("archive")
before = {(i, o): band(db, f, o)[0] for i, f in enumerate(band_sets) for o in (0, 120, -330)}
out["rows_in_window"] = db.query(func.count()).select_from(AuditLog).filter(AuditLog.timestamp >= lo).scalar()
db.close()
out["days"] = archive_all()
out["hot_left"] = q("SELECT count(*) FROM audit_logs WHERE timestamp < :t", t=at(ARCHIVED[-1], 0) + timedelta(days=1))[0][0]
out["nonempty"] = sum(1 for _f, ids in cases if ids)
out["mismatch"] = []
out["counts"] = []
out["during"] = []
for start, end in ranges:
    db = SessionLocal()
    with archive.source(db, start, end, st) as src:
        out["unreadable"] = src.note["unreadable"]
        out["during"].append(src.db.execute(text("SELECT to_regclass(:n) IS NOT NULL"),
                                            {"n": archive.SEARCH_TABLE}).scalar())
        for f, want in cases:
            if (f["start"], f["end"]) != (start, end):
                continue
            got = ids_of(src.db, src.entity, f)
            n = ev.build_events_query(src.db.query(src.entity), src.entity, **f).order_by(None).count()
            if got != want or n != len(want):
                out["mismatch"].append([str(f), len(want), len(got), n])
            out["counts"].append(len(want))
    db.close()
# Every connection of the pool, as the next request would get it: none holds the search's table.
held = [engine.connect() for _ in range(5)]
out["after"] = sum(1 for c in held if c.execute(text("SELECT to_regclass(:n) IS NOT NULL"),
                                                {"n": archive.SEARCH_TABLE}).scalar())
for c in held:
    c.close()
db = SessionLocal()
out["band_mismatch"] = []
notes = []
for i, f in enumerate(band_sets):
    for o in (0, 120, -330):
        b, note = band(db, f, o)
        notes.append(note)
        if b != before[(i, o)]:
            out["band_mismatch"].append([i, o, b["total"], before[(i, o)]["total"],
                                         [x["total"] for x in b["buckets"]][:6],
                                         [x["total"] for x in before[(i, o)]["buckets"]][:6]])
out["note"] = notes[0]
out["band_total"] = before[(0, 0)]["total"]
db.close()
''')
    assert got["stopped"] is None, got
    assert len(got["days"]) == 4 and got["hot_left"] == 0, got["days"]
    assert got["nonempty"] > 50 and len(got["counts"]) == 150, got
    assert got["mismatch"] == [], got["mismatch"][:5]
    assert got["unreadable"] == []
    assert got["during"] == [True, True, True] and got["after"] == 0
    # Within the 30-minute zone the hours that straddle a bucket's start count in the bucket before it: all the
    # filter sets' totals still match, and each bucket in the whole-hour zones.
    half = [m for m in got["band_mismatch"] if m[1] == -330]
    whole = [m for m in got["band_mismatch"] if m[1] != -330]
    assert whole == [], whole
    assert all(m[2] == m[3] for m in half), half
    assert got["band_total"] == got["rows_in_window"] >= 6 * 6 * 3
    note = got["note"]
    assert note["counted"] == ["events", "categories", "sign_ins"] and note["rows_only"] == ["people", "addresses"]
    assert note["oldest_day"] == got["days"][0] and note["unreadable"] == []


def test_the_routes_read_and_say_what_they_read_of_the_archive_on_postgres(throwaway):
    got = _script(throwaway, r'''
from fastapi import HTTPException, Response
from app.api import api_server as api
corpus()
out["stopped"] = passes()
admin_id = str(add_user("boss", RoleEnum.ADMIN))
start = at(ARCHIVED[1], 0)
db = SessionLocal()
expected = ids_of(db, AuditLog, {"start": start})
out["rows_from_first"] = db.query(func.count()).select_from(AuditLog).filter(
    AuditLog.timestamp >= at(ARCHIVED[0], 0)).scalar()
expected_web = ids_of(db, AuditLog, {"start": start, "channels": ["web"]})
db.close()
out["days"] = archive_all()


def call(fn, **kw):
    db = SessionLocal()
    try:
        admin = db.get(User, uuid.UUID(admin_id))
        got = fn(current_user=admin, db=db, **kw)
        return asyncio.run(got) if asyncio.iscoroutine(got) else got
    finally:
        db.close()


EVENTS = dict(category=[], channel=[], status=[], action=[], user=None, user_match="contains", no_account=False,
              ip=None, q=None, temp_credential_id=None, temp_credential=None, vault_id=None, from_date=None,
              to_date=None, cursor=None, page=None, after=None, overlap=0, ids=[], count_only=False, limit=50,
              request=None)
first = call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), page=1, limit=25))
out["note"] = first["archive"]
out["expected"] = len(expected)
out["total"] = first["total"]
walked = [e["id"] for e in first["events"]]
for page in range(2, first["pages"] + 1):
    walked += [e["id"] for e in call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), page=page,
                                                                 limit=25))["events"]]
out["paged_ok"] = walked == expected
allmode, cursor = [], None
while True:
    r = call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), cursor=cursor, limit=40))
    allmode += [e["id"] for e in r["events"]]
    cursor = r["next_cursor"]
    if not cursor:
        break
out["all_ok"] = allmode == expected
web = call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), channel=["web"], limit=200))
out["web_ok"] = [e["id"] for e in web["events"]] == expected_web
one = call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), ids=[expected[-1]]))
out["ids_ok"] = [e["id"] for e in one["events"]] == [expected[-1]]
# The rows after a point: from an archived row, the search starts at that point (one archived day here); from a
# row still kept, it reads rows only and says nothing of the archive.
everything = call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), limit=200))["events"]
anchor = next(i for i, e in enumerate(everything) if e["timestamp"].startswith(ARCHIVED[3].isoformat()))
newer = call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), after=everything[anchor]["cursor"],
                                          limit=200))
out["after_ok"] = [e["id"] for e in newer["events"]] == list(reversed(expected[:anchor]))
out["after_note"] = newer.get("archive")
hot_row = next(e for e in everything if e["timestamp"].startswith(HOT[0].isoformat()))
out["after_hot_note"] = call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), after=hot_row["cursor"],
                                                         limit=5)).get("archive", "absent")
rows_only = call(api.activity_events, **dict(EVENTS, limit=5))
out["rows_only_note"] = rows_only.get("archive")
hot = call(api.activity_events, **dict(EVENTS, from_date=at(HOT[0], 0).isoformat(), limit=5))
out["hot_note"] = hot.get("archive", "absent")
archive.MAX_DAYS = 1
try:
    call(api.activity_events, **dict(EVENTS, from_date=start.isoformat()))
    out["refused"] = None
except HTTPException as exc:
    out["refused"] = [exc.status_code, exc.detail]
archive.MAX_DAYS = 31

summary_route = call(api.activity_summary, range_="custom", range_from=at(ARCHIVED[0], 0).isoformat(), range_to=None,
                     tz=None, tz_offset=0, category=[], channel=[], status=[], action=[], user=None,
                     user_match="contains", no_account=False, ip=None, q=None, temp_credential_id=None,
                     temp_credential=None, vault_id=None, from_date=None, to_date=None)
out["band_note"] = summary_route.get("archive")
out["band_total"] = summary_route["total"]

EXPORT = dict(category=[], channel=[], status=[], action=[], user=None, user_match="contains", no_account=False,
              ip=None, q=None, temp_credential_id=None, temp_credential=None, vault_id=None, to_date=None,
              request=None)


async def body(resp):
    chunks = []
    async for c in resp.body_iterator:
        chunks.append(c if isinstance(c, str) else c.decode())
    if resp.background is not None:
        await resp.background()
    return "".join(chunks)


resp = call(api.activity_export, **dict(EXPORT, format="ndjson", from_date=start.isoformat()))
lines = [json.loads(l) for l in asyncio.run(body(resp)).splitlines()]
out["export_ids_ok"] = [l["id"] for l in lines if "id" in l] == expected
out["export_total"] = resp.headers["X-Export-Total"]
out["export_row"] = q("SELECT details::text FROM audit_logs WHERE action = 'audit_exported' ORDER BY timestamp DESC "
                      "LIMIT 1")[0][0]
resp = call(api.activity_export, **dict(EXPORT, format="csv", from_date=None))
text_ = asyncio.run(body(resp))
out["export_left_out"] = [l for l in text_.splitlines() if "archived and not in this export" in l]
held = [engine.connect() for _ in range(5)]
out["temp_after"] = sum(1 for c in held if c.execute(text("SELECT to_regclass(:n) IS NOT NULL"),
                                                     {"n": archive.SEARCH_TABLE}).scalar())
for c in held:
    c.close()
r = Response()
call(api.search_audit_log, response=r, user_id=None, action=None, from_date=None, to_date=None, limit=5)
out["log_headers"] = [r.headers.get(h) for h in archive.ARCHIVE_HEADERS]
r = Response()
call(api.search_audit_log, response=r, user_id=None, action=None, from_date=at(HOT[0], 0).isoformat(), to_date=None,
     limit=5)
out["log_headers_hot"] = [r.headers.get(h) for h in archive.ARCHIVE_HEADERS]
r = Response()
call(api.recent_audit_events, response=r, limit=3)
out["feed_headers"] = [r.headers.get(h) for h in archive.ARCHIVE_HEADERS]
''')
    assert got["stopped"] is None, got
    assert len(got["days"]) == 4
    note = got["note"]
    assert note["searched"] is True and note["searched_days"] == 3 and note["unreadable"] == [], note
    assert got["total"] == got["expected"] == 3 * 18 + 2 * 18
    assert got["paged_ok"] and got["all_ok"] and got["web_ok"] and got["ids_ok"], got
    assert got["after_ok"] and got["after_note"]["searched_days"] == 1, got["after_note"]
    assert got["after_hot_note"] == "absent"
    assert got["rows_only_note"]["searched"] is False and got["rows_only_note"]["newest_day"] == got["days"][-1]
    assert got["hot_note"] == "absent"
    assert got["refused"][0] == 400 and "at most 1 at a time" in got["refused"][1], got["refused"]
    assert got["export_ids_ok"] and int(got["export_total"]) == got["total"]
    assert '"archived_days": 3' in got["export_row"], got["export_row"]
    assert len(got["export_left_out"]) == 1 and got["days"][-1] in got["export_left_out"][0]
    assert got["temp_after"] == 0
    assert got["log_headers"] == [got["days"][0], got["days"][-1]]
    assert got["log_headers_hot"] == [None, None]
    assert got["feed_headers"] == [got["days"][0], got["days"][-1]]
    assert got["band_note"]["counted"] == ["events", "categories", "sign_ins"]
    assert got["band_total"] == got["rows_from_first"] >= 6 * 6 * 3, got


def test_rows_read_by_id_stay_in_the_rows_and_a_stalled_export_frees_its_search_on_postgres(throwaway):
    """The live list reads its new rows by id with the list's own range, which reaches the archive here: the read
    stays in the rows and searches no block (also when the row does not match the filters, and for a count); an id
    that is no row is searched for, and an open event's re-check narrowed to its own instant reads one archived day.
    A search's statements and its idle time are bounded for its own transaction. An export whose reader stops
    reading loses its search once the idle time has run: Postgres ends the session, the export stops with an
    error, nothing waits idle in a transaction any more, and the next export runs."""
    got = _script(throwaway, r'''
import time
from app.api import api_server as api
corpus()
out["stopped"] = passes()
admin_id = str(add_user("boss", RoleEnum.ADMIN))
start = at(ARCHIVED[0], 0)
db = SessionLocal()
archived_id = ids_of(db, AuditLog, {"start": at(ARCHIVED[1], 0), "end": at(ARCHIVED[2], 0)})[0]
db.close()
out["days"] = archive_all()
new = str(uuid.uuid4())
q("INSERT INTO audit_logs (id, action, status, channel, timestamp, username, seal_nonce) VALUES (:i, 'file_uploaded', "
  "'success', 'web', :t, 'eve', :n)", i=new, t=clock[0] - timedelta(seconds=5), n=os.urandom(16))


def call(fn, **kw):
    db = SessionLocal()
    try:
        admin = db.get(User, uuid.UUID(admin_id))
        got = fn(current_user=admin, db=db, **kw)
        return asyncio.run(got) if asyncio.iscoroutine(got) else got
    finally:
        db.close()


EVENTS = dict(category=[], channel=[], status=[], action=[], user=None, user_match="contains", no_account=False,
              ip=None, q=None, temp_credential_id=None, temp_credential=None, vault_id=None, from_date=None,
              to_date=None, cursor=None, page=None, after=None, overlap=0, ids=[], count_only=False, limit=50,
              request=None)
searched = []
real_search = archive.search


def counted(engine_, p, st_=None):
    searched.append(len(p.days))
    return real_search(engine_, p, st_)


archive.search = counted
r = call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), ids=[new]))
out["new"] = [[e["id"] for e in r["events"]] == [new], (r.get("archive") or {}).get("searched"), list(searched)]
r = call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), ids=[new], count_only=True))
out["new_count"] = [r["count"], list(searched)]
r = call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), ids=[new], channel=["sftp"]))
out["new_filtered_out"] = [len(r["events"]), list(searched)]
r = call(api.activity_events, **dict(EVENTS, from_date=start.isoformat(), ids=[archived_id]))
out["archived"] = [[e["id"] for e in r["events"]] == [archived_id], r["archive"]["searched"], list(searched)]
ts = r["events"][0]["timestamp"]
moment = datetime.fromisoformat(ts).replace(tzinfo=None)
del searched[:]
r = call(api.activity_events, **dict(EVENTS, from_date=ts, to_date=(moment + timedelta(milliseconds=1)).isoformat(),
                                     ids=[archived_id]))
out["recheck"] = [[e["id"] for e in r["events"]] == [archived_id], list(searched)]
archive.search = real_search

p = archive.plan(start, None, st)
with archive.search(engine, p, st) as s:
    out["inside"] = [s.db.execute(text("SHOW statement_timeout")).scalar(),
                     s.db.execute(text("SHOW idle_in_transaction_session_timeout")).scalar()]
with engine.connect() as c:
    out["outside"] = [c.execute(text("SHOW statement_timeout")).scalar(),
                      c.execute(text("SHOW idle_in_transaction_session_timeout")).scalar()]

EXPORT = dict(category=[], channel=[], status=[], action=[], user=None, user_match="contains", no_account=False,
              ip=None, q=None, temp_credential_id=None, temp_credential=None, vault_id=None, to_date=None,
              request=None)


def idle_in_transaction():
    return q("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
             "AND state = 'idle in transaction'")[0][0]


async def stalled(resp, pause):
    it = resp.body_iterator
    got = [await it.__anext__()]
    out["idle_while_stalled"] = idle_in_transaction()
    time.sleep(pause)
    error = None
    try:
        async for chunk in it:
            got.append(chunk)
    except Exception as exc:  # noqa: BLE001
        error = type(exc).__name__
    if resp.background is not None:
        await resp.background()
    return len(got), error


archive.IDLE_TIMEOUT_MS = 1500
ev.EXPORT_BATCH = 10
ev.export_page.__defaults__ = (10,)
resp = call(api.activity_export, **dict(EXPORT, format="ndjson", from_date=start.isoformat()))
out["stalled"] = list(asyncio.run(stalled(resp, 4)))
out["idle_after"] = idle_in_transaction()


async def body(resp):
    chunks = []
    async for c in resp.body_iterator:
        chunks.append(c if isinstance(c, str) else c.decode())
    if resp.background is not None:
        await resp.background()
    return "".join(chunks)


resp = call(api.activity_export, **dict(EXPORT, format="ndjson", from_date=start.isoformat()))
text_ = asyncio.run(body(resp))
out["next_export"] = [sum(1 for line in text_.splitlines() if '"id"' in line), int(resp.headers["X-Export-Total"])]
''')
    assert got["stopped"] is None, got
    assert len(got["days"]) == 4
    assert got["new"] == [True, False, []], got["new"]
    assert got["new_count"] == [1, []], got["new_count"]
    assert got["new_filtered_out"] == [0, []], got["new_filtered_out"]
    assert got["archived"] == [True, True, [4]], got["archived"]
    assert got["recheck"] == [True, [1]], got["recheck"]
    assert got["inside"] == ["1min", "2min"], got
    assert got["outside"][0] == "0" and got["outside"][1] != "2min", got           # for the search's transaction only
    assert got["idle_while_stalled"] >= 1, got
    assert got["stalled"][1] is not None, got["stalled"]
    assert got["idle_after"] == 0, got
    assert got["next_export"][0] == got["next_export"][1] > 72, got


def test_archived_rows_read_back_identical_in_every_column_on_postgres(throwaway):
    """A search loads the archived rows with COPY: every column of every row reads back as it was stored before it
    was archived, the JSON column's stored text included, whatever the text holds (backslashes, tabs, line ends, a
    literal \\N, quotes, characters outside ASCII), and NULLs stay NULL; a row of an account deleted since loses its
    link."""
    got = _script(throwaway, r'''
from app.core.models import AuditLog
NAMES = [c.name for c in AuditLog.__table__.columns]
SPECIALS = ["back\\slash", "tab\there", "new\nline", "carriage\rreturn", "\\N", "\\x41", "quote\"s 'and' `ticks`",
            "café ☃ \U0001F600", "", "comma, semi; pipe|", "tab\tand \\t written", " spaced "]
uid = add_user("gone", RoleEnum.USER)
kept = add_user("kept", RoleEnum.USER)
db = SessionLocal()
ids = []
for i, sv in enumerate(SPECIALS):
    row = AuditLog(id=uuid.uuid4(), user_id=(uid if i % 3 == 0 else kept if i % 3 == 1 else None), username=sv,
                   action="file_uploaded", temp_credential_id=uuid.uuid4() if i % 2 else None,
                   temp_credential_name=sv or None, resource_type="file", resource_id=sv,
                   timestamp=at(ARCHIVED[1], 3, i) + timedelta(microseconds=123456 + i),
                   ip_address=("2001:db8::%x" % i) if i % 2 else "203.0.113.%d" % i, user_agent=sv, method="PUT",
                   endpoint="/api/files/{id}", channel=(None if i % 4 == 0 else "sftp"), status="success",
                   details=({"s": sv, "nested": {"a": [1, 2.5, None, True], "big": 2 ** 63, "neg": -0.0}}
                            if i % 5 else None),
                   error_message=sv if i % 2 == 0 else None, seal_nonce=os.urandom(16) if i % 3 else None,
                   privacy_version=i if i % 4 else None, recorded=({"names": [sv], "n": i} if i % 2 else None),
                   ip_via=("trusted-proxy" if i % 2 else None), case_id=uuid.uuid4() if i % 3 == 2 else None)
    db.add(row)
    ids.append(row.id)
db.commit()


def norm(v):
    if isinstance(v, memoryview):
        v = bytes(v)
    if isinstance(v, bytes):
        return "b:" + v.hex()
    return v


def columns(session, entity):
    out_ = {}
    for r in session.query(entity).filter(entity.id.in_(ids)).all():
        out_[str(r.id)] = {n: norm(getattr(r, n)) for n in NAMES}
    return out_


def stored_text(session, table):
    return {str(i): (d, r) for i, d, r in session.execute(text(
        f"SELECT id, details::text, recorded::text FROM {table} WHERE id = ANY(:ids)"), {"ids": ids}).all()}


before = columns(db, AuditLog)
before_text = stored_text(db, "audit_logs")
db.close()
out["stopped"] = passes()
out["days"] = archive_all()
db = SessionLocal()
db.query(User).filter(User.id == uid).delete()
db.commit()
out["still_rows"] = db.query(func.count()).select_from(AuditLog).filter(AuditLog.id.in_(ids)).scalar()
db.close()
p = archive.plan(at(ARCHIVED[0], 0), None, st)
with archive.search(engine, p, st) as s:
    after = columns(s.db, s.entity)
    after_text = stored_text(s.db, archive.SEARCH_TABLE)
    out["unreadable"] = s.unreadable
for rid, row in before.items():
    if row["user_id"] is not None and str(row["user_id"]) == str(uid):
        row["user_id"] = None
out["rows"] = [len(before), len(after)]
out["differ"] = {rid: {n: [row[n], after.get(rid, {}).get(n)] for n in NAMES if row[n] != after.get(rid, {}).get(n)}
                 for rid, row in before.items() if row != after.get(rid)}
out["text_differ"] = {rid: [t, after_text.get(rid)] for rid, t in before_text.items() if after_text.get(rid) != t}
out["specials_seen"] = sorted(r["username"] for r in after.values()) == sorted(SPECIALS)
''')
    assert got["stopped"] is None and len(got["days"]) == 1, got
    assert got["still_rows"] == 0 and got["unreadable"] == {}, got
    assert got["rows"] == [12, 12], got
    assert got["differ"] == {} and got["text_differ"] == {}, got
    assert got["specials_seen"], got
