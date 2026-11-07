"""A web process that has just started, on a running stack's Postgres: it reads an archived day, and exports it, at
once (app/core/audit_integrity.py read_at_start, app/services/activity_archive.py "Before the view is read").

A throwaway database (tests/_throwaway_db.py) gets rows on a day a hundred days back and on a recent day, sealed and
the old day archived by the server's own passes. Then the web app itself is started in the web container against
that database, on a port of its own, and as soon as it answers:

- the Events list for the archived day holds its rows and says it read the archive, and the export holds them too,
  long before the pruner's first pass (a minute in), which until now was the first time the process read the chain;
- with a seal of the chain changed in the database, a new process cannot read the chain: the archived day is
  refused (503, with why and when to ask again), so is its export, the integrity page says the archive is not known,
  and a recent day is answered from rows as ever.

tests/test_activity_archive_unread.py covers the rules offline.
"""
import json
import secrets

import pytest

from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

KEY = "k" * 64

SCRIPT = PREAMBLE + r'''
import subprocess, time, urllib.error, urllib.request
from app.core import audit_archive as arc
out = {}
DAY = (now - timedelta(days=100)).date()
HOT = (now - timedelta(days=2)).date()


def at(day, hour, minute=0):
    return datetime(day.year, day.month, day.day, hour, minute)


def q(sql, **params):
    with engine.begin() as c:
        res = c.execute(text(sql), params)
        return [list(r) for r in res] if res.returns_rows else []


def http(method, base, path, token=None, body=None):
    """(status, headers (looked up in any case), body text) of a request to the process under test."""
    req = urllib.request.Request(base + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Host": "localhost", "Content-Type": "application/json",
                                          **({"Authorization": "Bearer " + token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.headers, resp.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        return err.code, err.headers, err.read().decode("utf-8")


def serve(port, password):
    """Start the web app on ``port`` against this database, read and export the archived day as soon as it answers,
    stop it. Returns what it answered and when (seconds since the process was started)."""
    log = open(f"/tmp/{name}-{port}.log", "w")
    env = dict(os.environ, ADMIN_USERNAME="archreader", ADMIN_PASSWORD=password, ADMIN_EMAIL="archreader@example.com",
               VAULT_LOG_SINK_OWNER="test", API_USE_HTTPS="false")
    env.pop("ADMIN_PASSWORD_FILE", None)
    base = f"http://127.0.0.1:{port}"
    t0 = time.monotonic()
    p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.api.api_server:app", "--host", "127.0.0.1", "--port",
                          str(port)], env=env, stdout=log, stderr=subprocess.STDOUT)
    got = {}
    try:
        while True:
            try:
                if http("GET", base, "/health")[0] == 200:
                    break
            except OSError:
                pass
            if p.poll() is not None or time.monotonic() - t0 > 120:
                raise SystemExit("the web process did not answer: " + open(log.name).read()[-2000:])
            time.sleep(0.2)
        got["health_after"] = time.monotonic() - t0
        code, _h, body = http("POST", base, "/auth/login", body={"username": "archreader", "password": password})
        assert code == 200, body[:300]
        token = json.loads(body)["access_token"]
        day = DAY.isoformat()
        code, headers, body = http("GET", base, f"/activity/events?from_date={day}&to_date={day}&page=1&limit=50",
                                   token)
        got["events"] = {"status": code, "retry_after": headers.get("Retry-After"), "body": json.loads(body)}
        code, headers, body = http("GET", base, f"/activity/export?from_date={day}&to_date={day}&format=csv", token)
        got["export"] = {"status": code, "retry_after": headers.get("Retry-After"), "body": body}
        hot = HOT.isoformat()
        code, _h, body = http("GET", base, f"/activity/events?from_date={hot}&to_date={hot}&page=1&limit=50", token)
        got["recent"] = {"status": code, "body": json.loads(body)}
        code, _h, body = http("GET", base, "/activity/integrity", token)
        got["integrity_archive"] = json.loads(body).get("archive") if code == 200 else code
        got["answered_by"] = time.monotonic() - t0
    finally:
        p.terminate()
        try:
            p.wait(30)
        except subprocess.TimeoutExpired:
            p.kill()
        log.close()
    got["log"] = [ln for ln in open(log.name).read().splitlines() if "integrity chain" in ln]
    os.remove(log.name)
    return got


ids = []
for d, hours in ((DAY, (3, 9, 15)), (HOT, (8, 12))):
    for h in hours:
        i = str(uuid.uuid4())
        q("INSERT INTO audit_logs (id, action, status, channel, timestamp, username, details, seal_nonce, "
          "privacy_version) VALUES (:id, 'login_success', 'success', 'web', :t, 'probe', CAST(:d AS json), :n, 1)",
          id=i, t=at(d, h, 17), d='{"n": 1}', n=os.urandom(16))
        if d == DAY:
            ids.append(i)
for _ in range(400):
    r = ai.seal_pass(SessionLocal, st=st, now=now)
    if r.stopped or not r.sealed:
        break
out["stopped"] = r.stopped
later = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=5)      # after the chain's first seal
for _ in range(3):
    arc.archive_job(retention.Pass(SessionLocal, now=later))
out["blocks"] = q("SELECT day::text, row_count FROM audit_archive_blocks")
out["rows_left"] = q("SELECT count(*) FROM audit_logs WHERE timestamp >= :a AND timestamp < :b",
                     a=at(DAY, 0), b=at(DAY, 0) + timedelta(days=1))[0][0]
out["ids"] = sorted(ids)
out["day"] = DAY.isoformat()
out["first_pass"] = retention.FIRST_PASS_SECONDS
engine.dispose()
out["first"] = serve(int(os.environ["PORT_ONE"]), os.environ["READER_PASSWORD"])
# A seal changed in the database: the next process cannot read the chain through.
q("UPDATE audit_seals SET row_bytes = row_bytes + 1 WHERE seq = 2")
engine.dispose()
out["tampered"] = serve(int(os.environ["PORT_TWO"]), os.environ["READER_PASSWORD"])
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def test_a_web_process_that_has_just_started_reads_and_exports_an_archived_day_at_once(throwaway):
    password = "Arch-" + secrets.token_hex(12) + "-9a"
    got = run_in(throwaway, SCRIPT + "\nprint(json.dumps(out, default=str))\n",
                 env={"AUDIT_CHAIN_KEY": KEY, "AUDIT_ARCHIVE_START_AFTER_DAYS": "0", "PORT_ONE": "18761",
                      "PORT_TWO": "18762", "READER_PASSWORD": password})
    assert got["stopped"] is None and got["blocks"] == [[got["day"], 3]] and got["rows_left"] == 0, got
    first = got["first"]
    # Read before the pruner's first pass would have read the chain.
    assert first["answered_by"] < got["first_pass"] == 60, first
    events = first["events"]
    assert events["status"] == 200, events
    assert sorted(e["id"] for e in events["body"]["events"]) == got["ids"] and events["body"]["total"] == 3
    assert events["body"]["archive"]["searched"] is True and events["body"]["archive"]["unreadable"] == []
    export = first["export"]
    assert export["status"] == 200
    lines = export["body"].splitlines()
    assert sum(1 for ln in lines if ln.startswith(got["day"])) == 3, lines
    assert lines[-1].startswith("# Audit chain head when this export started: dvchain1:")
    assert first["recent"]["status"] == 200 and first["recent"]["body"]["total"] == 2
    assert first["integrity_archive"]["read"] is True and first["integrity_archive"]["days"] == 1
    assert any("[OK] The audit log's integrity chain was read" in ln for ln in first["log"]), first["log"]

    tampered = got["tampered"]
    events = tampered["events"]
    assert events["status"] == 503 and events["retry_after"] == "60", events
    detail = events["body"]["detail"]
    assert detail.startswith("The archived days of the audit log cannot be read yet: the audit log's integrity "
                             "chain does not check out (head-record-mismatch)"), detail
    export = tampered["export"]
    assert export["status"] == 503 and export["retry_after"] == "60"
    assert json.loads(export["body"])["detail"] == detail
    assert tampered["recent"]["status"] == 200 and tampered["recent"]["body"]["total"] == 2
    assert tampered["recent"]["body"].get("archive") is None
    assert tampered["integrity_archive"]["read"] is False and tampered["integrity_archive"]["days"] is None
    assert any("could not be read at the start (sealing would stop: head-record-mismatch)" in ln
               for ln in tampered["log"]), tampered["log"]
