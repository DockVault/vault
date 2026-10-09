"""The host's commands that let the audit chain go on after it stopped, on a running stack's Postgres
(app/core/audit_chain_cli.py, what ``dockvault.py audit`` runs in the web container).

Each case runs on a throwaway database of its own, with the web image's code in the web container: the server's
passes run as scripts whose clock can be set, and the host's command runs as ``python -m app.core.audit_integrity``
in a process of its own, in its two phases (``--read`` prints the state it saw, ``--expect`` writes only while
that state holds), with an old key given on its standard input. After each, a server pass seals again and the
chain verifies clean:

- a key changed without the old one: sealing waits until ``rekey`` moves the chain with the old key's proof; a
  lost old key: ``rekey --accept-unverified-history``, reported for good as information;
- a seal another writer appended after the head record: a warning until ``after-record`` acknowledges it; one
  refused on its face stops sealing until ``after-record --discard`` deletes it, its rows saved;
- a database restored from an older copy: sealing stops until ``accept-database-head`` writes a restore seal,
  and nothing is deleted during the grace after it;
- a whole backup restored (the keys volume first, the restore mark beside the head record, then the database):
  nothing is deleted while the mark is there, and ``accept-restore`` acknowledges the seals written between the
  keys and the database parts of the backup, removes the mark and starts the grace;
- rows an older release removed by age while sealing was stopped: ``acknowledge-removed-before`` seals over
  them;
- rows added to an hour sealed more than 6 hours before: ``acknowledge --late-rows`` seals them; a row holding a
  value no release writes: ``acknowledge --rows``;
- a head kept before a removal: with the key it matches and every seal is authenticated; without the key
  (``verify --no-key``) the removal's prune is "not authenticated"; a later head closes it. The same for a head
  kept before rows were added to an hour it covered and sealed by ``acknowledge --late-rows``: the host's late
  seal is "not authenticated" without the key. A head a database restore lost is reported against the restore
  seal, as information with the key and a warning without it;
- a lost head record: accepted once its key history is confirmed by name, and reported for good; a database
  cut back to before a key change: its chain ends under a key the chain left, accepted by name, and the move
  back needs ``rekey --confirm-return``; reported for good.

test_audit_chain_recovery.py, test_audit_chain_restore.py, test_audit_chain_external.py and
test_audit_chain_host.py cover the rules offline.
"""
import json
import subprocess
from datetime import datetime, timezone

import pytest

from _account_change_helpers import API, psql
from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

KEY = "k" * 64

SCRIPT = PREAMBLE + r'''
from app.core import audit_chain_format as fmt, audit_chain_verify as v
from app.core.models import AuditSeal
out = {}
real_now = now
clock = [real_now]
st = ai.ChainState(clock=lambda: clock[0])
ai.set_state(st)


def at(hours=0, days=0, minutes=0):
    return real_now - timedelta(days=days, hours=hours, minutes=minutes)


def add_row(t, nonce=True, details=None):
    rid = uuid.uuid4()
    with engine.begin() as c:
        c.execute(text(
            "INSERT INTO audit_logs (id, action, status, timestamp, username, ip_address, details, seal_nonce, "
            "privacy_version) VALUES (:id, 'file_uploaded', 'success', :t, 'carol', '203.0.113.5', "
            "CAST(:d AS json), :n, 3)"),
            {"id": rid, "t": t, "d": details or json.dumps({"n": 1}), "n": os.urandom(16) if nonce else None})
    return str(rid)


def passes(when=None):
    clock[0] = when or ai.utcnow()
    r = None
    for _ in range(300):
        r = ai.seal_pass(SessionLocal, st=st, now=clock[0])
        if r.stopped or not r.sealed:
            break
    return r.stopped if r else None


def report():
    db = SessionLocal()
    try:
        held = {k: c.key for k, c in st.keys_held().items()}
        rep = v.verify(db, record=st.head_store().load(), held=held, current_key_id=st.current_key().key_id,
                       now=clock[0])
        return {s: sorted({f.kind for f in rep.findings if f.severity == s})
                for s in ("failure", "warning", "information")}
    finally:
        db.close()


def seals():
    with engine.begin() as c:
        return [[s, k] for s, k in c.execute(text("SELECT seq, kind FROM audit_seals ORDER BY seq"))]


def forge(kind, detail, sealed_at):
    """A seal appended by someone who holds the key but not the host: no head record write."""
    db = SessionLocal()
    try:
        prev = fmt.LINK_0
        rows = list(ai.read_seals(db, 0))
        for s in rows:
            prev = fmt.link(prev, s.body())
        key = st.current_key()
        seq = rows[-1].seq + 1
        seal = ai.Seal(seq, kind, None, None, fmt.FORMAT, 0, 0, None, None, None, detail, key.key_id, sealed_at)
        link = fmt.link(prev, seal.body())
        db.add(AuditSeal(seq=seq, kind=kind, period_start=None, period_end=None, format=1, row_count=0, row_bytes=0,
                         root_s=None, root_c=None, ids_digest=None, detail=detail, key_id=key.key_id,
                         sealed_at=sealed_at, mac=fmt.mac(key.key, link), link=link))
        db.commit()
        return seq
    finally:
        db.close()


def record():
    return st.head_store().load() or {}


ADMIN_ACK = {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin", "user_id": None,
             "request": None}
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def _script(name, body, key=KEY):
    return run_in(name, SCRIPT + body + "\nprint(json.dumps(out, default=str))\n", env={"AUDIT_CHAIN_KEY": key})


def _url(name):
    base = subprocess.run(["docker", "exec", API, "printenv", "DATABASE_URL"], capture_output=True, text=True,
                          timeout=60).stdout.strip()
    return base.rsplit("/", 1)[0] + "/" + name


def _cli(name, *args, key=KEY, stdin=""):
    """The host's command in a process of its own in the web container, on the throwaway database."""
    env = {"DATABASE_URL": _url(name), "AUDIT_CHAIN_HEAD_FILE": f"/tmp/{name}-head.json", "AUDIT_CHAIN_KEY": key}
    cmd = ["docker", "exec", "-i"] + [f"-e{k}={v}" for k, v in env.items()] + \
        [API, "python", "-m", "app.core.audit_integrity", *args]
    r = subprocess.run(cmd, input=stdin, capture_output=True, text=True, encoding="utf-8", timeout=900)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    answer = json.loads(lines[-1]) if lines and lines[-1].startswith("{") else None
    return r.returncode, answer, r.stderr


def _two(name, *args, key=KEY, stdin=""):
    """Both phases: the read, then the write with the state it printed."""
    code, seen, err = _cli(name, *args, "--read", key=key, stdin=stdin)
    assert code == 0 and seen and seen["ok"], (seen, err[-3000:])
    code, done, err = _cli(name, *args, "--expect", seen["state"], key=key, stdin=stdin)
    assert code == 0 and done and done["ok"], (done, err[-3000:])
    return seen, done


def _in_api(*args, stdin=None):
    return subprocess.run(["docker", "exec", "-i", API, *args], input=stdin, capture_output=True, text=True,
                          encoding="utf-8", timeout=120)


def _clean(report):
    assert report["failure"] == [], report


# --------------------------------------------------------------------------- keys

A, B = "a" * 64, "b" * 64


def test_a_key_changed_without_the_old_one_waits_until_rekey_moves_the_chain_with_its_proof(throwaway):
    first = _script(throwaway, r'''
add_row(at(hours=5)); add_row(at(hours=4))
out["stopped"] = passes()
''', key=A)
    assert first["stopped"] is None, first
    waiting = _script(throwaway, 'out["stopped"] = passes()\n', key=B)
    assert waiting["stopped"] == "key-change-waiting", waiting
    code, refused, _err = _cli(throwaway, "rekey", "--read", key=B)
    assert code == 2 and "not held" in refused["error"], refused
    seen, done = _two(throwaway, "rekey", "--old-key-stdin", key=B, stdin=A + "\n")
    assert done["from"] != done["to"] and done["unverified"] is False
    after = _script(throwaway, r'''
out["stopped"] = passes()
out["report"] = report()
with engine.begin() as c:
    out["proof"] = c.execute(text("SELECT detail->>'old_key_proof' FROM audit_seals WHERE kind = 'key'")).scalar()
''', key=B)
    assert after["stopped"] is None, after
    _clean(after["report"])
    assert "key-change-waiting" not in after["report"]["warning"]
    assert after["proof"], after


def test_a_lost_old_key_is_accepted_without_its_proof_and_reported_for_good(throwaway):
    _script(throwaway, 'add_row(at(hours=5))\nout["stopped"] = passes()\n', key=A)
    assert _script(throwaway, 'out["stopped"] = passes()\n', key=B)["stopped"] == "key-change-waiting"
    seen, done = _two(throwaway, "rekey", "--accept-unverified-history", key=B)
    assert "WITHOUT the old key's proof" in "\n".join(seen["lines"])
    assert done["unverified"] is True
    after = _script(throwaway, 'out["stopped"] = passes()\nout["report"] = report()\n', key=B)
    assert after["stopped"] is None, after
    _clean(after["report"])
    assert "key-accepted-unverified" in after["report"]["information"]


# --------------------------------------------------------------------------- seals after the head record

def test_a_seal_another_writer_appended_is_a_warning_until_after_record_acknowledges_it(throwaway):
    first = _script(throwaway, r'''
add_row(at(hours=5))
out["stopped"] = passes()
out["forged"] = forge("ack", ADMIN_ACK, ai.utcnow())
out["after"] = passes()
out["foreign"] = sorted(ai.unacknowledged_foreign(st.view, record()))
out["report"] = report()
out["status"] = sorted(ai.status(st)["warnings"])
''')
    assert first["after"] is None and first["foreign"] == [first["forged"]], first
    assert "after-record" in first["status"], first
    code, found, _answer = _verify(throwaway)
    waiting = [(f["severity"], f["seq"]) for f in found.get("after-record") or []]
    assert code == 1 and waiting == [("warning", first["forged"])], found
    seen, done = _two(throwaway, "after-record")
    assert first["forged"] in done["accepted"], done
    after = _script(throwaway, r'''
out["stopped"] = passes()
out["foreign"] = sorted(ai.unacknowledged_foreign(st.view, record()))
out["report"] = report()
out["status"] = sorted(ai.status(st)["warnings"])
''')
    assert after["stopped"] is None and after["foreign"] == [], after
    _clean(after["report"])
    assert "after-record" not in after["status"], after
    _code, found, _answer = _verify(throwaway)
    assert "after-record" not in found, found


def test_a_seal_refused_on_its_face_is_discarded_with_its_rows_saved(throwaway):
    first = _script(throwaway, r'''
add_row(at(hours=5))
out["stopped"] = passes()
out["forged"] = forge("ack", ADMIN_ACK, ai.utcnow() - timedelta(hours=3))
out["after"] = passes()
''')
    assert first["after"] == "after-record-invalid", first
    seen, done = _two(throwaway, "after-record", "--discard")
    assert done["discarded"] == [first["forged"]], done
    saved = _in_api("cat", done["saved"])
    assert saved.returncode == 0 and json.loads(saved.stdout)[0]["seq"] == first["forged"]
    after = _script(throwaway, r'''
out["stopped"] = passes()
out["discards"] = record().get("discards")
out["kinds"] = seals()
out["report"] = report()
''')
    assert after["stopped"] is None and after["discards"] == 1, after
    assert [k for s, k in after["kinds"] if s == first["forged"]] == ["ack"]
    _clean(after["report"])
    _in_api("rm", "-f", done["saved"])


# --------------------------------------------------------------------------- restores

def test_a_database_restored_from_an_older_copy_is_accepted_with_a_restore_seal_and_a_grace(throwaway):
    old = throwaway + "_old"
    try:
        _script(throwaway, r'''
for h in range(10, 1, -1):
    add_row(at(hours=h))
out["stopped"] = passes(at(hours=6))
''')
        psql(f"CREATE DATABASE {old} TEMPLATE {throwaway}")
        newer = _script(throwaway, 'out["stopped"] = passes()\nout["seals"] = len(seals())\n')
        assert newer["stopped"] is None
        # The older copy put back in its place, the head record left as the newer chain wrote it.
        psql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{throwaway}'")
        psql(f"DROP DATABASE {throwaway}")
        psql(f"CREATE DATABASE {throwaway} TEMPLATE {old}")
        stopped = _script(throwaway, 'out["stopped"] = passes()\nout["seals"] = len(seals())\n')
        assert stopped["stopped"] == "head-record-mismatch", stopped
        assert stopped["seals"] < newer["seals"]
        seen, done = _two(throwaway, "accept-database-head")
        text = "\n".join(seen["lines"])
        assert "an older copy" in text and seen["confirm"] == [], seen
        assert done["grace_days"] >= 1 and done["generation"] == 2, done
        after = _script(throwaway, r'''
out["stopped"] = passes()
out["holds"] = st.holds_deletion()
out["chain_holds"] = retention.chain_holds()
out["generation"] = record().get("generation")
out["report"] = report()
''')
        assert after["stopped"] is None, after
        assert after["holds"] and "grace" in after["holds"] and after["chain_holds"] is True, after
        assert after["generation"] == 2
        _clean(after["report"])
    finally:
        psql(f"DROP DATABASE IF EXISTS {old}")


def test_a_whole_backup_restored_holds_deletion_until_accept_restore(throwaway):
    copy = throwaway + "_bak"
    head = f"/tmp/{throwaway}-head.json"
    try:
        _script(throwaway, r'''
for h in range(9, 1, -1):
    add_row(at(hours=h))
out["stopped"] = passes(at(hours=5))
''')
        # The backup: the keys volume (the head record) first, then the database, with seals written between.
        assert _in_api("cp", head, head + ".bak").returncode == 0
        window = _script(throwaway, 'out["before"] = len(seals())\nout["stopped"] = passes(at(hours=3))\n'
                                    'out["after"] = len(seals())\n')
        assert window["after"] > window["before"], window
        psql(f"CREATE DATABASE {copy} TEMPLATE {throwaway}")
        later = _script(throwaway, 'out["stopped"] = passes()\nout["seals"] = len(seals())\n')
        assert later["stopped"] is None
        # The restore: the keys volume, the mark beside the head record, then the database.
        replaced = json.loads(_in_api("cat", head).stdout)
        assert _in_api("cp", head + ".bak", head).returncode == 0
        restored = json.loads(_in_api("cat", head).stdout)
        mark = {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "bundle": "live-test-bundle",
                "record": replaced, "restored_record": restored}
        assert _in_api("sh", "-c", 'cat > "$0"', head + ".restore-pending", stdin=json.dumps(mark)).returncode == 0
        psql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{throwaway}'")
        psql(f"DROP DATABASE {throwaway}")
        psql(f"CREATE DATABASE {throwaway} TEMPLATE {copy}")
        start = _script(throwaway, r'''
out["stopped"] = passes()
out["holds"] = st.holds_deletion()
out["foreign"] = sorted(ai.unacknowledged_foreign(st.view, record()))
out["status"] = sorted(ai.status(st)["warnings"])
''')
        assert start["holds"] and "restore" in start["holds"], start
        assert "restore-pending" in start["status"], start
        window_seals = list(range(window["before"] + 1, window["after"] + 1))
        assert set(window_seals) <= set(start["foreign"]), (window_seals, start)
        seen, done = _two(throwaway, "accept-restore")
        assert done["acknowledged"] == window_seals, (window_seals, done)
        assert _in_api("test", "-e", head + ".restore-pending").returncode == 1
        after = _script(throwaway, r'''
out["stopped"] = passes()
out["holds"] = st.holds_deletion()
out["foreign"] = sorted(ai.unacknowledged_foreign(st.view, record()))
out["generation"] = record().get("generation")
out["report"] = report()
''')
        assert after["stopped"] is None and after["foreign"] == [], after
        assert after["holds"] and "grace" in after["holds"], after
        assert after["generation"] >= 2
        _clean(after["report"])
    finally:
        psql(f"DROP DATABASE IF EXISTS {copy}")
        _in_api("rm", "-f", head + ".bak", head + ".restore-pending")


# --------------------------------------------------------------------------- rows

def test_rows_an_older_release_removed_by_age_are_sealed_over_by_acknowledge_removed_before(throwaway):
    first = _script(throwaway, r'''
rows = [add_row(at(days=20, hours=-h)) for h in range(6)]
out["stopped"] = passes(at(days=19))
# Sealing stopped (an older release ran), and its retention removed the oldest rows by age.
with engine.begin() as c:
    t = c.execute(text("SELECT timestamp FROM audit_logs WHERE id = :id"), {"id": rows[3]}).scalar()
    c.execute(text("DELETE FROM audit_logs WHERE timestamp < :t"), {"t": t})
out["before"] = fmt.time_text(t)
out["back"] = passes()
out["report"] = report()
''')
    assert first["stopped"] is None and first["back"] is None, first
    assert "rows-missing" in first["report"]["failure"], first
    code, refused, _err = _cli(throwaway, "acknowledge-removed-before", first["before"], "--retention-days", "30",
                               "--read")
    assert code == 2 and "too recent" in refused["error"], refused
    seen, done = _two(throwaway, "acknowledge-removed-before", first["before"], "--retention-days", "7")
    assert done["sealed"] and done["hours"] >= 1, done
    after = _script(throwaway, 'out["stopped"] = passes()\nout["report"] = report()\n')
    assert after["stopped"] is None, after
    _clean(after["report"])


def test_rows_added_to_an_hour_sealed_long_before_are_sealed_by_the_host_once_read(throwaway):
    first = _script(throwaway, r'''
add_row(at(hours=12))
out["stopped"] = passes(at(hours=9))
hour = ai.hour_floor(at(hours=12))
out["added"] = add_row(hour + timedelta(minutes=50))
out["back"] = passes()
out["hour"] = fmt.hour_text(hour)
out["late"] = [s for s, k in seals() if k == "late"]
out["report"] = report()
''')
    assert first["late"] == [] and "rows-added" in first["report"]["failure"], first
    seen, done = _two(throwaway, "acknowledge", "--late-rows", first["hour"])
    assert first["added"] in "\n".join(seen["lines"]) and done["added"] == 1, (seen, done)
    after = _script(throwaway, r'''
out["stopped"] = passes()
out["report"] = report()
out["warnings"] = sorted(ai.status(st)["warnings"])
''')
    assert after["stopped"] is None, after
    _clean(after["report"])
    assert "late" not in after["warnings"]


def test_a_row_holding_a_value_no_release_writes_is_a_failure_until_the_host_has_looked_at_it(throwaway):
    first = _script(throwaway, r'''
out["plain"] = add_row(at(hours=6))
out["odd"] = add_row(at(hours=6, minutes=-5), details='{"n": 1e400}')
out["stopped"] = passes()
out["report"] = report()
''')
    assert "rows-altered" in first["report"]["failure"], first
    code, refused, _err = _cli(throwaway, "acknowledge", "--rows", first["plain"], "--read")
    assert code == 2 and "not a row holding a value" in refused["error"], refused
    seen, done = _two(throwaway, "acknowledge", "--rows", first["odd"])
    assert done["rows"] == [first["odd"]], done
    after = _script(throwaway, 'out["stopped"] = passes()\nout["report"] = report()\n')
    _clean(after["report"])
    assert "value-not-writable" in after["report"]["information"]


# --------------------------------------------------------------------------- anchors and what verify reports

def _verify(name, *args, key=KEY):
    """audit verify in the web container on the throwaway database: (exit code, findings by kind)."""
    code, answer, err = _cli(name, "verify", "--json", *args, key=key)
    assert answer and answer["ok"], (answer, err[-3000:])
    found = {}
    for f in answer["findings"]:
        found.setdefault(f["kind"], []).append(f)
    return code, found, answer


def test_an_anchor_kept_before_a_removal_is_checked_with_and_without_the_key(throwaway):
    first = _script(throwaway, r"""
rows = [add_row(at(days=20, hours=-h)) for h in range(6)]
out["stopped"] = passes(at(days=19))
""")
    assert first["stopped"] is None, first
    _code, _found, sealed = _verify(throwaway)
    anchor = sealed["head"]
    removed = _script(throwaway, r"""
with engine.begin() as c:
    ts = [r[0] for r in c.execute(text("SELECT timestamp FROM audit_logs WHERE action = 'file_uploaded' "
                                       "ORDER BY timestamp"))]
    t = ts[3]
    c.execute(text("DELETE FROM audit_logs WHERE timestamp < :t"), {"t": t})
out["before"] = fmt.time_text(t)
out["back"] = passes()
""")
    assert removed["back"] is None, removed
    _two(throwaway, "acknowledge-removed-before", removed["before"], "--retention-days", "7")
    _script(throwaway, 'out["stopped"] = passes()\n')
    # With the key: every seal authenticated, the anchor matches, the prune and the stop reported for good.
    code, found, answer = _verify(throwaway, "--anchor", anchor)
    assert code == 0 and "anchor-mismatch" not in found and "changed-after-anchor" not in found, found
    assert found.get("pruned") and "external prune of" in found["pruned"][0]["message"], found
    assert found.get("gap"), found
    # Without the key, as an auditor holding only the anchor: the prune is not authenticated.
    code, found, _answer = _verify(throwaway, "--anchor", anchor, "--no-key")
    changed = found.get("changed-after-anchor") or []
    assert code == 1 and changed and all(f["severity"] == "warning" for f in changed), found
    assert {f["seq"] for f in changed} == {f["seq"] for f in found["pruned"]}, found
    assert "anchor-mismatch" not in found
    # A head kept after the removal closes it.
    code, found, _answer = _verify(throwaway, "--anchor", answer["head"], "--no-key")
    assert "changed-after-anchor" not in found and "anchor-mismatch" not in found, found


def test_an_anchor_kept_before_rows_were_added_to_its_hour_is_checked_with_and_without_the_key(throwaway):
    first = _script(throwaway, r"""
add_row(at(hours=12))
out["stopped"] = passes(at(hours=9))
out["hour"] = fmt.hour_text(ai.hour_floor(at(hours=12)))
""")
    assert first["stopped"] is None, first
    _code, _found, sealed = _verify(throwaway)
    anchor = sealed["head"]
    added = _script(throwaway, r"""
out["added"] = add_row(ai.hour_floor(at(hours=12)) + timedelta(minutes=50))
out["back"] = passes()
""")
    _seen, done = _two(throwaway, "acknowledge", "--late-rows", first["hour"])
    assert done["added"] == 1, (added, done)
    after = _script(throwaway, r"""
out["stopped"] = passes()
out["late"] = [s for s, k in seals() if k == "late"]
""")
    assert after["stopped"] is None and len(after["late"]) == 1, after
    # With the key: the anchor matches and the host's late seal is authenticated.
    code, found, answer = _verify(throwaway, "--anchor", anchor)
    assert "anchor-mismatch" not in found and "changed-after-anchor" not in found, found
    # Without the key, as an auditor holding only the anchor: the late seal is not authenticated.
    code, found, _answer = _verify(throwaway, "--anchor", anchor, "--no-key")
    changed = found.get("changed-after-anchor") or []
    late = [(f["seq"], f["hour"], f["severity"]) for f in changed]
    assert code == 1 and late == [(after["late"][0], first["hour"], "warning")], found
    assert "not authenticated" in changed[0]["message"] and "anchor-mismatch" not in found, found
    # A head kept after the late seal closes it.
    code, found, _answer = _verify(throwaway, "--anchor", answer["head"], "--no-key")
    assert "changed-after-anchor" not in found and "anchor-mismatch" not in found, found


def test_an_anchor_a_database_restore_lost_is_reported_against_its_restore_seal(throwaway):
    old = throwaway + "_old"
    try:
        _script(throwaway, r"""
for h in range(10, 1, -1):
    add_row(at(hours=h))
out["stopped"] = passes(at(hours=6))
""")
        psql(f"CREATE DATABASE {old} TEMPLATE {throwaway}")
        _script(throwaway, 'out["stopped"] = passes()\n')
        _code, _found, newer = _verify(throwaway)
        anchor = newer["head"]
        psql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{throwaway}'")
        psql(f"DROP DATABASE {throwaway}")
        psql(f"CREATE DATABASE {throwaway} TEMPLATE {old}")
        _two(throwaway, "accept-database-head")
        _script(throwaway, 'out["stopped"] = passes()\n')
        code, found, _answer = _verify(throwaway, "--anchor", anchor)
        assert "anchor-mismatch" not in found, found
        lost = found.get("anchor-lost") or []
        assert [f["severity"] for f in lost] == ["information"], found
        restored = found.get("restored") or []
        assert [f["seq"] for f in restored] == [lost[0]["seq"]], found
        assert found.get("resealed-after-restore"), found
        code, found, _answer = _verify(throwaway, "--anchor", anchor, "--no-key")
        assert [f["severity"] for f in found.get("anchor-lost") or []] == ["warning"], found
        assert "anchor-mismatch" not in found
    finally:
        psql(f"DROP DATABASE IF EXISTS {old}")


def test_a_lost_head_record_is_accepted_after_its_key_history_is_confirmed_and_reported_for_good(throwaway):
    head = f"/tmp/{throwaway}-head.json"
    first = _script(throwaway, r"""
add_row(at(hours=5)); add_row(at(hours=4))
out["stopped"] = passes()
""")
    assert first["stopped"] is None, first
    assert _in_api("rm", "-f", head).returncode == 0
    stopped = _script(throwaway, 'out["stopped"] = passes()\n')
    assert stopped["stopped"] == "head-record-missing", stopped
    code, seen, _err = _cli(throwaway, "accept-database-head", "--read")
    assert code == 0 and seen["ok"] and seen["confirm"] and seen["confirm"][0].startswith("key-history-"), seen
    code, refused, _err = _cli(throwaway, "accept-database-head", "--expect", seen["state"])
    assert code == 2 and "confirm by name" in refused["error"], refused
    code, done, err = _cli(throwaway, "accept-database-head", "--expect", seen["state"],
                           *[x for c in seen["confirm"] for x in ("--confirm", c)])
    assert code == 0 and done["ok"], (done, err[-3000:])
    after = _script(throwaway, 'out["stopped"] = passes()\nout["report"] = report()\n')
    assert after["stopped"] is None, after
    _clean(after["report"])
    _code, found, _answer = _verify(throwaway)
    assert any("the head record missing" in f["message"] for f in found.get("restored") or []), found


def test_a_database_cut_back_under_a_key_the_chain_left_needs_rekey_with_a_confirmation(throwaway):
    under_a = throwaway + "_a"
    try:
        _script(throwaway, r"""
for h in range(9, 4, -1):
    add_row(at(hours=h))
out["stopped"] = passes(at(hours=4))
""", key=A)
        psql(f"CREATE DATABASE {under_a} TEMPLATE {throwaway}")
        assert _script(throwaway, 'out["stopped"] = passes()\n', key=B)["stopped"] == "key-change-waiting"
        _two(throwaway, "rekey", "--old-key-stdin", key=B, stdin=A + "\n")
        moved = _script(throwaway, 'out["stopped"] = passes()\n', key=B)
        assert moved["stopped"] is None, moved
        # The database put back to a copy from before the move: its chain ends under A, which the chain left.
        psql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{throwaway}'")
        psql(f"DROP DATABASE {throwaway}")
        psql(f"CREATE DATABASE {throwaway} TEMPLATE {under_a}")
        assert _script(throwaway, 'out["stopped"] = passes()\n', key=B)["stopped"] == "head-record-mismatch"
        code, seen, err = _cli(throwaway, "accept-database-head", "--old-key-stdin", "--read", key=B, stdin=A + "\n")
        assert code == 0 and seen["ok"], (seen, err[-3000:])
        assert any(c.startswith("left-key-") for c in seen["confirm"]), seen
        assert any("A KEY THE RECORDED CHAIN LEFT" in ln for ln in seen["lines"]), seen
        code, done, err = _cli(throwaway, "accept-database-head", "--old-key-stdin", "--expect", seen["state"],
                               *[x for c in seen["confirm"] for x in ("--confirm", c)], key=B, stdin=A + "\n")
        assert code == 0 and done["ok"], (done, err[-3000:])
        assert _script(throwaway, 'out["stopped"] = passes()\n', key=B)["stopped"] == "key-not-current"
        code, refused, _err = _cli(throwaway, "rekey", "--old-key-stdin", "--read", key=B, stdin=A + "\n")
        if code == 0:
            code, refused, _err = _cli(throwaway, "rekey", "--old-key-stdin", "--expect", refused["state"], key=B,
                                       stdin=A + "\n")
        assert code == 2 and "--confirm-return" in refused["error"], refused
        _two(throwaway, "rekey", "--old-key-stdin", "--confirm-return", key=B, stdin=A + "\n")
        after = _script(throwaway, 'out["stopped"] = passes()\nout["report"] = report()\n', key=B)
        assert after["stopped"] is None, after
        _clean(after["report"])
        assert "restored-under-left-key" in after["report"]["information"], after
    finally:
        psql(f"DROP DATABASE IF EXISTS {under_a}")
