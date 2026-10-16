"""Per-person erase on a running stack (app/api/person_erase_router.py, app/core/person_erase.py,
app/core/audit_chain_erase.py).

On the stack's own database, through the routes: asking asks for the password every time; an account's name, and a
name that starts with "erased-", are refused; the preview counts the audit rows of the name; an erase asked for is
listed by its placeholder, its request seal, its row (the name only sealed) and its audit row never name the person,
and any administrator cancels it (each erase asked for here is cancelled, so the stack's chain and database agree
afterwards); a user, and no session, are refused; an account cannot be created with a placeholder's name.

On a throwaway database of its own (tests/_throwaway_db.py), its passes run as a script whose clock is set: an
erase over rows and an archived day on Postgres, the chain clean afterwards, the other stores given the placeholder,
the head record holding no salt, the tables vacuumed; and deleting an account leaves its audit rows to the
database's ON DELETE SET NULL, the chain still clean. tests/test_person_erase.py and tests/test_audit_chain_erase.py
cover the rules offline.
"""
import json
import time
import uuid

import pytest

from _account_change_helpers import psql, second_admin
from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

ACTION = "admin.retention.write"


def _receipt(client, password):
    r = client.post("/auth/second-factor/step-up", json={"action": ACTION, "method": "password", "code": password})
    assert r.status_code == 200, r.text
    return r.json()["receipt"]


def _wait_for(check, timeout=20.0, step=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(step)
    return check()


@pytest.fixture(autouse=True, scope="module")
def chain_started():
    ok = _wait_for(lambda: psql("SELECT count(*) FROM audit_seals WHERE kind = 'policy'") not in ("", "0"),
                   timeout=240, step=3)
    assert ok, "the audit chain never started"


def _typed_rows(name, n=2):
    """Audit rows of a failed sign-in with ``name`` typed, as the app writes them (no account)."""
    for _ in range(n):
        psql("INSERT INTO audit_logs (id, action, status, timestamp, username, ip_address, details, seal_nonce) "
             f"VALUES ('{uuid.uuid4()}', 'login_failed', 'failure', now() at time zone 'utc' - interval '2 hours', "
             f"'{name}', '198.51.100.23', '{{}}', decode('{uuid.uuid4().hex}', 'hex'))")


def test_asking_for_an_erase_asks_for_the_password_and_never_names_the_person(admin):
    name = "erase-live-" + uuid.uuid4().hex[:10]
    _typed_rows(name)
    with second_admin(admin) as (account, client):
        p = client.post("/settings/erase-requests/preview", json={"name": name})
        assert p.status_code == 200, p.text
        assert p.json()["audit_rows"] == 2 and p.json()["refused"] is None
        r = client.post("/settings/erase-requests", json={"name": name})
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["action"] == ACTION
        r = client.post("/settings/erase-requests", json={"name": name},
                        headers={"X-Second-Factor": _receipt(client, account["_password"])})
        assert r.status_code == 200, r.text
        asked = r.json()["request"]
        assert asked["status"] == "pending" and asked["placeholder"].startswith("erased-")
        assert name not in r.text
        listed = client.get("/settings/erase-requests")
        assert listed.status_code == 200 and name not in listed.text
        assert any(e["id"] == asked["id"] and e["cancellable"] for e in listed.json()["requests"])
        seal = psql(f"SELECT detail::text FROM audit_seals WHERE seq = {asked['request_seq']}")
        assert json.loads(seal)["placeholder"] == asked["placeholder"] and name not in seal
        row = psql(f"SELECT name_token, placeholder, status FROM erase_requests WHERE id = '{asked['id']}'")
        assert row.startswith("en1:") and name not in row and asked["placeholder"] in row
        audit = psql("SELECT details::text FROM audit_logs WHERE action = 'person_erase_requested' "
                     f"AND resource_id = '{asked['id']}'")
        assert asked["placeholder"] in audit and name not in audit
        notices = psql("SELECT string_agg(body, ' ') FROM notifications WHERE type = 'retention_change' "
                       f"AND body LIKE '%{asked['placeholder']}%'")
        assert asked["placeholder"] in notices and name not in notices
        c = admin.post(f"/settings/erase-requests/{asked['id']}/cancel")
        assert c.status_code == 200, c.text
        assert c.json()["request"]["status"] == "cancelled"
        assert psql(f"SELECT status || ':' || coalesce(name_token, '-') FROM erase_requests "
                    f"WHERE id = '{asked['id']}'") == "cancelled:-"
        assert client.post(f"/settings/erase-requests/{asked['id']}/cancel").status_code == 409
    assert psql(f"SELECT count(*) FROM audit_logs WHERE username = '{name}'") == "2"


def test_an_accounts_name_and_a_placeholder_are_refused(admin):
    with second_admin(admin) as (account, client):
        r = client.post("/settings/erase-requests", json={"name": account["_username"]},
                        headers={"X-Second-Factor": _receipt(client, account["_password"])})
        assert r.status_code == 400 and "an account has this name" in r.json()["detail"]
        r = client.post("/settings/erase-requests", json={"name": "Erased-1234abcd"})
        assert r.status_code == 400 and "erased-" in r.json()["detail"]
        p = client.post("/settings/erase-requests/preview", json={"name": account["_username"]})
        assert p.status_code == 200 and p.json()["refused"].startswith("an account has this name")
        assert client.post(f"/settings/erase-requests/{uuid.uuid4()}/cancel").status_code == 404


def test_a_user_and_no_session_are_refused(temp_user_client, anon):
    for client in (temp_user_client, anon):
        assert client.get("/settings/erase-requests").status_code in (401, 403)
        assert client.post("/settings/erase-requests/preview", json={"name": "x"}).status_code in (401, 403)
        assert client.post("/settings/erase-requests", json={"name": "x"}).status_code in (401, 403)


def test_no_account_can_be_created_with_a_placeholders_name(admin):
    r = admin.post("/users", json={"username": "erased-" + uuid.uuid4().hex[:8], "password": "Aa1!" + "x" * 14,
                                   "role": "user"})
    assert r.status_code in (400, 422) and "erased-" in r.text


# --------------------------------------------------------------------------- the run, on a database of its own

SCRIPT = PREAMBLE + r'''
import hashlib
from sqlalchemy import func
from app.core import audit_archive as arc, audit_chain_erase as ae, audit_chain_format as fmt
from app.core import audit_chain_policy_seals as ps, audit_chain_verify as v, person_erase as pe
from sqlalchemy import event
from app.core.models import (AuditArchiveBlock, AuditLog, EraseRequest, RoleEnum, SecurityAlert, SecurityRecord,
                             User)
out = {}
clock = [now]
st = ai.ChainState(clock=lambda: clock[0])
ai.set_state(st)
DAY = (now - timedelta(days=100)).date()
NAME = "erase-run-" + uuid.uuid4().hex[:8]


def at(hour, minute=0, day=None):
    d = day or DAY
    return datetime(d.year, d.month, d.day, hour, minute)


def add_row(t, username, nonce=True, details=None):
    rid = uuid.uuid4()
    with engine.begin() as c:
        c.execute(text(
            "INSERT INTO audit_logs (id, action, status, timestamp, username, ip_address, user_agent, endpoint, "
            "details, recorded, seal_nonce, privacy_version) VALUES (:id, 'file_uploaded', 'success', :t, :u, "
            "'203.0.113.5', 'Mozilla/5.0 test', '/raw/' || :u, CAST(:d AS json), CAST(:r AS jsonb), :n, 3)"),
            {"id": rid, "t": t, "u": username, "d": json.dumps(details or {"vault_id": "v1", "count": 1}),
             "r": json.dumps({"ip": "203.0.113.0/24"}), "n": os.urandom(16) if nonce else None})
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
        retention.run_pass(SessionLocal, engine=engine, now=clock[0])


archived = [add_row(at(3, 5), NAME), add_row(at(5, 5), NAME, nonce=False), add_row(at(5, 25), "alice", nonce=False)]
hot = [add_row(now - timedelta(hours=30), NAME), add_row(now - timedelta(hours=30, minutes=-5), NAME, nonce=False),
       add_row(now - timedelta(hours=30, minutes=-10), "alice", nonce=False)]
with SessionLocal() as db:
    db.add(SecurityRecord(id=uuid.uuid4(), at=now, kind="password", name=NAME, address="198.51.100.9"))
    db.add(SecurityAlert(id=uuid.uuid4(), event_type="failed_login", severity="warning", timestamp=now,
                         message="Failed login for " + NAME + " from 198.51.100.9", username=NAME,
                         ip_address="198.51.100.9", details={"user": NAME}))
    db.commit()
out["stopped"] = passes()
retention.run_pass(SessionLocal, engine=engine, now=clock[0])          # archives the day (start after: 0 days)
with SessionLocal() as db:
    out["blocks_before"] = db.query(func.count()).select_from(AuditArchiveBlock).scalar()
    admin = User(id=uuid.uuid4(), username="ada-" + NAME[-8:], email=None, password_hash="x", role=RoleEnum.ADMIN,
                 is_active=True)
    db.add(admin)
    db.commit()
    admin = db.get(User, admin.id)
    with ps.change_transaction(engine) as w:
        asked = pe.request(w, NAME, w.db.get(User, admin.id))
out["placeholder"] = asked["placeholder"]
hour = ai.hour_floor(now - timedelta(hours=30))
with SessionLocal() as db:
    out["salt_before"] = bytes(ai.working_row(db, hour).legacy_salt).hex()
run_days(8)
with SessionLocal() as db:
    row = db.get(EraseRequest, uuid.UUID(asked["id"]))
    out["status"] = row.status
    out["token"] = row.name_token
    out["counts"] = row.counts
    out["hot"] = {r.id.hex: (r.username, r.ip_address, r.user_agent, r.endpoint, r.recorded, r.details,
                             bytes(r.seal_nonce).hex() if r.seal_nonce else None)
                  for r in db.query(AuditLog).filter(AuditLog.id.in_([uuid.UUID(i) for i in hot]))}
    view = st.view
    found = {}
    for day, part in view.archived_parts():
        for r in arc.PartReader(db, view, day, part).rows():
            found[r["id"].hex] = (r["username"], r["ip_address"], r["details"])
    out["archived"] = {uuid.UUID(i).hex: found.get(uuid.UUID(i).hex) for i in archived}
    out["record"] = db.query(SecurityRecord).first().name
    alert = db.query(SecurityAlert).first()
    out["alert"] = [alert.username, alert.ip_address, alert.message, alert.details]
    out["erases"] = [s.detail for s in ai.read_seals(db, 0) if s.kind == "erase"]
    out["kinds"] = [s.kind for s in ai.read_seals(db, 0)][-12:]
    out["seals_text"] = NAME in json.dumps([str(s.detail) for s in ai.read_seals(db, 0)])
    out["audit_text"] = NAME in json.dumps([str(r.details) for r in db.query(AuditLog).filter(
        AuditLog.action.in_(["person_erased", "person_erase_requested"]))])
    out["salt_after"] = (ai.working_row(db, hour).legacy_salt or b"").hex()
held = {k: c.key for k, c in st.keys_held().items()}
with SessionLocal() as db:
    report = v.verify(db, record=st.head_store().load(), held=held, current_key_id=st.current_key().key_id,
                      now=clock[0])
out["failures"] = [[f.kind, f.message] for f in report.findings if f.severity == "failure"]
with open(st.head_store().path, encoding="utf-8") as f:
    head = f.read()
out["salt_in_record"] = out["salt_before"] in head
with engine.connect() as c:
    out["vacuumed"] = c.execute(text("SELECT last_vacuum IS NOT NULL FROM pg_stat_user_tables "
                                     "WHERE relname = 'audit_seals'")).scalar()
# Deleting an account leaves its audit rows to the database's ON DELETE SET NULL.
with SessionLocal() as db:
    gone = User(id=uuid.uuid4(), username="gone-" + NAME[-8:], email=None, password_hash="x", role=RoleEnum.USER,
                is_active=True)
    db.add(gone)
    db.commit()
    gid = gone.id
with engine.begin() as c:
    c.execute(text("INSERT INTO audit_logs (id, action, status, timestamp, user_id, username, seal_nonce) "
                   "VALUES (:id, 'login', 'success', :t, :u, :n, :s)"),
              {"id": uuid.uuid4(), "t": clock[0] - timedelta(hours=3), "u": gid, "n": "gone-" + NAME[-8:],
               "s": os.urandom(16)})
passes(clock[0] + timedelta(hours=1))
updates = []


def _seen(conn, cursor, statement, parameters, context, executemany):
    if statement.lstrip().upper().startswith("UPDATE AUDIT_LOGS"):
        updates.append(statement)
event.listen(engine, "before_cursor_execute", _seen)
with SessionLocal() as db:
    db.delete(db.get(User, gid))
    db.commit()
event.remove(engine, "before_cursor_execute", _seen)
out["orm_updates"] = len(updates)
with SessionLocal() as db:
    out["orphan"] = db.query(func.count()).select_from(AuditLog).filter(
        AuditLog.username == "gone-" + NAME[-8:], AuditLog.user_id.is_(None)).scalar()
    report = v.verify(db, record=st.head_store().load(), held=held, current_key_id=st.current_key().key_id,
                      now=clock[0])
out["failures_after_delete"] = [[f.kind, f.message] for f in report.findings if f.severity == "failure"]
out["name"] = NAME
print(json.dumps(out, default=str))
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def test_an_erase_runs_over_rows_and_an_archived_day_on_postgres_and_the_chain_stays_clean(throwaway):
    out = run_in(throwaway, SCRIPT, env={"AUDIT_ARCHIVE_START_AFTER_DAYS": "0"})
    ph, name = out["placeholder"], out["name"]
    assert out["stopped"] is None and out["blocks_before"] >= 1
    assert out["status"] == "completed" and out["token"] is None
    assert out["counts"]["audit_rows"] == 4 and out["counts"]["stores"]["security_records"] == 1
    for rid, (username, ip, agent, endpoint, recorded, details, nonce) in out["hot"].items():
        if username == "alice":
            continue
        assert (username, ip, agent, endpoint, recorded, nonce) == (ph, None, None, None, None, "00" * 16)
        assert details == {"vault_id": "v1", "count": 1}
    values = list(out["archived"].values())
    assert [v[0] for v in values] == [ph, ph, "alice"] and values[0][1] is None and values[2][1] == "203.0.113.5"
    assert out["record"] == ph
    assert out["alert"][0] == ph and out["alert"][1] is None and name not in out["alert"][2]
    assert "198.51.100.9" not in out["alert"][2] and name not in json.dumps(out["alert"][3])
    erases = out["erases"]
    assert [e["final"] for e in erases] == [False] * (len(erases) - 1) + [True]
    assert sum(len(e["rows"]) for e in erases) == 4 and {e["placeholder"] for e in erases} == {ph}
    assert "archive" in out["kinds"]
    assert not out["seals_text"] and not out["audit_text"]
    assert out["salt_after"] == "" and not out["salt_in_record"]
    assert out["vacuumed"] is True
    assert out["failures"] == []
    assert out["orphan"] == 1 and out["failures_after_delete"] == []
    assert out["orm_updates"] == 0              # the database cleared user_id; the ORM loaded and wrote no row
