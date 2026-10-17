"""Removing values recorded under earlier levels, and keeping full addresses for a number of days only, on a
running stack (app/api/value_removal_router.py, app/core/audit_value_removal.py, app/core/audit_rewrite.py).

On the stack's own database, through the routes: a user is refused; at full there is nothing to remove; with a
level lowered the preview counts the rows above it; asking asks for the password every time; a removal asked for is
listed with its levels and its scope, its request seal and its audit row are written, a second one is refused while
it waits, and any administrator cancels it (each one asked for here is cancelled, so the stack's rows stay as they
are); a cancel of one that is not waiting is refused. The levels are set back afterwards.

On a throwaway database of its own (tests/_throwaway_db.py), its passes run as a script whose clock is set, on
Postgres: a removal over rows and an archived day, and AUDIT_IP_FULL_DAYS over rows and an archived day; the rows,
the blocks and the seals as they should be, and the chain clean afterwards.
"""
import json
import time
import uuid

import pytest

from _account_change_helpers import psql, second_admin
from _recording_levels import levels_restored, store  # noqa: F401 -- a fixture
from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

ACTION = "admin.audit_privacy.write"
FULL = {"names": "full", "signin_names": "full", "emails": "full", "ip": "full", "user_agent": "full"}


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


def test_a_user_and_no_session_are_refused(temp_user_client, anon):
    for client, status in ((temp_user_client, 403), (anon, 401)):
        assert client.get("/settings/value-removals").status_code == status
        assert client.post("/settings/value-removals/preview").status_code == status
        assert client.post("/settings/value-removals").status_code == status


def test_a_removal_asks_for_the_password_is_listed_and_any_administrator_cancels_it(admin, admin_creds,
                                                                                 levels_restored):
    store(dict(FULL))
    full = admin.post("/settings/value-removals/preview")
    assert full.status_code == 200 and full.json()["kinds"] == [], full.text
    r = admin.post("/settings/value-removals", headers={"X-Second-Factor": _receipt(admin, admin_creds["password"])})
    assert r.status_code == 400 and "nothing to remove" in r.json()["detail"], r.text
    store(dict(FULL, ip="shortened", user_agent="none"))
    p = admin.post("/settings/value-removals/preview")
    assert p.status_code == 200, p.text
    out = p.json()
    assert {k["key"]: k["level"] for k in out["kinds"]} == {"ip": "shortened", "user_agent": "none"}
    assert out["rows"] > 0 and out["delay_days"] >= 1
    r = admin.post("/settings/value-removals")
    assert r.status_code == 403 and r.json()["detail"]["action"] == ACTION, r.text
    r = admin.post("/settings/value-removals", headers={"X-Second-Factor": _receipt(admin, admin_creds["password"])})
    assert r.status_code == 200, r.text
    asked = r.json()["request"]
    try:
        assert asked["status"] == "pending" and asked["levels"]["ip"] == "shortened" and asked["cancellable"]
        seal = psql("SELECT detail->>'what', detail->'new'->'levels'->>'user_agent', detail->>'request' FROM audit_seals "
                    f"WHERE kind = 'request' AND detail->>'request' = '{asked['id']}'")
        assert seal == f"removal|none|{asked['id']}"
        assert psql("SELECT count(*) FROM audit_logs WHERE action = 'audit_values_removal_requested' "
                    f"AND resource_id = '{asked['id']}'") == "1"
        listed = admin.get("/settings/value-removals").json()
        assert listed["requests"][0]["id"] == asked["id"] and listed["requests"][0]["status"] == "pending"
        again = admin.post("/settings/value-removals",
                           headers={"X-Second-Factor": _receipt(admin, admin_creds["password"])})
        assert again.status_code == 400 and "already waiting" in again.json()["detail"]
        with second_admin(admin) as (_account, client):
            c = client.post(f"/settings/value-removals/{asked['id']}/cancel")
            assert c.status_code == 200 and c.json()["request"]["status"] == "cancelled", c.text
            again = client.post(f"/settings/value-removals/{asked['id']}/cancel")
            assert again.status_code == 409 and "no longer waiting" in again.json()["detail"]
            assert client.post(f"/settings/value-removals/{uuid.uuid4()}/cancel").status_code == 404
        assert psql("SELECT status FROM audit_value_removals WHERE id = '" + asked["id"] + "'") == "cancelled"
        assert psql("SELECT detail->>'by' FROM audit_seals WHERE kind = 'cancel' "
                    f"AND detail->>'request' = '{asked['id']}'") == "admin"
    finally:
        admin.post(f"/settings/value-removals/{asked['id']}/cancel")


def test_the_levels_page_and_the_notice_say_how_long_addresses_stay_in_full(admin):
    out = admin.get("/settings/recording").json()
    assert out["ip_full_days"] == 0
    managed = admin.get("/settings/managed").json()
    keys = {s["key"] for s in managed["settings"]} if isinstance(managed, dict) else set()
    assert "audit_ip_full_days" in keys


# --------------------------------------------------------------------------- the runs, on a database of their own

SCRIPT = PREAMBLE + r'''
from sqlalchemy import func
from app.core import audit_archive as arc, audit_chain_format as fmt, audit_chain_policy_seals as ps
from app.core import audit_chain_verify as v, audit_value_removal as vr
from app.core.models import AuditArchiveBlock, AuditLog, AuditValueRemoval, RoleEnum, User
out = {}
clock = [now]
st = ai.ChainState(clock=lambda: clock[0])
ai.set_state(st)
DAY = (now - timedelta(days=100)).date()
MODE = os.environ.get("SCENARIO")


def add_row(t, details=None, ip="203.0.113.5"):
    rid = uuid.uuid4()
    with engine.begin() as c:
        c.execute(text(
            "INSERT INTO audit_logs (id, action, status, timestamp, username, ip_address, user_agent, details, "
            "seal_nonce, privacy_version) VALUES (:id, 'file_uploaded', 'success', :t, 'alice', :ip, "
            "'Mozilla/5.0 test', CAST(:d AS json), :n, 3)"),
            {"id": rid, "t": t, "ip": ip, "d": json.dumps(details or {"vault_id": "v1", "count": 1}),
             "n": os.urandom(16)})
    return rid


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


def at(hour, minute=0):
    return datetime(DAY.year, DAY.month, DAY.day, hour, minute)


archived = [add_row(at(3, 5), {"email": "a@example.com", "count": 1}), add_row(at(3, 15))]
old = [add_row(ai.hour_floor(now - timedelta(days=40)) + timedelta(minutes=5), {"client_ip": "198.51.100.4"}),
       add_row(ai.hour_floor(now - timedelta(days=40)) + timedelta(minutes=10))]
young = add_row(ai.hour_floor(now - timedelta(days=10)) + timedelta(minutes=5))
out["stopped"] = passes()
arc.archive_job(retention.Pass(SessionLocal, now=clock[0]))           # archives the day (start after: 0 days)
with SessionLocal() as db:
    out["blocks"] = db.query(func.count()).select_from(AuditArchiveBlock).scalar()
if MODE == "removal":
    with engine.begin() as c:
        c.execute(text("INSERT INTO audit_privacy_policies (version, names, signin_names, emails, ip, user_agent, "
                       "reason, created_at, created_by_name) SELECT max(version) + 1, 'none', 'full', 'none', "
                       "'shortened', 'none', 'admin', :t, 'test' FROM audit_privacy_policies"), {"t": clock[0]})
    with SessionLocal() as db:
        admin = User(id=uuid.uuid4(), username="ada-" + uuid.uuid4().hex[:8], email=None, password_hash="x",
                     role=RoleEnum.ADMIN, is_active=True)
        db.add(admin)
        db.commit()
        with SessionLocal() as db2:
            out["preview"] = vr.preview(db2, st, clock[0])
        with ps.change_transaction(engine) as w:
            asked = vr.request(w, w.db.get(User, admin.id))
    later = add_row(ai.hour_floor(clock[0]) + timedelta(hours=1, minutes=5))
    run_days(8)
    with SessionLocal() as db:
        row = db.get(AuditValueRemoval, uuid.UUID(asked["id"]))
        out["status"], out["counts"] = row.status, row.counts
        out["later"] = db.get(AuditLog, later).ip_address
else:
    run_days(1)
with SessionLocal() as db:
    out["rows"] = {str(r.id): [r.ip_address, r.user_agent, r.recorded, r.details]
                   for r in db.query(AuditLog).filter(AuditLog.id.in_(old + [young]))}
    view = st.view
    found = {}
    for day, part in view.archived_parts():
        for r in arc.PartReader(db, view, day, part).rows():
            found[str(r["id"])] = [r["ip_address"], r["user_agent"], r["recorded"], r["details"]]
    out["archived"] = {str(i): found.get(str(i)) for i in archived}
    seals = list(ai.read_seals(db, 0))
    out["rewrites"] = [s.detail for s in seals if s.kind == "rewrite"]
    out["after_rewrite"] = [seals[i + 1].kind + ":" + str((seals[i + 1].detail or {}).get("cause"))
                            for i, s in enumerate(seals[:-1]) if s.kind == "rewrite" and s.detail.get("hours")]
held = {k: c.key for k, c in st.keys_held().items()}
with SessionLocal() as db:
    report = v.verify(db, record=st.head_store().load(), held=held, current_key_id=st.current_key().key_id,
                      now=clock[0])
out["failures"] = [[f.kind, f.message] for f in report.findings if f.severity == "failure"]
out["old"], out["young"], out["archived_ids"] = [str(i) for i in old], str(young), [str(i) for i in archived]
print(json.dumps(out, default=str))
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def test_a_removal_runs_over_rows_and_an_archived_day_on_postgres_and_the_chain_stays_clean(throwaway):
    out = run_in(throwaway, SCRIPT, env={"AUDIT_ARCHIVE_START_AFTER_DAYS": "0", "SCENARIO": "removal"})
    assert out["stopped"] is None and out["blocks"] >= 1
    assert out["status"] == "completed", out
    assert out["preview"]["rows"] >= 3 and out["preview"]["archived_days"] >= 1
    assert out["counts"]["archived_rows"] == 2 and out["counts"]["rows"] == out["preview"]["rows"]
    for rid in out["old"] + [out["young"]]:
        ip, agent, recorded, details = out["rows"][rid]
        assert ip is None and agent is None and recorded["ip"] == "203.0.113.0/24"
    assert out["rows"][out["old"][0]][2]["details"] == {"client_ip": "198.51.100.0/24"}
    for rid in out["archived_ids"]:
        ip, agent, recorded, details = out["archived"][rid]
        assert ip is None and agent is None and json.loads(recorded)["ip"] == "203.0.113.0/24"
        assert "email" not in (details or "")
    assert out["later"] == "203.0.113.5"
    rewrites = out["rewrites"]
    assert {r["reason"] for r in rewrites} == {"levels"} and [r["final"] for r in rewrites][-1] is True
    assert sum(1 for r in rewrites if r["final"]) == 1 and rewrites[-1]["hours"] == []
    assert "archive:rewrite" in out["after_rewrite"]
    assert out["failures"] == []


def test_full_addresses_are_shortened_after_their_days_on_postgres_and_the_chain_stays_clean(throwaway):
    out = run_in(throwaway, SCRIPT, env={"AUDIT_ARCHIVE_START_AFTER_DAYS": "0", "AUDIT_IP_FULL_DAYS": "30",
                                          "SCENARIO": "shorten"})
    assert out["stopped"] is None and out["blocks"] >= 1
    for rid in out["old"]:
        ip, agent, recorded, _details = out["rows"][rid]
        assert ip is None and agent == "Mozilla/5.0 test" and recorded["ip"] == "203.0.113.0/24"
    assert out["rows"][out["young"]][0] == "203.0.113.5"
    for rid in out["archived_ids"]:
        assert out["archived"][rid][0] is None and json.loads(out["archived"][rid][2])["ip"] == "203.0.113.0/24"
    assert {r["reason"] for r in out["rewrites"]} == {"shorten-ip"}
    assert all(r["request_seq"] is None for r in out["rewrites"])
    assert "archive:rewrite" in out["after_rewrite"]
    assert out["failures"] == []


