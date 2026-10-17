"""Running a per-person erase (app/core/audit_chain_erase.py), offline, on a throwaway SQLite database with a chain
of its own (tests/_erase_env.py):

- once its delay has run, the name's rows read the placeholder, their personal values are cleared and their
  details scrubbed by the recording levels' kinds, one erase seal per hour lists each row's commitments, the roots
  stay, and verify is clean; rows of other names, and near misses, are untouched; the other stores get the
  placeholder in the final transaction; the person_erased row never names the person; the head record holds no
  salt of an erased hour, however the erase names it;
- the run's scope: rows written after it began are not erased; a crash mid-way resumes from the hours without a
  seal of the request; an erase that finds no row writes one final seal with no hour;
- it waits for the hold switch, a registered rule (legal holds, open cases), an account, temporary credential or
  waiting invitation that has the name, a restore not finished, and with ERASE_BLOCKED_BY_PROTECTED_MINIMUM for the
  protected minimum; a database that removes or ends its row vetoes it (a cancel seal by the database), and one that
  changes its name, its token or its placeholder copy gets nothing erased (unjustified-input);
- archived days: the blocks holding the name are rewritten (an erase seal per hour, then the archive seal of cause
  rewrite), verify reads the erased rows back from the blocks, and an erased hour is archived and pruned like any.
"""
import json
import uuid
from datetime import datetime, time, timedelta

import pytest
from sqlalchemy import text

from _audit_chain_env import T0, failures
from _erase_env import EraseEnv
from app.core import audit_archive as arc
from app.core import audit_chain_erase as ae
from app.core import audit_chain_format as fmt
from app.core import audit_integrity as ai
from app.core import person_erase as pe
from app.core import retention
from app.core.models import (AccountInvitation, ActivitySavedSearch, AuditArchiveBlock, AuditLog, EraseRequest,
                             Notification, SecurityAlert, SecurityRecord, TemporaryCredential, User)

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = EraseEnv(monkeypatch, tmp_path, audit_archive_start_after_days=0)
    arc._marker_checked.clear()
    arc._figures.clear()
    yield e
    e.close()


def _rows(env, **filters):
    with env.session() as db:
        q = db.query(AuditLog)
        for k, v in filters.items():
            q = q.filter(getattr(AuditLog, k) == v)
        return q.all()


def _put(env, when, username="eve", **values):
    row = dict(id=uuid.uuid4(), action="file_uploaded", status="success", timestamp=when, username=username,
               ip_address="203.0.113.9", user_agent="Mozilla/5.0 test", endpoint="/vaults/{vault_id}/files",
               details={"n": 1}, seal_nonce=uuid.uuid4().bytes)
    row.update(values)
    with env.session() as db:
        db.add(AuditLog(**row))
        db.commit()
    return row["id"]


def _due(env, name="eve"):
    """Ask for an erase of ``name`` and let its delay run (seven days of passes)."""
    out = env.ask(name)
    env.passes(24 * 7 + 6)
    return out


def _done(env, request_id):
    return env.request_row(request_id).status == pe.COMPLETED


# --------------------------------------------------------------------------- the run over rows

def test_an_erase_gives_the_placeholder_clears_the_values_and_keeps_the_chain_valid(env, monkeypatch):
    monkeypatch.setattr(ae, "route_templates", lambda: frozenset({"/vaults/{vault_id}/files"}))
    h1 = T0 - timedelta(hours=30)
    mine = [_put(env, h1 + timedelta(minutes=m), details={"vault_id": "v1", "file_name": "secret.txt", "count": 2, "n": 3,
                                                           "username": "eve", "reason": "eve did it",
                                                           "email": "eve@example.com", "x_unclassified": 1,
                                                           "recipients": 3, "sent": "a,b", "error": "KeyError",
                                                           "changes": {"email": "eve@example.com", "role": "user"},
                                                           "token": "secret"},
                 recorded={"ip": "203.0.113.0/24"}, error_message="eve not found", temp_credential_name="tc-eve")
            for m in (5, 15)]
    mine.append(_put(env, T0 - timedelta(hours=20), endpoint="/raw/path/eve", error_message="ValueError"))
    other = _put(env, h1 + timedelta(minutes=25), username="alice")
    near = _put(env, h1 + timedelta(minutes=35), username="Eve")
    env.run_until_sealed()
    roots_before = {s.seq: (s.root_s, s.root_c) for s in env.seals() if s.kind == "hour"}
    asked = _due(env)
    assert _done(env, asked["id"])
    for rid in mine[:2]:
        row = _rows(env, id=rid)[0]
        assert row.username == asked["placeholder"] and row.ip_address is None and row.user_agent is None
        assert row.recorded is None and row.temp_credential_name is None and row.error_message is None
        assert row.endpoint == "/vaults/{vault_id}/files"
        assert row.details == {"vault_id": "v1", "count": 2, "recipients": 3, "error": "KeyError",
                               "changes": {"role": "user"}}         # unclassified keys go too
        assert bytes(row.seal_nonce) == fmt.ZERO_NONCE
    third = _rows(env, id=mine[2])[0]
    assert third.endpoint is None and third.error_message == "ValueError"
    assert _rows(env, id=other)[0].username == "alice" and _rows(env, id=near)[0].username == "Eve"
    assert {s.seq: (s.root_s, s.root_c) for s in env.seals() if s.seq in roots_before} == roots_before
    erases = env.erase_seals()
    assert [len(s.detail["rows"]) for s in erases] == [2, 1]
    assert [s.detail["final"] for s in erases] == [False, True]
    assert {s.detail["placeholder"] for s in erases} == {asked["placeholder"]}
    assert {s.detail["through"] for s in erases} == {erases[0].detail["through"]}
    assert all(s.detail["policy_seq"] == env.view().newest_policy()[0] or s.detail["policy_seq"] for s in erases)
    report = env.verify()
    assert failures(report) == [], report.findings


def test_the_person_erased_row_and_the_seals_never_name_the_person(env):
    name = "zelda.unique-person"
    _put(env, T0 - timedelta(hours=30), username=name)
    env.run_until_sealed()
    asked = _due(env, name)
    assert _done(env, asked["id"])
    rows = _rows(env, action=pe.ERASED_ACTION) + _rows(env, action=pe.REQUESTED_ACTION)
    assert len(rows) == 2
    for row in rows:
        assert name not in json.dumps(row.details) and name not in (row.username or "")
        assert row.details["placeholder"] == asked["placeholder"]
    erased = _rows(env, action=pe.ERASED_ACTION)[0]
    assert erased.details["rows"] == 1 and erased.details["request_id"] == asked["id"]
    with env.session() as db:
        seals = db.execute(text("SELECT detail FROM audit_seals")).fetchall()
        assert not any(name in str(r[0]) for r in seals)
        assert db.get(EraseRequest, uuid.UUID(asked["id"])).name_token is None
    assert env.told == [("completed", {"placeholder": asked["placeholder"], "audit_rows": 1, "other_rows": 0})]


def test_rows_written_after_the_run_began_are_not_erased(env, monkeypatch):
    first = _put(env, T0 - timedelta(hours=30))
    second = _put(env, T0 - timedelta(hours=29))
    env.run_until_sealed()
    asked = env.ask("eve")
    env.passes(24 * 7 - 6)
    assert env.erase_seals() == []
    # The run begins with its first unit only: the second waits for the next transaction.
    real = ae.step
    calls = []

    def one_unit(p, w, seq, findings, tried, cache=None):
        out = real(p, w, seq, findings, tried, cache)
        calls.append(out[0])
        if out[0] == ae.ERASED:
            p.deadline = 0          # the pass ends after the first unit
        return out
    monkeypatch.setattr(ae, "step", one_unit)
    env.clock.advance(hours=6)
    retention.run_pass(env.session, now=env.clock())
    monkeypatch.setattr(ae, "step", real)
    assert _rows(env, id=first)[0].username == asked["placeholder"] and _rows(env, id=second)[0].username == "eve"
    later = _put(env, env.clock() + timedelta(minutes=5))
    env.passes(12)
    assert _done(env, asked["id"])
    assert _rows(env, id=second)[0].username == asked["placeholder"]
    assert _rows(env, id=later)[0].username == "eve"            # after the run's scope
    assert failures(env.verify()) == []


def test_a_crash_mid_run_resumes_from_the_hours_without_a_seal(env, monkeypatch):
    ids = [_put(env, T0 - timedelta(hours=h)) for h in (40, 30, 20)]
    env.run_until_sealed()
    asked = env.ask("eve")
    env.passes(24 * 7 - 6)
    assert env.erase_seals() == []
    real = ae.erase_hour
    calls = {"n": 0}

    def crash_on_second(*a, **k):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("the process died")
        return real(*a, **k)
    monkeypatch.setattr(ae, "erase_hour", crash_on_second)
    env.clock.advance(hours=6)
    retention.run_pass(env.session, now=env.clock())
    assert [_rows(env, id=i)[0].username for i in ids] == [asked["placeholder"], "eve", "eve"]
    assert len(env.erase_seals()) == 1 and env.request_row(asked["id"]).status == pe.RUNNING
    monkeypatch.setattr(ae, "erase_hour", real)
    env.fresh_process()
    env.passes(6)
    assert {_rows(env, id=i)[0].username for i in ids} == {asked["placeholder"]}
    assert len(env.erase_seals()) == 3 and _done(env, asked["id"])
    assert failures(env.verify()) == []


def test_the_audit_table_is_read_for_the_hours_once_a_pass_and_again_for_the_last_unit(env, monkeypatch):
    ids = [_put(env, T0 - timedelta(hours=h)) for h in (50, 40, 30, 20)]
    env.run_until_sealed()
    asked = env.ask("eve")
    env.passes(24 * 7 - 6)
    real, calls = ae.hot_hours, []
    monkeypatch.setattr(ae, "hot_hours", lambda *a, **k: calls.append(1) or real(*a, **k))
    env.clock.advance(hours=6)
    retention.run_pass(env.session, now=env.clock())
    assert {_rows(env, id=i)[0].username for i in ids} == {asked["placeholder"]} and _done(env, asked["id"])
    assert len(calls) == 2                      # once for the pass, once more before the last unit


def test_the_last_unit_is_decided_on_the_table_as_it_is_and_not_on_the_pass_list(env):
    ids = [_put(env, T0 - timedelta(hours=h)) for h in (40, 30)]
    env.run_until_sealed()
    asked = env.ask("eve")
    env.passes(24 * 7 - 6)
    env.clock.advance(hours=6)
    env.seal()
    st = env.st
    seq = asked["request_seq"]
    p = retention.Pass(env.session, now=env.clock())
    with ai.ChainWriter(env.engine, st) as w:
        out = ae.step(p, w, seq, {}, set(), {"hours": []})        # a list that says nothing is left
    assert out[0] == ae.ERASED and out[2] is None                  # not the end: the table still holds two hours
    seals = env.erase_seals()
    assert len(seals) == 1 and seals[0].detail["final"] is False and seals[0].detail["hour"] is not None
    env.passes(6)
    assert {_rows(env, id=i)[0].username for i in ids} == {asked["placeholder"]} and _done(env, asked["id"])
    assert failures(env.verify()) == []


def test_an_erase_that_finds_no_row_writes_one_final_seal_and_still_covers_the_other_stores(env):
    env.row(T0 - timedelta(hours=5), username="alice")
    env.run_until_sealed()
    with env.session() as db:
        db.add(SecurityRecord(id=uuid.uuid4(), at=T0, kind="password", name="nobody-here", address="198.51.100.4"))
        db.commit()
    asked = _due(env, "nobody-here")
    seals = env.erase_seals()
    assert len(seals) == 1 and seals[0].detail["hour"] is None and seals[0].detail["final"] is True
    assert seals[0].detail["rows"] == []
    with env.session() as db:
        rec = db.query(SecurityRecord).one()
        assert rec.name == asked["placeholder"] and rec.address is None
    assert failures(env.verify()) == []


def test_the_head_record_holds_no_salt_of_an_erased_hour(env):
    _put(env, T0 - timedelta(hours=30), seal_nonce=None)
    _put(env, T0 - timedelta(hours=30, minutes=-10), username="alice", seal_nonce=None)
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=30))
    with env.session() as db:
        salt = bytes(ai.working_row(db, hour).legacy_salt)
    _due(env)
    with env.session() as db:
        assert ai.working_row(db, hour).legacy_salt is None
        alice = db.query(AuditLog).filter(AuditLog.username == "alice").one()
        assert bytes(alice.seal_nonce) == fmt.legacy_nonce(salt, alice.id)      # materialised
    record = env.st.head_store().load()
    assert all(v.get("salt") is None for v in record["hours"].values())
    with open(env.settings.audit_chain_head_file, encoding="utf-8") as f:
        assert salt.hex() not in f.read()
    erase = env.erase_seals()[0]
    assert erase.detail["hour"] == fmt.hour_text(hour)
    assert failures(env.verify()) == []


def test_rows_of_a_name_recorded_as_a_fingerprint_are_erased_too(env):
    fp = pe.signin_fingerprint("eve", env.settings)
    typed = _put(env, T0 - timedelta(hours=30), username=None, recorded={"signin_name": fp}, action="login_failed",
                 status="failure")
    other = _put(env, T0 - timedelta(hours=30, minutes=-5), username=None, action="login_failed", status="failure",
                 recorded={"signin_name": pe.signin_fingerprint("mallory", env.settings)})
    # A row with an account's username is that account's, whatever its recorded values say.
    named = _put(env, T0 - timedelta(hours=30, minutes=-10), username="alice", recorded={"signin_name": fp})
    env.run_until_sealed()
    asked = _due(env)
    row = _rows(env, id=typed)[0]
    assert row.username == asked["placeholder"] and row.recorded is None and row.ip_address is None
    assert _rows(env, id=other)[0].username is None and _rows(env, id=other)[0].recorded is not None
    assert _rows(env, id=named)[0].username == "alice" and _rows(env, id=named)[0].recorded == {"signin_name": fp}
    assert failures(env.verify()) == []


def test_the_scans_of_an_erase_are_forgotten_once_it_ends(env):
    _archived_day(env)
    asked = _due(env)
    assert _done(env, asked["id"])
    assert not [k for k in env.st.erase_scans if k[0] == asked["request_seq"]]


class _Conn:
    def __init__(self, log, clock, cost):
        self.log, self.clock, self.cost = log, clock, cost

    def execution_options(self, **kw):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, statement):
        self.log.append(str(statement))
        if str(statement).startswith("VACUUM"):
            self.clock[0] += self.cost


def test_the_vacuum_after_an_erase_keeps_to_its_budget(monkeypatch):
    import time as _time
    clock = [1000.0]
    monkeypatch.setattr(_time, "monotonic", lambda: clock[0])
    log = []

    class Engine:
        dialect = type("D", (), {"name": "postgresql"})()

        def connect(self):
            return _Conn(log, clock, 40.0)
    done = ae.vacuum(Engine(), budget=100.0)
    assert done == list(ae.VACUUM_TABLES[:3])
    timeouts = [int(x.split("= ")[1]) for x in log if x.startswith("SET statement_timeout")]
    assert timeouts == [100000, 60000, 20000]
    assert ae.VACUUM_TABLES[0] == "audit_seals" and ae.VACUUM_TABLES[-1] == "audit_logs"


@pytest.mark.parametrize("model, column", [
    ("AdminGrant", "granted_by_name"), ("Note", "sent_from_name"), ("ManagedSettingChange", "requested_by_name"),
    ("ManagedSettingChange", "decided_by_name"), ("ManagedSetting", "updated_by_name"),
    ("AuditPrivacyPolicy", "created_by_name"), ("UserSSHKey", "created_by_name"),
    ("EraseRequest", "requested_by_name"), ("CredentialChange", "requested_by_name"),
    ("CredentialChange", "decided_by_name")])
def test_a_name_column_of_each_store_gets_the_placeholder(env, model, column):
    import sqlalchemy as sa
    from app.core import models
    m = getattr(models, model)
    _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    values = {}
    for c in m.__table__.columns:
        if c.primary_key:
            values[c.name] = uuid.uuid4() if isinstance(c.type, sa.Uuid) else (
                "k-" + uuid.uuid4().hex[:8] if isinstance(c.type, sa.String) else 1)
        elif not c.nullable:
            values[c.name] = _filler(c)
    values[column] = "eve"
    with env.engine.begin() as conn:
        conn.execute(m.__table__.insert().values(**values))
    asked = _due(env)
    with env.engine.begin() as conn:
        assert conn.execute(sa.select(m.__table__.c[column])).scalar() == asked["placeholder"]


def _filler(column):
    import sqlalchemy as sa
    t = column.type
    if isinstance(t, sa.Uuid):
        return uuid.uuid4()
    if isinstance(t, sa.DateTime):
        return T0
    if isinstance(t, (sa.Integer, sa.Boolean)):
        return 0
    if isinstance(t, sa.JSON):
        return {}
    if isinstance(t, sa.Enum):
        return list(t.enums)[0]
    return "x"


def test_every_other_store_gets_the_placeholder_in_the_final_transaction(env):
    _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    now = env.clock()
    owner = env.admin("owner")
    with env.session() as db:
        db.add(SecurityAlert(id=uuid.uuid4(), event_type="failed_login", severity="warning",
                             message="Failed login for eve from 198.51.100.7", username="eve",
                             ip_address="198.51.100.7", details={"user": "eve", "ip": "198.51.100.7"},
                             timestamp=now, resolved=True, resolved_by="ada", resolution_notes="eve was locked"))
        db.add(SecurityRecord(id=uuid.uuid4(), at=now, kind="password", name="eve", address="198.51.100.7"))
        db.add(AccountInvitation(id=uuid.uuid4(), username="eve", email="eve@example.com", role="user",
                                 token_prefix="p", token_hash=uuid.uuid4().hex, expires_at=now - timedelta(days=1),
                                 created_at=now - timedelta(days=9)))
        db.add(ActivitySavedSearch(id=uuid.uuid4(), user_id=owner.id, name="eve's", filters={"user": "eve"},
                                   created_at=now, updated_at=now))
        db.add(Notification(id=uuid.uuid4(), user_id=owner.id, type="x", title="eve shared a file", body="from eve",
                            created_at=now))
        db.commit()
    asked = _due(env)
    ph = asked["placeholder"]
    with env.session() as db:
        alert = db.query(SecurityAlert).one()
        assert alert.username == ph and alert.ip_address is None and "eve" not in alert.message
        assert "198.51.100.7" not in alert.message and "eve" not in json.dumps(alert.details)
        assert "198.51.100.7" not in json.dumps(alert.details) and alert.resolution_notes == f"{ph} was locked"
        rec = db.query(SecurityRecord).one()
        assert rec.name == ph and rec.address is None
        inv = db.query(AccountInvitation).one()
        assert inv.username == ph and inv.email is None
        assert db.query(ActivitySavedSearch).one().filters == {"user": ph}
        note = db.query(Notification).one()
        assert note.title == f"{ph} shared a file" and note.body == f"from {ph}"
        row = db.get(EraseRequest, uuid.UUID(asked["id"]))
        assert row.counts["stores"]["security_alerts"] == 1 and row.counts["stores"]["notifications"] == 1
        assert row.counts["audit_rows"] == 1
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- what it waits for

def test_nothing_is_due_while_a_gap_in_sealing_is_open(env):
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    env.ask("eve")
    env.passes(24 * 7 - 6)
    env.clock.advance(hours=18)                 # no seal for 18 hours: a gap is open
    assert ae.due(env.view(), env.st.known_record(), env.clock()) == []
    env.erase_job()
    assert _rows(env, id=rid)[0].username == "eve" and env.erase_seals() == []
    # Sealing again closes the gap, which moved the delay on by its length: due 18 hours after its date.
    env.seal()
    env.erase_job()
    env.clock.advance(hours=5)
    env.seal()
    env.erase_job()
    assert _rows(env, id=rid)[0].username == "eve" and env.erase_seals() == []
    env.clock.advance(hours=1)
    env.seal()
    env.erase_job()
    assert _rows(env, id=rid)[0].username != "eve"


def test_an_erase_long_due_does_not_run_while_a_gap_is_open(env):
    """An erase held back past its date (a rule kept it waiting) is due at once when the rule ends; but not while
    sealing has stopped for more than 12 hours: nothing applies while a gap is open."""
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    env.ask("eve")
    held = {"on": True}
    pe.register_wait(lambda db, now: "a legal hold stands" if held["on"] else None)
    env.passes(24 * 10)
    held["on"] = False
    env.clock.advance(hours=13)                 # no seal for 13 hours
    assert ae.due(env.view(), env.st.known_record(), env.clock()) == []
    env.erase_job()
    assert _rows(env, id=rid)[0].username == "eve"
    env.seal()
    env.erase_job()
    assert _rows(env, id=rid)[0].username != "eve"


def test_an_hour_another_writer_resealed_waits_for_the_host(env):
    from test_audit_chain_held import _foreign_late
    from test_audit_archive import _ack_by_host
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    hour = ai.hour_floor(T0 - timedelta(hours=30))
    extra = _put(env, hour + timedelta(minutes=40), username="alice")
    late = _foreign_late(env, hour, [extra])
    env.clock.advance(minutes=30)
    assert env.seal().stopped is None
    asked = env.ask("eve")
    env.passes(24 * 8)
    assert _rows(env, id=rid)[0].username == "eve" and env.erase_seals() == []
    assert "waits for the host operator" in env.request_row(asked["id"]).waiting
    _ack_by_host(env, [late])
    env.passes(6)
    assert _rows(env, id=rid)[0].username == asked["placeholder"]
    assert failures(env.verify()) == []


def test_the_hold_switch_defers_it(env, monkeypatch):
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    asked = env.ask("eve")
    monkeypatch.setattr(retention, "hold_in_force", lambda: True)
    env.passes(24 * 8)
    assert _rows(env, id=rid)[0].username == "eve" and env.erase_seals() == []
    monkeypatch.setattr(retention, "hold_in_force", lambda: False)
    env.passes(6)
    assert _rows(env, id=rid)[0].username == asked["placeholder"]


def test_a_registered_rule_defers_it_and_says_why(env):
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    asked = env.ask("eve")
    held = {"on": True}
    pe.register_wait(lambda db, now: "a legal hold stands" if held["on"] else None)
    env.passes(24 * 8)
    assert _rows(env, id=rid)[0].username == "eve" and env.erase_seals() == []
    row = env.request_row(asked["id"])
    assert row.status == pe.PENDING and "a legal hold stands" in row.waiting
    held["on"] = False
    env.passes(6)
    assert _done(env, asked["id"]) and env.request_row(asked["id"]).waiting is None


@pytest.mark.parametrize("who", ["account", "credential", "invitation"])
def test_a_name_someone_took_meanwhile_waits(env, who):
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    asked = env.ask("eve")
    with env.session() as db:
        if who == "account":
            db.add(User(id=uuid.uuid4(), username="eve", email="e@example.com", password_hash="x", is_active=True))
        elif who == "credential":
            db.add(TemporaryCredential(id=uuid.uuid4(), user_id=uuid.uuid4(), temp_username="eve",
                                       credential_hash="x", expires_at=env.clock() + timedelta(days=30),
                                       deactivate_at=env.clock() + timedelta(days=30)))
        else:
            db.add(AccountInvitation(id=uuid.uuid4(), username="eve", role="user", token_prefix="p",
                                     token_hash=uuid.uuid4().hex, expires_at=env.clock() + timedelta(days=30)))
        db.commit()
    env.passes(24 * 8)
    assert _rows(env, id=rid)[0].username == "eve" and env.erase_seals() == []
    assert "has this name" in env.request_row(asked["id"]).waiting or "waiting" in env.request_row(asked["id"]).waiting


@pytest.mark.parametrize("action, bound", [("settings_updated", "AUDIT_PROTECTED_MIN_DAYS"),
                                           ("file_uploaded", "AUDIT_MIN_RETENTION_DAYS")])
def test_with_the_protected_minimum_it_waits_until_the_rows_are_older(env, monkeypatch, action, bound):
    """ERASE_BLOCKED_BY_PROTECTED_MINIMUM=true: an erase waits while a row it would change is younger than the
    minimum for its kind (the protected minimum for an administration row, the minimum for every row)."""
    env.settings.erase_blocked_by_protected_minimum = True
    monkeypatch.setenv(bound, "10")
    setattr(env.settings, bound.lower(), 10)
    rid = _put(env, T0 - timedelta(hours=29), action=action)
    env.run_until_sealed()
    asked = env.ask("eve")
    env.passes(24 * 8)                               # due; the row is 8 days old
    assert _rows(env, id=rid)[0].username == "eve"
    assert "protected minimum" in env.request_row(asked["id"]).waiting
    env.passes(24 * 3)                               # 11 days old
    assert _rows(env, id=rid)[0].username == asked["placeholder"]
    assert failures(env.verify()) == []


def test_without_the_flag_the_protected_minimum_does_not_hold_it(env):
    rid = _put(env, T0 - timedelta(hours=30), action="settings_updated")
    env.run_until_sealed()
    asked = _due(env)
    assert _rows(env, id=rid)[0].username == asked["placeholder"]


# --------------------------------------------------------------------------- what the database can and cannot do

@pytest.mark.parametrize("how", ["removed", "cancelled", "token gone"])
def test_a_database_that_holds_the_row_back_vetoes_the_erase(env, how):
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    asked = env.ask("eve")
    with env.session() as db:
        row = db.get(EraseRequest, uuid.UUID(asked["id"]))
        if how == "removed":
            db.delete(row)
        elif how == "cancelled":
            row.status = pe.CANCELLED
        else:
            row.name_token = None
        db.commit()
    env.passes(6)                               # vetoed at once: it does not wait for its delay
    cancels = [s for s in env.seals() if s.kind == "cancel"]
    assert len(cancels) == 1 and cancels[0].detail["by"] == "database"
    env.passes(24 * 8)
    assert _rows(env, id=rid)[0].username == "eve" and env.erase_seals() == []
    assert len([s for s in env.seals() if s.kind == "cancel"]) == 1
    assert cancels[0].seq in ai.database_seqs(env.view())


@pytest.mark.parametrize("how", ["name swapped", "placeholder copy", "token of another request"])
def test_a_database_that_changes_the_name_gets_nothing_erased(env, how):
    rid = _put(env, T0 - timedelta(hours=30))
    other_row = _put(env, T0 - timedelta(hours=29), username="mallory")
    env.run_until_sealed()
    asked = env.ask("eve")
    second = env.ask("someone-else")
    with env.session() as db:
        row = db.get(EraseRequest, uuid.UUID(asked["id"]))
        if how == "name swapped":
            import secrets
            row.name_token = pe.seal_name(env.settings, row.id, secrets.token_bytes(32), "mallory")
        elif how == "placeholder copy":
            row.placeholder = "erased-00000000"
        else:
            row.name_token = db.get(EraseRequest, uuid.UUID(second["id"])).name_token
        db.commit()
    env.passes(24 * 8)
    assert _rows(env, id=rid)[0].username == "eve" and _rows(env, id=other_row)[0].username == "mallory"
    assert not any(s.detail.get("request_seq") == asked["request_seq"] for s in env.erase_seals())
    record = env.st.head_store().load()
    assert "unjustified-input" in (record.get("failures") or {})


def test_the_daily_check_reports_a_waiting_erase_whose_name_was_swapped(env):
    from app.core import audit_chain_verify as v
    _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    asked = env.ask("eve")
    with env.session() as db:
        row = db.get(EraseRequest, uuid.UUID(asked["id"]))
        row.name_token = pe.seal_name(env.settings, row.id, b"r" * 32, "mallory")
        db.commit()
    report = v.daily_check(env.session, env.st, env.clock(), force=True)
    assert "unjustified-input" in failures(report)


def test_an_erase_seal_must_name_the_policy_seal_in_force(env, monkeypatch):
    _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    real = ae._detail
    monkeypatch.setattr(ae, "_detail", lambda *a, **k: dict(real(*a, **k), policy_seq=1))
    _due(env)
    found = [f for f in env.verify().findings if f.kind == "unjustified"]
    assert found and "policy seal in force" in found[0].message


# --------------------------------------------------------------------------- archived days

DAY = (T0 - timedelta(days=100)).date()


def at(hour, minute=0, day=DAY):
    return datetime.combine(day, time(hour, minute))


def _archived_day(env):
    ids = {"eve": [_put(env, at(3, 5)), _put(env, at(3, 15)), _put(env, at(5, 5), seal_nonce=None)],
           "alice": [_put(env, at(3, 25), username="alice"), _put(env, at(5, 25), username="alice", seal_nonce=None)]}
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    assert len(_blocks(env)) == 1 and _rows(env, username="eve") == []
    return ids


def _blocks(env):
    with env.session() as db:
        return db.query(AuditArchiveBlock).all()


def _block_rows(env):
    with env.session() as db:
        out = {}
        for b in db.query(AuditArchiveBlock).all():
            part = env.st.view.archives[b.day].part_for(at(3))
            for row in arc.PartReader(db, env.st.view, b.day, part).rows():
                out[row["id"]] = row
        return out


def test_the_rows_of_the_name_in_an_archived_day_are_erased_in_the_block(env):
    ids = _archived_day(env)
    asked = _due(env)
    assert _done(env, asked["id"])
    rows = _block_rows(env)
    for rid in ids["eve"]:
        assert rows[rid]["username"] == asked["placeholder"] and rows[rid]["ip_address"] is None
        assert rows[rid]["seal_nonce"] == fmt.ZERO_NONCE
    for rid in ids["alice"]:
        assert rows[rid]["username"] == "alice" and rows[rid]["ip_address"] == "203.0.113.9"
    kinds = [s.kind for s in env.seals()]
    erases = env.erase_seals()
    assert [s.detail["hour"] for s in erases] == [fmt.hour_text(at(3)), fmt.hour_text(at(5))]
    assert erases[-1].detail["final"] is True and kinds[kinds.index("erase") + 2] == "archive"
    archive = [s for s in env.seals() if s.kind == "archive"][-1]
    assert archive.detail["cause"] == "rewrite" and archive.detail["after_seq"] == erases[-1].seq
    # Hour 5 had no nonces: alice's row there now carries its derived nonce, and the block keeps no salt of it.
    with env.session() as db:
        block = db.query(AuditArchiveBlock).one()
        assert at(5) not in arc.open_part(db, block.day, env.st.view.archives[block.day].parts[0]).salts
    report = env.verify()
    assert failures(report) == [], report.findings


def test_an_erased_row_changed_in_a_block_is_found(env, monkeypatch):
    ids = _archived_day(env)
    _due(env)
    with env.session() as db:
        view = env.st.view
        parts = list(view.archived_parts())
        assert arc.block_problems(db, view) == []
    # A key holder who rewrites the block (and its archive seal) with the old name back is still found: the erase
    # seal's c_next does not match.
    from app.core import audit_archive_format as af
    with ai.ChainWriter(env.engine, env.st) as w:
        day, part = parts[0]
        block = arc.open_part(w.db, day, part)
        rows = list(block.rows())
        bw = af.BlockWriter(day, part.part, block.salts)
        for row in rows:
            if row["id"] == ids["eve"][0]:
                row = dict(row, ip_address="203.0.113.9")
            bw.add(row)
        payload = bw.finish()
        w.db.query(AuditArchiveBlock).filter(AuditArchiveBlock.day == day).update(
            {AuditArchiveBlock.payload: payload, AuditArchiveBlock.aggregates: bw.aggregates},
            synchronize_session=False)
        new = arc.ArchivePart(part.part, part.first_hour, part.last_hour, bw.rows, len(payload), af.digest(payload))
        arc._write_archive_seal(w, day, "archive", [new])
    assert "unjustified" in failures(env.verify())


def test_an_hour_an_erase_changed_is_archived_and_pruned_like_any(monkeypatch, tmp_path):
    """The erase runs while the hour is still rows (archiving starts 14 days after the chain's first start); once
    archiving starts the erased hour goes into a block like any other, verify reads its erased row back, and the
    audit job deletes archived rows of that hour."""
    from app.core import audit_chain_prune
    env = EraseEnv(monkeypatch, tmp_path, audit_archive_start_after_days=14)
    arc._marker_checked.clear()
    arc._figures.clear()
    try:
        rows = [_put(env, at(3, 5)), _put(env, at(3, 15), username="alice")]
        env.run_until_sealed()
        asked = _due(env)
        assert _blocks(env) == [] and _rows(env, id=rows[0])[0].username == asked["placeholder"]
        env.passes(24 * 8)                          # archiving begins
        assert len(_blocks(env)) == 1 and _rows(env, id=rows[0]) == []
        assert _block_rows(env)[rows[0]]["username"] == asked["placeholder"]
        assert failures(env.verify()) == []
        p = retention.Pass(env.session, now=env.clock())
        audit_chain_prune.prune(p, [AuditLog.username == "alice"], reason="retention",
                                archived=lambda m: [m.username == "alice"], before=env.clock())
        assert set(_block_rows(env)) == {rows[0]}
        assert failures(env.verify()) == []
    finally:
        env.close()


def test_a_block_whose_erased_row_is_not_what_its_erase_seal_says_is_found(env):
    """Reading a block, an erased row must hold the placeholder and values whose commitment is the erase seal's
    c_next: the roots alone cannot tell, since the row counts by its commitment before the erase."""
    ids = _archived_day(env)
    asked = _due(env)
    with env.session() as db:
        view = env.st.view
        day, part = list(view.archived_parts())[0]
        hours = arc.hours_between(part.first_hour, part.last_hour)
        entries = {h: arc.erase_entries(db, view, h) for h in hours}
        c_prev = {h: {rid: e[0] for rid, e in es.items()} for h, es in entries.items()}
        right = {h: {rid: (e[1], e[2]) for rid, e in es.items()} for h, es in entries.items()}
        assert ids["eve"][0] in right[at(3)]
        arc.PartReader(db, view, day, part, c_prev=c_prev, erased=right).finish()
        for bad in ((bytes(32), asked["placeholder"]), (right[at(3)][ids["eve"][0]][0], "erased-ffffffff")):
            wrong = {h: dict(v) for h, v in right.items()}
            wrong[at(3)][ids["eve"][0]] = bad
            with pytest.raises(arc.NotVerified) as nv:
                arc.PartReader(db, view, day, part, c_prev=c_prev, erased=wrong).finish()
            assert nv.value.kind == "unjustified"
