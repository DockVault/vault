"""Legal holds and compliance cases hold back what the audit log's integrity work changes or deletes, offline, on a
throwaway SQLite database with a chain of its own (tests/_removal_env.py) and the compliance tables.

- The rule compliance access registers with person_erase.register_wait (compliance_retention.holds_back) says why
  everything waits while any legal hold stands or any case is open, and nothing once neither does; it is registered
  wherever person_erase is imported.
- Each path waits under a standing hold, with nothing changed, and goes on once the hold is released and its case
  closed: an erase of rows and of an archived day, and of the other records (person_erase.STORES); the deletion of
  an ended erase's sealed name (a cancel, a veto by the database), which the erase job makes once nothing holds it;
  a removal of earlier values, as rows and in archived days; the shortening of addresses, as rows and in archived
  days; the deletion of ended invitations, ended one-time proofs and old notifications.
- A compliance case's rows that must be kept (compliance_retention.case_rows_kept) stay as they are where an
  erase, a removal or the shortening would change them; the archive leaves a day that holds one as rows, and takes
  it once they may go; the audit job's prune of an archived day keeps them in its blocks.
"""
import subprocess
import sys
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa

from _audit_chain_env import T0, failures
from _erase_env import add_tables
from _removal_env import RemovalEnv, until
from app.core import audit_archive as arc
from app.core import audit_privacy as ap
from app.core import audit_retention as ar
from app.core import audit_rewrite as rw
from app.core import audit_value_removal as vr
from app.core import compliance_retention as cr
from app.core import person_erase as pe
from app.core import retention
from app.core import working_records as wr
from app.core.models import (AccountInvitation, AuditArchiveBlock, AuditLog, ComplianceCase, EmailChangeCode,
                             EraseRequest, LegalHoldVault, Notification, OtpCode, PasswordResetToken,
                             SecurityRecord)

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
LOWER = {ap.NAMES: ap.FULL, ap.SIGNIN_NAMES: ap.FULL, ap.EMAILS: ap.NONE, ap.IP: ap.SHORTENED,
         ap.USER_AGENT: ap.NONE}
# Compliance access's own jobs need tables these tests do not make; they are not under test here.
COMPLIANCE_JOBS = ("auditor_grants", "compliance_cases", "legal_holds", "owner_notices")
FLOOR_DAYS = 365


def _env(monkeypatch, tmp_path, **kw):
    e = RemovalEnv(monkeypatch, tmp_path, levels=LOWER, audit_archive_start_after_days=0,
                   compliance_record_min_days=FLOOR_DAYS, **kw)
    add_tables(e.engine, (ComplianceCase, LegalHoldVault, PasswordResetToken, OtpCode, EmailChangeCode))
    monkeypatch.setattr(pe, "WAIT_RULES", [cr.holds_back])
    monkeypatch.setattr(retention, "KEEP_RULES", {"audit_logs": [cr.case_rows_kept]})
    monkeypatch.setattr(retention, "AS_IS_RULES", {"audit_logs": [cr.case_rows_kept]})
    monkeypatch.setattr(retention, "JOBS", [j for j in retention.JOBS if j.name not in COMPLIANCE_JOBS])
    arc._marker_checked.clear()
    arc._figures.clear()
    return e


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = _env(monkeypatch, tmp_path)
    yield e
    e.close()


@pytest.fixture
def env30(monkeypatch, tmp_path):
    """Addresses kept in full for 30 days."""
    e = _env(monkeypatch, tmp_path, audit_ip_full_days=30)
    monkeypatch.setenv("AUDIT_IP_FULL_DAYS", "30")
    yield e
    e.close()


def _case(env, *, closed_days=None):
    """A compliance case: open, or closed ``closed_days`` before the test's clock."""
    case_id = uuid.uuid4()
    with env.session() as db:
        db.add(ComplianceCase(id=case_id, status="closed" if closed_days is not None else "active",
                              purpose="internal_investigation", legal_basis="f", justification_enc="x",
                              owner_note_enc="x", auditor_id=uuid.uuid4(), auditor_username="aud",
                              closed_at=None if closed_days is None else T0 - timedelta(days=closed_days)))
        db.commit()
    return case_id


def _hold(env, case_id):
    """A legal hold of the case, placed and confirmed, standing."""
    vault = uuid.uuid4()
    with env.session() as db:
        db.add(LegalHoldVault(case_id=case_id, vault_id=vault, placed_by_username="aud",
                              placed_at=T0 - timedelta(days=500), confirmed_by_username="bea",
                              confirmed_at=T0 - timedelta(days=499)))
        db.commit()
    return vault


def _release(env, case_id):
    with env.session() as db:
        db.query(LegalHoldVault).filter(LegalHoldVault.case_id == case_id).update(
            {LegalHoldVault.released_at: env.clock(), LegalHoldVault.released_by_username: "bea"},
            synchronize_session=False)
        db.commit()


def _close(env, case_id, days):
    with env.session() as db:
        db.query(ComplianceCase).filter(ComplianceCase.id == case_id).update(
            {ComplianceCase.status: "closed", ComplianceCase.closed_at: env.clock() - timedelta(days=days)},
            synchronize_session=False)
        db.commit()


def _held(env):
    """A case closed long ago (past the records' floor) with a hold that stands."""
    case = _case(env, closed_days=FLOOR_DAYS + 100)
    _hold(env, case)
    return case


def _at(day, hour, minute=0):
    return (T0 - timedelta(days=day)).replace(hour=hour, minute=minute)


# --------------------------------------------------------------------------- the rule

def test_the_rule_says_why_while_a_hold_stands_or_a_case_is_open_and_nothing_once_neither_does(env):
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) is None
    case = _held(env)
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) == "a legal hold stands"
        assert pe.rule_waits(db, env.clock()) == "a legal hold stands"
    _release(env, case)
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) is None
    open_case = _case(env)
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) == "a compliance case is open"
    _close(env, open_case, 1)
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) is None
    lapsed = _held(env)
    with env.session() as db:
        db.query(LegalHoldVault).filter(LegalHoldVault.case_id == lapsed).update(
            {LegalHoldVault.lapsed_at: env.clock(), LegalHoldVault.released_at: env.clock()},
            synchronize_session=False)
        db.commit()
        assert cr.holds_back(db, env.clock()) is None


def test_the_rule_is_registered_wherever_the_erase_is_imported():
    """In a process of its own, importing person_erase alone registers compliance access's rule, and its rows kept as
    they are: no path that asks rule_waits runs without them."""
    script = ("import sys; sys.path.insert(0, 'tests'); from _bare_api_env import set_bare_api_env; "
              "set_bare_api_env(); from app.core import person_erase as pe; from app.core import retention; "
              "print([r.__module__ + '.' + r.__name__ for r in pe.WAIT_RULES]); "
              "print([r.__module__ + '.' + r.__name__ for r in retention.AS_IS_RULES['audit_logs']])")
    out = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr[-600:]
    assert out.stdout.split("\n")[:2] == ["['app.core.compliance_retention.holds_back']",
                                          "['app.core.compliance_retention.case_rows_kept']"]
    assert pe.WAIT_MODULES == ("app.core.compliance_retention",)


def test_a_rule_that_cannot_be_read_holds_everything_back(env, monkeypatch):
    """compliance_retention.holds_back on a database without the compliance tables raises: rule_waits keeps the
    records, as for any rule that cannot tell."""
    with env.session() as db:
        db.execute(sa.text("DROP TABLE legal_hold_vaults"))
        db.commit()
    with env.session() as db:
        assert "could not be read" in pe.rule_waits(db, env.clock())


# --------------------------------------------------------------------------- an erase (rows, archived days, stores)

def _store_rows(env, name):
    with env.session() as db:
        rid = uuid.uuid4()
        db.add(SecurityRecord(id=rid, at=env.clock() - timedelta(days=2), kind="login_failure", name=name,
                              address="198.51.100.4"))
        db.commit()
    return rid


@pytest.mark.parametrize("archived", [False, True], ids=["rows", "an archived day"])
def test_an_erase_waits_while_a_hold_stands_and_runs_once_it_is_released(env, archived):
    when = _at(120, 3) if archived else T0 - timedelta(hours=30)
    mine = [env.put(when, username="eve"), env.put(when + timedelta(minutes=10), username="eve")]
    other = env.put(when + timedelta(minutes=20))
    env.run_until_sealed()
    if archived:
        arc.archive_job(retention.Pass(env.session, now=env.clock()))
        with env.session() as db:
            assert db.query(AuditArchiveBlock).count() == 1
    record = _store_rows(env, "eve")
    case = _held(env)
    asked = env.ask("eve")
    env.passes(24 * 9)
    row = env.request_row(asked["id"])
    assert row.status == pe.PENDING and row.waiting == "It waits: a legal hold stands."
    assert env.erase_seals() == []
    with env.session() as db:
        assert db.get(SecurityRecord, record).name == "eve"
    if not archived:
        assert {env.get(i).username for i in mine} == {"eve"}
    _release(env, case)
    assert until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED)
    placeholder = asked["placeholder"]
    if archived:
        with env.session() as db:
            block = db.query(AuditArchiveBlock).one()
            rows = {r["id"]: r for r in arc.PartReader(db, env.st.view, block.day,
                                                       env.st.view.archives[block.day].parts[0]).rows()}
        assert {rows[i]["username"] for i in mine} == {placeholder} and rows[other]["username"] == "alice"
    else:
        assert {env.get(i).username for i in mine} == {placeholder} and env.get(other).username == "alice"
    with env.session() as db:
        assert db.get(SecurityRecord, record).name == placeholder
    assert env.request_row(asked["id"]).name_token is None
    assert failures(env.verify()) == []


def test_an_open_case_holds_an_erase_back(env):
    env.put(T0 - timedelta(hours=30), username="eve")
    env.run_until_sealed()
    case = _case(env)
    asked = env.ask("eve")
    env.passes(24 * 9)
    assert env.request_row(asked["id"]).waiting == "It waits: a compliance case is open."
    assert env.erase_seals() == []
    _close(env, case, FLOOR_DAYS + 1)
    assert until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED)


def test_an_erase_that_meets_a_hold_between_two_units_waits_there_and_completes_after(env, monkeypatch):
    """A hold placed after an erase has begun stops it at its next unit: what was erased stays erased, nothing more
    changes while the hold stands, and it completes once the hold is released."""
    first = env.put(T0 - timedelta(hours=40), username="eve")
    second = env.put(T0 - timedelta(hours=20), username="eve")
    env.run_until_sealed()
    asked = env.ask("eve")
    waiting = _case(env)                                      # its delay runs while an open case holds it back
    env.passes(24 * 7 + 6)
    _close(env, waiting, FLOOR_DAYS + 1)
    real = retention.Pass.time_left
    calls = {"n": 0}

    def one_unit(self):
        calls["n"] += 1
        return calls["n"] <= 1
    monkeypatch.setattr(retention.Pass, "time_left", one_unit)
    env.erase_job()
    monkeypatch.setattr(retention.Pass, "time_left", real)
    assert env.get(first).username == asked["placeholder"] and env.get(second).username == "eve"
    case = _held(env)
    env.passes(24 * 2)
    assert env.get(second).username == "eve" and env.request_row(asked["id"]).status == pe.RUNNING
    assert env.request_row(asked["id"]).waiting == "It waits: a legal hold stands."
    _release(env, case)
    assert until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED)
    assert env.get(second).username == asked["placeholder"]


def test_a_cases_rows_that_must_be_kept_are_not_erased(env):
    """A row of the name written under a case closed within the records' floor stays as it is; the erase completes and
    erases the rest, and the chain still verifies."""
    case = _case(env, closed_days=30)
    kept = env.put(T0 - timedelta(hours=30), username="eve", case_id=case)
    gone = env.put(T0 - timedelta(hours=30, minutes=-10), username="eve")
    env.run_until_sealed()
    asked = env.ask("eve")
    assert until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED)
    assert env.get(kept).username == "eve" and env.get(kept).ip_address == "203.0.113.9"
    assert env.get(gone).username == asked["placeholder"]
    assert failures(env.verify()) == []


def test_the_preview_counts_a_cases_rows_that_must_be_kept_apart(env):
    case = _case(env, closed_days=30)
    env.put(T0 - timedelta(hours=30), username="eve", case_id=case)
    env.put(T0 - timedelta(hours=29), username="eve")
    env.run_until_sealed()
    with env.session() as db:
        seen = pe.preview(db, "eve", env.clock(), env.st)
    assert seen["audit_rows"] == 1
    assert ("1 audit rows of a compliance case whose records must be kept, which stay as they are"
            in seen["not_reached"]), seen["not_reached"]


def test_a_cases_rows_in_an_archived_day_are_not_erased(env, monkeypatch):
    """A case row archived while nothing kept it (its case closed long ago), then kept again (the floor raised): an
    erase over the archived day leaves it as it is."""
    case = _case(env, closed_days=FLOOR_DAYS + 30)
    kept = env.put(_at(120, 3), username="eve", case_id=case)
    gone = env.put(_at(120, 3, 20), username="eve")
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    env.settings.compliance_record_min_days = FLOOR_DAYS + 60
    asked = env.ask("eve")
    assert until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED)
    with env.session() as db:
        block = db.query(AuditArchiveBlock).one()
        rows = {r["id"]: r for r in arc.PartReader(db, env.st.view, block.day,
                                                   env.st.view.archives[block.day].parts[0]).rows()}
    assert rows[kept]["username"] == "eve" and rows[gone]["username"] == asked["placeholder"]
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- an erase's sealed name

def test_a_cancel_under_a_hold_keeps_the_sealed_name_until_the_erase_job_finds_nothing_holding_it(env):
    env.put(T0 - timedelta(hours=30), username="eve")
    env.run_until_sealed()
    asked = env.ask("eve")
    case = _held(env)
    env.cancel(asked["id"], env.admin("bea"))
    row = env.request_row(asked["id"])
    assert row.status == pe.CANCELLED and row.name_token
    env.erase_job()
    assert env.request_row(asked["id"]).name_token
    _release(env, case)
    env.erase_job()
    assert env.request_row(asked["id"]).name_token is None


def test_a_veto_under_a_hold_keeps_the_sealed_name_until_nothing_holds_it(env):
    """The database marking a waiting erase cancelled vetoes it (a cancel seal by the database); under a hold its sealed
    name stays, and goes once the hold is released."""
    env.put(T0 - timedelta(hours=30), username="eve")
    env.run_until_sealed()
    asked = env.ask("eve")
    case = _held(env)
    with env.session() as db:
        db.query(EraseRequest).filter(EraseRequest.id == uuid.UUID(asked["id"])).update(
            {EraseRequest.status: pe.CANCELLED}, synchronize_session=False)
        db.commit()
    env.erase_job()
    assert [s.detail["by"] for s in env.seals() if s.kind == "cancel"] == ["database"]
    assert env.request_row(asked["id"]).name_token
    _release(env, case)
    env.erase_job()
    assert env.request_row(asked["id"]).name_token is None


def test_a_cancel_while_sealing_is_stopped_under_a_hold_keeps_the_sealed_name_too(env):
    env.put(T0 - timedelta(hours=30), username="eve")
    env.run_until_sealed()
    asked = env.ask("eve")
    case = _held(env)
    with env.session() as db:
        pe.cancel_while_stopped(db, asked["id"], env.admin("bea"), st=env.st)
        db.commit()
    row = env.request_row(asked["id"])
    assert row.status == pe.CANCELLED and row.name_token
    _release(env, case)
    env.passes(6)                                         # the next pass seals the cancel, then the name goes
    env.erase_job()
    assert env.request_row(asked["id"]).name_token is None


def test_a_cancel_with_nothing_holding_deletes_the_sealed_name_at_once(env):
    env.put(T0 - timedelta(hours=30), username="eve")
    env.run_until_sealed()
    asked = env.ask("eve")
    env.cancel(asked["id"], env.admin("bea"))
    assert env.request_row(asked["id"]).name_token is None


# --------------------------------------------------------------------------- a removal of earlier values

def test_a_removal_waits_while_a_hold_stands_over_rows_and_archived_days_and_runs_after(env):
    archived = env.put(_at(120, 3))
    hot = env.put(T0 - timedelta(hours=30))
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        block = db.query(AuditArchiveBlock).one()
        payload = bytes(block.payload)
    case = _held(env)
    asked = env.ask_removal()
    env.week()
    env.passes(24)
    row = env.removal_row(asked["id"])
    assert row.status == vr.PENDING and row.waiting == "It waits: a legal hold stands."
    assert env.rewrite_seals() == [] and env.get(hot).ip_address == "203.0.113.9"
    with env.session() as db:
        assert bytes(db.query(AuditArchiveBlock).one().payload) == payload
    _release(env, case)
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    assert env.get(hot).ip_address is None
    with env.session() as db:
        block = db.query(AuditArchiveBlock).one()
        rows = {r["id"]: r for r in arc.PartReader(db, env.st.view, block.day,
                                                   env.st.view.archives[block.day].parts[0]).rows()}
    assert rows[archived]["ip_address"] is None
    assert failures(env.verify()) == []


def test_a_removal_leaves_a_cases_rows_that_must_be_kept_as_they_are(env):
    case = _case(env, closed_days=30)
    kept = env.put(T0 - timedelta(hours=30), case_id=case, details={"email": "a@example.com"})
    gone = env.put(T0 - timedelta(hours=30, minutes=-10), details={"email": "b@example.com"})
    env.run_until_sealed()
    asked = env.ask_removal()
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    assert env.get(kept).ip_address == "203.0.113.9" and env.get(kept).details == {"email": "a@example.com"}
    assert env.get(gone).ip_address is None and "email" not in (env.get(gone).details or {})
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- the shortening of addresses

def test_the_shortening_waits_while_a_hold_stands_over_rows_and_archived_days_and_runs_after(env30):
    env = env30
    archived = env.put(_at(120, 3))
    hot = env.put(T0 - timedelta(days=40))
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        payload = bytes(db.query(AuditArchiveBlock).one().payload)
    case = _held(env)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(hot).ip_address == "203.0.113.9" and env.rewrite_seals() == []
    with env.session() as db:
        assert bytes(db.query(AuditArchiveBlock).one().payload) == payload
    _release(env, case)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(hot).ip_address is None and (env.get(hot).recorded or {}).get("ip") == "203.0.113.0/24"
    with env.session() as db:
        block = db.query(AuditArchiveBlock).one()
        rows = {r["id"]: r for r in arc.PartReader(db, env.st.view, block.day,
                                                   env.st.view.archives[block.day].parts[0]).rows()}
    assert rows[archived]["ip_address"] is None
    assert failures(env.verify()) == []


def test_the_shortening_leaves_a_cases_rows_that_must_be_kept_as_they_are(env30):
    env = env30
    case = _case(env, closed_days=30)
    kept = env.put(T0 - timedelta(days=40), case_id=case)
    gone = env.put(T0 - timedelta(days=40, minutes=-10))
    env.run_until_sealed()
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(kept).ip_address == "203.0.113.9"
    assert env.get(gone).ip_address is None
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- the archive and the audit job's prune

def _blocks(env):
    with env.session() as db:
        return db.query(AuditArchiveBlock).count()


def test_the_archive_leaves_a_day_with_a_held_cases_rows_as_rows_and_takes_it_once_they_may_go(env):
    case = _held(env)
    row = env.put(_at(120, 3), case_id=case)
    other = env.put(_at(120, 4))
    later = env.put(_at(110, 3))
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        assert {r[0] for r in db.query(AuditLog.id).filter(AuditLog.id.in_([row, other])).all()} == {row, other}
        assert db.get(AuditLog, later) is None                       # the next day, which holds none, is archived
    assert _blocks(env) == 1
    _release(env, case)
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.id.in_([row, other, later])).count() == 0
    assert _blocks(env) == 2
    assert failures(env.verify()) == []


def test_the_archive_leaves_an_open_cases_rows_as_rows(env):
    case = _case(env)
    row = env.put(_at(120, 3), case_id=case)
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(row) is not None and _blocks(env) == 0
    _close(env, case, FLOOR_DAYS + 1)
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(row) is None and _blocks(env) == 1


def test_the_audit_jobs_prune_of_an_archived_day_keeps_a_held_cases_rows(env):
    """A day archived while nothing kept its case row; then a hold of the case stands (its release undone, say): the
    prune by age rewrites the day's block without the other rows and keeps that one, and takes it once the hold is
    released."""
    case = _case(env, closed_days=FLOOR_DAYS + 100)
    row = env.put(_at(120, 3), case_id=case)
    other = env.put(_at(120, 4))
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(row) is None and _blocks(env) == 1
    _hold(env, case)
    ar.prune(retention.Pass(env.session, now=env.clock()), ar.Numbers(100, 0, 0, 0))

    def archived_ids():
        with env.session() as db:
            out = set()
            for day, entry in env.st.view.archives.items():
                for part in entry.parts:
                    out |= {r["id"] for r in arc.PartReader(db, env.st.view, day, part).rows()}
            return out
    assert archived_ids() == {row}
    _release(env, case)
    env.clock.advance(days=1)                     # the audit job reads an archived day once a day
    env.seal()
    ar.prune(retention.Pass(env.session, now=env.clock()), ar.Numbers(100, 0, 0, 0))
    assert row not in archived_ids() and other not in archived_ids()
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- working records

def test_working_records_wait_while_a_hold_stands_and_go_after(env, monkeypatch):
    old = T0 - timedelta(days=60)
    with env.session() as db:
        db.add(AccountInvitation(id=uuid.uuid4(), username="ivy", token_prefix="hhhh", token_hash="h" * 64,
                                 role="user", created_at=old, expires_at=old + timedelta(days=1), revoked_at=old))
        db.add(PasswordResetToken(id=uuid.uuid4(), user_id=uuid.uuid4(), token_prefix="rrrr", token_hash="r" * 64,
                                  created_at=old, expires_at=old + timedelta(hours=1)))
        db.add(Notification(id=uuid.uuid4(), user_id=uuid.uuid4(), type="info", title="t", body="b",
                            is_read=False, created_at=old))
        db.commit()
    monkeypatch.setattr(wr, "notification_days", lambda: 30)
    case = _held(env)

    def counts():
        with env.session() as db:
            return [db.query(m).count() for m in (AccountInvitation, PasswordResetToken, Notification)]
    p = retention.Pass(env.session, now=env.clock())
    for job in (wr.prune_invitations, wr.prune_one_time_proofs, wr.prune_notifications):
        job(p)
    assert counts() == [1, 1, 1]
    _release(env, case)
    p = retention.Pass(env.session, now=env.clock())
    for job in (wr.prune_invitations, wr.prune_one_time_proofs, wr.prune_notifications):
        job(p)
    assert counts() == [0, 0, 0]


# --------------------------------------------------------------------------- the turn of holds and deletions

class _Postgres:
    """A session on Postgres that records what it is asked to run."""

    def __init__(self):
        self.sql = []

    def get_bind(self):
        from types import SimpleNamespace
        return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    def execute(self, statement, params=None):
        self.sql.append((str(statement), params))


def test_the_turn_is_a_transaction_lock_shared_by_deletions_and_exclusive_for_a_hold_or_a_case():
    from app.core import legal_holds
    db = _Postgres()
    legal_holds.take_turn(db, shared=True)
    legal_holds.take_turn(db, shared=False)
    params = {"c": legal_holds.HOLD_TURN[0], "k": legal_holds.HOLD_TURN[1]}
    assert db.sql == [("SELECT pg_advisory_xact_lock_shared(:c, :k)", params),
                      ("SELECT pg_advisory_xact_lock(:c, :k)", params)]


def test_the_check_takes_the_turn_before_it_reads_and_every_step_that_makes_a_hold_stand_before_it_writes():
    import inspect
    from app.core import cases
    from app.core import legal_holds
    check = inspect.getsource(cr.holds_back)
    assert check.count("legal_holds.take_turn(db, shared=True)") == 1
    assert check.index("legal_holds.take_turn(db, shared=True)") < check.index("db.query(")
    place = inspect.getsource(legal_holds.place_hold_only)
    assert place.count("take_turn(db, shared=False)") == 1
    assert place.index("take_turn(db, shared=False)") < place.index("ComplianceCase(")
    undo = inspect.getsource(legal_holds.undo_release)
    assert undo.count("take_turn(db, shared=False)") == 1
    assert undo.index("take_turn(db, shared=False)") < undo.index("hold.released_at = ")
    ask = inspect.getsource(cases.request_case)
    assert ask.count("legal_holds.take_turn(db, shared=False)") == 1
    assert ask.index("legal_holds.take_turn(db, shared=False)") < ask.index("case = ComplianceCase(")
