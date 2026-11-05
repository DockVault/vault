"""Legal holds and compliance cases hold back what the audit log's integrity work changes or deletes, offline, on a
throwaway SQLite database with a chain of its own (tests/_removal_env.py) and the compliance tables.

- The rule compliance access registers with person_erase.register_wait (compliance_retention.holds_back) says why
  everything waits while any confirmed legal hold stands or any case is open, and nothing once neither does (a
  hold-only case whose hold nobody has confirmed yet holds nothing back); it is registered wherever person_erase is
  imported.
- Each path waits under a standing hold, with nothing changed, and goes on once the hold is released and its case
  closed: an erase of rows and of an archived day, and of the other records (person_erase.STORES); the deletion of
  an ended erase's sealed name (a cancel, a veto by the database), which the erase job makes once nothing holds it;
  a removal of earlier values, as rows and in archived days; the shortening of addresses, as rows and in archived
  days; the deletion of ended invitations, ended one-time proofs and old notifications.
- A compliance case's rows that must be kept (compliance_retention.case_rows_kept) stay as they are where an
  erase, a removal or the shortening would change them; the archive leaves a day that holds one as rows, and takes
  it once they may go; the audit job's prune of an archived day keeps them in its blocks. An erase or a removal
  that met such rows stays running and says so until the case lets them go, then changes them and completes; the
  shortening goes back to them once the case lets them go, as rows or in an archived day, in the same process.
"""
import json
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
from app.core import audit_chain_erase as ae
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


def _case(env, *, closed_days=None, number=None):
    """A compliance case: open, or closed ``closed_days`` before the test's clock (its counts kept on it, as the
    compliance cases' job does 30 days after the close); with ``number`` once approved, none before."""
    case_id = uuid.uuid4()
    closed = None if closed_days is None else T0 - timedelta(days=closed_days)
    with env.session() as db:
        db.add(ComplianceCase(id=case_id, status="closed" if closed_days is not None else "active",
                              purpose="internal_investigation", legal_basis="f", justification_enc="x",
                              owner_note_enc="x", auditor_id=uuid.uuid4(), auditor_username="aud",
                              closed_at=closed, counts_kept_at=closed, number=number))
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
            {ComplianceCase.status: "closed", ComplianceCase.closed_at: env.clock() - timedelta(days=days),
             ComplianceCase.counts_kept_at: env.clock() - timedelta(days=days)},
            synchronize_session=False)
        db.commit()


def _held(env, number=None):
    """A case closed long ago (past the records' floor) with a hold that stands."""
    case = _case(env, closed_days=FLOOR_DAYS + 100, number=number)
    _hold(env, case)
    return case


def _at(day, hour, minute=0):
    return (T0 - timedelta(days=day)).replace(hour=hour, minute=minute)


def _archived_rows(env):
    """Every archived row, by id, as its block holds it now."""
    with env.session() as db:
        out = {}
        for day, entry in env.st.view.archives.items():
            for part in entry.parts:
                out.update({r["id"]: r for r in arc.PartReader(db, env.st.view, day, part).rows()})
        return out


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


def test_a_hold_nobody_confirmed_holds_nothing_back_until_it_is_confirmed(env):
    """One person places a hold-only case alone: until a second person confirms its hold, no erase or other
    deletion of records waits for it (it keeps what is deleted from its vaults all the same). Confirmed, it holds
    back as any other. A case asking for access holds back from its request on, unconfirmed hold or not."""
    case_id, vault = uuid.uuid4(), uuid.uuid4()
    with env.session() as db:
        db.add(ComplianceCase(id=case_id, status="hold_only", purpose="litigation_hold", legal_basis="c",
                              justification_enc="x", owner_note_enc="x", auditor_id=uuid.uuid4(),
                              auditor_username="ada", number="C-2026-0301"))
        db.add(LegalHoldVault(case_id=case_id, vault_id=vault, placed_by_username="ada", placed_at=env.clock(),
                              confirm_by_deadline=env.clock() + timedelta(days=7)))
        db.commit()
        assert cr.holds_back(db, env.clock()) is None
        assert pe.rule_waits(db, env.clock()) is None
        db.query(LegalHoldVault).filter(LegalHoldVault.case_id == case_id).update(
            {LegalHoldVault.confirmed_at: env.clock(), LegalHoldVault.confirmed_by_username: "bob"},
            synchronize_session=False)
        db.commit()
        assert cr.holds_back(db, env.clock()) == "the legal hold of case C-2026-0301 stands"
        db.query(LegalHoldVault).update({LegalHoldVault.released_at: env.clock()}, synchronize_session=False)
        db.query(ComplianceCase).filter(ComplianceCase.id == case_id).update(
            {ComplianceCase.status: "closed", ComplianceCase.closed_at: env.clock()}, synchronize_session=False)
        db.commit()
        assert cr.holds_back(db, env.clock()) is None
    asked = _case(env)
    with env.session() as db:
        db.query(ComplianceCase).filter(ComplianceCase.id == asked).update(
            {ComplianceCase.status: "pending"}, synchronize_session=False)
        db.commit()
        assert cr.holds_back(db, env.clock()) == "a compliance case is open"


def test_the_rule_names_the_cases_it_waits_for(env):
    """What waits shows the reason to the administrators, who see the cases: it names the case of each hold that
    stands, then of each open case, at most three and then how many more. A case not yet approved has no number."""
    first = _held(env, "C-2026-0101")
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) == "the legal hold of case C-2026-0101 stands"
    _held(env, "C-2026-0102")
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) == "the legal holds of cases C-2026-0101 and C-2026-0102 stand"
    _hold(env, first)                                           # a second vault of the same case: still one case
    _held(env, "C-2026-0103")
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) == ("the legal holds of cases C-2026-0101, C-2026-0102 and "
                                                  "C-2026-0103 stand")
    _held(env, "C-2026-0104")
    _held(env)
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) == ("the legal holds of cases C-2026-0101, C-2026-0102, "
                                                  "C-2026-0103 and 2 more stand")
        db.query(LegalHoldVault).update({LegalHoldVault.released_at: env.clock()}, synchronize_session=False)
        db.commit()
    open_case = _case(env, number="C-2026-0201")
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) == "case C-2026-0201 is open"
    _case(env)                                                  # requested, not approved yet
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) == "cases C-2026-0201 and 1 more are open"
    _close(env, open_case, 1)
    _case(env)
    with env.session() as db:
        assert cr.holds_back(db, env.clock()) == "compliance cases are open"


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


def test_an_erase_says_which_case_it_waits_for(env):
    """The erase's waiting text names the case whose hold stands, then the case that is open, as each holds it."""
    env.put(T0 - timedelta(hours=30), username="eve")
    env.run_until_sealed()
    held = _held(env, "C-2026-0301")
    open_case = _case(env, number="C-2026-0302")
    asked = env.ask("eve")
    env.passes(24 * 9)
    assert env.request_row(asked["id"]).waiting == "It waits: the legal hold of case C-2026-0301 stands."
    _release(env, held)
    env.passes(2)
    row = env.request_row(asked["id"])
    assert row.status == pe.PENDING and row.waiting == "It waits: case C-2026-0302 is open."
    _close(env, open_case, FLOOR_DAYS + 1)
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


def test_a_cases_rows_that_must_be_kept_are_not_erased_until_the_case_lets_them_go(env):
    """A row of the name written under a case closed within the records' floor stays as it is: the erase erases the
    rest and gives the other records the placeholder, then stays running, says why and keeps the name sealed. Once
    the case lets the row go, the erase erases it and completes; the chain verifies throughout."""
    case = _case(env, closed_days=30)
    kept = env.put(T0 - timedelta(hours=30), username="eve", case_id=case)
    gone = env.put(T0 - timedelta(hours=30, minutes=-10), username="eve")
    env.run_until_sealed()
    record = _store_rows(env, "eve")
    asked = env.ask("eve")
    assert not until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED, hours=24 * 12)
    row = env.request_row(asked["id"])
    assert row.status == pe.RUNNING and row.waiting == ae.KEPT_WAIT.format(n=1) and row.name_token
    assert env.get(kept).username == "eve" and env.get(kept).ip_address == "203.0.113.9"
    assert env.get(gone).username == asked["placeholder"]
    with env.session() as db:
        assert db.get(SecurityRecord, record).name == asked["placeholder"]
    assert [s.detail.get("final") for s in env.erase_seals()] == [False]
    assert failures(env.verify()) == []
    _close(env, case, FLOOR_DAYS + 1)                         # its records' floor has passed: it lets the row go
    assert until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED)
    assert env.get(kept).username == asked["placeholder"] and env.get(kept).ip_address is None
    row = env.request_row(asked["id"])
    assert row.name_token is None and row.counts["audit_rows"] == 2 and row.counts["stores"]["security_records"] == 1
    assert [s.detail.get("final") for s in env.erase_seals()] == [False, True]
    assert failures(env.verify()) == []


def test_the_preview_counts_a_cases_rows_that_must_be_kept_apart(env):
    case = _case(env, closed_days=30)
    env.put(T0 - timedelta(hours=30), username="eve", case_id=case)
    env.put(T0 - timedelta(hours=29), username="eve")
    env.run_until_sealed()
    with env.session() as db:
        seen = pe.preview(db, "eve", env.clock(), env.st)
    assert seen["audit_rows"] == 1
    assert any(n.startswith("1 audit rows of a compliance case whose records must be kept, which stay as they are "
                            "until the case lets them go") for n in seen["not_reached"]), seen["not_reached"]


def test_a_cases_rows_in_an_archived_day_are_not_erased_until_the_case_lets_them_go(env, monkeypatch):
    """A case row archived while nothing kept it (its case closed long ago), then kept again (the floor raised): an
    erase over the archived day leaves it as it is and waits; once the floor is back, the day is read again and the
    row erased, and the erase completes."""
    case = _case(env, closed_days=FLOOR_DAYS + 30)
    kept = env.put(_at(120, 3), username="eve", case_id=case)
    gone = env.put(_at(120, 3, 20), username="eve")
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    env.settings.compliance_record_min_days = FLOOR_DAYS + 60
    asked = env.ask("eve")
    assert not until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED, hours=24 * 12)
    assert env.request_row(asked["id"]).waiting == ae.KEPT_WAIT.format(n=1)
    rows = _archived_rows(env)
    assert rows[kept]["username"] == "eve" and rows[gone]["username"] == asked["placeholder"]
    assert failures(env.verify()) == []
    env.settings.compliance_record_min_days = FLOOR_DAYS
    assert until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED)
    assert _archived_rows(env)[kept]["username"] == asked["placeholder"]
    assert failures(env.verify()) == []


def test_an_archived_day_whose_only_rows_of_the_name_must_be_kept_is_not_a_unit_of_the_erase(env):
    """An archived day whose rows of the name are all a case's rows that must be kept holds nothing the erase may
    change: it is not counted as a day with rows of the name (else the erase would try it, change nothing, and
    stop on a day it cannot finish), and the erase completes with the rest of the name erased."""
    case = _case(env, closed_days=FLOOR_DAYS + 30)
    kept = env.put(_at(120, 3), username="eve", case_id=case)
    other = env.put(_at(120, 4))
    hot = env.put(T0 - timedelta(hours=30), username="eve")
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    env.settings.compliance_record_min_days = FLOOR_DAYS + 200
    asked = env.ask("eve")
    assert not until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED, hours=24 * 12)
    assert env.get(hot).username == asked["placeholder"]
    assert env.request_row(asked["id"]).waiting == ae.KEPT_WAIT.format(n=1)
    rows = _archived_rows(env)
    assert rows[kept]["username"] == "eve" and rows[other]["username"] == "alice"
    assert failures(env.verify()) == []


def test_an_erase_whose_only_rows_a_case_keeps_does_not_begin_until_the_case_lets_them_go(env):
    """Nothing it may change yet: it does not begin (no seal, the other records untouched, still cancellable) and
    says why; once the case lets the rows go, it runs and completes."""
    case = _case(env, closed_days=30)
    kept = env.put(T0 - timedelta(hours=30), username="eve", case_id=case)
    env.run_until_sealed()
    record = _store_rows(env, "eve")
    asked = env.ask("eve")
    assert not until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED, hours=24 * 12)
    row = env.request_row(asked["id"])
    assert row.status == pe.PENDING and row.waiting == ae.KEPT_WAIT_TO_BEGIN.format(n=1)
    assert env.erase_seals() == [] and env.get(kept).username == "eve"
    with env.session() as db:
        assert db.get(SecurityRecord, record).name == "eve"
    _close(env, case, FLOOR_DAYS + 1)
    assert until(env, lambda: env.request_row(asked["id"]).status == pe.COMPLETED)
    assert env.get(kept).username == asked["placeholder"]
    with env.session() as db:
        assert db.get(SecurityRecord, record).name == asked["placeholder"]
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


def test_a_removal_leaves_a_cases_rows_that_must_be_kept_as_they_are_until_the_case_lets_them_go(env):
    """The removal changes the rest and stays running, saying why, while a case keeps a row of its scope; once the
    case lets it go the removal goes back to it, changes it, and completes."""
    case = _case(env, closed_days=30)
    kept = env.put(T0 - timedelta(hours=30), case_id=case, details={"email": "a@example.com"})
    gone = env.put(T0 - timedelta(hours=30, minutes=-10), details={"email": "b@example.com"})
    later = env.put(T0 - timedelta(hours=20), details={"email": "c@example.com"})
    env.run_until_sealed()
    asked = env.ask_removal()
    assert not until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED, hours=24 * 12)
    row = env.removal_row(asked["id"])
    assert row.status == vr.RUNNING and row.waiting == vr.KEPT_WAIT.format(n=1)
    assert env.get(kept).ip_address == "203.0.113.9" and env.get(kept).details == {"email": "a@example.com"}
    assert env.get(gone).ip_address is None and "email" not in (env.get(gone).details or {})
    assert env.get(later).ip_address is None
    assert not [s for s in env.rewrite_seals() if s.detail.get("final")]
    assert failures(env.verify()) == []
    _close(env, case, FLOOR_DAYS + 1)
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    assert env.get(kept).ip_address is None and "email" not in (env.get(kept).details or {})
    assert [s.detail.get("final") for s in env.rewrite_seals()][-1] is True
    assert failures(env.verify()) == []


def _steps(env, n):
    """A pass with time for ``n`` transactions of a job, so that a run can be taken a unit at a time."""
    p = retention.Pass(env.session, now=env.clock())
    left = {"n": n}

    def time_left():
        left["n"] -= 1
        return left["n"] >= 0
    p.time_left = time_left
    return p


def _removal_past_its_first_unit(env, monkeypatch, day):
    """A row a case keeps and a row beside it in the last hour of a day, ``day`` days ago (so a block of that day
    would end where the run stands after it), a row in a later day, and a removal whose run has taken the first day
    only (the archive idle): it changed the row beside, and left the kept row as it is. Returns the real archive job
    too."""
    real = arc.archive_job
    monkeypatch.setattr(arc, "archive_job", lambda p: retention.JobResult())
    case = _case(env, closed_days=30)
    kept = env.put(_at(day, 23), case_id=case, details={"email": "a@example.com"})
    gone = env.put(_at(day, 23, 10), details={"email": "b@example.com"})
    later = env.put(_at(1, 3), details={"email": "c@example.com"})
    env.run_until_sealed()
    asked = env.ask_removal()
    waiting = _case(env)                                      # its delay runs while an open case holds it back
    env.week()
    _close(env, waiting, FLOOR_DAYS + 1)
    vr.run_job(_steps(env, 1))
    assert env.get(gone).ip_address is None and env.get(kept).ip_address == "203.0.113.9"
    assert env.get(later).ip_address == "203.0.113.9"
    assert env.removal_row(asked["id"]).status == vr.RUNNING
    return case, kept, later, asked, real


def test_a_removal_goes_back_to_a_row_a_case_let_go_after_its_run_passed_it(env, monkeypatch):
    """The case lets the kept row go before the run reaches the end of its scope, so the run never waits there for it:
    it goes back to the row, changes it, and completes."""
    case, kept, later, asked, _real = _removal_past_its_first_unit(env, monkeypatch, 3)
    _close(env, case, FLOOR_DAYS + 1)
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    assert env.get(kept).ip_address is None and "email" not in (env.get(kept).details or {})
    assert env.get(later).ip_address is None
    assert failures(env.verify()) == []


def test_a_removal_reaches_a_row_a_case_let_go_in_the_day_the_archive_moved_it_to(env, monkeypatch):
    """The case lets the kept row go, and the archive moves its day into a block, after the run passed it: the run
    goes back to that day, changes the row in its block, and completes."""
    case, kept, later, asked, real = _removal_past_its_first_unit(env, monkeypatch, 120)
    _close(env, case, FLOOR_DAYS + 1)
    real(retention.Pass(env.session, now=env.clock()))
    assert env.get(kept) is None and _archived_rows(env)[kept]["ip_address"] == "203.0.113.9"
    assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
    row = _archived_rows(env)[kept]
    assert row["ip_address"] is None and "email" not in json.loads(row["details"] or "{}")
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


def _shorten(env):
    env.clock.advance(hours=6)
    env.run_until_sealed()
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))


def test_the_shortening_goes_back_to_a_row_a_case_let_go_after_its_run_passed_it(env30):
    """The run passed a row a closed case kept (within the records' floor) and went on to the cutoff; while the case
    keeps it, the next passes leave it and write nothing. Once the case lets it go, the next pass of the same
    process goes back to it and shortens it: no restart is needed to start the run again from the first hour."""
    env = env30
    case = _case(env, closed_days=30)
    gone = env.put(T0 - timedelta(days=40))
    kept = env.put(T0 - timedelta(days=40, hours=-2), case_id=case)       # in an hour after every other row
    env.run_until_sealed()
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(gone).ip_address is None and env.get(kept).ip_address == "203.0.113.9"
    key = (id(env.st), env.st.view.generation)
    reached = rw._cursors[key]
    assert reached > T0 - timedelta(days=40, hours=-2)
    seals = len(env.rewrite_seals())
    _shorten(env)
    assert env.get(kept).ip_address == "203.0.113.9" and len(env.rewrite_seals()) == seals
    _close(env, case, FLOOR_DAYS + 1)
    at = rw._cursors[key]                       # the run stands at the cutoff, which a pass at this clock keeps
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(kept).ip_address is None and (env.get(kept).recorded or {}).get("ip") == "203.0.113.0/24"
    assert rw._cursors[key] == at > reached
    assert failures(env.verify()) == []


def test_the_shortening_reaches_a_row_a_case_let_go_in_the_day_the_archive_moved_it_to(env30):
    """The case lets the row go after the run passed it, and the archive then moves its day into a block: the next
    pass goes back to that day and shortens the row in its block."""
    env = env30
    case = _case(env, closed_days=30)
    kept = env.put(_at(120, 23), case_id=case)
    gone = env.put(_at(120, 23, 10))
    env.run_until_sealed()
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(kept).ip_address == "203.0.113.9" and env.get(gone).ip_address is None
    _close(env, case, FLOOR_DAYS + 1)
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(kept) is None and _archived_rows(env)[kept]["ip_address"] == "203.0.113.9"
    _shorten(env)
    assert _archived_rows(env)[kept]["ip_address"] is None
    assert failures(env.verify()) == []


def test_the_shortening_goes_back_to_an_archived_days_row_a_case_let_go(env30):
    """A case row archived while nothing kept it, then kept again (the floor raised): the shortening leaves it in its
    block; once the floor is back where it was, the next pass reads the day again and shortens it there."""
    env = env30
    case = _case(env, closed_days=FLOOR_DAYS + 30)
    kept = env.put(_at(120, 3), case_id=case)
    gone = env.put(_at(120, 3, 20))
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(kept) is None and _blocks(env) == 1
    env.settings.compliance_record_min_days = FLOOR_DAYS + 200
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    rows = _archived_rows(env)
    assert rows[kept]["ip_address"] == "203.0.113.9" and rows[gone]["ip_address"] is None
    _shorten(env)
    assert _archived_rows(env)[kept]["ip_address"] == "203.0.113.9"
    env.settings.compliance_record_min_days = FLOOR_DAYS
    _shorten(env)
    assert _archived_rows(env)[kept]["ip_address"] is None
    assert failures(env.verify()) == []


def test_the_shortening_reads_of_a_row_only_the_columns_its_notes_and_its_look_load():
    """The notes and the look load SHORTEN_COLUMNS of a row (the notes grow with what the cases keep, and are looked at
    every pass): shortened() must read nothing else of a row, whatever the row holds."""
    class Seen(dict):
        def __init__(self, row):
            super().__init__(row)
            self.read = set()

        def get(self, k, default=None):
            self.read.add(k)
            return super().get(k, default)

        def __getitem__(self, k):
            self.read.add(k)
            return super().__getitem__(k)
    base = {"id": uuid.uuid4(), "action": "file_uploaded", "status": "success", "username": "alice",
            "user_id": None, "temp_credential_id": None, "user_agent": "Mozilla/5.0 test", "endpoint": "/x"}
    rows = [dict(base, ip_address="203.0.113.9", details={"n": 1}, recorded=None),
            dict(base, ip_address=None, details={"client_ip": "198.51.100.7", "filters": {"ip": "192.0.2.1"}},
                 recorded=None),
            dict(base, ip_address="203.0.113.9", details=None, recorded={"ip": "203.0.113.0/24"}),
            dict(base, ip_address=None, details=None, recorded={"details": {"client_ip": "198.51.100.0/24"}}),
            dict(base, action="login_failed", username="bob@example.com", ip_address="203.0.113.9",
                 details={"email": "bob@example.com", "user_agent": "x"}, recorded=None)]
    for row in rows:
        seen = Seen(row)
        rw.shortened(seen)
        assert seen.read <= set(rw.SHORTEN_COLUMNS), seen.read
    assert rw.shortened(rows[1]) is not None and rw.shortened(rows[0]) is not None


def test_a_pass_that_only_looks_reads_no_row_a_case_still_keeps(env30, monkeypatch):
    """The look asks the case's rule for the noted ids, and reads the address of only those a case has let go: while
    the case keeps them all, a pass reads none of them and the run does not go back."""
    env = env30
    case = _case(env, closed_days=30)
    kept = [env.put(T0 - timedelta(days=40, minutes=-i), case_id=case) for i in range(3)]
    env.run_until_sealed()
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    key = (id(env.st), env.st.view.generation)
    assert set(kept) <= set(rw._kept_rows[key])
    at = rw._cursors[key]
    read = []
    real = rw._address_rows

    def counting(db, *conditions):
        for row in real(db, *conditions):
            read.append(row[0])
            yield row
    monkeypatch.setattr(rw, "_address_rows", counting)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert read == [] and rw._cursors[key] == at
    assert all(env.get(i).ip_address == "203.0.113.9" for i in kept)

def test_the_shortening_goes_back_to_a_let_go_row_whose_only_full_address_is_in_its_details(env30):
    """The look loads only the columns of an address: an address under a key of details (no ip_address) is one."""
    env = env30
    case = _case(env, closed_days=30)
    kept = env.put(T0 - timedelta(days=40), case_id=case, ip_address=None, details={"client_ip": "198.51.100.7"})
    env.run_until_sealed()
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(kept).details == {"client_ip": "198.51.100.7"}
    _close(env, case, FLOOR_DAYS + 1)
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert "client_ip" not in (env.get(kept).details or {})
    assert failures(env.verify()) == []


@pytest.mark.parametrize("fails", [False, True], ids=["control", "a-noted-days-read-fails-once"])
def test_a_look_that_fails_while_it_reads_a_noted_day_forgets_no_row_a_case_let_go(env30, monkeypatch, fails):
    """The look reads the noted rows, then the noted archived days. A read of a day that fails (a statement's timeout,
    a lost connection) ends the pass; the rows a case let go of stay noted, and the next pass shortens them, with no
    restart."""
    env = env30
    case = _case(env, closed_days=30)
    kept = env.put(T0 - timedelta(days=40), case_id=case)
    other = env.put(T0 - timedelta(days=40, minutes=-10))
    env.run_until_sealed()
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(kept).ip_address == "203.0.113.9" and env.get(other).ip_address is None
    key = (id(env.st), env.st.view.generation)
    assert kept in rw._kept_rows[key]
    some_day = (T0 - timedelta(days=200)).date()
    rw._kept_days.setdefault(key, {})[some_day] = 1          # a noted archived day, which still keeps its row
    calls = []

    def read_day(*a, **k):
        calls.append(1)
        if fails and len(calls) == 1:
            raise RuntimeError("the statement ran out of time")
        return 1
    monkeypatch.setattr(rw, "kept_in_archived_day", read_day)
    _close(env, case, FLOOR_DAYS + 1)
    if fails:
        with pytest.raises(RuntimeError):
            rw.shorten_job(retention.Pass(env.session, now=env.clock()))
        assert kept in rw._kept_rows[key] and rw._kept_days[key] == {some_day: 1}
        assert env.get(kept).ip_address == "203.0.113.9"
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(kept).ip_address is None and kept not in rw._kept_rows[key]
    assert rw._kept_days[key] == {some_day: 1}
    assert failures(env.verify()) == []


def test_a_look_that_fails_on_a_later_day_forgets_no_earlier_day_a_case_let_go(env30, monkeypatch):
    """Two noted archived days: the first keeps fewer rows than when it was read (a case let one go), the read of the
    second fails. The first stays noted as it was, and the next pass goes back to its start."""
    env = env30
    env.put(T0 - timedelta(days=40))
    env.run_until_sealed()
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    key = (id(env.st), env.st.view.generation)
    first, second = (T0 - timedelta(days=220)).date(), (T0 - timedelta(days=200)).date()
    rw._kept_days.setdefault(key, {}).update({first: 2, second: 1})
    calls = []

    def read_day(w, day, *a, **k):
        calls.append(day)
        if day == second and calls.count(second) == 1:
            raise RuntimeError("the connection was lost")
        return 1                                  # the first now keeps one row of its two; the second its one
    monkeypatch.setattr(rw, "kept_in_archived_day", read_day)
    starts = []
    real_step = rw.step
    monkeypatch.setattr(rw, "step", lambda p, w, scope, cursor: (starts.append(cursor), real_step(p, w, scope,
                                                                                                    cursor))[1])
    with pytest.raises(RuntimeError):
        rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert rw._kept_days[key] == {first: 2, second: 1} and starts == []
    rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    assert starts and starts[0] == arc.day_start(first)
    assert rw._kept_days[key] == {first: 1, second: 1}


@pytest.mark.parametrize("change, fixture", [("removal", "env"), ("shortening", "env30")],
                         ids=["removal", "shortening"])
def test_a_removal_and_the_shortening_leave_a_cases_rows_in_an_archived_day_as_they_are(request, change, fixture):
    """A case row archived while nothing kept it (its case closed long ago), then kept again (the floor raised): the
    rewrite of the archived day changes the day's other row and leaves that one as its block holds it."""
    env = request.getfixturevalue(fixture)
    case = _case(env, closed_days=FLOOR_DAYS + 30)
    kept = env.put(_at(120, 3), case_id=case, details={"email": "a@example.com"})
    gone = env.put(_at(120, 3, 20), details={"email": "b@example.com"})
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    assert env.get(kept) is None and _blocks(env) == 1
    env.settings.compliance_record_min_days = FLOOR_DAYS + 200
    if change == "removal":
        asked = env.ask_removal()
        assert not until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED, hours=24 * 12)
        assert env.removal_row(asked["id"]).waiting == vr.KEPT_WAIT.format(n=1)
    else:
        rw.shorten_job(retention.Pass(env.session, now=env.clock()))
    rows = _archived_rows(env)
    assert rows[kept]["ip_address"] == "203.0.113.9" and json.loads(rows[kept]["details"]) == {"email": "a@example.com"}
    assert rows[gone]["ip_address"] is None
    if change == "removal":
        assert "email" not in json.loads(rows[gone]["details"] or "{}")
        # The floor back where it was: the day is read again, its row changed, and the removal completes.
        env.settings.compliance_record_min_days = FLOOR_DAYS
        assert until(env, lambda: env.removal_row(asked["id"]).status == vr.COMPLETED)
        assert _archived_rows(env)[kept]["ip_address"] is None
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
    """A session on Postgres that records what it is asked to run, and its savepoints; ``fail`` is raised by the
    exclusive lock."""

    def __init__(self, fail=None):
        self.sql = []
        self.fail = fail

    def get_bind(self):
        from types import SimpleNamespace
        return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    def execute(self, statement, params=None):
        from types import SimpleNamespace
        self.sql.append((str(statement), params))
        if self.fail is not None and "pg_advisory_xact_lock(" in str(statement):
            raise self.fail
        return SimpleNamespace(one=lambda: ("5s", "5s"))

    def begin_nested(self):
        from types import SimpleNamespace
        self.sql.append(("SAVEPOINT", None))
        return SimpleNamespace(commit=lambda: self.sql.append(("RELEASE", None)),
                               rollback=lambda: self.sql.append(("ROLLBACK TO", None)))


_SETTINGS = "SELECT current_setting('lock_timeout'), current_setting('statement_timeout')"
_SET = "SELECT set_config('lock_timeout', :lock, true), set_config('statement_timeout', :stmt, true)"


def test_the_turn_is_a_transaction_lock_shared_by_deletions_and_exclusive_for_a_hold_or_a_case():
    """The exclusive turn waits up to TURN_WAIT_SECONDS (longer than the connection's 5 s lock_timeout, raised for
    that one statement in a savepoint and put back after), so a deletion step that holds it for seconds is waited
    for rather than failing the step."""
    from app.core import legal_holds
    db = _Postgres()
    legal_holds.take_turn(db, shared=True)
    legal_holds.take_turn(db, shared=False)
    params = {"c": legal_holds.HOLD_TURN[0], "k": legal_holds.HOLD_TURN[1]}
    wait = int(legal_holds.TURN_WAIT_SECONDS * 1000)
    assert legal_holds.TURN_WAIT_SECONDS > 5
    assert db.sql == [("SELECT pg_advisory_xact_lock_shared(:c, :k)", params),
                      (_SETTINGS, None), ("SAVEPOINT", None),
                      (_SET, {"lock": f"{wait}ms", "stmt": f"{wait + 10000}ms"}),
                      ("SELECT pg_advisory_xact_lock(:c, :k)", params), ("RELEASE", None),
                      (_SET, {"lock": "5s", "stmt": "5s"}),
                      ("DELETE FROM system_settings WHERE key = :k", {"k": legal_holds.TURN_WANTED})]


@pytest.mark.parametrize("pgcode", ["55P03", "57014"])
def test_an_exclusive_turn_a_deletion_holds_too_long_is_refused_as_busy_with_the_transaction_as_it_was(pgcode):
    from types import SimpleNamespace
    from sqlalchemy.exc import OperationalError
    from app.core import legal_holds
    db = _Postgres(fail=OperationalError("SELECT pg_advisory_xact_lock(...)", {}, SimpleNamespace(pgcode=pgcode)))
    with pytest.raises(legal_holds.TurnBusy):
        legal_holds.take_turn(db, shared=False)
    params = {"c": legal_holds.HOLD_TURN[0], "k": legal_holds.HOLD_TURN[1]}
    assert db.sql[-2:] == [("SELECT pg_advisory_xact_lock(:c, :k)", params), ("ROLLBACK TO", None)]


def test_any_other_failure_of_the_turn_is_not_taken_for_busy():
    from types import SimpleNamespace
    from sqlalchemy.exc import OperationalError
    from app.core import legal_holds
    db = _Postgres(fail=OperationalError("SELECT pg_advisory_xact_lock(...)", {}, SimpleNamespace(pgcode="40P01")))
    with pytest.raises(OperationalError):
        legal_holds.take_turn(db, shared=False)
    assert db.sql[-1] == ("ROLLBACK TO", None)


def test_the_routes_take_the_turn_before_the_code_is_used_and_keep_it_until_the_step_commits():
    """A hold, an undone release and a case request: the turn is taken before the code is used, the route's check is
    called in a session of its own (using a code may commit), and the step runs after, in the turn. The hold and the
    undo ask for the code before they wait for the turn when there is no receipt, and use none after it."""
    import inspect
    from app.api import compliance_router as routes
    for route, step_up, then in ((routes.place_hold, "STEP_UP_HOLD_PLACE", "holds.place_hold_only(db, "),
                                 (routes.undo_hold_release, "STEP_UP_HOLD_DECIDE", "_take_decision("),
                                 (routes.request_case, "STEP_UP_CASE_REQUEST", "case = cases.request_case(db, ")):
        lines = inspect.getsource(route).splitlines()
        calls = [i for i, line in enumerate(lines) if f"{step_up}(" in line]
        for i in calls:
            assert lines[i].strip().startswith(f"{step_up}(own, current_user, request)"), (route.__name__, lines[i])
            assert lines[i - 1].strip() == "with _code_session() as own:", (route.__name__, lines[i - 1])
        turns = [i for i, line in enumerate(lines) if "_take_the_turn(db, " in line]
        assert len(turns) == 1, route.__name__
        turn, step = turns[0], next(i for i, line in enumerate(lines) if then in line)
        if route is routes.request_case:
            assert len(calls) == 1 and turn < calls[0] < step, route.__name__
            continue
        assert len(calls) == 2, route.__name__
        first, after = calls
        assert first < turn < after < step, route.__name__
        assert lines[first - 2].strip() == "if asked:" and lines[after - 2].strip() == "if not asked:", route.__name__
        assert sum(line.strip() == "asked = _no_receipt(request)" for line in lines[:first - 2]) == 1, route.__name__
    ask = inspect.getsource(routes.request_case)
    assert "db.rollback()" not in ask
    assert ask.index("_take_the_turn(db, ") < ask.index("point = db.begin_nested()") < ask.index(
        "cases.request_case(db, current_user, **args)")


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
