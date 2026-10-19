"""The per-person erase's guards, each pinned by the case it is there for (app/core/audit_chain_erase.py, the run;
app/core/person_erase.py, the request side), offline on a throwaway SQLite database with a chain of its own
(tests/_erase_env.py):

- when it runs: a request another writer appended runs only once the host acknowledges it; the hold switch, a
  restore mark and a registered rule stop it between units, and a rule that cannot be read keeps it waiting; a
  late row in an hour it reaches makes it wait for the late seal, while a row added to an hour sealed long ago is
  a finding; the protected minimum is asked only before the run begins, and a row exactly at the minimum does
  not hold it; the database vetoes on a day that holds no veto of its yet; a new request never takes a delay
  shorter than the chain's newest;
- what it acts on: a name the token opens to that no erase may take, a row already erased that holds the name
  again, an archived hour another writer sealed, and an invitation exactly at its expiry;
- what it writes: an archived erased row keeps none of its personal values, a key that holds the name goes even
  when it is classified, and a unit whose rows did not take their values, whose other rows changed, or that
  fails after it wrote, commits nothing.
"""
import json
import os
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
from app.core.models import AccountInvitation, AuditLog, EraseRequest

pytestmark = pytest.mark.unit


def _env(monkeypatch, tmp_path, start):
    e = EraseEnv(monkeypatch, tmp_path, audit_archive_start_after_days=start)
    arc._marker_checked.clear()
    arc._figures.clear()
    return e


@pytest.fixture
def hot(monkeypatch, tmp_path):
    """Archiving far off: the rows stay rows."""
    e = _env(monkeypatch, tmp_path, 1000)
    yield e
    e.close()


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Archiving from the first pass."""
    e = _env(monkeypatch, tmp_path, 0)
    yield e
    e.close()


def _put(env, when, username="eve", **values):
    row = dict(id=uuid.uuid4(), action="file_uploaded", status="success", timestamp=when, username=username,
               ip_address="203.0.113.9", user_agent="Mozilla/5.0 test", endpoint="/vaults/{vault_id}/files",
               details={"n": 1}, seal_nonce=uuid.uuid4().bytes)
    row.update(values)
    with env.session() as db:
        db.add(AuditLog(**row))
        db.commit()
    return row["id"]


def _row(env, rid):
    with env.session() as db:
        return db.get(AuditLog, rid)


def _edit(env, rid, **values):
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == rid).update(values, synchronize_session=False)
        db.commit()


def _erased(env, name="eve"):
    asked = env.ask(name)
    env.passes(24 * 7 + 6)
    assert env.request_row(asked["id"]).status == pe.COMPLETED
    return asked


def _recorded_failures(env):
    return sorted((env.st.head_store().load() or {}).get("failures") or {})


def _foreign_request(env, name):
    """An erase request seal for ``name`` that another writer holding both keys appended, consistent in every field
    (sealed_at, not_before, subject, placeholder), with its erase_requests row and token. Returns (placeholder,
    its seq)."""
    from test_audit_chain_guards import _forge
    req_id = uuid.uuid4()
    r = os.urandom(32)
    placeholder = "erased-" + uuid.uuid4().hex[:8]
    subject = pe.subject_of(req_id, r, name).hex()
    seq = _forge(env, "request", lambda s, at: {
        "what": "erase", "request": str(req_id), "setting": None, "old": None, "new": None, "subject": subject,
        "placeholder": placeholder, "not_before": fmt.time_text(at + timedelta(days=7)), "audit_row": None,
        "by": "admin", "user_id": None})
    with env.session() as db:
        db.add(EraseRequest(id=req_id, status=pe.PENDING, name_token=pe.seal_name(env.settings, req_id, r, name),
                            placeholder=placeholder, requested_at=env.clock(), request_seq=seq))
        db.commit()
    return placeholder, seq


def _due_pass(env, hours=(40, 30, 20)):
    """Rows of eve in three hours, sealed, an erase asked and its delay all but run; then the pass in which it is
    due, to run by hand. Returns (the rows, the pass)."""
    ids = [_put(env, T0 - timedelta(hours=h)) for h in hours]
    env.run_until_sealed()
    env.ask("eve")
    env.passes(24 * 7 - 6)
    assert env.erase_seals() == []
    env.clock.advance(hours=6)
    return ids, retention.Pass(env.session, now=env.clock())


# --------------------------------------------------------------------------- when it runs

def test_an_erase_request_another_writer_appended_runs_only_once_the_host_acknowledges_it(hot):
    """Someone holding both keys appends a consistent erase request with its row and token. Nothing is erased
    before the host acknowledges it, and then not before a delay from its acceptance."""
    from test_audit_chain_held import _ack_by_host
    env = hot
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    placeholder, seq = _foreign_request(env, "eve")
    accepted = env.clock()
    env.passes(24 * 9)                                   # its own not_before passed; not acknowledged
    assert _row(env, rid).username == "eve" and env.erase_seals() == []
    _ack_by_host(env, [seq])
    env.passes(12)
    first = env.erase_seals()
    assert first and _row(env, rid).username == placeholder
    assert first[0].sealed_at >= accepted + timedelta(days=7)
    assert failures(env.verify()) == []


def test_the_hold_switch_turned_on_during_a_pass_stops_the_next_unit(hot):
    from app.core import audit_chain_policy_seals as ps
    env = hot
    ids, p = _due_pass(env)
    admin = env.admin("holder")
    real = p.time_left
    held = {"on": False}

    def time_left():
        if not held["on"] and env.erase_seals():
            with ps.change_transaction(env.engine) as w:
                assert ps.change(w, retention.HOLD_KEY, True, admin, now=env.clock()).status == "applied"
            held["on"] = True
        return real()
    p.time_left = time_left
    ae.run_job(p)
    assert held["on"] and len(env.erase_seals()) == 1
    assert [_row(env, i).username == "eve" for i in ids] == [False, True, True]


def test_a_restore_mark_written_during_a_pass_stops_the_next_unit(hot):
    from app.core import audit_head_record as hr
    env = hot
    ids, p = _due_pass(env)
    real = p.time_left
    marked = {"on": False}

    def time_left():
        if not marked["on"] and env.erase_seals():
            hr.write_mark(env.st.head_store().path, {"at": fmt.time_text(env.clock()), "bundle": "dockvault-test-1",
                                                     "record": None})
            marked["on"] = True
        return real()
    p.time_left = time_left
    ae.run_job(p)
    assert marked["on"] and len(env.erase_seals()) == 1
    assert [_row(env, i).username == "eve" for i in ids] == [False, True, True]


def test_a_registered_rule_that_cannot_be_read_keeps_every_erase_waiting(hot):
    """The interface legal holds and open cases register with must fail closed: a rule that raises holds."""
    env = hot
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    asked = env.ask("eve")

    def broken(db, now):
        raise RuntimeError("the table of holds cannot be read")
    pe.register_wait(broken)
    env.passes(24 * 8)
    assert _row(env, rid).username == "eve" and env.erase_seals() == []
    assert "could not be read (RuntimeError)" in (env.request_row(asked["id"]).waiting or "")


def _row_near_not_before(env):
    """An erase asked, then eve's row in an hour sealed three hours before the request is due, then sealing on to
    half an hour after it is due. Returns (the request, eve's row, its hour)."""
    _put(env, T0 - timedelta(hours=30), username="alice")
    env.run_until_sealed()
    asked = env.ask("eve")
    not_before = fmt.parse_time_text(env.view().requests[asked["request_seq"]]["not_before"])
    while env.clock() < not_before - timedelta(hours=3):
        env.clock.advance(hours=1)
        env.seal()
    rid = _put(env, env.clock() - timedelta(minutes=10))
    hour = ai.hour_floor(env.clock() - timedelta(minutes=10))
    while env.clock() < not_before + timedelta(minutes=30):
        env.clock.advance(hours=1)
        env.seal()
    entry = env.view().entry_for(hour)
    assert entry is not None and env.clock() - entry.root.sealed_at < ai.LATE_WINDOW
    return asked, rid, hour


def test_a_late_row_in_an_hour_the_erase_reaches_waits_for_its_late_seal_without_a_finding(hot):
    env = hot
    asked, rid, hour = _row_near_not_before(env)
    _put(env, hour + timedelta(minutes=55), username="alice")     # arrives late, within the six hours
    env.erase_job()
    assert _row(env, rid).username == "eve"
    assert "rows-altered" not in _recorded_failures(env)
    assert "the sealer seals them first" in (env.request_row(asked["id"]).waiting or "")
    env.clock.advance(minutes=10)
    env.seal()
    assert [s.detail["by"] for s in env.seals() if s.kind == "late"] == ["sealer"]
    env.erase_job()
    assert _row(env, rid).username == asked["placeholder"]
    assert env.request_row(asked["id"]).status == pe.COMPLETED
    assert _recorded_failures(env) == [] and failures(env.verify()) == []


def test_a_row_added_to_an_hour_sealed_long_ago_is_a_finding_and_not_a_wait(hot):
    env = hot
    at = T0 - timedelta(days=40)
    rid = _put(env, at + timedelta(minutes=5))
    env.run_until_sealed()
    env.passes(12)                                       # the hour's seal is now more than six hours old
    _put(env, at + timedelta(minutes=50), username="alice")
    env.ask("eve")
    env.passes(24 * 7 + 6)
    assert _row(env, rid).username == "eve" and env.erase_seals() == []
    assert [s for s in env.seals() if s.kind == "late"] == []
    assert "rows-altered" in _recorded_failures(env)


def test_a_row_added_to_an_hour_whose_seal_is_past_the_late_window_but_hours_old_is_a_finding_at_once(hot):
    """The hour's seal about nine hours old when the erase reaches it (past the six hours of the late window, well
    within a day), and a row added to it: the sealer no longer seals it late, so the erase reports rows-altered at
    once and does not say it waits for the sealer."""
    env = hot
    _put(env, T0 - timedelta(hours=30), username="alice")
    env.run_until_sealed()
    asked = env.ask("eve")
    not_before = fmt.parse_time_text(env.view().requests[asked["request_seq"]]["not_before"])
    while env.clock() < not_before - timedelta(hours=9):
        env.clock.advance(hours=1)
        env.seal()
    rid = _put(env, env.clock() - timedelta(minutes=10))
    hour = ai.hour_floor(env.clock() - timedelta(minutes=10))
    while env.clock() < not_before + timedelta(minutes=30):
        env.clock.advance(hours=1)
        env.seal()
    age = env.clock() - env.view().entry_for(hour).root.sealed_at
    assert ai.LATE_WINDOW < age < 2 * ai.LATE_WINDOW, age
    _put(env, hour + timedelta(minutes=55), username="alice")
    env.erase_job()
    waiting = env.request_row(asked["id"]).waiting or ""
    assert _row(env, rid).username == "eve" and env.erase_seals() == []
    assert "rows-altered" in _recorded_failures(env)
    assert "the sealer seals them first" not in waiting and "(rows-altered)" in waiting


def test_once_the_late_window_closes_the_request_says_a_finding_holds_it_not_that_it_waits_for_the_sealer(hot):
    """A late row beside a sealed row someone changed, in the hour the erase reaches: inside the six hours the request
    says it waits for the sealer; once they have passed, the erase's own check reports rows-altered, and the request
    says that a finding holds it instead of the wait that is no longer true."""
    env = hot
    _put(env, T0 - timedelta(hours=30), username="alice")
    env.run_until_sealed()
    asked = env.ask("eve")
    not_before = fmt.parse_time_text(env.view().requests[asked["request_seq"]]["not_before"])
    while env.clock() < not_before - timedelta(hours=3):
        env.clock.advance(hours=1)
        env.seal()
    rid = _put(env, env.clock() - timedelta(minutes=10))
    alice = _put(env, env.clock() - timedelta(minutes=9), username="alice")
    hour = ai.hour_floor(env.clock() - timedelta(minutes=10))
    while env.clock() < not_before + timedelta(minutes=30):
        env.clock.advance(hours=1)
        env.seal()
    assert env.clock() - env.view().entry_for(hour).root.sealed_at < ai.LATE_WINDOW
    _put(env, hour + timedelta(minutes=55), username="alice")     # a late row
    _edit(env, alice, ip_address="198.51.100.7")                  # and a sealed row changed
    env.erase_job()
    first = env.request_row(asked["id"]).waiting or ""
    assert "the sealer seals them first" in first and "rows-altered" not in _recorded_failures(env)
    env.clock.advance(hours=7)                                    # the late window has closed
    env.erase_job()
    then = env.request_row(asked["id"]).waiting or ""
    assert _row(env, rid).username == "eve" and env.erase_seals() == []
    assert "rows-altered" in _recorded_failures(env)
    assert then == ae.held_by("rows-altered") and "the sealer" not in then
    assert env.request_row(asked["id"]).status in (pe.PENDING, pe.RUNNING)


def test_once_an_erase_has_begun_the_protected_minimum_is_not_asked_again(hot, monkeypatch):
    """ERASE_BLOCKED_BY_PROTECTED_MINIMUM holds an erase before it begins; a run that has begun completes, even when
    the minimum is raised while it runs."""
    from app.core import audit_retention as ar
    env = hot
    env.settings.erase_blocked_by_protected_minimum = True
    ids, p = _due_pass(env, hours=(24 * 40 + 3, 24 * 40 + 1))
    real = p.time_left
    p.time_left = lambda: real() and not env.erase_seals()          # the pass ends after the first unit
    ae.run_job(p)
    assert len(env.erase_seals()) == 1
    numbers = ar.chain_numbers
    monkeypatch.setattr(ar, "chain_numbers",
                        lambda: (lambda n: (ar.Numbers(n[0].max_days, 1000, 1000, n[0].max_mb),) + n[1:])(numbers()))
    env.erase_job()
    assert [_row(env, i).username == "eve" for i in ids] == [False, False]
    assert len(env.erase_seals()) == 2


def test_a_row_exactly_as_old_as_the_minimum_does_not_hold_the_erase(hot, monkeypatch):
    env = hot
    env.settings.erase_blocked_by_protected_minimum = True
    monkeypatch.setenv("AUDIT_MIN_RETENTION_DAYS", "10")
    env.settings.audit_min_retention_days = 10
    when = T0 - timedelta(days=2, minutes=50)
    rid = _put(env, when)
    env.run_until_sealed()
    asked = env.ask("eve")
    env.passes(24 * 7 + 12)                              # due; the row is about nine and a half days old
    assert _row(env, rid).username == "eve"
    assert "protected minimum" in (env.request_row(asked["id"]).waiting or "")
    env.clock.at = when + timedelta(days=10)             # exactly ten days old
    env.erase_job()
    assert _row(env, rid).username == asked["placeholder"]


def test_an_erase_is_vetoed_on_a_day_that_holds_no_veto_of_the_database_yet(hot):
    """A veto from the database is sealed at most once a day: on a day the database's value veto was sealed, the
    cancel of a vetoed erase waits for the next day (and nothing is erased meanwhile)."""
    from app.core import audit_retention as ar
    from app.core import settings_registry as reg
    env = hot
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    asked = env.ask("eve")
    with env.session() as db:
        reg.store(db, "audit_min_days", ar.chain_numbers()[0].min_days + 30)       # keeps more: a veto
        db.commit()
    env.passes(6)
    day = env.clock().date()
    vetoes = [s for s in env.seals() if s.kind == "policy" and s.detail.get("cause") == "database"]
    assert len(vetoes) == 1 and vetoes[0].sealed_at.date() == day

    def cancels():
        return [s for s in env.seals() if s.kind == "cancel" and s.detail.get("by") == "database"]
    with env.session() as db:
        db.delete(db.get(EraseRequest, uuid.UUID(asked["id"])))
        db.commit()
    env.passes(6)
    assert env.clock().date() == day and cancels() == []
    env.passes(18)
    assert env.clock().date() > day and len(cancels()) == 1 and cancels()[0].sealed_at.date() > day
    assert _row(env, rid).username == "eve" and env.erase_seals() == []


def test_a_new_request_never_takes_a_delay_shorter_than_the_chains_newest(hot, monkeypatch):
    from app.core import audit_chain_honour as honour
    from app.core import audit_chain_policy as pol
    env = hot
    env.run_until_sealed()
    newest = pol.delay_days(env.view().newest_state())
    real = honour.honoured_state

    def shorter(view, record, now=None):
        state = real(view, record, now)
        state[pol.DELAY_ENTRY] = dict(state.get(pol.DELAY_ENTRY) or {}, value=1)
        return state
    monkeypatch.setattr(honour, "honoured_state", shorter)
    assert newest > 1 and pe.delay_days(env.view(), env.st) == newest


# --------------------------------------------------------------------------- what it acts on

def test_a_request_another_writer_appended_for_a_name_no_erase_may_take_is_not_acted_on(hot):
    """The name the token opens to is checked again when the erase runs: a request for the server's own name,
    appended by someone holding both keys and acknowledged by the host, erases nothing."""
    from app.core.audit_privacy import SERVER_CONFIGURATION
    from test_audit_chain_held import _ack_by_host
    env = hot
    rid = _put(env, T0 - timedelta(hours=30), username=SERVER_CONFIGURATION)
    env.run_until_sealed()
    _placeholder, seq = _foreign_request(env, SERVER_CONFIGURATION)
    _ack_by_host(env, [seq])
    env.passes(24 * 9)
    assert _row(env, rid).username == SERVER_CONFIGURATION and env.erase_seals() == []
    assert "unjustified-input" in _recorded_failures(env)


def test_a_row_an_erase_changed_that_holds_the_name_again_is_not_erased_twice(hot):
    """The name put back in an erased row and sealed over by another writer's late seal (inside the six hours after
    the hour's seal), which the host then acknowledged: a second erase of the name finds the row listed as erased
    and leaves the hour as it is."""
    from test_audit_chain_held import _ack_by_host, _foreign_late
    env = hot
    first, rid, hour = _row_near_not_before(env)
    env.erase_job()
    assert env.request_row(first["id"]).status == pe.COMPLETED and _row(env, rid).username == first["placeholder"]
    _edit(env, rid, username="eve")
    extra = _put(env, hour + timedelta(minutes=50), username="alice")
    _ack_by_host(env, [_foreign_late(env, hour, [extra])])
    seals = len(env.erase_seals())
    asked = env.ask("eve")
    env.passes(24 * 7 + 6)
    assert _row(env, rid).username == "eve" and len(env.erase_seals()) == seals
    assert env.request_row(asked["id"]).status == pe.PENDING
    assert "unjustified" in _recorded_failures(env)


DAY = (T0 - timedelta(days=100)).date()


def at(hour, minute=0, day=DAY):
    return datetime.combine(day, time(hour, minute))


def _archived_rows(env):
    with env.session() as db:
        view = env.st.view
        out = {}
        for day, part in view.archived_parts():
            for r in arc.PartReader(db, view, day, part).rows():
                out[r["id"]] = r
        return out


def test_an_archived_hour_another_writer_sealed_is_not_erased(env, monkeypatch):
    ids = [_put(env, at(3, 5)), _put(env, at(5, 5))]
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    real = ai.hour_held
    monkeypatch.setattr(ai, "hour_held", lambda view, record, hour: 77 if hour == at(3) else real(view, record, hour))
    asked = env.ask("eve")
    env.passes(24 * 8)
    rows = _archived_rows(env)
    assert [rows[i]["username"] for i in ids] == ["eve", "eve"] and env.erase_seals() == []
    assert "waits for the host operator" in (env.request_row(asked["id"]).waiting or "")


def test_a_row_of_the_name_in_an_archived_day_listed_as_erased_already_is_a_finding(env):
    """As in an hour of rows: the run reads such a day and stops with a finding, and erases nothing. (The row is
    listed in the view as an erase seal over it would list it.)"""
    ids = [_put(env, at(3, 5)), _put(env, at(5, 5))]
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    env.st.view.erased_rows.add(str(ids[0]))
    asked = env.ask("eve")
    env.passes(24 * 8)
    rows = _archived_rows(env)
    assert [rows[i]["username"] for i in ids] == ["eve", "eve"] and env.erase_seals() == []
    assert "unjustified" in _recorded_failures(env)
    assert env.request_row(asked["id"]).waiting == ae.held_by("unjustified")


def test_an_invitation_exactly_at_its_expiry_no_longer_holds_the_name(hot):
    env = hot
    now = env.clock()
    with env.session() as db:
        db.add(AccountInvitation(id=uuid.uuid4(), username="eve", role="user", token_prefix="p",
                                 token_hash=uuid.uuid4().hex, expires_at=now))
        db.commit()
        assert pe.holder(db, "eve", now) is None
        assert "invitation" in (pe.holder(db, "eve", now - timedelta(microseconds=1)) or "")


# --------------------------------------------------------------------------- what it writes

def test_an_archived_erased_row_keeps_none_of_its_personal_values(env, monkeypatch):
    monkeypatch.setattr(ae, "route_templates", lambda: frozenset({"/vaults/{vault_id}/files"}))
    rid = _put(env, at(3, 5), user_agent="agent of eve", endpoint="/raw/eve", temp_credential_name="tc-eve",
               error_message="eve failed", recorded={"ip": "203.0.113.0/24"}, details={"vault_id": "v1", "x": 1})
    env.run_until_sealed()
    arc.archive_job(retention.Pass(env.session, now=env.clock()))
    asked = _erased(env)
    r = _archived_rows(env)[rid]
    assert r["username"] == asked["placeholder"]
    assert (r["ip_address"], r["user_agent"], r["endpoint"], r["temp_credential_name"], r["error_message"],
            r["recorded"]) == (None, None, None, None, None, None)
    assert json.loads(r["details"]) == {"vault_id": "v1"}


def test_a_details_key_that_holds_the_name_goes_even_when_it_is_classified(hot):
    assert ae.scrub_details({"vault_id": "v1", "count": 2}, "eve") == {"vault_id": "v1", "count": 2}
    assert ae.scrub_details({"vault_id": "v1", "count": 2}, "vault") == {"count": 2}


def _trigger(env, body):
    """A database trigger that acts when the erase writes a placeholder into a row."""
    with env.engine.begin() as conn:
        conn.execute(text("CREATE TRIGGER erase_undone AFTER UPDATE OF username ON audit_logs "
                          f"WHEN NEW.username LIKE 'erased-%' BEGIN {body}; END"))


def test_rows_that_did_not_take_their_erased_values_get_no_erase_seal(hot):
    env = hot
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    _trigger(env, "UPDATE audit_logs SET username = 'eve' WHERE id = NEW.id")
    env.ask("eve")
    env.passes(24 * 7 + 6)
    assert _row(env, rid).username == "eve" and env.erase_seals() == []
    assert "unjustified" in _recorded_failures(env)


def test_an_hour_whose_other_rows_changed_as_it_was_erased_gets_no_erase_seal(hot):
    env = hot
    base = T0 - timedelta(hours=30)
    rid = _put(env, base + timedelta(minutes=5))
    other = _put(env, base + timedelta(minutes=15), username="alice")
    env.run_until_sealed()
    _trigger(env, "UPDATE audit_logs SET ip_address = '198.51.100.7' WHERE username = 'alice'")
    env.ask("eve")
    env.passes(24 * 7 + 6)
    assert _row(env, rid).username == "eve" and _row(env, other).ip_address == "203.0.113.9"
    assert env.erase_seals() == []
    assert "rows-altered" in _recorded_failures(env)


def test_a_unit_that_fails_after_it_wrote_commits_nothing(hot, monkeypatch):
    env = hot
    rid = _put(env, T0 - timedelta(hours=30))
    env.run_until_sealed()
    real = ae.erase_hour

    def fails_after_writing(w, *a, **kw):
        assert real(w, *a, **kw) == 1 and w.written
        raise ae.NotErased("a check after the seal failed", "unjustified")
    monkeypatch.setattr(ae, "erase_hour", fails_after_writing)
    asked = env.ask("eve")
    env.passes(24 * 7 + 6)
    assert _row(env, rid).username == "eve" and env.erase_seals() == []
    assert env.request_row(asked["id"]).status == pe.PENDING
