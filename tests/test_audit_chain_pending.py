"""The changes waiting, as the retention screen lists them (app/core/audit_chain_pending.py), offline.

The list is the audit log's integrity chain's: the request seals no cancel names and no seal supersedes, from
this process's verified view, and the requests another writer's applies applied whose value does not count yet.
A row of managed_setting_changes neither adds an entry, nor hides one, nor changes what an entry says or when it
applies; an edited or deleted request seal in audit_seals changes nothing either, since the view holds what this
process authenticated. A cancel is addressed to the request the chain holds, whatever the row says, and a row the
chain holds no request of is no change.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
import uuid
from datetime import datetime, timedelta

import pytest

from _audit_chain_env import failures
from app.core import audit_chain_format as fmt
from app.core import audit_chain_honour as honour
from app.core import audit_chain_pending as pending
from app.core import audit_chain_policy_seals as ps
from app.core import retention
from app.core import setting_changes as sc
from app.core import settings_registry as reg
from app.core.models import AuditLog, AuditSeal, ManagedSettingChange
from test_audit_chain_dates import _accept, _applies_of, _env, _request_after
from test_audit_chain_trust import _ack_by_host, _admin, _change, _run_to

pytestmark = pytest.mark.unit

KEY = "audit_max_days"


@pytest.fixture
def env(monkeypatch, tmp_path):
    """A chain whose minimum for administration and security events is 30 days, so a request another writer
    appends for a maximum of 30 days is one the server accepts."""
    e = _env(monkeypatch, tmp_path, AUDIT_PROTECTED_MIN_DAYS=30)
    yield e
    e.close()


def _listed(env):
    with env.session() as db:
        return pending.entries(db, env.st, env.clock())


def _at(text):
    return datetime.fromisoformat(text.rstrip("Z"))


def _request(env, actor, value=90):
    """An administrator's reduction of the maximum (no limit by default): its change and its request seal."""
    outcome = _change(env, actor, KEY, value)
    assert outcome.status == "pending"
    seal = [s for s in env.seals() if s.kind == "request"][-1]
    return outcome.change.id, seal.seq, fmt.parse_time_text(seal.detail["not_before"])


def _cancel(env, actor, change_id):
    with ps.change_transaction(env.engine) as w:
        return ps.cancel(w, change_id, actor)


def _audit_rows(env, action=sc.CANCELLED_ACTION):
    with env.session() as db:
        return [(r.username, r.details) for r in db.query(AuditLog).filter(AuditLog.action == action).all()]


def _honoured_max_days(env):
    return honour.honoured_state(env.st.view, env.st.known_record(), env.clock())[KEY]["value"]


def test_an_entry_says_what_the_request_seal_holds_whatever_the_row_says(env):
    """The row's values, date and name edited (a change that keeps more, a year away): the list still shows the
    sealed reduction and the date the pruner applies it on, and the pruner applies the sealed value then."""
    env.run_until_sealed()
    ada = _admin(env)
    change_id, req, not_before = _request(env, ada)
    with env.session() as db:
        row = db.get(ManagedSettingChange, change_id)
        row.old_value, row.setting, row.new_value = 368, 417, 417
        row.effective_at = row.effective_at + timedelta(days=300)
        row.requested_by_name, row.requested_at = "mallory", row.requested_at + timedelta(days=300)
        db.commit()
    (e,) = _listed(env)
    assert (e["id"], e["request_seq"], e["key"], e["status"]) == (str(change_id), req, KEY, pending.WAITING)
    assert (e["old"], e["setting"], e["new"], e["requested_by"]) == (0, 90, 90, "ada")
    assert _at(e["effective_at"]) == not_before and _at(e["requested_at"]) == env.st.view.at(req)
    assert (e["cancellable"], e["waits_for_host"], e["another_writer"], e["database"]) == (True, False, False, None)
    _run_to(env, not_before + timedelta(hours=1))
    assert _honoured_max_days(env) == 90 and req in env.st.view.applied
    assert _listed(env) == []


def test_an_edited_request_seal_in_the_database_changes_nothing_listed(env):
    """The list reads the view this process authenticated, never audit_seals: a request seal edited there (a
    value that keeps more, a date a year away) leaves the entry as sealed."""
    env.run_until_sealed()
    change_id, req, not_before = _request(env, _admin(env))
    with env.session() as db:
        seal = db.get(AuditSeal, req)
        seal.detail = dict(seal.detail, new=400, not_before=fmt.time_text(not_before + timedelta(days=365)))
        db.commit()
    (e,) = _listed(env)
    assert (e["id"], e["setting"], e["new"]) == (str(change_id), 90, 90)
    assert _at(e["effective_at"]) == not_before


@pytest.mark.parametrize("how", ["cancelled", "superseded", "applied", "missing"])
def test_a_row_no_longer_waiting_neither_hides_the_entry_nor_keeps_it_from_being_cancelled(env, how):
    """A database writer marks the row ended, or deletes it: the entry is still listed, with what the database
    says beside it, and an administrator's cancel is sealed. The audit row names the sealed change; the row, when
    there is one, is marked cancelled by that administrator. The change never applies."""
    env.run_until_sealed()
    ada, bob = _admin(env), _admin(env, "bob")
    change_id, req, not_before = _request(env, ada)
    with env.session() as db:
        row = db.get(ManagedSettingChange, change_id)
        if how == "missing":
            db.delete(row)
        else:
            row.status = how
        db.commit()
    (e,) = _listed(env)
    assert (e["id"], e["request_seq"], e["database"], e["cancellable"]) == (str(change_id), req, how, True)
    out = _cancel(env, bob, change_id)
    assert (out["status"], out["decided_by"], out["key"], out["old"], out["new"]) == ("cancelled", "bob", KEY, 0, 90)
    assert "_audit_row" not in out
    seal = env.seals()[-1]
    assert (seal.kind, seal.detail["cancels"], seal.detail["request"], seal.detail["by"]) == (
        "cancel", req, str(change_id), "admin")
    assert seal.detail["user_id"] == str(bob.id) and seal.detail["audit_row"] is not None
    assert _audit_rows(env) == [("bob", {"key": KEY, "change_id": str(change_id), "old": 0, "new": 90,
                                         "setting": 90, "requested_by": "ada"})]
    with env.session() as db:
        row = db.get(ManagedSettingChange, change_id)
        if how == "missing":
            assert row is None
        else:
            assert (row.status, row.decided_by_name) == (sc.CANCELLED, "bob")
    assert _listed(env) == [] and req in env.st.view.cancels
    _run_to(env, not_before + timedelta(hours=1))
    assert _honoured_max_days(env) == 0 and req not in env.st.view.applied
    assert failures(env.verify()) == []


def test_a_row_the_chain_holds_no_request_of_is_neither_listed_nor_cancelled(env):
    """A pending row planted in the database, with no request seal: it is not listed, and a cancel of it is
    refused (LookupError, 404 on the route) with no audit row and no seal; the row is left as it is."""
    env.run_until_sealed()
    ada = _admin(env)
    planted = uuid.uuid4()
    with env.session() as db:
        db.add(ManagedSettingChange(id=planted, key=KEY, setting=1, old_value=0, new_value=1, status=sc.PENDING,
                                    requested_by=ada.id, requested_by_name="ada", requested_at=env.clock(),
                                    effective_at=env.clock() + timedelta(days=7)))
        db.commit()
    assert _listed(env) == []
    seals = len(env.seals())
    with pytest.raises(LookupError):
        _cancel(env, ada, planted)
    assert len(env.seals()) == seals and _audit_rows(env) == []
    with env.session() as db:
        assert db.get(ManagedSettingChange, planted).status == sc.PENDING


def test_a_cancel_of_a_change_no_longer_waiting_says_how_it_ended_in_the_chain(env):
    """The chain says how it ended, not the row: a row set back to pending does not make a cancelled change
    waiting again."""
    env.run_until_sealed()
    ada = _admin(env)
    change_id, req, _nb = _request(env, ada)
    _cancel(env, ada, change_id)
    with env.session() as db:
        db.get(ManagedSettingChange, change_id).status = sc.PENDING
        db.commit()
    assert _listed(env) == []
    with pytest.raises(reg.SettingRefused) as refused:
        _cancel(env, ada, change_id)
    assert str(refused.value) == "This change is no longer waiting: it was cancelled."
    newer_id, newer, _nb = _request(env, ada, 60)
    assert [e["request_seq"] for e in _listed(env)] == [newer]
    with env.session() as db:
        db.get(ManagedSettingChange, change_id).status = sc.PENDING
        db.commit()
    assert [e["id"] for e in _listed(env)] == [str(newer_id)]


def test_another_writers_request_waits_for_the_host_and_its_date_counts_from_the_servers_acceptance(env):
    """A request another writer appended 11 hours before the server first reads it: listed as another writer's,
    waiting for the host, due a delay of seven days after the server first accepted it (11 hours after its own
    not_before); once acknowledged it no longer waits for the host."""
    env.run_until_sealed()
    req = _request_after(env, 30, 7)
    not_before = fmt.parse_time_text(env.seals()[-1].detail["not_before"])
    env.clock.advance(hours=11)
    retention.run_pass(env.session, now=env.clock())     # the server accepts it here
    accepted = fmt.parse_time_text([e for e in env.st.head_store().load()["after_record"]
                                    if e["seq"] == req][0]["accepted_at"])
    (e,) = _listed(env)
    assert (e["request_seq"], e["setting"], e["another_writer"], e["waits_for_host"]) == (req, 30, True, True)
    assert abs(_at(e["effective_at"]) - (accepted + timedelta(days=7))) < timedelta(minutes=1)
    assert _at(e["effective_at"]) - not_before > timedelta(hours=10)
    assert e["requested_by"] == "an administrator whose account no longer exists"
    _ack_by_host(env, [req])
    (e,) = _listed(env)
    assert (e["another_writer"], e["waits_for_host"], e["cancellable"]) == (True, False, True)


def test_a_request_another_writers_applies_applied_is_listed_until_its_value_counts(env):
    """Another writer's applies, four minutes before the request is due on the server's clock: the request has
    left the pending set but its value does not count. It is listed as applied by that seal, waiting for the
    host, with its due date, and cannot be cancelled; once acknowledged it is listed with the date its value
    counts from, until that date has passed."""
    env.run_until_sealed()
    admin = _admin(env)
    change_id, req, _nb = _request(env, admin)
    _run_to(env, env.clock() + timedelta(days=7, hours=-1))
    nb = fmt.parse_time_text(env.st.view.requests[req]["not_before"])
    env.clock.at = nb
    applies = _applies_of(env, req, 90)
    env.clock.at = nb - timedelta(minutes=4)
    _accept(env)
    (e,) = _listed(env)
    assert (e["id"], e["request_seq"], e["status"], e["applied_by"]) == (
        str(change_id), req, pending.APPLIED_WAITING, applies)
    assert (e["cancellable"], e["waits_for_host"], e["counts_from"], e["database"]) == (False, True, None, None)
    due = honour.request_due(env.st.view, env.st.known_record(), req, env.clock())
    assert _at(e["effective_at"]) == due
    with pytest.raises(reg.SettingRefused):
        _cancel(env, admin, change_id)
    _ack_by_host(env, [applies])
    (e,) = _listed(env)
    counts = honour.counts_from(env.st.view, env.st.known_record(), applies, env.clock())
    assert counts is not None and counts > env.clock()
    assert (e["status"], e["waits_for_host"], _at(e["counts_from"]), _at(e["effective_at"])) == (
        pending.APPLIED_WAITING, False, counts, counts)
    _run_to(env, counts + timedelta(hours=1))
    assert _listed(env) == [] and _honoured_max_days(env) == 90


def test_nothing_is_listed_before_the_chain_is_read_and_a_stop_is_said(env):
    assert pending.chain_state(env.st) == {"read": False, "stopped": None}
    assert _listed(env) == []
    env.run_until_sealed()
    assert pending.chain_state(env.st) == {"read": True, "stopped": None}
