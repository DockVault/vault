"""Legal holds, offline on a real (SQLite) database (app/core/legal_holds.py, its routes in
app/api/compliance_router.py, the pruner's legal_holds job in app/core/retention.py).

Placing a hold-only case: by a live auditor or an administrator the vaults do not concern, at once, the case
numbered, its text sealed, its vaults' owners told in the same transaction and the administrators after it. A
second, independent administrator confirms it within COMPLIANCE_HOLD_CONFIRM_DAYS, or the server's operator on the
host; unconfirmed, it lapses, and its placer cannot place another unconfirmed hold on those vaults for 30 days. A
review is asked for every COMPLIANCE_HOLD_REVIEW_DAYS and nothing is released by the clock. The case's auditor or an
independent administrator releases it with a reason; what it kept is purged COMPLIANCE_HOLD_PURGE_DELAY_DAYS later,
unless an independent administrator undoes the release first; a kept file is purged only when no hold stands on its
vault and no release of one waits. Every step is recorded under its case; a refusal is recorded too.

SQLite has no triggers: a test writes the kept rows the database's trigger would write. test_legal_holds_live.py
drives the routes on a running stack.
"""
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import compliance_router as cr  # noqa: E402
from app.core import admin_grants  # noqa: E402
from app.core import auditor_rights  # noqa: E402
from app.core import case_context  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import host_compliance  # noqa: E402
from app.core import independence as ind  # noqa: E402
from app.core import legal_holds as holds  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core.security import open_case_field  # noqa: E402

pytestmark = pytest.mark.unit

OLD = timedelta(days=400)
NOW = datetime(2026, 11, 2, 10, 0)
TEXT = dict(purpose="litigation_hold", legal_basis="legal_obligation",
            justification="Preserve the records named in the claim served on 2026-10-30.",
            owner_note="Files deleted from your vaults are kept for a legal matter.")


@pytest.fixture
def db():
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


@pytest.fixture(autouse=True)
def told(monkeypatch):
    """What the administrators were told after each commit, instead of sending it."""
    out = []
    monkeypatch.setattr(holds, "deliver", lambda notices: out.extend(notices))
    return out


@pytest.fixture(autouse=True)
def sftp_same(monkeypatch):
    """Every SFTP server runs this version, unless a test sets ``check`` (an answer) or clears it (the real check,
    against SftpProcess rows and the environment ``env``)."""
    from app.core import sftp_versions
    real = sftp_versions.sftp_same_version
    state = {"check": sftp_versions.VersionCheck(True, sftp_versions.SAME, ("0.34.0",)), "env": {}}
    monkeypatch.setattr(sftp_versions, "sftp_same_version",
                        lambda db_, **_k: state["check"] if state["check"] is not None
                        else real(db_, environ=state["env"], version="0.34.0"))
    return state


@pytest.fixture
def settings(monkeypatch):
    values = {key: cs.current(key) for key in cs.KEYS}
    monkeypatch.setattr(cs, "current", lambda key: values[key])
    return values


def _user(db, name, role=m.RoleEnum.USER, *, admin_for=OLD, by=None, created_by=None):
    u = m.User(username=name, email=f"{name}@example.test", password_hash="x", role=role, is_active=True,
               is_locked=False, created_by=created_by)
    db.add(u)
    db.commit()
    if role == m.RoleEnum.ADMIN:
        admin_grants.record(db, u.id, granted_by_id=by.id if by is not None else None,
                            granted_by_name=by.username if by is not None else cc.HOST_OPERATOR,
                            now=NOW - admin_for)
        db.commit()
    return u


def _vault(db, owner):
    v = m.Vault(id=uuid.uuid4(), name="v", owner_id=owner.id)
    db.add(v)
    db.commit()
    return v


@pytest.fixture
def people(db):
    """ada and bob, independent administrators of long standing; olga owns two vaults."""
    ada = _user(db, "ada", m.RoleEnum.ADMIN)
    bob = _user(db, "bob", m.RoleEnum.ADMIN)
    olga = _user(db, "olga")
    return SimpleNamespace(ada=ada, bob=bob, olga=olga, v1=_vault(db, olga), v2=_vault(db, olga))


def _place(db, who, vaults, now=NOW, **kw):
    case = holds.place_hold_only(db, who, [v.id for v in vaults], now=now, **{**TEXT, **kw})
    db.commit()
    return case


def _refused(fn, *args, **kwargs):
    with pytest.raises(holds.HoldRefused) as refused:
        fn(*args, **kwargs)
    return refused.value


def _rows(db, action):
    return db.query(m.AuditLog).filter(m.AuditLog.action == action).order_by(m.AuditLog.timestamp).all()


def _keep(db, vault, *, path=None, size=10, folder=False):
    """The row the database's trigger writes when a held vault's file (or folder) is deleted."""
    if folder:
        row = m.HeldFolder(id=uuid.uuid4(), vault_id=vault.id, kept_reason="deleted", kept_at=NOW)
    else:
        row = m.HeldFile(id=uuid.uuid4(), vault_id=vault.id, storage_path=path or f"{vault.id}/{uuid.uuid4()}",
                         size_bytes=size, kept_reason="deleted", kept_at=NOW)
    db.add(row)
    db.commit()
    return row


# --------------------------------------------------------------------------- placing

def test_placing_opens_a_numbered_hold_only_case_holding_each_vault_at_once(db, people, told):
    case = _place(db, people.ada, [people.v1, people.v2])
    assert case.status == "hold_only" and case.number == "C-2026-0001" and case.hold_requested
    assert case.auditor_id == people.ada.id and case.grant_id is None
    assert open_case_field(case.id, case.justification_enc, "justification") == TEXT["justification"]
    assert open_case_field(case.id, case.owner_note_enc, "owner_note") == TEXT["owner_note"]
    rows = db.query(m.LegalHoldVault).filter(m.LegalHoldVault.case_id == case.id).all()
    assert {r.vault_id for r in rows} == {people.v1.id, people.v2.id}
    for r in rows:
        assert r.placed_by == people.ada.id and r.placed_at == NOW and r.released_at is None
        assert r.confirm_by_deadline == NOW + timedelta(days=7) and r.confirmed_at is None
    assert {(p.user_id, p.why) for p in db.query(m.ComplianceCasePerson)} == {(people.olga.id, "owner")}
    assert {s.target_id for s in db.query(m.ComplianceCaseScope)} == {people.v1.id, people.v2.id}
    assert holds.held_vault_ids(db) == {people.v1.id, people.v2.id}
    # Recorded under the case, one row per vault, with no name.
    placed = _rows(db, "hold_placed")
    assert [r.case_id for r in placed] == [case.id, case.id]
    assert {r.details["vault_id"] for r in placed} == {str(people.v1.id), str(people.v2.id)}
    # The owner is told in the placing transaction (one notice for both vaults); the administrators after it.
    notes = db.query(m.Notification).filter(m.Notification.type == "legal_hold").all()
    assert [(n.user_id, n.title) for n in notes] == [(people.olga.id, "Legal hold on your vaults")]
    assert "2 vaults" in notes[0].body and case.number in notes[0].body
    assert TEXT["justification"] not in notes[0].body and TEXT["owner_note"] not in notes[0].body
    assert [n["title"] for n in told] == ["Legal hold placed"]


def test_nothing_is_told_or_written_when_the_placing_transaction_rolls_back(db, people, told):
    holds.place_hold_only(db, people.ada, [people.v1.id], now=NOW, **TEXT)
    db.rollback()
    assert told == [] and db.query(m.LegalHoldVault).count() == 0 and db.query(m.ComplianceCase).count() == 0


def test_case_numbers_run_on_across_hold_only_cases(db, people):
    assert _place(db, people.ada, [people.v1]).number == "C-2026-0001"
    assert _place(db, people.bob, [people.v1]).number == "C-2026-0002"


@pytest.mark.parametrize("change, reason", [
    ({"purpose": "curiosity"}, holds.BAD_PURPOSE),
    ({"legal_basis": "consent"}, holds.BAD_BASIS),
    ({"legal_basis": "legitimate_interests"}, holds.NO_LIA_REFERENCE),
    ({"justification": "too short to explain it"}, holds.SHORT_JUSTIFICATION),
    ({"owner_note": "   "}, holds.NO_OWNER_NOTE),
])
def test_a_case_must_say_what_it_is_for_on_what_basis_and_why(db, people, change, reason):
    refused = _refused(holds.place_hold_only, db, people.ada, [people.v1.id], now=NOW, **{**TEXT, **change})
    assert refused.reason == reason and refused.code == 422
    case = _place(db, people.ada, [people.v1], legal_basis="legitimate_interests", lia_reference="LIA-7")
    assert case.lia_reference == "LIA-7"


def test_only_an_administrator_or_a_live_auditor_may_place_one(db, people, monkeypatch):
    refused = _refused(holds.place_hold_only, db, people.olga, [people.v1.id], now=NOW, **TEXT)
    assert refused.reason == holds.NOT_ALLOWED and refused.code == 403
    uma = _user(db, "uma")
    grant = SimpleNamespace(id=uuid.uuid4())
    monkeypatch.setattr(auditor_rights, "auditor_live",
                        lambda db_, user, now=None: auditor_rights.Standing(user.id == uma.id, None, grant))
    case = _place(db, uma, [people.v1])
    assert case.auditor_id == uma.id and case.grant_id == grant.id


def test_whom_the_vaults_concern_cannot_place_it(db, people):
    alma = _user(db, "alma", m.RoleEnum.ADMIN)
    own = _vault(db, alma)
    refused = _refused(holds.place_hold_only, db, alma, [people.v1.id, own.id], now=NOW, **TEXT)
    assert refused.reason == holds.PLACER_CONCERNED and refused.code == 403
    assert db.query(m.LegalHoldVault).count() == 0


def test_an_unknown_vault_or_too_many_refuse_the_whole_placing(db, people, settings):
    refused = _refused(holds.place_hold_only, db, people.ada, [people.v1.id, uuid.uuid4()], now=NOW, **TEXT)
    assert refused.reason == holds.NO_SUCH_VAULT and refused.code == 404
    db.rollback()
    settings[cs.MAX_CASE_VAULTS] = 1
    refused = _refused(holds.place_hold_only, db, people.ada, [people.v1.id, people.v2.id], now=NOW, **TEXT)
    assert refused.reason == holds.TOO_MANY_VAULTS
    assert _refused(holds.place_hold_only, db, people.ada, [], now=NOW, **TEXT).reason == holds.NO_VAULTS


def test_while_compliance_access_is_off_no_hold_is_placed(db, people, settings):
    settings[cs.ACCESS] = "disabled"
    assert _refused(holds.place_hold_only, db, people.ada, [people.v1.id], now=NOW, **TEXT).reason == \
        holds.ACCESS_OFF


def test_each_vault_is_locked_for_update_before_its_hold_is_written(db, people, monkeypatch):
    """The lock waits for a deletion holding the vault's row (FOR NO KEY UPDATE), so the hold covers every
    deletion that commits after it. test_legal_holds_live.py shows the wait on Postgres."""
    seen = []
    real = holds._lock_vaults

    def spy(db_, ids):
        out = real(db_, ids)
        seen.append(sorted(str(i) for i in ids))
        assert db_.query(m.LegalHoldVault).count() == 0
        return out

    monkeypatch.setattr(holds, "_lock_vaults", spy)
    _place(db, people.ada, [people.v2, people.v1])
    assert seen == [sorted([str(people.v1.id), str(people.v2.id)])]
    import inspect
    source = inspect.getsource(real)
    assert ".with_for_update()" in source and "key_share" not in source


# --------------------------------------------------------------------------- the SFTP guard

@pytest.fixture
def sftp_real(sftp_same):
    """The real check; returns the environment it reads."""
    sftp_same["check"] = None
    return sftp_same["env"]


def _sftp(db, version, *, seen=None):
    db.add(m.SftpProcess(id=str(uuid.uuid4()), version=version, host="sftp", started_at=NOW,
                         seen_at=seen or datetime.utcnow()))
    db.commit()


def test_a_hold_is_refused_while_an_sftp_server_of_another_version_runs(db, people, sftp_real):
    _sftp(db, "0.33.2")
    refused = _refused(holds.place_hold_only, db, people.ada, [people.v1.id], **TEXT)
    assert refused.reason == holds.SFTP_VERSION and "0.33.2" in refused.detail
    assert db.query(m.LegalHoldVault).count() == 0 and db.query(m.ComplianceCase).count() == 0


def test_a_hold_is_refused_while_sftp_is_on_and_no_server_has_said_its_version(db, people, sftp_real):
    _sftp(db, "0.34.0", seen=datetime.utcnow() - timedelta(minutes=10))   # long gone
    refused = _refused(holds.place_hold_only, db, people.ada, [people.v1.id], **TEXT)
    assert refused.reason == holds.SFTP_VERSION and "has reported its version" in refused.detail


def test_a_hold_is_placed_when_every_sftp_server_runs_this_version_or_none_runs(db, people, sftp_real):
    _sftp(db, "0.34.0")
    assert _place(db, people.ada, [people.v1], now=datetime.utcnow()).status == "hold_only"
    db.query(m.SftpProcess).delete()
    db.commit()
    sftp_real["VAULT_COMBINED_SFTP"] = "off"
    assert _place(db, people.bob, [people.v2], now=datetime.utcnow()).status == "hold_only"


def test_undoing_a_release_is_refused_by_the_same_guard(db, people, sftp_same, monkeypatch):
    from app.core import sftp_versions
    case = _place(db, people.ada, [people.v1])
    holds.release(db, case, by=people.ada, reason="settled", now=NOW + timedelta(days=1))
    db.commit()
    sftp_same["check"] = sftp_versions.VersionCheck(False, sftp_versions.OTHER_VERSION, ("0.33.2",))
    monkeypatch.setattr(cr, "STEP_UP_HOLD_DECIDE", lambda *_a: None)
    monkeypatch.setattr(holds, "utcnow", lambda: NOW + timedelta(days=2))
    with pytest.raises(HTTPException) as refused:
        cr.undo_hold_release(case.id, SimpleNamespace(headers={}), people.bob, db)
    assert refused.value.status_code == 409 and refused.value.detail["reason"] == holds.SFTP_VERSION
    assert holds.standing(db, case.id) == []
    assert _rows(db, "hold_release_undone")[-1].status == "failure"


# --------------------------------------------------------------------------- confirming

def test_an_independent_administrator_confirms_and_the_placer_cannot(db, people, told):
    case = _place(db, people.ada, [people.v1, people.v2])
    assert holds.confirm_refusal(db, case, people.ada, NOW) == holds.PLACER
    assert holds.confirm_refusal(db, case, people.bob, NOW) is None
    assert holds.confirm(db, case, by=people.bob, now=NOW + timedelta(hours=1)) == 2
    db.commit()
    for r in holds.standing(db, case.id):
        assert (r.confirmed_by, r.confirmed_by_username) == (people.bob.id, "bob")
    assert [r.case_id for r in _rows(db, "hold_confirmed")] == [case.id, case.id]
    assert holds.confirm_refusal(db, case, people.bob, NOW) == holds.NOTHING_TO_CONFIRM
    assert told[-1]["title"] == "Legal hold confirmed"


@pytest.mark.parametrize("who, reason", [("owner_admin", ind.CONCERNED), ("new_admin", ind.NEW_ADMIN),
                                         ("made_by_placer", ind.MADE_BY_REQUESTER),
                                         ("created_placer", ind.CREATED_SUBJECT)])
def test_who_is_not_independent_of_the_placer_cannot_confirm(db, people, who, reason):
    if who == "owner_admin":
        person = _user(db, "oscar", m.RoleEnum.ADMIN)
        own = _vault(db, person)
        case = _place(db, people.ada, [people.v1, own])
    elif who == "new_admin":
        person = _user(db, "nina", m.RoleEnum.ADMIN, admin_for=timedelta(days=3))
        case = _place(db, people.ada, [people.v1])
    elif who == "made_by_placer":
        person = _user(db, "mia", m.RoleEnum.ADMIN, by=people.ada)
        case = _place(db, people.ada, [people.v1])
    else:
        person = _user(db, "carl", m.RoleEnum.ADMIN)
        placer = _user(db, "pia", m.RoleEnum.ADMIN, created_by=person.id)
        case = _place(db, placer, [people.v1])
    assert holds.confirm_refusal(db, case, person, NOW) == reason


def test_for_an_auditors_case_the_grants_exclusions_decide(db, people, monkeypatch):
    from app.core import case_eligibility
    asked = []
    monkeypatch.setattr(case_eligibility, "approver_refusal",
                        lambda db_, case, person, now=None: asked.append(person.username) or ind.PROPOSED)
    case = _place(db, people.ada, [people.v1])
    case.grant_id = uuid.uuid4()
    assert holds.decider_refusal(db, case, people.bob, NOW) == ind.PROPOSED and asked == ["bob"]


def test_the_host_confirms_as_the_operator(db, people):
    case = _place(db, people.ada, [people.v1])
    out = host_compliance.CASE_STEPS["confirm-hold"](db, case)
    db.commit()
    assert out["confirmed"] == 1
    (row,) = holds.standing(db, case.id)
    assert row.confirmed_by is None and row.confirmed_by_username == "operator@host"
    assert _rows(db, "hold_confirmed")[0].username == "operator@host"
    from app.core.host_operator import _Answer
    with pytest.raises(_Answer):
        host_compliance.CASE_STEPS["confirm-hold"](db, case)


# --------------------------------------------------------------------------- lapsing, and placing again

def test_an_unconfirmed_hold_lapses_at_its_deadline_and_follows_the_release_path(db, people, told):
    case = _place(db, people.ada, [people.v1])
    kept = _keep(db, people.v1)
    assert holds.lapse_due(db, NOW + timedelta(days=7) - timedelta(seconds=1)) == 0
    at = NOW + timedelta(days=7)
    assert holds.lapse_due(db, at) == 1
    db.commit()
    (row,) = db.query(m.LegalHoldVault).all()
    assert row.lapsed_at == row.released_at == at and row.purge_after == at + timedelta(days=7)
    assert db.get(m.HeldFile, kept.id).purge_after == at + timedelta(days=7)
    db.refresh(case)
    assert case.status == "closed" and case.closed_at == at
    assert case.records_kept_until == at + timedelta(days=cs.current(cs.RECORD_MIN_DAYS))
    assert _rows(db, "hold_lapsed")[0].case_id == case.id
    assert told[-1]["title"] == "Legal hold lapsed"


def test_a_confirmed_hold_never_lapses(db, people):
    case = _place(db, people.ada, [people.v1])
    holds.confirm(db, case, by=people.bob, now=NOW)
    db.commit()
    assert holds.lapse_due(db, NOW + timedelta(days=400)) == 0


def test_a_lowered_confirm_period_lapses_a_hold_sooner_and_a_raised_one_never_later(db, people, settings):
    case = _place(db, people.ada, [people.v1])
    settings[cs.HOLD_CONFIRM_DAYS] = 30
    assert holds.lapse_due(db, NOW + timedelta(days=7, seconds=1)) == 1
    db.commit()
    settings[cs.HOLD_CONFIRM_DAYS] = 2
    case2 = _place(db, people.bob, [people.v2])
    assert holds.confirm_deadline(holds.standing(db, case2.id)[0], case2) == NOW + timedelta(days=2)
    settings[cs.HOLD_CONFIRM_DAYS] = 1
    assert holds.lapse_due(db, NOW + timedelta(days=1, seconds=1)) == 1
    assert case.id != case2.id


def test_after_a_lapse_its_placer_cannot_place_again_on_those_vaults_for_30_days(db, people):
    _place(db, people.ada, [people.v1])
    holds.lapse_due(db, NOW + timedelta(days=7))
    db.commit()
    later = NOW + timedelta(days=8)
    assert _refused(holds.place_hold_only, db, people.ada, [people.v1.id, people.v2.id], now=later,
                    **TEXT).reason == holds.PLACE_BLOCKED
    db.rollback()
    assert _place(db, people.ada, [people.v2], now=later).status == "hold_only"
    assert _place(db, people.bob, [people.v1], now=later).status == "hold_only"
    assert _place(db, people.ada, [people.v1], now=NOW + timedelta(days=7 + 30, seconds=1)).status == "hold_only"


# --------------------------------------------------------------------------- the review prompt

def test_a_review_is_asked_for_once_per_period_and_answering_starts_the_next(db, people, told):
    case = _place(db, people.ada, [people.v1])
    holds.confirm(db, case, by=people.bob, now=NOW)
    db.commit()
    assert holds.prompt_reviews(db, NOW + timedelta(days=180) - timedelta(seconds=1)) == 0
    due = NOW + timedelta(days=180)
    assert holds.prompt_reviews(db, due) == 1
    db.commit()
    assert told[-1]["title"] == "Legal hold review"
    assert holds.prompt_reviews(db, due + timedelta(days=30)) == 0
    assert holds.review(db, case, by=people.bob, now=due + timedelta(days=31)) == 1
    db.commit()
    (row,) = holds.standing(db, case.id)
    assert row.last_reviewed_at == due + timedelta(days=31) and row.review_prompted_at is None
    assert _rows(db, "hold_reviewed")[0].case_id == case.id
    assert holds.prompt_reviews(db, due + timedelta(days=31 + 179)) == 0
    assert holds.prompt_reviews(db, due + timedelta(days=31 + 180)) == 1
    assert holds.standing(db, case.id), "nothing is released by the clock"


# --------------------------------------------------------------------------- releasing, undoing, purging

def test_the_placer_or_an_independent_administrator_releases_with_a_reason(db, people, told):
    case = _place(db, people.ada, [people.v1, people.v2])
    kept = _keep(db, people.v1)
    oscar = _user(db, "oscar", m.RoleEnum.ADMIN)
    assert holds.release_refusal(db, case, oscar, NOW) is None
    owner_admin = _user(db, "otto", m.RoleEnum.ADMIN)
    db.add(m.ComplianceCasePerson(case_id=case.id, user_id=owner_admin.id, why="named"))
    db.commit()
    assert holds.release_refusal(db, case, owner_admin, NOW) == ind.CONCERNED
    assert holds.release_refusal(db, case, people.ada, NOW) is None
    at = NOW + timedelta(days=3)
    assert holds.release(db, case, by=people.ada, reason="The claim was withdrawn.", now=at) == 2
    db.commit()
    rows = db.query(m.LegalHoldVault).all()
    for r in rows:
        assert r.released_at == at and r.released_by == people.ada.id and r.purge_after == at + timedelta(days=7)
        assert open_case_field(case.id, r.release_reason_enc, "release_reason", item_id=r.vault_id) == \
            "The claim was withdrawn."
    assert db.get(m.HeldFile, kept.id).purge_after == at + timedelta(days=7)
    db.refresh(case)
    assert case.status == "closed" and open_case_field(case.id, case.close_reason_enc, "close_reason") == \
        "The claim was withdrawn."
    assert len(_rows(db, "hold_released")) == 2 and _rows(db, "case_closed")[0].case_id == case.id
    assert holds.release_refusal(db, case, people.ada, at) == holds.NOTHING_TO_RELEASE
    titles = [n.title for n in db.query(m.Notification).filter(m.Notification.user_id == people.olga.id)]
    assert titles == ["Legal hold on your vaults", "Legal hold released"]


def test_a_raised_purge_delay_counts_and_a_lowered_one_does_not(db, people, settings):
    case = _place(db, people.ada, [people.v1])
    settings[cs.HOLD_PURGE_DELAY_DAYS] = 10
    holds.release(db, case, by=people.ada, reason="r", now=NOW)
    assert holds.last_release(db, case.id)[0].purge_after == NOW + timedelta(days=10)
    case2 = _place(db, people.bob, [people.v2])
    settings[cs.HOLD_PURGE_DELAY_DAYS] = 2
    holds.release(db, case2, by=people.bob, reason="r", now=NOW)
    assert holds.last_release(db, case2.id)[0].purge_after == NOW + timedelta(days=10)


def test_an_independent_administrator_undoes_a_release_before_the_purge(db, people):
    case = _place(db, people.ada, [people.v1])
    holds.confirm(db, case, by=people.bob, now=NOW)
    kept = _keep(db, people.v1)
    released = NOW + timedelta(days=1)
    holds.release(db, case, by=people.ada, reason="r", now=released)
    db.commit()
    assert holds.undo_refusal(db, case, people.ada, released) == ind.ASKED
    assert holds.undo_refusal(db, case, people.bob, released) is None
    assert holds.undo_release(db, case, by=people.bob, now=released + timedelta(days=6)) == 1
    db.commit()
    (row,) = holds.standing(db, case.id)
    assert row.confirmed_by == people.bob.id and row.purge_after is None and row.release_reason_enc is None
    assert db.get(m.HeldFile, kept.id).purge_after is None
    db.refresh(case)
    assert case.status == "hold_only" and case.closed_at is None and case.records_kept_until is None
    assert _rows(db, "hold_release_undone")[0].case_id == case.id
    assert holds.undo_refusal(db, case, people.bob, released) == holds.NOTHING_TO_UNDO
    # Released again, it can no longer be undone once its purge time has come.
    again = released + timedelta(days=7)
    holds.release(db, case, by=people.ada, reason="r2", now=again)
    db.commit()
    assert holds.undo_refusal(db, case, people.bob, again + timedelta(days=7)) == holds.UNDO_TOO_LATE


def test_a_lapse_is_not_undone(db, people):
    case = _place(db, people.ada, [people.v1])
    holds.lapse_due(db, NOW + timedelta(days=7))
    db.commit()
    assert holds.undo_refusal(db, case, people.bob, NOW + timedelta(days=8)) == holds.NOTHING_TO_UNDO


def _purge(db, now, destroyed):
    records = []
    count = holds.purge(lambda: db, now=now, batch=2, destroy=destroyed.extend,
                        record=lambda db_, n, table: records.append((table, n)))
    return count, records


def test_the_purge_waits_for_every_hold_and_its_delay_then_deletes_records_and_destroys(db, people):
    case = _place(db, people.ada, [people.v1])
    files = [_keep(db, people.v1, path=f"p{i}") for i in range(3)]
    paths, ids = sorted(f.storage_path for f in files), sorted(str(f.id) for f in files)
    folder = _keep(db, people.v1, folder=True)
    db.add(m.HeldNameHistory(object_id=uuid.uuid4(), vault_id=people.v1.id, kind="file", name="old.txt"))
    db.commit()
    destroyed = []
    db.close = lambda: None
    assert _purge(db, NOW + timedelta(days=100), destroyed) == (0, [])      # the hold stands
    holds.release(db, case, by=people.ada, reason="r", now=NOW)
    db.commit()
    assert _purge(db, NOW + timedelta(days=7) - timedelta(seconds=1), destroyed)[0] == 0   # its delay runs
    count, records = _purge(db, NOW + timedelta(days=7), destroyed)
    assert count == 3 and sorted(destroyed) == paths
    assert db.query(m.HeldFile).count() == 0 and db.query(m.HeldFolder).count() == 0
    assert db.query(m.HeldNameHistory).count() == 0 and folder is not None
    purged = _rows(db, "held_file_purged")
    assert sorted(r.resource_id for r in purged) == ids
    assert ("held_files", 2) in records and ("held_files", 1) in records
    assert ("held_folders", 1) in records and ("held_name_history", 1) in records
    # The hold's own record stays.
    assert db.query(m.LegalHoldVault).count() == 1


def test_a_kept_file_is_not_purged_while_another_hold_stands_on_its_vault(db, people):
    first = _place(db, people.ada, [people.v1])
    _place(db, people.bob, [people.v1])
    _keep(db, people.v1)
    holds.release(db, first, by=people.ada, reason="r", now=NOW)
    db.commit()
    db.close = lambda: None
    destroyed = []
    assert _purge(db, NOW + timedelta(days=30), destroyed) == (0, [])
    assert destroyed == [] and db.query(m.HeldFile).count() == 1


def test_a_kept_file_waits_for_the_latest_release_of_its_vault(db, people):
    first = _place(db, people.ada, [people.v1])
    second = _place(db, people.bob, [people.v1])
    _keep(db, people.v1)
    holds.release(db, first, by=people.ada, reason="r", now=NOW)
    holds.release(db, second, by=people.bob, reason="r", now=NOW + timedelta(days=5))
    db.commit()
    db.close = lambda: None
    destroyed = []
    assert _purge(db, NOW + timedelta(days=8), destroyed)[0] == 0
    assert _purge(db, NOW + timedelta(days=12), destroyed)[0] == 1


# --------------------------------------------------------------------------- the routes

@pytest.fixture
def steps(monkeypatch):
    asked = []
    for name in ("STEP_UP_HOLD_PLACE", "STEP_UP_HOLD_DECIDE"):
        check = getattr(cr, name)
        monkeypatch.setattr(cr, name, lambda db_, user, request, _a=check.action: asked.append((_a, user.username)))
    monkeypatch.setattr(holds, "utcnow", lambda: NOW)
    return asked


def _request():
    return SimpleNamespace(headers={}, client=None)


def _body(vaults, **kw):
    return cr.HoldPlacement(vault_ids=[v.id for v in vaults], **{**TEXT, **kw})


def test_the_routes_place_confirm_review_release_and_undo_each_with_the_step_up(db, people, steps):
    view = cr.place_hold(_body([people.v1]), _request(), people.ada, db)
    assert view["status"] == "hold_only" and view["you_may"]["confirm"]["may"] is False
    assert view["you_may"]["confirm"]["why_not"]["reason"] == holds.PLACER
    case_id = uuid.UUID(view["id"])
    view = cr.confirm_hold(case_id, _request(), people.bob, db)
    assert view["holds"][0]["confirmed_by"] == "bob"
    view = cr.review_hold(case_id, people.ada, db)
    assert view["holds"][0]["last_reviewed_at"] is not None
    view = cr.release_hold(case_id, cr.Reason(reason="done"), _request(), people.ada, db)
    assert view["holds"][0]["standing"] is False and view["status"] == "closed"
    view = cr.undo_hold_release(case_id, _request(), people.bob, db)
    assert view["holds"][0]["standing"] is True and view["status"] == "hold_only"
    assert steps == [("compliance.hold.place", "ada"), ("compliance.hold.decide", "bob"),
                     ("compliance.hold.decide", "ada"), ("compliance.hold.decide", "bob")]
    listed = cr.list_holds(people.bob, db)
    assert [c["id"] for c in listed["cases"]] == [str(case_id)]
    assert listed["cases"][0]["kept"] == {"files": 0, "bytes": 0, "folders": 0}


def test_a_refused_step_is_recorded_and_asks_for_no_code(db, people, steps):
    view = cr.place_hold(_body([people.v1]), _request(), people.ada, db)
    case_id = uuid.UUID(view["id"])
    with pytest.raises(HTTPException) as refused:
        cr.confirm_hold(case_id, _request(), people.ada, db)
    assert refused.value.status_code == 403 and refused.value.detail["reason"] == holds.PLACER
    failed = [r for r in _rows(db, "hold_confirmed") if r.status == "failure"]
    assert len(failed) == 1 and failed[0].case_id == case_id and failed[0].details["reason"] == holds.PLACER
    with pytest.raises(HTTPException) as refused:
        cr.review_hold(case_id, people.olga, db)
    assert refused.value.status_code == 404
    with pytest.raises(HTTPException) as refused:
        cr.place_hold(_body([people.v1]), _request(), people.olga, db)
    assert refused.value.status_code == 403 and _rows(db, "hold_placed")[-1].status == "failure"
    assert steps == [("compliance.hold.place", "ada")]


def test_a_case_only_shows_counts_and_sizes(db, people, steps):
    view = cr.place_hold(_body([people.v1]), _request(), people.ada, db)
    _keep(db, people.v1, size=123)
    listed = cr.list_holds(people.bob, db)["cases"][0]
    assert listed["kept"] == {"files": 1, "bytes": 123, "folders": 0}
    text = str(listed)
    assert TEXT["justification"] not in text and TEXT["owner_note"] not in text and "olga" not in text
    assert view["id"] == listed["id"]


# --------------------------------------------------------------------------- why each deletion happens

def test_each_deleting_path_says_why_for_what_a_hold_keeps():
    """The reason and the actor a kept row records come from the deleting code (app/core/kept_tables.py,
    mark_deletes), set in the transaction of the deletion, before it."""
    import inspect
    from pathlib import Path
    from app.services.vault_service import VaultService
    root = Path(__file__).resolve().parent.parent

    def order(fn, said, deletion):
        source = inspect.getsource(fn)
        assert source.index(said) < source.index(deletion), fn.__name__

    order(VaultService.delete_file, "kept_tables.mark_deletes(self.db, reason, user)", "self.db.delete(file)")
    order(VaultService._stage_same_name_replacement, 'kept_tables.mark_deletes(self.db, "replaced", actor)',
          "self.db.delete(ex)")
    order(VaultService.cleanup_expired_files, 'kept_tables.mark_deletes(self.db, "expired")',
          "self.db.query(File).filter(File.id.in_([r.id for r in rows])).delete(")
    order(VaultService.delete_folder_tree, 'kept_tables.mark_deletes(self.db, "deleted", user)',
          "self.db.query(Folder).filter(Folder.id.in_(tree)).delete(")
    order(VaultService.move_file, "self._stream_copy_file_record(", 'self.delete_file(file_id, user, reason="moved")')
    assert "actor=file_info.get('uploaded_by')" in inspect.getsource(VaultService.finalize_streaming_upload)
    api = (root / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    collapse = api.split("def _add_name_uniqueness", 1)[1].split("\ndef ", 1)[0]
    assert collapse.index('kept_tables.mark_deletes(db, "duplicate")') < collapse.index("db.delete(f)")


# --------------------------------------------------------------------------- the case on every row

def test_rows_built_while_acting_for_a_case_carry_it_and_others_do_not(db):
    from app.services.audit_logger import AuditLogger
    case_id = uuid.uuid4()
    with case_context.acting_for(case_id):
        inside = AuditLogger(db).build_row(action="hold_reviewed", status="success")
    outside = AuditLogger(db).build_row(action="hold_reviewed", status="success")
    assert inside.case_id == case_id and outside.case_id is None
    assert case_context.current() is None
