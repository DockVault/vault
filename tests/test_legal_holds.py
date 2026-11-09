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


@pytest.fixture
def clock_after_placing(monkeypatch):
    """The module's clock an hour after NOW. A test that places a hold at NOW and then calls a path that reads the
    clock itself (the host's steps, the case summary, an undo) needs it: read from the wall clock, that path would
    see the hold's confirmation time, or the purge time of its release, run out days after NOW, whatever day the
    suite runs. NOW itself stays a fixed date: case numbers carry its year."""
    monkeypatch.setattr(holds, "utcnow", lambda: NOW + timedelta(hours=1))


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


def _totp(db, user):
    """An authenticator for ``user``: a confirmation asks for its code, so only then can they confirm."""
    db.add(m.SecondFactorEnrollment(user_id=user.id, method="totp", secret_enc="sealed", status="active"))
    db.commit()


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
    # The owner is told in the placing transaction (one notice for both vaults, in the app and through the email
    # outbox); the administrators after it.
    notes = db.query(m.Notification).filter(m.Notification.type == "compliance_access").all()
    assert [(n.user_id, n.title) for n in notes] == [(people.olga.id, "Legal hold on your vaults")]
    assert "2 vaults" in notes[0].body and case.number in notes[0].body
    assert TEXT["justification"] not in notes[0].body and TEXT["owner_note"] not in notes[0].body
    assert [(o.user_id, o.kind) for o in db.query(m.ComplianceNoticeOutbox)] == [(people.olga.id, "hold_placed")]
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


def test_one_person_keeps_at_most_five_hold_only_cases_waiting_for_confirmation(db, people):
    """Placing a hold needs no second person, and each keeps what is deleted from its vaults until it is confirmed
    or lapses: one person may have MAX_UNCONFIRMED_CASES of them waiting at once. Another person may still place
    one, and the placer may again once one of theirs is confirmed, released (the placer may release their own), or
    past its confirm deadline (it lapses then, whether or not the job has run yet)."""
    assert holds.MAX_UNCONFIRMED_CASES == 5
    cases = [_place(db, people.ada, [people.v1, people.v2]) for _ in range(5)]
    refused = _refused(holds.place_hold_only, db, people.ada, [people.v2.id], now=NOW, **TEXT)
    assert refused.reason == holds.TOO_MANY_UNCONFIRMED and refused.code == 409
    assert holds.text(refused.reason).startswith("5 legal holds you placed are waiting for another person")
    db.rollback()
    assert db.query(m.ComplianceCase).count() == 5
    _place(db, people.bob, [people.v2])
    holds.confirm(db, cases[0], by=people.bob, now=NOW)
    db.commit()
    _place(db, people.ada, [people.v2])
    assert _refused(holds.place_hold_only, db, people.ada, [people.v2.id], now=NOW,
                    **TEXT).reason == holds.TOO_MANY_UNCONFIRMED
    db.rollback()
    # A hold the placer releases frees its place, as the refusal says. Releasing it unconfirmed keeps the placer
    # from its vaults for PLACE_BLOCK_DAYS, so the next is placed on a third vault.
    assert holds.release_refusal(db, cases[1], people.ada, now=NOW) is None
    assert holds.release(db, cases[1], by=people.ada, reason="no longer needed", now=NOW) == 2
    db.commit()
    v3 = _vault(db, people.olga)
    assert _refused(holds.place_hold_only, db, people.ada, [people.v2.id], now=NOW,
                    **TEXT).reason == holds.PLACE_BLOCKED
    db.rollback()
    _place(db, people.ada, [v3])
    assert _refused(holds.place_hold_only, db, people.ada, [v3.id], now=NOW,
                    **TEXT).reason == holds.TOO_MANY_UNCONFIRMED
    db.rollback()
    assert _place(db, people.ada, [v3], now=NOW + timedelta(days=7)).status == "hold_only"


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
                                         ("created_placer", ind.CREATED_SUBJECT),
                                         ("made_by_placers_creator", ind.MADE_BY_CREATOR),
                                         ("made_placers_creator", ind.MADE_CREATOR)])
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
    elif who == "made_by_placers_creator":
        # cleo created pia's account and made mia an administrator; pia places, mia may not confirm.
        cleo = _user(db, "cleo", m.RoleEnum.ADMIN)
        person = _user(db, "mia", m.RoleEnum.ADMIN, by=cleo)
        placer = _user(db, "pia", m.RoleEnum.ADMIN, created_by=cleo.id)
        case = _place(db, placer, [people.v1])
    elif who == "made_placers_creator":
        # zed made cleo an administrator, cleo created pia's account; pia places, zed may not confirm.
        person = _user(db, "zed", m.RoleEnum.ADMIN)
        cleo = _user(db, "cleo", m.RoleEnum.ADMIN, by=person)
        placer = _user(db, "pia", m.RoleEnum.ADMIN, created_by=cleo.id)
        case = _place(db, placer, [people.v1])
    else:
        person = _user(db, "carl", m.RoleEnum.ADMIN)
        placer = _user(db, "pia", m.RoleEnum.ADMIN, created_by=person.id)
        case = _place(db, placer, [people.v1])
    assert holds.confirm_refusal(db, case, person, NOW) == reason


def test_an_administrator_whose_password_another_set_decides_nothing(db, people):
    case = _place(db, people.ada, [people.v1])
    holds.release(db, case, by=people.ada, reason="r", now=NOW + timedelta(hours=1))
    db.commit()
    case2 = _place(db, people.ada, [people.v2], now=NOW + timedelta(hours=2))
    people.bob.password_set_by = people.ada.id
    people.bob.password_set_by_other_at = NOW
    db.commit()
    at = NOW + timedelta(hours=3)
    assert holds.confirm_refusal(db, case2, people.bob, at) == ind.PASSWORD_NOT_OWN
    assert holds.release_refusal(db, case2, people.bob, at) == ind.PASSWORD_NOT_OWN
    assert holds.review_refusal(db, case2, people.bob, at) == ind.PASSWORD_NOT_OWN
    assert holds.undo_refusal(db, case, people.bob, at) == ind.PASSWORD_NOT_OWN


def test_an_administrator_who_changed_the_starters_sign_in_details_decides_nothing(db, people):
    db.add(m.CredentialChange(target_user_id=people.ada.id, kind="second_factor", status="made",
                              requested_by_id=people.bob.id, requested_by_name="bob",
                              requested_at=NOW - timedelta(hours=2), applied_at=NOW - timedelta(hours=2)))
    db.commit()
    case = _place(db, people.ada, [people.v1])
    at = NOW + timedelta(hours=1)
    assert holds.confirm_refusal(db, case, people.bob, at) == ind.CHANGED_ACCOUNT
    assert holds.release_refusal(db, case, people.bob, at) == ind.CHANGED_ACCOUNT
    assert holds.review_refusal(db, case, people.bob, at) == ind.CHANGED_ACCOUNT
    carl = _user(db, "carl", m.RoleEnum.ADMIN)
    assert holds.confirm_refusal(db, case, carl, at) is None


def test_an_administrator_who_cannot_act_or_an_ordinary_user_decides_nothing(db, people):
    case = _place(db, people.ada, [people.v1])
    gone = _user(db, "gina", m.RoleEnum.ADMIN)
    gone.is_active = False
    db.commit()
    assert holds.confirm_refusal(db, case, gone, NOW) == "not_able"
    assert holds.decider_refusal(db, case, _user(db, "ulla"), NOW) == "not_able"
    assert holds.confirm_refusal(db, case, people.bob, NOW) is None


def test_for_an_auditors_case_the_grants_exclusions_decide(db, people, monkeypatch):
    from app.core import case_eligibility
    asked = []
    monkeypatch.setattr(case_eligibility, "approver_refusal",
                        lambda db_, case, person, now=None: asked.append(person.username) or ind.PROPOSED)
    case = _place(db, people.ada, [people.v1])
    case.grant_id = uuid.uuid4()
    assert holds.decider_refusal(db, case, people.bob, NOW) == ind.PROPOSED and asked == ["bob"]


def test_the_host_confirms_as_the_operator_when_no_administrator_could(db, people, clock_after_placing):
    """bob is independent of ada but has no authenticator (the confirmation asks for its code): nobody can
    confirm on the web, so the server's operator may."""
    case = _place(db, people.ada, [people.v1])
    assert holds.independent_confirmers(db, case, NOW) == []
    out = host_compliance.CASE_STEPS["confirm-hold"](db, case)
    db.commit()
    assert out["confirmed"] == 1
    (row,) = holds.standing(db, case.id)
    assert row.confirmed_by is None and row.confirmed_by_username == "operator@host"
    assert _rows(db, "hold_confirmed")[0].username == "operator@host"
    from app.core.host_operator import _Answer
    with pytest.raises(_Answer):
        host_compliance.CASE_STEPS["confirm-hold"](db, case)


def test_the_host_may_not_confirm_while_an_administrator_could_and_the_refusal_is_recorded(db, people,
                                                                                         clock_after_placing):
    from app.core.host_operator import _Answer
    case = _place(db, people.ada, [people.v1])
    _totp(db, people.ada)        # the placer: never a confirmer
    _totp(db, people.bob)
    assert [a.username for a in holds.independent_confirmers(db, case, NOW)] == ["bob"]
    with pytest.raises(_Answer) as done:
        host_compliance.CASE_STEPS["confirm-hold"](db, case)
    assert done.value.code == 2 and "bob" in done.value.obj["error"] and "may not" in done.value.obj["error"]
    (row,) = holds.standing(db, case.id)
    assert row.confirmed_at is None
    (refused,) = [r for r in _rows(db, "hold_confirmed") if r.status == "failure"]
    assert refused.username == "operator@host" and refused.case_id == case.id
    assert refused.details["reason"] == holds.INDEPENDENT_ADMIN


def test_the_host_list_and_show_say_whether_the_host_may_confirm(db, people, clock_after_placing):
    case = _place(db, people.ada, [people.v1, people.v2])
    summary = host_compliance._case_summary(db, case)
    assert (summary["holds_to_confirm"], summary["independent_confirmers"], summary["host_may_confirm"]) == \
        (2, [], True)
    _totp(db, people.bob)
    summary = host_compliance._case_summary(db, case)
    assert (summary["independent_confirmers"], summary["host_may_confirm"]) == (["bob"], False)
    holds.confirm(db, case, by=people.bob, now=NOW)
    db.commit()
    summary = host_compliance._case_summary(db, case)
    assert (summary["holds_to_confirm"], summary["independent_confirmers"], summary["host_may_confirm"]) == \
        (0, [], False)


def test_past_its_confirm_deadline_a_hold_is_confirmed_by_nobody_before_the_job_lapses_it(db, people, monkeypatch):
    from app.core.host_operator import _Answer
    case = _place(db, people.ada, [people.v1])
    late = NOW + timedelta(days=7)
    assert holds.confirm_refusal(db, case, people.bob, late - timedelta(seconds=1)) is None
    assert holds.confirm_refusal(db, case, people.bob, late) == holds.CONFIRM_TOO_LATE
    assert holds.confirm(db, case, by=people.bob, now=late) == 0
    monkeypatch.setattr(holds, "utcnow", lambda: late)
    with pytest.raises(_Answer) as done:
        host_compliance.CASE_STEPS["confirm-hold"](db, case)
    assert "passed" in done.value.obj["error"]
    assert holds.standing(db, case.id)[0].confirmed_at is None
    assert holds.lapse_due(db, late) == 1


def test_a_confirmation_takes_the_turn_of_holds_and_deletions_before_it_writes(db, people, monkeypatch,
                                                                               clock_after_placing):
    """From its confirmation a hold holds back every erase and other deletion of records, so the confirmation takes
    the turn as a placing does: exclusively, before it writes (test_legal_hold_turn_routes_live.py shows the wait on
    Postgres). A deletion step that keeps the turn too long refuses the host's confirmation, recorded, and nothing
    is confirmed."""
    from app.core.host_operator import _Answer
    case = _place(db, people.ada, [people.v1])
    seen = []
    monkeypatch.setattr(holds, "take_turn", lambda db_, shared: seen.append(
        (shared, [h.confirmed_at for h in holds.standing(db_, case.id)])))
    assert holds.confirm(db, case, by=people.bob, now=NOW) == 1
    assert seen == [(False, [None])], "taken exclusively, before the hold was confirmed"
    db.rollback()

    def busy(db_, shared):
        raise holds.TurnBusy()
    monkeypatch.setattr(holds, "take_turn", busy)
    wanted = []
    monkeypatch.setattr(holds, "want_turn", lambda: wanted.append(True))
    with pytest.raises(_Answer) as done:
        host_compliance.CASE_STEPS["confirm-hold"](db, case)
    assert done.value.code == 2 and "try again" in done.value.obj["error"] and wanted == [True]
    assert holds.standing(db, case.id)[0].confirmed_at is None
    (refused,) = [r for r in _rows(db, "hold_confirmed") if r.status == "failure"]
    assert refused.details["reason"] == holds.DELETION_RUNNING and refused.username == "operator@host"


def test_run_as_a_program_the_tool_looks_its_case_steps_up_in_the_module_they_register_in():
    """``python -m app.core.host_compliance`` runs the file as __main__, a second copy of the module, while the
    modules that own the case steps register them into app.core.host_compliance. The program runs that module's
    run(), so its steps are found."""
    import runpy
    import sys
    ran = []
    real = host_compliance.run
    host_compliance.run = lambda argv=None: ran.append(argv) or 0
    try:
        with pytest.raises(SystemExit) as done:
            runpy.run_module("app.core.host_compliance", run_name="__main__")
    finally:
        host_compliance.run = real
    assert done.value.code == 0 and ran == [None]
    assert sys.modules["app.core.host_compliance"] is host_compliance
    assert "confirm-hold" in host_compliance.CASE_STEPS


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
    titles = [n.title for n in db.query(m.Notification).filter(m.Notification.user_id == people.olga.id)]
    assert titles == ["Legal hold on your vaults", "Legal hold lapsed"], "the owner is told of the lapse"


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


@pytest.mark.parametrize("by", ["placer", "another"])
def test_a_hold_released_unconfirmed_blocks_its_placer_as_a_lapse_does(db, people, by):
    """Releasing one's own unconfirmed hold before it lapses and placing another at once would keep deleted data
    for good with no second person ever agreeing. A hold that ended unconfirmed, however it ended, blocks its
    placer on those vaults for 30 days."""
    case = _place(db, people.ada, [people.v1])
    released = NOW + timedelta(days=6)
    holds.release(db, case, by=people.ada if by == "placer" else people.bob, reason="again", now=released)
    db.commit()
    assert _refused(holds.place_hold_only, db, people.ada, [people.v1.id], now=released + timedelta(minutes=1),
                    **TEXT).reason == holds.PLACE_BLOCKED
    db.rollback()
    assert _place(db, people.bob, [people.v1], now=released + timedelta(minutes=2)).status == "hold_only"
    assert _place(db, people.ada, [people.v1], now=released + timedelta(days=30, seconds=1)).status == "hold_only"


def test_a_confirmed_hold_released_does_not_block_its_placer(db, people):
    case = _place(db, people.ada, [people.v1])
    holds.confirm(db, case, by=people.bob, now=NOW + timedelta(hours=1))
    holds.release(db, case, by=people.ada, reason="done", now=NOW + timedelta(days=2))
    db.commit()
    assert _place(db, people.ada, [people.v1], now=NOW + timedelta(days=2, minutes=1)).status == "hold_only"


def test_releasing_and_placing_again_never_keeps_a_deleted_file_past_its_purge(db, people):
    """The rolling case the block ends: one person cannot carry a kept file forward through unconfirmed holds."""
    from sqlalchemy.orm import sessionmaker
    case = _place(db, people.ada, [people.v1])
    kept = _keep(db, people.v1)
    kept_id, kept_path = kept.id, kept.storage_path
    holds.release(db, case, by=people.ada, reason="again", now=NOW + timedelta(days=6))
    db.commit()
    assert _refused(holds.place_hold_only, db, people.ada, [people.v1.id], now=NOW + timedelta(days=6, minutes=1),
                    **TEXT).reason == holds.PLACE_BLOCKED
    db.rollback()
    destroyed = []
    holds.purge(sessionmaker(bind=db.get_bind()), now=NOW + timedelta(days=13), destroy=destroyed.extend)
    db.expire_all()
    assert db.get(m.HeldFile, kept_id) is None and destroyed == [kept_path]


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


def _live_auditor(monkeypatch, person, state):
    """``person`` holds an auditor right in force while state["live"] (else the reason in state["why"])."""
    grant = SimpleNamespace(id=uuid.uuid4())
    real = auditor_rights.auditor_live

    def live(db_, user, now=None):
        if user is not None and user.id == person.id:
            return auditor_rights.Standing(state["live"], None if state["live"] else state["why"], grant)
        return real(db_, user, now)
    monkeypatch.setattr(auditor_rights, "auditor_live", live)


def test_an_auditor_who_started_the_case_releases_and_reviews_it_only_while_their_right_is_in_force(
        db, people, monkeypatch):
    uma = _user(db, "uma")
    state = {"live": True, "why": None}
    _live_auditor(monkeypatch, uma, state)
    case = _place(db, uma, [people.v1])
    assert case.grant_id is not None
    for refusal in (holds.release_refusal, holds.review_refusal, cr._release_refusal, cr._review_refusal):
        assert refusal(db, case, uma, NOW) is None
    state.update(live=False, why=auditor_rights.NO_GRANT)        # revoked
    for refusal in (holds.release_refusal, holds.review_refusal, cr._release_refusal, cr._review_refusal):
        assert refusal(db, case, uma, NOW) == auditor_rights.NO_GRANT
    state.update(why=auditor_rights.SUSPENDED)
    assert holds.release_refusal(db, case, uma, NOW) == auditor_rights.SUSPENDED


def _changed_by(db, target, by, at):
    db.add(m.CredentialChange(target_user_id=target.id, kind="password", status="made", requested_by_id=by.id,
                              requested_by_name=by.username, requested_at=at, applied_at=at))
    db.commit()


@pytest.mark.parametrize("vector", ["demoted", "deactivated", "locked", "password_set_by_other",
                                    "sign_in_changed_by_other", "ssh_key_added_by_other"])
def test_an_administrator_who_placed_a_hold_ends_it_alone_only_while_they_stand_as_they_did(db, people, vector):
    case = _place(db, people.ada, [people.v1])
    after = NOW + timedelta(hours=1)
    ada = people.ada
    assert holds.release_refusal(db, case, ada, after) is None and holds.review_refusal(db, case, ada, after) is None
    expected = "not_able"
    if vector == "demoted":
        ada.role = m.RoleEnum.USER
    elif vector == "deactivated":
        ada.is_active = False
    elif vector == "locked":
        ada.is_locked, ada.locked_until = True, None        # an administrator's lock: no end time
    elif vector == "password_set_by_other":
        ada.password_set_by, ada.password_set_by_other_at = people.bob.id, after
        expected = ind.PASSWORD_NOT_OWN
    elif vector == "sign_in_changed_by_other":
        _changed_by(db, ada, people.bob, after)
        expected = holds.STARTER_CHANGED
    else:
        db.add(m.UserSSHKey(user_id=ada.id, name="k", public_key="ssh-ed25519 AAAA test", fingerprint="SHA256:x",
                            created_by=people.bob.id, created_at=after))
        expected = holds.STARTER_CHANGED
    db.commit()
    at = after + timedelta(minutes=1)
    assert holds.release_refusal(db, case, ada, at) == expected
    assert holds.review_refusal(db, case, ada, at) == expected
    carl = _user(db, "carl", m.RoleEnum.ADMIN)
    assert holds.release_refusal(db, case, carl, at) is None, "an independent administrator still may"


def test_a_change_to_the_starters_sign_in_details_before_the_case_started_does_not_count(db, people):
    _changed_by(db, people.ada, people.bob, NOW - timedelta(days=1))
    case = _place(db, people.ada, [people.v1])
    assert holds.release_refusal(db, case, people.ada, NOW + timedelta(hours=1)) is None


def test_a_starter_whose_auditor_right_is_in_force_ends_the_hold_alone_as_its_auditor(db, people, monkeypatch):
    """An administrator who started the case and holds an auditor right in force (reconfirmed with their own
    password and authenticator after someone else changed their sign-in details) stands as an auditor, which is
    enough; as an administrator alone that change would refuse them."""
    case = _place(db, people.ada, [people.v1])
    _changed_by(db, people.ada, people.bob, NOW + timedelta(hours=1))
    at = NOW + timedelta(hours=2)
    assert holds.release_refusal(db, case, people.ada, at) == holds.STARTER_CHANGED
    _live_auditor(monkeypatch, people.ada, {"live": True, "why": None})
    assert holds.release_refusal(db, case, people.ada, at) is None
    assert holds.review_refusal(db, case, people.ada, at) is None


def test_a_case_started_as_an_auditor_counts_only_the_auditor_right(db, people, monkeypatch):
    """An administrator who started a case as an auditor (the case records the grant) ends its hold alone only while
    that right is in force: being an administrator able to act, with their own password and nobody else's change,
    does not stand in for a right revoked or suspended since."""
    state = {"live": True, "why": None}
    _live_auditor(monkeypatch, people.ada, state)
    case = _place(db, people.ada, [people.v1])
    assert case.grant_id is not None
    at = NOW + timedelta(hours=1)
    assert holds.release_refusal(db, case, people.ada, at) is None
    for why in (auditor_rights.NO_GRANT, auditor_rights.SUSPENDED, auditor_rights.EXPIRED):
        state.update(live=False, why=why)
        for refusal in (holds.release_refusal, holds.review_refusal, cr._release_refusal, cr._review_refusal):
            assert refusal(db, case, people.ada, at) == why


# --------------------------------------------------------------------------- a change kept on the case

@pytest.fixture
def changing(monkeypatch):
    """The credential-change routes' own helper (api_server._credential_change), with what is not the database left
    out: a reset link is made without the reset machinery, no session is ended, nothing is told."""
    from app.api import api_server as api
    monkeypatch.setattr(api, "_mint_reset_link",
                        lambda db_, user, base_url, *, created_by_id, made_by_other=False: "https://v.test/?reset=x")
    monkeypatch.setattr(api, "_password_reset_policy", lambda db_: (True, 30))
    monkeypatch.setattr(api, "_revoke_sessions", lambda db_, **kw: 0)
    monkeypatch.setattr(auditor_rights, "deliver", lambda notices: None)
    return api


CHANGES = {
    cc.PASSWORD: {"password_hash": "set-by-bob"},
    cc.EMAIL: {"email": "ada.elsewhere@example.test"},
    cc.RESET_LINK: {"delivery": "copy"},
    cc.SSH_KEY: {"name": "k", "key_type": "ssh-ed25519", "public_key": "ssh-ed25519 AAAA", "fingerprint": "SHA256:k"},
    cc.SECOND_FACTOR: {},
}


def _undone_by_the_account(db, ada, kind):
    """What the account's controller does afterwards so that nothing on the account itself shows the change: their
    own password, the key removed, an authenticator enrolled again."""
    from app.core import password_origin
    password_origin.set_by_self(ada)
    if kind == cc.SSH_KEY:
        db.query(m.UserSSHKey).filter(m.UserSSHKey.user_id == ada.id).delete()
    if kind == cc.SECOND_FACTOR:
        ada.second_factor_reset_at = None
        _totp(db, ada)
    db.commit()


@pytest.mark.parametrize("kind", list(CHANGES))
def test_a_change_by_someone_else_still_refuses_the_starter_after_its_record_is_pruned(db, people, changing, kind):
    """Another administrator changes the sign-in details of the administrator who placed a hold. The account's own
    flags clear once it sets its own password or enrolls again, and the change's record is deleted 14 days after it
    applied: the case keeps the change, so whoever holds the account still does not end the hold alone."""
    start = holds.utcnow() - timedelta(hours=2)
    case = _place(db, people.ada, [people.v1], now=start)
    ada = people.ada
    changing._credential_change(db, people.bob, ada, kind, summary=kind, payload=dict(CHANGES[kind]))
    db.commit()
    db.expire_all()
    assert (case.starter_changed_at, case.starter_changed_kind) != (None, None) and case.starter_changed_kind == kind
    _undone_by_the_account(db, ada, kind)
    soon = holds.utcnow() + timedelta(minutes=1)
    assert holds.release_refusal(db, case, ada, soon) == holds.STARTER_CHANGED
    later = holds.utcnow() + cc.WINDOW + timedelta(days=1)
    cc.prune_done(db, later)
    db.commit()
    assert db.query(m.CredentialChange).filter(m.CredentialChange.target_user_id == ada.id).count() == 0
    for refusal in (holds.release_refusal, holds.review_refusal, cr._release_refusal, cr._review_refusal):
        assert refusal(db, case, ada, later) == holds.STARTER_CHANGED, refusal
    from app.core import cases
    assert cases.close_refusal(db, case, ada, later) == holds.STARTER_CHANGED
    # An independent administrator still ends it.
    assert holds.release_refusal(db, case, people.bob, later) is None


def test_the_change_is_kept_on_every_case_the_account_started_and_only_the_first_one(db, people, changing):
    start = holds.utcnow() - timedelta(hours=2)
    one = _place(db, people.ada, [people.v1], now=start)
    other = _place(db, people.ada, [people.v2], now=start)
    bobs = _place(db, people.bob, [_vault(db, people.olga)], now=start)
    changing._credential_change(db, people.bob, people.ada, cc.EMAIL, summary="e", payload=dict(CHANGES[cc.EMAIL]))
    db.commit()
    db.expire_all()
    first = one.starter_changed_at
    assert first is not None and other.starter_changed_at == first and bobs.starter_changed_at is None
    assert holds.after_starter_change(db, people.ada, cc.PASSWORD, now=first + timedelta(days=3)) == 0
    db.commit()
    db.expire_all()
    assert (one.starter_changed_at, one.starter_changed_kind) == (first, cc.EMAIL)


def test_the_accounts_own_change_through_an_administrators_route_is_not_kept(db, people, changing):
    case = _place(db, people.ada, [people.v1], now=holds.utcnow() - timedelta(hours=2))
    changing._credential_change(db, people.ada, people.ada, cc.EMAIL, summary="e", payload=dict(CHANGES[cc.EMAIL]))
    db.commit()
    db.expire_all()
    assert case.starter_changed_at is None
    assert holds.release_refusal(db, case, people.ada, holds.utcnow()) is None


def test_a_change_before_the_case_started_is_not_kept_on_it(db, people, changing):
    changing._credential_change(db, people.bob, people.ada, cc.EMAIL, summary="e", payload=dict(CHANGES[cc.EMAIL]))
    db.commit()
    case = _place(db, people.ada, [people.v1], now=holds.utcnow() + timedelta(seconds=1))
    assert case.starter_changed_at is None
    assert holds.release_refusal(db, case, people.ada, holds.utcnow() + timedelta(minutes=1)) is None


def test_a_change_while_the_case_is_closed_counts_once_an_undo_opens_it_again(db, people, changing):
    """The administrator who placed a hold releases it (the case closes); someone else then changes their sign-in
    details; an independent administrator undoes the release. The case kept the change while closed."""
    cara = _user(db, "cara", m.RoleEnum.ADMIN)
    case = _place(db, people.ada, [people.v1], now=holds.utcnow() - timedelta(hours=2))
    holds.release(db, case, by=people.ada, reason="done")
    db.commit()
    assert case.status == "closed"
    changing._credential_change(db, people.bob, people.ada, cc.EMAIL, summary="e", payload=dict(CHANGES[cc.EMAIL]))
    db.commit()
    assert holds.undo_refusal(db, case, cara) is None
    holds.undo_release(db, case, by=cara)
    db.commit()
    assert case.status == "hold_only"
    later = holds.utcnow() + cc.WINDOW + timedelta(days=1)
    cc.prune_done(db, later)
    db.commit()
    assert holds.release_refusal(db, case, people.ada, later) == holds.STARTER_CHANGED


def test_a_link_someone_else_made_before_the_case_and_used_after_it_is_kept_on_it(db, people, monkeypatch):
    """A reset link another administrator made before the case started, used after it: the password the link set is
    theirs, and the case keeps that once the account sets its own password again."""
    from _async_run import run_coroutine
    from app.api import api_server as api
    from app.core import password_origin, password_reset, rate_limiter
    pepper = "r" * 48 + ":password_reset"
    monkeypatch.setattr(api, "_reset_pepper", lambda: pepper)
    monkeypatch.setattr(password_reset, "pepper_ok", lambda value: True)
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))
    monkeypatch.setattr(api, "_validate_password_policy", lambda db_, pw: None)
    monkeypatch.setattr(api, "_revoke_sessions", lambda db_, **kw: 0)
    monkeypatch.setattr(api, "_password_reset_policy", lambda db_: (False, 15))
    link = api._mint_reset_link(db, people.ada, "https://vault.example.com", created_by_id=people.bob.id,
                                made_by_other=True)
    case = _place(db, people.ada, [people.v1], now=holds.utcnow())
    assert case.starter_changed_at is None
    run_coroutine(api.do_reset(token=link.split("?reset=")[1],
                               body=api.ResetPasswordRequest(new_password="Set-Through-Bobs-Link-1!"),
                               request=SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.9")), db=db))
    db.expire_all()
    assert case.starter_changed_kind == cc.PASSWORD
    password_origin.set_by_self(people.ada)
    db.commit()
    later = holds.utcnow() + cc.WINDOW + timedelta(days=1)
    assert holds.release_refusal(db, case, people.ada, later) == holds.STARTER_CHANGED


def test_a_raised_purge_delay_counts_and_a_lowered_one_does_not(db, people, settings):
    case = _place(db, people.ada, [people.v1])
    settings[cs.HOLD_PURGE_DELAY_DAYS] = 10
    holds.release(db, case, by=people.ada, reason="r", now=NOW)
    assert holds.last_release(db, case.id)[0].purge_after == NOW + timedelta(days=10)
    case2 = _place(db, people.bob, [people.v2])
    settings[cs.HOLD_PURGE_DELAY_DAYS] = 2
    holds.release(db, case2, by=people.bob, reason="r", now=NOW)
    assert holds.last_release(db, case2.id)[0].purge_after == NOW + timedelta(days=10)


def test_an_independent_administrator_undoes_a_release_before_the_purge(db, people, clock_after_placing):
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
    assert row.confirmed_at == NOW and row.confirmed_by_username == "bob", "restored with its confirmation"
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


def test_an_undo_locks_the_vaults_then_reads_the_purge_time_again(db, people, monkeypatch):
    """The undo takes each vault's row FOR UPDATE, as a placing does (the purge leaves a vault so locked), and
    reads the purge time once it holds them: an undo checked just before the purge time that gets the lock after
    it is refused, so no hold is restored over kept rows a purge has taken."""
    case = _place(db, people.ada, [people.v1])
    holds.release(db, case, by=people.ada, reason="r", now=NOW)
    db.commit()
    purge_at = holds.last_release(db, case.id)[0].purge_after
    locked = []
    real = holds._lock_vaults
    monkeypatch.setattr(holds, "_lock_vaults", lambda db_, ids: locked.append(sorted(map(str, ids))) or real(db_, ids))
    monkeypatch.setattr(holds, "utcnow", lambda: purge_at)       # the lock came after the purge time
    just_before = purge_at - timedelta(seconds=1)
    assert holds.undo_refusal(db, case, people.bob, just_before) is None
    assert _refused(holds.undo_release, db, case, by=people.bob, now=just_before).reason == holds.UNDO_TOO_LATE
    assert locked == [[str(people.v1.id)]]
    db.rollback()
    assert holds.standing(db, case.id) == []


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


def test_kept_folders_and_old_names_go_only_with_the_last_kept_file_of_their_vault(db, people):
    case = _place(db, people.ada, [people.v1])
    for i in range(3):
        _keep(db, people.v1, path=f"q{i}")
    _keep(db, people.v1, folder=True)
    db.add(m.HeldNameHistory(object_id=uuid.uuid4(), vault_id=people.v1.id, kind="file", name="old.txt"))
    db.commit()
    holds.release(db, case, by=people.ada, reason="r", now=NOW)
    db.commit()
    db.close = lambda: None
    passes = iter([True, False])
    destroyed = []
    # One batch of two, then out of time: a kept file of the vault is left, so its folders and names stay.
    assert holds.purge(lambda: db, now=NOW + timedelta(days=8), batch=2, destroy=destroyed.extend,
                       time_left=lambda: next(passes)) == 2
    assert db.query(m.HeldFile).count() == 1
    assert db.query(m.HeldFolder).count() == 1 and db.query(m.HeldNameHistory).count() == 1
    assert holds.purge(lambda: db, now=NOW + timedelta(days=8), batch=2, destroy=destroyed.extend) == 1
    assert db.query(m.HeldFolder).count() == 0 and db.query(m.HeldNameHistory).count() == 0


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


def test_a_standing_hold_keeps_its_files_whatever_its_purge_time_says(db, people):
    """A hold that stands (never released) keeps what it kept, even when its row carries a purge time from an
    earlier release or an older write: only a released hold's time counts."""
    case = _place(db, people.ada, [people.v1])
    _keep(db, people.v1)
    (hold,) = holds.standing(db, case.id)
    hold.purge_after = NOW - timedelta(days=30)
    db.commit()
    db.close = lambda: None
    destroyed = []
    assert _purge(db, NOW, destroyed) == (0, []) and destroyed == []
    assert db.query(m.HeldFile).count() == 1


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


# --------------------------------------------------------------------------- the rollback marker

def _marker(db):
    return db.execute(__import__("sqlalchemy").text(
        "SELECT requires_at_least, reason, undo FROM data_requirements WHERE key = 'legal-holds'")).first()


def test_the_marker_follows_the_holds_and_the_kept_rows(db, people):
    from app.core import legal_hold_marker
    assert legal_hold_marker.sync(db) is False and _marker(db) is None
    case = _place(db, people.ada, [people.v1])
    row = _marker(db)
    assert row is not None and "Legal holds keep files deleted from vaults" in row[1] and "Release every" in row[2]
    _keep(db, people.v1)
    holds.release(db, case, by=people.ada, reason="r", now=NOW)
    db.commit()
    assert _marker(db) is not None, "kept rows wait for their purge"
    db.close = lambda: None
    _purge(db, NOW + timedelta(days=7), [])
    assert _marker(db) is None


def test_releasing_a_hold_that_kept_nothing_removes_the_marker_at_once(db, people):
    case = _place(db, people.ada, [people.v1])
    holds.release(db, case, by=people.ada, reason="r", now=NOW)
    db.commit()
    assert _marker(db) is None


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


@pytest.mark.parametrize("why", [holds.CONFIRM_TOO_LATE, holds.NOTHING_TO_CONFIRM, holds.NOTHING_TO_RELEASE,
                                 holds.NOTHING_TO_REVIEW, holds.NOTHING_TO_UNDO, holds.UNDO_TOO_LATE])
def test_a_step_with_nothing_left_to_act_on_answers_409_is_recorded_and_asks_for_no_code(db, people, steps,
                                                                                       monkeypatch, why):
    """A step the case's state leaves nothing to do for (nothing waiting, or its time passed) conflicts with the
    case, 409, whoever asks: it is not a refusal of the person (403). It is recorded with its reason, asks for no
    code and changes nothing."""
    view = cr.place_hold(_body([people.v1]), _request(), people.ada, db)
    case_id = uuid.UUID(view["id"])

    def at(when):
        monkeypatch.setattr(holds, "utcnow", lambda: when)

    def confirm():
        return cr.confirm_hold(case_id, _request(), people.bob, db)

    def release():
        return cr.release_hold(case_id, cr.Reason(reason="done"), _request(), people.ada, db)

    def review():
        return cr.review_hold(case_id, people.ada, db)

    def undo():
        return cr.undo_hold_release(case_id, _request(), people.bob, db)

    step, action = {holds.CONFIRM_TOO_LATE: (confirm, "hold_confirmed"),
                    holds.NOTHING_TO_CONFIRM: (confirm, "hold_confirmed"),
                    holds.NOTHING_TO_RELEASE: (release, "hold_released"),
                    holds.NOTHING_TO_REVIEW: (review, "hold_reviewed"),
                    holds.NOTHING_TO_UNDO: (undo, "hold_release_undone"),
                    holds.UNDO_TOO_LATE: (undo, "hold_release_undone")}[why]
    if why == holds.CONFIRM_TOO_LATE:
        at(NOW + timedelta(days=int(cs.current(cs.HOLD_CONFIRM_DAYS))))
    elif why == holds.NOTHING_TO_CONFIRM:
        confirm()
    elif why in (holds.NOTHING_TO_RELEASE, holds.NOTHING_TO_REVIEW, holds.UNDO_TOO_LATE):
        release()
        if why == holds.UNDO_TOO_LATE:
            at(NOW + timedelta(days=int(cs.current(cs.HOLD_PURGE_DELAY_DAYS))))
    asked = list(steps)
    before = [(h.vault_id, h.confirmed_at, h.released_at, h.last_reviewed_at) for h in db.query(m.LegalHoldVault)]
    with pytest.raises(HTTPException) as refused:
        step()
    assert refused.value.status_code == 409 and refused.value.detail["reason"] == why
    failed = [r for r in _rows(db, action) if r.status == "failure"]
    assert len(failed) == 1 and failed[0].case_id == case_id and failed[0].details["reason"] == why
    assert steps == asked, "no code is asked for a step with nothing to act on"
    db.expire_all()
    assert [(h.vault_id, h.confirmed_at, h.released_at, h.last_reviewed_at)
            for h in db.query(m.LegalHoldVault)] == before


def test_a_release_needs_a_reason_that_is_more_than_spaces(db, people, steps):
    view = cr.place_hold(_body([people.v1]), _request(), people.ada, db)
    case_id = uuid.UUID(view["id"])
    with pytest.raises(HTTPException) as refused:
        cr.release_hold(case_id, cr.Reason(reason="   "), _request(), people.ada, db)
    assert refused.value.status_code == 422 and refused.value.detail["reason"] == holds.NO_REASON
    assert holds.standing(db, case_id) and steps == [("compliance.hold.place", "ada")]
    view = cr.release_hold(case_id, cr.Reason(reason="  The claim was withdrawn. "), _request(), people.ada, db)
    (row,) = db.query(m.LegalHoldVault).all()
    assert open_case_field(case_id, row.release_reason_enc, "release_reason", item_id=row.vault_id) == \
        "The claim was withdrawn."


def test_an_auditor_lists_only_the_cases_they_started_and_only_while_their_right_is_in_force(
        db, people, steps, monkeypatch):
    uma = _user(db, "uma")
    state = {"live": True, "why": None}
    _live_auditor(monkeypatch, uma, state)
    mine = cr.place_hold(_body([people.v1]), _request(), uma, db)
    other = cr.place_hold(_body([people.v2]), _request(), people.ada, db)
    assert [c["id"] for c in cr.list_holds(uma, db)["cases"]] == [mine["id"]]
    assert sorted(c["id"] for c in cr.list_holds(people.bob, db)["cases"]) == sorted([mine["id"], other["id"]])
    state.update(live=False, why=auditor_rights.SUSPENDED)
    with pytest.raises(HTTPException) as refused:
        cr.list_holds(uma, db)
    assert refused.value.status_code == 403
    with pytest.raises(HTTPException) as refused:
        cr.list_holds(people.olga, db)
    assert refused.value.status_code == 403


def test_an_auditor_counts_only_what_their_own_hold_kept(db, people, steps, monkeypatch):
    """Rows kept on the same vault under another case, before the auditor's hold or after it ended, are that
    case's: an administrator sees every case and counts them all; the auditor does not."""
    uma = _user(db, "uma")
    _live_auditor(monkeypatch, uma, {"live": True, "why": None})
    _place(db, people.bob, [people.v1], now=NOW - timedelta(days=1))       # another case, standing throughout

    def kept_at(when, size):
        row = _keep(db, people.v1, size=size)
        row.kept_at = when
        db.commit()

    kept_at(NOW - timedelta(hours=1), 1000)        # before the auditor's hold
    mine = cr.place_hold(_body([people.v1]), _request(), uma, db)
    kept_at(NOW + timedelta(hours=1), 7)            # while it stands
    _keep(db, people.v1, folder=True).kept_at = NOW + timedelta(hours=2)
    db.commit()
    cr.release_hold(uuid.UUID(mine["id"]), cr.Reason(reason="done"), _request(), uma, db)
    db.query(m.LegalHoldVault).filter(m.LegalHoldVault.case_id == uuid.UUID(mine["id"])).update(
        {m.LegalHoldVault.released_at: NOW + timedelta(hours=3)}, synchronize_session=False)
    db.commit()
    kept_at(NOW + timedelta(hours=4), 50)           # after it ended
    (view,) = [c for c in cr.list_holds(uma, db)["cases"] if c["id"] == mine["id"]]
    assert view["kept"] == {"files": 1, "bytes": 7, "folders": 1}
    (admin_view,) = [c for c in cr.list_holds(people.ada, db)["cases"] if c["id"] == mine["id"]]
    assert admin_view["kept"] == {"files": 3, "bytes": 1057, "folders": 1}


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
