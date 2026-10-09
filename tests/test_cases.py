"""Compliance cases with access, offline on a real (SQLite) database (app/core/cases.py, its routes in
app/api/compliance_router.py, the pruner's compliance_cases job in app/core/retention.py, the host's approve and
reject in app/core/host_compliance.py).

Asking: a live auditor, the text, the days, the scope resolved into the vaults the approver sees and the people it
concerns; refused for an auditor it concerns, a sixth open case, too many vaults, a password vault the deployment
refuses. Approving: an independent administrator, in one transaction with the number, the access period, the hold
(confirmed by the approval) and every owner's notice and outbox row, or nothing; the owners read again. Turning
down, withdrawing, extending, narrowing, objections, closing; the clock; what each viewer sees; the routes' refusals,
each recorded. test_cases_live.py drives the flow on a running stack.
"""
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.api import compliance_router as cr  # noqa: E402
from app.core import admin_grants  # noqa: E402
from app.core import after_commit  # noqa: E402
from app.core import auditor_rights as rights  # noqa: E402
from app.core import case_rules as rules  # noqa: E402
from app.core import cases  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import host_compliance as hc  # noqa: E402
from app.core import independence as ind  # noqa: E402
from app.core import legal_holds as holds  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import owner_notices as on  # noqa: E402
from app.core.security import open_case_field  # noqa: E402

REAL_HOLDS_DELIVER = holds.deliver

pytestmark = pytest.mark.unit

OLD = timedelta(days=400)
TEXT = dict(purpose="internal_investigation", legal_basis="legal_obligation",
            justification="Suspected exfiltration of client records, ticket SEC-2041.",
            owner_note="Your vaults are part of an internal review.")


@pytest.fixture
def db():
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


@pytest.fixture(autouse=True)
def told(monkeypatch):
    """What was told after each commit (administrators, the auditor), instead of sending it."""
    from app.core import sftp_versions
    out = SimpleNamespace(cases=[], holds=[], rights=[])
    monkeypatch.setattr(cases, "_deliver", lambda notices: out.cases.extend(notices))
    after_commit.handler(cases._NOTICES, lambda notices: out.cases.extend(notices))
    monkeypatch.setattr(holds, "deliver", lambda notices: out.holds.extend(notices))
    monkeypatch.setattr(rights, "deliver", lambda notices: out.rights.extend(notices))
    after_commit.handler(on._NUDGES, lambda items: None)
    monkeypatch.setattr(on, "contact", lambda db_: None)
    monkeypatch.setattr(api, "_revoke_sessions", lambda db, **kw: 0)
    monkeypatch.setattr(sftp_versions, "sftp_same_version",
                        lambda db_, **_k: sftp_versions.VersionCheck(True, sftp_versions.SAME, ("0.34.0",)))
    yield out
    after_commit.handler(cases._NOTICES, cases._deliver)
    after_commit.handler(on._NUDGES, on._nudge)


@pytest.fixture
def settings(monkeypatch):
    values = {key: cs.current(key) for key in cs.KEYS}
    monkeypatch.setattr(cs, "current", lambda key: values[key])
    return values


def _user(db, name, role=m.RoleEnum.USER, *, totp=True, admin_for=OLD, created_by=None):
    u = m.User(username=name, email=f"{name}@example.test", password_hash="x", role=role, is_active=True,
               is_locked=False, created_by=created_by)
    db.add(u)
    db.commit()
    if role == m.RoleEnum.ADMIN:
        admin_grants.record(db, u.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR,
                            now=rights.utcnow() - admin_for)
    if totp:
        db.add(m.SecondFactorEnrollment(user_id=u.id, method="totp", secret_enc="sealed", status="active"))
    db.commit()
    return u


def _vault(db, owner, *, kind="standard", password=None):
    v = m.Vault(id=uuid.uuid4(), name="Payroll 2026", owner_id=owner.id, type=kind, password_hash=password,
                file_count=3, total_size_bytes=300)
    db.add(v)
    db.commit()
    return v


def _folder(db, vault, parent=None):
    f = m.Folder(id=uuid.uuid4(), vault_id=vault.id, name="Board minutes",
                 parent_folder_id=parent.id if parent is not None else None)
    db.add(f)
    db.commit()
    return f


@pytest.fixture
def people(db, settings):
    """ada proposed uma's auditor right and bob approved it; carl is another independent administrator; olga and
    otto own vaults."""
    ada, bob, carl = (_user(db, n, m.RoleEnum.ADMIN) for n in ("ada", "bob", "carl"))
    uma, olga, otto = _user(db, "uma"), _user(db, "olga"), _user(db, "otto")
    grant = rights.propose(db, uma, proposer=ada, now=rights.utcnow() - timedelta(hours=2))
    rights.approve(db, grant, approver=bob, now=rights.utcnow() - timedelta(hours=1))
    db.commit()
    return SimpleNamespace(ada=ada, bob=bob, carl=carl, uma=uma, olga=olga, otto=otto, grant=grant,
                           v1=_vault(db, olga), v2=_vault(db, olga), v3=_vault(db, otto))


def _ask(db, who, scope, **kw):
    case = cases.request_case(db, who, scope=scope, **{**TEXT, **kw})
    db.commit()
    return case


def _vaults(*vaults):
    return [{"kind": "vault", "target_id": v.id} for v in vaults]


def _refused(fn, *args, **kwargs):
    with pytest.raises(cases.CaseRefused) as refused:
        fn(*args, **kwargs)
    return refused.value


def _rows(db, action, status=None):
    q = db.query(m.AuditLog).filter(m.AuditLog.action == action)
    if status is not None:
        q = q.filter(m.AuditLog.status == status)
    return q.order_by(m.AuditLog.timestamp).all()


def _approve(db, case, by):
    cases.approve(db, case, approver=by)
    db.commit()
    return case


# --------------------------------------------------------------------------- asking

def test_a_live_auditor_asks_and_nothing_is_readable_or_told_to_the_owners_yet(db, people, told):
    case = _ask(db, people.uma, _vaults(people.v1, people.v3), named_user_ids=[people.carl.id])
    assert case.status == "pending" and case.number is None and case.access_starts_at is None
    assert case.grant_id == people.grant.id and case.access_days == 14 and case.hold_requested
    assert open_case_field(case.id, case.justification_enc, "justification") == TEXT["justification"]
    assert {(r.vault_id, r.folder_ids, r.owner_id_at_approval) for r in cases.vault_rows(db, case)} == {
        (people.v1.id, None, people.olga.id), (people.v3.id, None, people.otto.id)}
    assert {(p.user_id, p.why) for p in db.query(m.ComplianceCasePerson)} == {
        (people.olga.id, "owner"), (people.otto.id, "owner"), (people.carl.id, "named")}
    assert db.query(m.Notification).count() == 0 and db.query(m.ComplianceNoticeOutbox).count() == 0
    assert db.query(m.LegalHoldVault).count() == 0
    (asked,) = _rows(db, "case_requested")
    assert asked.case_id == case.id and asked.details["vaults"] == 2
    # The administrators who could approve it are told (carl is named, ada proposed the grant: neither may).
    (notice,) = told.cases
    assert set(notice["people"]) == {str(people.bob.id)} and TEXT["justification"] not in notice["body"]


def test_folders_and_a_custodian_resolve_into_the_list_the_approver_sees(db, people):
    f1 = _folder(db, people.v1)
    f2 = _folder(db, people.v1, parent=f1)
    case = _ask(db, people.uma, [{"kind": "folder", "target_id": f2.id}, {"kind": "custodian", "target_id": people.otto.id}])
    rows = {r.vault_id: r.folder_ids for r in cases.vault_rows(db, case)}
    assert rows == {people.v1.id: [str(f2.id)], people.v3.id: None}
    assert {(p.user_id, p.why) for p in db.query(m.ComplianceCasePerson)} == {
        (people.olga.id, "owner"), (people.otto.id, "custodian")}
    later = _vault(db, people.otto)
    assert later.id not in rows, "a vault made after the request is not added"


@pytest.mark.parametrize("purpose,expected", [("internal_investigation", True), ("data_subject_request", False)])
def test_the_hold_follows_the_purpose_unless_asked(db, people, purpose, expected):
    assert _ask(db, people.uma, _vaults(people.v1), purpose=purpose).hold_requested is expected
    assert _ask(db, people.uma, _vaults(people.v2), purpose=purpose, hold=not expected).hold_requested is (not expected)


@pytest.mark.parametrize("change,reason,code", [
    (dict(purpose="curiosity"), rules.BAD_PURPOSE, 422),
    (dict(legal_basis="legitimate_interests"), rules.NO_LIA_REFERENCE, 422),
    (dict(justification="too short"), rules.SHORT_JUSTIFICATION, 422),
    (dict(special_category=True), rules.NO_ART9_CONDITION, 422),
    (dict(access_days=0), rules.BAD_DAYS, 422),
    (dict(access_days=31), rules.TOO_LONG, 422),
    (dict(files_from=rights.utcnow(), files_to=rights.utcnow() - timedelta(days=1)), rules.BAD_RANGE, 422),
])
def test_what_a_request_must_say(db, people, change, reason, code):
    refused = _refused(cases.request_case, db, people.uma, scope=_vaults(people.v1), **{**TEXT, **change})
    assert (refused.reason, refused.code) == (reason, code)


def test_settings_that_refuse_a_request(db, people, settings):
    settings[cs.EXPORT] = cs.DISABLED
    assert _refused(cases.request_case, db, people.uma, scope=_vaults(people.v1), can_export=True,
                    **TEXT).reason == rules.EXPORT_OFF
    assert _refused(cases.request_case, db, people.uma, scope=_vaults(people.v1), password_override=True,
                    **TEXT).reason == rules.OVERRIDE_NOT_ALLOWED
    settings[cs.MAX_ACCESS_DAYS] = 10
    assert _refused(cases.request_case, db, people.uma, scope=_vaults(people.v1), access_days=11,
                    **TEXT).reason == rules.TOO_LONG
    settings[cs.MAX_CASE_VAULTS] = 1
    assert _refused(cases.request_case, db, people.uma, scope=_vaults(people.v1, people.v2), access_days=5,
                    **TEXT).reason == rules.TOO_MANY_VAULTS
    settings[cs.ACCESS] = cs.DISABLED
    assert _refused(cases.request_case, db, people.uma, scope=_vaults(people.v1), **TEXT).reason == rules.ACCESS_OFF


def test_a_sixth_open_case_is_refused(db, people):
    for _ in range(5):
        _ask(db, people.uma, _vaults(people.v1))
    refused = _refused(cases.request_case, db, people.uma, scope=_vaults(people.v1), **TEXT)
    assert (refused.reason, refused.code) == (rules.TOO_MANY_CASES, 409)
    db.rollback()
    first = db.query(m.ComplianceCase).first()
    cases.withdraw(db, first, by=people.uma)
    db.commit()
    assert _ask(db, people.uma, _vaults(people.v1)).status == "pending", "a withdrawn case no longer counts"


@pytest.mark.parametrize("scope_of", [
    lambda p: [{"kind": "vault", "target_id": p.own.id}],
    lambda p: [{"kind": "custodian", "target_id": p.uma.id}],
])
def test_an_auditor_the_case_concerns_is_refused(db, people, scope_of):
    people.own = _vault(db, people.uma)
    refused = _refused(cases.request_case, db, people.uma, scope=scope_of(people), **TEXT)
    assert (refused.reason, refused.code) == (rules.AUDITOR_CONCERNED, 403)


def test_naming_themselves_is_refused_too(db, people):
    refused = _refused(cases.request_case, db, people.uma, scope=_vaults(people.v1), named_user_ids=[people.uma.id],
                       **TEXT)
    assert refused.reason == rules.AUDITOR_CONCERNED


@pytest.mark.parametrize("scope,reason", [
    ([{"kind": "vault", "target_id": uuid.uuid4()}], rules.NO_SUCH_VAULT),
    ([{"kind": "folder", "target_id": uuid.uuid4()}], rules.NO_SUCH_FOLDER),
    ([{"kind": "custodian", "target_id": uuid.uuid4()}], rules.NO_SUCH_PERSON),
])
def test_what_does_not_exist_is_not_found(db, people, scope, reason):
    refused = _refused(cases.request_case, db, people.uma, scope=scope, **TEXT)
    assert (refused.reason, refused.code) == (reason, 404)


def test_a_password_vault_is_refused_while_the_deployment_refuses_them(db, people, settings):
    locked = _vault(db, people.olga, password="hash")
    settings[cs.PASSWORD_VAULTS] = cs.REFUSE
    assert _refused(cases.request_case, db, people.uma, scope=_vaults(locked), **TEXT).reason == \
        rules.PASSWORD_VAULT_REFUSED
    settings[cs.PASSWORD_VAULTS] = cs.WITH_PASSWORD
    assert _ask(db, people.uma, _vaults(locked)).status == "pending"


def test_an_auditor_whose_right_is_not_in_force_cannot_ask(db, people):
    rights.revoke(db, people.grant, actor=people.ada)
    db.commit()
    assert _refused(cases.request_case, db, people.uma, scope=_vaults(people.v1), **TEXT).reason == \
        rules.AUDITOR_NOT_LIVE


# --------------------------------------------------------------------------- approving

def test_the_approval_writes_everything_in_one_transaction(db, people, told):
    case = _ask(db, people.uma, _vaults(people.v1, people.v2, people.v3), access_days=10)
    before = rights.utcnow()
    _approve(db, case, people.bob)
    assert case.status == "active" and case.number.startswith("C-") and case.version == 2
    assert case.approved_by == people.bob.id and case.approved_by_username == "bob" and not case.approved_by_operator
    assert before <= case.approved_at <= rights.utcnow()
    assert case.access_starts_at == case.approved_at and case.access_ends_at == case.approved_at + timedelta(days=10)
    assert case.total_access_days == 10 and case.password_policy == cs.WITH_PASSWORD
    assert case.settings_at_approval == cs.snapshot()
    # The hold: placed at the auditor's request, confirmed by the approval.
    holds_rows = db.query(m.LegalHoldVault).filter(m.LegalHoldVault.case_id == case.id).all()
    assert len(holds_rows) == 3
    for h in holds_rows:
        assert h.placed_by == people.uma.id and h.confirmed_by == people.bob.id and h.confirmed_at == case.approved_at
    # Each owner told once (olga for two vaults), in the app and through the outbox, and recorded.
    notes = db.query(m.Notification).filter(m.Notification.type == "compliance_access").all()
    assert sorted((n.user_id, n.title) for n in notes) == sorted([
        (people.olga.id, "An investigation can open 2 of your vaults"),
        (people.otto.id, "An investigation can open 1 of your vaults")])
    assert all(TEXT["justification"] not in n.body and "carl" not in n.body for n in notes)
    outbox = db.query(m.ComplianceNoticeOutbox).filter(m.ComplianceNoticeOutbox.case_id == case.id).all()
    assert sorted((o.user_id, o.kind, o.details["vaults"]) for o in outbox) == sorted([
        (people.olga.id, "activation", 2), (people.otto.id, "activation", 1)])
    assert len(_rows(db, "owner_notice_written")) == 2 and _rows(db, "case_approved")[0].case_id == case.id
    assert {r.notice_written_at for r in cases.vault_rows(db, case)} == {case.approved_at}
    assert case.notice_written_at == case.approved_at and case.notice_email_status == "queued"
    assert told.cases[-1]["title"] == "Case approved"


def test_a_fault_in_an_owners_notice_fails_the_approval_and_nothing_is_given(db, people, monkeypatch):
    case = _ask(db, people.uma, _vaults(people.v1))

    def broken(*a, **k):
        raise RuntimeError("the outbox could not be written")
    monkeypatch.setattr(on, "tell_owners", broken)
    with pytest.raises(RuntimeError):
        cases.approve(db, case, approver=people.bob)
    db.rollback()
    db.refresh(case)
    assert case.status == "pending" and case.number is None and case.access_starts_at is None
    assert db.query(m.LegalHoldVault).count() == 0 and db.query(m.Notification).count() == 0
    assert db.query(m.ComplianceCaseCounter).count() == 0, "the number went back with the approval"
    assert rules.access_refusal(case.status, case.access_starts_at, case.access_ends_at, now=rights.utcnow(),
                                access_enabled=True, auditor_live=True) == rules.NOT_ACTIVE


@pytest.mark.parametrize("who,reason", [
    ("ada", ind.PROPOSED), ("uma", cases.NOT_ALLOWED), ("olga_admin", ind.CONCERNED), ("new", ind.NEW_ADMIN),
    ("maker", ind.CREATED_SUBJECT)])
def test_who_may_not_approve(db, people, who, reason):
    if who == "olga_admin":
        approver = _user(db, "oa", m.RoleEnum.ADMIN)
        vault = _vault(db, approver)
        case = _ask(db, people.uma, _vaults(vault))
    else:
        case = _ask(db, people.uma, _vaults(people.v1))
        approver = {"ada": people.ada, "uma": people.uma}.get(who)
        if who == "new":
            approver = _user(db, "newbie", m.RoleEnum.ADMIN, admin_for=timedelta(days=3))
        if who == "maker":
            approver = _user(db, "maker", m.RoleEnum.ADMIN)
            people.uma.created_by = approver.id
            db.commit()
    assert cases.decision_refusal(db, case, approver) == reason
    refused = _refused(cases.approve, db, case, approver=approver)
    assert refused.reason == reason and refused.code == 403


def test_a_vault_that_changed_hands_tells_its_new_owner_and_refuses_an_approver_it_now_concerns(db, people):
    case = _ask(db, people.uma, _vaults(people.v1))
    people.v1.owner_id = people.carl.id
    db.commit()
    refused = _refused(cases.approve, db, case, approver=people.carl)
    assert refused.reason == ind.CONCERNED
    db.rollback()
    _approve(db, case, people.bob)
    assert [r.owner_id_at_approval for r in cases.vault_rows(db, case)] == [people.carl.id]
    assert [o.user_id for o in db.query(m.ComplianceNoticeOutbox)] == [people.carl.id]


def test_a_vault_gone_since_the_request_is_left_out_and_none_left_refuses(db, people):
    case = _ask(db, people.uma, _vaults(people.v1, people.v2))
    db.delete(people.v2)
    db.commit()
    _approve(db, case, people.bob)
    assert {r.vault_id: r.folder_ids for r in cases.vault_rows(db, case)} == {people.v1.id: None, people.v2.id: []}
    assert db.query(m.LegalHoldVault).count() == 1
    other = _ask(db, people.uma, _vaults(people.v3))
    db.delete(people.v3)
    db.commit()
    assert _refused(cases.approve, db, other, approver=people.bob).reason == rules.NO_VAULTS


def test_the_approval_reads_the_settings_again(db, people, settings):
    locked = _vault(db, people.olga, password="hash")
    case = _ask(db, people.uma, _vaults(locked), can_export=True, access_days=20)
    settings[cs.PASSWORD_VAULTS] = cs.REFUSE
    assert _refused(cases.approve, db, case, approver=people.bob).reason == rules.PASSWORD_VAULT_REFUSED
    db.rollback()
    settings[cs.PASSWORD_VAULTS] = cs.WITH_PASSWORD
    settings[cs.EXPORT] = cs.DISABLED
    assert _refused(cases.approve, db, case, approver=people.bob).reason == rules.EXPORT_OFF
    db.rollback()
    settings[cs.EXPORT] = cs.ALLOWED
    assert _approve(db, case, people.bob).status == "active"


def test_a_period_longer_than_allowed_now_is_refused(db, people, settings):
    case = _ask(db, people.uma, _vaults(people.v1), access_days=20)
    settings[cs.MAX_ACCESS_DAYS] = 19
    assert _refused(cases.approve, db, case, approver=people.bob).reason == rules.TOO_LONG


def test_an_auditor_whose_right_ended_since_the_request_is_not_approved(db, people):
    case = _ask(db, people.uma, _vaults(people.v1))
    rights.revoke(db, people.grant, actor=people.ada)
    db.commit()
    refused = _refused(cases.approve, db, case, approver=people.bob)
    assert (refused.reason, refused.code) == (rules.AUDITOR_NOT_LIVE, 409)


def test_an_unapproved_case_expires_after_seven_days_to_the_second(db, people, told):
    case = _ask(db, people.uma, _vaults(people.v1))
    at = case.requested_at + timedelta(days=7)
    assert cases.decision_refusal(db, case, people.bob, at - timedelta(seconds=1)) is None
    assert cases.decision_refusal(db, case, people.bob, at) == cases.EXPIRED
    assert cases.expire_pending(db, at - timedelta(seconds=1)) == 0
    assert cases.expire_pending(db, at) == 1
    db.commit()
    assert case.status == "expired_unapproved" and case.closed_at == at
    assert case.records_kept_until == at + timedelta(days=cs.current(cs.RECORD_MIN_DAYS))
    assert _rows(db, "case_expired_unapproved")[0].case_id == case.id
    assert told.cases[-1]["title"] == "Case expired"


def test_an_approved_case_cannot_be_approved_again(db, people):
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    assert _refused(cases.approve, db, case, approver=people.carl).reason == rules.NOT_NOW


def test_a_hold_is_not_placed_while_another_sftp_version_may_run(db, people, monkeypatch):
    from app.core import sftp_versions
    case = _ask(db, people.uma, _vaults(people.v1))
    monkeypatch.setattr(sftp_versions, "sftp_same_version",
                        lambda db_, **_k: sftp_versions.VersionCheck(False, "other", ("0.33.0",)))
    assert _refused(cases.approve, db, case, approver=people.bob).reason == cases.SFTP_VERSION
    db.rollback()
    nohold = _ask(db, people.uma, _vaults(people.v2), hold=False)
    assert _approve(db, nohold, people.bob).status == "active"


@pytest.mark.parametrize("value,code", [(None, 428), ("", 428), ('"1"', None), ("1", None), ('W/"1"', None),
                                        ('"2"', 412), ("x", 412)])
def test_the_version_an_approval_sends_back(db, people, value, code):
    case = _ask(db, people.uma, _vaults(people.v1))
    if code is None:
        cases.check_version(case, value)
    else:
        assert _refused(cases.check_version, case, value).code == code


# --------------------------------------------------------------------------- the host

def _host(db, action, case, reason=None):
    from app.core.host_operator import _Answer
    step = hc.CASE_STEPS[action]
    try:
        return step(db, case, reason=reason), 0
    except _Answer as done:
        return done.obj, done.code


def test_the_host_approves_only_when_no_administrator_can(db, people):
    case = _ask(db, people.uma, _vaults(people.v1))
    answer, code = _host(db, "approve", case)
    assert code == 2 and "may not" in answer["error"]
    assert _rows(db, "case_approved", "failure")[0].details["reason"] == cases.NOT_INDEPENDENT_HOST
    for admin in (people.bob, people.carl):
        db.query(m.SecondFactorEnrollment).filter(m.SecondFactorEnrollment.user_id == admin.id).delete()
    db.commit()
    answer, code = _host(db, "approve", case)
    db.commit()
    assert code == 0 and answer["status"] == "active" and case.approved_by_operator
    assert case.approved_by_username == "operator@host" and case.approved_by is None
    assert db.query(m.ComplianceNoticeOutbox).count() == 1


def test_the_host_turns_down_only_when_no_administrator_can(db, people):
    case = _ask(db, people.uma, _vaults(people.v1))
    answer, code = _host(db, "reject", case, reason="Not enough grounds.")
    assert code == 2 and "may not" in answer["error"]
    for admin in (people.bob, people.carl):
        db.query(m.SecondFactorEnrollment).filter(m.SecondFactorEnrollment.user_id == admin.id).delete()
    db.commit()
    answer, code = _host(db, "reject", case, reason="Not enough grounds.")
    db.commit()
    assert code == 0 and case.status == "rejected" and case.rejected_by_username == "operator@host"


def test_both_host_steps_are_registered():
    assert hc.CASE_STEPS["approve"] is cases._host_approve and hc.CASE_STEPS["reject"] is cases._host_reject


# --------------------------------------------------------------------------- turning down, withdrawing

def test_turning_down_takes_a_reason_the_auditor_reads(db, people, told):
    case = _ask(db, people.uma, _vaults(people.v1))
    assert _refused(cases.reject, db, case, by=people.bob, reason=" ").reason == cases.NO_REASON
    assert _refused(cases.reject, db, case, by=people.ada, reason="No.").reason == ind.PROPOSED
    cases.reject(db, case, by=people.bob, reason="Not enough grounds.")
    db.commit()
    assert case.status == "rejected" and case.closed_at is not None and case.records_kept_until is not None
    assert open_case_field(case.id, case.reject_reason_enc, "reject_reason") == "Not enough grounds."
    view = cases.case_view(db, case, people.uma)
    assert view["reject_reason"] == "Not enough grounds."
    assert told.cases[-1]["people"] == [str(people.uma.id)] and "Not enough" not in told.cases[-1]["body"]


def test_only_the_auditor_withdraws_and_only_while_it_waits(db, people):
    case = _ask(db, people.uma, _vaults(people.v1))
    assert _refused(cases.withdraw, db, case, by=people.bob).reason == cases.NOT_ALLOWED
    cases.withdraw(db, case, by=people.uma)
    db.commit()
    assert case.status == "withdrawn" and _rows(db, "case_withdrawn")[0].case_id == case.id
    assert _refused(cases.withdraw, db, case, by=people.uma).reason == rules.NOT_NOW


# --------------------------------------------------------------------------- extending

def test_an_extension_adds_to_the_end_and_tells_the_owners(db, people):
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    end = case.access_ends_at
    cases.extend(db, case, by=people.carl, days=14, now=case.access_starts_at + timedelta(days=13))
    db.commit()
    assert case.access_ends_at == end + timedelta(days=14) and case.total_access_days == 28 and case.version == 3
    kinds = [o.kind for o in db.query(m.ComplianceNoticeOutbox).order_by(m.ComplianceNoticeOutbox.created_at)]
    assert kinds == ["activation", "extension"]
    assert _rows(db, "case_extended")[0].details["days"] == 14


def test_an_extension_is_refused_past_its_ceilings_or_once_access_ended(db, people, settings):
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1), access_days=30), people.bob)
    start = case.access_starts_at
    cases.extend(db, case, by=people.carl, days=30, now=start + timedelta(days=1))
    cases.extend(db, case, by=people.carl, days=30, now=start + timedelta(days=2))
    assert _refused(cases.extend, db, case, by=people.carl, days=1, now=start + timedelta(days=3)).reason == \
        rules.TOO_LONG
    assert _refused(cases.extend, db, case, by=people.carl, days=1, now=case.access_ends_at).reason == \
        rules.ACCESS_ENDED
    # A ceiling lowered since the approval applies (the stricter of the two).
    settings[cs.MAX_TOTAL_DAYS] = 80
    other = _approve(db, _ask(db, people.uma, _vaults(people.v2), access_days=30), people.bob)
    cases.extend(db, other, by=people.carl, days=30, now=other.access_starts_at)
    assert _refused(cases.extend, db, other, by=people.carl, days=21, now=other.access_starts_at).reason == \
        rules.TOO_LONG


def test_the_auditor_and_a_concerned_administrator_cannot_extend(db, people):
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    assert cases.extend_refusal(db, case, people.uma) == cases.NOT_ALLOWED
    assert cases.extend_refusal(db, case, people.ada) == ind.PROPOSED


# --------------------------------------------------------------------------- narrowing

def test_narrowing_a_case_needs_no_approval_and_tells_an_owner_whose_vault_left(db, people):
    f1 = _folder(db, people.v1)
    f2 = _folder(db, people.v1, parent=f1)
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1, people.v3)), people.bob)
    cases.narrow(db, case, by=people.uma, scope=[{"kind": "folder", "target_id": f2.id}])
    db.commit()
    assert {r.vault_id: r.folder_ids for r in cases.vault_rows(db, case)} == {people.v1.id: [str(f2.id)],
                                                                            people.v3.id: []}
    assert [(o.user_id, o.kind) for o in db.query(m.ComplianceNoticeOutbox).filter(
        m.ComplianceNoticeOutbox.kind == "scope_removed")] == [(people.otto.id, "scope_removed")]
    assert holds.held_vault_ids(db) == {people.v1.id, people.v3.id}, "a hold stays until it is released"
    (row,) = _rows(db, "case_scope_narrowed")
    assert row.details["vaults"] == 1 and row.details["removed"] == 1


@pytest.mark.parametrize("new_scope", [
    lambda p, f1, f2: [{"kind": "vault", "target_id": p.v1.id}],
    lambda p, f1, f2: [{"kind": "folder", "target_id": f1.id}],
    lambda p, f1, f2: [{"kind": "folder", "target_id": f2.id}, {"kind": "vault", "target_id": p.v2.id}],
])
def test_anything_wider_needs_a_new_case(db, people, new_scope):
    f1 = _folder(db, people.v1)
    f2 = _folder(db, people.v1, parent=f1)
    case = _approve(db, _ask(db, people.uma, [{"kind": "folder", "target_id": f2.id}]), people.bob)
    refused = _refused(cases.narrow, db, case, by=people.uma, scope=new_scope(people, f1, f2))
    assert (refused.reason, refused.code) == (rules.WIDENS, 409)


def test_the_time_range_narrows_only(db, people):
    now = rights.utcnow()
    case = _ask(db, people.uma, _vaults(people.v1), files_from=now - timedelta(days=30), files_to=now)
    cases.narrow(db, case, by=people.uma, scope=_vaults(people.v1), files_from=now - timedelta(days=10),
                 files_to=now, keep_range=False)
    assert case.files_from == now - timedelta(days=10)
    assert _refused(cases.narrow, db, case, by=people.uma, scope=_vaults(people.v1), files_from=None,
                    files_to=now, keep_range=False).reason == rules.WIDENS


def test_narrowing_a_pending_case_tells_nobody(db, people):
    case = _ask(db, people.uma, _vaults(people.v1, people.v3))
    cases.narrow(db, case, by=people.uma, scope=_vaults(people.v1))
    db.commit()
    assert db.query(m.ComplianceNoticeOutbox).count() == 0
    _approve(db, case, people.bob)
    assert [o.user_id for o in db.query(m.ComplianceNoticeOutbox)] == [people.olga.id], "only what is covered"


def test_who_may_narrow(db, people):
    case = _ask(db, people.uma, _vaults(people.v1))
    assert cases.narrow_refusal(db, case, people.uma) is None
    assert cases.narrow_refusal(db, case, people.bob) is None
    assert cases.narrow_refusal(db, case, people.olga) == cases.NOT_ALLOWED
    assert cases.narrow_refusal(db, case, people.ada) == ind.PROPOSED


# --------------------------------------------------------------------------- objections and closing

def test_an_owner_records_an_objection_sealed_and_shown_to_whoever_extends(db, people):
    case = _ask(db, people.uma, _vaults(people.v1))
    assert _refused(cases.record_objection, db, case, by=people.olga, text_="No.").reason == rules.NOT_NOW
    _approve(db, case, people.bob)
    assert _refused(cases.record_objection, db, case, by=people.otto, text_="No.").reason == cases.NOT_ALLOWED
    assert _refused(cases.record_objection, db, case, by=people.olga, text_="  ").reason == cases.NO_OBJECTION
    cases.record_objection(db, case, by=people.olga, text_="I object under Art. 21.")
    cases.record_objection(db, case, by=people.carl, text_="Answer sent on 3 Nov.")
    db.commit()
    assert "Art. 21" not in case.objection_enc
    entries = cases.objections(case)
    assert [(e["by"], e["as"], e["text"]) for e in entries] == [("olga", "owner", "I object under Art. 21."),
                                                                ("carl", "administrator", "Answer sent on 3 Nov.")]
    assert cases.case_view(db, case, people.carl)["objections"] == entries
    assert not cases.may_see(db, case, people.olga), "an owner reads the case on their own page, not here"
    assert [r.details["by_owner"] for r in _rows(db, "case_objection_recorded")] == [True, False]


def test_closing_releases_the_holds_and_tells_the_owners_with_a_summary(db, people):
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    assert _refused(cases.close, db, case, by=people.uma, reason=" ").reason == cases.NO_REASON
    assert cases.close_refusal(db, case, people.ada) == ind.PROPOSED
    cases.close(db, case, by=people.uma, reason="Concluded.")
    db.commit()
    assert case.status == "closed" and case.closed_by == people.uma.id
    assert open_case_field(case.id, case.close_reason_enc, "close_reason") == "Concluded."
    (h,) = db.query(m.LegalHoldVault).all()
    assert h.released_at is not None and h.purge_after is not None
    kinds = [o.kind for o in db.query(m.ComplianceNoticeOutbox).order_by(m.ComplianceNoticeOutbox.created_at)]
    assert kinds == ["activation", "closed"], "one closing notice, not a second for the release"
    closed = db.query(m.ComplianceNoticeOutbox).filter(m.ComplianceNoticeOutbox.kind == "closed").one()
    assert closed.details == {"by": "uma", "vaults": 1, "hold": False, "files_opened": 0, "exports": 0}


def test_a_case_that_only_holds_closes_by_releasing_its_hold(db, people):
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    assert cases.end_due(db, case.access_ends_at) == 1
    db.commit()
    assert case.status == "hold_only"
    cases.close(db, case, by=people.uma, reason="Matter settled.")
    db.commit()
    assert case.status == "closed" and holds.held_vault_ids(db) == set()
    assert sorted(o.kind for o in db.query(m.ComplianceNoticeOutbox)) == ["access_ended", "activation", "hold_released"]


# --------------------------------------------------------------------------- the clock

def test_access_ends_to_the_second_and_a_case_without_a_hold_closes(db, people, told):
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1), hold=False), people.bob)
    end = case.access_ends_at
    assert cases.end_due(db, end - timedelta(seconds=1)) == 0
    assert cases.end_due(db, end) == 1
    db.commit()
    assert case.status == "closed" and case.closed_by_username == "system" and case.closed_at == end
    assert _rows(db, "case_access_ended")[0].details["hold_only"] is False
    assert _rows(db, "case_closed")[0].details["access_ended"] is True
    ended = db.query(m.ComplianceNoticeOutbox).filter(m.ComplianceNoticeOutbox.kind == "access_ended").one()
    assert ended.details["hold"] is False and ended.user_id == people.olga.id


def test_access_that_ends_while_a_hold_stands_keeps_the_hold(db, people):
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    assert cases.end_due(db, case.access_ends_at) == 1
    db.commit()
    assert case.status == "hold_only" and case.closed_at is None
    assert db.query(m.ComplianceNoticeOutbox).filter(m.ComplianceNoticeOutbox.kind == "access_ended").one() \
        .details["hold"] is True
    assert cases.end_due(db, case.access_ends_at + timedelta(days=1)) == 0, "once is enough"


def test_the_clock_runs_as_the_pruners_job(db, people):
    from app.core import retention
    assert ("compliance_cases", False) in [(j.name, j.held) for j in retention.JOBS]
    names = [j.name for j in retention.JOBS]
    assert names.index("compliance_cases") < names.index("legal_holds")


# --------------------------------------------------------------------------- suspension and what a viewer sees

def test_turning_compliance_access_off_suspends_an_active_case_with_nothing_stored(db, people, settings):
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    assert cases.effective_status(db, case) == "active"
    settings[cs.ACCESS] = cs.DISABLED
    assert cases.effective_status(db, case) == "suspended" and case.status == "active"
    settings[cs.ACCESS] = cs.ENABLED
    assert cases.effective_status(db, case) == "active"
    rights.revoke(db, people.grant, actor=people.ada)
    db.commit()
    assert cases.effective_status(db, case) == "suspended"


def test_who_sees_the_justification_and_the_people_named(db, people):
    case = _ask(db, people.uma, _vaults(people.v1), named_user_ids=[people.otto.id])
    newbie = _user(db, "newbie", m.RoleEnum.ADMIN, admin_for=timedelta(days=3))
    otto_admin = people.otto
    otto_admin.role = m.RoleEnum.ADMIN
    db.commit()
    for viewer, justification, named in ((people.uma, True, True), (people.bob, True, True),
                                         (newbie, False, True), (otto_admin, False, False)):
        view = cases.case_view(db, case, viewer)
        assert ("justification" in view and view["justification"] == TEXT["justification"]) is justification, viewer
        assert ("people" in view) is named, viewer.username
    assert not cases.may_see(db, case, people.olga) and cases.may_see(db, case, people.carl)


def test_an_administrator_is_told_of_their_own_membership(db, people, monkeypatch):
    from app.core.authorization import PermissionService
    case = _ask(db, people.uma, _vaults(people.v1, people.v3))
    monkeypatch.setattr(PermissionService, "get_vault_permissions",
                        lambda self, user, vid, allow_share=False: {"read": True} if vid == people.v3.id else None)
    view = cases.case_view(db, case, people.bob)
    assert {v["vault_id"]: v["you_are_member"] for v in view["vaults"]} == {str(people.v1.id): False,
                                                                          str(people.v3.id): True}
    assert "you_are_member" not in cases.case_view(db, case, people.uma)["vaults"][0]


# --------------------------------------------------------------------------- the routes

@pytest.fixture
def no_codes(monkeypatch):
    """The compliance step-up passes (its own tests cover it); the calls are counted."""
    calls = []
    for name in ("STEP_UP_CASE_REQUEST", "STEP_UP_CASE_APPROVE", "STEP_UP_HOLD_DECIDE"):
        monkeypatch.setattr(cr, name, lambda db_, user, request, _n=name: calls.append(_n))
    return calls


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs), None
    except HTTPException as exc:
        return None, exc


def test_the_routes_ask_approve_and_refuse_with_a_record(db, people, no_codes):
    body = cr.CaseRequest(scope=[cr.ScopeItemIn(kind="vault", target_id=people.v1.id)], **TEXT)
    view = cr.request_case(body, request=None, current_user=people.uma, db=db)
    assert no_codes == ["STEP_UP_CASE_REQUEST"] and view["status"] == "pending"
    cid = uuid.UUID(view["id"])
    _, err = _call(cr.approve_case, cid, request=None, if_match=None, current_user=people.bob, db=db)
    assert err.status_code == 428 and no_codes == ["STEP_UP_CASE_REQUEST"], "no code is asked for a stale request"
    _, err = _call(cr.approve_case, cid, request=None, if_match='"7"', current_user=people.bob, db=db)
    assert err.status_code == 412
    _, err = _call(cr.approve_case, cid, request=None, if_match='"1"', current_user=people.ada, db=db)
    assert err.status_code == 403 and err.detail["reason"] == ind.PROPOSED
    assert _rows(db, "case_approved", "failure")[-1].details["reason"] == ind.PROPOSED
    out, err = _call(cr.approve_case, cid, request=None, if_match='"1"', current_user=people.bob, db=db)
    assert err is None and out["status"] == "active" and no_codes[-1] == "STEP_UP_CASE_APPROVE"
    _, err = _call(cr.approve_case, cid, request=None, if_match='"2"', current_user=people.carl, db=db)
    assert err.status_code == 409 and err.detail["reason"] == rules.NOT_NOW


def test_a_refused_request_is_recorded_and_costs_no_code(db, people, no_codes):
    own = _vault(db, people.uma)
    body = cr.CaseRequest(scope=[cr.ScopeItemIn(kind="vault", target_id=own.id)], **TEXT)
    _, err = _call(cr.request_case, body, request=None, current_user=people.uma, db=db)
    assert err.status_code == 403 and err.detail["reason"] == rules.AUDITOR_CONCERNED and no_codes == []
    assert _rows(db, "case_requested", "failure")[-1].details["reason"] == rules.AUDITOR_CONCERNED


def test_a_case_is_seen_by_its_auditor_and_administrators_only(db, people, no_codes):
    case = _ask(db, people.uma, _vaults(people.v1))
    response = SimpleNamespace(headers={})
    assert cr.get_case(case.id, response, current_user=people.uma, db=db)["id"] == str(case.id)
    assert response.headers["ETag"] == '"1"'
    _, err = _call(cr.get_case, case.id, response, current_user=people.olga, db=db)
    assert err.status_code == 404
    assert [c["id"] for c in cr.list_cases(current_user=people.bob, db=db)["cases"]] == [str(case.id)]
    assert cr.list_cases(current_user=people.olga, db=db)["cases"] == []


def test_closing_with_a_standing_hold_asks_for_the_release_code(db, people, no_codes):
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    cr.close_case(case.id, cr.Reason(reason="Concluded."), request=None, current_user=people.uma, db=db)
    assert no_codes == ["STEP_UP_HOLD_DECIDE"]
    nohold = _approve(db, _ask(db, people.uma, _vaults(people.v2), hold=False), people.bob)
    cr.close_case(nohold.id, cr.Reason(reason="Concluded."), request=None, current_user=people.uma, db=db)
    assert no_codes == ["STEP_UP_HOLD_DECIDE"], "closing only removes power: no code"


def test_an_auditor_whose_right_was_revoked_closes_alone_only_a_case_whose_hold_no_longer_stands(db, people,
                                                                                               no_codes):
    """Closing a case whose hold stands releases the hold: its auditor does that alone only while their right is in
    force, as for a release; the refusal is recorded and asks for no code. Closing a case without a standing hold
    only takes power away, so they still may; an independent administrator closes the other."""
    held = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    unheld = _approve(db, _ask(db, people.uma, _vaults(people.v2), hold=False), people.bob)
    rights.revoke(db, people.grant, actor=people.ada, reason="Left the team.")
    db.commit()
    assert cases.close_refusal(db, held, people.uma) == rights.NO_GRANT
    with pytest.raises(HTTPException) as refused:
        cr.close_case(held.id, cr.Reason(reason="Concluded."), request=None, current_user=people.uma, db=db)
    assert refused.value.status_code == 403 and refused.value.detail["reason"] == rights.NO_GRANT
    assert no_codes == [] and holds.standing(db, held.id) and held.status == "active"
    assert _rows(db, "case_closed", "failure")[-1].details["reason"] == rights.NO_GRANT
    assert cases.close_refusal(db, unheld, people.uma) is None
    cr.close_case(unheld.id, cr.Reason(reason="Concluded."), request=None, current_user=people.uma, db=db)
    assert unheld.status == "closed" and no_codes == []
    assert cases.close_refusal(db, held, people.carl) is None


def test_an_extension_once_access_ended_is_refused_before_any_code_and_the_case_says_so(db, people, no_codes,
                                                                                        monkeypatch):
    """Between the end of access and the clock's pass the case is still active: an extension then is refused for
    the end of access (409) before the code is asked for, and the case page tells the administrator so."""
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    ended = case.access_ends_at
    monkeypatch.setattr(cases, "utcnow", lambda: ended)
    assert case.status == "active" and cases.extend_refusal(db, case, people.carl) == rules.ACCESS_ENDED
    you_may = cases.case_view(db, case, people.carl, now=ended, detail=True)["you_may"]["extend"]
    assert you_may["may"] is False and you_may["why_not"]["reason"] == rules.ACCESS_ENDED
    with pytest.raises(HTTPException) as refused:
        cr.extend_case(case.id, cr.Extension(days=1), request=None, if_match=f'"{case.version}"',
                       current_user=people.carl, db=db)
    assert refused.value.status_code == 409 and refused.value.detail["reason"] == rules.ACCESS_ENDED
    assert no_codes == []
    assert _rows(db, "case_extended", "failure")[-1].details["reason"] == rules.ACCESS_ENDED
    db.expire_all()
    assert case.access_ends_at == ended


def test_a_new_grant_does_not_bring_back_a_case_asked_under_the_grant_revoked(db, people):
    """A case stands on the grant it was asked under: once that right is revoked, a new right granted later gives
    the auditor nothing in the old case, which stays suspended; a new case is asked under the new grant."""
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    rights.revoke(db, people.grant, actor=people.ada, reason="Left the team.")
    db.commit()
    assert cases.effective_status(db, case) == rules.SUSPENDED
    again = rights.propose(db, people.uma, proposer=people.ada, now=rights.utcnow() - timedelta(minutes=2))
    rights.approve(db, again, approver=people.bob, now=rights.utcnow() - timedelta(minutes=1))
    db.commit()
    assert rights.auditor_live(db, people.uma).live
    assert cases.auditor_standing(db, case)[0] is False
    assert cases.effective_status(db, case) == rules.SUSPENDED
    assert _refused(cases.extend, db, case, by=people.carl, days=1).reason == rules.AUDITOR_NOT_LIVE


def test_the_vault_picker_names_only_what_the_auditor_can_already_read(db, people, monkeypatch):
    from app.core.authorization import PermissionService
    zk = _vault(db, people.olga, kind="zero_knowledge")
    pw = _vault(db, people.olga, password="hash")
    monkeypatch.setattr(PermissionService, "get_vault_permissions",
                        lambda self, user, vid, allow_share=False: {"read": True} if vid in (people.v1.id, zk.id, pw.id)
                        else None)
    out = cr.vault_picker(owner="olga", current_user=people.uma, db=db)
    names = {v["id"]: v["name"] for v in out["vaults"]}
    assert names == {str(people.v1.id): "Payroll 2026", str(people.v2.id): None, str(zk.id): None, str(pw.id): None}
    assert out["vaults"][0]["file_count"] == 3
    (row,) = _rows(db, "case_picker_viewed")
    assert row.resource_id == str(people.olga.id) and row.user_id == people.uma.id
    _, err = _call(cr.vault_picker, owner=str(uuid.uuid4()), current_user=people.uma, db=db)
    assert err.status_code == 404


def _host_act(db, *argv):
    from app.core.host_operator import _Answer
    try:
        hc._act(db, hc.build_parser().parse_args(list(argv)))
    except _Answer as done:
        return done.obj, done.code
    raise AssertionError("no answer")


def test_the_tool_records_its_refusal_to_approve_and_approves_when_nobody_else_can(db, people):
    case = _ask(db, people.uma, _vaults(people.v1))
    answer, code = _host_act(db, "approve", "--case", str(case.id), "--confirm-case", hc.reference(case.id))
    assert code == 2 and "may not" in answer["error"]
    assert _rows(db, "case_approved", "failure")[-1].details["reason"] == cases.NOT_INDEPENDENT_HOST
    for admin in (people.bob, people.carl):
        db.query(m.SecondFactorEnrollment).filter(m.SecondFactorEnrollment.user_id == admin.id).delete()
    db.commit()
    answer, code = _host_act(db, "approve", "--case", str(case.id), "--confirm-case", hc.reference(case.id))
    assert code == 0 and answer["case"]["status"] == "active"
    db.refresh(case)
    assert case.approved_by_operator and case.notice_written_at is not None


def test_the_list_shows_no_texts_and_the_case_page_does(db, people):
    case = _ask(db, people.uma, _vaults(people.v1))
    listed = cr.list_cases(current_user=people.bob, db=db)["cases"][0]
    assert "justification" not in listed and "you_may" not in listed and "owner_note" not in listed
    assert "file_count" not in listed["vaults"][0]
    page = cases.case_view(db, case, people.bob)
    assert page["justification"] == TEXT["justification"] and "you_may" in page


def test_an_owner_not_told_yet_finds_no_case(db, people):
    case = _ask(db, people.uma, _vaults(people.v1))
    assert not cases.owns_a_vault_in(db, case, people.olga)
    _, err = _call(cr.record_case_objection, case.id, cr.ObjectionIn(text="I object."), current_user=people.olga, db=db)
    assert err.status_code == 404, "a pending case does not exist for its owners"
    _approve(db, case, people.bob)
    assert cases.owns_a_vault_in(db, case, people.olga)
    out = cr.record_case_objection(case.id, cr.ObjectionIn(text="I object."), current_user=people.olga, db=db)
    assert out["objections"] == 1


# --------------------------------------------------------------------------- the auditor's creator's lineage

@pytest.fixture
def creators(db, people):
    """A stand-in administrator and a stand-in account combined: zed made ada an administrator, ada created uma's
    account and made bea an administrator. (ada proposed uma's right and bob approved it.)"""
    zed = _user(db, "zed", m.RoleEnum.ADMIN)
    admin_grants.record(db, people.ada.id, granted_by_id=zed.id, granted_by_name="zed", now=rights.utcnow() - OLD)
    bea = _user(db, "bea", m.RoleEnum.ADMIN)
    admin_grants.record(db, bea.id, granted_by_id=people.ada.id, granted_by_name="ada", now=rights.utcnow() - OLD)
    people.uma.created_by = people.ada.id
    db.commit()
    return SimpleNamespace(zed=zed, bea=bea)


@pytest.mark.parametrize("who,reason", [("bea", ind.MADE_BY_CREATOR), ("zed", ind.MADE_CREATOR)])
def test_an_administrator_in_the_lineage_of_the_auditors_creator_decides_no_step_of_the_case(db, people, creators,
                                                                                            no_codes, who, reason):
    approver = getattr(creators, who)
    case = _ask(db, people.uma, _vaults(people.v1))
    assert cases.decision_refusal(db, case, approver) == reason
    assert sorted(a.username for a in cases.independent_approvers(db, case)) == ["bob", "carl"]
    # Through the routes: refused before any code, and recorded.
    _, err = _call(cr.approve_case, case.id, request=None, if_match='"1"', current_user=approver, db=db)
    assert err.status_code == 403 and err.detail["reason"] == reason and no_codes == []
    assert _rows(db, "case_approved", "failure")[-1].details["reason"] == reason
    assert err.detail["text"] == cases.text(reason) != reason
    _, err = _call(cr.reject_case, case.id, cr.Reason(reason="No grounds."), request=None, current_user=approver,
                   db=db)
    assert err.status_code == 403 and err.detail["reason"] == reason and no_codes == []
    # Every other step the rule decides: extending, narrowing, closing, releasing and undoing a release, confirming.
    _approve(db, case, people.bob)
    for refusal in (cases.extend_refusal, cases.narrow_refusal, cases.close_refusal, holds.release_refusal):
        assert refusal(db, case, approver) == reason, refusal.__name__
        assert refusal(db, case, people.carl) is None, refusal.__name__
    holds.release(db, case, by=people.carl, reason="Not needed.")
    db.commit()
    assert holds.undo_refusal(db, case, approver) == reason
    assert holds.undo_refusal(db, case, people.carl) is None
    held = holds.place_hold_only(db, people.uma, [people.v2.id], **TEXT)
    db.commit()
    assert holds.confirm_refusal(db, held, approver) == reason
    assert holds.confirm_refusal(db, held, people.carl) is None


def test_the_creator_kept_with_the_grant_still_refuses_after_the_creator_is_deleted_or_demoted(db, people,
                                                                                               creators):
    """The case reads the creator and their lineage as the auditor's grant kept them when it was proposed: deleting
    the creator clears the account's created_by, and demoting them deletes their lineage."""
    rights.revoke(db, people.grant, actor=people.carl, reason="Renewed.")
    db.commit()
    grant = rights.propose(db, people.uma, proposer=people.carl, now=rights.utcnow() - timedelta(hours=2))
    db.commit()
    assert grant.proposal_snapshot["creator"] == str(people.ada.id)
    assert grant.proposal_snapshot["creator_lineage"] == [str(creators.zed.id)]
    rights.approve(db, grant, approver=people.bob, now=rights.utcnow() - timedelta(hours=1))
    db.commit()
    case = _ask(db, people.uma, _vaults(people.v1))
    assert case.grant_id == grant.id
    people.uma.created_by = None
    admin_grants.forget(db, people.ada.id)
    db.commit()
    assert cases.decision_refusal(db, case, creators.bea) == ind.MADE_BY_CREATOR
    assert cases.decision_refusal(db, case, creators.zed) == ind.MADE_CREATOR


# --------------------------------------------------------------------------- the grant's proposer's lineage

@pytest.fixture
def proposers(db, people):
    """uma's account has no recorded creator (self-signup, or a creator deleted before the proposal); ada proposed
    her right. zed made ada an administrator, and ada made bea one."""
    zed = _user(db, "zed", m.RoleEnum.ADMIN)
    admin_grants.record(db, people.ada.id, granted_by_id=zed.id, granted_by_name="zed", now=rights.utcnow() - OLD)
    bea = _user(db, "bea", m.RoleEnum.ADMIN)
    admin_grants.record(db, bea.id, granted_by_id=people.ada.id, granted_by_name="ada", now=rights.utcnow() - OLD)
    db.commit()
    assert people.uma.created_by is None and people.grant.proposed_by == people.ada.id
    return SimpleNamespace(zed=zed, bea=bea)


@pytest.mark.parametrize("who,reason", [("bea", ind.MADE_BY_PROPOSER), ("zed", ind.MADE_PROPOSER)])
def test_an_administrator_in_the_lineage_of_the_grants_proposer_decides_no_step_of_the_case(db, people, proposers,
                                                                                           no_codes, who, reason):
    approver = getattr(proposers, who)
    case = _ask(db, people.uma, _vaults(people.v1))
    assert cases.decision_refusal(db, case, approver) == reason
    assert sorted(a.username for a in cases.independent_approvers(db, case)) == ["bob", "carl"]
    _, err = _call(cr.approve_case, case.id, request=None, if_match='"1"', current_user=approver, db=db)
    assert err.status_code == 403 and err.detail["reason"] == reason and no_codes == []
    assert _rows(db, "case_approved", "failure")[-1].details["reason"] == reason
    assert err.detail["text"] == cases.text(reason) != reason
    _, err = _call(cr.reject_case, case.id, cr.Reason(reason="No grounds."), request=None, current_user=approver,
                   db=db)
    assert err.status_code == 403 and err.detail["reason"] == reason and no_codes == []
    assert case.status == "pending"
    _approve(db, case, people.bob)
    for refusal in (cases.extend_refusal, cases.narrow_refusal, cases.close_refusal, holds.release_refusal):
        assert refusal(db, case, approver) == reason, refusal.__name__
        assert refusal(db, case, people.carl) is None, refusal.__name__
    holds.release(db, case, by=people.carl, reason="Not needed.")
    db.commit()
    assert holds.undo_refusal(db, case, approver) == reason
    held = holds.place_hold_only(db, people.uma, [people.v2.id], **TEXT)
    db.commit()
    assert held.grant_id == people.grant.id
    assert holds.confirm_refusal(db, held, approver) == reason
    assert holds.confirm_refusal(db, held, people.carl) is None


def test_the_proposer_kept_with_the_grant_still_refuses_after_the_proposer_is_demoted_or_deleted(db, people,
                                                                                                proposers):
    """The case reads the proposer and their lineage as the grant kept them when it was proposed: demoting the
    proposer deletes their lineage, and deleting them clears the grant's proposed_by."""
    rights.revoke(db, people.grant, actor=people.carl, reason="Renewed.")
    db.commit()
    grant = rights.propose(db, people.uma, proposer=people.ada, now=rights.utcnow() - timedelta(hours=2))
    db.commit()
    assert grant.proposal_snapshot["requester"] == str(people.ada.id)
    assert grant.proposal_snapshot["lineage"] == [str(proposers.zed.id)]
    rights.approve(db, grant, approver=people.bob, now=rights.utcnow() - timedelta(hours=1))
    db.commit()
    case = _ask(db, people.uma, _vaults(people.v1))
    assert case.grant_id == grant.id
    admin_grants.forget(db, people.ada.id)
    db.commit()
    assert cases.decision_refusal(db, case, proposers.zed) == ind.MADE_PROPOSER, "kept lineage, proposer demoted"
    grant.proposed_by = None
    db.commit()
    assert cases.decision_refusal(db, case, proposers.bea) == ind.MADE_BY_PROPOSER, "kept proposer, since deleted"
    assert cases.decision_refusal(db, case, proposers.zed) == ind.MADE_PROPOSER
    assert cases.decision_refusal(db, case, people.carl) is None


def test_the_grant_itself_refuses_the_proposers_lineage_as_the_one_who_asked(db, people, proposers):
    """Approving the right refuses the proposer's lineage already, as the one who asked: the case adds the same for
    every later step."""
    rights.revoke(db, people.grant, actor=people.carl, reason="Renewed.")
    db.commit()
    grant = rights.propose(db, people.uma, proposer=people.ada)
    db.commit()
    assert rights.approver_refusal(db, grant, proposers.bea) == ind.MADE_BY_REQUESTER
    assert rights.approver_refusal(db, grant, proposers.zed) == ind.MADE_REQUESTER
    assert rights.approver_refusal(db, grant, people.bob) is None


# --------------------------------------------------------------------------- the approval's hold and deletions

def test_the_approval_locks_the_vaults_its_hold_covers_before_it_reads_their_owners(db, people, monkeypatch):
    """A deletion holds its vault's row (FOR NO KEY UPDATE) until it commits: the approval locks the rows of the
    vaults its hold will cover, as placing a hold does, so it waits for that deletion and its hold covers every
    deletion that commits after it. test_cases_live.py shows the wait on PostgreSQL."""
    calls = []
    real_lock, real_owners = holds._lock_vaults, cases._refresh_owners

    def lock(db_, ids, **kw):
        calls.append(("lock", sorted(str(i) for i in ids), kw))
        return real_lock(db_, ids, **kw)

    def owners(db_, case):
        calls.append(("owners",))
        return real_owners(db_, case)
    monkeypatch.setattr(holds, "_lock_vaults", lock)
    monkeypatch.setattr(cases, "_refresh_owners", owners)
    case = _ask(db, people.uma, _vaults(people.v1, people.v3))
    _approve(db, case, people.bob)
    assert calls == [("lock", sorted([str(people.v1.id), str(people.v3.id)]), {"missing_ok": True}), ("owners",)]
    calls.clear()
    _approve(db, _ask(db, people.uma, _vaults(people.v2), hold=False), people.bob)
    assert calls == [("owners",)], "an approval with no hold locks nothing"


def test_a_vault_deleted_while_the_approval_waited_for_it_covers_nothing(db, people, monkeypatch):
    v1, v2 = people.v1.id, people.v2.id
    case = _ask(db, people.uma, _vaults(people.v1, people.v2))
    real = holds._lock_vaults

    def deleted_meanwhile(db_, ids, **kw):
        # The deletion the lock waited for committed first: the vault is gone when the lock is taken.
        db_.query(m.Vault).filter(m.Vault.id == v2).delete(synchronize_session=False)
        return real(db_, ids, **kw)
    monkeypatch.setattr(holds, "_lock_vaults", deleted_meanwhile)
    _approve(db, case, people.bob)
    assert case.status == "active"
    assert {r.vault_id: r.folder_ids for r in cases.vault_rows(db, case)} == {v1: None, v2: []}
    assert [h.vault_id for h in db.query(m.LegalHoldVault)] == [v1]


def test_locking_a_vault_that_is_gone_refuses_or_leaves_it_out():
    gone = uuid.uuid4()
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        try:
            assert holds._lock_vaults(session, [gone], missing_ok=True) == []
            with pytest.raises(holds.HoldRefused) as refused:
                holds._lock_vaults(session, [gone])
            assert refused.value.reason == holds.NO_SUCH_VAULT and refused.value.code == 404
        finally:
            session.close()


def test_the_approval_writes_the_rollback_marker_with_its_hold(db, people):
    """The marker that keeps an older release from starting is written by the approval's own transaction, not left
    to the pruner's next pass."""
    from sqlalchemy import text as sql
    marker = "SELECT count(*) FROM data_requirements WHERE key = 'legal-holds'"
    assert db.execute(sql(marker)).scalar() == 0
    _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    assert db.execute(sql(marker)).scalar() == 1


def test_a_vault_that_came_to_the_auditor_since_the_request_refuses_the_approval(db, people):
    """The owners are read again at the approval: an auditor who now owns a vault of the case is a person it
    concerns, and an auditor does not investigate themselves."""
    case = _ask(db, people.uma, _vaults(people.v1))
    people.v1.owner_id = people.uma.id
    db.commit()
    refused = _refused(cases.approve, db, case, approver=people.bob)
    assert refused.reason == rules.AUDITOR_CONCERNED and refused.code == 403
    db.rollback()
    db.refresh(case)
    assert case.status == "pending" and db.query(m.LegalHoldVault).count() == 0


# --------------------------------------------------------------------------- what each step records and asks

def test_turning_down_and_closing_each_write_their_success_row_under_the_case(db, people):
    turned = _ask(db, people.uma, _vaults(people.v1))
    cases.reject(db, turned, by=people.bob, reason="Not enough grounds.")
    db.commit()
    (row,) = _rows(db, "case_rejected", "success")
    assert (row.case_id, row.user_id, row.resource_id) == (turned.id, people.bob.id, str(turned.id))
    closed = _approve(db, _ask(db, people.uma, _vaults(people.v2), hold=False), people.bob)
    cases.close(db, closed, by=people.carl, reason="Concluded.")
    db.commit()
    (row,) = _rows(db, "case_closed", "success")
    assert (row.case_id, row.user_id, row.resource_id) == (closed.id, people.carl.id, str(closed.id))


@pytest.mark.parametrize("step", ["reject", "extend"])
def test_turning_down_and_extending_ask_for_the_approval_code_before_the_step(db, people, monkeypatch, step):
    asked = []

    def no_code(db_, user, request):
        asked.append(user.username)
        raise HTTPException(status_code=403, detail="the code was not given")
    monkeypatch.setattr(cr, "STEP_UP_CASE_APPROVE", no_code)
    case = _ask(db, people.uma, _vaults(people.v1))
    if step == "extend":
        _approve(db, case, people.bob)
        ends = case.access_ends_at
        _, err = _call(cr.extend_case, case.id, cr.Extension(days=1), request=None, if_match=f'"{case.version}"',
                       current_user=people.carl, db=db)
    else:
        _, err = _call(cr.reject_case, case.id, cr.Reason(reason="Not enough grounds."), request=None,
                       current_user=people.carl, db=db)
    assert err.status_code == 403 and err.detail == "the code was not given" and asked == ["carl"]
    db.expire_all()
    if step == "extend":
        assert case.status == "active" and case.access_ends_at == ends and _rows(db, "case_extended") == []
    else:
        assert case.status == "pending" and _rows(db, "case_rejected") == []


def test_the_vault_picker_and_asking_for_a_case_are_for_a_live_auditor_only():
    """Both depend on require_live_auditor, which refuses a right that is not in force whatever its stored state
    (test_auditor_liveness.py)."""
    for path, method in (("/compliance/vault-picker", "GET"), ("/compliance/cases", "POST")):
        (route,) = [r for r in cr.router.routes if getattr(r, "path", None) == path and method in r.methods]
        assert cr.require_live_auditor in {d.call for d in route.dependant.dependencies}, path


# --------------------------------------------------------------------------- an administrator the case concerns

def test_an_administrator_the_case_concerns_reads_no_reason_and_no_objection(db, people):
    """They see the case only as an owner does: not why it was turned down or closed, nor the owners' objections,
    free text that may name whom it is about."""
    otto_admin = people.otto
    otto_admin.role = m.RoleEnum.ADMIN
    db.commit()
    turned = _ask(db, people.uma, _vaults(people.v1, people.v3))
    cases.reject(db, turned, by=people.bob, reason="Insufficient grounds against otto.")
    closed = _approve(db, _ask(db, people.uma, _vaults(people.v2, people.v3)), people.bob)
    cases.record_objection(db, closed, by=people.olga, text_="otto is the one to ask.")
    cases.close(db, closed, by=people.carl, reason="Concluded: otto cleared.")
    db.commit()
    hidden = ("reject_reason", "close_reason", "objections", "people")
    for case in (turned, closed):
        mine = cases.case_view(db, case, otto_admin, detail=True)
        assert not set(hidden) & set(mine), case.status
        assert "otto" not in str({k: v for k, v in mine.items() if k not in ("vaults",)})
        assert mine["owner_note"] == TEXT["owner_note"]
        theirs = cases.case_view(db, case, people.carl, detail=True)
        assert set(hidden) <= set(theirs)
    assert cases.case_view(db, turned, people.carl)["reject_reason"] == "Insufficient grounds against otto."
    assert cases.case_view(db, closed, people.carl)["close_reason"] == "Concluded: otto cleared."
    assert [e["text"] for e in cases.case_view(db, closed, people.carl)["objections"]] == ["otto is the one to ask."]
    assert cases.case_view(db, closed, people.uma)["close_reason"] == "Concluded: otto cleared."


def _sees(db, case, viewer):
    """Whether the cases list, the case's page and the holds list show ``case`` to ``viewer``, each said apart."""
    listed = str(case.id) in {c["id"] for c in cr.list_cases(current_user=viewer, db=db)["cases"]}
    held = str(case.id) in {c["id"] for c in cr.list_holds(current_user=viewer, db=db)["cases"]}
    page, err = _call(cr.get_case, case.id, SimpleNamespace(headers={}), current_user=viewer, db=db)
    assert page is not None or err.status_code == 404, err
    return {"listed": listed, "page": page is not None, "holds": held}


NOTHING = {"listed": False, "page": False, "holds": False}


@pytest.fixture
def otto_admin(db, people):
    """otto, who owns v3, made an independent administrator long ago."""
    otto = people.otto
    otto.role = m.RoleEnum.ADMIN
    db.commit()
    admin_grants.record(db, otto.id, granted_by_id=None, granted_by_name=cc.HOST_OPERATOR,
                        now=rights.utcnow() - OLD)
    db.commit()
    return otto


def _steps_not_found(db, case, viewer, no_codes):
    """Every step of the case answers ``viewer`` as it answers anyone who may not see it: not found, with no
    record and no code asked."""
    before = db.query(m.AuditLog).count()
    asked = list(no_codes)
    calls = [
        (cr.approve_case, dict(request=None, if_match=f'"{case.version}"')),
        (cr.reject_case, dict(body=cr.Reason(reason="No."), request=None)),
        (cr.extend_case, dict(body=cr.Extension(days=1), request=None, if_match=f'"{case.version}"')),
        (cr.close_case, dict(body=cr.Reason(reason="Done."), request=None)),
        (cr.withdraw_case, {}),
        (cr.narrow_case, dict(body=cr.Narrowing(scope=[cr.ScopeItemIn(kind="vault",
                                                                       target_id=uuid.uuid4())]))),
        (cr.confirm_hold, dict(request=None)),
        (cr.review_hold, {}),
        (cr.release_hold, dict(body=cr.Reason(reason="Done."), request=None)),
        (cr.undo_hold_release, dict(request=None)),
    ]
    for fn, kw in calls:
        _, err = _call(fn, case.id, current_user=viewer, db=db, **kw)
        assert err is not None and err.status_code == 404, (fn.__name__, err and err.detail)
        db.rollback()
    assert db.query(m.AuditLog).count() == before and no_codes == asked


def test_a_named_administrator_sees_nothing_of_a_case_pending_or_active(db, people, otto_admin, told, no_codes):
    """An administrator a case names, who owns none of its vaults, sees it only as an owner does: an owner of none
    of its vaults sees nothing. Not while it waits for approval (before the owners are told and before its hold),
    nor once it is active: no list entry, no page, no step (not found, as for anyone else, never that it concerns
    them), no administrators' notice, and nothing on their own page. Another administrator sees it."""
    from app.core import owner_access
    case = _ask(db, people.uma, _vaults(people.v1), named_user_ids=[otto_admin.id], hold=True)
    assert _sees(db, case, otto_admin) == NOTHING
    assert _sees(db, case, people.carl) == {"listed": True, "page": True, "holds": False}
    _steps_not_found(db, case, otto_admin, no_codes)
    told.cases.clear()
    _approve(db, case, people.bob)
    assert case.status == "active" and holds.standing(db, case.id)
    assert _sees(db, case, otto_admin) == NOTHING
    assert _sees(db, case, people.carl) == {"listed": True, "page": True, "holds": True}
    _steps_not_found(db, case, otto_admin, no_codes)
    assert owner_access.page(db, otto_admin)["cases"] == []
    approved = [n for n in told.cases if n["title"] == "Case approved"]
    assert approved and all(str(otto_admin.id) not in n["people"] for n in approved)
    assert str(people.carl.id) in approved[0]["people"]


def test_an_administrator_who_owns_a_vault_in_the_case_sees_it_only_on_their_own_page(db, people, otto_admin,
                                                                                    no_codes):
    """otto owns v3: nothing while the case waits (an owner is not told yet); once it is active, his own page shows
    what any owner sees (its number and purpose, no justification, no people named), and the Compliance page still
    shows him nothing. He may record an objection on it, as an owner."""
    from app.core import owner_access
    case = _ask(db, people.uma, _vaults(people.v1, people.v3), named_user_ids=[people.carl.id])
    assert _sees(db, case, otto_admin) == NOTHING
    assert owner_access.page(db, otto_admin)["cases"] == []
    _approve(db, case, people.bob)
    assert _sees(db, case, otto_admin) == NOTHING
    _steps_not_found(db, case, otto_admin, no_codes)
    (mine,) = owner_access.page(db, otto_admin)["cases"]
    assert mine["number"] == case.number and mine["purpose"] == TEXT["purpose"]
    assert [v["vault_id"] for v in mine["vaults"]] == [str(people.v3.id)]
    assert "justification" not in mine and "people" not in mine and "carl" not in str(mine)
    out = cr.record_case_objection(case.id, cr.ObjectionIn(text="I object."), current_user=otto_admin, db=db)
    assert out["objections"] == 1


def test_an_administrator_a_vault_came_to_after_the_request_no_longer_sees_the_case(db, people, no_codes):
    """A vault of a waiting case that came to an administrator concerns them at once, before the approval reads
    its owners again: carl no longer sees the case, and is not among those who could approve it."""
    case = _ask(db, people.uma, _vaults(people.v1))
    assert _sees(db, case, people.carl)["page"]
    assert people.carl.id in {a.id for a in cases.independent_approvers(db, case)}
    people.v1.owner_id = people.carl.id
    db.commit()
    assert _sees(db, case, people.carl) == NOTHING
    assert people.carl.id not in {a.id for a in cases.independent_approvers(db, case)}
    _steps_not_found(db, case, people.carl, no_codes)


def test_a_hold_only_case_shows_an_administrator_it_concerns_nothing(db, people, otto_admin, told, no_codes):
    """A hold placed on otto's vault: he is told as its owner, the holds list does not show it to him, confirming it
    answers not found, unrecorded, and the administrators' notice of the hold leaves him out."""
    from app.core import owner_access
    case = holds.place_hold_only(db, people.uma, [people.v3.id], **TEXT)
    db.commit()
    assert _sees(db, case, otto_admin) == NOTHING
    assert _sees(db, case, people.carl)["holds"]
    _steps_not_found(db, case, otto_admin, no_codes)
    assert [c["id"] for c in owner_access.page(db, otto_admin)["cases"]] == [str(case.id)]
    assert told.holds and all(n["concerned"] == [str(otto_admin.id)] for n in told.holds)


def test_whom_a_step_concerns_is_read_with_what_the_step_added_but_not_yet_wrote(db, people, monkeypatch):
    """The session does not write on its own before a query: the administrators' notices read the people a step has
    just added (a named person, an owner read again) before leaving them out."""
    case = _ask(db, people.uma, _vaults(people.v1))
    db.add(m.ComplianceCasePerson(case_id=case.id, user_id=people.carl.id, why="named"))
    assert str(people.carl.id) not in {str(a) for a in cases._admins(db, case)}
    db.rollback()
    queued = []
    monkeypatch.setattr(holds, "queue", lambda db_, notice: queued.append(notice))
    db.add(m.ComplianceCasePerson(case_id=case.id, user_id=people.bob.id, why="named"))
    holds._tell(db, case, "t", "b")
    assert str(people.bob.id) in queued[0]["concerned"]
    db.rollback()


def test_the_administrators_notice_of_a_hold_leaves_out_those_it_concerns(db, people, otto_admin, monkeypatch):
    """legal_holds.deliver tells every active administrator and the auditor, but for the ones a notice says the case
    concerns."""
    from contextlib import contextmanager
    sent = []

    @contextmanager
    def same_db():
        yield db
    monkeypatch.setattr("app.core.database.get_db_context", same_db)
    monkeypatch.setattr(api, "_notify_users", lambda people_, *a, **k: sent.append(sorted(people_)))
    REAL_HOLDS_DELIVER([{"title": "t", "body": "b", "auditor_id": str(people.uma.id),
                         "concerned": [str(otto_admin.id)]}])
    (to,) = sent
    assert str(otto_admin.id) not in to
    assert {str(people.ada.id), str(people.bob.id), str(people.carl.id), str(people.uma.id)} <= set(to)


# --------------------------------------------------------------------------- closing while a release is undone

def test_a_close_that_asked_no_code_is_refused_when_a_hold_stands_again_under_the_lock(db, people, no_codes,
                                                                                      monkeypatch):
    """Whether a close asks for the hold's code is decided before the case's lock: a release undone in between
    would otherwise be released again without the code. Under the lock the close is refused (409, recorded) and the
    restored hold stands; asked again, it asks for the code."""
    case = _approve(db, _ask(db, people.uma, _vaults(people.v1)), people.bob)
    holds.release(db, case, by=people.carl, reason="Not needed.")
    db.commit()
    assert not holds.standing(db, case.id)
    real = cr._take_case_step

    def undone_meanwhile(case_id, current_user, db_, **kw):
        holds.undo_release(db_, db_.get(m.ComplianceCase, case_id), by=people.bob)
        db_.commit()
        return real(case_id, current_user, db_, **kw)
    monkeypatch.setattr(cr, "_take_case_step", undone_meanwhile)
    _, err = _call(cr.close_case, case.id, cr.Reason(reason="Concluded."), request=None, current_user=people.carl,
                   db=db)
    assert err.status_code == 409 and err.detail["reason"] == cases.HOLD_STANDS_AGAIN and no_codes == []
    assert _rows(db, "case_closed", "failure")[-1].details["reason"] == cases.HOLD_STANDS_AGAIN
    db.expire_all()
    assert case.status == "active" and holds.standing(db, case.id)
    monkeypatch.setattr(cr, "_take_case_step", real)
    out = cr.close_case(case.id, cr.Reason(reason="Concluded."), request=None, current_user=people.carl, db=db)
    assert out["status"] == "closed" and no_codes == ["STEP_UP_HOLD_DECIDE"]
