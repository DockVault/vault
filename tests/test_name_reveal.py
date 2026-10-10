"""Revealing a recorded name outside a case, offline on a real (SQLite) database (app/core/name_reveal.py, its route
in app/api/compliance_router.py, the owner's notice in app/core/owner_notices.py).

Only an auditor whose right is in force reveals, with a reason; the answer is the event's values kept in full and
nothing else (a fingerprint stays one, and is not returned); never of a vault with a password or a zero-knowledge
one, whatever the setting; never of a vault the auditor reads already, or one gone. The reveal row, the sealed
reason and the owner's notice (once per auditor, vault and day) commit together before the names are sent; the
row is written even when no value comes out; a daily cap; every refusal recorded. test_name_reveal_live.py runs it
on a stack.
"""
# ruff: noqa: F811 -- the fixtures of _case_access_helpers are imported by name and used as parameters
import uuid
from datetime import timedelta

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from _case_access_helpers import (  # noqa: E402,F401 -- the fixtures are used by name
    db, people, quiet, settings, storage)
from _case_access_helpers import file as _file  # noqa: E402
from _case_access_helpers import rows as _rows  # noqa: E402
from _case_access_helpers import user as _user  # noqa: E402
from _case_access_helpers import vault as _vault  # noqa: E402
from app.api import compliance_router as cr  # noqa: E402
from app.core import auditor_rights as rights  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import name_reveal as nr  # noqa: E402
from app.core import owner_notices as on  # noqa: E402
from app.core.audit_privacy import seal_name  # noqa: E402
from app.services.audit_logger import AuditLogger  # noqa: E402

pytestmark = pytest.mark.unit

REASON = "Ticket SEC-2041: tracing the copy of the payroll file."


def _call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs), None
    except HTTPException as exc:
        return None, exc


def _event(db, vault, *, by, file=None, names=None, fingerprints=()):
    """An event about ``file`` in ``vault`` whose recording kept ``names`` ({key: value}) in full and the keys in
    ``fingerprints`` as fingerprints only."""
    row = AuditLogger(db).build_row(action="file_download", status="success", user=by, resource_type="file",
                                    resource_id=str(file.id) if file is not None else str(uuid.uuid4()),
                                    details={"vault_id": str(vault.id)})
    row.id = row.id or uuid.uuid4()
    values = {key: {"fp": f"fp-{key}", "sealed": seal_name(vault.id, row.id, key, value)}
              for key, value in (names or {}).items()}
    values.update({key: {"fp": f"fp-{key}"} for key in fingerprints})
    row.recorded = {"names": {"vault": str(vault.id), "values": values}}
    db.add(row)
    db.commit()
    return row


def _reveal(db, who, row, category="security_incident", text=REASON):
    return cr.reveal_event_names(row.id if row is not None else uuid.uuid4(),
                                 cr.RevealIn(reason_category=category, reason_text=text), current_user=who, db=db)


def _refusals(db):
    return [r.details.get("reason") for r in _rows(db, nr.ACTION, "failure")]


# --------------------------------------------------------------------------- who reveals

def test_only_a_live_auditor_reveals(db, people):
    row = _event(db, people.v1, by=people.olga, names={"file_name": "payroll.xlsx"})
    route = [r for r in cr.router.routes if getattr(r, "path", "") == "/activity/events/{event_id}/reveal"]
    (route,) = route
    assert cr.require_live_auditor in {d.call for d in route.dependant.dependencies}
    for who in (people.olga, people.bob):
        _, err = _call(cr.require_live_auditor, current_user=who, db=db)
        assert err.status_code == 403, who.username
    rights.revoke(db, rights.open_grant(db, people.uma.id), actor=people.ada)
    db.commit()
    _, err = _call(cr.require_live_auditor, current_user=people.uma, db=db)
    assert err.status_code == 403
    assert db.query(m.ComplianceReveal).count() == 0 and row is not None


def test_a_reason_is_required_and_its_category_is_from_the_list(db, people):
    row = _event(db, people.v1, by=people.olga, names={"file_name": "payroll.xlsx"})
    for category, text in (("security_incident", "   "), ("because", REASON)):
        _, err = _call(_reveal, db, people.uma, row, category, text)
        assert err.status_code == 422
    assert db.query(m.ComplianceReveal).count() == 0 and _rows(db, nr.ACTION, "failure") == []


def test_a_reason_longer_than_is_sealed_is_refused_never_cut_short(db, people):
    """The reason is sealed whole: one past REASON_MAX characters (surrounding spaces aside) is refused, unrecorded
    and revealing nothing; one of exactly REASON_MAX is sealed as given."""
    from app.core.security import open_case_field
    row = _event(db, people.v1, by=people.olga, names={"file_name": "payroll.xlsx"})
    _, err = _call(_reveal, db, people.uma, row, "security_incident", "x" * (nr.REASON_MAX + 1))
    assert err.status_code == 422 and err.detail["reason"] == nr.LONG_REASON
    assert db.query(m.ComplianceReveal).count() == 0 and _rows(db, nr.ACTION, "failure") == []
    whole = "  " + "y" * nr.REASON_MAX + "  "
    assert _reveal(db, people.uma, row, "security_incident", whole)["names"] == {"file_name": "payroll.xlsx"}
    (kept,) = db.query(m.ComplianceReveal).all()
    assert open_case_field(kept.id, kept.reason_text_enc, "reveal_reason") == "y" * nr.REASON_MAX


# --------------------------------------------------------------------------- what is revealed

def test_the_values_kept_in_full_and_nothing_else(db, people, storage):
    f = _file(db, storage, people.v1, name="now-renamed.xlsx")
    row = _event(db, people.v1, by=people.olga, file=f, names={"file_name": "payroll.xlsx", "vault_name": "HR"},
                 fingerprints=("old_name",))
    out = _reveal(db, people.uma, row)
    assert out["names"] == {"file_name": "payroll.xlsx", "vault_name": "HR"}, "the recorded values, not today's"
    assert out["not_in_full"] == ["old_name"] and "fp-old_name" not in str(out), "a fingerprint stays hidden"
    assert out["vault_id"] == str(people.v1.id) and out["event_id"] == str(row.id)
    (ok,) = _rows(db, nr.ACTION)
    assert ok.details == {**ok.details, "event_id": str(row.id), "vault_id": str(people.v1.id),
                          "reason_category": "security_incident", "count": 2}
    assert "payroll" not in str(ok.details) and REASON not in str(ok.details)


def test_the_reveal_row_is_written_even_when_no_value_comes_out(db, people):
    row = _event(db, people.v1, by=people.olga, fingerprints=("file_name",))
    out = _reveal(db, people.uma, row)
    assert out["names"] == {} and out["not_in_full"] == ["file_name"]
    assert db.query(m.ComplianceReveal).count() == 1 and len(_rows(db, nr.ACTION)) == 1
    empty = _event(db, people.v1, by=people.olga, names={"file_name": ""})
    assert _reveal(db, people.uma, empty)["names"] == {"file_name": ""}
    assert db.query(m.ComplianceReveal).count() == 2


@pytest.mark.parametrize("setting", [cs.REFUSE, cs.WITH_PASSWORD, cs.OVERRIDE])
def test_never_a_vault_with_a_password_whatever_the_setting(db, people, settings, setting):
    settings[cs.PASSWORD_VAULTS] = setting
    pv = _vault(db, people.olga, password="argon2-hash")
    row = _event(db, pv, by=people.olga, names={"file_name": "salaries.csv"})
    _, err = _call(_reveal, db, people.uma, row)
    assert err.status_code == 403 and err.detail["reason"] == nr.PASSWORD_VAULT
    assert "salaries" not in str(err.detail)
    assert _refusals(db) == [nr.PASSWORD_VAULT] and db.query(m.ComplianceReveal).count() == 0
    assert db.query(m.ComplianceNoticeOutbox).count() == 0


def test_never_a_zero_knowledge_vault_one_gone_one_readable_or_an_event_of_no_vault(db, people, monkeypatch):
    zk = _vault(db, people.olga, kind="zero_knowledge")
    zrow = _event(db, zk, by=people.olga, names={"vault_name": "Sealed"})
    gone = _vault(db, people.olga)
    grow = _event(db, gone, by=people.olga, names={"file_name": "x.txt"})
    db.delete(gone)
    db.commit()
    plain = AuditLogger(db).build_row(action="sign_in", status="success", user=people.uma)
    db.add(plain)
    db.commit()
    mine = _vault(db, people.uma)
    mrow = _event(db, mine, by=people.uma, names={"file_name": "mine.txt"})
    for row, reason in ((zrow, nr.ZERO_KNOWLEDGE), (grow, nr.VAULT_GONE), (plain, nr.NO_VAULT), (mrow, nr.READABLE),
                        (None, nr.NO_SUCH_EVENT)):
        _, err = _call(_reveal, db, people.uma, row)
        assert err.status_code == nr.STATUS[reason] and err.detail["reason"] == reason, reason
    assert _refusals(db) == [nr.ZERO_KNOWLEDGE, nr.VAULT_GONE, nr.NO_VAULT, nr.READABLE, nr.NO_SUCH_EVENT]
    assert db.query(m.ComplianceReveal).count() == 0


# --------------------------------------------------------------------------- the reason, the owner, the cap

def test_the_reason_is_sealed_and_never_in_the_clear(db, people):
    row = _event(db, people.v1, by=people.olga, names={"file_name": "payroll.xlsx"})
    _reveal(db, people.uma, row)
    (kept,) = db.query(m.ComplianceReveal).all()
    assert kept.reason_text_enc and REASON not in kept.reason_text_enc
    from app.core.security import open_case_field
    assert open_case_field(kept.id, kept.reason_text_enc, "reveal_reason") == REASON
    from sqlalchemy import inspect as sa_inspect, text
    engine = db.get_bind()
    for table in sa_inspect(engine).get_table_names():
        for record in db.execute(text(f'SELECT * FROM "{table}"')).fetchall():
            assert REASON not in str(record) and "Ticket SEC-2041" not in str(record), table


def test_the_owner_is_told_once_per_auditor_vault_and_day_in_the_reveals_commit(db, people, monkeypatch):
    rows = [_event(db, people.v1, by=people.olga, names={"file_name": f"f{i}.txt"}) for i in range(3)]
    other = _event(db, people.v2, by=people.otto, names={"file_name": "o.txt"})
    day = nr.utcnow().replace(hour=10)
    real = nr.reveal
    monkeypatch.setattr(nr, "reveal", lambda *a, **k: real(*a, **{**k, "now": k.get("now") or day}))
    _reveal(db, people.uma, rows[0])
    _reveal(db, people.uma, rows[1])
    _reveal(db, people.mallory, rows[2])
    _reveal(db, people.uma, other)
    told = [(o.user_id, o.kind, o.details["auditor"]) for o in db.query(m.ComplianceNoticeOutbox)
            .order_by(m.ComplianceNoticeOutbox.created_at)]
    assert sorted(told) == sorted([(people.olga.id, on.REVEAL, "uma"), (people.olga.id, on.REVEAL, "mallory"),
                                   (people.otto.id, on.REVEAL, "uma")])
    notes = db.query(m.Notification).filter(m.Notification.user_id == people.olga.id).all()
    assert len(notes) == 2 and all("payroll" not in n.body and "f0" not in n.body for n in notes)
    assert all(o.case_id is None for o in db.query(m.ComplianceNoticeOutbox))
    monkeypatch.setattr(nr, "reveal", lambda *a, **k: real(*a, **{**k, "now": day + timedelta(days=1)}))
    _reveal(db, people.uma, rows[0])
    assert db.query(m.ComplianceNoticeOutbox).filter(m.ComplianceNoticeOutbox.user_id == people.olga.id).count() == 3
    assert len(_rows(db, "owner_notice_written")) == 4


def test_a_reveal_whose_notice_cannot_be_written_reveals_nothing(db, people, monkeypatch):
    row = _event(db, people.v1, by=people.olga, names={"file_name": "payroll.xlsx"})

    def broken(*a, **k):
        raise RuntimeError("the notice could not be written")
    monkeypatch.setattr(on, "tell_owner_of_reveal", broken)
    with pytest.raises(RuntimeError):
        _reveal(db, people.uma, row)
    db.rollback()
    assert db.query(m.ComplianceReveal).count() == 0 and _rows(db, nr.ACTION) == []


def test_the_daily_cap(db, people, settings):
    settings[cs.REVEALS_PER_DAY] = 2
    rows = [_event(db, people.v1, by=people.olga, names={"file_name": f"f{i}.txt"}) for i in range(3)]
    _reveal(db, people.uma, rows[0])
    _reveal(db, people.uma, rows[1])
    _, err = _call(_reveal, db, people.uma, rows[2])
    assert err.status_code == 429 and err.detail["reason"] == nr.CAP
    assert _refusals(db) == [nr.CAP]
    assert _reveal(db, people.mallory, rows[2])["names"] == {"file_name": "f2.txt"}, "the cap is each auditor's"
    yesterday = nr.utcnow() - timedelta(days=1, minutes=1)
    for r in db.query(m.ComplianceReveal).filter(m.ComplianceReveal.auditor_id == people.uma.id):
        r.created_at = yesterday
    db.commit()
    assert _reveal(db, people.uma, rows[2])["names"] == {"file_name": "f2.txt"}, "a new day"


def test_the_notice_says_who_and_why_never_a_name(db, people):
    title, lines = on.notice_text(on.Facts(kind=on.REVEAL, number=None, auditor="uma", reason="security_incident",
                                           vaults=1, contact="privacy@example.test"))
    text = title + " " + " ".join(lines)
    assert "uma" in text and "a security incident" in text and "privacy@example.test" in text
    row = m.ComplianceNoticeOutbox(id=uuid.uuid4(), case_id=None, user_id=people.olga.id, kind=on.REVEAL,
                                   dedup_key="k", details={"auditor": "uma", "reason": "other", "vaults": 1},
                                   status=on.PENDING, attempts=0, created_at=nr.utcnow(), sent_to=[])
    context = on.email_context(db, row, None)
    assert context["code"] == "" and "uma" in context["change"] and "another reason" in context["change"]


def test_the_sender_records_the_outcome_of_a_notice_outside_a_case(db, people, monkeypatch):
    row = m.ComplianceNoticeOutbox(id=uuid.uuid4(), case_id=None, user_id=people.olga.id, kind=on.REVEAL,
                                   dedup_key="k2", details={"auditor": "uma", "reason": "other", "vaults": 1},
                                   status=on.PENDING, attempts=0, created_at=nr.utcnow(), sent_to=[])
    from app.core.security import seal_case_field
    row.address_enc = seal_case_field(row.id, "olga@example.test", "notice_address")
    db.add(row)
    db.commit()
    sent = []
    assert on._attempt(db, row, nr.utcnow(), lambda db_, r, case, address, username: sent.append(address)) == on.SENT
    db.commit()
    assert sent == ["olga@example.test"]
    (ok,) = _rows(db, "owner_notice_email_sent")
    assert ok.details["kind"] == on.REVEAL and ok.case_id is None


def test_the_reveal_route_is_a_plain_def_with_a_statement_timeout_and_its_body_class():
    import inspect
    from app.core import body_limit as bl
    assert not inspect.iscoroutinefunction(cr.reveal_event_names)
    source = inspect.getsource(cr.reveal_event_names)
    assert "limit_statements(db)" in source and source.index("reveal(") < source.index("db.commit()")
    for forbidden in ("require_endpoint_permission", "PermissionEnum", "require_permission"):
        assert forbidden not in source
    rule = bl.rule_for("POST", f"/activity/events/{uuid.uuid4()}/reveal")
    assert rule.name == "case_query" and rule.needs_session
