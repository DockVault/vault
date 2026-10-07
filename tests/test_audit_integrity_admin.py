"""An administrator's acknowledgment of the audit log's integrity warnings (app/api/audit_integrity_router.py),
offline: the warnings list shows each late seal with the rows it added; the acknowledgment asks for the fixed
step-up, writes an ack seal naming the administrator with its audit row, and refuses failures' kinds and seals
another writer appended; the page's script exists and builds the list without innerHTML.

Runs on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException

from _audit_chain_env import Env, T0, failures
from app.api import audit_integrity_router as routes
from app.core import audit_integrity as ai
from app.core import fixed_step_up
from app.core.models import AuditLog, RoleEnum, User
from test_audit_chain_guards import _forge

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


@pytest.fixture
def admin(env):
    uid = uuid.uuid4()
    with env.session() as db:
        db.add(User(id=uid, username="ada", email="ada@example.com", password_hash="x", role=RoleEnum.ADMIN,
                    is_active=True))
        db.commit()
    return env.session().get(User, uid)


class _Body:
    def __init__(self, seqs):
        self.seqs = seqs


def _late(env):
    env.row(T0 - timedelta(hours=3, minutes=10))
    env.run_until_sealed()
    added = env.row(ai.hour_floor(T0 - timedelta(hours=3)) + timedelta(minutes=20), username="carol")
    env.clock.advance(hours=1)
    env.seal()
    return [s for s in env.seals() if s.kind == "late"][0].seq, added


def test_the_warnings_show_each_late_seal_with_the_rows_it_added(env, admin):
    seq, added = _late(env)
    out = routes.get_warnings(current_user=admin, db=env.session())
    (w,) = out["warnings"]
    assert w["seq"] == seq and w["kind"] == "late" and w["added"] == 1
    assert w["rows"][0]["id"] == str(added) and w["rows"][0]["account"] == "carol"


def test_the_warnings_show_a_late_seal_another_process_wrote_since_this_one_read_the_chain(env, admin):
    env.row(T0 - timedelta(hours=3, minutes=10))
    env.run_until_sealed()
    added = env.row(ai.hour_floor(T0 - timedelta(hours=3)) + timedelta(minutes=20), username="carol")
    env.clock.advance(hours=1)
    other = ai.ChainState(settings=env.settings, clock=env.clock)      # a pass run in a process of its own
    ai.seal_pass(env.session, engine=env.engine, st=other, now=env.clock())
    late = [s.seq for s in env.seals() if s.kind == "late"]
    assert late and env.st.view.position < late[0]
    (w,) = routes.get_warnings(current_user=admin, db=env.session())["warnings"]
    assert w["seq"] == late[0] and w["rows"][0]["id"] == str(added)


def test_an_acknowledgment_asks_for_the_step_up_and_writes_an_ack_seal_naming_the_administrator(env, admin,
                                                                                                monkeypatch):
    seq, _added = _late(env)
    seen = []
    monkeypatch.setattr(routes, "_step_up", lambda db, user, request: seen.append(user.username))
    out = routes.acknowledge_warnings(_Body([seq]), request=None, current_user=admin, db=env.session())
    assert out == {"acknowledged": [seq]} and seen == ["ada"]
    ack = env.seals()[-1]
    assert ack.kind == "ack" and ack.detail["by"] == "admin" and ack.detail["user_id"] == str(admin.id)
    assert ack.detail["acknowledges"] == [seq]
    with env.session() as db:
        row = db.query(AuditLog).filter(AuditLog.action == ai.ACKNOWLEDGED_ACTION).one()
        assert row.username == "ada" and str(row.id) == ack.detail["request"]
    assert "late" not in ai.status(env.st)["warnings"]
    assert routes.get_warnings(current_user=admin, db=env.session())["warnings"] == []


def test_a_refused_step_up_acknowledges_nothing(env, admin, monkeypatch):
    seq, _added = _late(env)

    def refuse(db, user, request):
        raise HTTPException(status_code=403, detail={"second_factor_required": True})
    monkeypatch.setattr(routes, "_step_up", refuse)
    with pytest.raises(HTTPException):
        routes.acknowledge_warnings(_Body([seq]), request=None, current_user=admin, db=env.session())
    assert env.seals()[-1].kind != "ack"


def test_an_administrator_cannot_acknowledge_another_writers_seal_or_a_seal_that_is_no_warning(env, admin,
                                                                                               monkeypatch):
    seq, _added = _late(env)
    monkeypatch.setattr(routes, "_step_up", lambda db, user, request: None)
    foreign = _forge(env, "ack", {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin",
                                  "user_id": None, "request": None})
    env.clock.advance(minutes=30)
    env.seal()
    for bad in ([foreign], [1], [seq, 2]):
        with pytest.raises(HTTPException) as refused:
            routes.acknowledge_warnings(_Body(bad), request=None, current_user=admin, db=env.session())
        assert refused.value.status_code == 409 and "host operator" in refused.value.detail
    assert not [s for s in env.seals() if s.kind == "ack" and (s.detail or {}).get("user_id") == str(admin.id)]
    assert failures(env.verify()) == []


def test_a_busy_chain_answers_busy(env, admin, monkeypatch):
    seq, _added = _late(env)
    monkeypatch.setattr(routes, "_step_up", lambda db, user, request: None)
    env.st.mutex.acquire()
    try:
        monkeypatch.setattr(ai.ChainWriter, "__init__", _quick(ai.ChainWriter.__init__))
        with pytest.raises(HTTPException) as busy:
            routes.acknowledge_warnings(_Body([seq]), request=None, current_user=admin, db=env.session())
        assert busy.value.status_code == 409 and "Busy" in busy.value.detail
    finally:
        env.st.mutex.release()


def _quick(init):
    def wrapped(self, engine, st=None, *, wait=30.0, **kw):
        init(self, engine, st, wait=0.2, **kw)
    return wrapped


def test_the_step_up_is_fixed_and_the_page_builds_the_list_without_inner_html():
    from app.core import second_factor_actions as acts
    assert routes.STEP_UP_ACTION in fixed_step_up.GUARDED
    assert acts.fixed_policy(routes.STEP_UP_ACTION) == "password_always"
    assert routes.STEP_UP_ACTION not in " ".join(fixed_step_up.contract_problems())
    js = (ROOT / "static" / "js" / "settings-integrity.js").read_text(encoding="utf-8")
    assert "innerHTML" not in js and "/settings/audit-integrity/acknowledge" in js
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    assert 'id="integrity-warnings-card"' in html and "/static/js/settings-integrity.js?v=" in html
