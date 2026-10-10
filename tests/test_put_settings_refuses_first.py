"""PUT /settings refuses a key it does not take before it settles the zero-knowledge switches or writes anything,
offline on a throwaway SQLite database.

The route's order is the step-up, then the payload's checks (``_validate_settings_payload``: among them the
settings registry's refusals, which hold the compliance settings, and the recording levels), then the switch rules
(``zero_knowledge_rules.settle_switches``), then the write and its audit row. A refused key never reaches the switch
rules and never changes the stored settings or writes an audit row. test_compliance_settings_live.py sends a
compliance key to the running route.
"""
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from _async_run import run_coroutine  # noqa: E402
from app.api import api_server as api  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402
from app.core import zero_knowledge_rules as zk_rules  # noqa: E402
from app.core.models import AuditLog, SystemSetting, User  # noqa: E402

pytestmark = pytest.mark.unit

ADMIN = SimpleNamespace(id=None, username="admin", role=api.RoleEnum.ADMIN)


@pytest.fixture
def steps(monkeypatch):
    """The route's steps, in the order they ran: the step-up, the checks, the switch rules, and each write."""
    seen = []
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: seen.append("step-up"))
    checks, settle = api._validate_settings_payload, zk_rules.settle_switches

    def checking(payload, db):
        seen.append("checks")
        return checks(payload, db)

    def settling(*a, **k):
        seen.append("switch rules")
        return settle(*a, **k)
    monkeypatch.setattr(api, "_validate_settings_payload", checking)
    monkeypatch.setattr(zk_rules, "settle_switches", settling)
    return seen


@pytest.fixture
def db(steps):
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'settings.db'}")
        for model in (SystemSetting, User, AuditLog):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine)()
        session.add(SystemSetting(key="global", value={"sharing_enabled": False}))
        session.commit()
        steps.clear()
        sa.event.listen(session, "before_flush", lambda s, *_a: steps.append("write") if (s.new or s.dirty) else None)
        sa.event.listen(session, "after_commit", lambda s: steps.append("commit"))
        yield session
        session.close()
        engine.dispose()


def _save(db, payload):
    return run_coroutine(api.update_settings(payload=payload, request=SimpleNamespace(headers={}, client=None),
                                             current_user=ADMIN, db=db))


def _stored(db):
    db.expire_all()
    return dict(db.get(SystemSetting, "global").value)


def test_a_save_is_checked_before_the_switch_rules_and_before_anything_is_written(db, steps):
    """Also the control for the refusals below: the steps recorded show the checks, the switch rules and the writes
    when they run."""
    _save(db, {"sharing_enabled": True})
    assert steps[:3] == ["step-up", "checks", "switch rules"]
    assert steps[3:] and set(steps[3:]) == {"write", "commit"} and steps[-1] == "commit", steps
    assert _stored(db) == {"sharing_enabled": True}
    assert db.query(AuditLog).filter(AuditLog.action == "settings_updated").count() == 1


@pytest.mark.parametrize("payload", [
    {cs.ACCESS: "enabled"},
    {cs.PASSWORD_VAULTS.upper(): "override", "sharing_enabled": True},
    {"sharing_enabled": True, cs.MAX_ACCESS_DAYS: 365},
    {"zero_knowledge_enabled": True, "force_zero_knowledge": True, cs.EXPORT: "allowed"},
    {"recording_levels": {"names": "full"}},
])
def test_a_refused_key_stops_the_save_before_the_switch_rules_and_any_write(db, steps, payload):
    with pytest.raises(HTTPException) as refused:
        _save(db, payload)
    assert refused.value.status_code == 400
    assert steps == ["step-up", "checks"], "refused before the switch rules and before any write"
    assert _stored(db) == {"sharing_enabled": False}
    assert db.query(AuditLog).count() == 0

