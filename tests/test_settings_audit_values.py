"""PUT /settings records each changed key's values before and after, in the save's own transaction.

The ``settings_updated`` row names every key the save carried (``keys``) and, for each key whose value
changed, the value before and after (``changes``): a secret only as whether it is set, a long value (an
image, a template) by its SHA-256 and length. The row commits with the save, and a save whose row cannot be
written is refused with nothing changed. These run on a throwaway SQLite database.
"""
import hashlib
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
from app.core.models import AuditLog, SystemSetting, User  # noqa: E402

pytestmark = pytest.mark.unit

ADMIN = SimpleNamespace(id=None, username="admin", role=api.RoleEnum.ADMIN)


@pytest.fixture
def db(monkeypatch):
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'settings.db'}")
        for model in (SystemSetting, User, AuditLog):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine)()
        yield session
        session.close()
        engine.dispose()


def _save(db, payload):
    return run_coroutine(api.update_settings(payload=payload, request=SimpleNamespace(headers={}, client=None),
                                             current_user=ADMIN, db=db))


def _stored(db):
    db.expire_all()
    row = db.get(SystemSetting, "global")
    return dict(row.value) if row else {}


def _last_row(db):
    return db.query(AuditLog).filter(AuditLog.action == "settings_updated").order_by(
        AuditLog.timestamp.desc()).first()


def test_each_changed_key_is_recorded_with_its_values_before_and_after(db):
    _save(db, {"example_hours": 72, "sharing_enabled": True})
    _save(db, {"example_hours": 48, "sharing_enabled": True, "session_timeout": 30})
    row = _last_row(db)
    assert row.details["keys"] == ["example_hours", "session_timeout", "sharing_enabled"]
    assert row.details["changes"] == {"example_hours": {"old": 72, "new": 48},
                                      "session_timeout": {"old": None, "new": 30}}


def test_a_secret_is_recorded_only_as_whether_it_is_set(db, monkeypatch):
    assert api._settings_value_for_audit("smtp_password", "hunter2-hunter2") == "(set)"
    assert api._settings_value_for_audit("smtp_password", "") is None
    monkeypatch.setattr(api, "_SETTINGS_SENSITIVE", api._SETTINGS_SENSITIVE | {"an_api_token"})
    _save(db, {"an_api_token": "hunter2-hunter2"})
    assert _last_row(db).details["changes"] == {"an_api_token": {"old": None, "new": "(set)"}}
    _save(db, {"an_api_token": ""})
    assert _last_row(db).details["changes"] == {"an_api_token": {"old": "(set)", "new": None}}
    assert "hunter2" not in str([r.details for r in db.query(AuditLog).all()])


def test_a_long_value_is_recorded_by_its_digest_and_length(db):
    banner = "x" * (api._SETTINGS_AUDIT_TEXT_MAX + 1)
    _save(db, {"login_banner_text": banner})
    change = _last_row(db).details["changes"]["login_banner_text"]
    assert change == {"old": None, "new": {"sha256": hashlib.sha256(banner.encode()).hexdigest(),
                                           "length": len(banner)}}
    edge = "y" * api._SETTINGS_AUDIT_TEXT_MAX
    assert api._settings_value_for_audit("a", edge) == edge
    big = {"items": ["z" * 300]}
    assert set(api._settings_value_for_audit("a", big)) == {"sha256", "length"}
    assert api._settings_value_for_audit("a", {"small": 1}) == {"small": 1}


def test_a_save_whose_audit_row_cannot_be_written_is_refused_and_nothing_changes(db):
    _save(db, {"example_hours": 72})
    AuditLog.__table__.drop(db.get_bind())
    with pytest.raises(HTTPException) as caught:
        _save(db, {"example_hours": 24})
    assert caught.value.status_code == 503 and "Nothing was changed" in caught.value.detail
    assert _stored(db)["example_hours"] == 72


def test_a_save_whose_audit_row_cannot_be_built_is_refused_and_nothing_changes(db, monkeypatch):
    from app.services.audit_logger import AuditLogger
    _save(db, {"example_hours": 72})

    def broken(*_a, **_k):
        raise RuntimeError("no row")

    monkeypatch.setattr(AuditLogger, "build_row", broken)
    with pytest.raises(HTTPException) as caught:
        _save(db, {"example_hours": 24})
    assert caught.value.status_code == 503
    assert _stored(db)["example_hours"] == 72
