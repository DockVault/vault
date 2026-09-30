"""A rate limit the deployment locks keeps its deployment value (SETTINGS_LOCKED_KEYS).

The rate limits stay in the general settings blob, and the settings registry lists each one (group
``rate_limits``) so the lock can name it: by its key, by the group, or with ``*``. A locked limit resolves
to the deployment default whatever the blob holds, for the login, vault and SFTP throttles and for the
general API buckets alike, and PUT /settings refuses a new override for it while still taking the clear (0)
the Settings page sends for a row without one.
"""
import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import rate_limit_settings as rls  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402

pytestmark = pytest.mark.unit

KEY = "rate_limit_vault_attempts"


@pytest.fixture
def locks(monkeypatch):
    """Set SETTINGS_LOCKED_KEYS for the test."""
    def set_locks(value):
        monkeypatch.setattr(reg._deployment_settings(), "settings_locked_keys", value, raising=False)
    set_locks("")
    return set_locks


def test_every_rate_limit_is_listed_under_one_group_and_left_to_put_settings():
    listed = {e.key: e.group for e in reg.all_listed()}
    assert {k: listed.get(k) for k in rls.OVERRIDE_KEYS} == {k: rls.LOCK_GROUP for k in rls.OVERRIDE_KEYS}
    assert rls.LOCK_GROUP == "rate_limits"
    assert not set(rls.OVERRIDE_KEYS) & reg.refused_settings_keys()
    assert "app.core.rate_limit_settings" in reg.SPEC_MODULES


@pytest.mark.parametrize("tokens", [KEY, "rate_limits", "RATE_LIMITS", "*", "other, rate_limit_vault_attempts"])
def test_a_locked_limit_is_its_deployment_default_whatever_is_stored(locks, tokens):
    blob = {KEY: 7}
    assert rls.resolve(KEY, blob) == 7 and rls.custom_value(KEY, blob) == 7
    locks(tokens)
    assert rls.is_locked(KEY) is True
    assert rls.resolve(KEY, blob) == rls.deployment_default(KEY)
    assert rls.custom_value(KEY, blob) is None
    row = {r["key"]: r for r in rls.describe_all(blob)}[KEY]
    assert (row["locked"], row["custom"], row["effective"]) == (True, None, rls.deployment_default(KEY))


def test_locking_one_limit_leaves_the_others(locks):
    other = "rate_limit_sftp_key_attempts"
    locks(KEY)
    blob = {KEY: 7, other: 9}
    assert rls.resolve(other, blob) == 9 and rls.is_locked(other) is False
    assert dict(rls.unlocked_overrides(blob)) == {other: 9}


def test_the_general_api_buckets_read_only_the_unlocked_overrides(locks):
    blob = {"rate_limit_api_default": 50, "rate_limit_api_poll": 70, "unrelated": 1}
    locks("rate_limit_api_default")
    assert api._rate_limit_overrides_in_force(blob) == {"rate_limit_api_poll": 70, "unrelated": 1}
    locks("")
    assert api._rate_limit_overrides_in_force(blob) == blob
    assert rls.unlocked_overrides(None) == {}


def test_the_general_api_loader_leaves_a_locked_override_out(locks, monkeypatch):
    class Row:
        value = {"rate_limit_api_default": 50, "rate_limit_api_poll": 70}

    class Query:
        def filter(self, *_a):
            return self

        def first(self):
            return Row()

    class Session:
        def query(self, _model):
            return Query()

        def close(self):
            pass

    import app.core.database as database
    monkeypatch.setattr(database, "SessionLocal", Session)
    locks("rate_limits")
    assert api._load_stored_api_rate_limit_overrides() == {}
    locks("")
    assert api._load_stored_api_rate_limit_overrides() == {"rate_limit_api_default": 50, "rate_limit_api_poll": 70}


def _refusal(payload):
    try:
        api._validate_settings_payload(payload, db=None)
    except HTTPException as exc:
        return exc
    return None


def test_put_settings_refuses_a_new_override_for_a_locked_limit_and_takes_its_clear(locks):
    locks("rate_limits")
    refused = _refusal({KEY: 7})
    assert refused is not None and refused.status_code == 400
    assert refused.detail == f"{KEY} is locked by the deployment"
    assert _refusal({KEY: 0}) is None
    locks("")
    assert _refusal({KEY: 7}) is None


def test_a_saved_override_of_a_locked_bucket_never_reaches_the_general_api_policy(locks, monkeypatch):
    """PUT /settings hands the general API buckets what it saved; a locked bucket's stored value is left out."""
    import tempfile
    from pathlib import Path
    from types import SimpleNamespace

    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker

    from _async_run import run_coroutine
    from app.core.models import AuditLog, SystemSetting, User

    replaced = []
    monkeypatch.setattr(api, "_enforce_step_up", lambda *a, **k: None)
    monkeypatch.setattr(api, "_api_rate_limit_policy_cache", SimpleNamespace(replace=replaced.append))
    admin = SimpleNamespace(id=None, username="admin", role=api.RoleEnum.ADMIN)
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'settings.db'}")
        for model in (SystemSetting, User, AuditLog):
            model.__table__.create(engine)
        db = sessionmaker(bind=engine)()
        try:
            db.add(SystemSetting(key="global", value={"rate_limit_api_default": 50}))
            db.commit()
            locks("rate_limit_api_default")
            run_coroutine(api.update_settings(payload={"rate_limit_api_poll": 70},
                                              request=SimpleNamespace(headers={}, client=None),
                                              current_user=admin, db=db))
        finally:
            db.close()
            engine.dispose()
    assert replaced == [{"rate_limit_api_poll": 70}]
