"""The managed-settings routes (app/api/managed_settings_router.py), offline.

GET /settings/managed describes every managed setting from the process's copy; PUT /settings/managed/{key}
stores an administrator's value with its audit row, in one transaction, and refuses what the panel may not
set: a setting only .env sets, a locked one, a value of the wrong kind, and one outside the deployment's
floor and ceiling, naming the .env line. The routes are plain functions (the thread pool runs them), mounted
on the app, and reached only by an interactive administrator. These run on a throwaway SQLite database, with
a throwaway setting.
"""
import inspect
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.api import managed_settings_router as routes  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402
from app.core.models import AuditLog, ManagedSetting, RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch):
    """Deployment settings the test controls, no stored values, and only the test's own settings."""
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    settings = SimpleNamespace(settings_locked_keys="", keep_days=30, keep_floor=7, keep_ceiling=None)
    monkeypatch.setattr(reg, "_deployment_settings", lambda: settings)
    reg.all_specs()
    saved = [(table, dict(table)) for table in (reg._SPECS, reg._LISTED, reg._LOCK_GROUPS)]
    for table, _ in saved:
        table.clear()
    reg.register(reg.SettingSpec(key="keep_days", kind="int", default=90, env="keep_days", minimum=1,
                                 maximum=3650, floor="keep_floor", ceiling="keep_ceiling", unlimited=0,
                                 reduction=reg.LOWER, group="keeping", label="Keep for"))
    reg.register(reg.SettingSpec(key="env_days", kind="int", default=5, editable=reg.ENV_ONLY))
    yield settings
    for table, before in saved:
        table.clear()
        table.update(before)


@pytest.fixture
def db(monkeypatch):
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'managed.db'}")
        for model in (User, ManagedSetting, AuditLog):
            model.__table__.create(engine)
        factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        monkeypatch.setattr(reg, "_default_session_factory", factory)
        session = factory()
        yield session
        session.close()
        engine.dispose()


def _admin(db, name="alice"):
    user = User(id=uuid.uuid4(), username=name, email=f"{name}@example.com", password_hash="x",
                role=RoleEnum.ADMIN, is_active=True)
    db.add(user)
    db.commit()
    return user


def _put(db, user, key, value):
    return routes.put_managed_setting(key, routes.ManagedValue(value=value), request=None,
                                      current_user=user, db=db)


def _rows(db, action="setting_changed"):
    return db.query(AuditLog).filter(AuditLog.action == action).all()


@contextmanager
def refused(status):
    with pytest.raises(HTTPException) as caught:
        yield caught
    assert caught.value.status_code == status


# --------------------------------------------------------------------------- the routes themselves

def _app_routes():
    from fastapi.routing import APIRoute, _IncludedRouter

    def walk(found, prefix):
        for r in found:
            if isinstance(r, _IncludedRouter):
                yield from walk(r.original_router.routes, prefix + r.include_context.prefix)
            elif isinstance(r, APIRoute):
                yield prefix + r.path, r

    return list(walk(api.app.router.routes, ""))


def _managed_routes():
    return {(method, path): route for path, route in _app_routes() if path.startswith("/settings/managed")
            for method in route.methods}


def test_the_routes_are_plain_functions_mounted_on_the_app():
    found = _managed_routes()
    assert {("GET", "/settings/managed"), ("PUT", "/settings/managed/{key}")} <= set(found)
    for route in found.values():
        assert not inspect.iscoroutinefunction(route.endpoint), route.path


def test_only_an_interactive_administrator_reaches_them():
    from app.api import user_management_api as um
    found = _managed_routes()
    assert found
    for route in found.values():
        deps = {d.call for d in route.dependant.dependencies}
        assert um.require_interactive_admin in deps, route.path


def test_every_statement_is_bounded_on_postgres():
    seen = []

    class Bind:
        dialect = SimpleNamespace(name="postgresql")

    class Session:
        def get_bind(self):
            return Bind()

        def execute(self, statement):
            seen.append(str(statement))

    routes.limit_statements(Session())
    assert seen == [f"SET LOCAL statement_timeout = {routes.STATEMENT_TIMEOUT_MS}"]
    for fn in (routes.get_managed_settings, routes.put_managed_setting):
        source = inspect.getsource(fn)
        body = source.split('"""', 2)[2]
        assert body.lstrip().startswith("limit_statements(db)"), fn.__name__


# --------------------------------------------------------------------------- reading

def test_get_describes_every_managed_setting_from_the_copy(env, db):
    user = _admin(db)
    out = routes.get_managed_settings(current_user=user, db=db)
    rows = {r["key"]: r for r in out["settings"]}
    assert set(rows) == {"keep_days", "env_days"}
    assert (rows["keep_days"]["value"], rows["keep_days"]["source"], rows["keep_days"]["floor_env"]) == (
        30, "default", "KEEP_FLOOR")
    assert out["locked"] == []


# --------------------------------------------------------------------------- storing

def test_a_change_is_stored_with_its_audit_row_in_one_transaction(env, db):
    user = _admin(db)
    out = _put(db, user, "keep_days", 400)
    assert out["status"] == "applied"
    assert (out["setting"]["value"], out["setting"]["source"]) == (400, "admin")
    (row,) = _rows(db)
    assert (row.username, row.resource_type, row.resource_id, row.status) == ("alice", "setting", "keep_days",
                                                                             "success")
    assert row.details == {"key": "keep_days", "old": 30, "new": 400, "setting": 400}
    assert db.get(ManagedSetting, "keep_days").value == 400
    assert reg.resolve("keep_days") == 400


def test_going_back_to_the_deployments_value_records_the_value_that_comes_back(env, db):
    user = _admin(db)
    _put(db, user, "keep_days", 400)
    out = _put(db, user, "keep_days", None)
    assert (out["setting"]["value"], out["setting"]["source"]) == (30, "default")
    assert _rows(db)[-1].details == {"key": "keep_days", "old": 400, "new": 30, "setting": None}


def test_the_same_value_again_changes_nothing_and_writes_no_row(env, db):
    user = _admin(db)
    assert _put(db, user, "keep_days", None)["status"] == "unchanged"   # nothing stored, nothing to clear
    _put(db, user, "keep_days", 400)
    assert _put(db, user, "keep_days", 400)["status"] == "unchanged"
    assert len(_rows(db)) == 1
    _put(db, user, "keep_days", None)
    assert _put(db, user, "keep_days", None)["status"] == "unchanged"
    assert len(_rows(db)) == 2


@pytest.mark.parametrize("key,value,status,why", [
    ("nobody", 5, 404, "nobody is not a managed setting"),
    ("env_days", 6, 400, "env_days is set by the deployment, not in the panel"),
    ("keep_days", "40", 400, "keep_days must be a whole number"),
    ("keep_days", 99999, 400, "keep_days must be at most 3650"),
    ("keep_days", 5, 400, "keep_days cannot be 5: the deployment keeps it at least 7 (KEEP_FLOOR in .env)"),
])
def test_what_the_panel_may_not_set_is_refused_and_nothing_is_written(env, db, key, value, status, why):
    user = _admin(db)
    with refused(status) as caught:
        _put(db, user, key, value)
    assert caught.value.detail == why
    assert db.query(ManagedSetting).count() == 0 and _rows(db) == []


def test_a_locked_setting_is_refused_with_the_line_that_locks_it(env, db):
    env.settings_locked_keys = "keeping"
    user = _admin(db)
    with refused(400) as caught:
        _put(db, user, "keep_days", 400)
    assert caught.value.detail == "keep_days is locked by the deployment (SETTINGS_LOCKED_KEYS)"


def test_no_limit_is_refused_under_a_ceiling(env, db):
    env.keep_ceiling = 365
    user = _admin(db)
    with refused(400) as caught:
        _put(db, user, "keep_days", 0)
    assert caught.value.detail == ("keep_days cannot be no limit: the deployment allows at most 365 "
                                   "(KEEP_CEILING in .env)")


def test_a_change_whose_audit_row_cannot_be_built_is_not_made(env, db, monkeypatch):
    from app.services.audit_logger import AuditLogger

    def broken(*_a, **_k):
        raise RuntimeError("no row")

    monkeypatch.setattr(AuditLogger, "build_row", broken)
    user = _admin(db)
    with refused(503) as caught:
        _put(db, user, "keep_days", 400)
    assert "Nothing was changed" in caught.value.detail
    assert db.query(ManagedSetting).count() == 0


def test_a_change_whose_audit_row_cannot_be_written_is_not_made(env, db):
    user = _admin(db)
    AuditLog.__table__.drop(db.get_bind())
    with refused(503):
        _put(db, user, "keep_days", 400)
    db.rollback()
    assert db.query(ManagedSetting).count() == 0
    assert reg.resolve("keep_days") == 30


def test_the_action_is_catalogued():
    from app.core import audit_catalog
    entry = audit_catalog.lookup("setting_changed")
    assert entry is not None and entry.category == "administration"
