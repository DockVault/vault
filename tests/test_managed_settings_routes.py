"""The managed-settings routes (app/api/managed_settings_router.py), offline.

GET /settings/managed describes every managed setting from the process's copy, with the changes waiting;
PUT /settings/managed/{key} asks for the fixed step-up, then changes the setting (at once, or after the delay
when it deletes data sooner, app/core/setting_changes.py) with its audit row in one transaction, and refuses
what the panel may not set: a setting only .env sets, a locked one, a value of the wrong kind, and one
outside the deployment's floor and ceiling, naming the .env line. POST .../changes/{id}/cancel cancels a
waiting change. The routes are plain functions (the thread pool runs them), mounted on the app, and reached
only by an interactive administrator. These run on a throwaway SQLite database, with a throwaway setting.
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
from app.core import setting_changes as sc  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402
from app.core.models import (AuditLog, AuditSeal, ManagedSetting, ManagedSettingChange, RoleEnum,  # noqa: E402
                             SystemSetting, User)
from _audit_chain_env import Chain  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch):
    """Deployment settings the test controls, no stored values, and only the test's own settings."""
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    settings = SimpleNamespace(settings_locked_keys="", keep_days=30, keep_floor=7, keep_ceiling=None,
                               retention_reduction_delay_days=7)
    monkeypatch.setattr(reg, "_deployment_settings", lambda: settings)
    reg.all_specs()
    saved = [(table, dict(table)) for table in (reg._SPECS, reg._LISTED, reg._LOCK_GROUPS)]
    delay = reg._SPECS[sc.DELAY_KEY]
    for table, _ in saved:
        table.clear()
    reg.register(delay)
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
        for model in (User, ManagedSetting, ManagedSettingChange, AuditLog, AuditSeal, SystemSetting):
            model.__table__.create(engine)
        factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        monkeypatch.setattr(reg, "_default_session_factory", factory)
        session = factory()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def chain(request, monkeypatch, tmp_path):
    """The audit log's integrity chain, started on the test's database: every change writes its seal there."""
    if "db" not in request.fixturenames:
        yield None
        return
    from datetime import datetime, timezone
    settings = request.getfixturevalue("env")
    request.getfixturevalue("db")
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    c = Chain(monkeypatch, tmp_path, settings, reg._default_session_factory, now)
    c.seal_all()
    yield c


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    """The step-up passes, and what would be announced to the administrators is recorded instead."""
    seen = {"step_up": [], "announced": []}
    monkeypatch.setattr(routes, "_step_up", lambda db, user, request: seen["step_up"].append(user.username))
    monkeypatch.setattr(sc, "announce", lambda event, details, by=None: seen["announced"].append(
        (event, details.get("key"), details.get("old"), details.get("new"), by)))
    return seen


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
    assert {("GET", "/settings/managed"), ("PUT", "/settings/managed/{key}"),
            ("POST", "/settings/managed/changes/{change_id}/cancel"),
            ("GET", "/settings/managed/audit/preview")} <= set(found)
    for route in found.values():
        assert not inspect.iscoroutinefunction(route.endpoint), route.path


def test_only_an_interactive_administrator_reaches_them():
    from app.api import user_management_api as um
    found = _managed_routes()
    assert len(found) == 4
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
    for fn in (routes.get_managed_settings, routes.put_managed_setting, routes.cancel_managed_setting_change):
        source = inspect.getsource(fn)
        body = source.split('"""', 2)[2]
        assert body.lstrip().startswith("limit_statements(db)"), fn.__name__
    # The step-up may commit (it uses its receipt once), which ends the bound: it is set again after it.
    put = inspect.getsource(routes.put_managed_setting)
    after = put.split("_step_up(db, current_user, request)", 1)[1]
    assert after.splitlines()[1].strip() == "limit_statements(db)"


def test_changing_a_value_asks_for_the_fixed_step_up_the_matrix_never_weakens():
    from app.core import fixed_step_up
    from app.core import second_factor_actions as acts
    from app.core import second_factor_policy as pol
    assert acts.FIXED_STEP_UP_ACTIONS[routes.STEP_UP_ACTION] == ("Change how long records are kept",
                                                                 pol.POLICY_PASSWORD_ALWAYS)
    assert routes.STEP_UP_ACTION == "admin.retention.write"
    assert routes.STEP_UP_ACTION not in acts.ACTION_KEYS
    assert routes.STEP_UP_ACTION in fixed_step_up.GUARDED
    assert fixed_step_up.contract_problems() == []


def test_a_refused_step_up_changes_nothing(env, db, monkeypatch):
    def refuse(db_, user, request):
        raise HTTPException(status_code=403, detail={"second_factor_required": True})

    monkeypatch.setattr(routes, "_step_up", refuse)
    user = _admin(db)
    for value in (400, 10):
        with refused(403):
            _put(db, user, "keep_days", value)
    assert db.query(ManagedSetting).count() == 0 and db.query(ManagedSettingChange).count() == 0
    assert db.query(AuditLog).count() == 0


def test_a_refusal_comes_before_the_step_up(env, db, quiet):
    user = _admin(db)
    with refused(404):
        _put(db, user, "nobody", 5)
    with refused(400):
        _put(db, user, "keep_days", "40")
    assert quiet["step_up"] == []
    _put(db, user, "keep_days", 400)
    assert quiet["step_up"] == ["alice"]


# --------------------------------------------------------------------------- reading

def test_get_describes_every_managed_setting_and_the_changes_waiting(env, db):
    user = _admin(db)
    out = routes.get_managed_settings(current_user=user, db=db)
    rows = {r["key"]: r for r in out["settings"]}
    assert set(rows) == {"keep_days", "env_days", sc.DELAY_KEY}
    assert (rows["keep_days"]["value"], rows["keep_days"]["source"], rows["keep_days"]["floor_env"]) == (
        30, "default", "KEEP_FLOOR")
    assert (out["locked"], out["pending"], out["reduction_delay_days"]) == ([], [], 7)
    _put(db, user, "keep_days", 10)
    (waiting,) = routes.get_managed_settings(current_user=user, db=db)["pending"]
    assert (waiting["key"], waiting["label"], waiting["old"], waiting["new"], waiting["status"],
            waiting["requested_by"]) == ("keep_days", "Keep for", 30, 10, "pending", "alice")
    assert waiting["effective_at"].endswith("Z")


# --------------------------------------------------------------------------- changing

def test_a_change_that_keeps_data_longer_applies_at_once_with_its_row(env, db, quiet):
    user = _admin(db)
    out = _put(db, user, "keep_days", 400)
    assert (out["status"], out["change"]) == ("applied", None)
    assert (out["setting"]["value"], out["setting"]["source"]) == (400, "admin")
    (row,) = _rows(db)
    assert (row.username, row.resource_type, row.resource_id, row.status) == ("alice", "setting", "keep_days",
                                                                             "success")
    assert row.details == {"key": "keep_days", "old": 30, "new": 400, "setting": 400, "superseded": []}
    assert db.get(ManagedSetting, "keep_days").value == 400
    assert reg.resolve("keep_days") == 400
    assert quiet["announced"] == [(sc.CHANGED_AT_ONCE, "keep_days", 30, 400, "alice")]


def test_a_change_that_deletes_sooner_waits_and_is_announced(env, db, quiet):
    user = _admin(db)
    out = _put(db, user, "keep_days", 10)
    assert out["status"] == "pending" and out["setting"]["value"] == 30
    assert (out["change"]["new"], out["change"]["status"]) == (10, "pending")
    assert db.query(ManagedSetting).count() == 0
    assert quiet["announced"] == [(sc.ASKED, "keep_days", 30, 10, "alice")]


def test_going_back_to_the_deployments_value_waits_when_it_deletes_sooner(env, db):
    user = _admin(db)
    _put(db, user, "keep_days", 400)
    out = _put(db, user, "keep_days", None)
    assert (out["status"], out["change"]["setting"], out["change"]["new"]) == ("pending", None, 30)


def test_the_same_value_again_changes_nothing_and_writes_no_row(env, db, quiet):
    user = _admin(db)
    assert _put(db, user, "keep_days", None)["status"] == "unchanged"   # nothing stored, nothing to clear
    _put(db, user, "keep_days", 400)
    assert _put(db, user, "keep_days", 400)["status"] == "unchanged"
    assert len(_rows(db)) == 1 and len(quiet["announced"]) == 1


@pytest.mark.parametrize("key,value,status,why", [
    ("nobody", 5, 404, "nobody is not a managed setting"),
    ("env_days", 6, 400, "env_days is set by the deployment, not in the panel"),
    ("env_days", 1, 400, "env_days is set by the deployment, not in the panel"),
    ("keep_days", "40", 400, "keep_days must be a whole number"),
    ("keep_days", 99999, 400, "keep_days must be at most 3650"),
    ("keep_days", 5, 400, "keep_days cannot be 5: the deployment keeps it at least 7 (KEEP_FLOOR in .env)"),
])
def test_what_the_panel_may_not_set_is_refused_and_nothing_is_written(env, db, key, value, status, why):
    reg._SPECS["env_days"] = reg.SettingSpec(key="env_days", kind="int", default=5, editable=reg.ENV_ONLY,
                                             reduction=reg.LOWER)
    user = _admin(db)
    with refused(status) as caught:
        _put(db, user, key, value)
    assert caught.value.detail == why
    assert db.query(ManagedSetting).count() == 0 and _rows(db) == []
    assert db.query(ManagedSettingChange).count() == 0


def test_a_locked_setting_is_refused_with_the_line_that_locks_it(env, db):
    env.settings_locked_keys = "keeping"
    user = _admin(db)
    for value in (400, 10):
        with refused(400) as caught:
            _put(db, user, "keep_days", value)
        assert caught.value.detail == "keep_days is locked by the deployment (SETTINGS_LOCKED_KEYS)"
    assert db.query(ManagedSettingChange).count() == 0


def test_no_limit_is_refused_under_a_ceiling(env, db):
    env.keep_ceiling = 365
    user = _admin(db)
    with refused(400) as caught:
        _put(db, user, "keep_days", 0)
    assert caught.value.detail == ("keep_days cannot be no limit: the deployment allows at most 365 "
                                   "(KEEP_CEILING in .env)")


def test_a_check_across_settings_refuses_before_anything_is_asked(env, db, monkeypatch, quiet):
    monkeypatch.setattr(sc, "CROSS_CHECKS", [lambda spec, value: "too short for the minimum"
                                                 if value == 8 else None])
    user = _admin(db)
    with refused(400) as caught:
        _put(db, user, "keep_days", 8)
    assert caught.value.detail == "too short for the minimum" and quiet["step_up"] == []
    assert _put(db, user, "keep_days", 9)["status"] == "pending"


def test_a_change_whose_audit_row_cannot_be_built_is_not_made(env, db, monkeypatch, quiet):
    from app.services.audit_logger import AuditLogger

    def broken(*_a, **_k):
        raise RuntimeError("no row")

    monkeypatch.setattr(AuditLogger, "build_row", broken)
    user = _admin(db)
    for value in (400, 10):
        with refused(503) as caught:
            _put(db, user, "keep_days", value)
        assert "Nothing was changed" in caught.value.detail
    assert db.query(ManagedSetting).count() == 0 and db.query(ManagedSettingChange).count() == 0
    assert quiet["announced"] == []


def test_a_change_whose_audit_row_cannot_be_written_is_not_made(env, db):
    user = _admin(db)
    AuditLog.__table__.drop(db.get_bind())
    for value in (400, 10):
        with refused(503):
            _put(db, user, "keep_days", value)
        db.rollback()
    assert db.query(ManagedSetting).count() == 0 and db.query(ManagedSettingChange).count() == 0
    assert reg.resolve("keep_days") == 30


# --------------------------------------------------------------------------- cancelling

def test_any_administrator_cancels_a_waiting_change(env, db, quiet):
    alice, bob = _admin(db), _admin(db, "bob")
    change_id = _put(db, alice, "keep_days", 10)["change"]["id"]
    out = routes.cancel_managed_setting_change(uuid.UUID(change_id), current_user=bob, db=db)
    assert (out["status"], out["change"]["status"], out["change"]["decided_by"]) == (
        "cancelled", "cancelled", "bob")
    assert quiet["announced"][-1] == (sc.CANCELLED_BY_ADMIN, "keep_days", 30, 10, "bob")
    (row,) = db.query(AuditLog).filter(AuditLog.action == sc.CANCELLED_ACTION).all()
    assert row.username == "bob"
    with refused(409) as caught:
        routes.cancel_managed_setting_change(uuid.UUID(change_id), current_user=bob, db=db)
    assert caught.value.detail == "This change is no longer waiting: it was cancelled."
    with refused(404):
        routes.cancel_managed_setting_change(uuid.uuid4(), current_user=bob, db=db)


def test_a_cancel_whose_audit_row_cannot_be_written_leaves_the_change_waiting(env, db, monkeypatch, quiet):
    alice = _admin(db)
    change_id = _put(db, alice, "keep_days", 10)["change"]["id"]
    from app.services.audit_logger import AuditLogger

    def broken(*_a, **_k):
        raise RuntimeError("no row")

    monkeypatch.setattr(AuditLogger, "build_row", broken)
    with refused(503) as caught:
        routes.cancel_managed_setting_change(uuid.UUID(change_id), current_user=alice, db=db)
    assert "still waiting" in caught.value.detail
    assert db.get(ManagedSettingChange, uuid.UUID(change_id)).status == sc.PENDING
    assert len(quiet["announced"]) == 1


def test_while_sealing_is_stopped_a_reduction_is_refused_and_a_longer_value_is_saved(env, db, chain):
    from app.core.models import AuditSeal
    db.query(AuditSeal).filter(AuditSeal.seq == db.query(sa.func.max(AuditSeal.seq)).scalar()).delete()
    db.commit()
    from app.core import audit_integrity
    chain.st.view.reset()
    user = _admin(db)
    with pytest.raises(HTTPException) as refused:
        routes.put_managed_setting("keep_days", routes.ManagedValue(value=10), request=None, current_user=user, db=db)
    assert refused.value.status_code == 409 and "not sealing" in refused.value.detail
    out = routes.put_managed_setting("keep_days", routes.ManagedValue(value=400), request=None, current_user=user,
                                     db=db)
    assert out["status"] == "applied"
    assert audit_integrity
