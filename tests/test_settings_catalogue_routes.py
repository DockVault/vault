"""The Settings pages' catalogue routes (app/api/settings_catalogue_router.py), offline.

GET /settings/catalogue and POST /settings/catalogue/seen are plain functions for interactive administrators
only. The release at which an administrator last opened the Settings pages is kept with their preferences
(user_preferences, settings_seen), with their other preferences left as they were, and counts for "New";
one that cannot be read counts as never, a running release that cannot be read is never kept, and
PUT /users/me/preferences can neither set it nor drop it. These run on a throwaway SQLite database.
"""
import inspect
import tempfile
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.api import settings_catalogue_router as routes  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402
from app.core.models import RoleEnum, User, UserPreference  # noqa: E402

pytestmark = pytest.mark.unit


def _app_routes():
    from fastapi.routing import APIRoute, _IncludedRouter

    def walk(found, prefix):
        for r in found:
            if isinstance(r, _IncludedRouter):
                yield from walk(r.original_router.routes, prefix + r.include_context.prefix)
            elif isinstance(r, APIRoute):
                yield prefix + r.path, r

    return {(m, path): route for path, route in walk(api.app.router.routes, "") if path.startswith("/settings/catalogue")
            for m in route.methods}


def test_the_routes_are_plain_functions_for_interactive_administrators():
    from app.api import user_management_api as um
    found = _app_routes()
    assert set(found) == {("GET", "/settings/catalogue"), ("POST", "/settings/catalogue/seen")}
    for route in found.values():
        assert not inspect.iscoroutinefunction(route.endpoint), route.path
        assert um.require_interactive_admin in {d.call for d in route.dependant.dependencies}, route.path


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'prefs.db'}")
        for model in (User, UserPreference):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


def _admin(db, name="alice"):
    user = User(id=uuid.uuid4(), username=name, email=f"{name}@example.com", password_hash="x",
                role=RoleEnum.ADMIN, is_active=True)
    db.add(user)
    db.commit()
    return user


def test_the_release_last_opened_at_is_kept_and_counts_for_new(db, monkeypatch):
    monkeypatch.setattr(routes, "running_version", lambda: "0.34.0")
    alice, bob = _admin(db), _admin(db, "bob")
    db.add(UserPreference(user_id=alice.id, preferences={"ui": "v1", "settings_seen": "0.29.0"}))
    db.commit()
    first = routes.get_settings_catalogue(current_user=alice, db=db)
    assert (first["version"], first["seen"]) == ("0.34.0", "0.29.0")
    new = {r["key"] for r in first["entries"] if r["new"]}
    assert "rate_limit_device_sync_attempts" in new                 # arrived in 0.30.0, after 0.29.0
    assert "max_vaults_per_user" not in new                         # 0.24.0
    assert routes.mark_settings_seen(current_user=alice, db=db) == {"seen": "0.34.0"}
    db.expire_all()
    stored = db.query(UserPreference).filter(UserPreference.user_id == alice.id).one().preferences
    assert stored == {"ui": "v1", "settings_seen": "0.34.0"}         # the other preferences are kept
    again = routes.get_settings_catalogue(current_user=alice, db=db)
    assert again["seen"] == "0.34.0"
    assert {r["key"] for r in again["entries"] if r["new"]} == {
        r["key"] for r in again["entries"] if reg.is_new(r["since"], "0.34.0")}
    assert "rate_limit_device_sync_attempts" not in {r["key"] for r in again["entries"] if r["new"]}
    # Another administrator has never opened them: no row yet, and one is made.
    assert routes.get_settings_catalogue(current_user=bob, db=db)["seen"] is None
    routes.mark_settings_seen(current_user=bob, db=db)
    assert routes.get_settings_catalogue(current_user=bob, db=db)["seen"] == "0.34.0"


@pytest.mark.parametrize("stored", ["0.31", "garbage", "", 31, None, "0.31.0<b>"])
def test_a_stored_release_that_cannot_be_read_counts_as_never(db, monkeypatch, stored):
    monkeypatch.setattr(routes, "running_version", lambda: "0.34.0")
    alice = _admin(db)
    db.add(UserPreference(user_id=alice.id, preferences={"settings_seen": stored}))
    db.commit()
    assert routes.get_settings_catalogue(current_user=alice, db=db)["seen"] is None


def test_a_running_release_that_cannot_be_read_is_never_kept(db, monkeypatch):
    monkeypatch.setattr(routes, "running_version", lambda: "")
    alice = _admin(db)
    assert routes.mark_settings_seen(current_user=alice, db=db) == {"seen": None}
    assert db.query(UserPreference).count() == 0


def test_the_preferences_keep_the_release_and_put_cannot_set_it():
    clean = api._sanitize_preferences({"settings_seen": "0.34.0", "ui": "v2"})
    assert clean == {"settings_seen": "0.34.0", "ui": "v2"}
    for bad in ("0.34", "0.34.0 ", "0.34.0<script>", "v0.34.0", 34, ["0.34.0"], None):
        assert "settings_seen" not in api._sanitize_preferences({"settings_seen": bad}), bad
    assert "settings_seen" not in api.PreferencesUpdate.model_fields
    assert api.PreferencesUpdate(**{"settings_seen": "0.1.0"}).model_dump(exclude_none=True) == {}
