"""Activity searches with what was typed in the body, and typed names matched against their fingerprints, offline.

POST /activity/events/search, /activity/summary/search and /activity/export take the same filters, with the same
bounds, as their GET forms and run the same handler, so a name, an address or free text typed into a filter
reaches no request line. A typed name matches rows that recorded it in full or as its fingerprint; a fingerprint
(as a saved search keeps one) matches only those. A saved search keeps a typed name as its fingerprint while names
typed at sign-in are recorded as fingerprints. The page posts any read whose filters hold typed text.
"""
import inspect
import tempfile
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import activity_search_router as routes  # noqa: E402
from app.api import api_server as api  # noqa: E402
from app.core import audit_fingerprints as fp  # noqa: E402
from app.core import audit_privacy as ap  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import AuditLog, User  # noqa: E402
from app.core.security import _runtime_settings  # noqa: E402
from app.services import activity_saved_searches as saved  # noqa: E402
from app.services.activity_events import build_events_query  # noqa: E402
from app.services.audit_logger import AuditLogger  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def env(monkeypatch):
    _runtime_settings()
    for key in ap.POLICY_KEYS:
        monkeypatch.setattr(settings, ap.env_field(key), "full")
    monkeypatch.setattr(settings, "settings_locked_keys", "")
    monkeypatch.setattr(settings, "audit_fingerprint_key", "k" * 64)
    yield


@pytest.fixture
def factory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'search.db'}")
        for model in (User, AuditLog):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine)
        engine.dispose()


# --------------------------------------------------------------------------- the routes

def _get_params(fn):
    return {n: p for n, p in inspect.signature(fn).parameters.items() if n not in ("current_user", "db")}


@pytest.mark.parametrize("model,handler", [
    (routes.EventsSearch, "activity_events"), (routes.SummarySearch, "activity_summary"),
    (routes.ExportSearch, "activity_export")])
def test_each_post_takes_the_get_forms_filters_with_the_same_bounds(model, handler):
    get = _get_params(getattr(api, handler))
    names = {("range_" if n == "range" else n) for n in model.model_fields}
    assert names == set(get), set(get) ^ names
    for name, field in model.model_fields.items():
        param = get["range_" if name == "range" else name]
        query = param.default
        for attr in ("max_length", "pattern"):
            want = next((getattr(m, attr) for m in getattr(query, "metadata", []) if hasattr(m, attr)), None)
            have = next((getattr(m, attr) for m in field.metadata if hasattr(m, attr)), None)
            if attr == "max_length" and want is None:
                continue
            assert have == want, (name, attr, have, want)


@pytest.mark.parametrize("route,handler,body", [
    ("search_events", "activity_events", routes.EventsSearch(user="eve", ip="192.0.2.1", q="x", limit=10)),
    ("search_summary", "activity_summary", routes.SummarySearch(user="eve", range="7d")),
    ("search_events", "activity_events", routes.EventsSearch(category=["sign_in"], user_match="exact", user="eve")),
    ("export_events", "activity_export", routes.ExportSearch(user="eve", format="ndjson"))])
def test_each_post_runs_its_get_forms_handler_with_every_filter(monkeypatch, route, handler, body):
    expected = set(_get_params(getattr(api, handler))) | {"current_user", "db"}
    seen = {}
    monkeypatch.setattr(api, handler, lambda **kw: seen.update(kw) or "answer")
    assert getattr(routes, route)(body, current_user="admin", db="db") == "answer"
    assert set(seen) == expected
    assert seen["user"] == "eve" and seen["current_user"] == "admin" and seen["db"] == "db"
    for name, value in body.model_dump().items():
        assert seen["range_" if name == "range" else name] == value


def test_the_routes_are_plain_functions_only_an_interactive_administrator_reaches():
    from fastapi.routing import APIRoute, _IncludedRouter
    from app.api import user_management_api as um

    def walk(found, prefix):
        for r in found:
            if isinstance(r, _IncludedRouter):
                yield from walk(r.original_router.routes, prefix + r.include_context.prefix)
            elif isinstance(r, APIRoute):
                yield prefix + r.path, r

    found = {(m, p): r for p, r in walk(api.app.router.routes, "") for m in r.methods
             if (m, p) in {("POST", "/activity/events/search"), ("POST", "/activity/summary/search"),
                           ("POST", "/activity/export")}}
    assert len(found) == 3
    for route in found.values():
        assert not inspect.iscoroutinefunction(route.endpoint)
        assert um.require_interactive_admin in {d.call for d in route.dependant.dependencies}


# --------------------------------------------------------------------------- matching a fingerprint

def _write(factory, name, level, action):
    ap.use(ap.Policy(9, {**ap.POLICY_ONE, "signin_names": level}))
    db = factory()
    AuditLogger(db).log_action(action=action, status="failure", username=name)
    db.close()


def _found(factory, **filters):
    db = factory()
    try:
        return sorted(r.action for r in build_events_query(db.query(AuditLog), AuditLog, **filters).all())
    finally:
        db.close()


def test_a_typed_name_finds_the_rows_that_kept_it_in_full_or_as_its_fingerprint(factory):
    _write(factory, "eve.smith", "full", "kept_full")
    _write(factory, "eve.smith", "fingerprint", "kept_fp")
    _write(factory, "bob", "fingerprint", "other_fp")
    assert _found(factory, username="eve.smith", user_exact=True) == ["kept_fp", "kept_full"]
    assert _found(factory, username="eve.smith") == ["kept_fp", "kept_full"]
    assert _found(factory, username="eve") == ["kept_full"]            # a fingerprint matches whole names only
    assert _found(factory, text="eve.smith") == ["kept_fp", "kept_full"]
    assert _found(factory, username="Eve.Smith", user_exact=True) == ["kept_full"]


def test_a_fingerprint_finds_only_the_rows_that_kept_that_fingerprint(factory):
    _write(factory, "eve.smith", "full", "kept_full")
    _write(factory, "eve.smith", "fingerprint", "kept_fp")
    value = fp.fingerprint(fp.SIGNIN, "eve.smith")
    assert _found(factory, username=value) == ["kept_fp"]
    assert _found(factory, username=value, user_exact=True) == ["kept_fp"]


def test_rows_under_no_account_include_a_fingerprinted_name(factory):
    _write(factory, "eve.smith", "fingerprint", "kept_fp")
    _write(factory, "eve.smith", "full", "kept_full")
    _write(factory, "gone", "none", "not_recorded")
    assert _found(factory, no_account=True) == ["kept_fp", "kept_full"]


# --------------------------------------------------------------------------- saved searches

def test_a_saved_search_keeps_a_typed_name_as_its_fingerprint_while_names_are(monkeypatch):
    ap.use(ap.Policy(9, {**ap.POLICY_ONE, "signin_names": "fingerprint"}))
    out = saved.clean_filters({"user": " eve.smith ", "q": "upload", "ip": "192.0.2.1"})
    assert out["user"] == fp.fingerprint(fp.SIGNIN, "eve.smith")
    assert out["q"] == "upload" and out["ip"] == "192.0.2.1"
    assert saved.clean_filters({"user": out["user"]})["user"] == out["user"]
    ap.use(ap.Policy(10, dict(ap.POLICY_ONE)))
    assert saved.clean_filters({"user": "eve.smith"})["user"] == "eve.smith"
    monkeypatch.setattr(settings, "audit_max_signin_names", "fingerprint")
    assert saved.clean_filters({"user": "eve.smith"})["user"] == fp.fingerprint(fp.SIGNIN, "eve.smith")


# --------------------------------------------------------------------------- the page

def test_the_page_posts_a_read_with_typed_filters_and_every_export():
    script = (ROOT / "static" / "js" / "activity.js").read_text(encoding="utf-8")
    assert "const TYPED_FILTERS = ['user', 'q', 'ip', 'temp_credential'];" in script
    assert "SEARCHES[base] && typedIn(params) ? await post(SEARCHES[base], params)" in script
    assert script.count("await post('/activity/export', p)") == 1
    assert "/activity/export?" not in script
    assert "'/activity/events': '/activity/events/search'" in script
    assert "'/activity/summary': '/activity/summary/search'" in script
