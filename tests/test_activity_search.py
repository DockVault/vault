"""Activity searches with what was typed in the body, and typed names matched against their fingerprints, offline.

POST /activity/events/search, /activity/summary/search and /activity/export take the same filters, with the same
bounds, as their GET forms and run the same handler, so a name, an address or free text typed into a filter
reaches no request line. A typed name matches rows that recorded it in full or as its fingerprint; a fingerprint
(as a saved search keeps one) matches only those. A saved search keeps a name the log holds in full (an account's)
as typed, and any other typed name as the levels keep it: its fingerprint, or, while none are recorded, not at all.
The page posts any read whose filters hold typed text.
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
    return {n: p for n, p in inspect.signature(fn).parameters.items() if n not in ("current_user", "db", "request")}


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
    if "request" in inspect.signature(getattr(api, handler)).parameters:
        expected.add("request")
    seen = {}
    monkeypatch.setattr(api, handler, lambda **kw: seen.update(kw) or "answer")
    call = getattr(routes, route)
    extra = {"request": "the request"} if "request" in inspect.signature(call).parameters else {}
    assert call(body, current_user="admin", db="db", **extra) == "answer"
    if extra:
        assert seen["request"] == "the request"
    assert set(seen) == expected
    assert seen["user"] == "eve" and seen["current_user"] == "admin" and seen["db"] == "db"
    for name, value in body.model_dump().items():
        assert seen["range_" if name == "range" else name] == value


def test_the_routes_are_plain_functions_an_administrator_or_a_live_auditor_reaches():
    from fastapi.routing import APIRoute, _IncludedRouter
    from app.api import activity_viewer as av

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
        assert av.require_activity_viewer in {d.call for d in route.dependant.dependencies}


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

def _account(factory, name):
    db = factory()
    user = User(username=name, email=f"{name}@example.test", password_hash="x")
    db.add(user)
    db.commit()
    uid = user.id
    db.close()
    return uid


def _account_row(factory, uid, action):
    ap.use(ap.Policy(9, {**ap.POLICY_ONE, "signin_names": "fingerprint"}))
    db = factory()
    AuditLogger(db).log_action(action=action, status="success", user_id=uid)
    db.close()


def _saved(factory, filters, level):
    """The filters a saved search keeps, saved through the routes' check, while typed names are at ``level``."""
    ap.use(ap.Policy(9, {**ap.POLICY_ONE, "signin_names": level}))
    db = factory()
    try:
        return saved.clean_filters(filters, saved.held_in_full(db))
    finally:
        db.close()


def _replay(factory, filters):
    return _found(factory, username=filters["user"], user_exact=filters.get("user_match") == "exact")


@pytest.mark.parametrize("value,match", [("ada.lovelace", "exact"), ("Ada.Lovelace", "exact"), ("lovelace", "contains")])
def test_at_the_fingerprint_level_a_saved_search_keeps_an_accounts_name_and_finds_its_events(factory, value, match):
    ada = _account(factory, "ada.lovelace")
    _account_row(factory, ada, "ada_signed_in")
    _write(factory, "eve.smith", "fingerprint", "typed_fp")
    filters = {"user": value, "user_match": match}
    assert _replay(factory, filters) == ["ada_signed_in"]
    kept = _saved(factory, filters, "fingerprint")
    assert kept == filters
    assert _replay(factory, kept) == ["ada_signed_in"]


def test_an_account_with_no_events_yet_is_kept_by_name(factory):
    _account(factory, "grace.hopper")
    assert _saved(factory, {"user": "grace.hopper"}, "fingerprint") == {"user": "grace.hopper"}


def test_at_the_fingerprint_level_a_typed_name_is_kept_as_its_fingerprint_and_finds_the_same_rows(factory):
    _account(factory, "ada.lovelace")
    _write(factory, "eve.smith", "fingerprint", "typed_fp")
    _write(factory, "bob", "fingerprint", "other_fp")
    kept = _saved(factory, {"user": " eve.smith ", "user_match": "exact", "q": "upload", "ip": "192.0.2.1"},
                  "fingerprint")
    assert kept == {"user": fp.fingerprint(fp.SIGNIN, "eve.smith"), "user_match": "exact", "q": "upload",
                    "ip": "192.0.2.1"}
    assert _replay(factory, kept) == _found(factory, username="eve.smith", user_exact=True) == ["typed_fp"]
    assert _saved(factory, {"user": kept["user"]}, "fingerprint") == {"user": kept["user"]}


def test_a_name_the_log_holds_in_full_is_kept_as_typed(factory):
    _write(factory, "eve.smith", "full", "kept_full")          # recorded in full under earlier levels
    _write(factory, "eve.smith", "fingerprint", "kept_fp")
    kept = _saved(factory, {"user": "eve.smith", "user_match": "exact"}, "fingerprint")
    assert kept["user"] == "eve.smith"
    assert _replay(factory, kept) == ["kept_fp", "kept_full"]


def test_the_check_matches_a_name_as_the_search_does(factory):
    _write(factory, "eve.smith", "full", "kept_full")
    _account(factory, "ada.lovelace")
    db = factory()
    try:
        check = saved.held_in_full(db)
        assert check("EVE.SMITH", True) and check("smith", False) and check("LOVE", False)
        assert check("ada.lovelace", True) and not check("ada", True) and not check("smith", True)
        assert not check("eve_smith", False) and not check("eve%", False)      # wildcards are plain text
    finally:
        db.close()


def test_an_exact_filter_that_is_only_part_of_a_name_held_in_full_is_a_typed_name(factory):
    # "lovelace" is part of an account's name, so a contains search for it is kept as typed; as an exact filter
    # it names nobody the log holds, so the levels decide.
    _account(factory, "ada.lovelace")
    assert _saved(factory, {"user": "lovelace"}, "fingerprint") == {"user": "lovelace"}
    kept = _saved(factory, {"user": "lovelace", "user_match": "exact"}, "fingerprint")
    assert kept == {"user": fp.fingerprint(fp.SIGNIN, "lovelace"), "user_match": "exact"}
    with pytest.raises(saved.InvalidSearch):
        _saved(factory, {"user": "lovelace", "user_match": "exact"}, "none")


def test_while_the_levels_cannot_be_read_a_typed_name_is_kept_as_its_fingerprint(factory, monkeypatch):
    def unreadable():
        raise ap.PolicyUnavailable("the policies table cannot be read")

    ap.use(ap.Policy(9, dict(ap.POLICY_ONE)))           # typed names in full, were the levels readable
    monkeypatch.setattr(ap, "current", unreadable)
    db = factory()
    try:
        kept = saved.clean_filters({"user": "eve.smith"}, saved.held_in_full(db))
    finally:
        db.close()
    assert kept == {"user": fp.fingerprint(fp.SIGNIN, "eve.smith")}


def test_while_no_typed_name_is_recorded_a_saved_search_cannot_hold_one(factory):
    _account(factory, "ada.lovelace")
    _write(factory, "eve.smith", "fingerprint", "kept_fp")
    with pytest.raises(saved.InvalidSearch, match="not recorded at the current recording levels"):
        _saved(factory, {"user": "typed.at.minimal"}, "none")
    with pytest.raises(saved.InvalidSearch):
        saved.clean_filters({"user": "typed.at.minimal"})
    assert _saved(factory, {"user": "ada.lovelace"}, "none") == {"user": "ada.lovelace"}
    value = fp.fingerprint(fp.SIGNIN, "eve.smith")
    assert _saved(factory, {"user": value}, "none") == {"user": value}
    assert _saved(factory, {"q": "typed.at.minimal"}, "none") == {"q": "typed.at.minimal"}   # free text: as typed


def test_at_the_full_level_a_typed_name_is_kept_as_typed_within_the_env_limit(factory, monkeypatch):
    assert _saved(factory, {"user": "eve.smith"}, "full") == {"user": "eve.smith"}
    monkeypatch.setattr(settings, "audit_max_signin_names", "fingerprint")
    assert _saved(factory, {"user": "eve.smith"}, "full") == {"user": fp.fingerprint(fp.SIGNIN, "eve.smith")}
    monkeypatch.setattr(settings, "audit_max_signin_names", "none")
    with pytest.raises(saved.InvalidSearch):
        _saved(factory, {"user": "eve.smith"}, "full")


def test_with_no_key_to_fingerprint_with_a_typed_name_is_refused_not_kept(factory, monkeypatch):
    monkeypatch.setattr(settings, "audit_fingerprint_key", "")
    monkeypatch.setattr(settings, "encryption_key", "")
    with pytest.raises(saved.InvalidSearch):
        _saved(factory, {"user": "eve.smith"}, "fingerprint")


def test_both_routes_that_store_filters_check_them_against_the_log():
    for handler in (api.create_saved_search, api.update_saved_search):
        source = inspect.getsource(handler)
        assert source.count("rules.clean_filters(body.filters, rules.held_in_full(db))") == 1, handler.__name__
        assert source.count("clean_filters(") == 1, handler.__name__


# --------------------------------------------------------------------------- the page

def test_the_page_posts_a_read_with_typed_filters_and_every_export():
    script = (ROOT / "static" / "js" / "activity.js").read_text(encoding="utf-8")
    assert "const TYPED_FILTERS = ['user', 'q', 'ip', 'temp_credential'];" in script
    assert "SEARCHES[base] && typedIn(params) ? await post(SEARCHES[base], params)" in script
    assert script.count("await post('/activity/export', p, ctl.signal)") == 1
    assert "/activity/export?" not in script
    assert "'/activity/events': '/activity/events/search'" in script
    assert "'/activity/summary': '/activity/summary/search'" in script
