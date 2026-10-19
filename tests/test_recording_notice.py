"""The notice of what this vault records, offline (app/core/recording_notice.py, app/api/recording_notice_router.py).

The public notice states the levels in force and nothing of earlier versions, how long each store keeps data
(every table with an address column is listed, or the test says which is not and why), who can see it, and the
legal basis and contact the operator states. It is computed at most once a minute. A new version notifies every
active user once and shows a banner until they say they have read it, which records reading it with an audit row.
The page has nothing inline and is linked from the sign-in, invitation and link pages and the account menu.
"""
import inspect
import re
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.api import recording_notice_router as routes  # noqa: E402
from app.core import audit_privacy as ap  # noqa: E402
from app.core import recording_notice as rn  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import (AuditLog, AuditPrivacyPolicy, Base, Notification, RoleEnum,  # noqa: E402
                             SystemSetting, User)

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def env(monkeypatch):
    for key in ap.POLICY_KEYS:
        monkeypatch.setattr(settings, ap.env_field(key), "full")
    monkeypatch.setattr(settings, "settings_locked_keys", "")
    rn.forget_notice()
    yield
    rn.forget_notice()


@pytest.fixture
def factory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'notice.db'}")
        for model in (User, AuditLog, AuditPrivacyPolicy, Notification, SystemSetting):
            model.__table__.create(engine)
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


def _user(db, name, active=True, role=RoleEnum.USER):
    u = User(id=uuid.uuid4(), username=name, email=f"{name}@example.com", password_hash="x", role=role,
             is_active=active)
    db.add(u)
    db.commit()
    return u


# --------------------------------------------------------------------------- the public notice

def test_the_notice_states_the_levels_in_force_and_no_earlier_version(factory, monkeypatch):
    monkeypatch.setattr(settings, "audit_max_ip", "shortened")
    ap.use(ap.Policy(4, {**ap.POLICY_ONE, "names": "fingerprint"}))
    db = factory()
    out = rn.build_notice(db)
    levels = {item["key"]: item["level"] for item in out["levels"]}
    assert levels == {**ap.POLICY_ONE, "names": "fingerprint", "ip": "shortened"}
    assert out["version"] == 4
    assert "versions" not in out and "history" not in out
    assert "fingerprint" in out["fingerprints"] and "guesses" in out["fingerprints"]
    assert "Any administrator can also test a guess of a name typed at a failed sign-in" in out["fingerprints"]
    assert all(set(item) == {"key", "label", "level", "words"} for item in out["levels"])
    ap.use(ap.Policy(5, dict(ap.POLICY_ONE)))
    assert rn.build_notice(db)["fingerprints"] is None


def test_the_notice_states_the_operators_legal_basis_and_contact(factory, monkeypatch):
    db = factory()
    monkeypatch.setattr(rn, "_contact_fallback", lambda db: "support@example.com")
    out = rn.build_notice(db)
    assert out["legal_basis"] is None and out["contact"] == "support@example.com"
    db.add(SystemSetting(key="global", value={"recording_notice_legal_basis": " Our legitimate interest ",
                                              "recording_notice_contact": "privacy@example.com"}))
    db.commit()
    out = rn.build_notice(db)
    assert out["legal_basis"] == "Our legitimate interest" and out["contact"] == "privacy@example.com"


def test_the_notice_is_computed_at_most_once_a_minute(monkeypatch):
    built = []
    monkeypatch.setattr(rn, "build_notice", lambda db: built.append(1) or {"n": len(built)})
    assert rn.notice(None, now=100.0) == {"n": 1}
    assert rn.notice(None, now=159.9) == {"n": 1}
    assert rn.notice(None, now=160.0) == {"n": 2}
    assert len(built) == 2


def test_the_general_request_limit_covers_the_public_notice():
    from app.core.rate_limiter import classify_api_rate_limit
    assert classify_api_rate_limit("GET", "/privacy/recording") == "default"
    assert classify_api_rate_limit("GET", "/recording") == "default"


def test_the_public_route_needs_no_sign_in_and_the_others_do():
    from fastapi.routing import APIRoute, _IncludedRouter

    def walk(found, prefix):
        for r in found:
            if isinstance(r, _IncludedRouter):
                yield from walk(r.original_router.routes, prefix + r.include_context.prefix)
            elif isinstance(r, APIRoute):
                yield prefix + r.path, r

    found = {(m, p): r for p, r in walk(api.app.router.routes, "") for m in r.methods
             if p in ("/recording", "/privacy/recording", "/privacy/recording/history",
                      "/privacy/recording/status", "/privacy/recording/seen")}
    assert len(found) == 5
    from app.api.user_management_api import get_current_user
    for (method, path), route in found.items():
        deps = {d.call for d in route.dependant.dependencies}
        assert (get_current_user in deps) == (path not in ("/recording", "/privacy/recording")), path
        assert not inspect.iscoroutinefunction(route.endpoint), path


# --------------------------------------------------------------------------- the stores

def test_every_table_with_an_address_column_is_a_listed_store_or_says_why_not():
    assert rn.unlisted_stores(Base.metadata) == []
    for store in rn.STORES:
        assert store.kept and store.what
    assert {"audit_logs", "security_records", "active_sessions", "backups", "container_output",
            "activity_saved_searches"} <= {s.key for s in rn.STORES}
    saved = next(s for s in rn.STORES if s.key == "activity_saved_searches")
    assert "typed at a failed sign-in" in saved.what and not saved.follows_levels


def test_a_new_table_with_an_address_is_caught_until_it_is_listed():
    meta = sa.MetaData()
    sa.Table("visits", meta, sa.Column("id", sa.Integer, primary_key=True), sa.Column("client_ip", sa.String))
    sa.Table("counts", meta, sa.Column("id", sa.Integer, primary_key=True), sa.Column("n", sa.Integer))
    assert rn.unlisted_stores(meta) == ["visits"]


def test_each_stores_lifetime_reads_the_configuration(monkeypatch):
    from app.core import settings_registry
    out = {s.key: s.kept() for s in rn.STORES}
    assert out["audit_logs"].startswith("Kept")
    assert "30 days" in out["security_records"] and "30 days" in out["active_sessions"]
    real = settings_registry.resolve
    monkeypatch.setattr(settings_registry, "resolve",
                        lambda key: 12 if key == "security_record_days" else real(key))
    assert "12 days" in next(s for s in rn.STORES if s.key == "security_records").kept()


def test_the_days_an_address_stays_in_full_say_an_archived_day_can_take_a_day_longer(monkeypatch):
    """With AUDIT_IP_FULL_DAYS, an address in a day the archive holds is shortened once the whole day is past the
    cutoff: the audit log's lifetime and the address level's words both say it can be up to a day later."""
    monkeypatch.setattr(rn, "_full_address_days", lambda: 0)
    assert "shortened" not in rn._audit_kept() and "shortened" not in rn._level_words(ap.IP, ap.FULL)
    monkeypatch.setattr(rn, "_full_address_days", lambda: 30)
    later = "in a day the archive holds, once the whole day is: up to a day later"
    assert f"shortened to the network it is in after 30 days ({later})." in rn._audit_kept()
    assert rn._level_words(ap.IP, ap.FULL).endswith(f", then shortened to the network it is in after 30 days ({later})")
    assert "after 30 days" not in rn._level_words(ap.IP, ap.SHORTENED)


# --------------------------------------------------------------------------- the banner, the notification

def test_the_banner_shows_a_version_the_user_has_not_read():
    assert rn.banner(SimpleNamespace(privacy_seen_version=None), 1)["show"] is False
    assert rn.banner(SimpleNamespace(privacy_seen_version=None), 2)["show"] is True
    assert rn.banner(SimpleNamespace(privacy_seen_version=2), 2)["show"] is False
    assert rn.banner(SimpleNamespace(privacy_seen_version=2), 3)["show"] is True


def test_a_new_version_notifies_every_active_user_once(factory):
    db = factory()
    ada, bob = _user(db, "ada"), _user(db, "bob")
    _user(db, "gone", active=False)
    nudged = []
    assert rn.announce(3, session_factory=factory, nudge=nudged.append) == 2
    assert rn.announce(3, session_factory=factory, nudge=nudged.append) == 0
    assert sorted(nudged) == sorted([str(ada.id), str(bob.id)])
    rows = factory().query(Notification).all()
    assert sorted((str(n.user_id), n.dedup_key) for n in rows) == sorted(
        (str(u.id), f"privacy:v3:{u.id}") for u in (ada, bob))
    assert all(n.type == "recording_levels_changed" and n.target == "#recording" for n in rows)
    assert rn.announce(4, session_factory=factory) == 2


def test_announcing_never_raises():
    def down():
        raise RuntimeError("no database")

    assert rn.announce(2, session_factory=down) == 0


def test_a_save_and_a_lowered_limit_at_the_start_announce(factory, monkeypatch):
    seen = []
    monkeypatch.setattr(rn, "announce", lambda version, **kw: seen.append(version))
    ap.prepare(factory)
    assert seen == []                                     # version 1 is no change
    monkeypatch.setattr(settings, "audit_max_ip", "none")
    ap.prepare(factory)
    assert seen == [2]
    from app.api import recording_levels_router
    source = inspect.getsource(recording_levels_router.put_recording_levels)
    assert source.index("db.commit()") < source.index("recording_notice.announce(saved.version, nudge=_nudge)")


def _seen(db, user, version):
    return routes.recording_seen(routes.Seen(version=version), current_user=user, db=db)


def test_marking_the_notice_read_records_it_with_an_audit_row(factory):
    ap.prepare(factory)
    db = factory()
    ada = _user(db, "ada")
    db.add(AuditPrivacyPolicy(version=2, reason="admin", **{**ap.POLICY_ONE, "ip": "none"}))
    db.commit()
    assert routes.recording_status(current_user=ada, db=db)["show"] is True
    for wrong in (3, 0):
        with pytest.raises(HTTPException) as caught:
            _seen(db, ada, wrong)
        assert caught.value.status_code == 400
    out = _seen(db, ada, 2)
    assert out["show"] is False
    db.expire_all()
    assert db.get(User, ada.id).privacy_seen_version == 2
    rows = db.query(AuditLog).filter(AuditLog.action == "privacy_notice_seen").all()
    assert len(rows) == 1 and rows[0].user_id == ada.id and rows[0].details == {"version": 2}
    _seen(db, ada, 2)
    _seen(db, ada, 1)
    assert db.query(AuditLog).filter(AuditLog.action == "privacy_notice_seen").count() == 1


def test_an_account_made_after_a_change_is_not_shown_it(factory):
    ap.prepare(factory)
    db = factory()
    ada = _user(db, "ada")
    db.add(AuditPrivacyPolicy(version=2, reason="admin", **dict(ap.POLICY_ONE)))
    db.commit()
    bob = _user(db, "bob")
    assert routes.known_at_creation(db, ada) == 1 and routes.known_at_creation(db, bob) == 2
    assert routes.recording_status(current_user=ada, db=db)["show"] is True
    assert routes.recording_status(current_user=bob, db=db)["show"] is False
    assert routes.recording_seen(routes.Seen(version=2), current_user=bob, db=db)["show"] is False
    assert db.query(AuditLog).filter(AuditLog.action == "privacy_notice_seen").count() == 0
    db.add(AuditPrivacyPolicy(version=3, reason="admin", **dict(ap.POLICY_ONE)))
    db.commit()
    assert routes.recording_status(current_user=bob, db=db)["show"] is True
    assert rn.banner(SimpleNamespace(privacy_seen_version=None), 3, known=3)["show"] is False


def test_a_temporary_credential_has_no_banner_and_cannot_mark_it_read(factory):
    ap.prepare(factory)
    db = factory()
    ada = _user(db, "ada")
    db.add(AuditPrivacyPolicy(version=2, reason="admin", **dict(ap.POLICY_ONE)))
    db.commit()
    assert routes.recording_status(current_user=ada, db=db)["show"] is True
    ada._is_temp_session = True
    assert routes.recording_status(current_user=ada, db=db)["show"] is False
    with pytest.raises(HTTPException) as caught:
        _seen(db, ada, 2)
    assert caught.value.status_code == 403


def test_when_the_audit_row_cannot_be_written_it_is_not_marked_read(factory, monkeypatch):
    from app.services.audit_logger import AuditLogger
    ap.prepare(factory)
    db = factory()
    ada = _user(db, "ada")
    db.add(AuditPrivacyPolicy(version=2, reason="admin", **dict(ap.POLICY_ONE)))
    db.commit()

    def broken(self, **kwargs):
        raise RuntimeError("refused")

    monkeypatch.setattr(AuditLogger, "build_row", broken)
    with pytest.raises(HTTPException) as caught:
        _seen(db, ada, 2)
    assert caught.value.status_code == 503
    db.expire_all()
    assert db.get(User, ada.id).privacy_seen_version is None


# --------------------------------------------------------------------------- the page and its links

def test_the_page_has_nothing_inline():
    page = (ROOT / "static" / "recording.html").read_text(encoding="utf-8")
    assert re.findall(r"<script\b[^>]*>", page) == ['<script src="/static/js/recording.js?v=20261002a" defer>']
    assert "<style" not in page and " style=" not in page and "javascript:" not in page
    assert re.search(r' on[a-z]+=', page) is None
    assert page.count('<link rel="stylesheet" href="/static/css/recording.css?v=') == 1
    script = (ROOT / "static" / "js" / "recording.js").read_text(encoding="utf-8")
    assert "innerHTML" not in script and "'/privacy/recording'" in script


def test_the_apps_policy_runs_no_inline_script():
    source = inspect.getsource(api)
    assert "\"script-src 'self'\"," in source
    policy = source[source.index("csp_directives = ["):source.index("]", source.index("csp_directives = ["))]
    assert "unsafe-inline" not in policy.split("script-src", 1)[1].split("\n", 1)[0]


def test_the_notice_is_linked_from_sign_in_invitation_the_link_pages_and_the_account_menu():
    index = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    login = index[index.index('<div id="login-screen"'):index.index('<div id="boot-screen"')]
    invite = index[index.index('<div id="invite-screen"'):index.index('<div id="reset-screen"')]
    menu = index[index.index('<div class="profile-menu">'):index.index("</nav>", index.index('<div class="profile-menu">'))]
    for part in (login, invite, menu):
        assert part.count('href="/recording"') == 1
    for name in ("public-link", "note-link", "upload-link"):
        assert (ROOT / "static" / f"{name}.html").read_text(encoding="utf-8").count('href="/recording"') == 1
    assert index.count('<script src="/static/js/notice-banner.js?v=') == 1
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    assert app.count("new CustomEvent('dockvault:recording-levels')") == 1
    banner = (ROOT / "static" / "js" / "notice-banner.js").read_text(encoding="utf-8")
    assert "'/privacy/recording/seen'" in banner and "'/privacy/recording/status'" in banner
    assert "innerHTML" not in banner


# --------------------------------------------------------------------------- settings, catalogue, inventory

@pytest.mark.parametrize("value", [5, "x" * 1001, ["a"]])
def test_put_settings_bounds_the_notices_text(value):
    for key in rn.NOTICE_KEYS:
        with pytest.raises(HTTPException) as caught:
            api._validate_settings_payload({key: value}, db=None)
        assert caught.value.status_code == 400 and "at most 1000 characters" in str(caught.value.detail)


def test_the_catalogue_and_the_inventory():
    from app.core import audit_catalog
    assert audit_catalog.lookup("privacy_notice_seen") is not None
    text = (ROOT / "docs" / "data-inventory.md").read_text(encoding="utf-8")
    assert "privacy_seen_version" in text
