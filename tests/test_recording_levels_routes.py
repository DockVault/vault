"""The recording levels' routes (app/api/recording_levels_router.py), offline.

GET /settings/recording describes each kind of data (the level, the .env limit and where it comes from, the
levels a choice may take and, for one .env forbids, the line to add), the presets within the limits, a sample,
and the versions saved. PUT /settings/recording refuses, before asking for the step-up, a kind or a level that
does not exist, a level above the limit, levels the deployment locks, and levels that record less than earlier
releases while an SFTP server of another version may be running; then it asks for the password (the fixed
step-up the matrix never weakens) and writes the version with its audit row in one transaction. These run on a
throwaway SQLite database.
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
from app.api import recording_levels_router as routes  # noqa: E402
from app.core import audit_privacy as ap  # noqa: E402
from app.core import sftp_versions  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.core.models import AuditLog, AuditPrivacyPolicy, RoleEnum, SftpProcess, User  # noqa: E402
from app.services.audit_logger import AuditLogger  # noqa: E402

pytestmark = pytest.mark.unit

FULL = {k: "full" for k in ap.POLICY_KEYS}


@pytest.fixture(autouse=True)
def env(monkeypatch):
    for key in ap.POLICY_KEYS:
        monkeypatch.setattr(settings, ap.env_field(key), "full")
        monkeypatch.delenv(ap.ENV_NAMES[key], raising=False)
    monkeypatch.setattr(settings, "settings_locked_keys", "")
    monkeypatch.setattr(sftp_versions, "deployment_runs_sftp", lambda environ=None: False)
    yield


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'levels.db'}")
        for model in (User, AuditLog, AuditPrivacyPolicy, SftpProcess):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        ap.prepare(lambda: session_for(engine))
        yield session
        session.close()
        engine.dispose()


def session_for(engine):
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)()


@pytest.fixture(autouse=True)
def step_up(monkeypatch):
    seen = []
    monkeypatch.setattr(routes, "_step_up", lambda db, user, request: seen.append(user.username))
    return seen


def _admin(db, name="alice"):
    user = User(id=uuid.uuid4(), username=name, email=f"{name}@example.com", password_hash="x",
                role=RoleEnum.ADMIN, is_active=True)
    db.add(user)
    db.commit()
    return user


def _put(db, user, **levels):
    return routes.put_recording_levels(routes.RecordingLevels(levels=levels), request=None, current_user=user, db=db)


def _versions(db):
    db.expire_all()
    return [r.version for r in db.query(AuditPrivacyPolicy).order_by(AuditPrivacyPolicy.version).all()]


def _changes(db):
    return db.query(AuditLog).filter(AuditLog.action == ap.CHANGED_ACTION).count()


@contextmanager
def refused(status, *needles):
    with pytest.raises(HTTPException) as caught:
        yield caught
    assert caught.value.status_code == status, caught.value.detail
    for needle in needles:
        assert needle in str(caught.value.detail), caught.value.detail


# --------------------------------------------------------------------------- the routes

def _routes():
    from fastapi.routing import APIRoute, _IncludedRouter

    def walk(found, prefix):
        for r in found:
            if isinstance(r, _IncludedRouter):
                yield from walk(r.original_router.routes, prefix + r.include_context.prefix)
            elif isinstance(r, APIRoute):
                yield prefix + r.path, r

    return {(m, path): r for path, r in walk(api.app.router.routes, "")
            if path.startswith("/settings/recording") for m in r.methods}


def test_the_routes_are_plain_functions_only_an_interactive_administrator_reaches():
    from app.api import user_management_api as um
    found = _routes()
    assert set(found) == {("GET", "/settings/recording"), ("PUT", "/settings/recording")}
    for route in found.values():
        assert not inspect.iscoroutinefunction(route.endpoint)
        assert um.require_interactive_admin in {d.call for d in route.dependant.dependencies}
    assert inspect.getsource(api).count("app.include_router(recording_levels_router)") == 1


def test_every_statement_is_bounded_and_bounded_again_after_the_step_up():
    for fn in (routes.get_recording_levels, routes.put_recording_levels):
        body = inspect.getsource(fn).split('"""', 2)[2]
        assert body.lstrip().startswith("limit_statements(db)"), fn.__name__
    put = inspect.getsource(routes.put_recording_levels)
    after = put.split("_step_up(db, current_user, request)", 1)[1]
    assert after.splitlines()[1].strip() == "limit_statements(db)"


def test_the_save_reads_the_newest_version_under_the_policies_lock():
    # Two saves at once, or a save and a process starting, must not both write the same next version: the save
    # takes the lock the start takes (a Postgres advisory lock), then reads the newest version, then writes.
    put = inspect.getsource(routes.put_recording_levels)
    tail = put[put.index("_step_up(db, current_user, request)"):]
    assert tail.index("ap.lock_policies(db)") < tail.index("ap.read_latest(db)") < tail.index("ap.write_version(")


def test_saving_asks_for_the_password_every_time():
    from app.core import fixed_step_up
    from app.core import second_factor_actions as acts
    from app.core import second_factor_policy as pol
    assert routes.STEP_UP_ACTION == "admin.audit_privacy.write"
    assert acts.FIXED_STEP_UP_ACTIONS[routes.STEP_UP_ACTION][1] == pol.POLICY_PASSWORD_ALWAYS
    assert routes.STEP_UP_ACTION not in acts.ACTION_KEYS
    assert routes.STEP_UP_ACTION in fixed_step_up.GUARDED
    assert fixed_step_up.contract_problems() == []


# --------------------------------------------------------------------------- refusals

def test_a_kind_or_a_level_that_does_not_exist_is_refused_before_the_step_up(db, step_up):
    user = _admin(db)
    with refused(400, "is not a kind of recorded data"):
        _put(db, user, everything="full")
    with refused(400, "IP addresses can be recorded as none, shortened, full, not fingerprint"):
        _put(db, user, ip="fingerprint")
    assert step_up == [] and _versions(db) == [1] and _changes(db) == 1


def test_a_level_above_the_limit_is_refused_and_names_the_env_line(db, step_up, monkeypatch):
    monkeypatch.setattr(settings, "audit_max_names", "fingerprint")
    user = _admin(db)
    with refused(400, "AUDIT_MAX_NAMES=full to .env, then run docker compose up -d"):
        _put(db, user, names="full")
    assert step_up == [] and _versions(db) == [1]


def test_locked_levels_are_refused(db, step_up, monkeypatch):
    monkeypatch.setattr(settings, "settings_locked_keys", "audit_levels")
    user = _admin(db)
    with refused(409, "SETTINGS_LOCKED_KEYS"):
        _put(db, user, ip="shortened")
    assert step_up == [] and _versions(db) == [1]


def _sftp(db, version):
    db.add(SftpProcess(id=str(uuid.uuid4()), version=version, host="sftp-1",
                       started_at=sftp_versions.datetime.utcnow(), seen_at=sftp_versions.datetime.utcnow()))
    db.commit()


def test_recording_less_than_earlier_releases_is_refused_while_an_older_sftp_server_may_run(db, step_up):
    user = _admin(db)
    _sftp(db, "0.30.0")
    with refused(409, "An SFTP server of another version is running (0.30.0)"):
        _put(db, user, ip="shortened")
    # Recording more than earlier releases is no such risk.
    _put(db, user, names="fingerprint")
    assert _versions(db) == [1, 2] and step_up == ["alice"]


def test_with_sftp_on_and_none_reporting_recording_less_is_refused(db, step_up, monkeypatch):
    monkeypatch.setattr(sftp_versions, "deployment_runs_sftp", lambda environ=None: True)
    user = _admin(db)
    with refused(409, "No SFTP server has reported its version"):
        _put(db, user, emails="none")
    _sftp(db, sftp_versions.code_version())
    assert _put(db, user, emails="none")["status"] == "saved"


def test_a_refused_step_up_changes_nothing(db, monkeypatch):
    def refuse(db_, user, request):
        raise HTTPException(status_code=403, detail={"second_factor_required": True})

    monkeypatch.setattr(routes, "_step_up", refuse)
    user = _admin(db)
    with refused(403):
        _put(db, user, ip="shortened")
    assert _versions(db) == [1] and _changes(db) == 1


# --------------------------------------------------------------------------- saving

def test_a_save_writes_the_next_version_and_its_audit_row_together(db, step_up):
    user = _admin(db)
    out = _put(db, user, ip="shortened", signin_names="fingerprint")
    assert out["status"] == "saved" and out["version"] == 2
    assert _versions(db) == [1, 2]
    row = db.query(AuditPrivacyPolicy).filter(AuditPrivacyPolicy.version == 2).one()
    assert (row.ip, row.signin_names, row.names, row.reason, row.created_by, row.created_by_name) == (
        "shortened", "fingerprint", "none", "admin", user.id, "alice")
    audit = db.query(AuditLog).filter(AuditLog.action == ap.CHANGED_ACTION, AuditLog.resource_id == "2").one()
    assert audit.user_id == user.id and audit.details["old"] == ap.POLICY_ONE
    assert audit.details["levels"]["ip"] == "shortened"
    assert ap.current().version == 2
    assert out["history"][0]["version"] == 2 and out["history"][0]["by"] == "alice"
    assert [h["version"] for h in out["history"]] == [2, 1]


def test_the_same_levels_again_write_nothing(db, step_up):
    user = _admin(db)
    assert _put(db, user, names="none")["status"] == "unchanged"
    assert _versions(db) == [1] and _changes(db) == 1


def test_when_the_audit_row_cannot_be_written_nothing_is_saved(db, monkeypatch):
    def broken(self, **kwargs):
        raise RuntimeError("the database refused the insert")

    user = _admin(db)
    monkeypatch.setattr(AuditLogger, "build_row", broken)
    with refused(503, "Nothing was changed"):
        _put(db, user, ip="none")
    assert _versions(db) == [1]


# --------------------------------------------------------------------------- what the page is told

def test_the_description_names_the_limit_its_source_and_the_line_for_a_forbidden_level(db, monkeypatch):
    monkeypatch.setattr(settings, "audit_max_ip", "shortened")
    monkeypatch.setenv("AUDIT_MAX_IP", "shortened")
    out = routes.get_recording_levels(current_user=_admin(db), db=db)
    ip = next(k for k in out["kinds"] if k["key"] == "ip")
    assert (ip["limit"], ip["limit_source"], ip["level"], ip["stored"]) == ("shortened", "env", "shortened", "full")
    choices = {c["level"]: c for c in ip["choices"]}
    assert choices["full"]["allowed"] is False and choices["full"]["env_line"] == "AUDIT_MAX_IP=full"
    assert choices["shortened"]["allowed"] and choices["shortened"]["env_line"] is None
    assert choices["shortened"]["sample"] == "203.0.113.0/24" and choices["none"]["sample"] is None
    emails = next(k for k in out["kinds"] if k["key"] == "emails")
    assert emails["limit_source"] == "default" and all(c["allowed"] for c in emails["choices"])
    assert out["version"] == 1 and out["locked"] is False and out["sftp"]["same_version"] is True


def test_the_presets_are_brought_within_the_limits(db, monkeypatch):
    monkeypatch.setattr(settings, "audit_max_user_agent", "none")
    monkeypatch.setattr(settings, "audit_max_names", "fingerprint")
    out = routes.get_recording_levels(current_user=_admin(db), db=db)
    presets = {p["key"]: p["levels"] for p in out["presets"]}
    assert set(presets) == {"minimal", "standard", "full"}
    assert presets["minimal"] == {k: "none" for k in ap.POLICY_KEYS}
    assert presets["full"] == {**FULL, "user_agent": "none", "names": "fingerprint"}
    assert presets["standard"] == {"names": "fingerprint", "signin_names": "fingerprint", "emails": "full",
                                   "ip": "shortened", "user_agent": "none"}


def test_while_locked_only_the_limit_may_be_chosen(db, monkeypatch):
    monkeypatch.setattr(settings, "settings_locked_keys", "audit_levels")
    out = routes.get_recording_levels(current_user=_admin(db), db=db)
    assert out["locked"] is True and out["lock_line"] == "SETTINGS_LOCKED_KEYS=audit_levels"
    for kind in out["kinds"]:
        assert [c["level"] for c in kind["choices"] if c["allowed"]] == [kind["limit"]]


@pytest.mark.parametrize("key", sorted(ap.SETTINGS_KEYS_REFUSED))
def test_put_settings_refuses_the_levels_whatever_the_case(key):
    for spelled in (key, key.upper()):
        with refused(400, "the recording levels are saved in Settings, Activity and records"):
            api._validate_settings_payload({spelled: "full"}, db=None)


def test_the_tab_and_its_script_are_on_the_page():
    root = Path(__file__).resolve().parent.parent
    page = (root / "static" / "index.html").read_text(encoding="utf-8")
    assert page.count('data-tab="records">Activity and records</button>') == 1
    assert page.count('<div id="settings-tab-records" class="settings-tab-content">') == 1
    assert page.count('<script src="/static/js/settings-records.js?v=') == 1
    script = (root / "static" / "js" / "settings-records.js").read_text(encoding="utf-8")
    assert "innerHTML" not in script and "'/settings/recording'" in script
    assert "Save All Changes" not in script.split("*/", 1)[1]
