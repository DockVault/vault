"""Changes to managed settings (app/core/setting_changes.py), offline, with an injected clock.

A change that keeps data at least as long applies at once; one that deletes data sooner waits
RETENTION_REDUCTION_DELAY_DAYS, any administrator may cancel it meanwhile, and the pruner applies it once it
is due. A newer change of the setting supersedes a waiting one; asking for the value in force keeps it and
cancels the waiting change. Each is written with its audit row, carrying the values before and after, in one
transaction, and every active administrator is told in the app and by email. These run on a throwaway
SQLite database with a throwaway setting.
"""
import tempfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import setting_changes as sc  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402
from app.core.models import AuditLog, ManagedSetting, ManagedSettingChange, RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 1, 12, 0, 0)


@pytest.fixture
def env(monkeypatch):
    """Deployment settings the test controls, no stored values, the throwaway setting and the delay."""
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    settings = SimpleNamespace(settings_locked_keys="", keep_days=90, keep_floor=None, keep_ceiling=None,
                               retention_reduction_delay_days=7)
    monkeypatch.setattr(reg, "_deployment_settings", lambda: settings)
    reg.all_specs()
    saved = [(table, dict(table)) for table in (reg._SPECS, reg._LISTED, reg._LOCK_GROUPS, reg._FIELDS)]
    delay = reg._SPECS[sc.DELAY_KEY]
    for table, _ in saved:
        table.clear()
    reg.register(delay)
    reg.register(reg.SettingSpec(key="keep_days", kind="int", default=90, env="keep_days", minimum=1,
                                 maximum=3650, floor="keep_floor", ceiling="keep_ceiling", unlimited=0,
                                 reduction=reg.LOWER, group="keeping", label="Keep records for", unit="days",
                                 level=reg.ADVANCED, since="0.34.0"))
    reg.register(reg.SettingSpec(key="hold", kind="bool", default=False, reduction=reg.LOWER,
                                 group="keeping", label="Hold deletion", level=reg.ADVANCED, since="0.34.0"))
    yield settings
    for table, before in saved:
        table.clear()
        table.update(before)


@pytest.fixture
def factory(monkeypatch):
    """A session factory on a throwaway database; every session it made is closed at the end."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'changes.db'}")
        for model in (User, ManagedSetting, ManagedSettingChange, AuditLog):
            model.__table__.create(engine)
        make = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        made = []

        def session():
            made.append(make())
            return made[-1]

        monkeypatch.setattr(reg, "_default_session_factory", session)
        yield session
        for s in made:
            s.close()
        engine.dispose()


@pytest.fixture
def told(monkeypatch, factory):
    """Every notice and email announce() sends, instead of sending them."""
    seen = {"notices": [], "emails": []}

    @contextmanager
    def ctx():
        s = factory()
        try:
            yield s
        finally:
            s.close()

    import app.core.database as database
    monkeypatch.setattr(database, "get_db_context", ctx)
    monkeypatch.setattr(api, "_notify_users",
                        lambda ids, ntype, title, body=None, target=None, **k: seen["notices"].append(
                            (sorted(ids), ntype, title, body, target)))
    monkeypatch.setattr(api, "_fire_action_email_bulk",
                        lambda db, key, recipients, ctx=None: seen["emails"].append((key, sorted(recipients), ctx)))
    return seen


def _user(db, name, role=RoleEnum.ADMIN, active=True):
    user = User(id=uuid.uuid4(), username=name, email=f"{name}@example.com", password_hash="x", role=role,
                is_active=active)
    db.add(user)
    db.commit()
    return user


def _rows(db, action):
    return db.query(AuditLog).filter(AuditLog.action == action).order_by(AuditLog.timestamp).all()


def _ask(db, user, value, key="keep_days", now=T0):
    out = sc.request(db, key, value, actor=user, now=now)
    db.commit()
    reg.refresh()
    return out


# --------------------------------------------------------------------------- the direction

@pytest.mark.parametrize("old,new,sooner", [
    (90, 365, False), (90, 0, False), (0, 365, True), (365, 90, True), (90, 90, False),
])
def test_a_change_deletes_sooner_when_it_lowers_the_setting(env, old, new, sooner):
    spec = reg.spec_for("keep_days")
    assert sc.deletes_sooner(spec, old, new) is sooner


def test_lowering_a_clamped_setting_waits_even_where_the_clamp_keeps_the_value(env, factory):
    env.keep_ceiling = 30                    # clamps both 400 and 200 to 30: the value stays, the setting falls
    db = factory()
    alice = _user(db, "alice")
    assert _ask(db, alice, 400).status == "applied" and reg.resolve("keep_days") == 30
    out = _ask(db, alice, 200)
    assert (out.status, out.old, out.new) == ("pending", 30, 30)
    assert _ask(db, alice, 500).status == "applied"


def test_turning_a_switch_off_that_holds_deletion_deletes_sooner(env):
    spec = reg.spec_for("hold")
    assert sc.deletes_sooner(spec, True, False) is True
    assert sc.deletes_sooner(spec, False, True) is False


# --------------------------------------------------------------------------- at once, or waiting

def test_a_change_that_keeps_data_longer_applies_at_once_with_its_row(env, factory):
    db = factory()
    alice = _user(db, "alice")
    out = _ask(db, alice, 365)
    assert (out.status, out.old, out.new) == ("applied", 90, 365)
    assert reg.resolve("keep_days") == 365
    (row,) = _rows(db, sc.CHANGED)
    assert row.details == {"key": "keep_days", "old": 90, "new": 365, "setting": 365, "superseded": []}
    assert db.query(ManagedSettingChange).count() == 0


def test_a_change_that_deletes_sooner_waits_the_delay(env, factory):
    db = factory()
    alice = _user(db, "alice")
    out = _ask(db, alice, 30)
    assert out.status == "pending"
    assert reg.resolve("keep_days") == 90 and db.query(ManagedSetting).count() == 0
    change = db.query(ManagedSettingChange).one()
    assert (change.key, change.setting, change.old_value, change.new_value, change.status) == (
        "keep_days", 30, 90, 30, sc.PENDING)
    assert (change.requested_by, change.requested_by_name, change.requested_at) == (alice.id, "alice", T0)
    assert change.effective_at == T0 + timedelta(days=7)
    (row,) = _rows(db, sc.REQUESTED)
    assert row.username == "alice" and row.details == {
        "key": "keep_days", "old": 90, "new": 30, "setting": 30, "change_id": str(change.id),
        "effective_at": "2026-10-08T12:00:00Z", "superseded": []}


def test_the_delay_is_the_deployments(env, factory):
    env.retention_reduction_delay_days = 2
    db = factory()
    _ask(db, _user(db, "alice"), 30)
    assert db.query(ManagedSettingChange).one().effective_at == T0 + timedelta(days=2)


def test_the_delay_is_at_least_a_day_and_at_most_ninety(env):
    spec = reg.spec_for(sc.DELAY_KEY)
    assert (spec.minimum, spec.maximum, spec.default, spec.editable) == (1, 90, 7, reg.ENV_ONLY)
    for bad in (0, -1, 91):
        env.retention_reduction_delay_days = bad
        assert any("RETENTION_REDUCTION_DELAY_DAYS is not valid" in p for p in reg.check_contract()), bad


def test_going_back_to_the_deployments_value_is_judged_like_any_other(env, factory):
    db = factory()
    alice = _user(db, "alice")
    _ask(db, alice, 365)
    out = _ask(db, alice, None)                      # 365 -> the deployment's 90: sooner
    assert (out.status, out.old, out.new, out.setting) == ("pending", 365, 90, None)
    _ask(db, alice, 30)
    env.keep_days = 400                              # the deployment keeps longer now
    assert _ask(db, alice, None).status == "applied"


# --------------------------------------------------------------------------- the lifecycle, by the clock

def test_a_waiting_change_applies_once_it_is_due_and_not_before(env, factory, told):
    db = factory()
    alice = _user(db, "alice")
    _ask(db, alice, 30)
    assert sc.apply_due(factory, now=T0 + timedelta(days=7) - timedelta(seconds=1)) == []
    assert reg.resolve("keep_days") == 90
    ended = sc.apply_due(factory, now=T0 + timedelta(days=7))
    change = factory().query(ManagedSettingChange).one()
    assert ended == [(change.id, sc.APPLIED)] and change.status == sc.APPLIED
    assert change.decided_at == T0 + timedelta(days=7) and change.decided_by is None
    assert reg.resolve("keep_days") == 30
    stored = factory().get(ManagedSetting, "keep_days")
    assert (stored.value, stored.updated_by, stored.updated_by_name) == (30, alice.id, "alice")
    (row,) = _rows(factory(), sc.APPLIED_ACTION)
    assert row.user_id is None and row.details == {
        "key": "keep_days", "change_id": str(change.id), "old": 90, "new": 30, "setting": 30,
        "requested_by": "alice", "requested_at": "2026-10-01T12:00:00Z"}
    assert sc.apply_due(factory, now=T0 + timedelta(days=30)) == []   # applied once


def test_any_administrator_cancels_a_waiting_change(env, factory, told):
    db = factory()
    alice, bob = _user(db, "alice"), _user(db, "bob")
    out = _ask(db, alice, 30)
    change = sc.cancel(db, out.change.id, actor=bob, now=T0 + timedelta(days=1))
    db.commit()
    assert (change.status, change.decided_by, change.decided_by_name) == (sc.CANCELLED, bob.id, "bob")
    (row,) = _rows(db, sc.CANCELLED_ACTION)
    assert row.username == "bob" and row.details["change_id"] == str(change.id)
    assert (row.details["old"], row.details["new"], row.details["requested_by"]) == (90, 30, "alice")
    assert sc.apply_due(factory, now=T0 + timedelta(days=30)) == []
    assert reg.resolve("keep_days") == 90


def test_the_one_who_asked_may_cancel_too_and_an_ended_change_cannot_be_cancelled(env, factory):
    db = factory()
    alice = _user(db, "alice")
    out = _ask(db, alice, 30)
    sc.cancel(db, out.change.id, actor=alice)
    db.commit()
    with pytest.raises(reg.SettingRefused, match="no longer waiting: it was cancelled"):
        sc.cancel(db, out.change.id, actor=alice)
    with pytest.raises(LookupError):
        sc.cancel(db, uuid.uuid4(), actor=alice)


def test_a_newer_change_supersedes_the_waiting_one(env, factory, told):
    db = factory()
    alice, bob = _user(db, "alice"), _user(db, "bob")
    first = _ask(db, alice, 30).change
    second = _ask(db, bob, 60, now=T0 + timedelta(days=1)).change
    first = db.get(ManagedSettingChange, first.id)
    assert (first.status, first.decided_by_name, first.reason) == (
        sc.SUPERSEDED, "bob", "a newer change of the same setting")
    assert db.get(ManagedSettingChange, second.id).status == sc.PENDING
    assert _rows(db, sc.REQUESTED)[-1].details["superseded"] == [str(first.id)]
    sc.apply_due(factory, now=T0 + timedelta(days=7, hours=1))      # the first would be due: nothing
    assert reg.resolve("keep_days") == 90
    sc.apply_due(factory, now=T0 + timedelta(days=8))
    assert reg.resolve("keep_days") == 60


def test_a_change_at_once_supersedes_a_waiting_one_too(env, factory):
    db = factory()
    alice = _user(db, "alice")
    waiting = _ask(db, alice, 30).change
    out = _ask(db, alice, 400)
    assert out.status == "applied" and db.get(ManagedSettingChange, waiting.id).status == sc.SUPERSEDED
    assert _rows(db, sc.CHANGED)[-1].details["superseded"] == [str(waiting.id)]


def test_asking_for_the_value_in_force_keeps_it_and_cancels_the_waiting_change(env, factory):
    db = factory()
    alice, bob = _user(db, "alice"), _user(db, "bob")
    _ask(db, alice, 365)
    waiting = _ask(db, alice, 30).change
    out = _ask(db, bob, 365)
    assert out.status == "kept" and reg.resolve("keep_days") == 365
    ended = db.get(ManagedSettingChange, waiting.id)
    assert (ended.status, ended.decided_by_name, ended.reason) == (sc.SUPERSEDED, "bob",
                                                                   "the value in force was kept")
    (row,) = _rows(db, sc.CANCELLED_ACTION)
    assert row.username == "bob" and row.details["kept"] == 365 and row.details["new"] == 30
    assert _ask(db, bob, 365).status == "unchanged"
    assert len(_rows(db, sc.CANCELLED_ACTION)) == 1


def test_a_change_the_deployment_has_meanwhile_locked_ends_without_applying(env, factory, told):
    db = factory()
    _ask(db, _user(db, "alice"), 30)
    env.settings_locked_keys = "keeping"
    sc.apply_due(factory, now=T0 + timedelta(days=8))
    change = factory().query(ManagedSettingChange).one()
    assert change.status == sc.CANCELLED and "locked by the deployment" in change.reason
    (row,) = _rows(factory(), sc.CANCELLED_ACTION)
    assert row.user_id is None and "locked by the deployment" in row.details["reason"]
    assert factory().query(ManagedSetting).count() == 0


def test_a_failed_pass_leaves_the_change_waiting_for_the_next(env, factory, told, monkeypatch, capsys):
    db = factory()
    _ask(db, _user(db, "alice"), 30)
    real = sc._audit

    def broken(*a, **k):
        raise RuntimeError("no row")

    monkeypatch.setattr(sc, "_audit", broken)
    assert sc.apply_due(factory, now=T0 + timedelta(days=8)) == []
    assert factory().query(ManagedSettingChange).one().status == sc.PENDING
    assert factory().query(ManagedSetting).count() == 0
    assert "was not applied (RuntimeError)" in capsys.readouterr().out
    monkeypatch.setattr(sc, "_audit", real)
    assert len(sc.apply_due(factory, now=T0 + timedelta(days=8))) == 1


# --------------------------------------------------------------------------- one transaction

def test_nothing_is_committed_by_a_request_the_caller_rolls_back(env, factory):
    db = factory()
    alice = _user(db, "alice")
    sc.request(db, "keep_days", 30, actor=alice, now=T0)
    sc.request(db, "keep_days", 365, actor=alice, now=T0)
    db.rollback()
    assert db.query(ManagedSettingChange).count() == 0 and db.query(ManagedSetting).count() == 0
    assert db.query(AuditLog).count() == 0


# --------------------------------------------------------------------------- telling every administrator

def test_every_active_administrator_is_told_in_the_app_and_by_system_email(env, factory, told):
    db = factory()
    alice, bob = _user(db, "alice"), _user(db, "bob")
    _user(db, "carol", role=RoleEnum.USER)
    _user(db, "dave", active=False)
    out = _ask(db, alice, 30)
    sc.announce_outcome(out, "alice")
    ((ids, ntype, title, body, target),) = told["notices"]
    assert ids == sorted([str(alice.id), str(bob.id)]) and (ntype, target) == ("retention_change", "#settings")
    assert title == "A change that deletes records sooner is waiting"
    assert body == ("alice asked to change “Keep records for” from 90 days to 30 days. Records would "
                    "be deleted sooner, so the change takes effect on 8 October 2026, 12:00 UTC unless an "
                    "administrator cancels it on the Settings page.")
    ((key, recipients, ctx),) = told["emails"]
    assert key == "retention_change"
    assert recipients == [("alice@example.com", "alice"), ("bob@example.com", "bob")]
    assert ctx["change"] == body and ctx["by"] == "alice"
    from app.core import email_actions
    assert email_actions.SPEC_BY_KEY["retention_change"]["category"] == email_actions.SYSTEM


@pytest.mark.parametrize("event,details,title,body", [
    (sc.CHANGED_AT_ONCE, {"key": "keep_days", "old": 90, "new": 0}, "A setting for how long records are kept was changed",
     "bob changed “Keep records for” from 90 days to no limit."),
    (sc.CANCELLED_BY_ADMIN, {"key": "keep_days", "old": 90, "new": 30, "requested_by": "alice"},
     "A waiting change was cancelled",
     "bob cancelled the change of “Keep records for” from 90 days to 30 days that alice asked for. "
     "Nothing changes."),
    (sc.KEPT, {"key": "keep_days", "old": 90, "new": 30}, "A waiting change was cancelled",
     "bob kept “Keep records for” at 90 days, which cancels the waiting change to 30 days."),
    (sc.TOOK_EFFECT, {"key": "keep_days", "old": 90, "new": 30, "requested_by": "alice",
                      "requested_at": "2026-10-01T12:00:00Z"},
     "A change that deletes records sooner took effect",
     "The change of “Keep records for” from 90 days to 30 days that alice asked for on 1 October "
     "2026, 12:00 UTC took effect."),
    (sc.ENDED_BY_DEPLOYMENT, {"key": "hold", "old": True, "new": False, "reason": "hold is locked"},
     "A waiting change did not take effect",
     "The change of “Hold deletion” to off did not take effect: hold is locked."),
])
def test_each_notice_says_what_changed(env, event, details, title, body):
    assert sc.notice_text(event, details, "bob") == (title, body)


def test_applying_and_cancelling_tell_every_administrator(env, factory, told):
    db = factory()
    alice = _user(db, "alice")
    _ask(db, alice, 30)
    sc.apply_due(factory, now=T0 + timedelta(days=7))
    assert [t[2] for t in told["notices"]] == ["A change that deletes records sooner took effect"]
    assert [e[0] for e in told["emails"]] == ["retention_change"]


def test_a_notice_that_cannot_be_sent_never_undoes_the_change(env, factory, monkeypatch, capsys):
    import app.core.database as database

    def broken():
        raise RuntimeError("no database")

    monkeypatch.setattr(database, "get_db_context", broken)
    sc.announce(sc.CHANGED_AT_ONCE, {"key": "keep_days", "old": 90, "new": 365}, "alice")
    assert "were not told of a settings change (RuntimeError)" in capsys.readouterr().out


def test_the_actions_are_catalogued():
    from app.core import audit_catalog
    for name in (sc.CHANGED, sc.REQUESTED, sc.CANCELLED_ACTION, sc.APPLIED_ACTION):
        entry = audit_catalog.lookup(name)
        assert entry is not None and entry.category == "administration", name
    assert audit_catalog.lookup(sc.APPLIED_ACTION).automatic is True


def test_the_delay_is_configured_documented_and_kept_by_the_tool(monkeypatch):
    import importlib.util
    from app.core.config import Settings
    root = Path(__file__).resolve().parent.parent
    assert Settings.model_fields["retention_reduction_delay_days"].default == 7
    example = (root / ".env.example").read_text(encoding="utf-8")
    assert example.count("\n# RETENTION_REDUCTION_DELAY_DAYS=7\n") == 1
    spec = importlib.util.spec_from_file_location("dockvault_retention", root / "dockvault.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    cfg = dv.new_set_config({"RETENTION_REDUCTION_DELAY_DAYS": "3"}, "prefix-1", "dep-1")
    lines = dv.build_env_lines({**cfg, "server_name": "localhost"})
    assert "RETENTION_REDUCTION_DELAY_DAYS=3" in lines
    assert Settings(retention_reduction_delay_days=dv.parse_env("\n".join(lines))[
        "RETENTION_REDUCTION_DELAY_DAYS"]).retention_reduction_delay_days == 3
    for kept in ({}, {"RETENTION_REDUCTION_DELAY_DAYS": "7"}):
        plain = dv.build_env_lines({**dv.new_set_config(kept, "prefix-1", "dep-1"), "server_name": "localhost"})
        assert not [line for line in plain if line.startswith("RETENTION_REDUCTION_DELAY_DAYS")]


def test_the_direction_is_judged_against_the_table_never_a_copy_seconds_old(env, factory):
    db = factory()
    alice, bob = _user(db, "alice"), _user(db, "bob")
    # Another process stored 365; this process has not refreshed its copy, which still says 90.
    reg.store(db, "keep_days", 365, by_id=bob.id, by_name="bob")
    db.commit()
    assert reg.resolve("keep_days") == 90
    out = sc.request(db, "keep_days", 200, actor=alice, now=T0)
    db.commit()
    assert (out.status, out.old, out.new) == ("pending", 365, 200)


def test_a_setting_the_deployment_locked_is_judged_at_its_deployment_value(env, factory, told):
    db = factory()
    alice = _user(db, "alice")
    _ask(db, alice, 365)
    _ask(db, alice, 30)
    env.settings_locked_keys = "keep_days"
    sc.apply_due(factory, now=T0 + timedelta(days=8))
    (row,) = _rows(factory(), sc.CANCELLED_ACTION)
    assert row.details["old"] == 90          # in force under the lock: the deployment's value, not 365
