"""The settings registry, offline (app/core/settings_registry.py).

A registered setting resolves to the deployment's value (.env, else the default), the administrator's
stored value when it may apply, clamped between the deployment's floor and ceiling, and locked by
SETTINGS_LOCKED_KEYS. Stored values are read from each process's copy of managed_settings, refreshed in
the background, so resolving never reads the table. PUT /settings refuses every registered key. The
startup contract refuses a floor above a ceiling and an invalid .env value, naming each. These run
against throwaway specs, on a throwaway SQLite database where a table is needed.
"""
import tempfile
import threading
import time
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
from app.core import settings_registry as reg  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.core.models import ManagedSetting, User  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


@contextmanager
def registered(*specs):
    for spec in specs:
        reg.register(spec)
    try:
        yield specs
    finally:
        for spec in specs:
            reg._SPECS.pop(spec.key, None)


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    """No stored values, only the throwaway specs a test registers (the release's own are set aside for
    the test and put back after it), and deployment settings the test controls."""
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    env = SimpleNamespace(settings_locked_keys="", keep_days=30, keep_floor=None, keep_ceiling=None,
                          hold=False, mode="fast")
    monkeypatch.setattr(reg, "_deployment_settings", lambda: env)
    reg.all_specs()                                   # import the spec modules before setting them aside
    saved = [(table, dict(table)) for table in (reg._SPECS, reg._LISTED, reg._LOCK_GROUPS)]
    contracts = list(reg._CONTRACTS)
    for table, _ in saved:
        table.clear()
    reg._CONTRACTS.clear()
    env.release_specs = saved                          # what a test of the release's own specs puts back
    yield env
    for table, before in saved:
        table.clear()
        table.update(before)
    reg._CONTRACTS[:] = contracts


def _days(**kw):
    base = dict(key="keep_days", kind="int", default=90, env="keep_days", minimum=1, maximum=3650,
                floor="keep_floor", ceiling="keep_ceiling", unlimited=0, reduction=reg.LOWER, group="keeping",
                label="Keep for")
    base.update(kw)
    return reg.SettingSpec(**base)


def _store(key, value, version=1):
    reg._cache.rows = {**reg._cache.rows, key: (value, version)}


# --------------------------------------------------------------------------- resolving

def test_the_deployment_value_is_the_env_value(clean, monkeypatch):
    with registered(_days()):
        monkeypatch.setenv("KEEP_DAYS", "30")
        assert reg.resolve("keep_days") == 30
        (row,) = reg.describe()
        assert (row["value"], row["source"], row["deployment_source"]) == (30, "env", "env")


def test_without_an_env_setting_it_is_the_default(clean):
    with registered(_days(env=None)):
        assert reg.resolve("keep_days") == 90
        assert reg.describe()[0]["source"] == "default"


def test_an_env_value_the_process_environment_does_not_set_reads_as_the_default_source(clean, monkeypatch):
    monkeypatch.delenv("KEEP_DAYS", raising=False)
    with registered(_days()):
        assert reg.describe()[0]["deployment_source"] == "default"


def test_the_administrators_value_wins_over_the_deployments(clean):
    with registered(_days()):
        _store("keep_days", 400)
        assert reg.resolve("keep_days") == 400
        row = reg.describe()[0]
        assert (row["value"], row["source"], row["stored"], row["deployment"]) == (400, "admin", 400, 30)


@pytest.mark.parametrize("bad", [0.5, "400", True, None, -3, 4000, [1]])
def test_an_invalid_stored_value_is_ignored_never_trusted(clean, bad):
    with registered(_days()):
        _store("keep_days", bad)
        assert reg.resolve("keep_days") == 30
        assert reg.describe()[0]["stored"] is None


def test_the_unlimited_value_is_a_valid_value_below_the_minimum(clean):
    with registered(_days()):
        _store("keep_days", 0)
        assert reg.resolve("keep_days") == 0


def test_a_setting_only_env_sets_ignores_a_stored_value(clean):
    with registered(_days(editable=reg.ENV_ONLY)):
        _store("keep_days", 400)
        assert reg.resolve("keep_days") == 30


def test_a_fixed_setting_is_its_default_whatever_env_or_the_store_says(clean):
    with registered(_days(editable=reg.FIXED)):
        _store("keep_days", 400)
        assert reg.resolve("keep_days") == 90


@pytest.mark.parametrize("floor,ceiling,stored,expected", [
    (60, None, 45, 60),        # below the floor: raised to it
    (None, 365, 400, 365),     # above the ceiling: lowered to it
    (None, 365, 0, 365),       # unlimited ranks above every number: the ceiling replaces it
    (60, 365, 200, 200),       # inside: kept
    (60, None, 0, 0),          # unlimited is above any floor
    (None, 0, 400, 400),       # a ceiling of unlimited is no ceiling
])
def test_the_value_is_clamped_between_the_deployments_floor_and_ceiling(clean, floor, ceiling, stored, expected):
    clean.keep_floor, clean.keep_ceiling = floor, ceiling
    with registered(_days()):
        _store("keep_days", stored)
        assert reg.resolve("keep_days") == expected
        assert reg.describe()[0]["clamped"] is (expected != stored)


def test_a_bound_can_be_computed_from_the_settings(clean):
    clean.keep_ceiling = 0
    spec = _days(ceiling=lambda s: 100 if s.keep_ceiling == 0 else None)
    with registered(spec):
        _store("keep_days", 400)
        assert reg.resolve("keep_days") == 100


@pytest.mark.parametrize("tokens", ["keep_days", "KEEP_DAYS", "keeping", " other , keep_days ", "*"])
def test_a_locked_setting_ignores_the_stored_value(clean, tokens):
    clean.settings_locked_keys = tokens
    with registered(_days()):
        _store("keep_days", 400)
        assert reg.resolve("keep_days") == 30
        row = reg.describe()[0]
        assert (row["locked"], row["source"], row["stored"]) == (True, "locked", None)


def test_a_setting_that_cannot_be_locked_is_never_locked(clean):
    clean.settings_locked_keys = "*"
    with registered(_days(lockable=False)):
        _store("keep_days", 400)
        assert reg.resolve("keep_days") == 400


def test_a_locked_value_is_still_clamped(clean):
    clean.settings_locked_keys, clean.keep_days, clean.keep_ceiling = "*", 500, 365
    with registered(_days()):
        assert reg.resolve("keep_days") == 365


def test_the_lock_names_that_match_nothing_are_reported(clean):
    clean.settings_locked_keys = "keep_days,keeping,*,nothing_here,also-not"
    with registered(_days()):
        assert reg.unknown_locked_tokens() == ["also-not", "nothing_here"]


def test_a_switch_is_clamped_by_its_floor(clean):
    clean.hold = True
    spec = reg.SettingSpec(key="hold_on", kind="bool", default=False, floor="hold", reduction=reg.LOWER)
    with registered(spec):
        _store("hold_on", False)
        assert reg.resolve("hold_on") is True
        assert reg.is_reduction(spec, True, False) and not reg.is_reduction(spec, False, True)


def test_an_unknown_key_is_a_key_error(clean):
    with pytest.raises(KeyError):
        reg.resolve("nobody_registered_this")


@pytest.mark.parametrize("old,new,reduces", [
    (90, 30, True), (30, 90, False), (0, 365, True), (365, 0, False), (90, 90, False), (None, 5, False)])
def test_a_reduction_is_a_change_towards_deleting_sooner(old, new, reduces):
    assert reg.is_reduction(_days(), old, new) is reduces
    assert reg.is_reduction(_days(reduction=None), old, new) is False
    if old is not None and old != new:
        assert reg.is_reduction(_days(reduction=reg.HIGHER), old, new) is (not reduces)


@pytest.mark.parametrize("spec,value,ok", [
    (reg.SettingSpec(key="k", kind="enum", default="a", choices=("a", "b")), "b", True),
    (reg.SettingSpec(key="k", kind="enum", default="a", choices=("a", "b")), "c", False),
    (reg.SettingSpec(key="k", kind="list", default=[], choices=("a", "b")), ["a", "b"], True),
    (reg.SettingSpec(key="k", kind="list", default=[], choices=("a", "b")), ["a", "z"], False),
    (reg.SettingSpec(key="k", kind="list", default=[]), "a", False),
    (reg.SettingSpec(key="k", kind="list", default=[]), ["a", "b"], True),
    (reg.SettingSpec(key="k", kind="list", default=[]), ["a", 3], False),
    (reg.SettingSpec(key="k", kind="list", default=[]), [None], False),
    (reg.SettingSpec(key="k", kind="str", default=""), "x", True),
    (reg.SettingSpec(key="k", kind="str", default=""), 3, False),
    (reg.SettingSpec(key="k", kind="bool", default=False), 1, False),
    (reg.SettingSpec(key="k", kind="str", default="", validate=lambda v: None if v != "x" else "not x"), "x",
     False),
])
def test_each_kind_checks_its_values(spec, value, ok):
    assert (reg.check_value(spec, value) is None) is ok


def test_a_list_in_env_is_written_comma_separated(clean):
    clean.mode = "a, b ,,c"
    spec = reg.SettingSpec(key="modes", kind="list", default=[], env="mode")
    with registered(spec):
        assert reg.resolve("modes") == ["a", "b", "c"]


# --------------------------------------------------------------------------- registering

@pytest.mark.parametrize("kw,why", [
    (dict(key="Keep"), "lower-case"),
    (dict(key="keep-days"), "lower-case"),
    (dict(kind="float"), "unknown kind"),
    (dict(editable="sometimes"), "unknown editable"),
    (dict(reduction="sideways"), "unknown reduction"),
    (dict(kind="str", default="", minimum=None, maximum=None, unlimited=None), "only a number"),
])
def test_a_spec_that_cannot_be_right_is_refused_when_registered(clean, kw, why):
    with pytest.raises(ValueError, match=why):
        reg.register(_days(**kw))


def test_a_key_is_registered_once(clean):
    with registered(_days()):
        with pytest.raises(ValueError, match="twice"):
            reg.register(_days())


def test_the_registry_imports_the_modules_that_register_specs(clean, monkeypatch):
    imported = []
    monkeypatch.setattr(reg, "SPEC_MODULES", ("fake.module",))
    monkeypatch.setattr(reg, "_modules_loaded", False)
    monkeypatch.setattr(reg.importlib, "import_module", lambda name: imported.append(name))
    reg.all_specs()
    reg.all_specs()
    assert imported == ["fake.module"]


# --------------------------------------------------------------------------- the startup contract

def test_the_contract_refuses_a_floor_above_the_ceiling_and_names_it(clean):
    clean.keep_floor, clean.keep_ceiling = 400, 365
    with registered(_days()):
        problems = reg.check_contract()
        assert problems == ["keep_days: the floor (400) is above the ceiling (365)"]
        with pytest.raises(reg.SettingsContractError, match="floor \\(400\\) is above the ceiling \\(365\\)"):
            reg.start(session_factory=_broken_factory)


def test_the_contract_accepts_an_unlimited_floor_under_an_unlimited_ceiling(clean):
    clean.keep_floor, clean.keep_ceiling = 30, 0
    with registered(_days()):
        assert reg.check_contract() == []


@pytest.mark.parametrize("value", [-1, 99999, "ten"])
def test_the_contract_refuses_an_invalid_env_value_and_names_it(clean, value):
    clean.keep_days = value
    with registered(_days()):
        (problem,) = reg.check_contract()
        assert problem.startswith("KEEP_DAYS is not valid")


@pytest.mark.parametrize("ceiling", ["a year", True])
def test_the_contract_refuses_a_bound_of_the_wrong_kind(clean, ceiling):
    # A switch is not a number, though Python counts True as 1.
    clean.keep_ceiling = ceiling
    with registered(_days()):
        assert reg.check_contract() == ["KEEP_CEILING, the ceiling of keep_days, is not a valid value"]


def test_the_contract_refuses_an_invalid_default(clean):
    with registered(_days(default=-5)):
        assert reg.check_contract()[0].startswith("keep_days: its default is not valid")


def test_the_web_process_and_the_sftp_process_start_the_registry():
    import inspect
    from app.sftp import sftp_server
    lifespan = inspect.getsource(api.lifespan)
    before_yield = lifespan.split("\n    yield\n")[0]
    assert before_yield.count("settings_registry.start()") == 1
    assert inspect.getsource(sftp_server.start_sftp_server).count("settings_registry.start(load_now=False)") == 1


# --------------------------------------------------------------------------- PUT /settings

def _refused(payload):
    try:
        api._validate_settings_payload(payload, db=None)
    except HTTPException as exc:
        return exc
    return None


@pytest.mark.parametrize("spelled", ["keep_days", "KEEP_DAYS", "Keep_Days"])
def test_put_settings_refuses_a_registered_key_whatever_its_case(clean, spelled):
    with registered(_days()):
        refused = _refused({spelled: 5})
        assert refused is not None and refused.status_code == 400
        assert "keep_days" in refused.detail and "managed setting" in refused.detail


def test_put_settings_refuses_a_key_only_env_sets(clean, monkeypatch):
    monkeypatch.setattr(reg, "ENV_ONLY_KEYS", frozenset({"SOME_SWITCH"}))
    refused = _refused({"some_switch": False})
    assert refused is not None and refused.status_code == 400


@pytest.mark.parametrize("spelled", ["zk_key_proof_enforce", "ZK_KEY_PROOF_ENFORCE", "Zk_Key_Proof_Enforce"])
def test_the_switches_only_env_sets_are_refused_by_the_registry_with_their_own_reason(clean, spelled):
    # One mechanism refuses every key only .env sets: ENV_ONLY_KEYS. The refusal is the one these switches
    # always had, a 400 that says the deployment environment manages them.
    assert "zk_key_proof_enforce" in {k.lower() for k in reg.ENV_ONLY_KEYS}
    assert "zk_key_proof_enforce" in reg.refused_settings_keys()
    for value in (False, True, "false", 0, None):
        refused = _refused({spelled: value})
        assert refused is not None and refused.status_code == 400
        assert refused.detail == "zk_key_proof_enforce is managed by the deployment environment"


def test_every_key_only_env_sets_is_a_setting_and_is_not_registered(clean):
    from app.core.config import Settings
    for key in reg.ENV_ONLY_KEYS:
        assert key.lower() in Settings.model_fields, f"{key} is not a setting of this deployment"
        assert reg.spec_for(key.lower()) is None, f"{key} is registered, so it is not only set by .env"
        assert key.lower() not in {listed.key for listed in reg.all_listed()}, f"{key} is listed in the registry"
    # No second list of them is kept where the settings are saved.
    import inspect
    source = inspect.getsource(api._validate_settings_payload)
    assert "env_only_key" not in source and "zk_key_proof_enforce" not in source
    assert source.count("_registry.settings_refusal(_key)") == 1


def test_put_settings_still_takes_other_keys(clean):
    with registered(_days()):
        assert _refused({"sharing_enabled": True}) is None


@pytest.mark.parametrize("key", sorted(reg.refused_settings_keys()) or ["(none registered)"])
def test_put_settings_refuses_every_key_the_registry_holds(clean, key):
    if key == "(none registered)":
        pytest.skip("no setting is registered yet")
    for table, before in clean.release_specs:
        table.update(before)
    refused = _refused({key: None})
    assert refused is not None and refused.status_code == 400


# --------------------------------------------------------------------------- storing and the copy

@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'managed.db'}")
        for model in (User, ManagedSetting):
            model.__table__.create(engine)
        factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        yield factory
        engine.dispose()


def test_a_stored_value_reaches_the_copy_after_a_refresh(clean, db):
    with registered(_days()):
        s = db()
        version = reg.store(s, "keep_days", 400, by_name="ada")
        s.commit()
        assert version == 1
        assert reg.resolve("keep_days") == 30          # not yet: resolving reads only the copy
        assert reg.refresh(db) is True
        assert reg.resolve("keep_days") == 400 and reg.stamp() == 1
        row = s.get(ManagedSetting, "keep_days")
        assert (row.value, row.version, row.updated_by_name) == (400, 1, "ada")
        s.close()


def test_every_change_takes_a_version_above_every_other_so_the_stamp_moves(clean, db):
    other = _days(key="other_days", env=None, floor=None, ceiling=None)
    with registered(_days(), other):
        s = db()
        assert reg.store(s, "other_days", 10) == 1
        assert reg.store(s, "other_days", 11) == 2
        assert reg.store(s, "keep_days", 400) == 3
        # Clearing is a change too: the row stays, holding None, with a new version.
        assert reg.store(s, "other_days", None) == 4
        s.commit()
        reg.refresh(db)
        assert reg.stamp() == 4
        assert reg.resolve("other_days") == 90 and reg.resolve("keep_days") == 400
        assert s.query(ManagedSetting).count() == 2
        s.close()


def test_a_refresh_that_finds_the_same_stamp_does_not_reload(clean, db):
    with registered(_days()):
        s = db()
        reg.store(s, "keep_days", 400)
        s.commit()
        s.close()
        assert reg.refresh(db) is True
        assert reg.refresh(db) is False


@pytest.mark.parametrize("key,value,why", [
    ("nobody", 1, "not a setting the panel manages"),
    ("keep_days", 99999, "at most 3650"),
    ("keep_days", "400", "whole number"),
])
def test_store_refuses_what_the_panel_may_not_set(clean, db, key, value, why):
    with registered(_days()):
        with pytest.raises(reg.SettingRefused, match=why):
            reg.store(db(), key, value)


def test_store_refuses_a_setting_only_env_sets_and_a_locked_one(clean, db):
    with registered(_days(editable=reg.ENV_ONLY), _days(key="locked_days")):
        clean.settings_locked_keys = "locked_days"
        with pytest.raises(reg.SettingRefused, match="set by the deployment"):
            reg.store(db(), "keep_days", 40)
        with pytest.raises(reg.SettingRefused, match="locked by the deployment"):
            reg.store(db(), "locked_days", 40)


def test_store_does_not_commit(clean, db):
    with registered(_days()):
        s = db()
        reg.store(s, "keep_days", 400)
        s.rollback()
        s.close()
        reg.refresh(db)
        assert reg.resolve("keep_days") == 30 and reg.stamp() == 0


def _broken_factory():
    raise AssertionError("the database was read")


def test_resolving_and_describing_never_read_the_database(clean, db, monkeypatch):
    with registered(_days()):
        s = db()
        reg.store(s, "keep_days", 400)
        s.commit()
        s.close()
        reg.refresh(db)
        monkeypatch.setattr(reg, "_default_session_factory", _broken_factory)
        for _ in range(50):
            assert reg.resolve("keep_days") == 400
            assert reg.describe()[0]["value"] == 400


def test_a_failed_refresh_keeps_the_copy_it_had(clean, db, capsys):
    with registered(_days()):
        s = db()
        reg.store(s, "keep_days", 400)
        s.commit()
        s.close()
        reg.refresh(db)
        assert reg.refresh(_broken_factory) is False
        assert reg.resolve("keep_days") == 400
        assert "were not refreshed (AssertionError)" in capsys.readouterr().out


def test_before_the_first_load_every_setting_is_the_deployments(clean):
    with registered(_days()):
        assert reg.stamp() is None and reg.resolve("keep_days") == 30


def test_the_background_refresh_picks_up_another_process_change(clean, db, monkeypatch):
    monkeypatch.setattr(reg, "_refresher", None)
    monkeypatch.setattr(reg, "_refresher_stop", threading.Event())
    with registered(_days()):
        thread = reg.start(session_factory=db, interval=0.05)
        try:
            assert thread.is_alive() and thread.daemon
            assert reg.resolve("keep_days") == 30
            s = db()                                     # "another process" writes and commits
            reg.store(s, "keep_days", 400)
            s.commit()
            s.close()
            deadline = time.monotonic() + 5
            while reg.resolve("keep_days") != 400 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert reg.resolve("keep_days") == 400
        finally:
            reg.stop()
            thread.join(timeout=2)
        assert not thread.is_alive()


def test_start_warns_about_lock_names_that_match_nothing(clean, db, monkeypatch, capsys):
    monkeypatch.setattr(reg, "_refresher", None)
    monkeypatch.setattr(reg, "_refresher_stop", threading.Event())
    clean.settings_locked_keys = "nothing_here"
    thread = reg.start(session_factory=db, interval=10)
    reg.stop()
    thread.join(timeout=2)
    assert "SETTINGS_LOCKED_KEYS names no setting or group: nothing_here" in capsys.readouterr().out


# --------------------------------------------------------------------------- configuration

def test_settings_locked_keys_is_configured_documented_and_kept_by_the_tool(monkeypatch):
    import importlib.util
    assert Settings.model_fields["settings_locked_keys"].default == ""
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert example.count("\n# SETTINGS_LOCKED_KEYS=") == 1
    spec = importlib.util.spec_from_file_location("dockvault_locks", ROOT / "dockvault.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    cfg = dv.new_set_config({"SETTINGS_LOCKED_KEYS": "keeping, other_days"}, "prefix-1", "dep-1")
    lines = dv.build_env_lines({**cfg, "server_name": "localhost"})
    assert "SETTINGS_LOCKED_KEYS='keeping, other_days'" in lines
    written = dv.parse_env("\n".join(lines))["SETTINGS_LOCKED_KEYS"]
    assert Settings(settings_locked_keys=written).settings_locked_keys == "keeping, other_days"
    # An install with nothing locked authors the .env it always did.
    plain = dv.build_env_lines({**dv.new_set_config({}, "prefix-1", "dep-1"), "server_name": "localhost"})
    assert not [line for line in plain if line.startswith("SETTINGS_LOCKED_KEYS")]


def test_a_process_that_must_not_wait_leaves_the_first_load_to_the_thread(clean, db, monkeypatch):
    monkeypatch.setattr(reg, "_refresher", None)
    monkeypatch.setattr(reg, "_refresher_stop", threading.Event())
    loads = []

    def slow_factory():
        loads.append(threading.current_thread().name)
        return db()

    with registered(_days()):
        s = db()
        reg.store(s, "keep_days", 400)
        s.commit()
        s.close()
        thread = reg.start(session_factory=slow_factory, interval=10, load_now=False)
        try:
            deadline = time.monotonic() + 5
            while reg.resolve("keep_days") != 400 and time.monotonic() < deadline:
                time.sleep(0.02)
            assert reg.resolve("keep_days") == 400
            assert loads and set(loads) == {"managed-settings-refresh"}
        finally:
            reg.stop()
            thread.join(timeout=2)


def test_a_console_that_cannot_print_the_warning_never_stops_a_refresh(clean, monkeypatch):
    import builtins

    def unprintable(*_a, **_k):
        raise UnicodeEncodeError("charmap", "x", 0, 1, "cannot print")

    monkeypatch.setattr(builtins, "print", unprintable)
    assert reg.refresh(_broken_factory) is False


@pytest.mark.parametrize("value", [99999, -1, "ten", True])
def test_an_invalid_env_value_is_never_the_value_in_force(clean, value):
    # The contract refuses to start with it; resolving still never uses it, if asked.
    clean.keep_days = value
    with registered(_days()):
        assert reg.resolve("keep_days") == 90
        row = reg.describe()[0]
        assert (row["deployment"], row["deployment_source"]) == (90, "default")


# --------------------------------------------------------------------------- what else the lock can name

def test_a_key_another_store_keeps_is_locked_by_its_key_its_group_or_everything(clean):
    reg.register_listed("some_limit", group="limits", label="Some limit")
    assert reg.listed_locked("some_limit") is False
    for tokens in ("some_limit", "LIMITS", "*", "other, some_limit"):
        clean.settings_locked_keys = tokens
        assert reg.listed_locked("some_limit") is True, tokens
    clean.settings_locked_keys = "keeping"
    assert reg.listed_locked("some_limit") is False
    assert reg.listed_locked("nobody_listed_this") is False


def test_a_listed_key_is_never_refused_by_put_settings_and_never_a_managed_row(clean):
    reg.register_listed("some_limit", group="limits")
    assert "some_limit" not in reg.refused_settings_keys()
    assert reg.describe() == []
    assert [e.key for e in reg.all_listed()] == ["some_limit"]


def test_a_listed_key_is_listed_once_and_named_like_a_setting(clean):
    reg.register_listed("some_limit", group="limits")
    with pytest.raises(ValueError, match="twice"):
        reg.register_listed("some_limit", group="limits")
    with pytest.raises(ValueError, match="lower-case"):
        reg.register_listed("Some-Limit", group="limits")
    with registered(_days()):
        with pytest.raises(ValueError, match="twice"):
            reg.register_listed("keep_days", group="limits")


def test_a_group_with_a_table_of_its_own_is_locked_by_its_name_or_everything(clean):
    reg.register_lock_group("audit_levels", "Recording levels")
    assert reg.group_locked("audit_levels") is False
    for tokens in ("audit_levels", "AUDIT_LEVELS", "*"):
        clean.settings_locked_keys = tokens
        assert reg.group_locked("audit_levels") is True, tokens


def test_the_lock_names_a_listed_key_its_group_and_a_group_without_specs(clean):
    reg.register_listed("some_limit", group="limits")
    reg.register_lock_group("audit_levels")
    clean.settings_locked_keys = "some_limit, limits, audit_levels, nothing_here"
    assert reg.unknown_locked_tokens() == ["nothing_here"]


def test_a_module_adds_its_own_check_to_the_startup_contract(clean, db, monkeypatch):
    monkeypatch.setattr(reg, "_refresher", None)
    monkeypatch.setattr(reg, "_refresher_stop", threading.Event())
    seen = []

    def check(settings):
        seen.append(settings)
        return ["the minimum is longer than the maximum"]

    assert reg.register_contract(check) is check
    reg.register_contract(check)                          # once, however often it is added
    assert reg.check_contract() == ["the minimum is longer than the maximum"]
    assert seen == [clean]
    with pytest.raises(reg.SettingsContractError, match="the minimum is longer than the maximum"):
        reg.start(session_factory=db, interval=10)
    assert reg._refresher is None


@pytest.mark.parametrize("value,why", [
    (400, "keep_days cannot be 400: the deployment allows at most 365 (KEEP_CEILING in .env)"),
    (0, "keep_days cannot be no limit: the deployment allows at most 365 (KEEP_CEILING in .env)"),
    (5, "keep_days cannot be 5: the deployment keeps it at least 7 (KEEP_FLOOR in .env)"),
    (7, None),
    (365, None),
    (None, None),
])
def test_a_value_outside_the_deployments_bounds_is_named_with_its_env_line(clean, value, why):
    clean.keep_floor, clean.keep_ceiling = 7, 365
    with registered(_days()):
        assert reg.check_bounds(reg.spec_for("keep_days"), value) == why


def test_without_a_ceiling_no_limit_is_within_the_bounds(clean):
    clean.keep_floor = 7
    with registered(_days()):
        assert reg.check_bounds(reg.spec_for("keep_days"), 0) is None


def test_a_computed_bound_is_named_without_an_env_line(clean):
    with registered(_days(floor=lambda s: 10, ceiling=None)):
        assert reg.check_bounds(reg.spec_for("keep_days"), 9) == (
            "keep_days cannot be 9: the deployment keeps it at least 10")


def test_describe_names_the_env_lines_that_set_a_value_and_its_bounds(clean):
    with registered(_days(), _days(key="fixed_days", editable=reg.FIXED),
                    _days(key="plain_days", env=None, floor=None, ceiling=lambda s: 99)):
        rows = {r["key"]: r for r in reg.describe()}
    assert (rows["keep_days"]["env"], rows["keep_days"]["floor_env"], rows["keep_days"]["ceiling_env"]) == (
        "KEEP_DAYS", "KEEP_FLOOR", "KEEP_CEILING")
    assert rows["fixed_days"]["env"] is None
    assert (rows["plain_days"]["env"], rows["plain_days"]["floor_env"], rows["plain_days"]["ceiling_env"]) == (
        None, None, None)



@pytest.mark.parametrize("ceiling", [-1, -5])
def test_a_negative_bound_as_for_the_plan_limits_is_no_bound(clean, ceiling):
    clean.keep_ceiling = ceiling
    with registered(_days()):
        assert reg.bounds(reg.spec_for("keep_days")) == (None, None)
        assert reg.check_contract() == []
        assert reg.check_bounds(reg.spec_for("keep_days"), 0) is None
        _store("keep_days", 0)
        assert reg.resolve("keep_days") == 0
