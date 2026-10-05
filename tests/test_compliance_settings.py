"""The boundary of compliance access, offline (app/core/compliance_settings.py).

Fifteen settings only .env sets. Each is registered with the settings registry, so the panel lists it and
SETTINGS_LOCKED_KEYS can name it or its group, and a value outside its bounds refuses to start, naming the
.env line. A case keeps the stricter of the value at its approval and the current one, and an unreadable
recorded value counts as the strictest. The startup contract refuses case records kept longer than the
audit log's ceiling allows, and an access period longer than a case's whole access. The settings are in
config.py, documented in .env.example, and written and kept by dockvault.py.
"""
import importlib.util
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import compliance_settings as cs  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402
from app.core.config import Settings  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent

# key: (default, the lowest valid, the highest valid) for a number, or (default, every choice) otherwise.
NUMBERS = {
    cs.MAX_ACCESS_DAYS: (30, 1, 365),
    cs.MAX_TOTAL_DAYS: (90, 1, 730),
    cs.MAX_CASE_VAULTS: (25, 1, 1000),
    cs.EXPORT_TTL_HOURS: (24, 1, 168),
    cs.HOLD_CONFIRM_DAYS: (7, 1, 30),
    cs.HOLD_PURGE_DELAY_DAYS: (7, 1, 90),
    cs.HOLD_REVIEW_DAYS: (180, 30, 730),
    cs.VIEW_RATE: (600, 10, 36000),
    cs.REVEALS_PER_DAY: (100, 1, 10000),
    cs.AUDITOR_GRANT_DAYS: (365, 1, 365),
    cs.RECORD_MIN_DAYS: (2190, 365, 36500),
}
CHOICES = {
    cs.ACCESS: ("enabled", ("enabled", "disabled")),
    cs.PASSWORD_VAULTS: ("with_password", ("refuse", "with_password", "override")),
    cs.EXPORT: ("allowed", ("allowed", "disabled")),
    cs.AUDITOR_NOT_ADMIN: (False, (False, True)),
}


@pytest.fixture
def env(monkeypatch):
    """The deployment's settings at their defaults, which a test changes; no stored values."""
    settings = Settings.model_construct()
    settings.settings_locked_keys = ""
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    monkeypatch.setattr(reg, "_deployment_settings", lambda: settings)
    for key in cs.KEYS:
        monkeypatch.delenv(key.upper(), raising=False)
    return settings


def test_there_are_fifteen_and_each_is_registered_set_only_in_env_and_lockable(env):
    assert len(cs.KEYS) == 15
    assert set(cs.KEYS) == set(NUMBERS) | set(CHOICES)
    for key in cs.KEYS:
        spec = reg.spec_for(key)
        assert spec is not None, key
        assert (spec.env, spec.editable, spec.lockable, spec.group) == (key, reg.ENV_ONLY, True, "compliance"), key
        assert spec.label, key
        default = NUMBERS[key][0] if key in NUMBERS else CHOICES[key][0]
        assert spec.default == default == Settings.model_fields[key].default, key
        assert reg.resolve(key) == default, key
    assert "app.core.compliance_settings" in reg.SPEC_MODULES


@pytest.mark.parametrize("key", sorted(NUMBERS))
def test_a_number_is_taken_within_its_bounds_and_refused_outside_them(env, key):
    _default, low, high = NUMBERS[key]
    # The checks between settings are left out here: each bound is read alone.
    env.plan_log_max_days, env.compliance_max_total_days = -1, 730
    for value in (low, high):
        setattr(env, key, value)
        if key == cs.MAX_TOTAL_DAYS:
            env.compliance_max_access_days = min(value, 30)
        assert not [p for p in reg.check_contract() if key.upper() in p], (key, value)
        assert reg.resolve(key) == value
    for value in (low - 1, high + 1, "7", True):
        setattr(env, key, value)
        problems = [p for p in reg.check_contract() if p.startswith(f"{key.upper()} is not valid")]
        assert len(problems) == 1, (key, value, reg.check_contract())
        assert reg.resolve(key) == reg.spec_for(key).default
        with pytest.raises(reg.SettingsContractError, match=key.upper()):
            reg.start(lambda: None, load_now=False)


@pytest.mark.parametrize("key", sorted(CHOICES))
def test_a_choice_is_taken_from_its_list_and_anything_else_is_refused(env, key):
    _default, choices = CHOICES[key]
    for value in choices:
        setattr(env, key, value)
        assert not [p for p in reg.check_contract() if key.upper() in p], (key, value)
        assert reg.resolve(key) == value
    for value in ("ENABLED", "on", "", 1, None):
        if key == cs.AUDITOR_NOT_ADMIN and value == 1:
            continue          # 1 is not a bool here either, but True == 1 makes it a poor probe
        setattr(env, key, value)
        assert [p for p in reg.check_contract() if p.startswith(f"{key.upper()} is not valid")], (key, value)
        assert reg.resolve(key) == reg.spec_for(key).default


@pytest.mark.parametrize("tokens", ["compliance", "compliance_view_rate", "*"])
def test_the_lock_names_a_setting_its_group_or_everything(env, tokens):
    env.settings_locked_keys = tokens
    rows = {row["key"]: row for row in reg.describe(cs.KEYS)}
    assert rows[cs.VIEW_RATE]["locked"] and rows[cs.VIEW_RATE]["source"] == reg.SOURCE_LOCKED
    assert reg.unknown_locked_tokens() == []
    assert (rows[cs.ACCESS]["locked"]) == (tokens != "compliance_view_rate")


def test_the_panel_cannot_store_one_and_put_settings_refuses_them(env):
    refused = reg.refused_settings_keys()
    for key in cs.KEYS:
        assert key in refused
        assert reg.describe([key])[0]["env"] == key.upper()


# --------------------------------------------------------------------------- the stricter value

STRICTER_CASES = [
    # key, recorded, now, the value a case uses
    (cs.ACCESS, "enabled", "disabled", "disabled"),
    (cs.ACCESS, "disabled", "enabled", "disabled"),
    (cs.ACCESS, "enabled", "enabled", "enabled"),
    (cs.PASSWORD_VAULTS, "override", "with_password", "with_password"),
    (cs.PASSWORD_VAULTS, "with_password", "override", "with_password"),
    (cs.PASSWORD_VAULTS, "refuse", "override", "refuse"),
    (cs.PASSWORD_VAULTS, "override", "refuse", "refuse"),
    (cs.EXPORT, "allowed", "disabled", "disabled"),
    (cs.EXPORT, "disabled", "allowed", "disabled"),
    (cs.MAX_ACCESS_DAYS, 30, 10, 10),
    (cs.MAX_ACCESS_DAYS, 10, 30, 10),
    (cs.MAX_TOTAL_DAYS, 90, 60, 60),
    (cs.MAX_CASE_VAULTS, 5, 25, 5),
    (cs.EXPORT_TTL_HOURS, 24, 48, 24),
    (cs.HOLD_CONFIRM_DAYS, 7, 3, 3),
    (cs.HOLD_PURGE_DELAY_DAYS, 7, 30, 30),
    (cs.HOLD_PURGE_DELAY_DAYS, 30, 7, 30),
    (cs.HOLD_REVIEW_DAYS, 180, 90, 90),
    (cs.VIEW_RATE, 600, 1200, 600),
    (cs.REVEALS_PER_DAY, 100, 50, 50),
    (cs.AUDITOR_NOT_ADMIN, False, True, True),
    (cs.AUDITOR_NOT_ADMIN, True, False, True),
    (cs.AUDITOR_GRANT_DAYS, 365, 180, 180),
    (cs.RECORD_MIN_DAYS, 2190, 3650, 3650),
    (cs.RECORD_MIN_DAYS, 3650, 2190, 3650),
]


@pytest.mark.parametrize("key,recorded,now,expected", STRICTER_CASES)
def test_a_case_uses_the_stricter_of_its_recorded_value_and_the_current_one(env, key, recorded, now, expected):
    got = cs.stricter(key, recorded, now)
    assert got == expected and type(got) is type(expected)


def test_every_setting_has_a_direction_and_a_case_covers_both_ways_for_each():
    assert set(cs.STRICTER) == set(cs.KEYS)
    covered = {key for key, *_ in STRICTER_CASES}
    assert covered == set(cs.KEYS)


@pytest.mark.parametrize("key,strictest", [
    (cs.ACCESS, "disabled"), (cs.PASSWORD_VAULTS, "refuse"), (cs.EXPORT, "disabled"),
    (cs.AUDITOR_NOT_ADMIN, True), (cs.MAX_ACCESS_DAYS, 1), (cs.VIEW_RATE, 10),
    (cs.HOLD_PURGE_DELAY_DAYS, 90), (cs.RECORD_MIN_DAYS, 36500),
])
@pytest.mark.parametrize("damaged", ["nonsense", -5, 10 ** 9, [], {"x": 1}])
def test_an_unreadable_recorded_value_counts_as_the_strictest(env, key, strictest, damaged):
    now = reg.spec_for(key).default
    assert cs.stricter(key, damaged, now) == strictest


def test_nothing_recorded_is_the_current_value(env):
    for key in cs.KEYS:
        assert cs.stricter(key, None, reg.spec_for(key).default) == reg.spec_for(key).default


def test_case_value_reads_the_value_in_force_now(env):
    recorded = cs.snapshot()
    assert recorded == {key: reg.spec_for(key).default for key in cs.KEYS}
    env.compliance_export = "disabled"
    env.compliance_max_access_days = 10
    assert cs.case_value(cs.EXPORT, recorded) == "disabled"
    assert cs.case_value(cs.MAX_ACCESS_DAYS, recorded) == 10
    # Widening .env later does not widen the case.
    env.compliance_max_access_days = 60
    assert cs.case_value(cs.MAX_ACCESS_DAYS, {**recorded, cs.MAX_ACCESS_DAYS: 10}) == 10
    assert cs.case_value(cs.MAX_ACCESS_DAYS, None) == 60
    with pytest.raises(KeyError):
        cs.case_value("compliance_something_else", recorded)
    with pytest.raises(KeyError):
        cs.stricter("audit_max_days", 1, 2)


# --------------------------------------------------------------------------- the startup contract

def test_start_is_refused_while_case_records_outlast_the_audit_logs_ceiling(env):
    env.plan_log_max_days = 365
    problems = [p for p in reg.check_contract() if "COMPLIANCE_RECORD_MIN_DAYS" in p]
    assert problems == ["COMPLIANCE_RECORD_MIN_DAYS (2190) is longer than PLAN_LOG_MAX_DAYS (365): case records "
                        "could be neither kept nor deleted; lower COMPLIANCE_RECORD_MIN_DAYS or raise "
                        "PLAN_LOG_MAX_DAYS, or set COMPLIANCE_ACCESS=disabled"]
    with pytest.raises(reg.SettingsContractError, match="COMPLIANCE_RECORD_MIN_DAYS"):
        reg.start(lambda: None, load_now=False)
    for ceiling, floor in ((2190, 2190), (3000, 2190), (-1, 2190), (400, 400)):
        env.plan_log_max_days, env.compliance_record_min_days = ceiling, floor
        assert not [p for p in reg.check_contract() if "COMPLIANCE_RECORD_MIN_DAYS" in p], (ceiling, floor)
    env.plan_log_max_days, env.compliance_record_min_days = 400, 401
    assert [p for p in reg.check_contract() if "COMPLIANCE_RECORD_MIN_DAYS (401)" in p]


@pytest.mark.parametrize("ceiling", [1, 90, 364, 365, 2189])
def test_a_ceiling_under_the_floor_starts_only_with_compliance_access_disabled(env, ceiling):
    # The floor is never under a year, so a plan that keeps its audit log for less runs without compliance
    # access rather than not at all. Enabled, or any value but "disabled" (refused on its own besides), it is
    # refused.
    env.plan_log_max_days, env.compliance_record_min_days = ceiling, max(365, ceiling + 1)
    for access in ("enabled", "Disabled", "off", None):
        env.compliance_access = access
        assert [p for p in reg.check_contract() if p.startswith("COMPLIANCE_RECORD_MIN_DAYS (")], access
    env.compliance_access = "disabled"
    assert not [p for p in reg.check_contract() if p.startswith("COMPLIANCE_RECORD_MIN_DAYS")]
    # Nothing else stands in the way once the protected minimum of the audit log fits the ceiling too.
    env.audit_protected_min_days = min(365, ceiling)
    assert reg.check_contract() == []
    # Disabled does not lower the floor's own bound.
    env.compliance_record_min_days = 364
    assert [p for p in reg.check_contract() if p.startswith("COMPLIANCE_RECORD_MIN_DAYS is not valid")]


def test_start_is_refused_while_one_access_period_outlasts_a_cases_whole_access(env):
    env.compliance_max_access_days, env.compliance_max_total_days = 91, 90
    assert [p for p in reg.check_contract() if p.startswith("COMPLIANCE_MAX_ACCESS_DAYS (91) is longer than "
                                                            "COMPLIANCE_MAX_TOTAL_DAYS (90)")]
    env.compliance_max_access_days = 90
    assert not [p for p in reg.check_contract() if "COMPLIANCE_MAX_ACCESS_DAYS" in p]


def test_the_defaults_start(env):
    assert reg.check_contract() == []


# --------------------------------------------------------------------------- config sync

def _dockvault():
    spec = importlib.util.spec_from_file_location("dockvault_compliance", ROOT / "dockvault.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    return dv


def test_the_settings_are_configured_documented_and_written_and_kept_by_the_tool(monkeypatch):
    dv = _dockvault()
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    tool = {cfg: (name, default) for cfg, name, default in dv.COMPLIANCE_ENV_KEYS}
    assert set(tool) == set(cs.KEYS)
    defaults = {}
    for key in cs.KEYS:
        name, default = tool[key]
        assert name == key.upper()
        expected = Settings.model_fields[key].default
        assert default == (str(expected).lower() if isinstance(expected, bool) else str(expected)), key
        assert example.count(f"\n# {name}={default}\n") == 1, name
        defaults[name] = default
    given = {"COMPLIANCE_ACCESS": "disabled", "COMPLIANCE_PASSWORD_VAULTS": "refuse", "COMPLIANCE_VIEW_RATE": "120",
             "COMPLIANCE_AUDITOR_NOT_ADMIN": "true", "COMPLIANCE_RECORD_MIN_DAYS": "3650"}
    lines = dv.build_env_lines({**dv.new_set_config(given, "prefix-1", "dep-1"), "server_name": "localhost"})
    written = dv.parse_env("\n".join(lines))
    assert {k: written.get(k) for k in given} == given
    assert not [k for k in defaults if k in written and k not in given]
    for kept in ({}, defaults):
        plain = dv.build_env_lines({**dv.new_set_config(kept, "prefix-1", "dep-1"), "server_name": "localhost"})
        assert not [line for line in plain if line.split("=")[0] in defaults]
