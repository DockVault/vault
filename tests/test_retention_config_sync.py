"""Every .env setting of how long records are kept, of the audit chain and archive, and of container output is in
the three places that must agree: the app's configuration (app/core/config.py), .env.example, and dockvault.py,
which writes a value that is not the default and keeps it across a fresh volume set. The settings registry's
defaults are the same ones.
"""
import importlib.util
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import settings_registry as reg  # noqa: E402
from app.core.config import Settings  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
# The .env lines this release's retention, integrity, archive, erase, working-record and log-rotation work added,
# each of which the tool must keep.
NEW_LINES = ("RETENTION_REDUCTION_DELAY_DAYS", "LOG_PRUNE_INTERVAL_MINUTES", "LOG_PRUNE_BATCH_ROWS", "RETENTION_HOLD",
             "AUDIT_MIN_RETENTION_DAYS", "AUDIT_PROTECTED_MIN_DAYS", "AUDIT_LOG_MAX_MB",
             "ERASE_BLOCKED_BY_PROTECTED_MINIMUM", "PLAN_LOG_MAX_DAYS", "PLAN_LOG_MAX_MB", "SECURITY_RECORD_DAYS",
             "SECURITY_RECORD_MIN_DAYS", "SECURITY_RECORD_MAX_DAYS", "AUDIT_SEAL_LAG_MINUTES", "AUDIT_CHAIN_HEAD_FILE",
             "AUDIT_HOT_DAYS", "AUDIT_ARCHIVE_START_AFTER_DAYS", "NOTIFICATION_RETENTION_DAYS", "LOG_PULL_SINK_MAX_MB",
             "DOCKER_LOG_MAX_SIZE", "DOCKER_LOG_MAX_FILE")


@pytest.fixture(scope="module")
def dv():
    spec = importlib.util.spec_from_file_location("dockvault_config_sync", ROOT / "dockvault.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _text(value) -> str:
    return str(value).lower() if isinstance(value, bool) else str(value)


def _other(value: str) -> str:
    """A value that is not ``value``, of its kind."""
    if value in ("true", "false"):
        return "false" if value == "true" else "true"
    if value.lstrip("-").isdigit():
        return str(int(value) + 1)
    if value in ("full", "none"):
        return "none" if value == "full" else "full"
    if value.endswith("m") and value[:-1].isdigit():
        return value[:-1] + "1m"
    return value + ".other"


def _tables(dv):
    return list(dv.RETENTION_ENV_KEYS) + list(dv.CONTAINER_LOG_ENV_KEYS)


def test_every_new_line_is_kept_by_the_tool(dv):
    kept = {env for _cfg, env, _default in _tables(dv)}
    assert set(NEW_LINES) <= kept
    assert len(kept) == len(_tables(dv))                 # each once


def test_every_line_the_tool_keeps_is_a_setting_of_the_app_with_that_default(dv):
    fields = Settings.model_fields
    for cfg, env, default in dv.RETENTION_ENV_KEYS:
        assert cfg == env.lower(), env
        assert cfg in fields, env
        assert _text(fields[cfg].default) == default, env


def test_every_line_is_documented_once_with_its_default(dv):
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for _cfg, env, default in _tables(dv):
        found = example.count(f"\n# {env}={default}\n") + example.count(f"\n{env}={default}\n")
        assert found == 1, env


def test_the_registrys_defaults_are_the_tools(dv):
    defaults = {cfg: default for cfg, _env, default in dv.RETENTION_ENV_KEYS}
    checked = 0
    for spec in reg.all_specs():
        if spec.env in defaults and spec.editable != reg.FIXED:
            assert _text(spec.default) == defaults[spec.env], spec.key
            checked += 1
    assert checked >= 15


def test_a_value_other_than_the_default_is_written_read_back_and_kept(dv, monkeypatch):
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    given = {env: _other(default) for _cfg, env, default in _tables(dv)}
    lines = dv.build_env_lines({**dv.new_set_config(given, "prefix-1", "dep-1"), "server_name": "localhost"})
    written = dv.parse_env("\n".join(lines))
    assert {k: written.get(k) for k in given} == given
    fields = Settings.model_fields
    parsed = Settings(**{k.lower(): v for k, v in written.items() if k.lower() in fields and k in given})
    for cfg, env, _default in dv.RETENTION_ENV_KEYS:
        assert _text(getattr(parsed, cfg)) == given[env], env


def test_the_default_or_nothing_writes_no_line(dv, monkeypatch):
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    names = {env for _cfg, env, _default in _tables(dv)}
    for kept in ({}, {env: default for _cfg, env, default in _tables(dv)}):
        plain = dv.build_env_lines({**dv.new_set_config(kept, "prefix-1", "dep-1"), "server_name": "localhost"})
        assert not [line for line in plain if line.split("=")[0] in names]


def test_the_chain_key_is_configured_documented_and_written_when_there_is_one(dv, monkeypatch):
    assert Settings.model_fields["audit_chain_key"].default == ""
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert example.count("\n# AUDIT_CHAIN_KEY=\n") == 1
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    cfg = {**dv.new_set_config({}, "prefix-1", "dep-1"), "server_name": "localhost"}
    assert dv.parse_env("\n".join(dv.build_env_lines(cfg)))["AUDIT_CHAIN_KEY"] == cfg["audit_chain_key"]
