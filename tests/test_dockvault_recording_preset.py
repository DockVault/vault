"""dockvault.py setup asks what the audit log may record of personal data, and writes the AUDIT_MAX_* limits.

Three presets: full (the app's default, so nothing is written), standard (fingerprints of names, IP addresses
shortened) and minimal (none of these). Locking adds audit_levels to SETTINGS_LOCKED_KEYS, so each limit is
also the level. The .env it writes is one the app reads with no unreadable limit.
"""
import argparse
import importlib.util
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import audit_privacy as ap  # noqa: E402
from app.core.config import Settings  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_recording", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)


def _env(cfg):
    base = dv.new_set_config({}, "prefix-1", "dep-1")
    base.update(cfg)
    base["server_name"] = "localhost"
    return dv.parse_env("\n".join(dv.build_env_lines(base)))


EXPECTED = {
    "full": {},
    "standard": {"AUDIT_MAX_NAMES": "fingerprint", "AUDIT_MAX_SIGNIN_NAMES": "fingerprint", "AUDIT_MAX_IP": "shortened"},
    "minimal": {name: "none" for name in ap.ENV_NAMES.values()},
}


@pytest.mark.parametrize("preset", sorted(EXPECTED))
def test_each_preset_writes_only_the_limits_it_lowers_and_the_app_reads_them(preset):
    env = _env(dv.recording_preset_config(preset))
    written = {k: v for k, v in env.items() if k.startswith("AUDIT_MAX_")}
    assert written == EXPECTED[preset]
    assert "SETTINGS_LOCKED_KEYS" not in env
    settings = Settings(**{k.lower(): v for k, v in written.items()})
    assert ap.env_problems(settings) == []
    limits = ap.env_limits(settings)
    for key, name in ap.ENV_NAMES.items():
        assert limits[key] == written.get(name, "full")


def test_the_presets_match_the_panels_within_full_limits():
    from app.api.recording_levels_router import PRESETS
    for name, levels in PRESETS.items():
        assert {ap.ENV_NAMES[k].lower(): v for k, v in levels.items()} == dv.RECORDING_PRESETS[name]


def test_locking_adds_the_levels_group_and_keeps_what_was_locked():
    assert dv.recording_preset_config("minimal", True)["settings_locked_keys"] == "audit_levels"
    assert dv.recording_preset_config("full", True, "rate_limits")["settings_locked_keys"] == "rate_limits,audit_levels"
    assert dv.recording_preset_config("full", True, "audit_levels")["settings_locked_keys"] == "audit_levels"
    assert dv.recording_preset_config("full", False, "rate_limits")["settings_locked_keys"] == "rate_limits"
    env = _env(dv.recording_preset_config("standard", True))
    assert env["SETTINGS_LOCKED_KEYS"] == "audit_levels"
    with pytest.raises(ValueError):
        dv.recording_preset_config("everything")


def _tool(tmp_path, monkeypatch):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_resolve_setup_image", lambda *a, **k: "dockvault-vault:latest")
    return tool


def test_the_flags_answer_setup_without_a_prompt(tmp_path, monkeypatch):
    args = argparse.Namespace(non_interactive=True, server_name="vault.example.com",
                              admin_password="Strong-Pass-1234", recording_preset="standard",
                              lock_recording_levels=True)
    got = _tool(tmp_path, monkeypatch)._collect_setup_config(args)
    assert got["audit_max_ip"] == "shortened" and got["settings_locked_keys"] == "audit_levels"
    plain = _tool(tmp_path, monkeypatch)._collect_setup_config(argparse.Namespace(
        non_interactive=True, server_name="vault.example.com", admin_password="Strong-Pass-1234"))
    assert plain["audit_max_ip"] == "full" and plain["settings_locked_keys"] is None
    parsed = dv.build_parser().parse_args(["setup", "--recording-preset", "minimal", "--lock-recording-levels"])
    assert (parsed.recording_preset, parsed.lock_recording_levels) == ("minimal", True)


@pytest.mark.parametrize("lock", [False, True])
def test_setup_asks_until_it_gets_a_preset_then_whether_to_lock(tmp_path, monkeypatch, lock):
    answers = iter(["vault.example.com", "admin", "admin@example.com", "everything", "Minimal"])
    asked, confirmed = [], []

    def ask(prompt, pal, default=None):
        asked.append(prompt)
        return next(answers)

    def confirm(prompt, pal, default=True):
        confirmed.append(prompt)
        return lock if "no one can record less" in prompt else False

    monkeypatch.setattr(dv, "ask", ask)
    monkeypatch.setattr(dv, "ask_secret", lambda prompt, pal: "Strong-Pass-1234")
    monkeypatch.setattr(dv, "confirm", confirm)
    monkeypatch.setattr(dv, "prompt_free_port", lambda pal, label, default: default)
    got = _tool(tmp_path, monkeypatch)._collect_setup_config(argparse.Namespace(non_interactive=False))
    assert [p for p in asked if p.startswith("Recording preset")] == ["Recording preset (full / standard / minimal)"] * 2
    assert len([p for p in confirmed if "no one can record less" in p]) == 1
    assert got["audit_max_names"] == "none"
    assert got["settings_locked_keys"] == ("audit_levels" if lock else None)
