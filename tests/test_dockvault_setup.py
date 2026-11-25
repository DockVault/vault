"""The host tool's setup (dockvault.py): the lines a fresh .env carries over from the one before it, the flags setup
takes, the files it copies into certs/ and checks the vault container can read, and what its summary says. Offline:
Docker is never asked."""
import argparse
import importlib.util
import os
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_setup_mod", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)

# The passkey settings that take a deployment value from .env under their own names (app/core/webauthn_settings.py).
PASSKEY_ENV = ("WEBAUTHN_MODE", "WEBAUTHN_REQUIRED_ROLES", "WEBAUTHN_ENROLLMENT_GRACE_DAYS", "WEBAUTHN_SIGN_IN",
               "WEBAUTHN_REQUIRE_UV", "WEBAUTHN_ALLOWED_ALGS", "WEBAUTHN_DEVICE_BOUND_ROLES")


@pytest.fixture(autouse=True)
def _keep_secret_acl_changes_hermetic(monkeypatch):
    """No test here changes the host ACL of its temporary secret files."""
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)


def _example():
    """.env.example, read as words: the backticks around a command are left out."""
    return (ROOT / ".env.example").read_text(encoding="utf-8").replace("`", "")


def _comment_block(text, line_start):
    """The comment that runs on from the line starting with ``line_start`` (its continuation lines too), as one
    line of words."""
    at = text.index(line_start)
    lines = []
    for raw in text[at:].splitlines():
        if lines and (not raw.lstrip().startswith("#") or re.match(r"# [A-Z_]+=", raw)):
            break
        lines.append(raw.strip().lstrip("#").strip())
    return " ".join(" ".join(lines).split())


def _lines(cfg):
    return dv.build_env_lines({**cfg, "server_name": "vault.example.com"})


# --------------------------------------------------------------------------- the passkey settings' .env values

def test_the_example_file_lists_each_passkey_setting_and_the_lock_names_their_group():
    text = _example()
    for name in PASSKEY_ENV:
        assert re.search(r"^# %s=" % name, text, re.M), name
    said = _comment_block(text, "# SETTINGS_LOCKED_KEYS=")
    assert ("The group webauthn (or each passkey setting by name, webauthn_mode and the others) locks the passkey "
            "settings of Settings, Sign-in methods at their WEBAUTHN_* values above") in said
    assert ("Attestation and the allowed authenticator makes have no .env value: locked, they stay at none and any "
            "make. * locks them, and the group sso, too.") in said


def test_the_example_file_says_whose_value_wins_and_what_a_requirement_set_there_skips():
    said = " ".join(line.lstrip("#").strip() for line in _example().split("# WEBAUTHN_MODE=")[0][-1600:].splitlines())
    said = " ".join(said.split())
    assert ("These are the deployment's values: an administrator's change in Settings, Sign-in methods replaces them "
            "unless SETTINGS_LOCKED_KEYS names the key or the group webauthn.") in said
    assert ("A requirement set here skips the panel's checks (that the vault's address can make a passkey, and that "
            "an administrator can still sign in): the grace period and python dockvault.py accounts --action "
            "clear-passkey-requirement are the safety net.") in said


def test_the_attestation_roots_line_says_how_a_change_to_it_takes_effect():
    text = _example()
    entry = text[text.index("# Passkeys: the file of root certificates"):text.index("# WEBAUTHN_ATTESTATION_ROOTS=")]
    said = " ".join(" ".join(line.lstrip("#").strip() for line in entry.splitlines()).split())
    assert ("A change to this line takes effect when the vault is restarted with python dockvault.py restart (a plain "
            "docker restart keeps the old environment).") in said


def test_a_fresh_volume_set_keeps_the_passkey_settings_the_old_env_gave():
    old = {"WEBAUTHN_MODE": "off", "WEBAUTHN_REQUIRED_ROLES": "admin, user", "WEBAUTHN_SIGN_IN": "",
           "WEBAUTHN_ENROLLMENT_GRACE_DAYS": "30", "WEBAUTHN_REQUIRE_UV": "false",
           "WEBAUTHN_ALLOWED_ALGS": "ES256", "WEBAUTHN_DEVICE_BOUND_ROLES": "admin"}
    lines = _lines(dv.new_set_config(old, "prefix-1", "dep-1"))
    written = dv.parse_env("\n".join(lines))
    for name, value in old.items():
        assert written.get(name) == value, (name, lines)
    # An empty line says something (no role signs in with a passkey alone): it is kept, not dropped.
    assert "WEBAUTHN_SIGN_IN=" in lines
    # Only what the old .env set is written: the others keep taking the default.
    one = dv.parse_env("\n".join(_lines(dv.new_set_config({"WEBAUTHN_MODE": "off"}, "prefix-1", "dep-1"))))
    assert one["WEBAUTHN_MODE"] == "off" and not [k for k in one if k.startswith("WEBAUTHN_") and k != "WEBAUTHN_MODE"]
    plain = _lines(dv.new_set_config({}, "prefix-1", "dep-1"))
    assert not [line for line in plain if line.startswith("WEBAUTHN_")], plain
