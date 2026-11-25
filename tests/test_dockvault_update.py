"""What `dockvault.py update` says about signing in at this deployment. Before the change: the notes that come from a
line in .env, for an upgrade onto 0.36.0 (an address no passkey can be made at, a lock on the settings that release
adds). After a healthy update: the sign-in lines that `status` prints. Offline: the update runs for real with its
compose, health and backup calls stubbed."""
import argparse
import importlib.util
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("dockvault_update", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)

PASSKEYS_LOCKED = "SETTINGS_LOCKED_KEYS in .env locks the passkey settings 0.36.0 adds"
SSO_LOCKED = "SETTINGS_LOCKED_KEYS in .env locks the single sign-on providers 0.36.0 adds"


def test_an_upgrade_onto_0_36_0_says_passkeys_stay_hidden_at_an_address_reached_by_ip():
    (note,) = dv.env_upgrade_notes({"ALLOWED_HOSTS": "10.0.0.5"}, "0.35.2", "0.36.0")
    assert note.startswith("ALLOWED_HOSTS in .env: from 0.36.0, passkeys stay hidden"), note
    assert note == "ALLOWED_HOSTS in .env: from 0.36.0, " + dv.sign_in_address_note("10.0.0.5")
    # Plain http and an empty address are said the same way, each in its own words.
    (http,) = dv.env_upgrade_notes({"ALLOWED_HOSTS": "http://vault.lan:8080"}, "0.35.2", "v0.36.0")
    assert "both need https" in http
    (empty,) = dv.env_upgrade_notes({}, "0.35.2", "0.36.0")
    assert "has no address" in empty


@pytest.mark.parametrize("allowed", ["vault.example.com", "https://vault.example.com:8443",
                                     "*.example.com,vault.example.com"])
def test_an_address_passkeys_can_be_made_at_gets_no_note(allowed):
    assert dv.env_upgrade_notes({"ALLOWED_HOSTS": allowed}, "0.35.2", "0.36.0") == []


@pytest.mark.parametrize("locked, passkeys, sso", [
    ("'*'", True, True), ("*", True, True), ('"*"', True, True),
    ("webauthn", True, False), ("WebAuthn", True, False), ("sso", False, True),
    # Read as the server reads it: commas, semicolons and spaces between the names, in any case.
    ("rate_limits;SSO", False, True), ("audit_levels webauthn", True, False), ("rate_limits, sso,webauthn", True, True),
    ("rate_limits,audit_levels", False, False), ("", False, False), ("webauthn_mode", False, False),
])
def test_a_lock_on_the_settings_0_36_0_adds_is_said(locked, passkeys, sso):
    env = {"ALLOWED_HOSTS": "vault.example.com", "SETTINGS_LOCKED_KEYS": locked}
    notes = dv.env_upgrade_notes(env, "0.35.2", "0.36.0")
    assert any(n.startswith(PASSKEYS_LOCKED) for n in notes) is passkeys, notes
    assert any(n.startswith(SSO_LOCKED) for n in notes) is sso, notes
    assert len(notes) == passkeys + sso, notes


def test_both_lock_sentences_say_what_the_lock_does_and_how_it_ends():
    notes = dv.env_upgrade_notes({"ALLOWED_HOSTS": "vault.example.com", "SETTINGS_LOCKED_KEYS": "'*'"},
                                 "0.35.2", "0.36.0")
    (passkeys,) = [n for n in notes if n.startswith(PASSKEYS_LOCKED)]
    (sso,) = [n for n in notes if n.startswith(SSO_LOCKED)]
    assert "(the group webauthn)" in passkeys and "until the lock stops naming them" in passkeys
    assert "no administrator can change them" in passkeys
    assert "(the group sso)" in sso and "no provider can be added in Settings until the lock stops naming them" in sso


@pytest.mark.parametrize("current, target", [("0.36.0", "0.36.1"), ("0.36.1", "v0.37.0"), ("0.35.1", "0.35.2"),
                                             ("0.34.5", "0.35.2")])
def test_only_an_upgrade_onto_0_36_0_says_any_of_it(current, target):
    env = {"ALLOWED_HOSTS": "10.0.0.5", "SETTINGS_LOCKED_KEYS": "'*'"}
    assert dv.env_upgrade_notes(env, current, target) == []


def test_an_upgrade_from_a_version_that_is_not_known_says_it():
    env = {"ALLOWED_HOSTS": "10.0.0.5", "SETTINGS_LOCKED_KEYS": "*"}
    assert len(dv.env_upgrade_notes(env, None, "0.36.0")) == 3


# --- after a healthy update ----------------------------------------------------------------------

def _matrix():
    return {
        "schema_version": 1, "about": "test", "kinds": {"direct": "a"},
        "versions": {"0.1.0": {"released": "2026-01-01", "notes": "a"},
                     "0.2.0": {"released": "2026-01-02", "notes": "b"}},
        "edges": [{"from": "0.1.0", "to": "0.2.0", "kind": "direct", "reversible": True,
                   "requires_backup": False}],
    }


def _deployment(tmp_path, monkeypatch, *, healthy=True, env_lines=()):
    (tmp_path / "VERSION").write_text("0.1.0\n", encoding="utf-8", newline="")
    (tmp_path / ".env").write_text(
        "COMPOSE_PROFILES=combined\nDOCKVAULT_IMAGE=%s\n%s" % (dv.LOCAL_IMAGE, "".join(l + "\n" for l in env_lines)),
        encoding="utf-8", newline="")
    (tmp_path / "docs").mkdir(exist_ok=True)
    (tmp_path / "docs" / "upgrade-matrix.json").write_text(json.dumps(_matrix()), encoding="utf-8", newline="")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _p: True)
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
    monkeypatch.setattr(dv, "fetch_release_tags", lambda *a, **k: [])
    monkeypatch.setattr(dv, "fetch_main_lifecycle_matrix", lambda *a, **k: None)

    def fetch(tag, root=None, opener=None):
        if root is None:
            return None, "no upgrade matrix could be read"
        return json.loads((Path(root) / "docs" / "upgrade-matrix.json").read_text(encoding="utf-8")), "the test matrix"
    monkeypatch.setattr(dv, "fetch_upgrade_matrix", fetch)
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: argparse.Namespace(returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
    monkeypatch.setattr(tool, "_start_secure_stack", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: healthy)
    monkeypatch.setattr(tool, "_running_version", lambda *a, **k: ("0.1.0", "the running container"))
    monkeypatch.setattr(tool, "_do_backup", lambda env, args: None)
    monkeypatch.setattr(tool, "_passkey_addresses", lambda: None)
    return tool


def _update(tool):
    tool.update(argparse.Namespace(tag="v0.2.0", source=False, yes=True, non_interactive=True, dry_run=False,
                                   backup_verified=False))


@pytest.mark.parametrize("healthy", [True, False])
def test_a_healthy_update_ends_with_the_sign_in_lines_status_prints(tmp_path, monkeypatch, healthy):
    tool = _deployment(tmp_path, monkeypatch, healthy=healthy)
    printed = []
    monkeypatch.setattr(tool, "_print_sign_in_lines", lambda env: printed.append(dict(env)))
    _update(tool)
    assert dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))["DOCKVAULT_IMAGE"].endswith(":v0.2.0")
    if healthy:
        # Once, with the deployment's .env as the update left it.
        assert len(printed) == 1 and printed[0]["DOCKVAULT_IMAGE"].endswith(":v0.2.0"), printed
    else:
        assert printed == []


def test_the_sign_in_lines_come_after_the_healthy_line(tmp_path, monkeypatch, capsys):
    tool = _deployment(tmp_path, monkeypatch, env_lines=("ALLOWED_HOSTS='https://203.0.113.9'",))
    _update(tool)
    out = capsys.readouterr().out
    said = dv.sign_in_address_note("https://203.0.113.9")
    assert out.count(said) == 1, out
    assert out.index("Update to v0.2.0: healthy.") < out.index(said)


def test_status_prints_its_sign_in_lines_through_the_same_method(monkeypatch, tmp_path):
    Tool = dv.DockVault
    tool = Tool.__new__(Tool)
    tool.pal = argparse.Namespace(paint=lambda text, colour=None: text)
    tool.root = str(tmp_path)
    (tmp_path / ".env").write_text("ALLOWED_HOSTS='vault.example.com'\n", encoding="utf-8")
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: None)
    seen = []
    monkeypatch.setattr(tool, "_print_sign_in_lines", lambda env: seen.append(env))
    tool._print_status("combined")
    assert seen == [{"ALLOWED_HOSTS": "vault.example.com"}]
