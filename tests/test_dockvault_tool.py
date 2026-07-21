"""Unit tests for the host-side management tool (dockvault.py).

Loaded by file path (the module is pure stdlib — no app imports), so these run without a live
instance and never touch Docker: the tested surface is the pure colour/prompt/menu/step-tracker
logic + the arg-mode routing. A subprocess smoke covers --help."""
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_mod", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)


class _TTY:
    def isatty(self):
        return True


class _NoTTY:
    def isatty(self):
        return False


def test_color_enabled_decision():
    assert dv.color_enabled(_TTY(), {}) is True
    assert dv.color_enabled(_NoTTY(), {}) is False           # not a TTY -> plain
    assert dv.color_enabled(_TTY(), {"NO_COLOR": ""}) is False   # NO_COLOR present (any value) -> off
    assert dv.color_enabled(_TTY(), {"NO_COLOR": "1"}) is False
    assert dv.color_enabled(_NoTTY(), {"DOCKVAULT_FORCE_COLOR": "1"}) is True  # forced


def test_palette_enabled_and_disabled():
    plain = dv.Palette(False)
    assert plain.paint("hi", "red", "bold") == "hi"          # disabled -> unchanged
    colored = dv.Palette(True)
    out = colored.paint("hi", "red")
    assert out.startswith("\033[31m") and out.endswith("\033[0m") and "hi" in out
    assert colored.paint("hi") == "hi"                        # no names -> unchanged


def test_parse_yes_no():
    assert dv.parse_yes_no("y") is True
    assert dv.parse_yes_no("YES") is True
    assert dv.parse_yes_no("n") is False
    assert dv.parse_yes_no("no") is False
    assert dv.parse_yes_no("", default=True) is True
    assert dv.parse_yes_no("", default=False) is False
    assert dv.parse_yes_no("maybe") is None                  # unrecognised -> re-prompt sentinel


def test_parse_menu_choice():
    assert dv.parse_menu_choice("1", 6) == 1
    assert dv.parse_menu_choice(" 6 ", 6) == 6
    assert dv.parse_menu_choice("7", 6) is None              # out of range
    assert dv.parse_menu_choice("0", 6) == 0                 # back/quit sentinel
    assert dv.parse_menu_choice("q", 6) == 0
    assert dv.parse_menu_choice("QUIT", 6) == 0
    assert dv.parse_menu_choice("x", 6) is None


def test_render_steps():
    steps = ["Collect settings", "Write .env", "Start stack"]
    assert dv.render_steps(steps, 0) == ["[>] Collect settings", "[ ] Write .env", "[ ] Start stack"]
    assert dv.render_steps(steps, 1) == ["[x] Collect settings", "[>] Write .env", "[ ] Start stack"]
    assert dv.render_steps(steps, 3) == ["[x] Collect settings", "[x] Write .env", "[x] Start stack"]


def test_menu_handlers_all_resolve():
    app = dv.DockVault(dv.Palette(False))
    for key, _label in dv.MENU:
        assert callable(app.handler(key)), "no handler for %s" % key
    assert app.handler("does-not-exist") is None


def test_build_parser_accepts_every_menu_command():
    parser = dv.build_parser()
    for key, _label in dv.MENU:
        assert parser.parse_args([key]).command == key
    assert parser.parse_args([]).command is None             # no subcommand -> interactive


def test_arg_mode_routes_to_handler(monkeypatch):
    calls = []
    monkeypatch.setattr(dv.DockVault, "volumes", lambda self, args=None: calls.append("volumes"))
    rc = dv.main(["volumes"])
    assert rc == 0 and calls == ["volumes"]


def test_menu_render_eof_is_clean(monkeypatch, capsys):
    # Feeding EOF to the interactive menu returns cleanly (no crash), after rendering the menu.
    monkeypatch.setattr("builtins.input", lambda *a, **k: (_ for _ in ()).throw(EOFError()))
    dv.DockVault(dv.Palette(False)).run_menu()
    out = capsys.readouterr().out
    assert "DockVault management" in out
    for _key, label in dv.MENU:
        assert label in out


def test_docker_available_missing_unreachable_and_ok(monkeypatch):
    monkeypatch.setattr(dv.shutil, "which", lambda name: None)
    ok, msg = dv.docker_available()
    assert ok is False and "not found" in msg
    monkeypatch.setattr(dv.shutil, "which", lambda name: "/usr/bin/docker")

    class _Rc:
        def __init__(self, rc):
            self.returncode = rc
    bad, msg2 = dv.docker_available(run=lambda *a, **k: _Rc(1))
    assert bad is False and "not reachable" in msg2

    def _raise(*a, **k):
        raise subprocess.TimeoutExpired("docker", 25)
    err, msg3 = dv.docker_available(run=_raise)      # daemon hang / exec failure -> graceful bail
    assert err is False and "could not run docker" in msg3

    good, _ = dv.docker_available(run=lambda *a, **k: _Rc(0))
    assert good is True


def test_dockvault_excluded_from_image():
    di = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    assert "dockvault.py" in di, "dockvault.py (host tooling) must be excluded from the shipped image"


def test_help_smoke():
    proc = subprocess.run([sys.executable, str(ROOT / "dockvault.py"), "--help"],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    assert "DockVault management tool" in proc.stdout


# --- Setup flow: secrets + .env authoring (pure core) ----------------------------------------
def test_gen_secrets_format():
    import base64
    fk = dv.gen_fernet_key()
    assert len(base64.urlsafe_b64decode(fk)) == 32          # a Fernet key wraps 32 bytes
    h = dv.gen_hex(16)
    assert len(h) == 32 and all(c in "0123456789abcdef" for c in h)
    assert dv.gen_fernet_key() != dv.gen_fernet_key()       # random each call


def test_validate_server_name():
    assert dv.validate_server_name("vault.example.com")
    assert dv.validate_server_name("10.0.0.5")
    assert not dv.validate_server_name("")
    assert not dv.validate_server_name("bad name")          # space
    assert not dv.validate_server_name("a;b")               # metachar


def test_admin_password_problem():
    assert dv.admin_password_problem("") is None                            # blank OK (post-bootstrap)
    assert dv.admin_password_problem("REPLACE_ME") is not None              # shipped placeholder, always
    assert dv.admin_password_problem("REPLACE_ME", "development") is not None
    assert dv.admin_password_problem("password", "production") is not None  # weak in production
    assert dv.admin_password_problem("weakpass", "production") is not None  # <12 in production
    assert dv.admin_password_problem("weakpass", "development") is None     # dev lenient
    assert dv.admin_password_problem("has'quote12345", "production") is not None
    assert dv.admin_password_problem("Strong-Pass-1234", "production") is None


def test_migrate_compose_profiles():
    assert dv.migrate_compose_profiles("combined") == "combined"
    assert dv.migrate_compose_profiles("split") == "split"
    assert dv.migrate_compose_profiles("sftp") == "split"   # legacy scheme -> split
    assert dv.migrate_compose_profiles("") == "combined"
    assert dv.migrate_compose_profiles(None) == "combined"


def test_build_env_lines_and_roundtrip():
    cfg = {
        "server_name": "vault.example.com",
        "encryption_key": dv.gen_fernet_key(), "jwt_secret_key": dv.gen_hex(32),
        "vault_db_password": dv.gen_hex(16), "redis_password": dv.gen_hex(24),
        "admin_username": "admin", "admin_email": "admin@example.com",
        "admin_password": "Strong-Pass-1234", "compose_profiles": "combined",
        "run_sftp": True, "update_check_enabled": True, "plan_log_pull": True,
        "log_token_pepper": dv.gen_hex(32),
    }
    env = dv.parse_env("\n".join(dv.build_env_lines(cfg)))
    for k in dv.REQUIRED_SECRET_KEYS:
        assert env.get(k), "authored .env missing %s" % k
    assert env["ENCRYPTION_KEY"] == cfg["encryption_key"]   # round-trips (quotes stripped)
    assert env["ADMIN_PASSWORD"] == "Strong-Pass-1234"
    assert env["ALLOWED_HOSTS"] == "vault.example.com" and env["SERVER_NAME"] == "vault.example.com"
    assert env["COMPOSE_PROFILES"] == "combined" and env["RUN_SFTP"] == "1"
    assert env["UPDATE_CHECK_ENABLED"] == "true"
    # log-pull opt-in writes BOTH the plan flag AND a strong pepper (closes the log-404 trap)
    assert env["PLAN_LOG_PULL"] == "true" and len(env["LOG_TOKEN_PEPPER"]) >= 32
    # with log-pull off, neither key is written (and no SFTP/update lines either)
    off = dv.parse_env("\n".join(dv.build_env_lines(dict(
        cfg, plan_log_pull=False, log_token_pepper="", run_sftp=False, update_check_enabled=False))))
    assert "PLAN_LOG_PULL" not in off and "LOG_TOKEN_PEPPER" not in off
    assert "RUN_SFTP" not in off and "UPDATE_CHECK_ENABLED" not in off


def test_env_is_reusable():
    assert dv.env_is_reusable({"ENCRYPTION_KEY": "k", "JWT_SECRET_KEY": "j", "VAULT_DB_PASSWORD": "d"}) == (True, [])
    ok, missing = dv.env_is_reusable({"ENCRYPTION_KEY": "k"})
    assert ok is False and "VAULT_DB_PASSWORD" in missing


def test_write_env_reports_tighten_result(tmp_path, monkeypatch):
    # write_env must REPORT whether it could restrict the secrets file (which holds ENCRYPTION_KEY),
    # not falsely claim success — so the caller can warn on a failed lockdown.
    p = str(tmp_path / ".env")
    monkeypatch.setattr(dv, "tighten_secret_file", lambda path: True)
    assert dv.write_env(p, ["ENCRYPTION_KEY='x'"]) is True
    assert Path(p).read_text(encoding="utf-8").startswith("ENCRYPTION_KEY")
    monkeypatch.setattr(dv, "tighten_secret_file", lambda path: False)
    assert dv.write_env(p, ["ENCRYPTION_KEY='y'"]) is False        # honest: reports the failure


def _cert_tool_available():
    return shutil.which("openssl") is not None or shutil.which("docker") is not None


_SETUP = [sys.executable, str(ROOT / "dockvault.py"), "setup", "--non-interactive",
          "--server-name", "localhost", "--admin-password", "Strong-Pass-1234", "--no-start"]


@pytest.mark.skipif(not _cert_tool_available(), reason="needs openssl or docker for cert generation")
def test_setup_no_start_authors_env_and_cert(tmp_path):
    env = dict(os.environ, DOCKVAULT_ROOT=str(tmp_path), NO_COLOR="1")
    proc = subprocess.run(_SETUP + ["--enable-log-pull", "--update-check"],
                          env=env, capture_output=True, text=True, timeout=240)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    parsed = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    for k in ("ENCRYPTION_KEY", "JWT_SECRET_KEY", "VAULT_DB_PASSWORD", "REDIS_PASSWORD",
              "ADMIN_USERNAME", "ADMIN_PASSWORD", "SERVER_NAME", "COMPOSE_PROFILES"):
        assert parsed.get(k), "authored .env missing %s" % k
    assert parsed["ADMIN_PASSWORD"] == "Strong-Pass-1234"
    assert parsed["PLAN_LOG_PULL"] == "true" and len(parsed.get("LOG_TOKEN_PEPPER", "")) >= 32
    assert parsed["UPDATE_CHECK_ENABLED"] == "true"
    cert = (tmp_path / "certs" / "cert.pem").read_text(encoding="utf-8", errors="ignore")
    key = (tmp_path / "certs" / "key.pem").read_text(encoding="utf-8", errors="ignore")
    assert "BEGIN CERTIFICATE" in cert and "PRIVATE KEY" in key


@pytest.mark.skipif(not _cert_tool_available(), reason="needs openssl or docker for cert generation")
def test_setup_reuse_does_not_regenerate(tmp_path):
    env = dict(os.environ, DOCKVAULT_ROOT=str(tmp_path), NO_COLOR="1")
    r1 = subprocess.run(_SETUP, env=env, capture_output=True, text=True, timeout=240)
    assert r1.returncode == 0, r1.stdout + r1.stderr
    key1 = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))["ENCRYPTION_KEY"]
    r2 = subprocess.run(_SETUP, env=env, capture_output=True, text=True, timeout=240)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    key2 = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))["ENCRYPTION_KEY"]
    assert key1 == key2, "a re-run must REUSE .env, never regenerate ENCRYPTION_KEY (the bundle invariant)"
    assert "Reusing" in r2.stdout


def test_authored_env_key_parity_with_setup_script():
    # The tool must author the same load-bearing keys the setup-secure.sh script writes, so a
    # tool-authored .env starts the same secure stack (parity).
    cfg = {
        "server_name": "localhost", "encryption_key": dv.gen_fernet_key(),
        "jwt_secret_key": dv.gen_hex(32), "vault_db_password": dv.gen_hex(16),
        "redis_password": dv.gen_hex(24), "admin_username": "admin",
        "admin_email": "admin@example.com", "admin_password": "Strong-Pass-1234",
        "compose_profiles": "combined",
    }
    keys = set(dv.parse_env("\n".join(dv.build_env_lines(cfg))))
    for k in ("ENCRYPTION_KEY", "JWT_SECRET_KEY", "VAULT_DB_PASSWORD", "REDIS_PASSWORD",
              "ALLOWED_HOSTS", "SERVER_NAME", "ADMIN_USERNAME", "ADMIN_EMAIL", "ADMIN_PASSWORD",
              "COMPOSE_PROFILES"):
        assert k in keys, "tool .env is missing the setup-script key %s" % k
