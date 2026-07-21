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


# --- Cert parity: BYO, renewal hook, userns, ports -------------------------------------------
def test_key_is_encrypted():
    assert dv.key_is_encrypted("-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc\n")
    assert not dv.key_is_encrypted("-----BEGIN PRIVATE KEY-----\nabc\n")
    assert not dv.key_is_encrypted("")


def test_render_renewal_hook():
    hook = dv.render_renewal_hook("/opt/vault", "/opt/vault/certs", "vault.example.com", "vault-api")
    assert hook.startswith("#!/bin/bash")
    assert "/etc/letsencrypt/live/vault.example.com/fullchain.pem" in hook
    assert "openssl x509" in hook and "openssl pkey" in hook            # validates the renewed pair
    assert '[ -n "$_c" ]' in hook                                       # non-empty guard (missing openssl -> fail)
    assert 'mv "$CD/.new-key.pem"  "$CD/key.pem"' in hook               # atomic swap
    assert "docker compose" in hook and "restart vault-api" in hook     # restarts so uvicorn reloads


def test_engine_is_remapped_detects_rootless_and_userns():
    class _R:
        def __init__(self, out):
            self.stdout, self.returncode = out, 0
    assert dv._engine_is_remapped(run=lambda *a, **k: _R("name=seccomp,rootless")) is True   # rootless
    assert dv._engine_is_remapped(run=lambda *a, **k: _R("name=userns")) is True             # userns-remap
    assert dv._engine_is_remapped(run=lambda *a, **k: _R("name=seccomp")) is False           # plain rootful
    assert dv._engine_is_remapped(run=lambda *a, **k: (_ for _ in ()).throw(OSError())) is False


def test_parse_subuid_base():
    txt = "root:0:65536\ndockremap:100000:65536\nlow:500:65536\n"
    assert dv.parse_subuid_base(txt, "dockremap") == 100000
    assert dv.parse_subuid_base(txt, "low") is None                    # base < 1000 (system uid) rejected
    assert dv.parse_subuid_base(txt, "missing") is None
    assert dv.parse_subuid_base("", "dockremap") is None


def test_port_free():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        assert dv.port_free(port, "127.0.0.1") is False                # bound -> busy
    finally:
        s.close()
    assert dv.port_free(port, "127.0.0.1") is True                     # freed -> free
    assert dv.port_free(99999) is False and dv.port_free(-1) is False  # out-of-range -> not bindable (no crash)


def test_port_or_clamps():
    assert dv._port_or("8443", 443) == 8443
    assert dv._port_or("99999", 443) == 443    # out of range -> default
    assert dv._port_or("-1", 443) == 443
    assert dv._port_or("bad", 443) == 443       # non-numeric -> default
    assert dv._port_or(None, 2322) == 2322


def test_cert_mode_parser():
    parser = dv.build_parser()
    ns = parser.parse_args(["setup", "--cert-mode", "byo", "--cert-path", "c.pem", "--key-path", "k.pem"])
    assert ns.cert_mode == "byo" and ns.cert_path == "c.pem" and ns.key_path == "k.pem"
    assert parser.parse_args(["setup", "--cert-mode", "letsencrypt", "--le-email", "a@b.com"]).le_email == "a@b.com"


def _mkpair(dirpath, cn="localhost"):
    dirpath.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1", "-nodes",
         "-keyout", str(dirpath / "k.pem"), "-out", str(dirpath / "c.pem"), "-subj", "/CN=%s" % cn],
        capture_output=True, text=True, timeout=60,
        env=dict(os.environ, MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*"))
    assert r.returncode == 0, r.stderr
    return dirpath / "c.pem", dirpath / "k.pem"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs host openssl to make a test cert pair")
def test_byo_install_validates_and_copies(tmp_path):
    cert, key = _mkpair(tmp_path / "src")
    dest = tmp_path / "certs"
    ok, msg = dv.install_byo_cert(str(dest), str(cert), str(key))
    assert ok, msg
    assert (dest / "cert.pem").exists() and (dest / "key.pem").exists()
    assert dv.cert_key_match(str(dest / "cert.pem"), str(dest / "key.pem")) is True
    # a passphrase-encrypted key is rejected up front
    enc = tmp_path / "src" / "enc.pem"
    enc.write_text("-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n-----END ENCRYPTED PRIVATE KEY-----\n")
    bad, badmsg = dv.install_byo_cert(str(tmp_path / "d2"), str(cert), str(enc))
    assert not bad and "passphrase" in badmsg
    # a MISMATCHED pair (a different key) is rejected
    _, key2 = _mkpair(tmp_path / "other", cn="other")
    mm, mmmsg = dv.install_byo_cert(str(tmp_path / "d3"), str(cert), str(key2))
    assert not mm and "not a matching pair" in mmmsg


def test_prompt_free_port_loops_until_free():
    pal = dv.Palette(False)
    # ask returns a busy port then a free one; free_fn: only 8443 is free -> loops to 8443
    answers = iter(["443", "8443"])
    assert dv.prompt_free_port(pal, "Web", 443,
                               ask_fn=lambda prompt, p, default=None: next(answers),
                               free_fn=lambda port: port == 8443) == 8443
    # a non-numeric answer is re-prompted, then accepted
    answers2 = iter(["notaport", "0", "9000"])   # non-int, out-of-range, then valid
    assert dv.prompt_free_port(pal, "Web", 443,
                               ask_fn=lambda prompt, p, default=None: next(answers2),
                               free_fn=lambda port: True) == 9000


def test_prompt_free_port_breaks_on_repeat_non_tty():
    # a non-TTY stdin returns the same default every time -> must NOT loop forever.
    pal = dv.Palette(False)
    calls = {"n": 0}
    def always_default(prompt, p, default=None):
        calls["n"] += 1
        assert calls["n"] < 10, "prompt_free_port looped instead of breaking on a repeated answer"
        return "443"
    # 443 is 'busy' -> it re-prompts once, gets 443 again, then gives up and returns it.
    assert dv.prompt_free_port(pal, "Web", 443,
                               ask_fn=always_default, free_fn=lambda port: False) == 443
    assert calls["n"] == 2


def test_build_env_lines_writes_ports_only_when_nondefault():
    base = {
        "server_name": "localhost", "encryption_key": dv.gen_fernet_key(),
        "jwt_secret_key": dv.gen_hex(32), "vault_db_password": dv.gen_hex(16),
        "redis_password": dv.gen_hex(24), "admin_username": "admin",
        "admin_email": "a@example.com", "admin_password": "Strong-Pass-1234", "compose_profiles": "combined",
    }
    # defaults -> no port lines (the compose defaults 443/2322 apply)
    env = dv.parse_env("\n".join(dv.build_env_lines(dict(base, web_host_port=443, run_sftp=False, sftp_host_port=2322))))
    assert "WEB_HOST_PORT" not in env and "SFTP_HOST_PORT" not in env
    # non-default web port + SFTP on with a non-default sftp port -> both written
    env2 = dv.parse_env("\n".join(dv.build_env_lines(dict(base, web_host_port=8443, run_sftp=True, sftp_host_port=2200))))
    assert env2["WEB_HOST_PORT"] == "8443" and env2["SFTP_HOST_PORT"] == "2200"
    # a non-default sftp port is ignored when SFTP is off (combined mode)
    env3 = dv.parse_env("\n".join(dv.build_env_lines(dict(base, web_host_port=443, run_sftp=False, sftp_host_port=2200))))
    assert "SFTP_HOST_PORT" not in env3
    # split mode always runs the SFTP container -> a non-default SFTP port IS written even with run_sftp off
    env4 = dv.parse_env("\n".join(dv.build_env_lines(dict(
        base, compose_profiles="split", web_host_port=443, run_sftp=False, sftp_host_port=2200))))
    assert env4["SFTP_HOST_PORT"] == "2200"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs host openssl for a BYO pair")
def test_setup_byo_cert_mode_installs_pair(tmp_path):
    cert, key = _mkpair(tmp_path / "src")
    root = tmp_path / "root"
    root.mkdir()
    env = dict(os.environ, DOCKVAULT_ROOT=str(root), NO_COLOR="1")
    r = subprocess.run(
        [sys.executable, str(ROOT / "dockvault.py"), "setup", "--non-interactive",
         "--server-name", "localhost", "--admin-password", "Strong-Pass-1234",
         "--cert-mode", "byo", "--cert-path", str(cert), "--key-path", str(key), "--no-start"],
        env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "BEGIN CERTIFICATE" in (root / "certs" / "cert.pem").read_text(encoding="utf-8", errors="ignore")
    assert dv.cert_key_match(str(root / "certs" / "cert.pem"), str(root / "certs" / "key.pem")) is True
    assert "bring-your-own" in r.stdout
