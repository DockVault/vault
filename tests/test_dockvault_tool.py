"""Unit tests for the host-side management tool (dockvault.py).

Loaded by file path (the module is pure stdlib — no app imports), so these run without a live
instance: the tested surface is the pure colour/prompt/menu/step-tracker logic, the arg-mode
routing, and the docker/compose call SHAPES (via an injected/patched `run`). A subprocess smoke
covers --help. A handful of tests marked as needing a live engine do drive real Docker - they skip
cleanly when `docker` is absent."""
import argparse
import importlib.util
import io
import json
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


class _Proc:
    """A stand-in for subprocess.CompletedProcess (injected `run` return value)."""
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


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


@pytest.mark.skipif(not _cert_tool_available(), reason="needs openssl or docker for cert generation")
def test_setup_new_stamps_deployment_id(tmp_path):
    env = dict(os.environ, DOCKVAULT_ROOT=str(tmp_path), NO_COLOR="1")
    proc = subprocess.run(_SETUP, env=env, capture_output=True, text=True, timeout=240)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    did = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8")).get("DEPLOYMENT_ID", "")
    assert len(did) == 8 and all(c in "0123456789abcdef" for c in did), \
        "a fresh setup must stamp a short hex DEPLOYMENT_ID (got %r)" % did


@pytest.mark.skipif(not _cert_tool_available(), reason="needs openssl or docker for cert generation")
def test_setup_reuse_adopts_legacy_deployment_id(tmp_path):
    # A pre-label ("legacy") .env carries every secret but no DEPLOYMENT_ID. Reusing it must ADOPT the
    # deployment under bundle 'default' - additive + idempotent - without regenerating any secret.
    cfg = {
        "server_name": "localhost", "encryption_key": dv.gen_fernet_key(),
        "jwt_secret_key": dv.gen_hex(32), "vault_db_password": dv.gen_hex(16),
        "redis_password": dv.gen_hex(24), "admin_username": "admin",
        "admin_email": "a@example.com", "admin_password": "Strong-Pass-1234", "compose_profiles": "combined",
    }
    legacy = dv.build_env_lines(cfg)
    assert not any(l.startswith("DEPLOYMENT_ID") for l in legacy), "seed must be truly legacy (no id)"
    (tmp_path / ".env").write_text("\n".join(legacy) + "\n", encoding="utf-8")
    env = dict(os.environ, DOCKVAULT_ROOT=str(tmp_path), NO_COLOR="1")
    r1 = subprocess.run(_SETUP, env=env, capture_output=True, text=True, timeout=240)
    assert r1.returncode == 0, r1.stdout + r1.stderr
    p1 = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert p1["DEPLOYMENT_ID"] == "default", "reuse must adopt a legacy deployment as bundle 'default'"
    assert p1["ENCRYPTION_KEY"] == cfg["encryption_key"], "reuse must NOT regenerate ENCRYPTION_KEY"
    # idempotent: a second reuse leaves DEPLOYMENT_ID=default untouched (no drift, no re-adopt)
    r2 = subprocess.run(_SETUP, env=env, capture_output=True, text=True, timeout=240)
    assert r2.returncode == 0, r2.stdout + r2.stderr
    p2 = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert p2["DEPLOYMENT_ID"] == "default" and p2["ENCRYPTION_KEY"] == cfg["encryption_key"]


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


def test_gen_deployment_id_is_short_hex():
    ids = {dv.gen_deployment_id() for _ in range(25)}
    assert all(len(i) == 8 and all(c in "0123456789abcdef" for c in i) for i in ids)
    assert len(ids) > 1, "deployment ids must vary, not be constant"


def test_build_env_lines_writes_deployment_id():
    base = {
        "server_name": "localhost", "encryption_key": dv.gen_fernet_key(),
        "jwt_secret_key": dv.gen_hex(32), "vault_db_password": dv.gen_hex(16),
        "redis_password": dv.gen_hex(24), "admin_username": "admin",
        "admin_email": "a@example.com", "admin_password": "Strong-Pass-1234", "compose_profiles": "combined",
    }
    env = dv.parse_env("\n".join(dv.build_env_lines(dict(base, deployment_id="deadbeef"))))
    assert env["DEPLOYMENT_ID"] == "deadbeef"
    # no id -> no line (the compose ${DEPLOYMENT_ID:-default} fallback applies)
    env2 = dv.parse_env("\n".join(dv.build_env_lines(base)))
    assert "DEPLOYMENT_ID" not in env2


def test_parse_and_group_volumes():
    out = ("dockvault-vault_vault_pg_data\tpg\tabc123\n"
           "dockvault-vault_vault_storage\tstorage\tabc123\n"
           "otherproj_vault_keys\tkeys\tzzz999\n"
           "\n"                       # blank line -> skipped
           "novol\t\t\n")            # empty role -> None, empty bundle -> 'default'
    recs = dv.parse_volume_ls(out)
    assert len(recs) == 4
    assert recs[0] == {"name": "dockvault-vault_vault_pg_data", "role": "pg", "bundle": "abc123"}
    assert recs[3]["role"] is None and recs[3]["bundle"] == "default"
    groups = dict(dv.group_volumes_by_bundle(recs))
    assert set(groups) == {"abc123", "zzz999", "default"}
    assert [r["name"] for r in groups["abc123"]] == [
        "dockvault-vault_vault_pg_data", "dockvault-vault_vault_storage"]


def test_list_managed_volumes_parses_and_fails_soft():
    def ok_run(cmd, **kw):
        assert "label=com.dockvault.managed=true" in cmd
        return _Proc(0, "v_pg\tpg\tb1\nv_st\tstorage\tb1\n")
    recs = dv.list_managed_volumes(run=ok_run)
    assert [(r["role"], r["bundle"]) for r in recs] == [("pg", "b1"), ("storage", "b1")]
    # docker missing / query failure -> [] (best-effort read, never raises)
    assert dv.list_managed_volumes(run=lambda *a, **k: (_ for _ in ()).throw(OSError("no docker"))) == []
    assert dv.list_managed_volumes(run=lambda *a, **k: _Proc(1, "")) == []


def test_list_legacy_volumes_only_unlabelled_wellknown():
    def run(cmd, **kw):
        return _Proc(0,
            "dockvault-vault_vault_pg_data\t\n"      # legacy (unlabelled) -> included
            "dockvault-vault_vault_storage\ttrue\n"   # already managed -> excluded
            "dockvault-vault_vault_keys\t\n"          # legacy -> included
            "someones_other_volume\t\n"               # not a well-known name -> excluded
            "dockvault-vault_vault_logs\t\n"
            "dockvault-vault_vault_brand\t\n")
    legacy = dv.list_legacy_volumes(run=run)
    assert legacy == sorted([
        "dockvault-vault_vault_pg_data", "dockvault-vault_vault_keys",
        "dockvault-vault_vault_logs", "dockvault-vault_vault_brand"])
    # fail-soft parity with list_managed_volumes: docker missing / nonzero -> [] (never raises)
    assert dv.list_legacy_volumes(run=lambda *a, **k: (_ for _ in ()).throw(OSError("no docker"))) == []
    assert dv.list_legacy_volumes(run=lambda *a, **k: _Proc(1, "")) == []


def test_list_managed_volumes_live_roundtrip():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    names = {"pg": "dvmanaged_pg", "storage": "dvmanaged_storage"}
    try:
        try:
            for role, name in names.items():
                subprocess.run(["docker", "volume", "create",
                                "--label", "com.dockvault.managed=true",
                                "--label", "com.dockvault.role=%s" % role,
                                "--label", "com.dockvault.bundle=dvmanagedbundle", name],
                               check=True, capture_output=True, timeout=30)
        except (subprocess.SubprocessError, OSError) as exc:   # binary present but daemon down -> skip, not error
            pytest.skip("docker daemon unavailable: %s" % exc)
        recs = [r for r in dv.list_managed_volumes() if r["bundle"] == "dvmanagedbundle"]
        assert {r["role"] for r in recs} == {"pg", "storage"}
        groups = dict(dv.group_volumes_by_bundle(recs))
        assert "dvmanagedbundle" in groups and len(groups["dvmanagedbundle"]) == 2
    finally:
        for name in names.values():
            subprocess.run(["docker", "volume", "rm", "-f", name], capture_output=True, timeout=30)


# --- secret<->volume guardrail ------------------------------------------------------------
def test_classify_pg_probe():
    assert dv.classify_pg_probe(0, "") == "ok"
    assert dv.classify_pg_probe(2, 'FATAL:  password authentication failed for user "sftp_user"') == "mismatch"
    assert dv.classify_pg_probe(1, "FATAL: 28P01") == "mismatch"
    assert dv.classify_pg_probe(1, "could not connect to server") == "ambiguous"     # fail-closed
    assert dv.classify_pg_probe(1, "") == "ambiguous"


def test_db_guard_decision():
    assert dv.db_guard_decision(False, "ambiguous") == "proceed"   # fresh volume always proceeds
    assert dv.db_guard_decision(True, "ok") == "proceed"
    assert dv.db_guard_decision(True, "mismatch") == "refuse"
    assert dv.db_guard_decision(True, "ambiguous") == "refuse"     # fail-closed


def test_fernet_key_looks_valid():
    assert dv.fernet_key_looks_valid(dv.gen_fernet_key()) is True
    assert dv.fernet_key_looks_valid("abc") is False               # too short
    assert dv.fernet_key_looks_valid("") is False
    assert dv.fernet_key_looks_valid("!!!not base64!!!") is False


def test_volume_exists_best_effort():
    assert dv.volume_exists("x", run=lambda *a, **k: _Proc(0, "")) is True
    assert dv.volume_exists("x", run=lambda *a, **k: _Proc(1, "", "no such volume")) is False
    assert dv.volume_exists("x", run=lambda *a, **k: (_ for _ in ()).throw(OSError("boom"))) is False


def test_probe_pg_password_passes_secret_by_env_not_argv():
    def run(cmd, **kw):
        if "hostname" in cmd:
            return _Proc(0, "10.1.2.3\n")
        # the psql probe: the password must NOT be on argv, must be in env, and must target the
        # container network IP (not 127.0.0.1 / the socket, which postgres trusts without a password).
        assert "SUPERSECRET" not in " ".join(cmd), "password must never appear on the psql argv"
        assert kw.get("env", {}).get("PGPASSWORD") == "SUPERSECRET", "password must be passed via env"
        assert "-h" in cmd and "10.1.2.3" in cmd, "must probe the container network IP"
        return _Proc(0, "1\n")
    assert dv.probe_pg_password("vault-db", "sftp_user", "sftp_db", "SUPERSECRET", run=run) == "ok"

    def run_fail(cmd, **kw):
        if "hostname" in cmd:
            return _Proc(0, "10.1.2.3\n")
        return _Proc(2, "", 'FATAL:  password authentication failed for user "sftp_user"')
    assert dv.probe_pg_password("vault-db", "sftp_user", "sftp_db", "x", run=run_fail) == "mismatch"
    # fail-closed on lookup failure / docker error
    assert dv.probe_pg_password("vault-db", "sftp_user", "sftp_db", "x",
                                run=lambda *a, **k: _Proc(1, "")) == "ambiguous"
    assert dv.probe_pg_password("vault-db", "sftp_user", "sftp_db", "x",
                                run=lambda *a, **k: (_ for _ in ()).throw(OSError("no docker"))) == "ambiguous"


# The coupling-stamp hooks, stubbed OUT: these tests exercise the authoritative live-probe path.
# (The stamp fast path has its own tests below.)
_NO_STAMP = dict(marker_fn=lambda vol: None, stamp_fn=lambda vol, env: True)


def _guard_tool():
    return dv.DockVault(dv.Palette(False), root=os.path.join("/", "nonexistent-dockvault-root"))


def test_guard_db_secret_fresh_volume_proceeds_without_probing():
    started = {"n": 0}
    ok = _guard_tool()._guard_db_secret(
        {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": "x"},
        exists_fn=lambda v: False,
        start_fn=lambda: started.__setitem__("n", started["n"] + 1) or True,
        wait_fn=lambda: True, probe_fn=lambda *a: "ok", stop_fn=lambda: None, **_NO_STAMP)
    assert ok is True and started["n"] == 0, "a fresh volume must proceed without starting/probing the db"


def test_guard_db_secret_match_proceeds():
    ok = _guard_tool()._guard_db_secret(
        {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": "x"},
        exists_fn=lambda v: True, start_fn=lambda: True, wait_fn=lambda: True,
        probe_fn=lambda *a: "ok", stop_fn=lambda: None, **_NO_STAMP)
    assert ok is True


def test_guard_db_secret_mismatch_refuses_without_leaking_secret(capsys):
    stopped = {"n": 0}
    ok = _guard_tool()._guard_db_secret(
        {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": "TOPSECRETPW_42"},
        exists_fn=lambda v: True, start_fn=lambda: True, wait_fn=lambda: True,
        probe_fn=lambda *a: "mismatch", stop_fn=lambda: stopped.__setitem__("n", stopped["n"] + 1), **_NO_STAMP)
    out = capsys.readouterr().out
    assert ok is False
    assert "TOPSECRETPW_42" not in out, "the diagnosis must NEVER print the secret value"
    assert "down -v" in out and "Restore" in out, "both recovery paths must be shown"
    assert "password authentication failed" in out
    assert stopped["n"] == 1, "the probe's db must be stopped on refusal"


def test_guard_db_secret_invalid_encryption_key_refuses_before_starting_db(capsys):
    started = {"n": 0}
    ok = _guard_tool()._guard_db_secret(
        {"ENCRYPTION_KEY": "not-a-fernet-key", "VAULT_DB_PASSWORD": "x"},
        exists_fn=lambda v: True,
        start_fn=lambda: started.__setitem__("n", started["n"] + 1) or True,
        wait_fn=lambda: True, probe_fn=lambda *a: "ok", stop_fn=lambda: None, **_NO_STAMP)
    out = capsys.readouterr().out
    assert ok is False and started["n"] == 0, "an invalid ENCRYPTION_KEY must be rejected before starting the db"
    assert "ENCRYPTION_KEY" in out


def test_guard_db_secret_ambiguous_when_db_never_ready(capsys):
    ok = _guard_tool()._guard_db_secret(
        {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": "x"},
        exists_fn=lambda v: True, start_fn=lambda: True, wait_fn=lambda: False,   # never ready
        probe_fn=lambda *a: "ok", stop_fn=lambda: None, **_NO_STAMP)
    out = capsys.readouterr().out
    assert ok is False and "did not become reachable" in out          # fail-closed on ambiguity


def test_container_running_reads_docker_inspect():
    assert dv.container_running("vault-db", run=lambda *a, **k: _Proc(0, "true\n")) is True
    assert dv.container_running("vault-db", run=lambda *a, **k: _Proc(0, "false\n")) is False
    assert dv.container_running("vault-db", run=lambda *a, **k: _Proc(1, "", "No such object")) is False
    assert dv.container_running(
        "vault-db", run=lambda *a, **k: (_ for _ in ()).throw(OSError("no docker"))) is False


def test_container_mounts_lists_named_volumes_and_fails_soft():
    assert dv.container_mounts(
        "vault-db", run=lambda *a, **k: _Proc(0, "dockvault-vault_vault_pg_data \n")
    ) == ["dockvault-vault_vault_pg_data"]
    assert dv.container_mounts("vault-db", run=lambda *a, **k: _Proc(0, "  \n")) == []
    # None = "could not ask", which callers must not read as "mounts nothing".
    assert dv.container_mounts("vault-db", run=lambda *a, **k: _Proc(1, "", "no such object")) is None
    assert dv.container_mounts(
        "vault-db", run=lambda *a, **k: (_ for _ in ()).throw(OSError("no docker"))) is None


def test_secret_probe_leaves_an_already_running_database_alone(monkeypatch):
    """The probe may only touch a database it started itself.

    The composes pin `container_name: vault-db` globally, so `compose stop vault-db` acts on
    whatever vault-db is on the host — including a LIVE deployment's. Stopping that took a running
    deployment's database down, and if the guard then refused, left it down. `up -d` is no better:
    under a different .env compose RECREATES the container and knocks the running app off its
    connection. A running database gets probed exactly as it stands.
    """
    tool = _guard_tool()
    calls = []
    monkeypatch.setattr(dv.DockVault, "_run_dc",
                        lambda self, *a, **k: calls.append(a) or _Proc(0))

    monkeypatch.setattr(dv, "container_running", lambda name: True)     # a live deployment
    assert tool._start_db_only() is True, "an already-running database counts as started"
    tool._stop_db_only()
    assert calls == [], \
        "the probe ran compose against a database that was already running - that is someone's " \
        f"deployment: {calls}"

    calls.clear()
    monkeypatch.setattr(dv, "container_running", lambda name: False)    # nothing was running
    tool._start_db_only()
    tool._stop_db_only()
    assert ("stop", "vault-db") in calls, "a probe-started database must still be cleaned up"


def test_refused_guard_does_not_stop_a_live_deployments_database(monkeypatch):
    """End to end through the real _start_db_only/_stop_db_only: a REFUSAL on a running deployment
    must leave the deployment running. This is the state an operator re-running setup lands in."""
    tool = _guard_tool()
    calls = []
    monkeypatch.setattr(dv.DockVault, "_run_dc",
                        lambda self, *a, **k: calls.append(a) or _Proc(0))
    monkeypatch.setattr(dv, "container_running", lambda name: True)
    # Stubbed, not left to the host: whether a real vault-db is running here, and what it mounts,
    # must not decide what this asserts.
    monkeypatch.setattr(dv, "container_mounts", lambda name: ["dockvault-vault_vault_pg_data"])
    ok = tool._guard_db_secret(
        {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": "x"},
        exists_fn=lambda v: True, wait_fn=lambda: True,     # real start_fn / stop_fn on purpose
        probe_fn=lambda *a: "mismatch", **_NO_STAMP)
    assert ok is False, "a mismatched .env must still be refused"
    assert not any(a[0] == "stop" for a in calls), \
        "the refused setup stopped the running deployment's database"


def test_probe_refuses_a_running_database_serving_a_different_volume_set(monkeypatch, capsys):
    """Leaving a running database alone must not mean probing the WRONG one.

    `container_name: vault-db` is pinned globally while the volume name varies with
    VAULT_VOLUME_PREFIX, so on a host with two sets the running container can be serving someone
    else's data. Recreating it to force the two together is exactly what must not happen here, so
    a divergence has to fail closed instead of answering a question about the wrong volume.
    """
    tool = _guard_tool()
    calls = []
    monkeypatch.setattr(dv.DockVault, "_run_dc", lambda self, *a, **k: calls.append(a) or _Proc(0))
    monkeypatch.setattr(dv, "container_running", lambda name: True)
    monkeypatch.setattr(dv, "container_mounts", lambda name: ["dockvault-vault-OTHER_vault_pg_data"])

    probes = []
    result = tool._verify_env_against_volume(
        {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": "x"},
        "dockvault-vault_vault_pg_data",
        (tool._start_db_only, lambda: True, lambda *a: probes.append(1) or "ok",
         tool._stop_db_only, lambda vol: None, lambda vol, env: True))

    assert result == "ambiguous", "a database serving another set must not answer for this one"
    assert probes == [], "the probe authenticated against another volume set's database"
    assert not any(a[0] == "stop" for a in calls), "and it must not stop that deployment either"
    assert "another volume set" in capsys.readouterr().out

    # The single-set case — same container, the volume actually being guarded — still probes.
    monkeypatch.setattr(dv, "container_mounts", lambda name: ["dockvault-vault_vault_pg_data"])
    assert tool._verify_env_against_volume(
        {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": "x"},
        "dockvault-vault_vault_pg_data",
        (tool._start_db_only, lambda: True, lambda *a: probes.append(1) or "ok",
         tool._stop_db_only, lambda vol: None, lambda vol, env: True)) == "ok"
    assert probes == [1]


def test_containers_publishing_parses_names_and_fails_soft():
    assert dv.containers_publishing(
        443, run=lambda *a, **k: _Proc(0, "vault\nvault-sftp\n")) == ["vault", "vault-sftp"]
    assert dv.containers_publishing(443, run=lambda *a, **k: _Proc(0, "\n")) == []
    # "could not ask" must be distinguishable from "nothing there", or a real conflict gets hidden.
    assert dv.containers_publishing(443, run=lambda *a, **k: _Proc(1, "", "boom")) is None
    assert dv.containers_publishing(
        443, run=lambda *a, **k: (_ for _ in ()).throw(OSError("no docker"))) is None


def test_port_preflight_ignores_the_deployments_own_container():
    """A re-run over a live deployment finds its own container on the web port — the one compose is
    about to recreate there. Warning about that sends the operator hunting for nothing; warning
    about anything else is still correct."""
    tool = _guard_tool()
    assert tool._port_is_ours(8443, ps_fn=lambda p: ["vault"]) is True         # combined
    assert tool._port_is_ours(8443, ps_fn=lambda p: ["vault-api"]) is True     # split
    assert tool._port_is_ours(8443, ps_fn=lambda p: ["nginx"]) is False        # a real conflict
    assert tool._port_is_ours(8443, ps_fn=lambda p: ["vault", "nginx"]) is False
    assert tool._port_is_ours(8443, ps_fn=lambda p: []) is False               # not docker's at all
    assert tool._port_is_ours(8443, ps_fn=lambda p: None) is False             # unknown -> still warn


def _reusable_env_cfg():
    return {
        "server_name": "localhost", "encryption_key": dv.gen_fernet_key(),
        "jwt_secret_key": dv.gen_hex(32), "vault_db_password": dv.gen_hex(16),
        "redis_password": dv.gen_hex(24), "admin_username": "admin",
        "admin_email": "a@example.com", "admin_password": "Strong-Pass-1234", "compose_profiles": "combined",
    }


def test_setup_stops_and_does_not_start_when_guard_refuses(tmp_path, monkeypatch):
    # The guard->STOP wiring runs only on a REAL start (after the --no-start early return), so drive
    # setup() directly with a reusable .env and the guard forced to refuse: setup must raise
    # SystemExit(1) and NEVER start the stack (the core footgun-closing behaviour).
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "_cert_pair_present", lambda *a, **k: True)       # skip cert generation
    monkeypatch.setattr(dv, "apply_cert_owner", lambda *a, **k: (True, ""))    # no real chown/icacls
    monkeypatch.setattr(dv, "cert_readable_by_app_uid", lambda *a, **k: True)  # no real docker probe
    started = []
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: started.append(1) or True)
    monkeypatch.setattr(tool, "_guard_db_secret", lambda env, **k: False)      # guard refuses
    with pytest.raises(SystemExit) as exc:
        tool.setup(argparse.Namespace(no_start=False, non_interactive=True))
    assert exc.value.code == 1
    assert started == [], "setup MUST NOT start the stack when the secret guard refuses"


def test_setup_proceeds_to_start_when_guard_passes(tmp_path, monkeypatch):
    # Mirror: when the guard passes, setup proceeds to start the stack.
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "_cert_pair_present", lambda *a, **k: True)
    monkeypatch.setattr(dv, "apply_cert_owner", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "cert_readable_by_app_uid", lambda *a, **k: True)  # no real docker probe
    monkeypatch.setattr(tool, "_guard_db_secret", lambda env, **k: True)       # guard passes
    started = []
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: started.append(1) or True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    tool.setup(argparse.Namespace(no_start=False, non_interactive=True))
    assert started == [1], "setup must start the stack when the guard passes"


def test_flush_stdin_is_safe():
    assert dv.flush_stdin() is None            # non-TTY under pytest -> no-op, never raises


def _ask_seq(*answers):
    """Build an `ask` stand-in that returns the given answers in order (for a menu-loop test)."""
    it = iter(answers)
    return lambda *a, **k: next(it)


def test_existing_volume_menu_new_set_keeps_data(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    old = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "ask", _ask_seq("3"))               # "deploy a NEW set under a fresh name"
    assert tool._guard_db_secret(old, interactive=True, exists_fn=lambda v: True, **_NO_STAMP) is True
    new = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert new["VAULT_VOLUME_PREFIX"].startswith("dockvault-vault-")   # fresh named set (old data untouched)
    assert new["ENCRYPTION_KEY"] != old["ENCRYPTION_KEY"]              # fresh secrets
    assert (tmp_path / ".env.dockvault-vault").exists()               # previous set's .env archived aside


def test_existing_volume_menu_verify_probes_only_on_choice(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    probes = []
    hooks = dict(exists_fn=lambda v: True, start_fn=lambda: True, wait_fn=lambda: True,
                 probe_fn=lambda *a: probes.append(1) or "ok", stop_fn=lambda: None)
    monkeypatch.setattr(dv, "ask", _ask_seq("1"))               # verify -> ok -> proceed
    assert tool._guard_db_secret(env, interactive=True, **hooks, **_NO_STAMP) is True and probes == [1]
    probes.clear()
    monkeypatch.setattr(dv, "ask", _ask_seq("5"))               # cancel -> never probes
    assert tool._guard_db_secret(env, interactive=True, **hooks, **_NO_STAMP) is False and probes == []


def test_existing_volume_menu_verify_mismatch_loops_then_cancel(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "ask", _ask_seq("1", "5"))          # verify -> mismatch -> BACK to menu -> cancel
    assert tool._guard_db_secret(env, interactive=True, exists_fn=lambda v: True,
                                 start_fn=lambda: True, wait_fn=lambda: True, probe_fn=lambda *a: "mismatch",
                                 stop_fn=lambda: None, **_NO_STAMP) is False


def test_existing_volume_menu_destroy(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    calls = []
    monkeypatch.setattr(dv.subprocess, "run", lambda cmd, **k: calls.append(cmd) or _Proc(0, ""))
    monkeypatch.setattr(dv, "confirm", lambda *a, **k: True)    # confirm the destructive down -v
    monkeypatch.setattr(dv, "ask", _ask_seq("4"))
    assert tool._guard_db_secret(env, interactive=True, exists_fn=lambda v: True, **_NO_STAMP) is True
    assert any(("down" in c and "-v" in c) for c in calls), "destroy must run down -v"
    # declining loops back to the menu (then cancel); no down -v runs
    calls.clear()
    monkeypatch.setattr(dv, "confirm", lambda *a, **k: False)
    monkeypatch.setattr(dv, "ask", _ask_seq("4", "5"))
    assert tool._guard_db_secret(env, interactive=True, exists_fn=lambda v: True, **_NO_STAMP) is False
    assert not any("down" in c for c in calls), "a declined destroy must not run down -v"


def test_existing_volume_menu_point_at_env(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    other = dict(_reusable_env_cfg())
    src = tmp_path / "saved.env"
    src.write_text("\n".join(dv.build_env_lines(other)) + "\n", encoding="utf-8")
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "ask", _ask_seq("2", str(src)))     # option 2, then the path to try
    assert tool._guard_db_secret(env, interactive=True, exists_fn=lambda v: True,
                                 start_fn=lambda: True, wait_fn=lambda: True, probe_fn=lambda *a: "ok",
                                 stop_fn=lambda: None, **_NO_STAMP) is True
    installed = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert installed["ENCRYPTION_KEY"] == other["encryption_key"]     # the supplied .env was installed


def test_guard_interactive_routes_to_menu_not_autoprobe(tmp_path, monkeypatch):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    env = {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": "x"}
    called = []
    monkeypatch.setattr(tool, "_resolve_existing_volume", lambda e, vol, hooks: called.append(1) or True)
    # interactive + existing volume -> the menu (nothing probes automatically)
    assert tool._guard_db_secret(env, interactive=True, exists_fn=lambda v: True, **_NO_STAMP) is True and called == [1]
    # non-interactive -> auto-verify directly, NO menu
    called.clear()
    ok = tool._guard_db_secret(env, interactive=False, exists_fn=lambda v: True,
                               start_fn=lambda: True, wait_fn=lambda: True, probe_fn=lambda *a: "ok",
                               stop_fn=lambda: None, **_NO_STAMP)
    assert ok is True and called == []


def test_probe_pg_password_live_distinguishes_secrets():
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    import time
    vol, cont = "dvpgprobe_pgdata", "dvpgprobe_db"
    try:
        try:
            subprocess.run(["docker", "run", "-d", "--rm", "--name", cont,
                            "-e", "POSTGRES_USER=sftp_user", "-e", "POSTGRES_PASSWORD=passA_1234",
                            "-e", "POSTGRES_DB=sftp_db", "-v", "%s:/var/lib/postgresql/data" % vol,
                            "postgres:15-alpine"], check=True, capture_output=True, timeout=90)
        except (subprocess.SubprocessError, OSError) as exc:
            pytest.skip("docker daemon/image unavailable: %s" % exc)
        ready = False
        for _ in range(30):
            r = subprocess.run(["docker", "exec", cont, "pg_isready", "-U", "sftp_user", "-d", "sftp_db"],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                ready = True
                break
            time.sleep(2)
        assert ready, "throwaway postgres never became ready"
        # the SAME scram path the app uses: correct password authenticates, wrong one is a mismatch
        assert dv.probe_pg_password(cont, "sftp_user", "sftp_db", "passA_1234") == "ok"
        assert dv.probe_pg_password(cont, "sftp_user", "sftp_db", "wrongB_9999") == "mismatch"
    finally:
        subprocess.run(["docker", "rm", "-f", cont], capture_output=True, timeout=30)
        subprocess.run(["docker", "volume", "rm", "-f", vol], capture_output=True, timeout=30)


# --- volume SETS: prefix + picker (reuse / new / repoint) + reset -------------------------
def test_volume_prefix_and_set_names():
    assert dv.volume_prefix({}) == "dockvault-vault"
    assert dv.volume_prefix({"VAULT_VOLUME_PREFIX": ""}) == "dockvault-vault"       # blank -> default
    assert dv.volume_prefix({"VAULT_VOLUME_PREFIX": "dockvault-vault-a1"}) == "dockvault-vault-a1"
    names = dv.set_volume_names("dockvault-vault-a1")
    assert names["pg"] == "dockvault-vault-a1_vault_pg_data" and names["keys"] == "dockvault-vault-a1_vault_keys"
    assert set(names) == {"pg", "storage", "keys", "logs", "brand"}


def test_volume_set_prefix_and_grouping():
    assert dv.volume_set_prefix("dockvault-vault_vault_pg_data") == "dockvault-vault"
    assert dv.volume_set_prefix("dockvault-vault-b7_vault_keys") == "dockvault-vault-b7"
    assert dv.volume_set_prefix("some_other_volume") is None
    recs = [{"name": "dockvault-vault_vault_pg_data", "role": "pg", "bundle": "default"},
            {"name": "dockvault-vault-b1_vault_pg_data", "role": "pg", "bundle": "b1"},
            {"name": "dockvault-vault-b1_vault_keys", "role": "keys", "bundle": "b1"},
            {"name": "weird_name_no_match", "role": None, "bundle": "x"}]     # unparse-able name
    grouped = dict(dv.group_volumes_by_prefix(recs))
    assert set(grouped) == {"dockvault-vault", "dockvault-vault-b1", "weird_name_no_match"}
    assert len(grouped["dockvault-vault-b1"]) == 2
    assert grouped["weird_name_no_match"][0]["name"] == "weird_name_no_match"  # not dropped, keyed raw


def test_plan_volume_action():
    assert dv.plan_volume_action("reuse")["action"] == "reuse"
    new = dv.plan_volume_action("new")
    assert new["author_env"] is True and new["fresh_secrets"] is True and new["archive_current"] is True
    rep = dv.plan_volume_action("repoint")
    assert rep["requires_env"] is True and rep["guard"] is True    # repoint MUST supply a matching .env + guard
    assert dv.plan_volume_action("bogus") is None


def test_new_set_config_keeps_settings_regenerates_secrets():
    cur = {"SERVER_NAME": "v.example.com", "ADMIN_USERNAME": "boss", "COMPOSE_PROFILES": "combined",
           "ENCRYPTION_KEY": "OLD-KEY", "VAULT_DB_PASSWORD": "OLD-PW", "RUN_SFTP": "1"}
    cfg = dv.new_set_config(cur, "dockvault-vault-z9", "z9")
    assert cfg["server_name"] == "v.example.com" and cfg["admin_username"] == "boss" and cfg["run_sftp"] is True
    assert cfg["encryption_key"] != "OLD-KEY" and cfg["vault_db_password"] != "OLD-PW"   # fresh secrets
    assert cfg["volume_prefix"] == "dockvault-vault-z9" and cfg["deployment_id"] == "z9"
    env = dv.parse_env("\n".join(dv.build_env_lines(cfg)))
    assert env["VAULT_VOLUME_PREFIX"] == "dockvault-vault-z9"
    # a default prefix is NOT written (keeps the historical names)
    assert "VAULT_VOLUME_PREFIX" not in dv.parse_env("\n".join(dv.build_env_lines(dict(cfg, volume_prefix="dockvault-vault"))))


def test_archive_env_is_collision_safe(tmp_path):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    (tmp_path / ".env").write_text("A=1\n", encoding="utf-8")
    a1 = tool._archive_env("dockvault-vault")
    assert os.path.basename(a1) == ".env.dockvault-vault"
    (tmp_path / ".env").write_text("A=2\n", encoding="utf-8")
    a2 = tool._archive_env("dockvault-vault")
    assert a1 != a2 and os.path.exists(a1) and os.path.exists(a2)   # never clobbers the first archive
    assert not os.path.exists(tool._env_path())                     # both were moved aside
    assert tool._archive_env("dockvault-vault") is None             # nothing left to archive -> None


def test_volume_new_authors_fresh_set_and_archives_current(tmp_path):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    old = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    tool._volume_new(old, argparse.Namespace(non_interactive=True))
    new = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert new["VAULT_VOLUME_PREFIX"].startswith("dockvault-vault-")          # a fresh named set
    assert new["ENCRYPTION_KEY"] != old["ENCRYPTION_KEY"]                     # born with fresh secrets
    assert new["VAULT_DB_PASSWORD"] != old["VAULT_DB_PASSWORD"]
    assert new["SERVER_NAME"] == old["SERVER_NAME"]                           # non-secret settings kept
    archive = tmp_path / ".env.dockvault-vault"                              # current set's .env saved
    assert archive.exists()
    assert dv.parse_env(archive.read_text(encoding="utf-8"))["ENCRYPTION_KEY"] == old["ENCRYPTION_KEY"]


def _write_target_set(tmp_path, prefix, did):
    tcfg = dict(_reusable_env_cfg(), volume_prefix=prefix, deployment_id=did)
    (tmp_path / (".env." + prefix)).write_text("\n".join(dv.build_env_lines(tcfg)) + "\n", encoding="utf-8")
    return tcfg


def test_volume_repoint_installs_target_when_guard_passes(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    tgt = _write_target_set(tmp_path, "dockvault-vault-t1", "t1")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_guard_db_secret", lambda env, **k: True)
    monkeypatch.setattr(tool, "_stop_stack", lambda: None)
    monkeypatch.setattr(tool, "_stop_db_only", lambda: None)
    monkeypatch.setattr(dv, "list_managed_volumes",
                        lambda *a, **k: [{"name": "dockvault-vault-t1_vault_pg_data", "role": "pg", "bundle": "t1"}])
    tool._volume_repoint(dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8")),
                         argparse.Namespace(non_interactive=True, target_prefix="dockvault-vault-t1", env_source=None))
    installed = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert dv.volume_prefix(installed) == "dockvault-vault-t1"                # now points at the target set
    assert installed["ENCRYPTION_KEY"] == tgt["encryption_key"]              # the TARGET set's secrets installed
    assert (tmp_path / ".env.dockvault-vault").exists()                      # previous set's .env archived


def test_volume_repoint_restores_env_when_guard_refuses(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    cur_key = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))["ENCRYPTION_KEY"]
    _write_target_set(tmp_path, "dockvault-vault-t1", "t1")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_guard_db_secret", lambda env, **k: False)    # secret guard rejects the pairing
    monkeypatch.setattr(tool, "_stop_stack", lambda: None)
    monkeypatch.setattr(tool, "_stop_db_only", lambda: None)
    monkeypatch.setattr(dv, "list_managed_volumes",
                        lambda *a, **k: [{"name": "dockvault-vault-t1_vault_pg_data", "role": "pg", "bundle": "t1"}])
    tool._volume_repoint(dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8")),
                         argparse.Namespace(non_interactive=True, target_prefix="dockvault-vault-t1", env_source=None))
    restored = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert restored["ENCRYPTION_KEY"] == cur_key                             # original .env restored, repoint undone
    assert dv.volume_prefix(restored) == "dockvault-vault"
    assert not (tmp_path / ".env.dockvault-vault").exists()                  # archive was moved BACK, not left duplicated


def test_volume_repoint_refuses_env_naming_wrong_set(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    cur_key = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))["ENCRYPTION_KEY"]
    wrong = dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-OTHER", deployment_id="other")
    src = tmp_path / "provided.env"
    src.write_text("\n".join(dv.build_env_lines(wrong)) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "list_managed_volumes",
                        lambda *a, **k: [{"name": "dockvault-vault-t1_vault_pg_data", "role": "pg", "bundle": "t1"}])
    with pytest.raises(SystemExit):
        tool._volume_repoint(dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8")),
                             argparse.Namespace(non_interactive=True, target_prefix="dockvault-vault-t1", env_source=str(src)))
    # rejected before any archive/install -> current .env untouched
    assert dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))["ENCRYPTION_KEY"] == cur_key


def test_reset_requires_confirmation_then_down_v_and_archives(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    calls = []
    monkeypatch.setattr(dv.subprocess, "run", lambda cmd, **k: calls.append(cmd) or _Proc(0, ""))
    # unconfirmed (non-interactive) -> no teardown, .env untouched
    tool.reset(argparse.Namespace(non_interactive=True, confirm=False))
    assert not any("down" in c for c in calls), "reset must NOT run down -v without confirmation"
    assert (tmp_path / ".env").exists()
    # confirmed -> runs down -v and moves .env aside
    tool.reset(argparse.Namespace(non_interactive=True, confirm=True))
    assert any(("down" in c and "-v" in c) for c in calls), "confirmed reset must run down -v"
    assert not (tmp_path / ".env").exists()
    assert list(tmp_path.glob(".env.removed-*")), "the destroyed set's .env must be archived aside"


def test_reset_interactive_typed_confirmation(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    calls = []
    monkeypatch.setattr(dv.subprocess, "run", lambda cmd, **k: calls.append(cmd) or _Proc(0, ""))
    # interactive + WRONG typed name -> cancelled: no down -v, .env kept
    monkeypatch.setattr(dv, "ask", lambda *a, **k: "not-the-name")
    tool.reset(argparse.Namespace())        # no non_interactive attr -> interactive path
    assert not any("down" in c for c in calls) and (tmp_path / ".env").exists()
    # interactive + CORRECT typed name (the set prefix) -> teardown runs
    monkeypatch.setattr(dv, "ask", lambda *a, **k: "dockvault-vault")
    tool.reset(argparse.Namespace())
    assert any(("down" in c and "-v" in c) for c in calls)
    assert not (tmp_path / ".env").exists()


def test_reset_aborts_and_keeps_env_when_down_v_fails(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv.subprocess, "run", lambda cmd, **k: _Proc(1, "", "volume is in use"))  # down -v fails
    with pytest.raises(SystemExit):
        tool.reset(argparse.Namespace(non_interactive=True, confirm=True))
    # a FAILED teardown must NOT move the .env aside (else fresh secrets vs surviving volumes = the footgun)
    assert (tmp_path / ".env").exists() and not list(tmp_path.glob(".env.removed-*"))


def test_volume_sets_coexist_and_down_v_removes_only_current_live(tmp_path):
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    compose = tmp_path / "sets.yml"
    compose.write_text(
        'name: ${VAULT_VOLUME_PREFIX:-dvvolsets}\n'
        'services:\n'
        '  probe:\n'
        '    image: busybox\n'
        '    command: ["sh","-c","echo ok; sleep 1"]\n'
        '    volumes:\n'
        '      - vault_pg_data:/data\n'
        'volumes:\n'
        '  vault_pg_data:\n'
        '    name: ${VAULT_VOLUME_PREFIX:-dvvolsets}_vault_pg_data\n'
        '    labels:\n'
        '      com.dockvault.managed: "true"\n'
        '      com.dockvault.role: "pg"\n', encoding="utf-8")
    volA, volB = "dvvolsets-a_vault_pg_data", "dvvolsets-b_vault_pg_data"

    def dc(prefix, *args):
        env = dict(os.environ, VAULT_VOLUME_PREFIX=prefix)
        return subprocess.run(["docker", "compose", "-f", str(compose), *args],
                              env=env, capture_output=True, text=True, timeout=90)

    def exists(name):
        return subprocess.run(["docker", "volume", "inspect", name],
                              capture_output=True, timeout=20).returncode == 0
    try:
        try:
            up_a = dc("dvvolsets-a", "up", "-d")
            up_b = dc("dvvolsets-b", "up", "-d")
        except (subprocess.SubprocessError, OSError) as exc:
            pytest.skip("docker unavailable: %s" % exc)
        if up_a.returncode != 0 or up_b.returncode != 0:   # daemon/image unavailable -> skip, not fail
            pytest.skip("docker compose up failed: %s" % ((up_a.stderr or up_b.stderr) or "")[:200])
        assert exists(volA) and exists(volB), "two prefixed sets must coexist side by side"
        # down -v on set B removes ONLY B's volume; A is untouched (no cross-set data loss)
        dc("dvvolsets-b", "down", "-v")
        assert not exists(volB), "down -v must remove the current set's volume"
        assert exists(volA), "the other set must be left intact"
    finally:
        dc("dvvolsets-a", "down", "-v")
        dc("dvvolsets-b", "down", "-v")
        subprocess.run(["docker", "volume", "rm", "-f", volA, volB], capture_output=True, timeout=30)


# --- backup / restore (atomic {.env + volumes} bundle) ------------------------------------
def test_coupling_fingerprint_and_manifest_carry_no_secret():
    env = {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": dv.gen_hex(16)}
    salt = dv.gen_salt()
    fp = dv.compute_coupling_fingerprint(env, salt)
    assert len(fp) == 64 and all(c in "0123456789abcdef" for c in fp)     # sha256 hex, not the secret
    assert dv.compute_coupling_fingerprint(env, salt) == fp               # deterministic per env+salt
    assert dv.compute_coupling_fingerprint(env, dv.gen_salt()) != fp      # salted -> varies per bundle
    man = dv.build_backup_manifest("dockvault-vault-b1", "b1",
                                   [{"role": "pg", "name": "dockvault-vault-b1_vault_pg_data", "archive": "vault_pg_data.tar.gz"}],
                                   salt, env, created="20260721-000000")
    blob = json.dumps(man)
    assert env["ENCRYPTION_KEY"] not in blob and env["VAULT_DB_PASSWORD"] not in blob   # NO secret in the manifest
    assert man["volume_prefix"] == "dockvault-vault-b1" and man["bundle_id"] == "b1" and man["env_file"] == "env"


def test_verify_backup_coupling_matches_only_its_own_env():
    env = {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": dv.gen_hex(16)}
    man = dv.build_backup_manifest("p", "b", [], dv.gen_salt(), env)
    assert dv.verify_backup_coupling(env, man) is True
    assert dv.verify_backup_coupling(dict(env, ENCRYPTION_KEY=dv.gen_fernet_key()), man) is False  # swapped key
    assert dv.verify_backup_coupling(dict(env, VAULT_DB_PASSWORD="other"), man) is False           # swapped pw
    assert dv.verify_backup_coupling(env, {}) is False                                             # no coupling
    assert dv.verify_backup_coupling(env, {"coupling": {"salt": "", "sha256": ""}}) is False


def _write_bundle(tmp_path, cfg, entries, env_override=None, name="bundle"):
    bundle = tmp_path / name
    bundle.mkdir(exist_ok=True)
    env_text = "\n".join(dv.build_env_lines(cfg)) + "\n"
    (bundle / "env").write_text(env_text, encoding="utf-8")
    manifest_env = dv.parse_env(env_text) if env_override is None else env_override
    man = dv.build_backup_manifest(cfg.get("volume_prefix", "dockvault-vault"),
                                   cfg.get("deployment_id", "default"), entries, dv.gen_salt(), manifest_env)
    (bundle / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
    return bundle


def test_restore_refuses_mismatched_env(tmp_path):
    # manifest coupling is built from env A, but the bundle's `env` file is a DIFFERENT env -> refuse.
    cfg = dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-r1", deployment_id="r1")
    other = {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": dv.gen_hex(16)}
    bundle = _write_bundle(tmp_path, cfg, [], env_override=other)   # manifest fingerprints `other`, env file is cfg
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    with pytest.raises(SystemExit):
        tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(bundle), force=False))


def test_valid_volume_prefix():
    assert dv.valid_volume_prefix("dockvault-vault") and dv.valid_volume_prefix("dockvault-vault-a1")
    assert not dv.valid_volume_prefix("")
    assert not dv.valid_volume_prefix("/etc")            # slash -> reject (bind-mount redirection)
    assert not dv.valid_volume_prefix("../evil")
    assert not dv.valid_volume_prefix("a b")             # space
    assert not dv.valid_volume_prefix("-leading")        # must start alnum (docker's own rule)


def test_restore_rejects_crafted_manifest(tmp_path, monkeypatch):
    # a hostile bundle can't redirect the restore's -v mount or inject via the archive name: restore
    # reconstructs names/archives from the validated prefix + a known role, never from manifest strings.
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: False)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    # (1) hostile prefix "/etc" -> refused before any docker call
    b1 = _write_bundle(tmp_path, dict(_reusable_env_cfg(), volume_prefix="/etc", deployment_id="x"),
                       [{"role": "pg", "name": "/etc", "archive": "a.tgz; rm -rf /"}], name="b1")
    with pytest.raises(SystemExit):
        tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(b1), force=False))
    # (2) unknown volume role -> refused even with a valid prefix
    b2 = _write_bundle(tmp_path, dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-ok", deployment_id="x"),
                       [{"role": "evil", "name": "n", "archive": "a"}], name="b2")
    with pytest.raises(SystemExit):
        tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(b2), force=False))


def test_restore_refuses_incomplete_bundle(tmp_path):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "manifest.json").write_text("{}", encoding="utf-8")   # no `env` file alongside
    with pytest.raises(SystemExit):
        tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(bundle), force=False))


def test_verify_backup_coupling_tolerates_malformed_manifest():
    env = {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": dv.gen_hex(16)}
    for bad in ("hello", 5, [1, 2], None, {"coupling": "x"}, {"coupling": 5}, {"coupling": {}}):
        assert dv.verify_backup_coupling(env, bad) is False, "a malformed manifest must be a clean False, not a crash"


def test_restore_refuses_missing_archive(tmp_path, monkeypatch):
    # a bundle whose manifest is well-formed and coupled, valid prefix + known role, but with the
    # actual tar.gz missing -> refuse (don't restore a half-bundle).
    cfg = dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-r3", deployment_id="r3")
    entries = [{"role": "pg", "name": "dockvault-vault-r3_vault_pg_data", "archive": "vault_pg_data.tar.gz"}]
    bundle = _write_bundle(tmp_path, cfg, entries, name="b3")     # _write_bundle does NOT create the tar.gz
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: False)   # not clobbering
    with pytest.raises(SystemExit):
        tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(bundle), force=False))


def test_backup_aborts_and_removes_partial_on_tar_failure(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(
        dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-fail", deployment_id="f"))) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: name.endswith("_vault_pg_data"))
    monkeypatch.setattr(dv, "tar_volume", lambda *a, **k: False)        # archiving fails
    with pytest.raises(SystemExit):
        tool._do_backup(dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8")),
                        argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups")))
    # the partial, secret-bearing bundle (it holds a copy of .env) must be gone - no manifest left behind
    assert not list((tmp_path / "backups").glob("dockvault-*")), "a failed backup must leave no partial bundle"


def test_restore_refuses_clobbering_existing_volumes(tmp_path, monkeypatch):
    cfg = dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-r2", deployment_id="r2")
    entries = [{"role": "pg", "name": "dockvault-vault-r2_vault_pg_data", "archive": "vault_pg_data.tar.gz"}]
    bundle = _write_bundle(tmp_path, cfg, entries)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: True)   # the target volume already exists
    with pytest.raises(SystemExit):    # refuse without --force (coupling passes, but won't clobber)
        tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(bundle), force=False))


def test_backup_writes_env_600_and_manifest_without_secret(tmp_path, monkeypatch):
    # unit-level backup (no docker): stub tar + volume_exists so only the .env-copy + manifest run.
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(
        dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-b9", deployment_id="b9"))) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: name.endswith("_vault_pg_data"))  # only pg present
    monkeypatch.setattr(dv, "tar_volume", lambda *a, **k: True)
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    tool._do_backup(env, argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups")))
    bundles = list((tmp_path / "backups").glob("dockvault-dockvault-vault-b9-*"))
    assert len(bundles) == 1
    bundle = bundles[0]
    man = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert [e["role"] for e in man["volumes"]] == ["pg"]     # only the existing volume recorded
    assert env["ENCRYPTION_KEY"] not in json.dumps(man)       # no secret in the manifest
    assert (bundle / "env").exists()                          # the paired .env is copied in
    if os.name != "nt":
        assert (os.stat(bundle / "env").st_mode & 0o077) == 0, "the backup .env must be mode-600"
        assert (os.stat(bundle).st_mode & 0o077) == 0, "the bundle dir must be owner-only (0700)"


def test_backup_restore_round_trip_live(tmp_path):
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    prefix = "dvbaklive"
    cfg = dict(_reusable_env_cfg(), volume_prefix=prefix, deployment_id="live")
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(cfg)) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    names = dv.set_volume_names(prefix)
    vols = [names["pg"], names["storage"], names["keys"]]

    def run(*a):
        return subprocess.run(list(a), capture_output=True, text=True, timeout=90)
    try:
        try:
            for v in vols:
                run("docker", "volume", "create", v)
            seed = run("docker", "run", "--rm", "-v", names["keys"] + ":/d", "busybox",
                       "sh", "-c", "echo SECRET-DATA-42 > /d/marker.txt")
            if seed.returncode != 0:
                pytest.skip("docker run unavailable: %s" % seed.stderr[:120])
        except (subprocess.SubprocessError, OSError) as exc:
            pytest.skip("docker unavailable: %s" % exc)
        backup_dir = tmp_path / "backups"
        tool._do_backup(dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8")),
                        argparse.Namespace(non_interactive=True, backup_dir=str(backup_dir)))
        bundles = list(backup_dir.glob("dockvault-%s-*" % prefix))
        assert len(bundles) == 1
        bundle = bundles[0]
        assert cfg["encryption_key"] not in (bundle / "manifest.json").read_text(encoding="utf-8")
        # simulate a down -v: destroy the volumes, then restore
        for v in vols:
            run("docker", "volume", "rm", "-f", v)
        assert not any(dv.volume_exists(v) for v in vols)
        tool._do_restore(argparse.Namespace(non_interactive=True, bundle_dir=str(bundle), force=False))
        got = run("docker", "run", "--rm", "-v", names["keys"] + ":/d:ro", "busybox", "cat", "/d/marker.txt")
        assert "SECRET-DATA-42" in got.stdout, "the restored volume must contain the original file"
        assert (tmp_path / ".env").exists()          # the paired .env was installed
    finally:
        for v in vols:
            run("docker", "volume", "rm", "-f", v)


# --- update + logs helpers ----------------------------------------------------------------
def test_update_version_helpers():
    assert dv.parse_semver("v0.6.0") == (0, 6, 0) and dv.parse_semver("1.2.3-rc1") == (1, 2, 3)
    assert dv.parse_semver("nightly") is None and dv.parse_semver("") is None
    assert dv.compare_semver("v0.6.0", "v0.5.9") == 1 and dv.compare_semver("v0.5.0", "v0.6.0") == -1
    assert dv.compare_semver("1.0.0", "v1.0.0") == 0
    assert dv.is_downgrade("v0.6.0", "v0.5.0") and not dv.is_downgrade("v0.5.0", "v0.6.0")
    assert not dv.is_downgrade("unknown", "v0.6.0") and not dv.is_downgrade("v0.6.0", "unknown")
    data = [{"tag_name": "v0.6.0"}, {"tag_name": "v0.5.4"}, {"tag_name": "nightly"},
            {"tag_name": "v0.6.0"}, {"nope": 1}, "junk"]
    assert dv.parse_releases(data) == ["v0.6.0", "v0.5.4"]         # newest-first, semver-only, de-duped
    assert dv.parse_releases("nope") == [] and dv.parse_releases(None) == []
    # fail-closed to [] on a network/parse error; parse on success
    assert dv.fetch_release_tags(fetch=lambda u: (_ for _ in ()).throw(OSError("no net"))) == []
    assert dv.fetch_release_tags(fetch=lambda u: data) == ["v0.6.0", "v0.5.4"]


def test_read_version_file(tmp_path):
    assert dv.read_version_file(str(tmp_path)) == "unknown"
    (tmp_path / "VERSION").write_text("0.6.0\n", encoding="utf-8")
    assert dv.read_version_file(str(tmp_path)) == "0.6.0"


def test_logs_enable_opts_in_plan_and_pepper(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    recreated = []
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: recreated.append(build) or True)
    tool.logs(argparse.Namespace(non_interactive=True, enable=True))
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert env["PLAN_LOG_PULL"] == "true" and len(env.get("LOG_TOKEN_PEPPER", "")) >= 32
    assert recreated == [False], "an env-only change must recreate WITHOUT --build (no image clobber)"


def test_logs_without_enable_changes_nothing(tmp_path, monkeypatch):
    # the guided helper must ONLY guide opt-in - opting out leaves the (default-off) exposure untouched.
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    before = (tmp_path / ".env").read_text(encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    tool.logs(argparse.Namespace(non_interactive=True, enable=False))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == before, "logs opt-out must not touch .env"


def test_update_cancels_without_a_tag(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    (tmp_path / "VERSION").write_text("0.6.0\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "fetch_release_tags", lambda *a, **k: [])
    started = []
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: started.append(1) or True)
    tool.update(argparse.Namespace(non_interactive=True, tag=None, source=False, yes=False))
    assert started == [], "update with no tag must not recreate the stack"


def test_update_from_source_checks_out_and_recreates(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    (tmp_path / "VERSION").write_text("0.6.0\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    calls = []
    monkeypatch.setattr(dv.subprocess, "run", lambda cmd, **k: calls.append(cmd) or _Proc(0, ""))
    started = []
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: started.append(1) or True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    # a downgrade, explicitly confirmed via --yes, built from source
    tool.update(argparse.Namespace(non_interactive=True, tag="v0.5.0", source=True, yes=True))
    assert any(("checkout" in c and "v0.5.0" in c) for c in calls), "must git checkout the chosen tag"
    assert started == [1]


def test_update_pull_path_sets_image_and_recreates_without_build(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    (tmp_path / "VERSION").write_text("0.6.0\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    calls = []
    monkeypatch.setattr(dv.subprocess, "run", lambda cmd, **k: calls.append(cmd) or _Proc(0, ""))
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    tool.update(argparse.Namespace(non_interactive=True, tag="v0.7.0", source=False, yes=True))  # upgrade, pull
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert env["DOCKVAULT_IMAGE"] == "ghcr.io/dockvault/vault:v0.7.0"
    assert any("pull" in c for c in calls), "pull path must 'docker compose pull'"
    recreate = [c for c in calls if "up" in c]
    assert recreate and all("--build" not in c for c in recreate), \
        "the pull path must recreate WITHOUT --build (else it clobbers the pulled image)"


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


# --- docker compose must never block on an invisible prompt -----------------------------------
def test_compose_calls_close_stdin(tmp_path, monkeypatch):
    """Every `docker compose` invocation runs with stdin CLOSED.

    Compose asks a BLOCKING yes/no on stdin when an existing volume's labels don't match the compose
    file ("Volume X exists but doesn't match configuration in compose file. Recreate (data will be
    lost)?"). With stdin inherited that prompt hangs the tool - and with the output captured it is
    also INVISIBLE, so the operator sees a frozen screen and a stray 'y' would destroy the data
    volume. DEVNULL makes Compose take its safe default (keep the volume)."""
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    seen = []
    monkeypatch.setattr(dv.subprocess, "run",
                        lambda cmd, **k: seen.append((cmd, k)) or _Proc(0, ""))
    # Nothing already running, so the probe issues its compose calls for real. Stubbed rather than
    # left to the host: whether a vault-db happens to exist here must not decide what this asserts.
    monkeypatch.setattr(dv, "container_running", lambda name: False)
    tool._start_db_only()
    tool._stop_db_only()
    tool._stop_stack()
    tool._recreate_stack(build=True)
    assert seen, "no compose call was made"
    for cmd, kw in seen:
        assert cmd[:2] == ["docker", "compose"]
        assert kw.get("stdin") is dv.subprocess.DEVNULL, \
            "%s ran with stdin open - Compose could block on an unseen prompt" % " ".join(cmd[:4])


def test_start_db_only_streams_so_docker_errors_are_visible(tmp_path, monkeypatch):
    """The db-only start must NOT capture output: Compose's own progress/errors are the operator's
    only diagnosis when it fails, and a captured stream is what made the prompt invisible."""
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    seen = {}
    monkeypatch.setattr(dv.subprocess, "run", lambda cmd, **k: seen.update(k) or _Proc(1, ""))
    monkeypatch.setattr(dv, "container_running", lambda name: False)   # host-independent
    assert tool._start_db_only() is False                      # non-zero exit is reported honestly
    assert seen.get("capture_output") is not True, "compose output must reach the terminal"


def test_wait_db_ready_reports_progress_and_closes_stdin(tmp_path, monkeypatch):
    import time as _t
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    seen = []
    monkeypatch.setattr(dv.subprocess, "run", lambda cmd, **k: seen.append(k) or _Proc(1, ""))
    monkeypatch.setattr(_t, "sleep", lambda *_a: None)
    ticks = []
    assert tool._wait_db_ready(tries=3, tick=ticks.append) is False
    assert len(ticks) == 3, "each poll must report progress so a 40s wait never looks frozen"
    assert all(k.get("stdin") is dv.subprocess.DEVNULL for k in seen)


def test_waiting_tick_prints_only_every_ten_seconds(capsys):
    tool = dv.DockVault(dv.Palette(False))
    for s in (0, 2, 4, 6, 8, 10, 12, 20):
        tool._waiting_tick(s)
    out = capsys.readouterr().out
    assert out.count("still waiting") == 2 and "(10s)" in out and "(20s)" in out


# --- failures show the logs instead of a bare "check the logs" --------------------------------
def test_tail_logs_prints_container_output(tmp_path, monkeypatch, capsys):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    cmds = []
    monkeypatch.setattr(dv.subprocess, "run",
                        lambda cmd, **k: cmds.append(cmd) or _Proc(0, "PermissionError: [Errno 13]"))
    tool._tail_logs("vault-api", lines=25)
    out = capsys.readouterr().out
    assert "PermissionError" in out, "the operator must see the actual failure, not a pointer to it"
    assert cmds and "logs" in cmds[0] and "vault-api" in cmds[0] and "25" in cmds[0]


def test_web_service_per_profile():
    assert dv.DockVault._web_service("split") == "vault-api"
    assert dv.DockVault._web_service("combined") == "vault"
    assert dv.DockVault._web_service(None) == "vault"


def test_setup_tails_logs_and_fails_when_the_stack_does_not_start(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "_cert_pair_present", lambda *a, **k: True)
    monkeypatch.setattr(dv, "apply_cert_owner", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "cert_readable_by_app_uid", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_guard_db_secret", lambda env, **k: True)
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: False)            # the stack fails
    tailed = []
    monkeypatch.setattr(tool, "_tail_logs", lambda svc=None, lines=40: tailed.append(svc))
    with pytest.raises(SystemExit):
        tool.setup(argparse.Namespace(no_start=False, non_interactive=True))
    assert tailed == ["vault"], "a failed start must surface the failing container's logs"


# --- the TLS key must be readable by the container's app user ---------------------------------
def test_cert_readable_probe_classifies_docker_failure_as_undetermined(monkeypatch):
    monkeypatch.setattr(dv.shutil, "which", lambda *_a: "/usr/bin/docker")
    assert dv.cert_readable_by_app_uid("/c", run=lambda *a, **k: _Proc(0)) is True
    assert dv.cert_readable_by_app_uid("/c", run=lambda *a, **k: _Proc(1)) is False
    for rc in (125, 126, 127):     # docker itself failed -> "unknown", never a permission verdict
        assert dv.cert_readable_by_app_uid("/c", run=lambda *a, **k: _Proc(rc)) is None
    assert dv.cert_readable_by_app_uid(
        "/c", run=lambda *a, **k: (_ for _ in ()).throw(OSError("boom"))) is None
    monkeypatch.setattr(dv.shutil, "which", lambda *_a: None)
    assert dv.cert_readable_by_app_uid("/c") is None            # no docker -> undetermined


def test_cert_probe_never_emits_key_bytes(monkeypatch, capsys):
    """Even if the probe container somehow emitted key material, none of it may reach the operator's
    screen or the return value: the verdict comes from the exit code alone."""
    monkeypatch.setattr(dv.shutil, "which", lambda *_a: "docker")
    secret = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----"
    seen = {}
    out = dv.cert_readable_by_app_uid(
        "/c", run=lambda cmd, **k: seen.update(cmd=cmd) or _Proc(0, secret, secret))
    assert out is True                                    # the verdict, never the bytes
    printed = capsys.readouterr()
    assert secret not in printed.out and secret not in printed.err
    script = seen["cmd"][-1]                              # and the container discards them at source
    assert ">/dev/null" in script and "head -c 1" in script


def test_apply_cert_owner_on_windows_repairs_via_container(monkeypatch):
    """openssl writes key.pem mode 600 owned by uid 0; on a Docker Desktop bind mount the host has
    no chown that can hand it to uid 10001, so the repair must run INSIDE a container - and the
    result must be verified, never assumed (the old code returned 'ok' without checking, which
    surfaced as an endless restart loop)."""
    monkeypatch.setattr(dv.os, "name", "nt")
    monkeypatch.setattr(dv.shutil, "which", lambda *_a: "docker")
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        joined = " ".join(cmd)
        if "chown" in joined:
            return _Proc(0)
        # unreadable until the chown has run
        repaired = any("chown" in " ".join(c) for c in calls[:-1])
        return _Proc(0) if repaired else _Proc(1)

    ok, msg = dv.apply_cert_owner("/certs", run=fake_run)
    assert ok is True and "re-owned" in msg
    assert any("chown 10001:10001" in " ".join(c) for c in calls)


def test_apply_cert_owner_on_windows_reports_failure_honestly(monkeypatch):
    monkeypatch.setattr(dv.os, "name", "nt")
    monkeypatch.setattr(dv.shutil, "which", lambda *_a: "docker")
    ok, msg = dv.apply_cert_owner("/certs", run=lambda *a, **k: _Proc(1))   # never readable
    assert ok is False and "PermissionError" in msg and "re-run setup" in msg


def test_setup_refuses_to_start_with_an_unreadable_key(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "_cert_pair_present", lambda *a, **k: True)
    monkeypatch.setattr(dv, "apply_cert_owner", lambda *a, **k: (False, "unreadable"))
    monkeypatch.setattr(dv, "cert_readable_by_app_uid", lambda *a, **k: False)
    started = []
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: started.append(1) or True)
    monkeypatch.setattr(tool, "_guard_db_secret", lambda env, **k: True)
    # Keep it hermetic: without these, REVERTING the gate makes this test fall through into the
    # real health poll (minutes of live docker traffic) instead of failing fast.
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: False)
    monkeypatch.setattr(tool, "_tail_logs", lambda *a, **k: False)
    with pytest.raises(SystemExit) as exc:
        tool.setup(argparse.Namespace(no_start=False, non_interactive=True))
    assert exc.value.code == 1 and started == [], \
        "an unreadable TLS key must fail BEFORE the start, not become a restart loop"


@pytest.mark.skipif(shutil.which("docker") is None, reason="needs a live docker engine")
def test_cert_readability_probe_and_repair_roundtrip(tmp_path):
    """Live: a mode-600 root-owned key really IS unreadable to uid 10001, and the container-side
    repair really does fix it (the exact mechanism behind the reported restart loop)."""
    d = tmp_path / "certs"
    d.mkdir()
    mount = str(d).replace("\\", "/")
    seed = subprocess.run(
        ["docker", "run", "--rm", "-v", "%s:/c" % mount, "busybox", "sh", "-c",
         "echo c > /c/cert.pem; echo k > /c/key.pem; chmod 644 /c/cert.pem; chmod 600 /c/key.pem; "
         "chown 0:0 /c/cert.pem /c/key.pem"], capture_output=True, text=True, timeout=300)
    if seed.returncode != 0:
        pytest.skip("could not seed the cert dir: %s" % seed.stderr.strip()[:120])
    assert dv.cert_readable_by_app_uid(str(d)) is False, "a root-owned 0600 key must read as DENIED"
    assert dv._chown_certs_in_container(str(d)) is True
    assert dv.cert_readable_by_app_uid(str(d)) is True, "the container-side chown must fix it"


# --- the instant coupling stamp ---------------------------------------------------------------
def test_coupling_marker_verdict_confirms_only():
    env = dv.parse_env("\n".join(dv.build_env_lines(_reusable_env_cfg())))
    salt = dv.gen_salt()
    good = {"salt": salt, "sha256": dv.compute_coupling_fingerprint(env, salt)}
    assert dv.coupling_marker_verdict({"coupling": good}, env) == "ok"
    # a stale/absent/garbled stamp is "unknown" (None) - never a refusal, because a rotated DB
    # password would otherwise lock the operator out of their own data.
    assert dv.coupling_marker_verdict(None, env) is None
    assert dv.coupling_marker_verdict({}, env) is None
    assert dv.coupling_marker_verdict({"coupling": {"salt": salt, "sha256": "0" * 64}}, env) is None
    other = dv.parse_env("\n".join(dv.build_env_lines(_reusable_env_cfg())))
    assert dv.coupling_marker_verdict({"coupling": good}, other) is None


def test_coupling_marker_carries_no_secret():
    env = dv.parse_env("\n".join(dv.build_env_lines(_reusable_env_cfg())))
    seen = {}
    dv.write_volume_coupling("vol", env, run=lambda cmd, **k: seen.update(cmd=cmd, kw=k) or _Proc(0))
    blob = " ".join(seen["cmd"]) + str(seen["kw"].get("input"))
    assert env["ENCRYPTION_KEY"] not in blob and env["VAULT_DB_PASSWORD"] not in blob
    assert '"sha256"' in seen["kw"]["input"], "the stamp is written over stdin, not argv"


def test_read_volume_coupling_soft_fails():
    assert dv.read_volume_coupling("v", run=lambda *a, **k: _Proc(1, "")) is None
    assert dv.read_volume_coupling("v", run=lambda *a, **k: _Proc(0, "not json")) is None
    assert dv.read_volume_coupling("v", run=lambda *a, **k: _Proc(0, "[1,2]")) is None
    assert dv.read_volume_coupling("v", run=lambda *a, **k: _Proc(0, '{"salt":"a"}')) == {"salt": "a"}
    assert dv.read_volume_coupling(
        "v", run=lambda *a, **k: (_ for _ in ()).throw(OSError("x"))) is None


def test_read_volume_coupling_never_creates_a_stray_volume():
    """`docker run -v <name>:...` CREATES a missing volume, so the stamp read must check existence
    first - the menu can ask about a set that has never been deployed."""
    cmds = []

    def run(cmd, **k):
        cmds.append(cmd)
        return _Proc(1, "") if "inspect" in cmd else _Proc(0, "{}")

    assert dv.read_volume_coupling("never-deployed", run=run) is None
    assert all("run" not in c for c in cmds), "no `docker run` may touch a volume that doesn't exist"


def test_stamped_volume_verifies_without_starting_the_database(tmp_path, capsys):
    """The reported pain: 'must I really wait 20-40s to learn whether this .env matches?' - a
    stamped set answers instantly and never touches the database."""
    env = dv.parse_env("\n".join(dv.build_env_lines(_reusable_env_cfg())))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    salt = dv.gen_salt()
    marker = {"coupling": {"salt": salt, "sha256": dv.compute_coupling_fingerprint(env, salt)}}
    started = []
    ok = tool._guard_db_secret(
        env, exists_fn=lambda v: True,
        start_fn=lambda: started.append(1) or True, wait_fn=lambda: True,
        probe_fn=lambda *a: "ok", stop_fn=lambda: None,
        marker_fn=lambda vol: marker, stamp_fn=lambda vol, e: True)
    assert ok is True and started == [], "a stamped set must NOT start the database"
    assert "no database start needed" in capsys.readouterr().out


def test_live_probe_stamps_the_volume_so_the_next_check_is_instant(tmp_path):
    env = dv.parse_env("\n".join(dv.build_env_lines(_reusable_env_cfg())))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    stamped = []
    assert tool._guard_db_secret(
        env, exists_fn=lambda v: True, start_fn=lambda: True, wait_fn=lambda: True,
        probe_fn=lambda *a: "ok", stop_fn=lambda: None,
        marker_fn=lambda vol: None, stamp_fn=lambda vol, e: stamped.append(vol) or True) is True
    assert stamped == ["dockvault-vault_vault_pg_data"]


def test_a_mismatched_set_is_never_stamped(tmp_path):
    env = dv.parse_env("\n".join(dv.build_env_lines(_reusable_env_cfg())))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    stamped = []
    assert tool._guard_db_secret(
        env, exists_fn=lambda v: True, start_fn=lambda: True, wait_fn=lambda: True,
        probe_fn=lambda *a: "mismatch", stop_fn=lambda: None,
        marker_fn=lambda vol: None, stamp_fn=lambda vol, e: stamped.append(vol) or True) is False
    assert stamped == [], "only a CONFIRMED pairing may be stamped"


def test_unbuffer_stdout_is_best_effort():
    class _NoReconfigure:
        pass
    assert dv.unbuffer_stdout(_NoReconfigure()) is False       # never raises on an odd stdout
    assert dv.unbuffer_stdout(io.TextIOWrapper(io.BytesIO())) is True


# --- review follow-ups -------------------------------------------------------------------------
def _capture_stamp(env, salt=None):
    """Run the REAL writer and return the marker document it actually put in the volume."""
    seen = {}

    def run(cmd, **k):
        seen.update(cmd=cmd, kw=k)
        return _Proc(0, "")

    assert dv.write_volume_coupling("vol", env, salt=salt, run=run) is True
    return json.loads(seen["kw"]["input"])


def test_coupling_stamp_round_trips_writer_to_verdict():
    """The bug this test exists for: the writer emitted a FLAT {salt, sha256} document while the
    verifier read a NESTED {"coupling": {...}} one, so a stamp the tool wrote could never confirm
    anything and the whole 'instant' path was dead code - while every hand-built-marker test stayed
    green. Never hand-build the marker here: take whatever the writer actually produces."""
    env = dv.parse_env("\n".join(dv.build_env_lines(_reusable_env_cfg())))
    marker = _capture_stamp(env)
    assert dv.coupling_marker_verdict(marker, env) == "ok"
    other = dv.parse_env("\n".join(dv.build_env_lines(_reusable_env_cfg())))
    assert dv.coupling_marker_verdict(marker, other) is None


def test_coupling_stamp_round_trips_through_the_volume_reader():
    """Full chain: writer payload -> read_volume_coupling's parse -> verdict."""
    env = dv.parse_env("\n".join(dv.build_env_lines(_reusable_env_cfg())))
    payload = json.dumps(_capture_stamp(env))

    def run(cmd, **k):
        return _Proc(0, "") if "inspect" in cmd else _Proc(0, payload)

    assert dv.coupling_marker_verdict(dv.read_volume_coupling("vol", run=run), env) == "ok"


def test_setup_flow_uses_the_stamp_it_just_wrote(tmp_path, capsys):
    """End to end through the guard: the first check probes the DB and stamps; a second check with
    that same stamp in place is instant and never starts the database."""
    env = dv.parse_env("\n".join(dv.build_env_lines(_reusable_env_cfg())))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    store = {}
    hooks = dict(exists_fn=lambda v: True, wait_fn=lambda: True, probe_fn=lambda *a: "ok",
                 stop_fn=lambda: None,
                 marker_fn=lambda vol: store.get(vol),
                 stamp_fn=lambda vol, e: store.__setitem__(vol, dv.build_coupling_marker(e)) or True)
    starts = []
    assert tool._guard_db_secret(env, start_fn=lambda: starts.append(1) or True, **hooks) is True
    assert starts == [1] and store, "the first check must probe the live DB and leave a stamp"
    assert tool._guard_db_secret(env, start_fn=lambda: starts.append(1) or True, **hooks) is True
    assert starts == [1], "the second check must be answered by the stamp alone"
    assert "no database start needed" in capsys.readouterr().out


def test_write_volume_coupling_never_creates_a_stray_volume():
    cmds = []

    def run(cmd, **k):
        cmds.append(cmd)
        return _Proc(1, "") if "inspect" in cmd else _Proc(0, "")

    env = dv.parse_env("\n".join(dv.build_env_lines(_reusable_env_cfg())))
    assert dv.write_volume_coupling("never-deployed", env, run=run) is False
    assert all("run" not in c for c in cmds)


def test_undetermined_cert_probe_is_not_reported_as_denied(monkeypatch):
    """A stopped Docker engine must never be diagnosed as 'the key is unreadable - delete certs/':
    that talks an operator into destroying a bring-your-own or Let's Encrypt pair."""
    monkeypatch.setattr(dv.os, "name", "nt")
    monkeypatch.setattr(dv.shutil, "which", lambda *_a: "docker")
    ok, msg = dv.apply_cert_owner("/certs", run=lambda *a, **k: _Proc(125, "", "cannot connect"))
    assert ok is False
    assert "did not answer" in msg and "untouched" in msg
    assert "delete" not in msg.lower(), "undetermined must not carry destructive advice"
    # ...while a PROVEN denial still gets the actionable message.
    _, denied = dv.apply_cert_owner("/certs", run=lambda *a, **k: _Proc(1))
    assert "PermissionError" in denied


def test_docker_absent_leaves_certs_undetermined_not_denied(monkeypatch):
    monkeypatch.setattr(dv.os, "name", "nt")
    monkeypatch.setattr(dv.shutil, "which", lambda *_a: None)     # no docker at all
    ok, msg = dv.apply_cert_owner("/certs")
    assert ok is False and "did not answer" in msg and "delete" not in msg.lower()


def test_tail_logs_reports_whether_anything_was_shown(tmp_path, monkeypatch, capsys):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv.subprocess, "run", lambda cmd, **k: _Proc(0, "   \n  "))
    assert tool._tail_logs("vault") is False, "empty output must not count as 'logs shown'"
    assert "end of logs" not in capsys.readouterr().out
    monkeypatch.setattr(dv.subprocess, "run", lambda cmd, **k: _Proc(0, "boom"))
    assert tool._tail_logs("vault") is True


def test_tail_logs_falls_back_to_the_whole_stack(tmp_path, monkeypatch):
    """A build failure never creates the named container, so a per-service tail is empty - fall back
    to the stack rather than printing nothing."""
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    cmds = []

    def run(cmd, **k):
        cmds.append(cmd)
        return _Proc(0, "") if "vault-api" in cmd else _Proc(0, "stack-wide failure")

    monkeypatch.setattr(dv.subprocess, "run", run)
    assert tool._tail_logs("vault-api") is True
    assert len(cmds) == 2 and "vault-api" not in cmds[1]


def test_setup_does_not_claim_logs_are_above_when_there_are_none(tmp_path, monkeypatch, capsys):
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(_reusable_env_cfg())) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "_cert_pair_present", lambda *a, **k: True)
    monkeypatch.setattr(dv, "apply_cert_owner", lambda *a, **k: (True, ""))
    monkeypatch.setattr(dv, "cert_readable_by_app_uid", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_guard_db_secret", lambda env, **k: True)
    monkeypatch.setattr(tool, "_start_secure_stack", lambda: False)
    monkeypatch.setattr(tool, "_tail_logs", lambda *a, **k: False)      # nothing to show
    with pytest.raises(SystemExit):
        tool.setup(argparse.Namespace(no_start=False, non_interactive=True))
    out = capsys.readouterr().out
    assert "log lines are above" not in out and "docker output above" in out
