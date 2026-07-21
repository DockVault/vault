"""Unit tests for the host-side management tool (dockvault.py).

Loaded by file path (the module is pure stdlib — no app imports), so these run without a live
instance and never touch Docker: the tested surface is the pure colour/prompt/menu/step-tracker
logic + the arg-mode routing. A subprocess smoke covers --help."""
import importlib.util
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
