#!/usr/bin/env python3
"""DockVault management tool — interactive, menu-driven ops for a self-hosted vault.

Run with NO arguments for the interactive menu:

    python dockvault.py

  Setup            configure + start the vault (writes .env, certs, brings the stack up)
  Backup & Restore snapshot / restore the volume set + .env as one bundle
  Volumes          inspect / reuse / repoint DockVault-managed volume sets
  Reset            tear down (optionally destroy data)
  Update           upgrade / downgrade the running image
  Logs             enable + pull the authenticated log endpoint

Or run a subcommand directly for unattended use:

    python dockvault.py setup --server-name vault.example.com ...

Stdlib-only (no `pip install` needed); Python 3.7+. Colour works on Linux and modern Windows
terminals and is auto-disabled when stdout is not a TTY or NO_COLOR is set (https://no-color.org).

NOTE: this is a HOST-side ops tool — it is excluded from the shipped image (see .dockerignore).
The interactive area handlers are filled in by later phases; the skeleton wires the menu + the
pure prompt/colour/step-tracker helpers.
"""
import argparse
import os
import shutil
import subprocess
import sys

# Anchor at the repo root (this file lives there, next to .env / deploy/ / docker-compose*.yml).
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# The top-level menu: (command-key, human label). Handlers are resolved by key on the app object,
# so a later phase fills a handler in without touching the menu wiring. The label's text after the
# ' - ' is reused as the argparse subcommand help. Labels stay ASCII-only so they render on a legacy
# Windows console (the same reason the .ps1 setup scripts are ASCII-only).
MENU = [
    ("setup",   "Setup - configure + start the vault"),
    ("backup",  "Backup & Restore - snapshot / restore volumes + .env"),
    ("volumes", "Volumes - inspect / reuse / repoint DockVault volume sets"),
    ("reset",   "Reset - tear down (optionally destroy data)"),
    ("update",  "Update - upgrade / downgrade the running image"),
    ("logs",    "Logs - enable + pull the authenticated log endpoint"),
]


# --- colour ----------------------------------------------------------------------------------
# ANSI SGR codes; blanked out when colour is disabled so the same format strings work either way.
_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "cyan": "\033[36m", "grey": "\033[90m",
}


def color_enabled(stream=None, env=None):
    """Decide whether to emit ANSI colour. Rules (pure + injectable for tests):
      * NO_COLOR present (any value) -> off (https://no-color.org);
      * DOCKVAULT_FORCE_COLOR set    -> on (for piping into a colour-aware pager / CI);
      * otherwise on only for a real TTY."""
    env = os.environ if env is None else env
    stream = sys.stdout if stream is None else stream
    if "NO_COLOR" in env:
        return False
    if env.get("DOCKVAULT_FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


def enable_windows_vt():
    """Enable ANSI escape processing on a Windows 10+ console. No-op elsewhere / on any failure."""
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:  # noqa: BLE001 — colour is cosmetic; never fail startup over it
        pass


class Palette:
    """Active colour codes — real ANSI when enabled, empty strings when not. One per run."""

    def __init__(self, enabled):
        self.enabled = bool(enabled)
        for name, code in _ANSI.items():
            setattr(self, name, code if self.enabled else "")

    def paint(self, text, *names):
        """Wrap `text` in the named SGR codes + a reset. Returns `text` unchanged when disabled."""
        if not self.enabled or not names:
            return text
        return "".join(getattr(self, n, "") for n in names) + text + self.reset


# --- pure prompt / choice parsers (the tested core) ------------------------------------------
def parse_yes_no(answer, default=True):
    """Parse a y/n answer. Empty -> `default`; y/yes -> True; n/no -> False; anything else -> None."""
    a = (answer or "").strip().lower()
    if a == "":
        return default
    if a in ("y", "yes"):
        return True
    if a in ("n", "no"):
        return False
    return None


def parse_menu_choice(answer, n_options):
    """Map a raw menu answer to a 1-based index in [1, n_options]. 'q'/'quit'/'exit'/'0' -> 0 (a
    back/quit sentinel). Anything else -> None (re-prompt). Pure."""
    a = (answer or "").strip().lower()
    if a in ("q", "quit", "exit", "0"):
        return 0
    if a.isdigit():
        i = int(a)
        if 1 <= i <= n_options:
            return i
    return None


def render_steps(steps, current):
    """Render a flow checklist: steps before `current` are done ([x]), `current` is in-progress
    ([>]), the rest are pending ([ ]). `current == len(steps)` means all done. Pure; returns plain
    (uncoloured) lines so it is directly assertable."""
    lines = []
    for i, label in enumerate(steps):
        mark = "[x]" if i < current else ("[>]" if i == current else "[ ]")
        lines.append("%s %s" % (mark, label))
    return lines


# --- thin interactive wrappers (built on the parsers above) ----------------------------------
def ask(prompt, pal, default=None):
    suffix = " [%s]" % default if default not in (None, "") else ""
    try:
        raw = input(pal.paint("%s%s: " % (prompt, suffix), "cyan"))
    except EOFError:
        raw = ""
    return raw.strip() or (default or "")


def confirm(prompt, pal, default=True):
    hint = "Y/n" if default else "y/N"
    while True:
        try:
            raw = input(pal.paint("%s [%s]: " % (prompt, hint), "yellow"))
        except EOFError:
            return default
        res = parse_yes_no(raw, default)
        if res is not None:
            return res
        print("  please answer y or n")


def ask_secret(prompt, pal):
    import getpass
    try:
        return getpass.getpass(pal.paint("%s: " % prompt, "cyan"))
    except EOFError:
        return ""


class Steps:
    """A live step tracker for an interactive flow — prints the checklist as it advances."""

    def __init__(self, steps, pal):
        self.steps = list(steps)
        self.pal = pal
        self.current = 0

    def show(self):
        print()
        for i, line in enumerate(render_steps(self.steps, self.current)):
            if i < self.current:
                print(self.pal.paint(line, "green"))
            elif i == self.current:
                print(self.pal.paint(line, "bold", "cyan"))
            else:
                print(self.pal.paint(line, "grey"))
        print()

    def advance(self):
        self.current += 1


# --- preconditions ---------------------------------------------------------------------------
def docker_available(run=subprocess.run):
    """Return (ok, message): is the docker CLI on PATH and the daemon reachable? Handlers that need
    Docker call this and bail with the message if not. `run` is injectable for tests."""
    if shutil.which("docker") is None:
        return False, "docker was not found on PATH - install Docker and retry."
    try:
        r = run(["docker", "info"], capture_output=True, text=True, timeout=25)
    except Exception as e:  # noqa: BLE001
        return False, "could not run docker: %s" % e
    if r.returncode != 0:
        return False, "the Docker daemon is not reachable - is it running?"
    return True, "ok"


# --- app -------------------------------------------------------------------------------------
def _stub(name, pal):
    print(pal.paint("\n  '%s' is not implemented yet - coming in a later phase.\n" % name, "yellow"))


class DockVault:
    """The management app: holds the palette + repo root and dispatches menu/arg commands to the
    per-area handlers (stubbed in this skeleton; filled in by later phases)."""

    def __init__(self, pal, root=APP_ROOT):
        self.pal = pal
        self.root = root

    # Area handlers — accept an optional argparse namespace so the SAME handler serves both the
    # interactive menu (args=None) and arg-mode (args=<namespace>).
    def setup(self, args=None):
        _stub("Setup", self.pal)

    def backup(self, args=None):
        _stub("Backup & Restore", self.pal)

    def volumes(self, args=None):
        _stub("Volumes", self.pal)

    def reset(self, args=None):
        _stub("Reset", self.pal)

    def update(self, args=None):
        _stub("Update", self.pal)

    def logs(self, args=None):
        _stub("Logs", self.pal)

    def handler(self, key):
        """Resolve a menu/command key to its bound handler, or None if unknown."""
        keys = {k for k, _ in MENU}
        return getattr(self, key) if key in keys else None

    def run_menu(self):
        """The interactive top menu loop. Returns on Quit / EOF."""
        while True:
            print(self.pal.paint("\n=== DockVault management ===", "bold", "blue"))
            for i, (_key, label) in enumerate(MENU, 1):
                print("  %s) %s" % (self.pal.paint(str(i), "bold"), label))
            print("  %s) Quit" % self.pal.paint("q", "bold"))
            try:
                raw = input(self.pal.paint("\nChoose: ", "cyan"))
            except EOFError:
                print()
                return
            choice = parse_menu_choice(raw, len(MENU))
            if choice == 0:
                print("Bye.")
                return
            if choice is None:
                print(self.pal.paint("  not a valid choice", "red"))
                continue
            self.handler(MENU[choice - 1][0])()


# --- entry -----------------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(prog="dockvault", description="DockVault management tool.")
    sub = p.add_subparsers(dest="command")
    for key, label in MENU:
        sub.add_parser(key, help=label.split(" - ", 1)[-1])
    return p


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    enable_windows_vt()
    pal = Palette(color_enabled())
    app = DockVault(pal)
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "command", None):
        handler = app.handler(args.command)
        if handler is None:  # unreachable via argparse, but fail loud if the menu/parser drift
            parser.error("unknown command: %s" % args.command)
        handler(args)
        return 0
    app.run_menu()
    return 0


if __name__ == "__main__":
    sys.exit(main())
