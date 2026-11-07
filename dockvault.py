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
  Accounts         reset a user's password or second factor, approve a change held for approval

Or run a subcommand directly for unattended use:

    python dockvault.py setup --server-name vault.example.com ...

Stdlib-only (no `pip install` needed); Python 3.7+. Colour works on Linux and modern Windows
terminals and is auto-disabled when stdout is not a TTY or NO_COLOR is set (https://no-color.org).

NOTE: this is a HOST-side ops tool — it is excluded from the shipped image (see .dockerignore).
"""
import argparse
import os
import shutil
import subprocess
import sys

# Anchor at the repo root (this file lives there, next to .env / deploy/ / docker-compose*.yml).
# DOCKVAULT_ROOT overrides it (a checkout elsewhere, or an isolated dir under test).
APP_ROOT = os.environ.get("DOCKVAULT_ROOT") or os.path.dirname(os.path.abspath(__file__))

# The top-level menu: (command-key, human label). Handlers are resolved by key on the app object,
# so adding a handler needs no change to the menu wiring. The label's text after the
# ' - ' is reused as the argparse subcommand help. Labels stay ASCII-only so they render on a legacy
# Windows console (the same reason the .ps1 setup scripts are ASCII-only).
MENU = [
    ("setup",   "Setup - configure + start the vault"),
    ("start",   "Start - bring the deployment up (health-checked)"),
    ("stop",    "Stop - stop the deployment, KEEP containers (faster restart; secrets remain until 'down')"),
    ("down",    "Down - stop + REMOVE containers (clears secrets from Docker; confirms first; data kept)"),
    ("restart", "Restart - stop then start (health-checked)"),
    ("status",  "Status - containers, health, ports, lock state"),
    ("lock",    "Lock - seal .env into an encrypted .env.enc"),
    ("unlock",  "Unlock - open .env.enc back into .env"),
    ("change-passphrase", "Change passphrase - re-key .env.enc (recovery key unchanged)"),
    ("backup",  "Backup & Restore - snapshot / restore volumes + .env"),
    ("volumes", "Volumes - inspect / reuse / repoint DockVault volume sets"),
    ("storage", "Limits - storage the deployment may hold, transfers it may carry"),
    ("reset",   "Reset - tear down (optionally destroy data)"),
    ("update",  "Update - upgrade / downgrade the running image"),
    ("logs",    "Logs - enable + pull the authenticated log endpoint"),
    ("accounts", "Accounts - reset a user's password or second factor, unlock, approve a held change, "
                 "release a held encryption key"),
    ("cases", "Cases - compliance access: approve an auditor right or a case when no administrator can"),
    ("audit", "Audit log - retention, verify the integrity chain, unarchive, compact"),
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
def flush_stdin():
    """Drain any typed-ahead input so a stray keypress (e.g. an Enter pressed during a long docker
    wait, thinking it hung) isn't swallowed by the NEXT prompt. Best-effort + cross-platform; a no-op
    when stdin isn't an interactive terminal."""
    try:
        if not sys.stdin.isatty():
            return
        if os.name == "nt":
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getwch()
        else:
            import termios
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
    except Exception:  # noqa: BLE001 - never break a flow because we couldn't flush the buffer
        pass


def ask(prompt, pal, default=None):
    suffix = " [%s]" % default if default not in (None, "") else ""
    try:
        raw = input(pal.paint("%s%s: " % (prompt, suffix), "cyan"))
    except (EOFError, OSError):
        # EOF (piped/closed) or an unreadable stdin (non-TTY, captured) -> take the default.
        raw = ""
    return raw.strip() or (default or "")


def confirm(prompt, pal, default=True):
    hint = "Y/n" if default else "y/N"
    while True:
        try:
            raw = input(pal.paint("%s [%s]: " % (prompt, hint), "yellow"))
        except (EOFError, OSError):
            return default
        res = parse_yes_no(raw, default)
        if res is not None:
            return res
        print("  please answer y or n")


def ask_secret(prompt, pal):
    import getpass
    try:
        return getpass.getpass(pal.paint("%s: " % prompt, "cyan"))
    except (EOFError, OSError):
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


# --- setup: secrets + .env authoring (the pure, testable core) --------------------------------
import base64   # noqa: E402
import contextlib  # noqa: E402
import glob     # noqa: E402
import hashlib  # noqa: E402
import json     # noqa: E402
import math     # noqa: E402
import re       # noqa: E402
import shlex    # noqa: E402
import signal   # noqa: E402
import tempfile # noqa: E402

# The three secrets the compose file demands (an existing .env must carry these to be reusable).
REQUIRED_SECRET_KEYS = ("ENCRYPTION_KEY", "JWT_SECRET_KEY", "VAULT_DB_PASSWORD")

# The .env limits on how long records are kept, and on what the audit log records, as (config key, .env
# name, the app's default): written only when they differ from the default, and kept across a fresh volume
# set (see .env.example).
RETENTION_ENV_KEYS = (
    # The audit log's maximum days, and how long resolved security alerts are kept (both older than the rest).
    ("audit_log_retention_days", "AUDIT_LOG_RETENTION_DAYS", "0"),
    ("security_alert_retention_days", "SECURITY_ALERT_RETENTION_DAYS", "90"),
    ("retention_reduction_delay_days", "RETENTION_REDUCTION_DELAY_DAYS", "7"),
    ("log_prune_interval_minutes", "LOG_PRUNE_INTERVAL_MINUTES", "15"),
    ("log_prune_batch_rows", "LOG_PRUNE_BATCH_ROWS", "5000"),
    ("retention_hold", "RETENTION_HOLD", "false"),
    # Working records: how long notifications are kept (0 keeps them), and the log-access file's size.
    ("notification_retention_days", "NOTIFICATION_RETENTION_DAYS", "0"),
    # How many days an address in an audit row stays in full before it is shortened (0 keeps it as recorded).
    ("audit_ip_full_days", "AUDIT_IP_FULL_DAYS", "0"),
    ("log_pull_sink_max_mb", "LOG_PULL_SINK_MAX_MB", "15"),
    ("audit_min_retention_days", "AUDIT_MIN_RETENTION_DAYS", "0"),
    ("audit_protected_min_days", "AUDIT_PROTECTED_MIN_DAYS", "365"),
    ("audit_log_max_mb", "AUDIT_LOG_MAX_MB", "0"),
    ("erase_blocked_by_protected_minimum", "ERASE_BLOCKED_BY_PROTECTED_MINIMUM", "false"),
    ("plan_log_max_days", "PLAN_LOG_MAX_DAYS", "-1"),
    ("plan_log_max_mb", "PLAN_LOG_MAX_MB", "-1"),
    ("security_record_days", "SECURITY_RECORD_DAYS", "30"),
    ("security_record_min_days", "SECURITY_RECORD_MIN_DAYS", "7"),
    ("security_record_max_days", "SECURITY_RECORD_MAX_DAYS", "365"),
    # The most the audit log may record of each kind of personal data (the recording levels' limits).
    ("audit_max_names", "AUDIT_MAX_NAMES", "full"),
    ("audit_max_signin_names", "AUDIT_MAX_SIGNIN_NAMES", "full"),
    ("audit_max_emails", "AUDIT_MAX_EMAILS", "full"),
    ("audit_max_ip", "AUDIT_MAX_IP", "full"),
    ("audit_max_user_agent", "AUDIT_MAX_USER_AGENT", "full"),
    # The audit log's integrity chain: when an hour is sealed, and where the head record lives.
    ("audit_seal_lag_minutes", "AUDIT_SEAL_LAG_MINUTES", "60"),
    ("audit_chain_head_file", "AUDIT_CHAIN_HEAD_FILE", "/app/keys/audit-chain-head.json"),
    # The audit log's archive: the days kept as rows, and how long after this release first ran it begins.
    ("audit_hot_days", "AUDIT_HOT_DAYS", "90"),
    ("audit_archive_start_after_days", "AUDIT_ARCHIVE_START_AFTER_DAYS", "14"),
)

# The boundary of compliance access and legal holds, set only in .env (see .env.example), as (config key, .env
# name, the app's default): written only when they differ from the default, and kept across a fresh volume set.
COMPLIANCE_ENV_KEYS = (
    ("compliance_access", "COMPLIANCE_ACCESS", "enabled"),
    ("compliance_password_vaults", "COMPLIANCE_PASSWORD_VAULTS", "with_password"),
    ("compliance_export", "COMPLIANCE_EXPORT", "allowed"),
    ("compliance_max_access_days", "COMPLIANCE_MAX_ACCESS_DAYS", "30"),
    ("compliance_max_total_days", "COMPLIANCE_MAX_TOTAL_DAYS", "90"),
    ("compliance_max_case_vaults", "COMPLIANCE_MAX_CASE_VAULTS", "25"),
    ("compliance_export_ttl_hours", "COMPLIANCE_EXPORT_TTL_HOURS", "24"),
    ("compliance_hold_confirm_days", "COMPLIANCE_HOLD_CONFIRM_DAYS", "7"),
    ("compliance_hold_purge_delay_days", "COMPLIANCE_HOLD_PURGE_DELAY_DAYS", "7"),
    ("compliance_hold_review_days", "COMPLIANCE_HOLD_REVIEW_DAYS", "180"),
    ("compliance_view_rate", "COMPLIANCE_VIEW_RATE", "600"),
    ("compliance_reveals_per_day", "COMPLIANCE_REVEALS_PER_DAY", "100"),
    ("compliance_auditor_not_admin", "COMPLIANCE_AUDITOR_NOT_ADMIN", "false"),
    ("compliance_auditor_grant_days", "COMPLIANCE_AUDITOR_GRANT_DAYS", "365"),
    ("compliance_record_min_days", "COMPLIANCE_RECORD_MIN_DAYS", "2190"),
)

# How much container output (`docker logs`) Docker keeps: every service of the shipped compose files rotates it
# (json-file, at most DOCKER_LOG_MAX_FILE files of DOCKER_LOG_MAX_SIZE). (config key, .env name, the compose
# files' default): written only when they differ from the default, and kept across a fresh volume set.
CONTAINER_LOG_ENV_KEYS = (
    ("docker_log_max_size", "DOCKER_LOG_MAX_SIZE", "10m"),
    ("docker_log_max_file", "DOCKER_LOG_MAX_FILE", "5"),
)
# A size as Docker reads it (a number, then k/m/g/t/p, optionally "i" and "b"; decimal units).
_LOG_SIZE = re.compile(r"^(\d+(?:\.\d+)?) ?([kmgtp])?i?b?$", re.IGNORECASE)
_LOG_SIZE_UNITS = {None: 1, "k": 10 ** 3, "m": 10 ** 6, "g": 10 ** 9, "t": 10 ** 12, "p": 10 ** 15}


# ${NAME}, ${NAME:-default}, ${NAME-default}, $NAME, and $$ (a dollar sign), as docker compose replaces them in .env.
_ENV_REFERENCE = re.compile(r"\$\$|\$\{(\w+)(?:(:?)-([^}]*))?\}|\$(\w+)")
_DOUBLE_QUOTE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "$": "$$"}


def without_bom(text):
    """``text`` (.env's) without a byte order mark at its start, which an editor may write there (Windows
    PowerShell 5.1 writes UTF-8 with one): docker compose reads past it, so every reader of .env here does too,
    and the first line keeps its name."""
    text = text or ""
    return text[1:] if text.startswith("\ufeff") else text


def _env_replace(value, lookup):
    def one(m):
        if m.group(0) == "$$":
            return "$"
        name = m.group(1) or m.group(4)
        found = lookup(name)
        if m.group(1) and m.group(3) is not None and (found is None or (m.group(2) and found == "")):
            return m.group(3)
        return found or ""
    return _ENV_REFERENCE.sub(one, value)


def _env_line_value(rest, lookup):
    """The value of one .env line after its "=", as docker compose reads it, or None for a quote never closed."""
    rest = rest.strip(" \t")
    if rest[:1] == "'":
        end = rest.find("'", 1)
        return None if end < 0 else rest[1:end]
    if rest[:1] == '"':
        out, i = [], 1
        while i < len(rest):
            c = rest[i]
            if c == "\\" and i + 1 < len(rest):
                out.append(_DOUBLE_QUOTE_ESCAPES.get(rest[i + 1], c + rest[i + 1]))
                i += 2
                continue
            if c == '"':
                return _env_replace("".join(out), lookup)
            out.append(c)
            i += 1
        return None
    comment = rest.find(" #")
    if comment >= 0:
        rest = rest[:comment]
    return _env_replace(rest.strip(" \t"), lookup)


def compose_env_values(text, names, environ=None):
    """The values of ``names`` as docker compose gives them to the compose files, from .env's ``text`` and the
    process environment ``environ`` (os.environ when None), which compose prefers to .env. .env is read by compose's
    rules (docker compose 2.40): blank lines and lines starting with # are skipped, "export " is allowed, and the
    last line of a name wins; a value in single quotes is taken as it stands; one in double quotes with its escapes
    and its ${...} replaced, anything after the closing quote ignored; an unquoted one is cut at " #" (a space, then
    #), trimmed, and its ${...} replaced, from the process environment or the lines above it. parse_env differs on
    purpose: it keeps what the setup scripts wrote. A value whose quote is never closed is None: compose refuses
    the file. A byte order mark at the start of the file is read past, as compose does."""
    environ = os.environ if environ is None else environ
    read = {}

    def lookup(name):
        return environ[name] if name in environ else read.get(name)

    for raw in without_bom(text).splitlines():
        line = raw.strip(" \t\r")
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[7:].lstrip(" \t")
        key, sep, rest = line.partition("=")
        key = key.strip(" \t")
        if not sep or not key:
            continue
        read[key] = _env_line_value(rest, lookup)
    return {name: (environ[name] if name in environ else read[name]) for name in names
            if name in environ or name in read}


def _shown(value):
    return value if value == value.strip() and value.isprintable() else json.dumps(value)


def container_log_problems(env):
    """What in ``env`` (DOCKER_LOG_MAX_SIZE and DOCKER_LOG_MAX_FILE as docker compose gives them to the compose
    files: compose_env_values) Docker would refuse as the rotation of container output: [] when nothing. Docker
    starts no container whose log size is not a positive size, or whose file count is below 1, and a space before
    or after either is not one, so a stack recreated with one would not come back. An empty value takes the
    compose files' default; a quote never closed is named, since compose refuses the file."""
    problems = []
    for name in ("DOCKER_LOG_MAX_SIZE", "DOCKER_LOG_MAX_FILE"):
        if name in env and env[name] is None:
            problems.append("%s has a quote that is never closed, so docker compose cannot read .env" % name)
    size = env.get("DOCKER_LOG_MAX_SIZE") or ""
    if size:
        m = _LOG_SIZE.fullmatch(size)
        if not m or int(float(m.group(1)) * _LOG_SIZE_UNITS[(m.group(2) or "").lower() or None]) < 1:
            problems.append("DOCKER_LOG_MAX_SIZE=%s is not a size Docker reads (for example 10m, 50m, 1g)"
                            % _shown(size))
    count = env.get("DOCKER_LOG_MAX_FILE") or ""
    if count and not (re.fullmatch(r"\+?\d+", count) and int(count) >= 1):
        problems.append("DOCKER_LOG_MAX_FILE=%s is not a whole number of files, 1 or more" % _shown(count))
    return problems


def host_log_driver(run=None):
    """The Docker daemon's default logging driver ("json-file", "journald", ...), or None when it cannot be read."""
    run = run or subprocess.run
    try:
        r = run(["docker", "info", "--format", "{{.LoggingDriver}}"], capture_output=True, text=True, timeout=25,
                stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    driver = (getattr(r, "stdout", "") or "").strip()
    return driver if getattr(r, "returncode", 1) == 0 and driver else None


def compose_sets_logging(root):
    """Whether the secure compose file under ``root`` gives its services a ``logging:`` block: True, False (a
    checkout from before the rotation, or one whose operator removed it to keep the host's own driver), or None
    when there is no such file."""
    try:
        with open(os.path.join(root, "deploy", "docker-compose.secure.yml"), encoding="utf-8") as handle:
            return re.search(r"^\s+logging:", handle.read(), re.MULTILINE) is not None
    except OSError:
        return None


def container_log_note(root, run=None):
    """A note for the operator about where container output goes, or None when there is nothing to say: the
    checkout's compose files rotate nothing (they predate the rotation, or it was removed), or they rotate it in
    json-file files while the host's Docker sends container output to another driver by default (which then no
    longer gets DockVault's)."""
    sets = compose_sets_logging(root)
    if sets is None:
        return None
    driver = host_log_driver(run)
    if not sets:
        if driver not in (None, "json-file"):
            return None      # the host's own driver keeps the output: the reason to remove the block
        return ("The compose files of this checkout do not rotate container output, so Docker keeps it as this "
                "host's settings say (with Docker's defaults, without limit). Update the checkout to get the rotation "
                "(README, \"Container logs\").")
    if driver in (None, "json-file"):
        return None
    return ("This host's Docker sends container output to '%s' by default, but DockVault's compose files keep "
            "their containers' output in rotated json-file files instead (DOCKER_LOG_MAX_SIZE x DOCKER_LOG_MAX_FILE), "
            "so '%s' does not get it. To keep '%s' for DockVault, see README, \"Container logs\"."
            % (driver, driver, driver))

# What the audit log may record of personal data at most: setup offers three presets for the AUDIT_MAX_* limits
# (see .env.example). The panel then chooses the levels at or below them. "full" is the app's default (nothing is
# written); with --lock-recording-levels each limit is also the level (SETTINGS_LOCKED_KEYS gains audit_levels).
RECORDING_PRESETS = {
    "full": {"audit_max_names": "full", "audit_max_signin_names": "full", "audit_max_emails": "full",
             "audit_max_ip": "full", "audit_max_user_agent": "full"},
    "standard": {"audit_max_names": "fingerprint", "audit_max_signin_names": "fingerprint",
                 "audit_max_emails": "full", "audit_max_ip": "shortened", "audit_max_user_agent": "full"},
    "minimal": {"audit_max_names": "none", "audit_max_signin_names": "none", "audit_max_emails": "none",
                "audit_max_ip": "none", "audit_max_user_agent": "none"},
}
RECORDING_PRESET_HELP = (
    "full     = the audit log may record names typed at sign-in, email addresses, IP addresses and browser",
    "           descriptions in full, and vault, file and folder names (sealed); the panel can record less",
    "standard = at most fingerprints of names, IP addresses shortened to their network, email addresses and",
    "           browser descriptions in full",
    "minimal  = none of these is recorded; every event still is (who, what, when, the outcome)",
)
RECORDING_LOCK_GROUP = "audit_levels"


def recording_preset_config(preset, lock=False, locked_keys=None):
    """The setup config keys for a recording preset: the five AUDIT_MAX_* limits, and SETTINGS_LOCKED_KEYS with
    audit_levels added when ``lock`` (kept with whatever ``locked_keys`` already named)."""
    if preset not in RECORDING_PRESETS:
        raise ValueError("unknown recording preset %r (one of %s)" % (preset, ", ".join(RECORDING_PRESETS)))
    cfg = dict(RECORDING_PRESETS[preset])
    tokens = [t for t in str(locked_keys or "").replace(";", ",").replace(" ", ",").split(",") if t.strip()]
    if lock and RECORDING_LOCK_GROUP not in [t.strip().lower() for t in tokens]:
        tokens.append(RECORDING_LOCK_GROUP)
    cfg["settings_locked_keys"] = ",".join(t.strip() for t in tokens) or None
    return cfg


# Admin-password rules mirror the app's startup guard (app/core/config.py): the shipped placeholder
# is refused everywhere; a reachable (non-development) deploy also rejects a known-weak value or one
# under 12 chars. A BLANK password is allowed (the post-bootstrap no-op).
_ADMIN_PW_PLACEHOLDERS = {
    "replace_me", "change_this_secure_password", "changeme", "change_me", "change_this",
    "changethis", "password", "admin", "admin123", "your_admin_password", "your_password_here",
}
_ADMIN_PW_MIN = 12


def gen_fernet_key():
    """Fernet at-rest master key: urlsafe-base64 of 32 random bytes (matches the setup scripts and
    cryptography.fernet)."""
    return base64.urlsafe_b64encode(os.urandom(32)).decode()


def gen_hex(nbytes):
    """`nbytes` random bytes as hex (e.g. 32 -> a 64-char secret)."""
    return os.urandom(nbytes).hex()


def parse_env(text):
    """Parse a KEY=VALUE .env into a dict. First occurrence of a key wins; a single surrounding
    matching quote pair is stripped; tolerant of CRLF + whitespace around the key/'=', and of a byte
    order mark at the start (without_bom). Pure — mirrors the setup scripts' read_env so a re-run reads
    its own output back correctly."""
    out = {}
    for raw in without_bom(text).splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().rstrip("\r")
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key and key not in out:
            out[key] = val
    return out


def _int_or(value, default):
    """int(value), or `default` if value is None / not an integer (a hand-edited .env port)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _port_or(value, default):
    """A valid host port (1..65535) parsed from `value`, else `default` — tolerates a hand-edited or
    CLI-supplied out-of-range / non-numeric port instead of crashing later."""
    p = _int_or(value, default)
    return p if 1 <= p <= 65535 else default


def validate_server_name(name):
    """True if `name` is a plain host name / IP (letters, digits, dots, hyphens only) — the charset
    the setup scripts enforce before it flows into .env, the TLS cert subject, and docker args."""
    return bool(name) and re.match(r"^[A-Za-z0-9.-]+$", name) is not None


def is_ipv4(name):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", name or ""))


def admin_password_problem(pw, environment="production"):
    """Return a human reason `pw` is unacceptable as the bootstrap admin password, or None if OK.
    Mirrors the app startup guard so the tool rejects a bad value BEFORE it writes .env / boots."""
    p = (pw or "").strip()
    if not p:
        return None  # blank is the legitimate post-bootstrap state
    if "'" in p:
        return "must not contain a single quote (it breaks .env quoting)"
    low = p.lower()
    if low == "replace_me":
        return "is the shipped placeholder (a publicly known value)"
    strict = (environment or "").strip().lower() != "development"
    if strict and low in _ADMIN_PW_PLACEHOLDERS:
        return "is a known sample/weak value"
    if strict and len(p) < _ADMIN_PW_MIN:
        return "must be at least %d characters" % _ADMIN_PW_MIN
    return None


# The names the vault writes into its records for itself (app/core/person_erase.py system_names(); a test keeps the
# two the same). No account may take one, in any case or spacing.
SERVER_WRITTEN_NAMES = ("operator@host", "server configuration", "the server (AUDIT_LOG_RETENTION_DAYS in .env)",
                        "system")


def server_name_form(name):
    """``name`` as the vault compares it with the names it writes for itself (person_erase.server_name_form)."""
    import unicodedata
    return re.sub(r"[\s_.\-]+", "", unicodedata.normalize("NFKC", name).casefold())


def admin_username_problem(name):
    """Return a human reason ``name`` cannot be the first administrator's username, or None if OK. Mirrors the
    app's rules for a new account's username, so the first start does not refuse the name the tool wrote."""
    import unicodedata
    n = name or ""
    if not 3 <= len(n) <= 50:
        return "must be 3 to 50 characters"
    if "'" in n:
        return "must not contain a single quote (it breaks .env quoting)"
    if any(c in n for c in "<>@"):
        return "must not contain '<', '>' or '@'"
    if any(unicodedata.category(c).startswith("C") for c in n):
        return "must not contain control or invisible characters"
    if unicodedata.normalize("NFKC", n).casefold().startswith("erased-"):
        return "must not start with 'erased-' (kept for erased records)"
    if server_name_form(n) in {server_name_form(s) for s in SERVER_WRITTEN_NAMES}:
        return "is a name the vault writes into its records for itself"
    return None


def migrate_compose_profiles(existing):
    """Return the one selected app profile, migrating only supported legacy values.

    Empty values predate profiles and migrate to ``combined``; the former single ``sftp``
    profile migrates to ``split``.  Every non-empty current value must select exactly one of
    ``combined`` or ``split``.  Silently picking one item from a multi-profile or misspelled
    value can start both app layouts against the same ports, so those values fail closed.
    """
    parts = [p.strip().lower() for p in (existing or "").split(",") if p.strip()]
    if not parts:
        return "combined"
    if len(parts) != 1:
        raise ValueError(
            "COMPOSE_PROFILES must select exactly one profile: combined or split"
        )
    if parts[0] == "sftp":
        return "split"
    if parts[0] in ("combined", "split"):
        return parts[0]
    raise ValueError(
        "COMPOSE_PROFILES must select exactly one profile: combined or split"
    )


def profile_reconciliation_args(profile):
    """Compose arguments that remove only the inactive app layout for ``profile``.

    The targeted ``compose rm`` intentionally has no volume flag: database/cache services and
    all named data volumes survive a combined/split transition.
    """
    selected = migrate_compose_profiles(profile)
    if selected == "split":
        return ("--profile", "combined", "rm", "-s", "-f", "vault")
    return ("--profile", "split", "rm", "-s", "-f", "vault-api", "vault-sftp")


def build_env_lines(cfg):
    """Build the .env content (list of lines) from a collected-config dict — deterministic + pure
    (it does NOT generate secrets; the caller passes them in). Values are single-quoted, matching
    the setup scripts' dotenv quoting. `cfg` keys: server_name, encryption_key, jwt_secret_key,
    vault_db_password, redis_password, admin_username, admin_email, admin_password, compose_profiles,
    run_sftp (bool), update_check_enabled (bool), plan_log_pull (bool), log_token_pepper (str),
    invite_token_pepper (str), audit_fingerprint_key and audit_chain_key (str; each written only when set),
    enforce_file_expiry and
    zk_key_proof_enforce (raw strings; only a false value is written), max_single_request_upload_mb (int or
    None; written only when set), settings_locked_keys (str; written only when set)."""
    lines = []

    def q(k):
        lines.append("%s='%s'" % (k, cfg[k.lower()]))

    def bare(k, v):
        lines.append("%s=%s" % (k, v))

    lines.append("# Generated by dockvault.py for https://%s/" % cfg["server_name"])
    lines.append("# *** BACK THIS FILE UP off this host - it holds ENCRYPTION_KEY (the at-rest")
    lines.append("# master key): without it every stored file is permanently unrecoverable. ***")
    q("ENCRYPTION_KEY")
    q("JWT_SECRET_KEY")
    q("VAULT_DB_PASSWORD")
    q("REDIS_PASSWORD")
    bare("ALLOWED_HOSTS", "'%s'" % cfg["server_name"])
    bare("SERVER_NAME", "'%s'" % cfg["server_name"])
    q("ADMIN_USERNAME")
    q("ADMIN_EMAIL")
    q("ADMIN_PASSWORD")
    compose_profile = migrate_compose_profiles(cfg.get("compose_profiles", "combined"))
    bare("COMPOSE_PROFILES", compose_profile)
    # Stable bundle id: labels this deployment's five volumes so the tool can group them as one set.
    if cfg.get("deployment_id"):
        bare("DEPLOYMENT_ID", cfg["deployment_id"])
    # Only write a non-default volume prefix (a fresh/repointed set); the default keeps the historical
    # volume names so existing deployments are byte-identical.
    if cfg.get("volume_prefix") and cfg["volume_prefix"] != DEFAULT_PROJECT:
        bare("VAULT_VOLUME_PREFIX", cfg["volume_prefix"])
    # Only pin an image when the operator chose a PUBLISHED release. Left unset, the composes fall
    # back to the local build tag, so a build-from-source deployment authors exactly the .env it
    # always has.
    if cfg.get("dockvault_image"):
        bare("DOCKVAULT_IMAGE", cfg["dockvault_image"])
    if cfg.get("run_sftp"):
        bare("RUN_SFTP", "1")
    # Only write a port line when it differs from the compose default (443 web / 2322 sftp).
    if cfg.get("web_host_port") and int(cfg["web_host_port"]) != 443:
        bare("WEB_HOST_PORT", int(cfg["web_host_port"]))
    # split mode always runs the SFTP container, so honour a custom SFTP port there too.
    sftp_active = cfg.get("run_sftp") or compose_profile == "split"
    if sftp_active and cfg.get("sftp_host_port") and int(cfg["sftp_host_port"]) != 2322:
        bare("SFTP_HOST_PORT", int(cfg["sftp_host_port"]))
    # SFTP upload-staging tmpfs size (MiB) — used only by buffered uploads (SFTP_STREAMING_UPLOAD=false),
    # whose size it then also caps; streaming uploads, the default, never stage.
    # Written only when the operator chose a non-default value; otherwise the compose/app default
    # (512) applies, so an install that never mentions it authors the .env it always did.
    if sftp_active and cfg.get("sftp_staging_tmpfs_mb") not in (None, "") \
            and int(cfg["sftp_staging_tmpfs_mb"]) != 512:
        bare("SFTP_STAGING_TMPFS_MB", int(cfg["sftp_staging_tmpfs_mb"]))
    # SFTP pre-auth connection-admission caps (see .env.example). Written only when the operator set a
    # non-default value; otherwise the app defaults (100 / 10 / 30) apply, so an install that never
    # mentions them authors the .env it always did.
    for _cfg_key, _env_name, _default in (
        ("sftp_max_connections", "SFTP_MAX_CONNECTIONS", 100),
        ("sftp_max_connections_per_ip", "SFTP_MAX_CONNECTIONS_PER_IP", 10),
        ("sftp_max_authenticated_per_ip", "SFTP_MAX_AUTHENTICATED_PER_IP", 50),
        ("sftp_auth_grace_seconds", "SFTP_AUTH_GRACE_SECONDS", 30),
        # The write-progress watchdog's window and floor (see .env.example), same rule: only a
        # non-default value is written.
        ("sftp_write_progress_timeout_seconds", "SFTP_WRITE_PROGRESS_TIMEOUT_SECONDS", 120),
        ("sftp_write_progress_min_bytes", "SFTP_WRITE_PROGRESS_MIN_BYTES", 65536),
    ):
        if sftp_active and cfg.get(_cfg_key) not in (None, "") and int(cfg[_cfg_key]) != _default:
            bare(_env_name, int(cfg[_cfg_key]))
    # SFTP streaming upload (default ON): a normal install never mentions it. Author SFTP_STREAMING_UPLOAD
    # only when the operator explicitly DISABLED it (the buffered rollback), preserving that choice
    # across a fresh volume set; the reorder window and the memory ceiling are authored only when they
    # differ from the app defaults (16 / 64). An existing value is preserved through the env reader below.
    if sftp_active and str(cfg.get("sftp_streaming_upload") or "").strip().lower() in ("false", "0", "no", "off"):
        bare("SFTP_STREAMING_UPLOAD", "false")
    if sftp_active and cfg.get("sftp_streaming_reorder_mb") not in (None, "") \
            and int(cfg["sftp_streaming_reorder_mb"]) != 16:
        bare("SFTP_STREAMING_REORDER_MB", int(cfg["sftp_streaming_reorder_mb"]))
    if sftp_active and cfg.get("sftp_transfer_buffer_mb") not in (None, "") \
            and int(cfg["sftp_transfer_buffer_mb"]) != 64:
        bare("SFTP_TRANSFER_BUFFER_MB", int(cfg["sftp_transfer_buffer_mb"]))
    # In-flight upload marker TTL (seconds): the backstop on the ephemeral Redis marker an SFTP
    # write-open publishes so the web listing shows "uploading by <member>" and a same-name upload
    # is refused. Removed explicitly on close and refreshed during a live transfer, so this only
    # reaps a marker left by a killed client. Written only when the operator set a non-default value
    # (default 300); a normal install never mentions it and an existing value is preserved below.
    if sftp_active and cfg.get("upload_marker_ttl_seconds") not in (None, "") \
            and int(cfg["upload_marker_ttl_seconds"]) != 300:
        bare("UPLOAD_MARKER_TTL_SECONDS", int(cfg["upload_marker_ttl_seconds"]))
    # Where SFTP clients are told to connect, written only when it differs from what the deployment
    # would advertise by itself -- the address clients already use, and the published SFTP port.
    if sftp_active and (cfg.get("sftp_public_host") or "").strip():
        bare("SFTP_PUBLIC_HOST", cfg["sftp_public_host"].strip())
    if sftp_active and cfg.get("sftp_public_port") not in (None, "") \
            and int(cfg["sftp_public_port"]) != int(cfg.get("sftp_host_port") or 2322):
        bare("SFTP_PUBLIC_PORT", int(cfg["sftp_public_port"]))
    if cfg.get("update_check_enabled"):
        bare("UPDATE_CHECK_ENABLED", "true")
    # Deployment storage ceiling. Only written when the operator chose one: left out, the app's
    # own default (-1, unlimited) applies, so an install that never mentions storage authors the
    # .env it always did.
    if cfg.get("max_storage_gb") not in (None, ""):
        bare("MAX_STORAGE_GB", format_gb_value(cfg["max_storage_gb"]))
    # Transfer ceiling. The one that costs memory is MAX_CONCURRENT_TRANSFERS; the other two only
    # shape what happens to callers who arrive at a full deployment. Same rule as storage: written
    # only when this deployment has a value, so an install that never mentions them authors the
    # .env it always did and the app's own defaults apply.
    for key in ("max_concurrent_transfers", "max_queued_transfers", "transfer_queue_wait_seconds"):
        if cfg.get(key) not in (None, ""):
            bare(key.upper(), str(cfg[key]))
    # The cap on one multipart upload request, which the web container holds in memory before it
    # checks anything. Same rule: written only when this deployment has a value, so an install that
    # never mentions it authors the .env it always did and the app's default (64) applies.
    if cfg.get("max_single_request_upload_mb") not in (None, ""):
        bare("MAX_SINGLE_REQUEST_UPLOAD_MB", int(cfg["max_single_request_upload_mb"]))
    # File expiry is enforced by default, so a normal install never mentions it. Author
    # ENFORCE_FILE_EXPIRY only when the operator has postponed enforcement, so that choice survives
    # a fresh volume set instead of silently switching back on.
    if str(cfg.get("enforce_file_expiry") or "").strip().lower() in ("false", "0", "no", "off"):
        bare("ENFORCE_FILE_EXPIRY", "false")
    # The key proof on zero-knowledge key changes likewise: on by default and never mentioned, written
    # only when the operator has postponed it, so a fresh volume set does not switch it back on.
    if str(cfg.get("zk_key_proof_enforce") or "").strip().lower() in ("false", "0", "no", "off"):
        bare("ZK_KEY_PROOF_ENFORCE", "false")
    # The hold on the zero-knowledge key envelope after an administrator changes an account: 14 days by
    # default and never mentioned, written only when the operator chose another number of days (0 to 14;
    # 0 turns it off), so that choice survives a fresh volume set.
    hold = parse_envelope_hold_days(cfg.get("zk_envelope_hold_days"))
    if hold is not None and hold != ENVELOPE_HOLD_DAYS_DEFAULT:
        bare("ZK_ENVELOPE_HOLD_DAYS", str(hold))
    if cfg.get("plan_log_pull"):
        # Opting in here closes the log-404 trap: the endpoint needs BOTH the plan flag and a
        # strong pepper before it will serve (then an admin still ticks a component in the UI).
        bare("PLAN_LOG_PULL", "true")
        bare("LOG_TOKEN_PEPPER", "'%s'" % cfg["log_token_pepper"])
    # Settings the deployment locks against the admin panel: written only when there are some, so a normal
    # install's .env never mentions it, and kept across a fresh volume set.
    if str(cfg.get("settings_locked_keys") or "").strip():
        bare("SETTINGS_LOCKED_KEYS", "'%s'" % str(cfg["settings_locked_keys"]).strip())
    # The limits on how long records are kept (see .env.example). Written only when they differ from the
    # app's defaults, so an install that never mentions them authors the .env it always did.
    for _cfg_key, _env_name, _default in RETENTION_ENV_KEYS:
        if str(cfg.get(_cfg_key) or "").strip() not in ("", _default):
            bare(_env_name, str(cfg[_cfg_key]).strip())
    # The boundary of compliance access and legal holds (see .env.example), by the same rule.
    for _cfg_key, _env_name, _default in COMPLIANCE_ENV_KEYS:
        if str(cfg.get(_cfg_key) or "").strip() not in ("", _default):
            bare(_env_name, str(cfg[_cfg_key]).strip())
    # And how much container output Docker keeps, same rule.
    for _cfg_key, _env_name, _default in CONTAINER_LOG_ENV_KEYS:
        if str(cfg.get(_cfg_key) or "").strip() not in ("", _default):
            bare(_env_name, str(cfg[_cfg_key]).strip())
    # A dedicated pepper for account-invitation token hashes. Always written so invitation hashes are
    # decoupled from the JWT secret (the app falls back to the JWT secret only when this is absent).
    if cfg.get("invite_token_pepper"):
        bare("INVITE_TOKEN_PEPPER", "'%s'" % cfg["invite_token_pepper"])
    # The key of the audit log's fingerprints. Written when there is one: an install set up before it was
    # generated derives one from ENCRYPTION_KEY, and keeps doing so until a key is added here.
    if cfg.get("audit_fingerprint_key"):
        bare("AUDIT_FINGERPRINT_KEY", "'%s'" % cfg["audit_fingerprint_key"])
    # The audit log's integrity chain key. Written when there is one: an install set up before it was
    # generated derives the chain's key from ENCRYPTION_KEY until one is added here.
    if cfg.get("audit_chain_key"):
        bare("AUDIT_CHAIN_KEY", "'%s'" % cfg["audit_chain_key"])
    return lines


def env_is_reusable(existing):
    """An existing .env can be REUSED (keep its secrets + data) iff it carries every required
    secret. Returns (ok, missing_keys). The bundle invariant: never regenerate ENCRYPTION_KEY /
    VAULT_DB_PASSWORD against volumes created under the old ones."""
    missing = [k for k in REQUIRED_SECRET_KEYS if not (existing.get(k) or "").strip()]
    return (not missing), missing


def write_env(path, lines):
    """Write the .env (LF-joined + trailing newline). On POSIX it is CREATED mode-600 so the secrets
    are never briefly world-readable before the chmod; on Windows it is then locked via icacls.
    Returns True only if the perms were actually restricted (the caller warns, never aborts, on False)."""
    content = "\n".join(lines) + "\n"
    if os.name != "nt":
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    else:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    return tighten_secret_file(path)


def sync_to_disk(path):
    """Force a file just written, and its name in its directory, to the disk (the standard library's fsync, as the
    app's durable writes do), so a power cut right after cannot lose it. Windows, and a filesystem that cannot sync
    a directory (EINVAL, EBADF), skip the directory; any other error (EIO) raises OSError. On Windows the file is
    opened for writing (nothing is written): fsync there flushes through a handle that may write, and refuses one
    opened read-only (EBADF)."""
    fd = os.open(path, (os.O_RDWR | getattr(os, "O_BINARY", 0)) if os.name == "nt" else os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_directory(os.path.dirname(os.path.abspath(path)))


def sync_directory(directory):
    """Force the names in `directory` to the disk. Windows, and a filesystem that cannot sync a directory (EINVAL,
    EBADF), skip it; any other error (EIO) raises OSError."""
    import errno
    if os.name == "nt":
        return
    dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    except OSError as exc:
        if exc.errno not in (errno.EINVAL, errno.EBADF):
            raise
    finally:
        os.close(dfd)


def replace_file_durably(path, data):
    """Replace the file at `path` with `data` (text, written UTF-8 with LF line ends; or bytes, as they are) so that a
    power cut leaves the old file or the new one, whole, and the new one on the disk once this returns: written to a
    temporary file beside it (created mode 600), synced, renamed over it, then its directory synced. A symbolic link
    at `path` is followed: its target is replaced and the link stays. The file keeps its owner and group where this
    process may give them. Raises OSError: the file is then as it was, unless only the directory's sync failed (the
    rename was done)."""
    target = os.path.realpath(path)
    directory = os.path.dirname(target) or "."
    try:
        before = os.stat(target)
    except OSError:
        before = None
    fd, tmp = tempfile.mkstemp(prefix=".dvtmp-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            if os.name != "nt":
                os.fchmod(f.fileno(), 0o600)
                if before is not None:
                    try:
                        os.fchown(f.fileno(), before.st_uid, before.st_gid)
                    except OSError:
                        pass                  # not this process's to give: the file stays its own
            f.write(bytes(data) if isinstance(data, (bytes, bytearray)) else data.encode("utf-8"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
        tmp = None
    finally:
        if tmp is not None:
            try:
                os.remove(tmp)
            except OSError:
                pass
    sync_directory(directory)


def windows_system_tool(name):
    """The full path of a Windows tool in System32 (whoami.exe, icacls.exe). Each is run by that path, never by its
    bare name: Windows looks a bare name up in the folder of the program that starts it and in the current folder
    before System32, so a file of that name in the folder the tool is run from would run instead."""
    return os.path.join(os.environ.get("SystemRoot") or "C:\\Windows", "System32", name)


def windows_user_grantee():
    """Windows: how icacls is to name the account this process runs as. Its SID (`*S-1-...`, from whoami /user),
    which names that one account; else DOMAIN\\user from the environment; else the bare user name; else None. A
    bare name is looked up among this computer's own accounts first, so a domain user who has a same-named local
    account would grant that one, and a run as SYSTEM has the computer's account in USERNAME (COMPUTER$)."""
    import csv
    whoami = windows_system_tool("whoami.exe")
    try:
        r = subprocess.run([whoami, "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=15,
                           stdin=subprocess.DEVNULL)
        lines = (getattr(r, "stdout", "") or "").strip().splitlines() if getattr(r, "returncode", 1) == 0 else []
        fields = next(csv.reader([lines[-1]])) if lines else []
    except (OSError, ValueError, subprocess.SubprocessError, csv.Error, StopIteration):
        fields = []
    sid = fields[-1].strip() if fields else ""
    if re.match(r"^S-1-[0-9]+(-[0-9]+)+$", sid):
        return "*" + sid
    user = os.environ.get("USERNAME") or ""
    domain = os.environ.get("USERDOMAIN") or ""
    if user and domain:
        return "%s\\%s" % (domain, user)
    return user or None


def tighten_secret_file(path):
    """Restrict a secrets file to the current user - chmod 600 on POSIX, icacls on Windows. Returns
    True ONLY if the tightening actually succeeded, so a caller never falsely reports a secrets file
    (which holds ENCRYPTION_KEY) as locked down when it isn't."""
    try:
        if os.name == "nt":
            user = windows_user_grantee()
            if not user:
                return False  # can't form a valid icacls grant without a user name
            r = subprocess.run(
                [windows_system_tool("icacls.exe"), path, "/inheritance:r", "/grant:r", "%s:(R,W)" % user,
                 "BUILTIN\\Administrators:(F)", "NT AUTHORITY\\SYSTEM:(F)"],
                capture_output=True, text=True, timeout=15)
            return r.returncode == 0
        os.chmod(path, 0o600)
        return True
    except Exception:  # noqa: BLE001
        return False


def restrict_folder_to_owner(path):
    """Windows: restrict a folder to the current user (by SID: windows_user_grantee), SYSTEM and Administrators
    (inheritance from where it was made removed), so that what is written inside inherits that and nothing wider.
    True ONLY when icacls did it."""
    user = windows_user_grantee()
    if not user:
        return False          # can't form a valid icacls grant without a user name
    try:
        r = subprocess.run(
            [windows_system_tool("icacls.exe"), path, "/inheritance:r", "/grant:r", "%s:(OI)(CI)F" % user,
             "BUILTIN\\Administrators:(OI)(CI)F", "NT AUTHORITY\\SYSTEM:(OI)(CI)F"],
            capture_output=True, text=True, timeout=30)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return getattr(r, "returncode", 1) == 0


def _copy_secret(src, dst):
    """Copy `src` to `dst`, CREATING dst mode-600 on POSIX so a private key is never briefly
    world-readable before the perms are tightened (Windows perms are set by tighten_secret_file)."""
    with open(src, "rb") as f:
        data = f.read()
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(dst, flags, 0o600) if os.name != "nt" else os.open(dst, flags)
    with os.fdopen(fd, "wb") as out:
        out.write(data)


def write_kept_key(path, key):
    """Create `path` holding `key` (and a line end), mode 600, and put it on the disk with its name; never over a
    file already there (FileExistsError). A file this call created but could not finish is removed. Raises
    OSError."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600) if os.name != "nt" else os.open(path, flags)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
            out.write(key + "\n")
        tighten_secret_file(path)
        sync_to_disk(path)
    except OSError:
        try:
            os.remove(path)
        except OSError:
            pass
        raise


# --- setup: self-signed cert (host openssl or a throwaway container) --------------------------
def _openssl_args_self_signed(server_name):
    san = ("IP:%s" if is_ipv4(server_name) else "DNS:%s") % server_name
    return ["req", "-x509", "-newkey", "rsa:4096", "-sha256", "-days", "825", "-nodes",
            "-keyout", "key.pem", "-out", "cert.pem", "-subj", "/CN=%s" % server_name,
            "-addext", "subjectAltName=%s" % san]


def generate_self_signed_cert(cert_dir, server_name, run=subprocess.run):
    """Write cert_dir/{cert.pem,key.pem} (RSA-4096, 825d, SAN=server_name) via a host `openssl` if
    present, else a throwaway `alpine/openssl` container (host needs only Docker). Returns
    (ok, message). `run` is injectable for tests."""
    os.makedirs(cert_dir, exist_ok=True)
    args = _openssl_args_self_signed(server_name)

    def _try(cmd, **kw):
        # A timeout (e.g. a slow alpine/openssl pull) or a TOCTOU-missing exe must degrade to the
        # next path / the clean 'could not generate' message, not a raw traceback.
        try:
            r = run(cmd, capture_output=True, text=True, **kw)
        except Exception:  # noqa: BLE001
            return False
        return getattr(r, "returncode", 1) == 0 and _cert_pair_present(cert_dir)

    if shutil.which("openssl") is not None:
        # MSYS_NO_PATHCONV stops Git-for-Windows from mangling the leading-slash -subj into a path.
        env = dict(os.environ, MSYS_NO_PATHCONV="1", MSYS2_ARG_CONV_EXCL="*")
        old_umask = os.umask(0o077) if os.name != "nt" else None  # openssl writes key.pem mode-600 (no window)
        try:
            ok = _try(["openssl"] + args, cwd=cert_dir, env=env, timeout=60)
        finally:
            if old_umask is not None:
                os.umask(old_umask)
        if ok:
            return True, "generated a self-signed certificate with host openssl"
    if shutil.which("docker") is not None:
        mount = os.path.abspath(cert_dir).replace("\\", "/")  # forward slashes for docker -v on Windows
        if _try(["docker", "run", "--rm", "-v", "%s:/certs" % mount, "-w", "/certs", "alpine/openssl"] + args,
                timeout=180):
            return True, "generated a self-signed certificate via a throwaway container"
    return False, "could not generate a certificate (no working openssl, host or container)"


def _cert_pair_present(cert_dir):
    return (os.path.exists(os.path.join(cert_dir, "cert.pem"))
            and os.path.exists(os.path.join(cert_dir, "key.pem")))


# --- setup: cert parity — bring-your-own, Let's Encrypt, cert-owner/userns, port preflight -----
# The in-container app user; certs must be readable by it through the read-only bind mount.
APP_UID = 10001
CERT_MODES = ("selfsigned", "letsencrypt", "byo")


def key_is_encrypted(key_text):
    """True if a PEM private key is passphrase-encrypted. uvicorn is given no passphrase, so such a
    key can never serve — bring-your-own must reject it up front. Pure (mirrors `grep ENCRYPTED`)."""
    return "ENCRYPTED" in (key_text or "")


def cert_key_match(cert_path, key_path, run=subprocess.run):
    """True iff cert + key are a matching pair (public keys agree), via openssl. None when openssl
    is unavailable or can't parse either (the caller then warns rather than blocking)."""
    if shutil.which("openssl") is None:
        return None

    def _pub(args):
        try:
            r = run(["openssl"] + args, capture_output=True, text=True, timeout=30)
        except Exception:  # noqa: BLE001
            return None
        return r.stdout.strip() if getattr(r, "returncode", 1) == 0 else None

    cpub = _pub(["x509", "-in", cert_path, "-pubkey", "-noout"])
    kpub = _pub(["pkey", "-in", key_path, "-pubout"])
    if cpub is None or kpub is None:
        return None
    return cpub == kpub


def install_byo_cert(cert_dir, cert_path, key_path, run=subprocess.run):
    """Install a bring-your-own fullchain cert + key into cert_dir/{cert,key}.pem. Rejects a
    passphrase-encrypted key and a mismatched pair. Returns (ok, message)."""
    if not os.path.exists(cert_path):
        return False, "certificate not found: %s" % cert_path
    if not os.path.exists(key_path):
        return False, "private key not found: %s" % key_path
    if key_is_encrypted(open(key_path, encoding="utf-8", errors="ignore").read()):
        return False, "the private key is passphrase-encrypted; decrypt it first (uvicorn can't load it)"
    match = cert_key_match(cert_path, key_path, run=run)
    if match is False:
        return False, "the certificate and private key are not a matching pair"
    os.makedirs(cert_dir, exist_ok=True)
    shutil.copyfile(cert_path, os.path.join(cert_dir, "cert.pem"))   # the cert is public
    _copy_secret(key_path, os.path.join(cert_dir, "key.pem"))        # the key is created mode-600 (no window)
    tighten_secret_file(os.path.join(cert_dir, "key.pem"))
    caveat = "" if match else " (could not verify the pair - no openssl; ensure they match)"
    return True, "installed the bring-your-own certificate" + caveat


RENEWAL_HOOK = "/etc/letsencrypt/renewal-hooks/deploy/dockvault-vault.sh"


def renewal_hook_platform_ok():
    """True on Linux, where the renewal hook runs as written: its `stat -c` and `mv -T` are GNU coreutils' (or
    BusyBox's). macOS and the BSDs have neither, so there every renewal would stop before it deployed the certificate:
    Let's Encrypt automation is refused there, and Windows has no certbot hooks at all."""
    return sys.platform.startswith("linux")


def render_renewal_hook(app_dir, cert_dir, server_name, service, live_dir=None, owners=(0, APP_UID)):
    """The certbot deploy-hook script text, which certbot runs as root, unattended, at each renewal: stage the new
    fullchain/privkey, VALIDATE the pair, swap it into cert_dir keeping the live key's owner and mode, then restart
    the web container so uvicorn reloads.

    It trusts nothing a less trusted account could change. It reads no file of the checkout (`app_dir`, which may
    belong to another account): no compose file, no .env, and it restarts the container by its fixed name. It works
    in the certificate folder only once it has entered it and found it to be the very folder setup made (its
    physical path, so not a link put in its place), owned by root or by the container's app user (`owners`), and
    writable by nobody else; then nobody else can put a name in it. It stages in a fresh folder of its own there,
    and its changes of owner and mode follow no link (chown -h, files it just made), its moves replace names
    (mv -T). Anything else stops it before it changes anything. Pure text, for Linux (bash, and the stat -c and
    mv -T of GNU coreutils or BusyBox; renewal_hook_platform_ok)."""
    q = shlex.quote
    real = os.path.realpath(cert_dir)
    live = live_dir or "/etc/letsencrypt/live/%s" % server_name
    allowed = " ".join(str(int(o)) for o in sorted(set(owners)))
    stop = 'echo "dockvault renewal: %s; nothing was renewed" >&2; exit 1'
    return "\n".join([
        "#!/bin/bash",
        "# Written by dockvault.py - deploys a renewed Let's Encrypt cert into the vault stack and",
        "# restarts the web container so uvicorn picks it up. It reads nothing from the checkout.",
        "set -eu",
        "LIVE=%s" % q(live),
        "CD=%s" % q(real),
        'cd -P -- "$CD" || { %s; }' % (stop % "cannot enter the certificate folder"),
        '[ "$(pwd -P)" = "$CD" ] || { %s; }' % (stop % "the certificate folder is not the one setup made"),
        "_o=\"$(stat -c '%u' .)\"",
        "_m=\"$(stat -c '%a' .)\"",
        'case " %s " in *" $_o "*) ;; *) %s;; esac' % (allowed, stop % "the certificate folder is not owned by "
                                                                       "root or the app user"),
        '[ $(( 0$_m & 022 )) -eq 0 ] || { %s; }' % (stop % "the certificate folder is writable by others"),
        'T="$(mktemp -d .renew.XXXXXX)"',
        "trap 'rm -rf -- \"$T\"' EXIT",
        'install -m 600 "$LIVE/fullchain.pem" "$T/cert.pem"',
        'install -m 600 "$LIVE/privkey.pem" "$T/key.pem"',
        "_own=\"$(stat -c '%u:%g' key.pem 2>/dev/null || echo 0:0)\"",
        "_mode=\"$(stat -c '%a' key.pem 2>/dev/null || echo 600)\"",
        'chown -h "$_own" "$T/key.pem" "$T/cert.pem"',
        'chmod "$_mode" "$T/key.pem"',
        'chmod 644 "$T/cert.pem"',
        '_c="$(openssl x509 -in "$T/cert.pem" -pubkey -noout)"',
        '_k="$(openssl pkey -in "$T/key.pem" -pubout)"',
        # Under set -e a failure in an && list stops nothing unless it is the list's last command: an empty "$_c"
        # (an openssl that printed nothing) would have let the swap go on. The list's outcome stops it here.
        '[ -n "$_c" ] && [ "$_c" = "$_k" ] || { %s; }' % (stop % "the renewed certificate and key are not a pair, "
                                                                "or openssl could not read them"),
        'mv -fT "$T/key.pem" key.pem',
        'mv -fT "$T/cert.pem" cert.pem',
        "docker restart %s" % q(service),
        "",
    ])


def install_renewal_hook(app_dir, cert_dir, server_name, service, owners=(0, APP_UID), hook=RENEWAL_HOOK,
                         live_dir=None):
    """Write the certbot deploy hook (POSIX), root's, 755: written whole beside its name and moved over it, so the
    name is never written through (a link there is replaced, not followed). Returns True on success."""
    tmp = None
    try:
        os.makedirs(os.path.dirname(hook), exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".dockvault-hook-", dir=os.path.dirname(hook))
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(render_renewal_hook(app_dir, cert_dir, server_name, service, live_dir=live_dir, owners=owners))
        os.chmod(tmp, 0o755)
        os.replace(tmp, hook)
        tmp = None
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        if tmp is not None:
            try:
                os.remove(tmp)
            except OSError:
                pass


def renewal_hook_targets(text):
    """(the certificate folder, the Let's Encrypt live folder) that a renewal hook this tool wrote names, in any of
    its versions (`CD=` and `LIVE=` lines, or the live folder in the install lines of the first one), or None when
    the text names either not, or not once."""
    found = {}
    for line in text.splitlines():
        line = line.strip()
        for name in ("CD", "LIVE"):
            if line.startswith(name + "="):
                try:
                    words = shlex.split(line[len(name) + 1:])
                except ValueError:
                    return None
                if len(words) != 1 or name in found:
                    return None
                found[name] = words[0]
    if "LIVE" not in found:
        lives = set(re.findall(r'/etc/letsencrypt/live/([^/"\'\s]+)/(?:fullchain|privkey)\.pem', text))
        if len(lives) == 1:
            found["LIVE"] = "/etc/letsencrypt/live/" + lives.pop()
    if not found.get("CD") or not found.get("LIVE"):
        return None
    return found["CD"], found["LIVE"]


def refresh_renewal_hook(app_dir, cert_dir, service, owners=None, hook=RENEWAL_HOOK, is_root=None):
    """A setup re-run keeps the certificate it finds, so it never writes the Let's Encrypt renewal hook: an upgraded
    deployment kept the hook an earlier version wrote, which runs docker compose as root with the checkout's files.
    This brings this deployment's hook (the one that names its certificate folder) to the text install_renewal_hook
    writes now, keeping the live folder it renews from. Returns (outcome, a message or None), the outcome one of:
    "none" (no hook, or another deployment's: nothing to do), "unsupported" (not Linux: left as it is), "current",
    "rewritten", "not-root" (only root may write it: left as it is), "unreadable" (it could not be read, or names no
    certificate folder and live folder: left as it is) and "failed" (it could not be written). `owners`: the owners
    the hook accepts for the
    certificate folder, as obtain_letsencrypt_cert gives them (root, the app's uid, the uid a remapping engine maps
    it to) when None."""
    if not os.path.lexists(hook):
        return "none", None
    if not renewal_hook_platform_ok():
        return "unsupported", ("the Let's Encrypt renewal hook %s was left as it is: this version writes it on Linux "
                               "only (it needs the stat -c and mv -T of GNU coreutils or BusyBox)" % hook)
    try:
        with open(hook, encoding="utf-8") as f:
            text = f.read()
    except (OSError, ValueError) as exc:
        return "unreadable", ("could not read the Let's Encrypt renewal hook %s (%s), so it was left as it is"
                              % (hook, exc))
    targets = renewal_hook_targets(text)
    if targets is None:
        return "unreadable", ("the Let's Encrypt renewal hook %s names no certificate folder and live folder this "
                              "tool can read, so it was left as it is" % hook)
    named, live = targets
    if os.path.realpath(named) != os.path.realpath(cert_dir):
        return "none", None
    if owners is None:
        mapped = _remapped_cert_owner()
        owners = (0, APP_UID) + ((mapped,) if mapped is not None else ())
    if text == render_renewal_hook(app_dir, cert_dir, os.path.basename(live), service, live_dir=live, owners=owners):
        return "current", None
    if is_root is None:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if not is_root:
        why = ("it was written by an earlier version, and at each renewal it runs, as root, what this checkout's "
               "compose file and .env say" if "docker compose" in text else "it was written for other settings")
        return "not-root", ("the Let's Encrypt renewal hook %s is not the one this version writes: %s. Run setup "
                            "again as root (sudo python3 dockvault.py setup) to replace it" % (hook, why))
    if not install_renewal_hook(app_dir, cert_dir, os.path.basename(live), service, owners=owners, hook=hook,
                                live_dir=live):
        return "failed", "could not rewrite the Let's Encrypt renewal hook %s; it was left as it was" % hook
    return "rewritten", ("rewrote the Let's Encrypt renewal hook %s: it reads nothing of the checkout and restarts "
                         "the %s container by name" % (hook, service))


def obtain_letsencrypt_cert(cert_dir, server_name, email, app_dir, service, run=subprocess.run):
    """Obtain a Let's Encrypt cert via certbot standalone (http-01, binds port 80), install it, and
    write the auto-renewal deploy hook. POSIX-only (needs certbot + root + a public DNS name reachable
    on port 80). Returns (ok, message)."""
    if not renewal_hook_platform_ok():
        return False, ("Let's Encrypt automation is Linux-only here (the renewal hook needs the stat -c and mv -T of "
                       "GNU coreutils or BusyBox, which this system does not have): use --cert-mode byo with a "
                       "certificate you renew yourself, or self-signed")
    if is_ipv4(server_name):
        return False, "Let's Encrypt cannot issue for a bare IP - use a DNS name, or self-signed."
    if shutil.which("certbot") is None:
        return False, "certbot is not installed (e.g. apt-get install certbot); or use --cert-mode byo."
    try:
        r = run(["certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos",
                 "-m", email or "admin@example.com", "-d", server_name], text=True, timeout=300)
    except Exception as e:  # noqa: BLE001
        return False, "certbot failed: %s" % e
    if getattr(r, "returncode", 1) != 0:
        return False, "certbot did not obtain a certificate (is port 80 reachable from the internet?)"
    live = "/etc/letsencrypt/live/%s" % server_name
    ok, msg = install_byo_cert(cert_dir, live + "/fullchain.pem", live + "/privkey.pem", run=run)
    if not ok:
        return False, msg
    # The owners the hook accepts for the certificate folder: root, and whom apply_cert_owner hands it to (the app's
    # uid, or the host uid it maps to on a userns-remap engine).
    mapped = _remapped_cert_owner(run)
    install_renewal_hook(app_dir, cert_dir, server_name, service,
                         owners=(0, APP_UID) + ((mapped,) if mapped is not None else ()))
    return True, "obtained a Let's Encrypt certificate + installed the auto-renewal hook"


def parse_subuid_base(subuid_text, user):
    """The base subordinate uid allocated to `user` in /etc/subuid (or None). Pure — used to resolve
    the HOST uid a userns-remapped container's app user maps to, so a mode-600 key can be chowned to
    the right owner instead of made world-readable."""
    for line in (subuid_text or "").splitlines():
        parts = line.strip().split(":")
        if len(parts) >= 2 and parts[0] == user:
            try:
                base = int(parts[1])
            except ValueError:
                return None
            return base if base >= 1000 else None  # a subuid base is never a low/system uid
    return None


def _engine_is_remapped(run=subprocess.run):
    """True if the Docker engine remaps container uids to SUBORDINATE host uids - rootless OR
    rootful userns-remap. In that case the in-container app user is NOT host uid 10001, so a
    host-10001-owned mode-600 key is unreadable inside the container unless the mapping is resolvable
    and the key is chowned to the mapped host uid. Mirrors setup-secure.sh's `_remapped_engine`
    (which greps `rootless|name=userns`)."""
    try:
        r = run(["docker", "info", "--format", "{{join .SecurityOptions \",\"}}"],
                capture_output=True, text=True, timeout=15)
    except Exception:  # noqa: BLE001
        return False
    opts = getattr(r, "stdout", "") or ""
    return "rootless" in opts or "name=userns" in opts


def _cert_mount(cert_dir):
    """The `docker -v` source for the cert dir (forward slashes so a Windows path is accepted)."""
    return os.path.abspath(cert_dir).replace("\\", "/")


def cert_readable_by_app_uid(cert_dir, run=subprocess.run):
    """Can the in-container app user (uid APP_UID) actually READ cert.pem AND key.pem through the
    read-only bind mount? True / False / None (couldn't determine: no docker, or the probe itself
    failed). This is the ONLY honest check - host permissions do not predict what the container
    sees (a Docker Desktop bind mount carries POSIX modes written from inside a container, and a
    remapped engine shifts the uid) - and it catches the failure that otherwise surfaces only as
    uvicorn's `PermissionError: [Errno 13]` in an endless restart loop. Reads ONE byte and discards
    it, so the private key never reaches the host's stdout or a log."""
    if shutil.which("docker") is None:
        return None
    probe = ("head -c 1 /certs/cert.pem >/dev/null 2>&1 && head -c 1 /certs/key.pem >/dev/null 2>&1")
    try:
        r = run(["docker", "run", "--rm", "--user", "%d:%d" % (APP_UID, APP_UID),
                 "-v", "%s:/certs:ro" % _cert_mount(cert_dir), "busybox", "sh", "-c", probe],
                capture_output=True, text=True, timeout=120)
    except Exception:  # noqa: BLE001 - an unavailable/slow docker is "undetermined", not "unreadable"
        return None
    rc = getattr(r, "returncode", 125)
    if rc in (125, 126, 127):
        return None      # docker itself failed (bad image/mount) - not a permission verdict
    return rc == 0


def _chown_certs_in_container(cert_dir, run=subprocess.run):
    """Set cert ownership + modes from INSIDE a throwaway container. On an engine whose bind mounts
    carry POSIX metadata the host cannot express (Docker Desktop on Windows/macOS), this is the only
    way to hand the key to the app uid: openssl writes key.pem mode 600 owned by uid 0, and host
    ACLs cannot re-own it. Keeps the key at 600 (owner-only) rather than making it world-readable."""
    if shutil.which("docker") is None:
        return False
    fix = ("chown %d:%d /certs/cert.pem /certs/key.pem && chmod 644 /certs/cert.pem "
           "&& chmod 600 /certs/key.pem" % (APP_UID, APP_UID))
    try:
        r = run(["docker", "run", "--rm", "-v", "%s:/certs" % _cert_mount(cert_dir),
                 "busybox", "sh", "-c", fix], capture_output=True, text=True, timeout=120)
    except Exception:  # noqa: BLE001
        return False
    return getattr(r, "returncode", 1) == 0


_CERT_DENIED = ("the container's app user (uid %d) cannot read certs/key.pem - the vault would fail "
                "to start with 'PermissionError: [Errno 13]'. Re-install the pair, or delete the "
                "certs/ directory and re-run setup to regenerate a self-signed one." % APP_UID)
_CERT_UNKNOWN = ("could not check whether the container can read certs/ (the Docker engine did not "
                 "answer) - the certificates themselves are untouched. Re-run setup once Docker is "
                 "running.")


def _apply_cert_owner_container(cert_dir, run=subprocess.run):
    """The Windows/Docker-Desktop path for apply_cert_owner: re-own the pair to APP_UID from inside
    a container, then VERIFY the app uid can read it. Returns (mode600, message) like its caller.

    Keeps the probe's THREE states apart. 'Could not determine' (Docker not running, image missing)
    must never be reported as 'the key is unreadable' with advice to delete the certificates - that
    would talk an operator into destroying a bring-your-own or Let's Encrypt pair over a stopped
    daemon."""
    verdict = cert_readable_by_app_uid(cert_dir, run)
    if verdict is True:
        return True, "certs are readable by the container's app user (key mode 600)"
    if not _chown_certs_in_container(cert_dir, run):
        return False, (_CERT_UNKNOWN if verdict is None else _CERT_DENIED)
    after = cert_readable_by_app_uid(cert_dir, run)
    if after is True:
        return True, "certs re-owned to uid %d for the container (key mode 600, not world-readable)" % APP_UID
    return False, (_CERT_UNKNOWN if after is None else _CERT_DENIED)


def apply_cert_owner(cert_dir, run=subprocess.run):
    """Make cert_dir/{cert,key}.pem readable by the in-container app user through the read-only bind
    mount. On a plain rootful engine, chown to APP_UID (10001) keeping the key mode 600.
    On a userns-remap engine, chown to the MAPPED host uid (resolved from /etc/subuid), keeping 600.
    When the host cannot chown (setup not run as root, a ROOTLESS engine, a mapped uid that can't be
    resolved), a throwaway container re-owns the pair, keeping 600, and the container's view is
    verified. Only when that fails too does it fall back to a world-readable key (644, single-tenant
    host) so the container CAN read it - NEVER falsely reporting a mode-600 key when it would be
    unreadable. Returns (mode600, message)."""
    if os.name == "nt":
        # NOT a no-op: a Docker Desktop bind mount carries the POSIX mode of whatever wrote the file,
        # and openssl writes key.pem 0600 owned by uid 0 - unreadable to the app's uid 10001. The host
        # has no chown to fix that, so do it from inside a container and verify.
        return _apply_cert_owner_container(cert_dir, run)
    key = os.path.join(cert_dir, "key.pem")
    cert = os.path.join(cert_dir, "cert.pem")
    for path, mode in ((cert_dir, 0o700), (cert, 0o644), (key, 0o600)):
        try:
            os.chmod(path, mode)
        except OSError:
            pass

    def _world_readable(reason):
        for path, mode in ((cert_dir, 0o755), (key, 0o644)):
            try:
                os.chmod(path, mode)
            except OSError:
                pass
        return False, reason

    def _in_a_container(reason):
        # The host cannot hand the pair to the container's user (setup is not run as root, or the engine maps that
        # user to a subordinate uid): a container can, as Docker's own root, keeping the key 600, as on Windows.
        # The folder is opened to 755 (its names, not the key) so that the container's user reaches the files, and
        # what the container then sees is verified. Only when that fails is the key made world-readable.
        try:
            os.chmod(cert_dir, 0o755)
        except OSError:
            pass
        ok, msg = _apply_cert_owner_container(cert_dir, run)
        return (True, msg) if ok else _world_readable(reason)

    if _engine_is_remapped(run):
        owner = _remapped_cert_owner(run)   # mapped host uid (userns-remap), or None (rootless/unresolvable)
        if owner is None:
            return _in_a_container(
                "rootless/userns Docker: the container's app user is a subordinate host uid, so a "
                "mode-600 key owned by uid %d would be unreadable inside the container, and a container "
                "could not re-own it either. Made the TLS key world-readable (644) so the container can read "
                "it - host assumed single-tenant, restrict access accordingly." % APP_UID)
    else:
        owner = APP_UID
    try:
        for path in (cert_dir, cert, key):
            os.chown(path, owner, owner)
        if os.stat(key).st_uid == owner:
            return True, "certs owned by uid %d (key mode 600, not world-readable)" % owner
    except OSError:
        pass
    return _in_a_container(
        "could not chown certs to the container uid, on the host or from a container; made the TLS key "
        "world-readable (644) so the container can read it - host assumed single-tenant, restrict access "
        "accordingly.")


def _key_already_private(key):
    """POSIX: the key's mode gives nothing to group or others. A key a container re-owned to the app user (a setup
    not run as root) cannot be chmodded by this user again, and needs not be: it is 600 already."""
    if os.name == "nt":
        return False
    try:
        return (os.stat(key).st_mode & 0o077) == 0
    except OSError:
        return False


def _remapped_cert_owner(run=subprocess.run):
    """If the Docker engine uses rootful userns-remap, the HOST uid the container's APP_UID maps to
    (base subuid + APP_UID), else None. Only the rootful userns-remap case is resolvable from the
    host (rootless needs the daemon-user's subuid + a different offset, so it gets the world-readable
    fallback)."""
    try:
        r = run(["docker", "info", "--format", "{{join .SecurityOptions \",\"}}"],
                capture_output=True, text=True, timeout=15)
    except Exception:  # noqa: BLE001
        return None
    if "name=userns" not in (getattr(r, "stdout", "") or ""):
        return None
    user = "dockremap"
    try:
        with open("/etc/docker/daemon.json", encoding="utf-8") as f:
            m = re.search(r'"userns-remap"\s*:\s*"([^"]*)"', f.read())
        if m and m.group(1) not in ("", "default"):
            user = m.group(1).split(":")[0]
    except Exception:  # noqa: BLE001
        pass
    try:
        base = parse_subuid_base(open("/etc/subuid", encoding="utf-8").read(), user)
    except Exception:  # noqa: BLE001
        return None
    return (base + APP_UID) if base is not None else None


def port_free(port, host="0.0.0.0"):
    """True if `port` is free to bind on `host` right now. A real bind probe WITHOUT SO_REUSEADDR -
    that option would let the bind succeed against a port another socket already holds (on Windows
    SO_REUSEADDR behaves like SO_REUSEPORT), giving a false 'free' for a genuinely busy port. A
    privileged-port EACCES/EPERM (a non-root probe of a <1024 port like 443) is treated as
    'can't determine -> not busy', so setup doesn't false-warn when nothing actually holds it."""
    import errno
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, int(port)))
        return True
    except OverflowError:
        return False  # a port outside 0..65535 (hand-edited/CLI) is not bindable
    except OSError as e:
        return e.errno in (errno.EACCES, errno.EPERM)
    finally:
        s.close()


def prompt_free_port(pal, label, default, ask_fn=None, free_fn=None):
    """Prompt for a host port, RE-PROMPTING until the entered port is free to bind (or the operator
    frees the port and re-enters the same one). Returns the chosen int port. If the SAME answer comes
    back twice in a row (e.g. a non-TTY stdin returning the default each time), it stops re-prompting
    to avoid an endless loop. `ask_fn`/`free_fn` are injectable for tests."""
    ask_fn = ask_fn or ask
    free_fn = free_fn or port_free
    last = object()  # a sentinel that won't equal any real answer on the first pass
    while True:
        raw = ask_fn("%s host port" % label, pal, str(default))
        repeated, last = (raw == last), raw
        try:
            port = int(str(raw).strip())
        except (TypeError, ValueError):
            print(pal.paint("  enter a number between 1 and 65535", "red"))
            if repeated:
                return int(default)
            continue
        if not (1 <= port <= 65535):
            print(pal.paint("  the port must be between 1 and 65535", "red"))
            if repeated:
                return int(default)
            continue
        if free_fn(port):
            return port
        print(pal.paint("  port %d is already in use - free it and re-enter, or choose another." % port, "yellow"))
        if repeated:
            print(pal.paint("  using %d anyway (it may be busy); free it before starting." % port, "yellow"))
            return port


# --- volume management (labels + bundle enumeration) -----------------------------------------
# A deployment's data lives in five named volumes that MUST stay together with the .env that holds
# their secrets ({.env, pg_data, storage, keys} is one atomic bundle). The deploy composes label
# every volume (com.dockvault.managed=true / role=<...> / bundle=${DEPLOYMENT_ID:-default}) so the
# tool can enumerate a deployment's volumes as one set. Labels are applied at CREATE time only, so a
# pre-label ("legacy") deployment keeps its (unlabelled) volumes and is adopted under the "default"
# bundle - additive metadata, never a data move.
VOLUME_ROLES = ("pg", "storage", "keys", "logs", "brand")
VOLUME_BASENAMES = {"pg": "vault_pg_data", "storage": "vault_storage", "keys": "vault_keys",
                    "logs": "vault_logs", "brand": "vault_brand"}
DEFAULT_PROJECT = "dockvault-vault"
_VOL_LS_FORMAT = '{{.Name}}\t{{.Label "com.dockvault.role"}}\t{{.Label "com.dockvault.bundle"}}'


GIB = 1024 ** 3


def parse_max_storage_gb(raw):
    """The MAX_STORAGE_GB .env value -> a number of GB, or None when unset/blank/unparseable.
    Accepts the historical PLAN_MAX_STORAGE_GB spelling at the call site, not here."""
    text = (raw or "").strip().strip("'").strip('"')
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def _unquoted(raw):
    """A configured value as text: an .env line, or a number argparse has already converted.

    `--max-concurrent-transfers 0` arrives here as the integer 0, which is both un-strippable and
    falsy -- so treating "no value" as falsiness would raise on one input and silently discard the
    other. Only None and an empty string mean unset.
    """
    if raw is None:
        return ""
    if isinstance(raw, (int, float)):
        return repr(raw)
    return str(raw).strip().strip("'").strip('"')


def _finite_float(raw):
    """An .env value as a finite float, or None. 'inf' and 'nan' parse as floats and then break
    every comparison downstream, so they are unusable values rather than numbers."""
    text = _unquoted(raw)
    if not text:
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def parse_transfer_limit(raw):
    """MAX_CONCURRENT_TRANSFERS -> the ceiling the application would apply, or None if unset.

    Clamped rather than rejected, because the application clamps: it reads anything below one as
    one. Dropping a 0 here would carry it forward as "not configured", which is the default of
    sixteen -- silently widening a ceiling an operator had set as tight as it goes."""
    value = _finite_float(raw)
    return None if value is None else max(1, int(value))


def parse_transfer_queue(raw):
    """MAX_QUEUED_TRANSFERS -> the waiting room the application would apply, or None if unset.
    Zero is a real choice (refuse at once rather than queue); negatives read as zero."""
    value = _finite_float(raw)
    return None if value is None else max(0, int(value))


# The application caps the wait at an hour (TransferAdmission.MAX_WAIT_SECONDS). Mirrored here
# rather than imported, because this tool runs from a checkout that may not have the application
# importable -- the value is locked to the application's by a test.
TRANSFER_WAIT_CEILING_SECONDS = 3600


def parse_transfer_wait(raw):
    """TRANSFER_QUEUE_WAIT_SECONDS -> seconds, as the application would read them, or None.

    Clamped to the same ceiling the application applies, so what the tool writes back is what the
    deployment was actually doing rather than what its .env happened to say. Whole numbers come
    back whole so the .env reads '20' rather than '20.0'."""
    value = _finite_float(raw)
    if value is None:
        return None
    value = min(float(TRANSFER_WAIT_CEILING_SECONDS), max(0.0, value))
    return int(value) if value == int(value) else value


def parse_single_request_upload_mb(raw):
    """MAX_SINGLE_REQUEST_UPLOAD_MB -> the cap the application would apply, in MiB, or None if unset.
    Zero is a real choice (the cap is off); a negative is refused by the application, so it is
    carried as zero rather than as "not configured", which would be the default of 64."""
    value = _finite_float(raw)
    return None if value is None else max(0, int(value))


def format_gb_value(gb):
    """A GB number as an .env value. Deliberately not '%g': that renders large numbers in
    exponent notation ('1e+06'), and a whole number should read as '64', not '64.0'."""
    gb = float(gb)
    return str(int(gb)) if gb == int(gb) else repr(gb)


def format_bytes(n):
    """Bytes as a short human string for the console ('2.50 GB', '512 MB', '900 B')."""
    n = int(n or 0)
    for unit, size in (("GB", GIB), ("MB", 1024 ** 2), ("KB", 1024)):
        if n >= size:
            value = n / size
            return "%.2f %s" % (value, unit) if value < 10 else "%.0f %s" % (value, unit)
    return "%d B" % n


def storage_limit_problem(requested_gb, stored_bytes):
    """Why a proposed deployment storage limit is unacceptable, or None when it is fine.

    -1 (unlimited) is always acceptable. Otherwise the limit may not be set below what is ALREADY
    stored, which would strand existing files above a limit nobody can satisfy without deleting
    data. Physical disk capacity is deliberately NOT a refusal — a volume can be grown under a
    running deployment — so the caller warns about it instead.
    """
    if requested_gb is None:
        return "Enter a number of GB, or -1 for unlimited."
    if requested_gb < 0 and requested_gb != -1:
        return "A negative limit other than -1 (unlimited) is not a size."
    if requested_gb == -1:
        return None
    if requested_gb == 0:
        # 0 in this variable means "no ceiling configured", the same as -1 — so accepting it here
        # would hand an operator asking for a full stop the exact opposite. A stop is a LIVE limit,
        # which the vault's own Settings page can express (its 0 does mean zero).
        return ("0 here means 'no ceiling', not 'no storage'. To stop new uploads, set the live "
                "limit to 0 in the vault's Settings -> Storage; use -1 here for no ceiling.")
    if stored_bytes is not None and requested_gb * GIB < stored_bytes:
        return ("%s is already stored, so the limit cannot go below that. Delete files first, "
                "then lower the limit." % format_bytes(stored_bytes))
    return None


def gen_deployment_id():
    """A short, stable, label-safe bundle id for a fresh deployment (8 lowercase hex chars). Used as
    DEPLOYMENT_ID in .env so the deployment's volumes are labelled/grouped as one bundle."""
    return gen_hex(4)


def parse_volume_ls(output):
    """Parse the tab-separated `docker volume ls --format <_VOL_LS_FORMAT>` output into a list of
    {name, role, bundle} records. Blank lines are skipped; an empty bundle field falls back to
    'default' (matching the compose ${DEPLOYMENT_ID:-default}); an empty role stays None. Pure."""
    records = []
    for line in (output or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        name = parts[0].strip()
        if not name:
            continue
        role = (parts[1].strip() if len(parts) > 1 else "") or None
        bundle = (parts[2].strip() if len(parts) > 2 else "") or "default"
        records.append({"name": name, "role": role, "bundle": bundle})
    return records


def group_volumes_by_bundle(records):
    """Group parsed volume records by their bundle id, preserving first-seen order. Returns
    [(bundle, [records...]), ...]. Pure."""
    order, groups = [], {}
    for r in records:
        b = r["bundle"]
        if b not in groups:
            groups[b] = []
            order.append(b)
        groups[b].append(r)
    return [(b, groups[b]) for b in order]


def list_managed_volumes(run=subprocess.run):
    """Enumerate DockVault-managed volumes by their labels. Returns [{name, role, bundle}] (possibly
    empty). Returns [] when docker is unavailable or the query fails - a best-effort read."""
    try:
        r = run(["docker", "volume", "ls", "--filter", "label=com.dockvault.managed=true",
                 "--format", _VOL_LS_FORMAT], capture_output=True, text=True, timeout=30)
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    if getattr(r, "returncode", 1) != 0:
        return []
    return parse_volume_ls(r.stdout or "")


def list_legacy_volumes(run=subprocess.run, project=DEFAULT_PROJECT):
    """The canonical <project>_<basename> volumes that EXIST but carry no com.dockvault.managed
    label - a pre-label deployment. Returns their names (sorted). The tool adopts them under the
    'default' bundle. Best-effort: [] when docker is unavailable."""
    wanted = {"%s_%s" % (project, base) for base in VOLUME_BASENAMES.values()}
    fmt = '{{.Name}}\t{{.Label "com.dockvault.managed"}}'
    try:
        r = run(["docker", "volume", "ls", "--format", fmt],
                capture_output=True, text=True, timeout=30)
    except (OSError, ValueError, subprocess.SubprocessError):
        return []
    if getattr(r, "returncode", 1) != 0:
        return []
    legacy = []
    for line in (r.stdout or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        name = parts[0].strip()
        managed = (parts[1].strip() if len(parts) > 1 else "")
        if name in wanted and managed != "true":
            legacy.append(name)
    return sorted(legacy)


# --- volume SETS (prefix-based reuse / create-new / repoint) ---------------------------------
# A "set" is one deployment's five volumes, named <prefix>_vault_<role>. The prefix lives in .env
# as VAULT_VOLUME_PREFIX (default DEFAULT_PROJECT = the historical names). Switching the prefix (with
# its paired .env) points the stack at a different set, so multiple sets can sit side by side.
def volume_prefix(env):
    """The current set's volume-name prefix from a parsed .env (VAULT_VOLUME_PREFIX, else the
    historical default). Blank/absent -> DEFAULT_PROJECT."""
    return (env.get("VAULT_VOLUME_PREFIX") or "").strip() or DEFAULT_PROJECT


def set_volume_names(prefix):
    """The five volume names for a set with this prefix: {role: '<prefix>_<basename>'}."""
    return {role: "%s_%s" % (prefix, base) for role, base in VOLUME_BASENAMES.items()}


def valid_volume_prefix(prefix):
    """True if `prefix` is a safe docker volume-name prefix (docker's own rule: an alnum start then
    alnum/_/./-, no slash or traversal). Used to reject a crafted backup manifest whose prefix could
    otherwise redirect a restore's `-v` bind mount to an arbitrary host path."""
    return bool(prefix) and re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", prefix) is not None


def volume_set_prefix(name):
    """Derive a set's prefix from a DockVault volume name ('<prefix>_vault_<role>'), or None if the
    name doesn't end in a known volume basename."""
    for base in VOLUME_BASENAMES.values():
        suffix = "_" + base
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[:-len(suffix)]
    return None


# The names beside .env that are never a set's kept or archived .env, whatever the set is called: the sealed .env
# (lock's .env.enc) and the template (.env.example). A plain .env under the first would be taken for the sealed one
# (lock would refuse to seal, status would call it sealed, and deleting it as a stale sealed file would delete the
# set's only key) and kept out of the list of plain-text archives; under the second, for the template. A set named
# 'enc' or 'example' has its .env kept as .env.enc.1, .env.example.1 instead. Compared without case, and without
# trailing dots and spaces: where file names ignore case, .env.ENC is the sealed file, and Windows opens .env.enc.
# (the name for a set called 'enc.', a valid volume name) as .env.enc.
RESERVED_ENV_NAMES = (".env.enc", ".env.example")


def _env_copy_number(label, name):
    """The number of the name `name` among the names of set `label`'s kept or archived .env copies (0 for
    .env.<label>, n for .env.<label>.<n>), or None when it is not one of them (.env.<label>.x is another set's, whose
    prefix is <label>.x)."""
    base = ".env." + label
    if name == base:
        return 0
    if name.startswith(base + ".") and re.match(r"^[0-9]+$", name[len(base) + 1:]):
        return int(name[len(base) + 1:])
    return None


def _env_copies_there(root, label):
    """[(number, path)] of every name in `root` that is one of set `label`'s copy names, of any kind."""
    found = []
    for path in glob.glob(os.path.join(glob.escape(root), glob.escape(".env." + label) + "*")):
        number = _env_copy_number(label, os.path.basename(path))
        if number is not None:
            found.append((number, path))
    return found


def env_copy_names(root, label):
    """The names a kept or archived .env of `label` may take in `root`, in order: .env.<label> when no copy of it is
    there, else .env.<label>.<n> from the number after the highest one there, so that the newest copy always has
    the highest number (kept_env_copies takes the newest by it), never one of RESERVED_ENV_NAMES. A free name below
    the highest (a copy deleted since) is not taken again: a copy made there would sort as an old one."""
    base = os.path.join(root, ".env." + label)
    taken = [number for number, _path in _env_copies_there(root, label)]
    n = max(taken) + 1 if taken else 0
    while True:
        name = base if n == 0 else "%s.%d" % (base, n)
        n += 1
        if os.path.basename(name).rstrip(". ").lower() not in RESERVED_ENV_NAMES:
            yield name


def kept_env_copies(root, label):
    """The kept or archived copies of set `label`'s .env in `root` (the names env_copy_names gives: .env.<label>, then
    .env.<label>.1, .2, ...), the newest first: by the number, as a number (.10 after .9, which a sort by text puts
    first), and .env.<label> itself last. A name with any other ending (.env.<label>.x is another set's, whose
    prefix is <label>.x) is not one of them, nor is one of RESERVED_ENV_NAMES (for a set named 'enc', .env.enc is
    the sealed .env). Plain files only."""
    found = [(number, path) for number, path in _env_copies_there(root, label)
             if os.path.basename(path).rstrip(". ").lower() not in RESERVED_ENV_NAMES
             and os.path.isfile(path) and not os.path.islink(path)]
    return [path for _n, path in sorted(found, reverse=True)]


def group_volumes_by_prefix(records):
    """Group parsed volume records into physical SETS by their name prefix, first-seen order:
    [(prefix, [records...]), ...]. Records whose name doesn't parse are grouped under their raw
    name so nothing is silently dropped."""
    order, groups = [], {}
    for r in records:
        key = volume_set_prefix(r["name"]) or r["name"]
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(r)
    return [(k, groups[k]) for k in order]


# ZK_ENVELOPE_HOLD_DAYS: how long the zero-knowledge key envelope stays held after an administrator changes
# an account's sign-in details. The app refuses to start with a value outside 0..14.
ENVELOPE_HOLD_DAYS_DEFAULT = 14


def parse_envelope_hold_days(raw):
    """A ZK_ENVELOPE_HOLD_DAYS value as an int 0..14, or None when it is unset or not one (the app's
    default then applies, and the app itself refuses a value it cannot use at start)."""
    text = str(raw if raw is not None else "").strip()
    if not text:
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if 0 <= value <= 14 else None


def new_set_config(current_env, new_prefix, new_id):
    """Config for a FRESH set (born together with its own .env): keep the current .env's NON-secret
    settings (server, admin, ports, mode, flags) but generate BRAND-NEW secrets - a new set is new
    data, so it must get its own ENCRYPTION_KEY / DB password - and stamp the new volume prefix +
    deployment id. The paired secrets and volumes are created together, upholding the bundle invariant."""
    def truthy(k):
        return (current_env.get(k) or "").strip().lower() in ("1", "true", "yes", "on")
    # A new set is a new admin. Carry the source .env's admin password if it still has one, but a
    # deployment whose spent ADMIN_PASSWORD was dropped after bootstrap has none to carry - generate
    # a fresh one and flag it so the caller shows it once (the operator needs it to log into the new
    # set, and it is the only place it is ever printed).
    src_admin_pw = (current_env.get("ADMIN_PASSWORD") or "").strip()
    cfg = {
        "server_name": current_env.get("SERVER_NAME") or current_env.get("ALLOWED_HOSTS") or "localhost",
        "encryption_key": gen_fernet_key(), "jwt_secret_key": gen_hex(32),
        "vault_db_password": gen_hex(16), "redis_password": gen_hex(24),
        "admin_username": current_env.get("ADMIN_USERNAME") or "admin",
        "admin_email": current_env.get("ADMIN_EMAIL") or "admin@example.com",
        "admin_password": src_admin_pw or gen_hex(12),
        "_generated_admin_pw": not src_admin_pw,
        "compose_profiles": current_env.get("COMPOSE_PROFILES") or "combined",
        "deployment_id": new_id, "volume_prefix": new_prefix,
        "run_sftp": truthy("RUN_SFTP"),
        "web_host_port": _port_or(current_env.get("WEB_HOST_PORT"), 443),
        "sftp_host_port": _port_or(current_env.get("SFTP_HOST_PORT"), 2322),
        # Keep a custom SFTP staging size across a fresh volume set, like the ports above.
        "sftp_staging_tmpfs_mb": (current_env.get("SFTP_STAGING_TMPFS_MB") or "").strip() or None,
        # Keep any custom SFTP connection-admission limits across a fresh volume set too.
        "sftp_max_connections": (current_env.get("SFTP_MAX_CONNECTIONS") or "").strip() or None,
        "sftp_max_connections_per_ip": (current_env.get("SFTP_MAX_CONNECTIONS_PER_IP") or "").strip() or None,
        "sftp_max_authenticated_per_ip": (current_env.get("SFTP_MAX_AUTHENTICATED_PER_IP") or "").strip() or None,
        "sftp_auth_grace_seconds": (current_env.get("SFTP_AUTH_GRACE_SECONDS") or "").strip() or None,
        "sftp_write_progress_timeout_seconds":
            (current_env.get("SFTP_WRITE_PROGRESS_TIMEOUT_SECONDS") or "").strip() or None,
        "sftp_write_progress_min_bytes":
            (current_env.get("SFTP_WRITE_PROGRESS_MIN_BYTES") or "").strip() or None,
        # Keep an SFTP streaming-upload choice (raw, so an explicit "false" rollback survives; default
        # is ON), the reorder window, and the memory ceiling across a fresh volume set.
        "sftp_streaming_upload": (current_env.get("SFTP_STREAMING_UPLOAD") or "").strip() or None,
        "sftp_streaming_reorder_mb": (current_env.get("SFTP_STREAMING_REORDER_MB") or "").strip() or None,
        "sftp_transfer_buffer_mb": (current_env.get("SFTP_TRANSFER_BUFFER_MB") or "").strip() or None,
        # Keep a custom in-flight upload marker TTL across a fresh volume set, like the fields above.
        "upload_marker_ttl_seconds": (current_env.get("UPLOAD_MARKER_TTL_SECONDS") or "").strip() or None,
        # Keep where SFTP clients are told to connect (NAT / port forwarding) across a fresh volume set.
        "sftp_public_host": (current_env.get("SFTP_PUBLIC_HOST") or "").strip() or None,
        "sftp_public_port": (current_env.get("SFTP_PUBLIC_PORT") or "").strip() or None,
        "update_check_enabled": truthy("UPDATE_CHECK_ENABLED"),
        "plan_log_pull": truthy("PLAN_LOG_PULL"),
        "log_token_pepper": gen_hex(32) if truthy("PLAN_LOG_PULL") else "",
        # The settings the deployment locks against the admin panel.
        "settings_locked_keys": (current_env.get("SETTINGS_LOCKED_KEYS") or "").strip() or None,
        # And its limits on how long records are kept.
        **{cfg_key: (current_env.get(env_name) or "").strip() or None
           for cfg_key, env_name, _default in RETENTION_ENV_KEYS},
        # And the boundary of compliance access and legal holds.
        **{cfg_key: (current_env.get(env_name) or "").strip() or None
           for cfg_key, env_name, _default in COMPLIANCE_ENV_KEYS},
        # And how much container output Docker keeps.
        **{cfg_key: (current_env.get(env_name) or "").strip() or None
           for cfg_key, env_name, _default in CONTAINER_LOG_ENV_KEYS},
        "invite_token_pepper": (current_env.get("INVITE_TOKEN_PEPPER") or "").strip() or gen_hex(32),
        # A new set is new data: its audit fingerprints get a key of their own, and so does its audit chain.
        "audit_fingerprint_key": gen_hex(32),
        "audit_chain_key": gen_hex(32),
        # A fresh volume set is still the same deployment: keep whatever storage ceiling the
        # operator had configured rather than silently reverting it to unlimited.
        "max_storage_gb": parse_max_storage_gb(
            current_env.get("MAX_STORAGE_GB") or current_env.get("PLAN_MAX_STORAGE_GB")),
        # Likewise for the transfer ceiling: an operator who lowered it to fit the machine's
        # memory should not find it back at the default because they took a fresh volume set.
        "max_concurrent_transfers": parse_transfer_limit(
            current_env.get("MAX_CONCURRENT_TRANSFERS")),
        "max_queued_transfers": parse_transfer_queue(current_env.get("MAX_QUEUED_TRANSFERS")),
        "transfer_queue_wait_seconds": parse_transfer_wait(
            current_env.get("TRANSFER_QUEUE_WAIT_SECONDS")),
        # And the cap on one multipart upload request, for the same reason.
        "max_single_request_upload_mb": parse_single_request_upload_mb(
            current_env.get("MAX_SINGLE_REQUEST_UPLOAD_MB")),
        # Keep a postponed file-expiry enforcement across a fresh volume set, like the choices above
        # (raw, so an explicit "false" survives; the default is on).
        "enforce_file_expiry": (current_env.get("ENFORCE_FILE_EXPIRY") or "").strip() or None,
        # And a postponed key proof on zero-knowledge key changes, for the same reason.
        "zk_key_proof_enforce": (current_env.get("ZK_KEY_PROOF_ENFORCE") or "").strip() or None,
        # And a changed hold on the zero-knowledge key envelope after an administrator's change.
        "zk_envelope_hold_days": (current_env.get("ZK_ENVELOPE_HOLD_DAYS") or "").strip() or None,
    }
    return cfg


def plan_volume_action(choice):
    """Pure planner for the Volumes picker -> the required actions for a choice. Encodes the
    invariants the tests lock: 'new' MUST author a fresh paired .env; 'repoint' MUST supply a
    matching .env AND pass the secret guard; 'reuse' changes nothing. Unknown choice -> None."""
    plans = {
        "reuse":   {"action": "reuse", "author_env": False, "requires_env": False, "guard": False},
        "new":     {"action": "new", "archive_current": True, "author_env": True,
                    "fresh_secrets": True, "requires_env": False, "guard": False},
        "repoint": {"action": "repoint", "author_env": False, "requires_env": True, "guard": True},
    }
    return plans.get(choice)


# --- backup / restore (atomic {.env + volumes} bundle) ---------------------------------------
# A backup is ONE directory holding: `env` (the paired .env - it carries ENCRYPTION_KEY, so the whole
# bundle is sensitive), a tar.gz per data volume, and manifest.json. The manifest carries NO secret -
# only a salted one-way commitment over the .env's two random per-set secrets, so restore can confirm
# the .env in the bundle really is the one those volumes were created with (a swapped/wrong .env fails).
# The order archived in, and restored in; brand is optional. The keys volume comes first: it holds the audit
# chain's head record, and a database archived after it can only be ahead of its record (by the seals written
# meanwhile, which the server lists and the host acknowledges), never behind it, which would stop sealing as a
# cut tail does. The running deployment is paused while the volumes are archived, so every archive is of one moment.
BACKUP_ROLES = ("keys", "pg", "storage", "brand")
# The containers paused while a backup archives the volumes (each a compose service of the same name): the app's in
# either layout, which write the stored files, the keys and the database rows, and the database itself.
BACKUP_PAUSED_SERVICES = ("vault", "vault-api", "vault-sftp", "vault-db")
# The three that carry data. A bundle without them is not a backup, whatever else it contains,
# and saying so is load-bearing now that an upgrade takes one on the operator's behalf and
# proceeds with an irreversible change on the strength of it.
BACKUP_REQUIRED_ROLES = ("pg", "storage", "keys")
# The signals whose default action ends the process at once, without running a single `finally`: a closed SSH
# session or terminal (SIGHUP), kill, a timeout or a service stop (SIGTERM), and on Windows Ctrl-Break (SIGBREAK).
# While a backup holds the deployment paused, SignalsEndTheRun turns them into an exit that resumes it first. Ctrl-C
# is a KeyboardInterrupt already, which runs them. Each is used where this platform has it.
RUN_ENDING_SIGNALS = ("SIGHUP", "SIGTERM", "SIGBREAK")
# A resume of the deployment that Docker did not confirm is asked about and tried again: up to RESUME_RETRIES more
# rounds, RESUME_RETRY_GAP seconds apart, none begun once RESUME_RETRY_SECONDS have passed since the first try (a
# Docker that does not answer is not waited for again and again). The first try's docker child can be ended by the
# signal that ends the run: one started in the very moment the signal reaches the run's process group is still in
# that group, and systemd's stop signals every process of the service, whatever its group.
RESUME_RETRIES = 3
RESUME_RETRY_GAP = 0.5
RESUME_RETRY_SECONDS = 30


def own_session_kwargs():
    """The subprocess keyword arguments that start a docker child out of reach of the signals that end this run. A
    terminal's hangup (twice: the shell passes its SIGHUP on to its jobs, then the terminal sends its own), systemd's
    stop and GNU timeout signal the run's whole process group, and a `docker compose pause` they end can have taken
    effect with no answer, an `unpause` they end leaves the deployment paused. On POSIX a session of its own; on
    Windows a process group of its own (Ctrl-Break sent to the run's group) with no console (Ctrl-Break typed at the
    console reaches every process attached to it, whatever its group)."""
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)}
    return {"start_new_session": True}


class StoppedBySignal(SystemExit):
    """The run was ended by one of RUN_ENDING_SIGNALS while SignalsEndTheRun was in force. A SystemExit, so that the
    `finally` blocks on the way out run; its exit status is 128 + the signal's number, as a shell reports a process
    a signal ended."""

    def __init__(self, signum):
        super().__init__(128 + int(signum))
        self.signum = int(signum)

    def signal_name(self):
        try:
            return signal.Signals(self.signum).name
        except ValueError:
            return "signal %d" % self.signum


class SignalsEndTheRun(object):
    """A `with` block in which RUN_ENDING_SIGNALS raise StoppedBySignal (in the main thread) instead of ending the
    process at once, so that the block's `finally` runs first: a backup resumes the deployment it paused. Only a
    signal whose action is the default one is taken over: one that is ignored (a run under nohup goes on when its
    terminal closes) or already handled is left as it is. Each signal's previous action is put back when the block
    ends. Outside the main thread, where Python sets no handler, it changes nothing.

    hold() starts a stretch that a signal must not cut short (a pause, the resume): a signal that comes then is
    noted, release() raises it at the end of the stretch, and the end of the block raises one still noted (unless
    the block is already ending on an exception). Once one has been raised, every later one is only noted: a second
    signal does not cut short the `finally` the first one runs."""

    def __init__(self):
        self._previous = {}
        self._holding = False
        self._raised = False
        self._noted = None

    def _on_signal(self, signum, _frame):
        if self._holding or self._raised:
            if self._noted is None:
                self._noted = signum
            return
        self._raised = True
        raise StoppedBySignal(signum)

    def hold(self):
        self._holding = True

    def release(self):
        self._holding = False
        self._raise_noted()

    def _raise_noted(self):
        if self._noted is not None and not self._raised:
            signum, self._noted = self._noted, None
            self._raised = True
            raise StoppedBySignal(signum)

    def __enter__(self):
        for name in RUN_ENDING_SIGNALS:
            signum = getattr(signal, name, None)
            if signum is None:
                continue
            try:
                if signal.getsignal(signum) is not signal.SIG_DFL:
                    continue
                signal.signal(signum, self._on_signal)
            except (OSError, ValueError, RuntimeError):
                continue               # not the main thread, or a signal this platform gives no handler
            self._previous[signum] = signal.SIG_DFL
        return self

    def __exit__(self, exc_type, exc, tb):
        for signum, previous in self._previous.items():
            try:
                signal.signal(signum, previous)
            except (OSError, ValueError, RuntimeError):
                pass
        self._previous = {}
        if exc_type is None:
            self._raise_noted()
        return False


def gen_salt():
    """A random, NON-secret salt for a backup's coupling fingerprint."""
    return gen_hex(16)


def _timestamp():
    """A filesystem-safe local timestamp (YYYYmmdd-HHMMSS) for a backup bundle name."""
    import datetime
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def compute_coupling_fingerprint(env, salt):
    """A NON-secret, one-way commitment coupling a set's volumes to its .env: a salted SHA-256 over the
    two random per-set secrets. Reveals neither (both are cryptographically random, so the digest is not
    reversible), yet matches ONLY that exact .env. Stdlib hashlib."""
    material = "%s\x00%s\x00%s" % (salt, env.get("ENCRYPTION_KEY", ""), env.get("VAULT_DB_PASSWORD", ""))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# A NON-secret coupling stamp written into the postgres data volume the first time a .env is proven
# to open it. Lets a later run answer "does THIS .env match THIS volume?" in about a second, instead
# of booting postgres for a ~20-40s auth probe. Postgres ignores unrecognised files in its data
# directory (it only requires an EMPTY directory at initdb time, long before this is written).
COUPLING_MARKER = "dockvault_coupling.json"
# The stamp's version. A stamp is written once both halves of the pairing were checked: the database password opened
# the database, and ENCRYPTION_KEY opened the key check the vault keeps there. Earlier versions of this tool stamped
# after the password alone (version 1), so their stamp can vouch for a .env whose ENCRYPTION_KEY was never checked
# (one that shares the password): it is not taken, the live check runs and stamps this version.
COUPLING_STAMP_VERSION = 2


def read_volume_coupling(volume, run=subprocess.run):
    """Read the coupling marker out of `volume` via a throwaway busybox (read-only mount). Returns
    the parsed dict, or None when absent/unreadable/garbled - every one of which means 'unknown',
    never 'mismatch'. Checks existence FIRST: `docker run -v <name>:...` CREATES a missing volume,
    and this must never leave a stray empty one behind (the menu can ask about a set that has never
    been deployed)."""
    if not volume_exists(volume, run=run):
        return None
    try:
        r = run(["docker", "run", "--rm", "-v", "%s:/v:ro" % volume, "busybox",
                 "cat", "/v/%s" % COUPLING_MARKER], capture_output=True, text=True, timeout=120)
    except Exception:  # noqa: BLE001
        return None
    if getattr(r, "returncode", 1) != 0:
        return None
    try:
        marker = json.loads(getattr(r, "stdout", "") or "")
    except ValueError:
        return None
    return marker if isinstance(marker, dict) else None


def build_coupling_marker(env, salt=None):
    """The marker document, in the SAME shape verify_backup_coupling() reads (the digest nested
    under "coupling") so the writer and the reader can never drift apart. Salt + digest only."""
    salt = salt or gen_salt()
    return {"dockvault_coupling": COUPLING_STAMP_VERSION,
            "coupling": {"salt": salt, "sha256": compute_coupling_fingerprint(env, salt)}}


def write_volume_coupling(volume, env, salt=None, run=subprocess.run):
    """Stamp the coupling marker into `volume`. Best-effort: returns True on success, False on any
    failure (a set that can't be stamped simply keeps using the live probe). Writes the salt +
    digest ONLY - never a secret - and pipes it over stdin so nothing lands on the host argv.
    Refuses a volume that doesn't exist: `docker run -v <name>:...` would CREATE it."""
    if not volume_exists(volume, run=run):
        return False
    payload = json.dumps(build_coupling_marker(env, salt))
    try:
        r = run(["docker", "run", "--rm", "-i", "-v", "%s:/v" % volume, "busybox",
                 "sh", "-c", "cat > /v/%s" % COUPLING_MARKER],
                input=payload, capture_output=True, text=True, timeout=120)
    except Exception:  # noqa: BLE001
        return False
    return getattr(r, "returncode", 1) == 0


def coupling_marker_verdict(marker, env):
    """Pure: 'ok' when `marker` proves `env` is the .env this volume was stamped with, else None.
    NEVER returns a negative verdict - a stamp can go stale (the DB password was rotated in
    postgres and in .env), and only the live auth probe may refuse a start. Shares ONE digest
    comparison with the backup manifests (verify_backup_coupling). A stamp vouches for the exact
    .env it was written for, and only one written once both halves were checked
    (COUPLING_STAMP_VERSION) is taken; an older one (the password checked alone) is not."""
    version = marker.get("dockvault_coupling") if isinstance(marker, dict) else None
    if not (isinstance(version, int) and not isinstance(version, bool) and version >= COUPLING_STAMP_VERSION):
        return None
    return "ok" if verify_backup_coupling(env, marker) else None


# The manifest's format ("dockvault_backup"). 1: the backups made before archives had checksums (an entry records no
# sha256 or size). 2: every entry records its archive's sha256 and size, and a restore refuses a format-2 manifest
# that lacks one. Nothing in an unsealed bundle is authenticated, so whoever can write it can also write format 1
# with no checksums: a restore of a format-1 bundle says that nothing shows its archives are the backup's.
BACKUP_MANIFEST_FORMAT = 2


def manifest_format(manifest):
    """A manifest's format: 1 when it names none (every backup before formats were numbered wrote 1), the number when
    it is one this tool knows (1 .. BACKUP_MANIFEST_FORMAT), else None."""
    fmt = manifest.get("dockvault_backup", 1) if isinstance(manifest, dict) else None
    if isinstance(fmt, int) and not isinstance(fmt, bool) and 1 <= fmt <= BACKUP_MANIFEST_FORMAT:
        return fmt
    return None


def build_backup_manifest(prefix, bundle_id, volumes, salt, env, created=""):
    """The backup manifest dict (NO secrets): identifies the set + records the salted coupling
    fingerprint of the paired .env. `volumes` is a list of {role, name, archive, sha256, size}: the archive's
    SHA-256 and size as check_archive_file found them on the host (a backup made before them lacks both). Its
    format (BACKUP_MANIFEST_FORMAT) is the one that records them when every entry does, else 1."""
    entries = list(volumes)
    recorded = bool(entries) and all(isinstance(e, dict) and "sha256" in e and "size" in e for e in entries)
    return {
        "dockvault_backup": BACKUP_MANIFEST_FORMAT if recorded else 1,
        "created": created,
        "volume_prefix": prefix,
        "bundle_id": bundle_id or "default",
        "volumes": entries,
        "env_file": "env",
        "coupling": {"salt": salt, "sha256": compute_coupling_fingerprint(env, salt)},
        "note": "The 'env' file in this backup holds ENCRYPTION_KEY - protect the whole bundle off-host.",
    }


def verify_backup_coupling(env, manifest):
    """True iff `env` is the .env this manifest was built from (recompute the salted fingerprint and
    compare). A wrong/swapped .env -> False, so restore refuses a mismatched bundle. A malformed
    manifest (not a dict, or a non-dict/empty `coupling`) -> False, never a crash."""
    coupling = manifest.get("coupling") if isinstance(manifest, dict) else None
    if not isinstance(coupling, dict):
        return False
    salt, expected = coupling.get("salt"), coupling.get("sha256")
    if not (salt and expected):
        return False
    return compute_coupling_fingerprint(env, salt) == expected


# What a backup records of each archive, in its manifest entry: the SHA-256 of the archive file and its size in bytes,
# taken on the host once the archive has been read through whole (check_archive_file). A restore takes nothing from
# an archive whose bytes differ. A plain hash catches an archive damaged on the way; it does not stop someone who can
# write the bundle, who can write the manifest's hash as well. A sealed bundle's manifest is therefore authenticated
# too, under the key its env.enc is sealed with (BUNDLE_MANIFEST_MAC, manifest_mac): only that key's holder can make
# a manifest that passes.
ARCHIVE_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
BUNDLE_MANIFEST_MAC = "manifest.json.mac"
_MANIFEST_MAC_LABEL = b"dockvault backup manifest mac v1"


class _HashingReader:
    """A read-only file wrapper that feeds every byte read through it into `digest` and counts them."""

    def __init__(self, raw, digest):
        self._raw = raw
        self._digest = digest
        self.size = 0

    def read(self, n=-1):
        data = self._raw.read(n)
        self._digest.update(data)
        self.size += len(data)
        return data


def check_archive_file(path):
    """(SHA-256 hex, size) of the tar.gz at `path`, once it has been read through to its end in one pass: a gzip
    stream whose own checksum is right, holding a tar whose every entry lists (what `tar -tzf` checks). Raises
    ValueError saying what is wrong: missing, not a plain file, empty, or not readable as a whole tar.gz."""
    import gzip
    import tarfile
    import zlib
    if os.path.islink(path) or not os.path.isfile(path):
        raise ValueError("%s is not there (no plain file by that name)" % path)
    if os.path.getsize(path) == 0:
        raise ValueError("%s is empty" % path)
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as raw:
            reader = _HashingReader(raw, digest)
            with gzip.GzipFile(fileobj=reader, mode="rb") as gz:
                with tarfile.open(fileobj=gz, mode="r|") as tar:
                    for _member in tar:
                        pass
                while gz.read(1 << 20):          # the rest of the stream, through to its checksum
                    pass
            while reader.read(1 << 20):          # anything after it is hashed too
                pass
    except (OSError, EOFError, ValueError, tarfile.TarError, zlib.error) as exc:
        raise ValueError("%s does not read as a whole tar.gz archive (%s)" % (path, exc))
    return digest.hexdigest(), reader.size


def _copy_archive_in(archive_name, then):
    """A busybox shell script that copies /src/<archive_name> (the bundle's file, which can change while the restore
    runs) into the container's own file /tmp/dv-archive, prints the copy's SHA-256 as `dv-sha256 <hex>`, then runs
    `then`, which reads that copy only ($1 holds its SHA-256): what it reads is the very file hashed, whatever happens
    to the bundle meanwhile. It fails when the file is not there or is empty (exit 3), or when the copy cannot be
    made whole or hashed (exit 4: no room for it in Docker's storage, say). The restore's look at each archive before
    it stops anything (archive_digest_in_docker) and its extraction (untar_volume) both read this way: the look
    proves the extraction can (Docker sees the file, and has room for the copy)."""
    return ('f=/src/%s; [ -f "$f" ] && [ -s "$f" ] || { echo "no such archive, or an empty one" >&2; exit 3; }; '
            'cp "$f" /tmp/dv-archive || { echo "the archive could not be copied into the container (is there room '
            'for it in the Docker storage?)" >&2; exit 4; }; '
            's="$(sha256sum < /tmp/dv-archive)" || exit 4; set -- $s; echo "dv-sha256 $1"; %s'
            % (archive_name, then))


def _copied_sum(stdout):
    """The SHA-256 hex _copy_archive_in printed for its copy, or None."""
    for line in (stdout or "").splitlines():
        if line.startswith("dv-sha256 "):
            word = line[len("dv-sha256 "):].strip()
            return word if ARCHIVE_DIGEST_RE.match(word) else None
    return None


def archive_digest_in_docker(src_dir, archive_name, run=subprocess.run):
    """The SHA-256 hex of <src_dir>/<archive_name> as Docker sees it, through the same read-only bind mount the
    restore's untar_volume uses and read the same way (_copy_archive_in: copied into the container, then the copy
    hashed), once busybox tar has listed the copy to its end (gunzip checks the stream's own checksum on the way).
    Returns (digest or None, why not). A Docker that does not see the host's folder (another host's daemon, a
    confined one), or sees another file there, answers with no digest or another one; one with no room for the copy
    answers with none."""
    script = _copy_archive_in(archive_name, "tar tzf /tmp/dv-archive > /dev/null")
    try:
        r = run(["docker", "run", "--rm", "--network", "none", "-v", "%s:/src:ro" % src_dir, "busybox", "sh", "-c",
                 script], capture_output=True, text=True, timeout=3600)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return None, "Docker could not be run (%s)" % type(exc).__name__
    if getattr(r, "returncode", 1) != 0:
        why = " ".join((getattr(r, "stderr", "") or "").split())[-200:]
        return None, why or "exit %s" % getattr(r, "returncode", "?")
    seen = _copied_sum(getattr(r, "stdout", ""))
    if seen is None:
        return None, "no checksum came back"
    return seen, ""


def manifest_mac(dek, manifest_bytes):
    """HMAC-SHA256, hex, of a sealed bundle's manifest.json bytes, under a key derived from the data key its env.enc
    is sealed with (the recovery key). The passphrase or the recovery key opens env.enc and with it this key; nobody
    without either can make a manifest whose MAC is right."""
    import hmac
    raw = dek if isinstance(dek, (bytes, bytearray)) else str(dek).encode("ascii")
    key = hmac.new(bytes(raw), _MANIFEST_MAC_LABEL, hashlib.sha256).digest()
    return hmac.new(key, bytes(manifest_bytes), hashlib.sha256).hexdigest()


def manifest_mac_matches(dek, manifest_bytes, recorded):
    """True only when `recorded` is the MAC manifest_mac() gives for these bytes (compared in constant time)."""
    import hmac
    if not isinstance(recorded, str) or not ARCHIVE_DIGEST_RE.match(recorded):
        return False
    return hmac.compare_digest(manifest_mac(dek, manifest_bytes), recorded)


# What a sealed bundle's env.enc seals: its env, then one line saying that the bundle's manifest is authenticated
# (BUNDLE_MANIFEST_MAC), with an identifier of the data key it is sealed under. The line is sealed with the env, under
# that key, so nobody without the passphrase or the recovery key can take it out: a sealed bundle stripped of its MAC
# and of its checksums, to look like one made before them, is refused. Each seal has a data key of its own: such a
# line that reached a .env from elsewhere (an earlier version of the tool installs a payload as it is, line and all)
# names another key than the seal of the next backup of that .env, and does not make that backup, sealed by an
# earlier version with no MAC, look new.
_SEALED_LINE = b"\n# dockvault sealed backup %s: its manifest is authenticated (manifest.json.mac)\n"
_SEALED_LINE_RE = re.compile(rb"\n# dockvault sealed backup ([0-9a-f]{32}): its manifest is authenticated "
                             rb"\(manifest\.json\.mac\)\n\Z")
_SEALED_LINE_LABEL = b"dockvault sealed backup line v1"


def sealed_line_id(dek):
    """The identifier of the data key `dek` the line of a sealed bundle names (HMAC-SHA256 under the key, of a fixed
    label, cut to 32 hex): it says nothing of the key, and only the key's holder can make it."""
    import hmac
    raw = dek if isinstance(dek, (bytes, bytearray)) else str(dek).encode("ascii")
    return hmac.new(bytes(raw), _SEALED_LINE_LABEL, hashlib.sha256).hexdigest()[:32]


def sealed_bundle_payload(env_bytes, dek):
    """The bytes a sealed bundle's env.enc seals under the data key `dek`: the env, then the line that says its
    manifest is authenticated, naming that key (sealed_line_id)."""
    return bytes(env_bytes) + _SEALED_LINE % sealed_line_id(dek).encode("ascii")


def split_sealed_bundle_payload(payload, dek):
    """(the env bytes, True) for a payload sealed_bundle_payload made under the data key `dek` it was just opened
    with; else (the payload as it is, False): a bundle sealed before manifests were authenticated, whose payload is
    its env (a line there that names another key came from another seal)."""
    import hmac
    m = _SEALED_LINE_RE.search(bytes(payload))
    if m and dek is not None and hmac.compare_digest(m.group(1), sealed_line_id(dek).encode("ascii")):
        return bytes(payload)[:m.start()], True
    return bytes(payload), False


def tar_volume(volume, dest_dir, archive_name, run=subprocess.run):
    """Archive a docker volume to <dest_dir>/<archive_name> via a throwaway busybox container (read-only
    source mount). Returns True on success. Best-effort False on any docker error."""
    try:
        r = run(["docker", "run", "--rm", "-v", "%s:/src:ro" % volume, "-v", "%s:/dest" % dest_dir,
                 "busybox", "sh", "-c", "cd /src && tar czf /dest/%s ." % archive_name],
                capture_output=True, text=True, timeout=600)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return getattr(r, "returncode", 1) == 0


class ArchiveChanged(Exception):
    """untar_volume found its archive, as copied for the extraction, to be other bytes than the ones the restore
    checked, and extracted nothing of it. `seen` is the copy's SHA-256 hex."""

    def __init__(self, seen):
        Exception.__init__(self, seen)
        self.seen = seen


def untar_volume(volume, src_dir, archive_name, run=subprocess.run, sha256=None):
    """Restore <src_dir>/<archive_name> into a docker volume via a throwaway busybox container (the -v
    mount creates the volume if absent). Returns True on success.

    With `sha256` (the archive's SHA-256 hex as the restore checked it, before it stopped anything), the archive is
    copied into the extracting container first, the copy hashed, and the copy extracted only when it is those bytes
    (_copy_archive_in): the bundle can change between that check and this read (a bundle on a share or a removable
    disk, or one anyone else can write while the restore waits for its confirmation), and other bytes never reach
    tar, let alone the volume. They raise ArchiveChanged, with nothing extracted, and the caller stops there. A copy
    that could not be made or hashed extracts nothing either: False."""
    if sha256 is None:
        script = "cd /dest && tar xzf /src/%s" % archive_name
    elif not ARCHIVE_DIGEST_RE.match(str(sha256)):
        return False
    else:
        script = "cd /dest || exit 5; " + _copy_archive_in(
            archive_name, '[ "$1" = %s ] || { echo "not the archive checked" >&2; exit 6; }; tar xzf /tmp/dv-archive'
            % sha256)
    try:
        r = run(["docker", "run", "--rm", "-v", "%s:/dest" % volume, "-v", "%s:/src:ro" % src_dir,
                 "busybox", "sh", "-c", script],
                capture_output=True, text=True, timeout=3600)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    if sha256 is not None:
        seen = _copied_sum(getattr(r, "stdout", ""))
        if seen is None:
            return False                     # nothing was copied or hashed: nothing was extracted
        if seen != sha256:
            raise ArchiveChanged(seen)       # stopped before tar: nothing was extracted
    return getattr(r, "returncode", 1) == 0


def clear_volume(volume, run=subprocess.run):
    """Empty a docker volume's contents IN PLACE via a throwaway busybox (read-write mount), so a
    restore REPLACES rather than merges. Clears dotfiles + regular entries but keeps the volume
    OBJECT (and its DockVault labels) - unlike `docker volume rm`, which would drop the labels the
    volume manager groups sets by. The volume must not be in use (the caller stops the stack first);
    the -v mount creates it if absent (then the clear is a no-op on the empty dir). Returns True on
    success, False on a real failure - which the caller MUST honour rather than extracting on top (a
    partial clear + extract is the merge this exists to prevent). No trailing `; true`: the rm globs
    already exit 0 on an empty volume (rm -f ignores a non-matching literal), so keeping the real exit
    code lets a genuine failure (permission / read-only / I/O) surface as False."""
    try:
        r = run(["docker", "run", "--rm", "-v", "%s:/v" % volume, "busybox", "sh", "-c",
                 "rm -rf /v/..?* /v/.[!.]* /v/* 2>/dev/null"],
                capture_output=True, text=True, timeout=300)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return getattr(r, "returncode", 1) == 0


# The old AUDIT_CHAIN_KEY a key change keeps beside .env until the audit log's chain has moved to the new one. Each
# volume set has its own file, named with its VAULT_VOLUME_PREFIX (kept_chain_key_path): a change of set (Volumes'
# new set or repoint, a restore of another set's bundle) leaves every set's kept key under that set's name, never
# beside another set's .env as if it were that set's. Reset moves the file of the set it destroys aside
# (KEPT_CHAIN_KEY_REMOVED). A backup bundle, which is one set's own, carries it as KEPT_CHAIN_KEY_BUNDLE (sealed with
# env under --lock, as KEPT_CHAIN_KEY_BUNDLE + ".enc").
KEPT_CHAIN_KEY = ".audit-chain-key.previous"
KEPT_CHAIN_KEY_REMOVED = ".audit-chain-key.removed-"
KEPT_CHAIN_KEY_BUNDLE = "audit-chain-key.previous"
# Held by a key change, and by the key an update offers, from before either reads AUDIT_CHAIN_KEY in .env until it
# ends: another one started meanwhile is refused at once (an empty file, left in place).
CHAIN_KEY_LOCK = ".audit-chain-key.lock"
# Beside .env, one for each volume set (.restore-incomplete.<VAULT_VOLUME_PREFIX>): a restore of that set has begun to
# replace its volumes and has not finished. Written before the first volume is cleared and removed once the backup's
# .env is installed, so it stays after a restore that stopped part way, after Ctrl-C, after a crash. While it is
# there, nothing starts that set, whose volumes hold part of a backup: every command that would (restore_incomplete_
# refusers) refuses before it changes anything, and says the way back (run the restore again, or Reset); the stack's
# start and the database's own start for a check of .env refuse it too, whatever asked for them. Nor does backup take
# those volumes for a whole set. Reset of that set removes it. It holds no secret.
RESTORE_INCOMPLETE = ".restore-incomplete."


def restore_incomplete_refusers(what):
    """The commands that refuse set `what` (its name in quotes, or "it") while a restore of it that began to replace
    its volumes has not finished (RESTORE_INCOMPLETE), as the messages and the README say them."""
    return ("start, restart, setup, update, storage, logs and audit change-key refuse to start %s, and backup refuses "
            "to back it up" % what)


def restore_incomplete_path(root, prefix):
    """The restore-incomplete marker of set `prefix` in `root`. ValueError for a prefix that is not a volume set's
    name (it would not be a plain file name)."""
    if not (valid_volume_prefix(prefix) and prefix == prefix.strip()):
        raise ValueError("VAULT_VOLUME_PREFIX %r is not a volume set's name" % (prefix,))
    return os.path.join(root, RESTORE_INCOMPLETE + prefix)


def kept_chain_key_path(root, prefix):
    """The file in `root` that holds the old AUDIT_CHAIN_KEY of the volume set `prefix` while a change of its key is
    not finished. ValueError for a prefix that is not a volume set's name (it would not be a plain file name)."""
    if not (valid_volume_prefix(prefix) and prefix == prefix.strip()):
        raise ValueError("VAULT_VOLUME_PREFIX %r is not a volume set's name" % (prefix,))
    return os.path.join(root, "%s.%s" % (KEPT_CHAIN_KEY, prefix))


def kept_chain_key_files(root):
    """Every old AUDIT_CHAIN_KEY kept in plain text in `root`: each set's, and those Reset moved aside."""
    here = glob.escape(root)            # the folder's own name may hold [, ], * or ?
    return sorted(set(glob.glob(os.path.join(here, KEPT_CHAIN_KEY + "*")) +
                      glob.glob(os.path.join(here, KEPT_CHAIN_KEY_REMOVED + "*"))))


class LockBusy(Exception):
    """The lock asked for is held by another process."""


@contextlib.contextmanager
def held_lock(path):
    """An exclusive lock on the file `path` (created mode 600 when missing, and left in place) for a `with` block.
    Never waits: LockBusy when another process holds it. The system releases it when the process ends, however it
    ends."""
    flags = os.O_RDWR | os.O_CREAT
    fd = os.open(path, flags, 0o600) if os.name != "nt" else os.open(path, flags)
    try:
        if os.name == "nt":
            import msvcrt
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise LockBusy(str(exc))
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise LockBusy(str(exc))
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def kept_chain_key_text(text):
    """The key a kept file or a bundle carries (its text, the ends stripped), or None when `text` is not one: empty,
    more than one line, a control character in it, or longer than any key."""
    key = (text or "").strip()
    if not key or len(key) > 4096 or not all(c.isprintable() for c in key):
        return None
    return key


def chain_head_relpath(env):
    """Where the audit chain's head record lies inside the keys volume (AUDIT_CHAIN_HEAD_FILE under
    /app/keys), or None when .env puts it elsewhere (then a restore writes no mark: the operator's path)."""
    path = (env or {}).get("AUDIT_CHAIN_HEAD_FILE") or "/app/keys/audit-chain-head.json"
    path = path.strip().strip("'\"")
    prefix = "/app/keys/"
    if not path.startswith(prefix) or ".." in path.split("/"):
        return None
    rel = path[len(prefix):]
    return rel if rel and re.match(r"^[A-Za-z0-9._/-]+$", rel) else None


def read_volume_json(volume, rel, run=subprocess.run):
    """The JSON file `rel` inside a docker volume, through a throwaway busybox (read-only mount), or None."""
    try:
        r = run(["docker", "run", "--rm", "-v", "%s:/v:ro" % volume, "busybox", "cat", "/v/%s" % rel],
                capture_output=True, text=True, timeout=120)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if getattr(r, "returncode", 1) != 0:
        return None
    try:
        data = json.loads(getattr(r, "stdout", "") or "")
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def write_volume_file(volume, rel, text, run=subprocess.run):
    """Write `text` to `rel` inside a docker volume (mode 600, owned like the volume's top directory, so the
    app's user reads it), through a throwaway busybox fed on its standard input. True on success."""
    script = ('cat > "/v/$1.tmp" && chown "$(stat -c %u:%g /v)" "/v/$1.tmp" && chmod 600 "/v/$1.tmp" '
              '&& mv "/v/$1.tmp" "/v/$1" && sync')
    try:
        r = run(["docker", "run", "--rm", "-i", "-v", "%s:/v" % volume, "busybox", "sh", "-c", script, "sh", rel],
                input=text, capture_output=True, text=True, timeout=120)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return getattr(r, "returncode", 1) == 0


# --- backup directory resolution -------------------------------------------------------------
# Backups used to land in <repo>/backups (the script's own directory), so a clone under Downloads put
# every secret-bearing bundle under Downloads. They now default to a per-OS application-data directory
# and the location is overridable + can name SEVERAL directories.
def _writable_dir(path):
    """True if `path` exists-or-can-be-created AND a probe file can be written there (then removing the probe).
    Picking the first WRITABLE candidate stops a full / read-only / disconnected-network location from silently
    swallowing a backup. A folder this call makes is made 0700 on POSIX; a folder that was already there keeps its
    mode (it is the operator's, often shared, as with a --backup-dir under sudo): each backup inside is made 0700
    itself."""
    try:
        made = False
        if not os.path.isdir(path):
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            try:
                os.mkdir(path, 0o700)
                made = True
            except FileExistsError:
                pass                           # made meanwhile by someone else: theirs, left as it is
        if made and os.name != "nt":
            try:
                os.chmod(path, 0o700)          # mkdir's mode is masked by the umask
            except OSError:
                pass
        probe = os.path.join(path, ".dockvault_write_probe")
        try:
            with open(probe, "w", encoding="utf-8") as f:
                f.write("")
        finally:
            try:
                os.remove(probe)        # always clean up, even if the write raised mid-way
            except OSError:
                pass
        return True
    except OSError:
        return False


def _app_data_backup_root():
    """The per-OS application-data backup directory (a PATH only - not created, not probed). Windows:
    %LOCALAPPDATA% (non-roaming, because bundles are large and hold ENCRYPTION_KEY so they must not
    sync) then %APPDATA%. macOS: ~/Library/Application Support. Linux/other: $XDG_DATA_HOME then
    ~/.local/share. All under DockVault/backups."""
    home = os.path.expanduser("~")
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or home
    elif sys.platform == "darwin":
        base = os.path.join(home, "Library", "Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share")
    return os.path.join(base, "DockVault", "backups")


def parse_backup_dirs(raw):
    """Split a backup-location value into an ordered list of paths. Accepts a single path OR several
    separated by os.pathsep (';' Windows, ':' POSIX) or newlines, so DOCKVAULT_BACKUP_DIR / --backup-dir
    can name MULTIPLE locations. Expands ~; drops blanks. Returns [] for empty/None."""
    if not raw:
        return []
    out = []
    for chunk in str(raw).replace("\n", os.pathsep).split(os.pathsep):
        chunk = chunk.strip()
        if chunk:
            out.append(os.path.expanduser(chunk))
    return out


def _default_backup_candidates():
    """The ordered default write-target candidates when no --backup-dir is given: DOCKVAULT_BACKUP_DIR
    (which may list several), then the per-OS app-data dir, then ~/DockVault/backups, then
    ~/Downloads/DockVault/backups. PURE - computes paths only, never probes or creates (so a
    read-only listing can display them without side effects)."""
    home = os.path.expanduser("~")
    return parse_backup_dirs(os.environ.get("DOCKVAULT_BACKUP_DIR")) + [
        _app_data_backup_root(),
        os.path.join(home, "DockVault", "backups"),
        os.path.join(home, "Downloads", "DockVault", "backups"),
    ]


def default_backup_dir():
    """The directory NEW bundles are written to when no --backup-dir is given: the first WRITABLE
    default candidate (created as a side effect), else the app-data path (a later mkdir then surfaces
    the error) so a backup never silently vanishes into an unwritable location."""
    for cand in _default_backup_candidates():
        if _writable_dir(cand):
            return cand
    return _app_data_backup_root()


# --- update (release list + upgrade/downgrade) -----------------------------------------------
RELEASES_URL = "https://api.github.com/repos/DockVault/vault/releases"
GHCR_IMAGE = "ghcr.io/dockvault/vault"
# The tag a local `docker compose --build` produces, and the compose files' own fallback for an
# unset DOCKVAULT_IMAGE. Naming it here lets the from-source paths point .env back at a local build
# after a release image has been pulled over it.
LOCAL_IMAGE = "dockvault-vault:latest"
# The setting that lets an image start on data a newer release changed in a way it cannot read (see
# app/core/data_requirements.py). An operator sets it by hand, for as long as they need it; setup
# never writes it, so no .env this tool authors carries it.
NEWER_DATA_ESCAPE = "ALLOW_START_ON_NEWER_DATA"
# The first release whose image checks for such data and refuses to start on it. An image older
# than this has no check at all: it starts on data a newer release changed, whatever that data is,
# and may delete or change what the newer release keeps.
FIRST_NEWER_DATA_CHECK = "0.33.1"


def newer_data_escape_set(env):
    return str((env or {}).get(NEWER_DATA_ESCAPE) or "").strip().lower() in ("1", "true", "yes", "on")


def checks_newer_data(version):
    """True when `version`'s image refuses to start on data a newer release changed in a way it cannot
    read. False for a release before FIRST_NEWER_DATA_CHECK, and for a version that cannot be read:
    neither can be relied on to refuse."""
    parsed = parse_semver(version)
    return bool(parsed) and parsed >= parse_semver(FIRST_NEWER_DATA_CHECK)


# What `python -m app.core.host_operator ...` prints in an image that has no host operator module
# (every release before 0.33.0), as its own line.
_NO_HOST_OPERATOR = re.compile(r"No module named '?app\.core\.host_operator'?\s*$", re.MULTILINE)


def parse_downgrade_blockers(answer):
    """The blockers in a `downgrade-blockers` answer, or None when the answer does not say.

    Each is a dict with at least a `reason`; `requires_at_least` and `undo` are shown when present.
    An answer that is not ok, or whose list is missing or malformed, says nothing -- which is not
    the same as saying there is nothing in the way."""
    if not isinstance(answer, dict) or answer.get("ok") is not True:
        return None
    blockers = answer.get("blockers")
    if not isinstance(blockers, list) or not all(isinstance(b, dict) for b in blockers):
        return None
    return blockers


def release_image_ref(version):
    """The published GHCR reference for a version. '0.9.0' and 'v0.9.0' both -> '<repo>:v0.9.0'.
    Returns '' for a missing/unknown version, which callers read as "no release to pull"."""
    tag = (version or "").strip()
    if not tag or tag == "unknown":
        return ""
    return "%s:%s" % (GHCR_IMAGE, tag if tag.startswith("v") else "v" + tag)


def uses_release_image(env):
    """True when .env pins this deployment to a PUBLISHED image instead of a local build.

    Anything under the GHCR repository got there by being pulled; the local build always wears
    LOCAL_IMAGE. The distinction is load-bearing rather than cosmetic: `compose up --build` tags
    its output with whatever DOCKVAULT_IMAGE says, so building over a pulled release silently
    replaces the scanned, attested, published image with a local build wearing its version tag —
    and the deployment then reports a version it is not running."""
    image = (env.get("DOCKVAULT_IMAGE") or "").strip()
    return image.startswith(GHCR_IMAGE + ":") or image.startswith(GHCR_IMAGE + "@")


def release_image_version(image):
    """The version a published release image reference names ('ghcr.io/dockvault/vault:v0.34.0' -> '0.34.0'), or
    None for anything else (a local build, a digest-pinned reference, another repository)."""
    m = re.match(r"^%s:v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)$" % re.escape(GHCR_IMAGE), (image or "").strip())
    return m.group(1) if m else None


def image_present(image, run=None):
    """True when `image` is already in this host's Docker image store (`docker image inspect` finds it), so the
    stack can be recreated from it without the registry. False when it is not, and when Docker cannot be asked."""
    if not image:
        return False
    try:
        r = (run or subprocess.run)(["docker", "image", "inspect", "--format", "{{.Id}}", image],
                capture_output=True, text=True, timeout=30)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return getattr(r, "returncode", 1) == 0


def describe_image_mode(env):
    """One-line, operator-facing description of which image THIS .env runs: a pinned published
    release, or a local build of the checkout. Used so a setup re-run is never silent about the
    mode it is about to (re)start in."""
    if uses_release_image(env):
        return "published release %s" % (env.get("DOCKVAULT_IMAGE") or "").strip()
    img = (env.get("DOCKVAULT_IMAGE") or "").strip()
    return "local build of this checkout (%s)" % (img or LOCAL_IMAGE)


def rerun_image_target(existing_env, choice, version):
    """For a setup RE-RUN over an existing .env, decide what DOCKVAULT_IMAGE should become given the
    operator's image-source `choice`. Pure (no I/O) so it is unit-testable. Returns (action, value):

      * ('keep', None)       -> leave .env unchanged (already in the requested mode, or no choice)
      * ('set', <image>)     -> repoint DOCKVAULT_IMAGE to <image>

    'build' points .env at LOCAL_IMAGE so `compose up --build` runs the code you have checked out
    right now (the fix for "I git-pulled but setup keeps pulling the old release"). 'release' points
    it at this checkout's published GHCR ref; with no usable VERSION it degrades to 'keep' so a
    re-run never writes a broken pin. An empty/None choice keeps whatever the .env already says —
    a plain restart must not silently switch modes."""
    c = (choice or "").strip().lower()
    if c == "build":
        # Already building (unset, LOCAL_IMAGE, or any non-GHCR value) -> nothing to change.
        return ("keep", None) if not uses_release_image(existing_env) else ("set", LOCAL_IMAGE)
    if c == "release":
        ref = release_image_ref(version)
        if not ref:
            return ("keep", None)
        cur = (existing_env.get("DOCKVAULT_IMAGE") or "").strip()
        return ("keep", None) if cur == ref else ("set", ref)
    return ("keep", None)


def parse_semver(v):
    """('v1.2.3-rc1' | '1.2.3') -> (1,2,3); pre-release/build suffix ignored; None if unparseable.
    Mirrors the app's update-check parser so the tool ranks versions the same way."""
    if not v:
        return None
    m = re.match(r"[vV]?(\d+)\.(\d+)\.(\d+)", str(v).strip())
    return tuple(int(x) for x in m.groups()) if m else None


def compare_semver(a, b):
    """-1/0/1 comparing two version strings by (major, minor, patch); an unparseable side sorts LOW."""
    pa, pb = parse_semver(a) or (-1, -1, -1), parse_semver(b) or (-1, -1, -1)
    return (pa > pb) - (pa < pb)


def is_downgrade(current, target):
    """True only if BOTH parse and `target` is strictly OLDER than `current`."""
    return bool(parse_semver(current) and parse_semver(target) and compare_semver(target, current) < 0)


def sort_release_tags(tags):
    """Release tags highest version first; a tag that does not parse is dropped.

    The releases list is ordered by when each release was made, so a patch release of an older line
    made after a newer line's release comes first in it, and its first tag is then not the newest
    release. Everything that takes the newest release from the list sorts it first."""
    return sorted((t for t in tags or [] if parse_semver(t)), key=parse_semver, reverse=True)


def parse_releases(data):
    """Release tags from the GitHub releases LIST JSON (a list of {tag_name,...}), highest version
    first (sort_release_tags), keeping only version-shaped tags, de-duplicated. Pure; [] on
    non-list."""
    if not isinstance(data, list):
        return []
    tags = []
    for rel in data:
        if not isinstance(rel, dict):
            continue
        tag = (rel.get("tag_name") or "").strip()
        if tag and parse_semver(tag) and tag not in tags:
            tags.append(tag)
    return sort_release_tags(tags)


def release_line(version):
    """The release line of a version: '0.33' for '0.33.2' or 'v0.33.2'; None if it does not parse."""
    parsed = parse_semver(version)
    return "%d.%d" % parsed[:2] if parsed else None


def newest_on_line(tags, version):
    """The highest tag among `tags` on the same release line as `version`, or None.

    Taken from the releases list rather than from any matrix, so only a release that exists is ever
    named."""
    line = release_line(version)
    same = [t for t in sort_release_tags(tags) if line and release_line(t) == line]
    return same[0] if same else None


def _default_release_fetch(url):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "dockvault-tool",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=10) as r:  # noqa: S310 (fixed https URL)
        return json.loads(r.read(1000000).decode("utf-8"))


def fetch_release_tags(url=RELEASES_URL, fetch=None):
    """Best-effort list of release tags newest-first. FAIL-CLOSED to [] on ANY network/parse error so
    an air-gapped host just falls back to a manual tag entry. `fetch` is injectable for tests."""
    try:
        return parse_releases((fetch or _default_release_fetch)(url))
    except Exception:  # noqa: BLE001 - fail-closed-silent
        return []


# Where a released version's upgrade description lives when this checkout does not have it.
# Raw content rather than the release asset API: no token, no rate-limited JSON hop, and the file
# is the same bytes the release published.
MATRIX_RAW_URL = ("https://raw.githubusercontent.com/DockVault/vault/%s/docs/upgrade-matrix.json")
MATRIX_LOCAL = os.path.join("docs", "upgrade-matrix.json")


def _semver_key(version):
    return tuple(int(part) for part in version.split("."))


def _walk_edges(matrix, current, target):
    """The declared edges leading from `current` to `target`, or None if there is no route.

    A breadth-first search over what the file actually declares, rather than a march through
    version-order neighbours. The difference only shows up once a backport exists, and then it
    matters: releasing 0.9.1 after 0.10.0 has shipped puts it BETWEEN them by version, so a
    neighbour march looks for 0.9.1 -> 0.10.0, finds nothing, and calls a hop undescribable that
    the file describes perfectly well with 0.9.0 -> 0.10.0. The validator already exempts that
    pair from needing an edge, so the two halves disagreed about what "adjacent" meant.

    Shortest route, and ties broken by version order, so the answer is the same on every run and
    on both implementations.
    """
    edges = {}
    for edge in (matrix.get("edges") or []):
        if isinstance(edge, dict) and edge.get("from") and edge.get("to"):
            edges.setdefault(edge["from"], []).append(edge)
    for outgoing in edges.values():
        outgoing.sort(key=lambda e: _semver_key(e["to"]))

    queue = [(current, [])]
    seen = {current}
    while queue:
        node, path = queue.pop(0)
        if node == target:
            return path
        for edge in edges.get(node, []):
            nxt = edge["to"]
            if nxt in seen:
                continue
            seen.add(nxt)
            queue.append((nxt, path + [edge]))
    return None


def _split_into_legs(matrix, steps):
    """Group the route's edges into the legs the upgrade must actually be performed in.

    A version marked `must_land_here` cannot be passed through in one recreate: the deployment has
    to come up ON it, finish its boot, and be verified before continuing. That happens where a
    migration needs the previous release's data already rewritten, or where a change is staged
    across two releases and the second assumes the first has run.

    The operator still runs ONE upgrade. The legs are what the tool does underneath, and what the
    database goes through -- not extra work for the person. A route with no such version is one leg,
    which is the ordinary case and stays a single recreate.
    """
    versions = matrix.get("versions") or {}
    legs, current = [], []
    for edge in steps:
        current.append(edge)
        if versions.get(edge.get("to"), {}).get("must_land_here"):
            legs.append(current)
            current = []
    if current:
        legs.append(current)
    return legs


def _leg_summary(leg):
    return {
        "to": leg[-1]["to"],
        "steps": leg,
        "requires_backup": any(e.get("requires_backup") for e in leg),
        "irreversible": any(not e.get("reversible", True) for e in leg),
        "conditions": [c for e in leg for c in (e.get("conditions") or [])],
    }


def plan_upgrade_path(matrix, current, target):
    """What it takes to get from `current` to `target`, walking one adjacent edge at a time.

    Returns a dict: `steps` (the edges traversed, in order), `requires_backup`, `irreversible`,
    `blocked` (the first blocked edge, or None), `conditions`, and `known` (False when the matrix
    cannot describe the hop at all).

    Composed from adjacent edges rather than looked up as a single hop, because that is how the
    matrix is authored: an edge is only declared between neighbouring releases, so a longer upgrade
    is a walk. A pair nobody tested therefore has no edge to find, which is the point -- it comes
    back unknown instead of coming back safe.
    """
    unknown = {"steps": [], "legs": [], "requires_backup": True, "irreversible": True,
               "blocked": None, "conditions": [], "known": False}
    if not isinstance(matrix, dict):
        return unknown
    versions = matrix.get("versions") or {}
    current = (current or "").lstrip("vV")
    target = (target or "").lstrip("vV")
    if current not in versions or target not in versions:
        return unknown
    try:
        ordered = sorted(versions, key=_semver_key)
    except (TypeError, ValueError):
        return unknown
    if _semver_key(target) < _semver_key(current):
        # A downgrade. The matrix describes forward edges only, and reversing one is not the same
        # claim, so this is deliberately not classified from it here -- a downgrade is described by
        # `plan_downgrade_path`, and refused by `downgrade_refusal`, from each edge's `reversible`.
        return unknown

    steps = _walk_edges(matrix, current, target)
    if steps is None:
        return unknown

    return {
        "steps": steps,
        # What the tool performs, in order. One leg unless the route crosses a version the
        # deployment has to land on; the operator runs one upgrade either way.
        "legs": [_leg_summary(leg) for leg in _split_into_legs(matrix, steps)],
        "requires_backup": any(e.get("requires_backup") for e in steps),
        "irreversible": any(not e.get("reversible", True) for e in steps),
        "blocked": next((e for e in steps if e.get("kind") == "blocked"), None),
        "conditions": [c for e in steps for c in (e.get("conditions") or [])],
        "known": True,
    }


def plan_downgrade_path(matrix, current, target):
    """What a downgrade from `current` to `target` involves, as the matrix describes it, in the shape
    plan_upgrade_path returns.

    The matrix declares each upgrade between adjacent releases, and on each one whether it can be taken
    back (`reversible`). So a downgrade is described by the upgrade route from `target` up to `current`:
    reversible when every edge on it is, never across a blocked one (an upgrade that must not be taken has
    no reverse). It is one recreate, so it has no legs, and the conditions on the way up are the upgrade's,
    not carried. Whether it needs a backup is the downgrade's own rule (backup_reason): the backup flags on
    the way up are about the upgrade. Unknown, as before, when that route is not in the matrix, or when this
    is not a downgrade."""
    unknown = {"steps": [], "legs": [], "requires_backup": True, "irreversible": True,
               "blocked": None, "conditions": [], "known": False}
    if not isinstance(matrix, dict):
        return unknown
    versions = matrix.get("versions") or {}
    cur = (current or "").lstrip("vV")
    tgt = (target or "").lstrip("vV")
    try:
        if cur not in versions or tgt not in versions or _semver_key(tgt) >= _semver_key(cur):
            return unknown
    except (TypeError, ValueError):
        return unknown
    route = _walk_edges(matrix, tgt, cur)
    if not route:
        return unknown
    return {
        "steps": route,
        "legs": [],
        "requires_backup": False,
        "irreversible": any(not e.get("reversible", True) or e.get("kind") == "blocked" for e in route),
        "blocked": None,
        "conditions": [],
        "known": True,
        "downgrade": True,
    }


def env_upgrade_notes(env, current, target):
    """What an upgrade from ``current`` to ``target`` changes for this deployment because of a line in
    its .env, as sentences to show before the image changes. Pure: ``env`` is the parsed .env. update()
    prints them, so only a checkout whose tool has them (0.33.1 or later) shows them: both the pull and
    the source path run the tool already installed, and the source path checks out the target itself."""
    notes = []
    cur, tgt = parse_semver(current), parse_semver(target)

    def crosses(version):
        # Taken as crossing when the running version is not known.
        return tgt is not None and tgt >= version and (cur is None or cur < version)

    if crosses((0, 33, 1)):
        raw = (env.get("ACCOUNT_LOCKOUT_MINUTES") or "").strip()
        try:
            minutes = int(raw) if raw else None
        except ValueError:
            minutes = None
        if minutes == 0:
            notes.append(
                "ACCOUNT_LOCKOUT_MINUTES=0 in .env: from 0.33.1 an administrator's automatic lock (after "
                "failed sign-ins) has an end instead of lasting until another administrator clears it: a "
                "lock on sign-ins from one address ends after 15 minutes, a pause on sign-ins from every "
                "address once its count has also lost a failure (72 minutes with the default settings). "
                "Other accounts' automatic locks still last until cleared, and so does a lock with no end "
                "that a release before 0.33.0 armed, which is recorded like one an administrator set. "
                "From the host, python dockvault.py accounts --action unlock clears any account's locks.")
    return notes


# Where Docker puts compose networks by default (its default address pools), for when the deployment's
# own network cannot be inspected.
DOCKER_DEFAULT_POOLS = ("172.16.0.0/12", "192.168.0.0/16")


def gateway_trust_note(trusted, gateways, current, target):
    """The sentence to show before an upgrade from ``current`` to ``target`` when TRUSTED_PROXIES
    (``trusted``, the raw .env value) holds a range that covers the Docker network's gateway: from
    0.33.1 a range no longer trusts it. ``gateways`` are the gateway addresses of the deployment's
    network (read with docker network inspect); when none could be read, a range that overlaps Docker's
    default pools counts. None when nothing changes. Pure."""
    import ipaddress
    cur, tgt = parse_semver(current), parse_semver(target)
    if tgt is None or tgt < (0, 33, 1) or (cur is not None and cur >= (0, 33, 1)):
        return None
    ranges, exact, named = [], [], False
    for spec in (s.strip() for s in (trusted or "").split(",")):
        if not spec:
            continue
        if spec.lower() == "gateway":
            named = True
            continue
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            continue
        (exact if net.num_addresses == 1 else ranges).append(net)
    if named or not ranges:
        return None
    covered = []
    for gw in gateways or ():
        try:
            addr = ipaddress.ip_address(gw)
        except ValueError:
            continue
        if not any(addr in n for n in exact) and any(addr in n for n in ranges):
            covered.append(str(addr))
    if gateways:
        if not covered:
            return None
        where = "the gateway of the vault's Docker network (%s)" % ", ".join(covered)
    else:
        pools = [ipaddress.ip_network(p) for p in DOCKER_DEFAULT_POOLS]
        if not any(r.overlaps(p) for r in ranges for p in pools if r.version == p.version):
            return None
        where = "the part of Docker's address space where the vault's network gateway usually is"
    return ("TRUSTED_PROXIES=%s in .env covers %s. From 0.33.1 a range no longer trusts the gateway: every "
            "connection Docker relays to the published web port arrives from it (IPv6 clients, clients on this "
            "host, on Docker Desktop every client), so those clients could set their own address. After the "
            "upgrade they are recorded as the gateway and their X-Forwarded-For is ignored. A reverse proxy on "
            "this host arrives from the gateway too: for one, set TRUSTED_PROXIES=gateway and WEB_BIND=127.0.0.1 "
            "in .env (WEB_BIND needs the compose files of 0.33.1 or later; an install that updates by pulling "
            "images keeps its own, so publish the web port as 127.0.0.1:<port>:8000 there by hand). A proxy "
            "container on the vault's network is unaffected: list its address."
            % ((trusted or "").strip(), where))


def backup_reason(plan, down=False):
    """Why a version change needs a backup first, or None when it does not.

    ONE rule, read by both the summary the operator sees and the gate that enforces it, so the tool
    can never print "backup: not required" and then demand one. A change needs a backup when the
    matrix does not describe it, when the matrix says so, when it cannot be rolled back, or when it
    is a downgrade, since there are no down-migrations. (A downgrade arrives here described by the
    upgrade it takes back, plan_downgrade_path, or undescribed when the matrix has no such route; it
    needs a backup either way.)
    """
    if not plan.get("known", True):
        return "the matrix does not describe this change"
    if plan.get("requires_backup"):
        return "the matrix marks this change as needing one"
    if plan.get("irreversible"):
        return "this change cannot be rolled back"
    if down:
        return "this is a downgrade, and there are no down-migrations"
    return None


def downgrade_refusal(matrix, current, target):
    """Whether a DOWNGRADE from `current` to `target` must be refused, and why.

    The matrix declares forward edges; reversing one is only a safe claim where that edge is
    reversible, and impossible across a blocked one. So the reverse verdict is read off the FORWARD
    path from `target` up to `current`: a downgrade across any irreversible or blocked edge is
    refused. Returns (refused: bool, reason: str|None). A downgrade the matrix cannot describe at all
    is NOT force-refused here -- it flows through the existing 'undescribed, needs a backup' path so
    behaviour outside the declared range is unchanged.
    """
    if not isinstance(matrix, dict):
        return False, None
    versions = matrix.get("versions") or {}
    cur = (current or "").lstrip("vV")
    tgt = (target or "").lstrip("vV")
    if cur not in versions or tgt not in versions or _semver_key(tgt) >= _semver_key(cur):
        return False, None
    forward = _walk_edges(matrix, tgt, cur)
    if not forward:
        return False, None
    blocked = next((e for e in forward if e.get("kind") == "blocked"), None)
    if blocked is not None:
        return True, blocked.get("reason") or "the forward upgrade is blocked, so it has no reverse"
    if any(not e.get("reversible", True) for e in forward):
        return True, ("the upgrade into the running version is marked irreversible, so an older "
                      "image cannot read the data written since")
    return False, None


def version_support(matrix, version):
    """The `support` lifecycle block for `version`, or {} when it is not stated.

    Returns {} for a matrix that predates the lifecycle schema (an older published upgrade.json) or
    that does not declare the version, so an old file keeps working: an absent block means 'lifecycle
    not stated' -- neither end-of-life nor known-insecure -- rather than an error."""
    if not isinstance(matrix, dict):
        return {}
    version = (version or "").lstrip("vV")
    meta = (matrix.get("versions") or {}).get(version) or {}
    support = meta.get("support")
    return support if isinstance(support, dict) else {}


def is_eol(matrix, version):
    """True only when the matrix explicitly marks `version` end-of-life."""
    return version_support(matrix, version).get("eol") is True


def preferred_lifecycle_matrix(local_matrix, fetched_matrix, version):
    """Which matrix to read a version's LIFECYCLE (eol / secure) from.

    Lifecycle is a GLOBAL, time-varying property -- a version is marked end-of-life LATER than it
    shipped -- so the authoritative source is this checkout's newest matrix, not the target's own
    published one (which is frozen at its cut time and forever self-declares eol:false). Fall back to
    the target's matrix only when the local one does not describe the version at all, e.g. the target
    is newer than this checkout. This is the INVERSE of hop DESCRIPTION, where the target's own file
    is preferred because only it can describe a hop reaching a newer release."""
    return local_matrix if version_support(local_matrix, version) else fetched_matrix


# A terminal escape sequence, matched as a WHOLE so its payload is removed with it, not left behind
# as visible litter. This is the ECMA-48 escape grammar, and ORDER matters. Each control has a 7-bit
# form (ESC + a byte) and an 8-bit C1 form (a single 0x80-0x9F byte); both are accepted, since a
# fetched asset could carry either. The STRING-TYPE sequences carry an arbitrary payload between an
# introducer and a terminator, and are listed FIRST so the whole run is consumed:
#   * OSC (ESC ] or U+009D) -- window title, hyperlink -- ends at BEL, ST (ESC \ or U+009C);
#   * DCS/APC/PM/SOS (ESC P/_/^/X or U+0090/9F/9E/98) end at ST (BEL is NOT a terminator for these).
# Their body is DOTALL non-greedy with the terminator OPTIONAL (`...|$`): an unterminated string type
# is swallowed to end of string, exactly as a real terminal keeps consuming it, so no payload leaks.
# Then CSI (ESC [ or U+009B, params intermediates final -- a colour code, a screen-clear). LAST, the
# generic 7-bit escape: ESC, zero or more intermediates (0x20-0x2F), one final byte (0x30-0x7E),
# covering the nF (charset ESC ( B), Fp (keypad ESC =), Fe and Fs (RIS ESC c) forms. It sits last on
# purpose: a full CSI is consumed by the CSI rule first, and an unterminated 7-bit CSI degrades here
# to just "ESC [" with its parameters left as harmless text. The isprintable second pass then drops
# any control or C1 byte that no rule consumed, so no such byte ever reaches the terminal.
_TERMINAL_ESCAPE_RE = re.compile(
    r"(?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|\x9c|$)"          # OSC: ESC ] / U+009D ... BEL | ST | end
    r"|(?:\x1b[P_^X]|[\x90\x9e\x9f\x98]).*?(?:\x1b\\|\x9c|$)"  # DCS/APC/PM/SOS ... ST | end
    r"|(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"                 # CSI: ESC [ / U+009B params intermediates final
    r"|\x1b[ -/]*[0-~]",                                 # nF / Fp / Fe / Fs: ESC intermediates* final
    re.DOTALL,
)


def clean_matrix_text(value):
    """Strip terminal escape sequences and other non-printable characters from a matrix string.

    The upgrade matrix is fetched over HTTPS as a published release asset and its strings are printed
    RAW on the operator's terminal (version notes, vulnerability titles and descriptions, hop
    conditions, backup and block reasons). A tampered or compromised asset could carry ANSI escape
    sequences -- a colour code, a cursor move, a screen-clear, a window-title set, a hyperlink -- that
    would act on that terminal. The committed file is validated against these at commit time; a
    fetched one is trusted only this far. Two passes: first whole escape sequences are removed by the
    ECMA-48 grammar (the string types OSC/DCS/APC/PM/SOS with their payloads, CSI, and the generic
    nF/Fp/Fe/Fs escapes), in both their 7-bit ESC forms and their 8-bit C1 forms, and an unterminated
    string type is swallowed to end of string -- so nothing between an introducer and its terminator
    is left as visible text. Then anything `str.isprintable()` rejects (the C0/C1 controls, a lone or
    malformed ESC, line/paragraph separators) is dropped -- the second pass is the guarantee that no
    control byte ever reaches the terminal even if a sequence is malformed. Printable Unicode is kept,
    as is a plain space. The visible text between sequences is preserved -- e.g. an OSC-8 hyperlink's
    label survives while its URL does not."""
    if not isinstance(value, str):
        return ""
    text = _TERMINAL_ESCAPE_RE.sub("", value)
    return "".join(ch for ch in text if ch.isprintable() or ch == " ")


# Most severe first. Anything else a matrix says about severity reads as unrated.
_SEVERITY_RANK = ("critical", "high", "medium", "low")
# Long enough for any real impact/remediation/mitigation sentence, short enough that a tampered
# fetched matrix cannot flood the terminal through one field.
_DETAIL_CAP = 1000


def _severity(value):
    """A matrix severity as one of _SEVERITY_RANK, or None (unrated). A fetched matrix is untrusted,
    so another spelling, a number or an object reads as unrated rather than inventing a bucket."""
    text = value.strip().lower() if isinstance(value, str) else None
    return text if text in _SEVERITY_RANK else None


def _fix_list(value):
    """An advisory's `fixed_in_lines` as a list of version strings, or [] when it is absent or not a
    list. Bounded like every fetched scalar: at most 20 entries, each one that parses as a version."""
    if not isinstance(value, list):
        return []
    out = []
    for item in value[:20]:
        if isinstance(item, str) and parse_semver(item) and item not in out:
            out.append(_bound_scalar(item, cap=32))
    return out


def _line_fix(version, fixes):
    """Which of an advisory's fixes an affected version is told about: the lowest fix above it, which
    is the fix on its own line when that line has one (every other line's fix above it is on a
    higher line), and otherwise the next line's; None when there is none above it."""
    above = [f for f in fixes if parse_semver(version) and parse_semver(f) > parse_semver(version)]
    return min(above, key=parse_semver) if above else None


def version_vulnerabilities(matrix, version):
    """The known vulnerabilities declared for `version`, or [].

    Tolerant like `version_support`: a matrix that predates the field, or does not declare the
    version, or states something other than a list, reads as 'none listed' rather than an error. A
    non-dict entry is dropped.

    Each entry is normalised to {title, fixed_in, fixed_in_lines, advisory, severity, cvss, impact,
    remediation, mitigation}. title and fixed_in are read from the version's own entry exactly as
    every older copy of this tool reads them, and coerced to a bounded str or None before they reach
    the dedupe -- so an unhashable JSON value ({} / []) in either can never blow the (title, fixed_in)
    key. An entry may instead carry only its advisory's id ({"advisory": "<slug>"}); a title or
    fixed_in it leaves out is then taken from that advisory -- the fix on the version's own line when
    the advisory lists one per line (`fixed_in_lines`) -- and a missing title falls back to the id, so
    the vulnerability is still counted and named (the app's update check reads references the same
    way). fixed_in_lines is the advisory's list of fixes, one per line, or [].
    The rest comes from the advisory the entry names in the matrix's top-level `advisories`
    (schema 3), or from the entry itself when it carries the fields (an older matrix, or a list this
    tool has already resolved and merged). Every string is bounded here and escape-stripped where
    printed; an unrecognised severity reads as unrated. fixed_in None means no fix has been released
    yet."""
    if not isinstance(matrix, dict):
        return []
    version = (version or "").lstrip("vV")
    meta = (matrix.get("versions") or {}).get(version) or {}
    if not isinstance(meta, dict):
        return []
    vulns = meta.get("vulnerabilities")
    if not isinstance(vulns, list):
        return []
    advisories = matrix.get("advisories")
    advisories = advisories if isinstance(advisories, dict) else {}
    out = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        slug = v.get("advisory") if isinstance(v.get("advisory"), str) else None
        record = advisories.get(slug) if slug is not None else None
        record = record if isinstance(record, dict) else {}

        def detail(name, _v=v, _record=record):
            value = _v.get(name)
            return value if value is not None else _record.get(name)

        # A field the entry carries wins, as it always has; one it leaves out comes from its advisory.
        # An advisory fixed on several lines names one release per line; a reference that leaves its
        # fix out is then told its own line's fix, not the lowest one.
        fixes = _fix_list(v.get("fixed_in_lines") if "fixed_in_lines" in v
                          else record.get("fixed_in_lines"))
        title = v["title"] if "title" in v else (record.get("title") or slug)
        if "fixed_in" in v:
            fixed_in = v["fixed_in"]
        else:
            fixed_in = _line_fix(version, fixes) or record.get("fixed_in")
        out.append({
            "title": _bound_scalar(title),
            "fixed_in": _bound_scalar(fixed_in),
            "fixed_in_lines": fixes,
            "advisory": _bound_scalar(slug),
            "severity": _severity(detail("severity")),
            "cvss": _bound_scalar(detail("cvss")),
            "impact": _bound_scalar(detail("impact"), cap=_DETAIL_CAP),
            "remediation": _bound_scalar(detail("remediation"), cap=_DETAIL_CAP),
            "mitigation": _bound_scalar(detail("mitigation"), cap=_DETAIL_CAP),
        })
    return out


def severity_counts(vulns):
    """The non-zero severity buckets of a vulnerability list, most severe first: '1 high, 2 unrated'."""
    counts = {}
    for v in vulns:
        bucket = v.get("severity") or "unrated"
        counts[bucket] = counts.get(bucket, 0) + 1
    return ", ".join("%d %s" % (counts[b], b) for b in _SEVERITY_RANK + ("unrated",) if counts.get(b))


def vulnerability_summary(vulns):
    """'3 known vulnerabilities (1 high, 2 medium)' for a non-empty list."""
    n = len(vulns)
    return "%d known %s (%s)" % (n, "vulnerability" if n == 1 else "vulnerabilities",
                                  severity_counts(vulns))


def describe_vulnerabilities(vulns, indent="    ", width=100):
    """The lines an operator reads before choosing a version, one block per vulnerability, most
    severe first: the severity and title, the release that fixes it (or that none does yet), what it
    lets someone do, and what to do about it. Every string is escape-stripped here, at the print."""
    import textwrap

    def rank(v):
        return _SEVERITY_RANK.index(v["severity"]) if v.get("severity") in _SEVERITY_RANK else len(_SEVERITY_RANK)

    lines = []
    for v in sorted(vulns, key=rank):
        fixed = v.get("fixed_in")
        others = [f for f in v.get("fixed_in_lines") or [] if f != fixed]
        lines.append("%s- [%s] %s -- %s%s" % (
            indent, (v.get("severity") or "unrated").upper(), clean_matrix_text(v.get("title") or ""),
            ("fixed in %s" % clean_matrix_text(fixed)) if fixed else "no fix released yet",
            ("; on other lines in %s" % ", ".join(clean_matrix_text(f) for f in others))
            if fixed and others else ""))
        for heading, key in (("Impact", "impact"), ("Remediation", "remediation"),
                             ("Mitigation", "mitigation")):
            text = clean_matrix_text(v.get(key) or "")
            if text:
                lines.extend(textwrap.wrap("%s: %s" % (heading, text), width=width,
                                           initial_indent=indent + "    ",
                                           subsequent_indent=indent + "      "))
        if v.get("cvss"):
            lines.append("%s    CVSS: %s" % (indent, clean_matrix_text(v["cvss"])))
    return lines


def _finding_key(v):
    """One vulnerability's identity: its advisory's id when it names one, else (title, fixed_in).

    The id is what stays the same across lines: a reference names the fix on its own version's
    line, so the same advisory reads (title, 0.33.2) on 0.33.1 and (title, 0.34.1) on 0.34.0, and a
    move between them would otherwise both fix one vulnerability and bring one back."""
    slug = v.get("advisory")
    if isinstance(slug, str) and slug:
        return ("advisory", slug)
    return ("finding", v.get("title"), v.get("fixed_in"))


def _finding_keys(matrix, version):
    """The set of identities (_finding_key) a version is affected by, so a finding counts once
    however many sources list it."""
    return {_finding_key(v) for v in version_vulnerabilities(matrix, version)}


def _declares_version(matrix, version):
    versions = matrix.get("versions") if isinstance(matrix, dict) else None
    return isinstance(versions, dict) and (version or "").lstrip("vV") in versions


def safer_alternative(matrix, target, candidates):
    """A release among `candidates` whose known vulnerabilities are a strict subset of `target`'s --
    fewer of them, and none that `target` does not also have -- or None.

    Choosing `target` over such a release accepts known vulnerabilities for no difference in known
    ones in return, so the update asks for the target's name typed back. It is advice, never a
    refusal: the tool cannot know why someone wants a particular release (a rollback during an
    outage is the usual reason), and the vulnerability data can come from the unauthenticated copy on
    main, which may raise a warning but must never block a change.

    A release the matrix does not declare is never offered: it has no known vulnerabilities only
    because nothing is known about it. A target with nothing listed has no safer alternative, since
    nothing is a strict subset of an empty set. Among several, one on the target's own release line
    wins (the smaller move: someone asking for 0.33.1 is pointed at 0.33.2 before 0.34.1), then the
    fewest known vulnerabilities, then the newest."""
    if not _declares_version(matrix, target):
        return None
    affected = _finding_keys(matrix, target)
    if not affected:
        return None
    target_version = parse_semver(target)
    better = []
    for candidate in candidates or []:
        if parse_semver(candidate) is None or parse_semver(candidate) == target_version:
            continue
        if not _declares_version(matrix, candidate):
            continue
        keys = _finding_keys(matrix, candidate)
        if keys < affected:
            better.append((release_line(candidate) != release_line(target), len(keys),
                           tuple(-part for part in parse_semver(candidate)), candidate))
    return min(better)[-1] if better else None


def support_line(matrix, version, today=None):
    """A one-line human summary of a version's lifecycle, or '' when nothing is stated. Names the
    end-of-life state, any extended-support tail dates, and whether the version is insecure -- and,
    when the matrix lists them, how many known vulnerabilities it has by severity, and the releases
    that fix them. The titles and details are for the chosen version only (describe_vulnerabilities):
    one line per release has no room for them. Every matrix-sourced fragment is escape-stripped
    before it reaches a terminal.

    A version that is not end-of-life is "supported" only while its release line receives security
    fixes, as .github/SECURITY.md defines support and the matrix's `lines` map states it: end-of-life
    is the upgrade floor, not the end of support. A line whose fixes have ended, or one older than every
    line the map lists, reads "no security fixes" (or the day they ended)."""
    s = version_support(matrix, version)
    if not s:
        return ""
    if s.get("eol") is True:
        parts = ["end-of-life"]
        if s.get("code_support"):
            parts.append("code support until %s" % clean_matrix_text(s["code_support"]))
        if s.get("security_support"):
            parts.append("security support until %s" % clean_matrix_text(s["security_support"]))
        head = "; ".join(parts)
    else:
        line = line_support_note(matrix, version, today=today)
        if line.startswith("security fixes ended"):
            head = clean_matrix_text(line)
        elif line.startswith("no longer"):
            head = "no security fixes"
        else:
            head = "supported"
    if s.get("secure") is False:
        vulns = version_vulnerabilities(matrix, version)
        if not vulns:
            # Insecure with nothing itemised (an older matrix, or an end-of-life release): the bare fact.
            return head + " -- has known unpatched vulnerabilities"
        head += " -- " + vulnerability_summary(vulns)
        fixes = sorted({v.get("fixed_in") for v in vulns if v.get("fixed_in")},
                       key=lambda t: parse_semver(t) or (0, 0, 0))
        if fixes:
            head += " -- fixed in %s" % ", ".join(clean_matrix_text(f) for f in fixes)
        unfixed = sum(1 for v in vulns if not v.get("fixed_in"))
        if unfixed:
            head += " -- %d with no fix released yet" % unfixed
    return head


_MAIN_MATRIX_URL = MATRIX_RAW_URL % "main"   # the lifecycle copy on main (a fixed URL, NOT a tag)
_MAIN_MATRIX_MAX_BYTES = 512 * 1024


def fetch_main_lifecycle_matrix(opener=None):
    """MAIN's upgrade matrix from the fixed raw URL, or None. Bounded (timeout + size cap) and
    fail-safe: any error, oversized body, or wrong shape yields None so the caller falls back to the
    copy it already has. Never raises. Only the LIFECYCLE fields are ever read from it, and the merge
    that consumes it is add-only, so a compromised copy can only tighten -- never clear, never falsely
    secure, never gate an upgrade (the hard gates stay on the tag-pinned matrices)."""
    import json as _json
    try:
        import urllib.request
        get = opener or urllib.request.urlopen
        with get(_MAIN_MATRIX_URL, timeout=15) as response:
            raw = response.read(_MAIN_MATRIX_MAX_BYTES + 1)
        if len(raw) > _MAIN_MATRIX_MAX_BYTES:
            return None
        data = _json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) and isinstance(data.get("versions"), dict) else None


def _credible_remote_vulns(remote_vulns, released_ceiling):
    """Drop a remote vulnerability whose fixed_in names a version NEWER than the newest RELEASE the
    tool can see -- an unreleased fix is not a credible disclosure. The ceiling is the newest RELEASE
    tag, never the running version, so a fix in a newer-but-released version is kept. A vuln with no
    fix, or an unparseable ceiling, is kept (never over-drop)."""
    ceil = parse_semver(released_ceiling)
    out = []
    for v in remote_vulns:
        if not isinstance(v, dict):
            continue
        fx = parse_semver(v.get("fixed_in"))
        if fx is None or ceil is None or fx <= ceil:
            out.append(v)
    return out


def _earlier_date(a, b):
    """The earlier of two ISO date strings; whichever is present when only one is (ISO sorts
    chronologically). Add-only: support never ends LATER than either source says."""
    present = [d for d in (a, b) if isinstance(d, str) and d]
    return min(present) if present else None


def _merge_support(local_s, remote_s):
    """Add-only merge of two support blocks: insecure if EITHER is insecure, eol if EITHER is eol,
    support-end the EARLIER. Never clears a local verdict, never sets secure (no false secure:true)."""
    merged = dict(local_s or {})
    if (local_s or {}).get("secure") is False or (remote_s or {}).get("secure") is False:
        merged["secure"] = False
    if (local_s or {}).get("eol") is True or (remote_s or {}).get("eol") is True:
        merged["eol"] = True
    for key in ("code_support", "security_support"):
        d = _earlier_date((local_s or {}).get(key), (remote_s or {}).get(key))
        if d is not None:
            merged[key] = d
    return merged


def _bound_scalar(value, cap=200):
    """Coerce an untrusted matrix scalar (a fetched title/fixed_in can be any JSON type up to the body
    cap) to a bounded str, or None. Applied to the merged lifecycle before any print; clean_matrix_text
    still strips terminal escapes at the print sites."""
    return None if value is None else str(value)[:cap]


def _merge_vulnerabilities(local_v, remote_v):
    """Union of two vulnerability lists. Two entries are one finding when both name the same
    advisory id, or when either names none and their (title, fixed_in) agree; so a title or fix
    worded differently in the two copies still counts once, and two advisories that happen to share
    a title and fix still count twice. Local entries are always kept; the remote can only ADD."""
    ids, pairs, out = set(), {}, []
    for v in list(local_v or []) + list(remote_v or []):
        if not isinstance(v, dict):
            continue
        slug = v.get("advisory") if isinstance(v.get("advisory"), str) and v.get("advisory") else None
        pair = (v.get("title"), v.get("fixed_in"))
        if slug is not None and slug in ids:
            continue
        if pair in pairs and (slug is None or pairs[pair] is None):
            continue
        if slug is not None:
            ids.add(slug)
        pairs.setdefault(pair, slug)
        out.append(v)
    return out


def line_support_until(matrix, line):
    """What a matrix's `lines` map says about a release line, as (stated, until).

    stated is False when the map is missing or malformed, or does not list the line. When stated,
    until is the day the line's security fixes end (YYYY-MM-DD), or None for the newest line, whose
    end is set when the next minor release ships. A value of any other shape reads as not stated: a
    fetched matrix is untrusted, and only a plain date is ever printed."""
    lines = matrix.get("lines") if isinstance(matrix, dict) else None
    entry = lines.get(line) if isinstance(lines, dict) and isinstance(line, str) else None
    if not isinstance(entry, dict) or "security_fixes_until" not in entry:
        return False, None
    until = entry["security_fixes_until"]
    if until is None:
        return True, None
    if isinstance(until, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", until):
        return True, until
    return False, None


def _merge_lines(local_lines, main_lines):
    """Add-only merge of two `lines` maps: every line either copy states, and where both state one,
    the earlier end wins (a day is earlier than no end yet). main can only bring a line's end
    forward, never push it back."""
    merged = {}
    for source in (local_lines, main_lines):
        if not isinstance(source, dict):
            continue
        for line in source:
            stated, until = line_support_until({"lines": source}, line)
            if not stated or not re.fullmatch(r"[0-9]+\.[0-9]+", str(line)):
                continue
            if line in merged:
                until = _earlier_date(merged[line]["security_fixes_until"], until)
            merged[line] = {"security_fixes_until": until}
    return merged


def _today():
    import datetime as _dt
    return _dt.date.today().isoformat()


def line_support_note(matrix, version, today=None):
    """How the release line of `version` stands, for one line of output, or '' when the matrix does
    not say.

    Reads the `lines` map: a line with a day is supported until then and ended after it; the newest
    line has no end yet; a line below the first one listed was never given a support period."""
    line = release_line(version)
    if line is None:
        return ""
    stated, until = line_support_until(matrix, line)
    if not stated:
        lines = matrix.get("lines") if isinstance(matrix, dict) else None
        listed = [l for l in lines if re.fullmatch(r"[0-9]+\.[0-9]+", str(l))] \
            if isinstance(lines, dict) else []
        first = min(listed, key=lambda l: parse_semver(l + ".0")) if listed else None
        if first and parse_semver(line + ".0") < parse_semver(first + ".0"):
            return "no longer receives security fixes (lines before %s are not supported)" % first
        return ""
    if until is None:
        return ("the newest line: security fixes continue until six months after the next minor "
                "release")
    if until < (today or _today()):
        return "security fixes ended on %s" % until
    return "security fixes until %s" % until


def merge_lifecycle_matrix(local_matrix, main_matrix, released_ceiling):
    """A copy of `local_matrix` with each version's LIFECYCLE (support + vulnerabilities) merged
    ADD-ONLY with main's, and each release line's support period (`lines`: every line either copy
    states, the earlier end winning). Returns (merged_matrix, source): source 'main' when main
    contributed, else 'local'. DISPLAY/advisory only -- the hard upgrade-path gates keep reading the tag-pinned
    matrices, so a compromised main can raise a false warning but can never block or wave through a
    hop. Never prefers a source and never clears a field."""
    import copy as _copy
    if main_matrix is None:
        return local_matrix, "local"
    try:
        merged = _copy.deepcopy(local_matrix) if isinstance(local_matrix, dict) else {"versions": {}}
        versions = merged.setdefault("versions", {})
        local_vers = (local_matrix or {}).get("versions") or {}
        main_vers = main_matrix.get("versions") or {}
        for ver in set(local_vers) | set(main_vers):
            ms = _merge_support(version_support(local_matrix, ver), version_support(main_matrix, ver))
            mv = _merge_vulnerabilities(
                version_vulnerabilities(local_matrix, ver),
                _credible_remote_vulns(version_vulnerabilities(main_matrix, ver), released_ceiling))
            meta = versions.setdefault(ver, {})
            if ms:
                meta["support"] = ms
            if mv:
                # Bound the two untrusted scalars once here, so every downstream print (the list note
                # and the target warning) is capped; clean_matrix_text still runs at those sites.
                meta["vulnerabilities"] = [
                    {**v, "title": _bound_scalar(v.get("title")), "fixed_in": _bound_scalar(v.get("fixed_in"))}
                    for v in mv]
        lines = _merge_lines((local_matrix or {}).get("lines"), main_matrix.get("lines"))
        if lines:
            merged["lines"] = lines
        return merged, "main"
    except Exception:  # a malformed remote must never crash the tool's upgrade path (constraint 2);
        return local_matrix, "local"


def fetch_upgrade_matrix(tag, root=None, opener=None):
    """The upgrade matrix describing a hop TO `tag`. Returns (matrix_or_None, source_description).

    The published file for the target is preferred over this checkout's copy: the checkout may be
    older than the release being installed, and an older file cannot describe a newer hop. The
    local copy is the offline fallback and is labelled as possibly stale.
    """
    import json as _json

    if tag:
        url = MATRIX_RAW_URL % (tag if tag.startswith("v") else "v" + tag)
        try:
            import urllib.request
            get = opener or urllib.request.urlopen
            with get(url, timeout=15) as response:
                return _json.loads(response.read().decode("utf-8")), "the published %s matrix" % tag
        except Exception:
            pass

    if root:
        local = os.path.join(root, MATRIX_LOCAL)
        try:
            with open(local, encoding="utf-8") as handle:
                return _json.load(handle), "this checkout's matrix (may predate the target)"
        except Exception:
            pass
    return None, "no upgrade matrix could be read"


def fetch_describing_matrix(target, current, root=None):
    """The matrix a move from `current` to `target` is described by, and where it came from.

    The target's published matrix first (fetch_upgrade_matrix; this checkout's copy when offline).
    A release made on an older line after the target shipped is not in the target's matrix, so when
    that one does not declare both versions, the running version's own published matrix is asked:
    it declares that release's way up. Both are tag matrices, fixed once published and checked by the
    release gate; the copy on main is never used to describe or gate a move. When neither declares
    both, the target's answer stands and the move reads as not described."""
    matrix, source = fetch_upgrade_matrix(target, root=root)
    if not parse_semver(current) or (_declares_version(matrix, current)
                                     and _declares_version(matrix, target)):
        return matrix, source
    own = current if str(current).startswith("v") else "v" + str(current)
    other, other_source = fetch_upgrade_matrix(own, root=None)
    if _declares_version(other, current) and _declares_version(other, target):
        return other, other_source
    return matrix, source


def read_version_file(root):
    """The current version from <root>/VERSION, or 'unknown'."""
    try:
        return open(os.path.join(root, "VERSION"), encoding="utf-8").read().strip() or "unknown"
    except OSError:
        return "unknown"


# --- secret <-> volume guardrail -------------------------------------------------------------
# The reported footgun: Postgres bakes VAULT_DB_PASSWORD into vault_pg_data on FIRST init and never
# re-reads it, so a fresh/changed .env against a populated volume can't authenticate ("password
# authentication failed for user sftp_user") - and a mismatched ENCRYPTION_KEY makes stored files
# undecryptable. Before starting on an existing volume the tool verifies the current .env's DB
# password authenticates against it and refuses-with-explanation (never printing a secret) on a
# mismatch or an ambiguous result. These vault DB coordinates are fixed by the compose.
PG_USER = "sftp_user"
PG_DB = "sftp_db"
DB_CONTAINER = "vault-db"


def volume_exists(name, run=subprocess.run):
    """True if a docker volume named `name` exists. Best-effort (False on any docker error)."""
    try:
        r = run(["docker", "volume", "inspect", name], capture_output=True, text=True, timeout=20)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return getattr(r, "returncode", 1) == 0


def container_running(name, run=subprocess.run):
    """True if a container named `name` exists AND is running. Best-effort: any docker error
    answers False, which callers must treat as 'not known to be running'. A paused container is
    running here (Docker's .State.Running): it still holds its volumes. container_paused tells the
    two apart where that matters (a backup pauses only what is not paused already)."""
    try:
        r = run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                capture_output=True, text=True, timeout=20)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    if getattr(r, "returncode", 1) != 0:
        return False
    return (getattr(r, "stdout", "") or "").strip() == "true"


def container_paused(name, run=subprocess.run):
    """True if a container named `name` is paused, False if it is there and not paused, None when Docker cannot
    tell (no such container, or Docker did not answer). Asked while a backup resumes the deployment, so its docker
    child runs out of reach of the signals that end the run (own_session_kwargs)."""
    try:
        r = run(["docker", "inspect", "-f", "{{.State.Paused}}", name], capture_output=True, text=True, timeout=20,
                stdin=subprocess.DEVNULL, **own_session_kwargs())
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if getattr(r, "returncode", 1) != 0:
        return None
    answer = (getattr(r, "stdout", "") or "").strip()
    return True if answer == "true" else False if answer == "false" else None


def container_exists(name, run=subprocess.run):
    """True if a container named `name` exists at all - RUNNING OR STOPPED. A stopped container still
    holds its environment in Docker's on-disk config, so this (not container_running) is what tells an
    operator whether the deployment's secrets still sit in Docker while .env is sealed. Best-effort:
    any docker error answers False."""
    try:
        r = run(["docker", "container", "inspect", name], capture_output=True, text=True, timeout=20)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return getattr(r, "returncode", 1) == 0


def container_mounts(name, run=subprocess.run):
    """The named volumes a container has mounted, or None if docker could not be asked. Bind
    mounts have no .Name and come back blank, so they are dropped."""
    try:
        r = run(["docker", "inspect", "-f", "{{range .Mounts}}{{.Name}} {{end}}", name],
                capture_output=True, text=True, timeout=20)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if getattr(r, "returncode", 1) != 0:
        return None
    return (getattr(r, "stdout", "") or "").split()


def containers_publishing(port, run=subprocess.run):
    """The names of running containers publishing host `port`, or None if docker could not be
    asked. An empty list means 'nothing of docker's is on that port' - distinct from None, which
    means 'unknown', so a caller can tell "not ours" from "could not tell"."""
    try:
        r = run(["docker", "ps", "--filter", "publish=%s" % port, "--format", "{{.Names}}"],
                capture_output=True, text=True, timeout=20)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if getattr(r, "returncode", 1) != 0:
        return None
    return [line.strip() for line in (getattr(r, "stdout", "") or "").splitlines() if line.strip()]


def fernet_key_looks_valid(key):
    """True if `key` is shaped like a Fernet key: urlsafe-base64 of exactly 32 bytes. Stdlib-only
    (no decryption) - a cheap sanity check that ENCRYPTION_KEY isn't missing/garbled, without pulling
    in a crypto dependency."""
    try:
        raw = base64.urlsafe_b64decode((key or "").encode("ascii"))
    except Exception:   # noqa: BLE001 - any decode failure means "not a Fernet key"
        return False
    return len(raw) == 32


def classify_pg_probe(returncode, stderr):
    """Classify a `psql` auth probe -> 'ok' | 'mismatch' | 'ambiguous'. A clean exit is a password
    MATCH; a Postgres auth failure (28P01 / 'password authentication failed') is a definite MISMATCH;
    anything else (server not ready, network, unknown) is AMBIGUOUS so the caller fails closed. Pure -
    it never sees the password."""
    if returncode == 0:
        return "ok"
    s = (stderr or "").lower()
    if "password authentication failed" in s or "28p01" in s or "28000" in s:
        return "mismatch"
    return "ambiguous"


def probe_pg_password(container, user, db, password, run=subprocess.run):
    """Auth-probe a RUNNING postgres `container` with `password` -> classify_pg_probe(...). Connects
    over the container's OWN network IP (NOT 127.0.0.1 / the unix socket, which the postgres image
    trusts WITHOUT a password) so the probe exercises the SAME scram password auth the vault app uses.
    The password is passed via PGPASSWORD INSIDE the container (docker exec -e NAME, value taken from
    the client env) so it never lands on the host argv or in logs. Ambiguous on any docker/exec error
    so the caller fails closed."""
    try:
        ipr = run(["docker", "exec", container, "hostname", "-i"],
                  capture_output=True, text=True, timeout=20)
    except (OSError, ValueError, subprocess.SubprocessError):
        return "ambiguous"
    if getattr(ipr, "returncode", 1) != 0:
        return "ambiguous"
    parts = (getattr(ipr, "stdout", "") or "").split()
    if not parts:
        return "ambiguous"
    ip = parts[0]
    try:
        r = run(["docker", "exec", "-e", "PGPASSWORD", container,
                 "psql", "-h", ip, "-U", user, "-d", db, "-tAc", "SELECT 1"],
                capture_output=True, text=True, timeout=30,
                env=dict(os.environ, PGPASSWORD=password))
    except (OSError, ValueError, subprocess.SubprocessError):
        return "ambiguous"
    return classify_pg_probe(getattr(r, "returncode", 1), getattr(r, "stderr", ""))


def admin_bootstrap_done(container, user, db, password, run=subprocess.run):
    """Whether the running DB carries the admin_bootstrap marker - i.e. an admin exists and the
    initial ADMIN_PASSWORD is spent. Returns True (marker present), False (confirmed absent) or None
    (any docker/exec/auth error -> the caller must fail closed and KEEP the password). Connects the
    same way probe_pg_password does (the container's own IP + PGPASSWORD, never the trusted socket),
    so it exercises real auth and never puts a secret on the host argv."""
    try:
        ipr = run(["docker", "exec", container, "hostname", "-i"],
                  capture_output=True, text=True, timeout=20)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if getattr(ipr, "returncode", 1) != 0:
        return None
    parts = (getattr(ipr, "stdout", "") or "").split()
    if not parts:
        return None
    ip = parts[0]
    try:
        r = run(["docker", "exec", "-e", "PGPASSWORD", container,
                 "psql", "-h", ip, "-U", user, "-d", db, "-tAc",
                 "SELECT 1 FROM system_settings WHERE key='admin_bootstrap' LIMIT 1"],
                capture_output=True, text=True, timeout=30,
                env=dict(os.environ, PGPASSWORD=password))
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if getattr(r, "returncode", 1) != 0:
        return None
    return (getattr(r, "stdout", "") or "").strip() == "1"


def read_key_canary(container, user, db, password, run=subprocess.run):
    """The ENCRYPTION_KEY check the vault keeps in its database (app/core/key_canary.py: a Fernet token of a fixed
    text, sealed under the deployment's ENCRYPTION_KEY at its first start), read from the RUNNING postgres
    `container` the way probe_pg_password connects (its own IP, PGPASSWORD inside the container, never on the host
    argv). Returns the token, '' when the database holds none (a set whose app has not started yet), or None when it
    cannot be read (any docker, exec or SQL error): unknown, never a mismatch."""
    try:
        ipr = run(["docker", "exec", container, "hostname", "-i"], capture_output=True, text=True, timeout=20)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    parts = (getattr(ipr, "stdout", "") or "").split() if getattr(ipr, "returncode", 1) == 0 else []
    if not parts:
        return None
    try:
        r = run(["docker", "exec", "-e", "PGPASSWORD", container,
                 "psql", "-h", parts[0], "-U", user, "-d", db, "-tAc",
                 "SELECT value->>'ct' FROM system_settings WHERE key='encryption_key_canary'"],
                capture_output=True, text=True, timeout=30, env=dict(os.environ, PGPASSWORD=password))
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    if getattr(r, "returncode", 1) != 0:
        return None
    return (getattr(r, "stdout", "") or "").strip()


def fernet_token_signed_by(key, token):
    """True when the Fernet `token` was made under the Fernet `key`: its HMAC-SHA256, under the key's signing half,
    verifies. Stdlib only (no decryption, so no crypto dependency); a token of a fixed text that verifies under a key
    proves it is that key. False for another key, a garbled token, or anything not a key."""
    import hmac
    try:
        raw = base64.urlsafe_b64decode((key or "").strip().encode("ascii"))
        text = (token or "").strip().encode("ascii")
        data = base64.urlsafe_b64decode(text + b"=" * (-len(text) % 4))
    except (ValueError, UnicodeEncodeError):
        return False
    if len(raw) != 32 or len(data) < 1 + 8 + 16 + 16 + 32 or data[0] != 0x80:
        return False
    mac = hmac.new(raw[:16], data[:-32], hashlib.sha256).digest()
    return hmac.compare_digest(mac, data[-32:])


def db_guard_decision(volume_exists_flag, probe_result):
    """The pure guardrail decision: 'proceed' | 'refuse'. A fresh (non-existent) volume always
    proceeds (the .env password is baked in on first init). An existing volume proceeds ONLY on a
    confirmed password match; a mismatch OR an ambiguous probe refuses (fail-closed)."""
    if not volume_exists_flag:
        return "proceed"
    return "proceed" if probe_result == "ok" else "refuse"


# --- credential lock: seal .env <-> .env.enc (envelope encryption) ---------------------------
# .env holds every deployment secret (ENCRYPTION_KEY, VAULT_DB_PASSWORD, ...). `lock` seals it into
# an encrypted .env.enc and removes the plaintext; `unlock` restores it. TWO credentials can open it:
# the unlock PASSPHRASE and a high-entropy RECOVERY KEY (which is the file's data key). Envelope model
# (the LUKS / age multi-recipient pattern, with vetted primitives): one random DEK encrypts .env once
# with Fernet (authenticated AES-128-CBC + HMAC); the DEK is wrapped under a scrypt-derived key from
# the passphrase, and the DEK itself is the recovery key. Full rationale + threat model:
# docs/design/credential-lock-and-lifecycle.md. This protects .env only while sealed/off - a RUNNING
# stack needs plaintext .env; host full-disk encryption is the control for a running box.
ENV_LOCK_MAGIC = "DOCKVAULT-ENV-LOCK v1"
ENV_LOCK_KDF = {"algo": "scrypt", "n": 1 << 15, "r": 8, "p": 1}


class EnvLockError(Exception):
    """A .env.enc could not be parsed or decrypted (wrong passphrase/recovery key, or tampering)."""


def load_fernet():
    """Return the Fernet class, or None if the `cryptography` package is not installed. Imported
    LAZILY so every OTHER dockvault.py command stays stdlib-only; only lock/unlock need it."""
    try:
        from cryptography.fernet import Fernet
        return Fernet
    except Exception:  # noqa: BLE001 - not installed / broken install
        return None


def _scrypt_maxmem(n, r):
    """A maxmem for hashlib.scrypt big enough that the given (n, r) reliably succeeds on any host -
    the default (~32 MiB) REJECTS our params, which would otherwise force a silent KDF downgrade.
    scrypt's OUTPUT does not depend on maxmem, so a generous value keeps derivation identical across
    machines (only the allocation ceiling changes)."""
    return max(64 * 1024 * 1024, 128 * int(r) * int(n) * 2)


def _scrypt_ok():
    """True if this host's hashlib.scrypt can run the sealing params (a few Python builds omit it)."""
    try:
        hashlib.scrypt(b"probe", salt=b"\x00" * 16, n=ENV_LOCK_KDF["n"], r=ENV_LOCK_KDF["r"],
                       p=ENV_LOCK_KDF["p"],
                       maxmem=_scrypt_maxmem(ENV_LOCK_KDF["n"], ENV_LOCK_KDF["r"]), dklen=32)
        return True
    except Exception:  # noqa: BLE001
        return False


def _seal_kdf():
    """The KDF descriptor to seal a NEW .env.enc with: memory-hard scrypt where the host supports it,
    else strong PBKDF2. The descriptor (algo + params) is written into the header so env_lock_open
    reproduces the EXACT derivation on ANY host - never a runtime scrypt-vs-pbkdf2 guess that could
    diverge between the sealing host and a restore host (which silently broke the passphrase before)."""
    if _scrypt_ok():
        return {"algo": "scrypt", "n": ENV_LOCK_KDF["n"], "r": ENV_LOCK_KDF["r"], "p": ENV_LOCK_KDF["p"]}
    return {"algo": "pbkdf2", "iterations": 600000}


def _derive_kek(passphrase, salt, kdf):
    """Derive the 32-byte key-encryption-key EXACTLY as the recorded `kdf` (algo + params) specifies,
    returned as a url-safe-base64 Fernet key. Deterministic: the same kdf + passphrase + salt yields
    the same key on every host. Raises EnvLockError if the recorded algo cannot run here (loud, never
    a silent switch to a different KDF that would compute the wrong key)."""
    pw = passphrase.encode("utf-8")
    algo = kdf.get("algo")
    if algo == "scrypt":
        try:
            raw = hashlib.scrypt(pw, salt=salt, n=int(kdf["n"]), r=int(kdf["r"]), p=int(kdf["p"]),
                                 maxmem=_scrypt_maxmem(int(kdf["n"]), int(kdf["r"])), dklen=32)
        except (ValueError, MemoryError, KeyError) as exc:
            raise EnvLockError("this host cannot run the lock file's scrypt parameters (%s)" % exc)
    elif algo == "pbkdf2":
        try:
            raw = hashlib.pbkdf2_hmac("sha256", pw, salt, int(kdf["iterations"]), dklen=32)
        except (ValueError, KeyError) as exc:
            raise EnvLockError("invalid pbkdf2 parameters in the lock file (%s)" % exc)
    else:
        raise EnvLockError("unknown KDF %r in the lock file" % algo)
    return base64.urlsafe_b64encode(raw)


def env_lock_seal(fernet, env_bytes, passphrase, dek=None, hint=None, now_iso=None):
    """Encrypt the raw .env bytes into the .env.enc text (magic header + JSON). If dek is None a fresh
    one is generated (its value IS the recovery key). The KDF descriptor actually used is recorded in
    the header. Returns (enc_text, dek). env_bytes is bytes so lock/unlock are byte-exact."""
    if dek is None:
        dek = fernet.generate_key()
    salt = os.urandom(16)
    kdf = _seal_kdf()
    kek = _derive_kek(passphrase, salt, kdf)
    body = {
        "version": 1,
        "kdf": dict(kdf, salt=base64.b64encode(salt).decode()),
        "cipher": "fernet",
        "wrapped_dek": base64.b64encode(fernet(kek).encrypt(dek)).decode(),
        "payload": base64.b64encode(fernet(dek).encrypt(env_bytes)).decode(),
    }
    if now_iso:
        body["created_at"] = now_iso
    if hint:
        body["hint"] = str(hint)[:200]
    return ENV_LOCK_MAGIC + "\n" + json.dumps(body, indent=2) + "\n", dek


def _parse_env_lock(enc_text):
    """Validate the magic header + JSON body of a .env.enc. Raises EnvLockError on anything off."""
    parts = enc_text.split("\n", 1)
    if not parts or parts[0].strip() != ENV_LOCK_MAGIC:
        raise EnvLockError("not a DockVault credential lock file (bad header)")
    try:
        body = json.loads(parts[1]) if len(parts) > 1 else {}
    except ValueError:
        raise EnvLockError("the lock file body is not valid JSON (corrupt)")
    if body.get("version") != 1 or "payload" not in body:
        raise EnvLockError("unsupported or incomplete lock file (version %r)" % body.get("version"))
    return body


def sealed_set_differs(sealed_bytes, env_bytes):
    """Why the .env sealed in `sealed_bytes` belongs to another set than `env_bytes`, or "" when both are the
    same set's (an edited .env, sealed again). A set is its volumes (VAULT_VOLUME_PREFIX) and the key its data is
    encrypted under (ENCRYPTION_KEY): another set's .env differs in either. Names neither key's value."""
    def _read(raw):
        try:
            return parse_env(bytes(raw).decode("utf-8"))
        except (UnicodeDecodeError, TypeError):
            return {}
    sealed, new = _read(sealed_bytes), _read(env_bytes)
    if volume_prefix(sealed) != volume_prefix(new):
        return "set '%s', while .env is set '%s'" % (volume_prefix(sealed), volume_prefix(new))
    if (sealed.get("ENCRYPTION_KEY") or "").strip() != (new.get("ENCRYPTION_KEY") or "").strip():
        return "set '%s' with another ENCRYPTION_KEY than this .env's" % volume_prefix(sealed)
    return ""


def env_lock_open(fernet, enc_text, passphrase=None, recovery_key=None):
    """Decrypt a .env.enc. Provide EITHER passphrase OR recovery_key. Returns (env_bytes, dek).
    Raises EnvLockError on a wrong credential, tampering, or a malformed file."""
    from cryptography.fernet import InvalidToken
    body = _parse_env_lock(enc_text)
    if recovery_key is not None:
        rk = recovery_key.strip() if isinstance(recovery_key, str) else recovery_key
        try:
            dek = rk.encode("ascii") if isinstance(rk, str) else rk
        except UnicodeEncodeError:
            raise EnvLockError("the recovery key contains invalid characters")
    elif passphrase is not None:
        try:
            salt = base64.b64decode(body["kdf"]["salt"])
        except Exception:  # noqa: BLE001
            raise EnvLockError("the lock file key parameters are corrupt")
        kek = _derive_kek(passphrase, salt, body["kdf"])
        try:
            dek = fernet(kek).decrypt(base64.b64decode(body["wrapped_dek"]))
        except (InvalidToken, KeyError, ValueError):
            raise EnvLockError("wrong passphrase")
    else:
        raise EnvLockError("no passphrase or recovery key supplied")
    try:
        env_bytes = fernet(dek).decrypt(base64.b64decode(body["payload"]))
    except (InvalidToken, ValueError):
        raise EnvLockError("could not decrypt (wrong recovery key, or the file is corrupt/tampered)")
    return env_bytes, dek


# --- app -------------------------------------------------------------------------------------
# --- accounts (host operator) ------------------------------------------------------------------
ACCOUNT_ACTIONS = (
    ("reset-password", "Reset a password (a one-time reset link)"),
    ("reset-second-factor", "Reset a second factor (set up again at the next sign-in)"),
    ("approve", "Approve a change waiting for a second administrator"),
    ("list", "List the changes waiting for approval"),
    ("user-managers", "List who may manage users without being an administrator"),
    ("regranted-defaults", "List revoked permissions that a restart granted again (before 0.33.1)"),
    ("unlock", "Unlock an account: its automatic locks and an administrator's lock"),
    ("release-key-hold", "Let a user open their encryption key without the emailed code (after an "
                         "administrator's change)"),
)


def parse_operator_answer(stdout):
    """The JSON answer the account tool inside the container prints as its LAST line, or None.

    Anything the application prints while it starts comes before it, so only the last non-empty line
    is read, and only a JSON object carrying "ok" counts."""
    lines = [ln for ln in (stdout or "").splitlines() if ln.strip()]
    if not lines:
        return None
    try:
        answer = json.loads(lines[-1])
    except ValueError:
        return None
    return answer if isinstance(answer, dict) and "ok" in answer else None


def parse_df_available(stdout):
    """The available bytes `df -Pk <path>` prints for its one filesystem, or None."""
    lines = [ln.split() for ln in (stdout or "").splitlines() if ln.strip()]
    if len(lines) < 2 or len(lines[-1]) < 4:
        return None
    try:
        return int(lines[-1][3]) * 1024
    except ValueError:
        return None


def server_text(value, default=""):
    """A string the account tool read from the server, made safe to print on this terminal.

    Usernames, email addresses and refusal texts come from the deployment's database. A username
    created before the server refused control characters can carry an escape sequence that would act on
    the operator's terminal (a colour, a cursor move, a window title, a hyperlink), so each is passed
    through clean_matrix_text first. None prints as `default`."""
    if value is None:
        return default
    return clean_matrix_text(value if isinstance(value, str) else str(value))


# --- cases (compliance access, from the host) ------------------------------------------------------
CASE_ACTIONS = (
    ("list", "List the auditor rights and the cases that are open"),
    ("show", "Show an auditor right or a case"),
    ("grant-approve", "Approve an auditor right (only when no administrator can)"),
    ("revoke-auditor", "Revoke an account's auditor right"),
    ("approve", "Approve a case (only when no administrator can)"),
    ("reject", "Turn a case down"),
    ("confirm-hold", "Confirm a case's legal hold (only when no administrator can)"),
    ("downgrade-blockers", "List what stops going back to an older version"),
)


def case_reference_problem(typed):
    """Why a case step must not go ahead: no reference typed back. None when one was. The container checks
    that it matches the case."""
    if not (typed or "").strip():
        return "type the case's reference again with --confirm-case (list shows it)"
    return None


# The audit menu: what `audit` does when it is chosen from the top menu (each is also `audit <action>`).
AUDIT_MENU = (
    ("retention", "Retention - how long records are kept, and change a .env limit"),
    ("verify", "Verify - check the integrity chain and print its head to keep elsewhere"),
    ("unarchive", "Unarchive - restore archived days as rows (checks the free space first)"),
    ("compact", "Compact - give the audit tables' free space back to the system (locks them while it runs)"),
)
# The headings of the retention settings' groups, as the Settings page names them.
RETENTION_GROUPS = (("audit_retention", "Audit log"), ("retention", "Other records"),
                    ("audit_integrity", "Sealing"), ("working_records", "Fixed periods"))
_RETENTION_SOURCES = {"default": "default", "env": "from .env", "admin": "set in the panel",
                      "locked": "locked by .env"}
_ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def parse_retention_sets(texts):
    """--set NAME=VALUE texts as [(NAME, VALUE)], or raise ValueError naming the first that is not of that form
    (an upper-case .env name, a value without a line break) or that repeats a name. Which names are lines of
    the retention settings, and which values the server accepts, the server says (audit retention)."""
    out, seen = [], set()
    for text in texts or []:
        name, sep, value = (text or "").partition("=")
        name, value = name.strip(), value.strip()
        if not sep or not _ENV_LINE.match(name) or not value or "\n" in value or "\r" in value:
            raise ValueError("%r is not NAME=VALUE (an upper-case .env name)" % (text,))
        if name in seen:
            raise ValueError("%s is given twice" % name)
        seen.add(name)
        out.append((name, value))
    return out


def retention_value_text(row, value):
    """A retention setting's value as words: on/off, no limit (no cap, for a size), or the number and unit."""
    if value is None:
        return "not set"
    if row.get("kind") == "bool" or isinstance(value, bool):
        return "on" if value else "off"
    if row.get("unlimited") is not None and value == row.get("unlimited"):
        return "no cap" if row.get("unit") == "MB" else "no limit"
    unit = server_text(row.get("unit"))
    if value == 1 and unit.endswith("s"):
        unit = unit[:-1]                                  # 1 hour, 1 day
    return ("%s %s" % (server_text(value), unit)).strip()


def describe_retention(answer):
    """The lines `audit retention` prints for the server's answer: each group's settings with the value in
    force, where it comes from and the .env lines that set and bound it; then the changes waiting."""
    rows = answer.get("settings") or []
    lines = []
    for group, heading in RETENTION_GROUPS:
        mine = [r for r in rows if r.get("group") == group]
        if not mine:
            continue
        lines.append("  %s" % heading)
        for r in mine:
            how = [_RETENTION_SOURCES.get(r.get("source"), server_text(r.get("source")))]
            if r.get("editable") == "fixed":
                how = ["fixed"]
            elif r.get("env"):
                how.append("set by %s" % server_text(r.get("env")))
            if r.get("kind") == "bool":
                if r.get("floor") is True and r.get("floor_env"):
                    how.append("kept on by %s" % server_text(r.get("floor_env")))
            elif r.get("floor") is not None and r.get("floor_env"):
                how.append("at least %s (%s)" % (retention_value_text(r, r.get("floor")),
                                                 server_text(r.get("floor_env"))))
            if r.get("ceiling") is not None and r.get("ceiling_env"):
                how.append("at most %s (%s)" % (retention_value_text(r, r.get("ceiling")),
                                                server_text(r.get("ceiling_env"))))
            if r.get("editable") == "env_only":
                how.append("only .env changes it")
            lines.append("    %-58s %s" % (server_text(r.get("label") or r.get("key")),
                                           retention_value_text(r, r.get("value"))))
            lines.append("    %-58s %s" % ("", "; ".join(how)))
    pending = answer.get("pending") or []
    if pending:
        lines.append("  Waiting (any administrator can cancel them in Settings, Activity and records)")
        for p in pending:
            lines.append("    %s: %s -> %s from %s, asked by %s" % (
                server_text(p.get("label") or p.get("key")), server_text(p.get("old"), "the deployment's"),
                server_text(p.get("new"), "the deployment's"), server_text(p.get("effective_at"), "?"),
                server_text(p.get("requested_by"), "?")))
    if answer.get("chain_unreadable"):
        lines.append("  The audit chain could not be read (%s): the values are the database's, not necessarily "
                     "what the pruner acts on." % server_text(answer.get("chain_unreadable")))
    return lines


def username_confirmation_problem(username, typed_again):
    """Why an account change must not go ahead: the username was not given, or not typed again
    exactly. None when it may. The container checks the same again."""
    if not (username or "").strip():
        return "no username given"
    if typed_again != username:
        return "the username typed again does not match - nothing was changed"
    return None


class DockVault:
    """The management app: holds the palette + repo root and dispatches menu/arg commands to the
    per-area handlers (setup / backup / volumes / reset / update / logs)."""

    # Every container this deployment can run. The composes pin these names globally, so a
    # container answering to one of them IS this deployment - two sets cannot coexist.
    OWN_CONTAINERS = frozenset({"vault", "vault-api", "vault-sftp", DB_CONTAINER, "vault-redis"})

    def __init__(self, pal, root=APP_ROOT):
        self.pal = pal
        self.root = root
        # Set by _start_db_only: whether vault-db was already up before the secret probe.
        self._db_was_running = False
        # Set by _verify_env_against_volume: the pg volume the current check is about.
        self._guard_vol = None
        # Set by _guard_db_secret: how a .env whose database password opens the volume has its ENCRYPTION_KEY checked
        # too (the vault's key check in the database), or None for no such check (a stand-in probe).
        self._canary_check = None

    # Area handlers — accept an optional argparse namespace so the SAME handler serves both the
    # interactive menu (args=None) and arg-mode (args=<namespace>).
    def _fail(self, msg):
        print(self.pal.paint("ERROR: %s" % msg, "red"))
        raise SystemExit(1)

    def _env_path(self):
        return os.path.join(self.root, ".env")

    def _certs_dir(self):
        return os.path.join(self.root, "certs")

    def _env_lock_path(self):
        return os.path.join(self.root, ".env.enc")

    def _is_locked(self):
        """True when .env is sealed: no plaintext .env, but a .env.enc is present."""
        return (not os.path.exists(self._env_path())) and os.path.exists(self._env_lock_path())

    def _refuse_while_locked(self, what):
        """Stop `what`, a command that writes .env, while .env is sealed by `lock`, before it writes anything. A .env
        written beside the sealed one would be another set's (fresh secrets, a new set's, another set's copy), and a
        later `lock` (or `down --lock`) would seal it over the sealed one: the sealed set's ENCRYPTION_KEY would then
        be nowhere, and its volumes could never be read again."""
        if self._is_locked():
            self._fail(".env is locked (sealed in .env.enc): unlock it first (python dockvault.py unlock), then run %s "
                       "again. A .env written beside the sealed one, and sealed over it by a later lock, would lose "
                       "the sealed set's keys. Nothing changed." % what)

    def _atomic_write_secret(self, path, data):
        """Write `data` to `path` atomically (temp in the same dir -> fsync -> os.replace) and tighten
        perms to owner-only. The temp file is created mode-600 on POSIX so a secret is never briefly
        world-readable before the rename. `data` may be str (written UTF-8, LF) or bytes (written
        verbatim - used for .env so a lock/unlock round-trip is byte-for-byte identical)."""
        is_bytes = isinstance(data, (bytes, bytearray))
        d = os.path.dirname(path) or "."
        fd, tmp = tempfile.mkstemp(prefix=".dvtmp-", dir=d)
        try:
            if os.name != "nt":
                os.fchmod(fd, 0o600)
            if is_bytes:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
            else:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
            os.replace(tmp, path)
            tmp = None
        finally:
            if tmp is not None and os.path.exists(tmp):
                try:
                    os.remove(tmp)
                except OSError:
                    pass
        tighten_secret_file(path)

    # --- credential lock / unlock -----------------------------------------------------------
    def _require_fernet(self):
        fernet = load_fernet()
        if fernet is None:
            print(self.pal.paint(
                "  Locking/unlocking needs the 'cryptography' package (not installed).\n"
                "  Install it, then retry:   pip install cryptography", "red"))
            raise SystemExit(2)
        return fernet

    def _read_passphrase(self, args, confirm, prefix="passphrase", label="Unlock passphrase"):
        """A passphrase, from --<prefix>-file / --<prefix>-stdin, else an interactive prompt. `confirm`
        asks twice + enforces a minimum length (used only when SETTING one). `prefix`/`label` let this
        serve both the current passphrase and a NEW one (change-passphrase)."""
        pf = getattr(args, prefix + "_file", None)
        flag = prefix.replace("_", "-")
        if pf:
            try:
                with open(pf, encoding="utf-8") as f:
                    return f.readline().rstrip("\r\n")
            except OSError as exc:
                print(self.pal.paint("  Cannot read --%s-file %s: %s" % (flag, pf, exc), "red"))
                raise SystemExit(2)
        if getattr(args, prefix + "_stdin", False):
            return sys.stdin.readline().rstrip("\r\n")
        while True:
            pw = ask_secret(label, self.pal)
            if not confirm:
                return pw
            if len(pw) < 8:
                print(self.pal.paint("  Use at least 8 characters.", "red"))
                continue
            if ask_secret("Confirm " + label.lower(), self.pal) != pw:
                print(self.pal.paint("  Passphrases do not match.", "red"))
                continue
            return pw

    def _read_recovery_key(self, args):
        rf = getattr(args, "recovery_key_file", None)
        if rf:
            try:
                with open(rf, encoding="utf-8") as f:
                    return f.read().strip()
            except OSError as exc:
                print(self.pal.paint("  Cannot read --recovery-key-file %s: %s" % (rf, exc), "red"))
                raise SystemExit(2)
        return ask_secret("Credential recovery key", self.pal).strip()

    def _emit_secret(self, text, label="secret", kept_in=None):
        """Write a one-time secret to the controlling TERMINAL (/dev/tty, or CON on Windows), NOT
        stdout - so a redirected or tee'd stdout (a setup log, CI output) can't capture it. With no
        controlling terminal (cloud-init, a CI job, a service) it goes to a new file only this user can read
        (_write_secret_file), and stdout names only that file - or, with `kept_in` (a file the caller writes the
        secret to anyway, as --recovery-out), only that one. stdout carries the secret only when no file can be
        written either, and says so."""
        dev = "CON" if os.name == "nt" else "/dev/tty"
        try:
            with open(dev, "w", encoding="utf-8") as tty:
                tty.write(text + "\n")
                return
        except OSError:
            pass
        what = label.replace("-", " ")
        if kept_in:
            print(self.pal.paint("  No terminal to show the %s on: it is written to %s only." % (what, kept_in),
                                 "yellow"))
            return
        path = self._write_secret_file(label, text)
        if path:
            print(self.pal.paint("  No terminal to show the %s on: it is in %s, which only you can read. Read it, "
                                 "keep it somewhere safe, then delete that file." % (what, path), "yellow"))
            return
        print(self.pal.paint("  WARNING: no terminal, and no file could be written, to take the %s: it is printed "
                             "here, so remove it from any log this output reaches." % what, "red"))
        print(text)

    def _write_secret_file(self, label, text):
        """Write a one-time secret (`text`, colour codes removed) to a new file of its own in this user's DockVault
        application-data folder (beside the default backups, never in the checkout, which the image build copies
        and git tracks): created mode 600, never over a file already there, the folder made 0700 if the tool makes
        it. Returns its path, or None when it cannot be written."""
        folder = os.path.join(os.path.dirname(_app_data_backup_root()), "secrets")
        try:
            if not os.path.isdir(folder):
                os.makedirs(os.path.dirname(folder), exist_ok=True)
                try:
                    os.mkdir(folder, 0o700)
                    if os.name != "nt":
                        os.chmod(folder, 0o700)
                except FileExistsError:
                    pass
            plain = re.sub("\x1b\\[[0-9;]*m", "", text).strip("\n") + "\n"
            base = os.path.join(folder, "%s-%s" % (label, _timestamp()))
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            for n in range(100):
                path = base if n == 0 else "%s-%d" % (base, n)
                try:
                    fd = os.open(path, flags, 0o600)
                except FileExistsError:
                    continue
                try:
                    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                        f.write(plain)
                        f.flush()
                        os.fsync(f.fileno())
                except OSError:
                    try:
                        os.remove(path)          # no part of a secret is left in a file nobody was told of
                    except OSError:
                        pass
                    raise
                tighten_secret_file(path)
                return path
        except OSError:
            return None
        return None

    def _show_recovery_key(self, dek, args):
        key = dek.decode("ascii") if isinstance(dek, (bytes, bytearray)) else str(dek)
        pal = self.pal
        out = getattr(args, "recovery_out", None)
        # --recovery-out is written first, so that nothing says the key is there before it is. A file that cannot
        # be written is said so, and the key goes where it would go without one.
        written = False
        if out:
            try:
                self._atomic_write_secret(out, key + "\n")
                written = True
            except OSError as exc:
                print(pal.paint("  WARNING: could not write the recovery key to %s (%s): it is shown as without "
                                "--recovery-out instead." % (out, exc), "red"))
        # Show the key + its guidance on the controlling terminal only (see _emit_secret); with no terminal, in
        # --recovery-out when it was written, else in a file of its own.
        self._emit_secret("\n".join([
            pal.paint("\n  ===== CREDENTIAL RECOVERY KEY (shown once) =====", "bold", "yellow"),
            "    " + pal.paint(key, "bold"),
            pal.paint("  Save this in a password manager. It unlocks .env if you forget the passphrase.\n"
                      "  It does NOT recover vault files or deployments. If you lose BOTH this key and the\n"
                      "  passphrase, every stored file becomes permanently unrecoverable.", "yellow"),
        ]), label="recovery-key", kept_in=out if written else None)
        if written:
            print(pal.paint("  Also written to %s - move it OFF this host, then delete it here." % out,
                            "yellow"))

    def lock(self, args=None):
        """Seal .env into an encrypted .env.enc (verify-before-destroy), then remove the plaintext .env."""
        pal = self.pal
        fernet = self._require_fernet()
        env_path, enc_path = self._env_path(), self._env_lock_path()
        if not os.path.exists(env_path):
            if os.path.exists(enc_path):
                print(pal.paint("  .env is already locked (only .env.enc is present).", "yellow"))
                return
            print(pal.paint("  No .env to lock - run 'setup' first.", "red"))
            raise SystemExit(2)
        with open(env_path, "rb") as f:
            env_bytes = f.read()
        reuse = os.path.exists(enc_path)
        dek = None
        if reuse:
            # Re-locking an edited .env: unwrap the EXISTING data key with the passphrase so the
            # recovery key stays stable across locks.
            passphrase = self._read_passphrase(args, confirm=False)
            try:
                with open(enc_path, encoding="utf-8") as f:
                    sealed_bytes, dek = env_lock_open(fernet, f.read(), passphrase=passphrase)
            except EnvLockError as exc:
                print(pal.paint("  Cannot re-lock: %s." % exc, "red"))
                raise SystemExit(2)
            # Re-locking writes over .env.enc, so it may only seal the same set's .env again (an edited one).
            # The .env of another set (another VAULT_VOLUME_PREFIX, or another ENCRYPTION_KEY) sealed over it
            # would leave the sealed set's ENCRYPTION_KEY nowhere: its volumes could never be read again.
            other = sealed_set_differs(sealed_bytes, env_bytes)
            if other:
                print(pal.paint(
                    "  Refusing to lock: .env.enc holds the .env of another set (%s), and sealing this .env over it "
                    "would lose that set's keys. Keep it first: move .env.enc somewhere safe (it still opens with "
                    "its passphrase or recovery key), then run lock again to seal this .env under a passphrase of "
                    "its own. Nothing changed." % other, "red"))
                raise SystemExit(2)
        else:
            print(pal.paint(
                "\n  Set an unlock passphrase for .env. You will also get a one-time recovery key.\n"
                "  Lose BOTH and every stored file is permanently unrecoverable - back them up.",
                "yellow"))
            passphrase = self._read_passphrase(args, confirm=True)
        import datetime as _dt
        now_iso = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
        enc_text, dek = env_lock_seal(fernet, env_bytes, passphrase, dek=dek,
                                      hint=getattr(args, "hint", None), now_iso=now_iso)
        self._atomic_write_secret(enc_path, enc_text)
        # Verify-before-destroy: the freshly written .env.enc must unlock (by passphrase) back to the
        # exact bytes we started with, or we leave BOTH files intact and abort loud.
        try:
            with open(enc_path, encoding="utf-8") as f:
                check_bytes, _ = env_lock_open(fernet, f.read(), passphrase=passphrase)
        except EnvLockError as exc:
            print(pal.paint("  Verification of the new .env.enc FAILED (%s); .env left intact." % exc, "red"))
            raise SystemExit(1)
        if check_bytes != env_bytes:
            print(pal.paint("  Verification mismatch; .env left intact, nothing removed.", "red"))
            raise SystemExit(1)
        os.remove(env_path)
        print(pal.paint("  Locked: .env -> .env.enc (plaintext .env removed).", "green"))
        # Sealing .env seals ONLY .env. Any .env.<prefix> archives set aside by 'new set' / repoint /
        # remove are still plaintext on disk and each holds an ENCRYPTION_KEY -- surface them so they
        # are not overlooked (lock does not manage them).
        archives = self._env_archives()
        if archives:
            print(pal.paint(
                "  WARNING: %d plaintext .env archive(s) are NOT sealed by lock and still hold an\n"
                "  ENCRYPTION_KEY (%s). Back them up off this host, then delete them."
                % (len(archives), ", ".join(os.path.basename(a) for a in archives)), "red"))
        # The old AUDIT_CHAIN_KEY a key change keeps until the audit log's chain has moved off it stays in plain
        # text too: while the change is not finished, the chain is still under that key.
        kept = kept_chain_key_files(self.root)
        if kept:
            print(pal.paint(
                "  WARNING: %d old AUDIT_CHAIN_KEY file(s) are NOT sealed by lock (%s). Each holds, in plain text,\n"
                "  a key an audit log's chain may still be under, as a change of AUDIT_CHAIN_KEY is not finished:\n"
                "  finish it (unlock, then python dockvault.py audit rekey --old-key-file <file>) and remove the file\n"
                "  once the rekey says its key is no longer needed, or keep the file off this host until then."
                % (len(kept), ", ".join(os.path.basename(k) for k in kept)), "red"))
        # Sealing .env does NOT clear the copy Docker already baked into a running/stopped container's
        # on-disk config -- point the operator at the command that does.
        if container_exists(DB_CONTAINER):
            print(pal.paint("  NOTE: the deployment's containers still exist, so their secrets are STILL "
                            "in Docker's on-disk config even though .env is sealed - run 'down' to remove "
                            "the containers (or 'down --lock' to do both at once).", "yellow"))
        if not reuse:
            self._show_recovery_key(dek, args)

    def unlock(self, args=None):
        """Open .env.enc back into a plaintext .env."""
        pal = self.pal
        fernet = self._require_fernet()
        enc_path, env_path = self._env_lock_path(), self._env_path()
        if not os.path.exists(enc_path):
            print(pal.paint("  No .env.enc to unlock.", "red"))
            raise SystemExit(2)
        with open(enc_path, encoding="utf-8") as f:
            enc_text = f.read()
        use_recovery = getattr(args, "recovery_key", False) or getattr(args, "recovery_key_file", None)
        try:
            if use_recovery:
                env_bytes, dek = env_lock_open(fernet, enc_text, recovery_key=self._read_recovery_key(args))
            else:
                env_bytes, dek = env_lock_open(fernet, enc_text,
                                               passphrase=self._read_passphrase(args, confirm=False))
        except EnvLockError as exc:
            print(pal.paint("  Unlock failed: %s." % exc, "red"))
            raise SystemExit(2)
        if getattr(args, "show_recovery_key", False):
            self._show_recovery_key(dek, args)
            return
        kept = None
        if os.path.exists(env_path):
            if not getattr(args, "force", False):
                print(pal.paint("  .env already exists; refusing to overwrite. Re-run with --force to replace it.",
                                "red"))
                raise SystemExit(2)
            kept = self._keep_env_before_unlock(env_bytes)
            if kept is False:
                print(pal.paint("  .env already reads as the sealed one; nothing was changed.", "green"))
                return
        self._atomic_write_secret(env_path, env_bytes)
        print(pal.paint("  Unlocked: .env.enc -> .env.", "green"))
        if kept:
            prefix = volume_prefix(parse_env(env_bytes.decode("utf-8", "replace")))
            arg = '"%s"' % kept if any(c.isspace() for c in kept) else kept
            print(pal.paint("  The .env it replaced is kept as %s. To go back to it: python dockvault.py volumes "
                            "--non-interactive --action repoint --target-prefix %s --env-source %s"
                            % (kept, prefix, arg), "yellow"))

    def _keep_env_before_unlock(self, env_bytes):
        """`unlock --force` writes the sealed .env (`env_bytes`) over the .env there, which may be the only copy of
        its set's keys. Returns False when that .env already reads as the sealed one (nothing to write). Refuses, with
        nothing changed, when it is another set's (another VAULT_VOLUME_PREFIX or ENCRYPTION_KEY: sealed_set_differs),
        whose keys the overwrite would leave nowhere. Otherwise (the same set's .env, edited since the lock) keeps it
        first as .env.<prefix>[.n] (_keep_env_copy) and returns the copy's path. A .env that cannot be read or kept
        is not replaced."""
        env_path = self._env_path()
        try:
            with open(env_path, "rb") as f:
                current = f.read()
        except OSError as exc:
            self._fail("could not read the current .env (%s), so it was not replaced. Nothing changed." % exc)
        if current == bytes(env_bytes):
            return False
        prefix = volume_prefix(parse_env(current.decode("utf-8", "replace")))
        label = prefix if valid_volume_prefix(prefix) else "before-unlock"
        other = sealed_set_differs(env_bytes, current)
        if other:
            aside = next(env_copy_names(self.root, label))
            self._fail(".env.enc holds the .env of another set (%s): unlocking it over .env would leave the keys of the "
                       "set .env opens (its ENCRYPTION_KEY and database password) nowhere. Nothing changed. To switch "
                       "this host to the sealed set, first move .env to %s (a name Volumes' repoint finds it by), "
                       "then run unlock again; to come back to set '%s' later: python dockvault.py volumes "
                       "--non-interactive --action repoint --target-prefix %s --env-source %s. If .env.enc is an old "
                       "seal nobody needs, move it somewhere safe instead and lock this .env under a passphrase of "
                       "its own." % (other, aside, prefix, prefix, aside))
        try:
            kept = self._keep_env_copy(label, current)
        except OSError as exc:
            self._fail("could not keep the current .env as %s (%s), so it was not replaced. Nothing changed."
                       % (getattr(exc, "kept_as", None) or next(env_copy_names(self.root, label)), exc))
        print(self.pal.paint("  Kept the current .env (set '%s') as %s before unlocking over it." % (prefix, kept),
                             "cyan"))
        return kept

    def change_passphrase(self, args=None):
        """Set a NEW unlock passphrase for .env.enc, keeping the same data key and recovery key.
        Authenticate with the CURRENT passphrase OR the recovery key (so a forgotten passphrase can be
        replaced with the recovery key without ever exposing a new recovery key)."""
        pal = self.pal
        fernet = self._require_fernet()
        enc_path = self._env_lock_path()
        if not os.path.exists(enc_path):
            print(pal.paint("  No .env.enc to re-key - run 'lock' first.", "red"))
            raise SystemExit(2)
        with open(enc_path, encoding="utf-8") as f:
            enc_text = f.read()
        use_recovery = getattr(args, "recovery_key", False) or getattr(args, "recovery_key_file", None)
        try:
            if use_recovery:
                env_bytes, dek = env_lock_open(fernet, enc_text, recovery_key=self._read_recovery_key(args))
            else:
                env_bytes, dek = env_lock_open(fernet, enc_text,
                                               passphrase=self._read_passphrase(args, confirm=False))
        except EnvLockError as exc:
            print(pal.paint("  Cannot change the passphrase: %s." % exc, "red"))
            raise SystemExit(2)
        new_pass = self._read_passphrase(args, confirm=True, prefix="new_passphrase",
                                         label="New unlock passphrase")
        # Re-seal the SAME data key (and thus the same recovery key) under the new passphrase; the
        # payload is re-encrypted under that data key (harmless - the recovery key still opens it).
        new_enc, _ = env_lock_seal(fernet, env_bytes, new_pass, dek=dek)
        # Verify the new file opens with the NEW passphrase before it replaces the old one.
        try:
            check, _ = env_lock_open(fernet, new_enc, passphrase=new_pass)
        except EnvLockError as exc:
            print(pal.paint("  Verification failed (%s); .env.enc left unchanged." % exc, "red"))
            raise SystemExit(1)
        if check != env_bytes:
            print(pal.paint("  Verification mismatch; .env.enc left unchanged.", "red"))
            raise SystemExit(1)
        self._atomic_write_secret(enc_path, new_enc)
        print(pal.paint("  Passphrase changed. The recovery key is unchanged.", "green"))

    # --- deployment lifecycle ---------------------------------------------------------------
    def start(self, args=None):
        """Bring the deployment up (health-checked). If .env is sealed, unlock it inline first."""
        pal = self.pal
        if self._is_locked():
            print(pal.paint("  .env is locked; unlock it to start.", "yellow"))
            self.unlock(args)
        if not os.path.exists(self._env_path()):
            print(pal.paint("  No .env - run 'setup' first (or 'unlock' if it is sealed).", "red"))
            raise SystemExit(2)
        self._refuse_incomplete_restore("start")
        ok, msg = docker_available()
        if not ok:
            print(pal.paint("  Docker is not available: %s" % msg, "red"))
            raise SystemExit(2)
        profiles = self._load_env().get("COMPOSE_PROFILES", "combined")
        print(pal.paint("  Starting the deployment ...", "cyan"))
        if not self._start_secure_stack():
            self._tail_logs(self._web_service(profiles))
            print(pal.paint("  Start failed - the last log lines are above.", "red"))
            raise SystemExit(1)
        if not self._wait_secure_healthy(profiles):
            self._tail_logs(self._web_service(profiles))
            print(pal.paint("  Started, but the vault did NOT report healthy - logs above.", "red"))
            raise SystemExit(1)
        print(pal.paint("  Up and healthy.", "green"))
        self._print_status(profiles)

    def _tear_down_containers(self):
        """`compose down --remove-orphans` (removes containers, keeps data volumes). Removing the
        containers also removes Docker's on-disk copy of their environment, so the deployment's secrets
        stop sitting in config.v2.json / `docker inspect`. Returns True if it ran, False when there was
        nothing to address (no .env). Raises SystemExit on docker-unavailable or a compose failure."""
        pal = self.pal
        ok, _ = docker_available()
        if not ok:
            print(pal.paint("  Docker is not available.", "red"))
            raise SystemExit(2)
        if not os.path.exists(self._env_path()):
            # compose needs .env for the ${VAR:?} interpolation even to address the stack.
            print(pal.paint("  .env is not present (locked?); nothing to remove by this tool.", "yellow"))
            return False
        try:
            self._run_dc("down", "--remove-orphans", capture=False, timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            print(pal.paint("  Down failed: %s" % exc, "red"))
            raise SystemExit(1)
        return True

    def _confirm_remove(self, args):
        """Confirm removing the containers. `--yes` bypasses. Otherwise prompt, defaulting to NO -- so a
        piped/EOF stdin (automation) declines rather than silently removing containers; a script must be
        explicit via `--yes`. (A programmatic `non_interactive` arg also refuses outright, with a clear
        message.)"""
        if getattr(args, "yes", False):
            return True
        if args is not None and getattr(args, "non_interactive", False):
            print(self.pal.paint("  Refusing to remove containers non-interactively without --yes.",
                                  "red"))
            return False
        return confirm("Remove the deployment's containers now? (data volumes are kept)",
                       self.pal, default=False)

    def stop(self, args=None):
        """Stop the deployment but KEEP its (stopped) containers, for a faster restart and to retain
        `docker logs` (`docker compose stop`). WARNING: a stopped container STILL holds the deployment's
        secrets in Docker's on-disk config (config.v2.json) and via `docker inspect`, so this does NOT
        remove them from disk -- run `down` for that (or `down --lock` to also seal `.env`)."""
        pal = self.pal
        ok, _ = docker_available()
        if not ok:
            print(pal.paint("  Docker is not available.", "red"))
            raise SystemExit(2)
        if not os.path.exists(self._env_path()):
            print(pal.paint("  .env is not present (locked?); nothing to stop by this tool.", "yellow"))
            return
        print(pal.paint("  Stopping the deployment, keeping its containers (data volumes kept) ...",
                        "cyan"))
        try:
            self._run_dc("stop", capture=False, timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            print(pal.paint("  Stop failed: %s" % exc, "red"))
            raise SystemExit(1)
        print(pal.paint("  Stopped (containers kept). WARNING: the stopped containers STILL hold the "
                        "deployment secrets in Docker's on-disk config - run 'down' to remove them "
                        "(or 'down --lock' to also seal .env).", "yellow"))

    def down(self, args=None):
        """Stop the deployment and REMOVE its containers (`docker compose down`, never `-v` - data
        volumes are kept), which also clears Docker's on-disk copy of their secrets. Confirms first (it
        removes the running containers); `--yes` skips the prompt, and a piped/non-interactive stdin
        declines unless `--yes` is given. `--lock` also seals `.env` into `.env.enc` afterwards, so no
        plaintext secret is left at rest anywhere."""
        pal = self.pal
        if os.path.exists(self._env_path()):
            # Check Docker BEFORE prompting, so we don't ask + announce a removal we then can't do.
            ok, _ = docker_available()
            if not ok:
                print(pal.paint("  Docker is not available.", "red"))
                raise SystemExit(2)
            if not self._confirm_remove(args):
                print(pal.paint("  Cancelled - nothing was removed.", "yellow"))
                return
            print(pal.paint("  Stopping the deployment and removing its containers (data volumes are "
                            "kept) ...", "cyan"))
            self._tear_down_containers()
            print(pal.paint("  Stopped and removed - the deployment's secrets are no longer held in "
                            "Docker's container config.", "green"))
        else:
            # Nothing this tool can address; still allow a --lock to seal a stray plaintext .env below.
            print(pal.paint("  .env is not present (locked?); nothing to remove by this tool.", "yellow"))
        if getattr(args, "lock", False) and os.path.exists(self._env_path()):
            self.lock(args)

    def restart(self, args=None):
        """Recreate the deployment (compose down + start, health-checked) so a changed .env takes
        effect. Data volumes are untouched. No prompt: this is an explicit in-place action, not the
        standalone `down`. A container-log rotation Docker would refuse stops it before anything is
        taken down, and so does a published release image that is neither here nor can be pulled: it is
        made present BEFORE the containers are removed, so a host without the registry (offline, an
        outage, a rate limit) keeps the deployment it has rather than being left with nothing running. A deployment
        that builds from source is built from the checkout as it is, BEFORE anything is taken down, for the same
        reason: a build that fails (no network for the base image or the packages, a broken checkout) leaves the
        deployment running as it is. A checkout older than the version the deployment has run is refused before
        that (_refuse_older_build): its image would not start on the newer data."""
        if not self._container_logs_readable():
            raise SystemExit(1)
        if os.path.exists(self._env_path()):
            self._refuse_incomplete_restore("restart")
            if uses_release_image(self._load_env()):
                if not self._ensure_release_image():
                    print(self.pal.paint("  Nothing was taken down: the deployment keeps running as it is.",
                                         "yellow"))
                    raise SystemExit(1)
            else:
                self._refuse_older_build("restart")
                if not self._build_checkout():
                    print(self.pal.paint("  Nothing was taken down: the deployment keeps running as it is.",
                                         "yellow"))
                    raise SystemExit(1)
        self._tear_down_containers()
        self.start(args)

    def _build_checkout(self):
        """`docker compose build`: the images of a deployment that builds from source, built from the checkout as it
        is (start's `up --build` then finds them built). True when the build succeeded."""
        print(self.pal.paint("  Building this checkout before anything is taken down ...", "cyan"))
        try:
            r = self._run_dc("build", capture=False, timeout=1800)
        except (OSError, subprocess.SubprocessError) as exc:
            print(self.pal.paint("  docker compose build failed: %s" % exc, "red"))
            return False
        if getattr(r, "returncode", 1) != 0:
            print(self.pal.paint("  The build failed (Docker's output is above).", "red"))
            return False
        return True

    def _refuse_older_build(self, command):
        """Stop `command`, which builds this checkout and starts it, when this checkout's VERSION is older than the
        version the deployment has run (_running_version): the older code would go back over data a newer version
        wrote (an image from 0.33.1 on refuses to start on it, and the deployment would be left with nothing
        running). Going back is update's to do, with its checks. Nothing was built or taken down."""
        version = read_version_file(self.root)
        if not parse_semver(version):
            return
        running, source = self._running_version()
        if parse_semver(running) and parse_semver(version) < parse_semver(running):
            self._fail("%s would build and start this checkout at %s, which is older than %s, the version this "
                       "deployment has run (from %s). It does not go back to an older version: python dockvault.py "
                       "update --tag v%s does, after it checks what the data holds that %s cannot read. Nothing was "
                       "built or taken down." % (command, version, running, source, version.lstrip("vV"), version))

    def status(self, args=None):
        """Show credential lock state + container/health/port status (read-only)."""
        self._print_status(self._load_env().get("COMPOSE_PROFILES", "combined"))

    def _print_status(self, profiles):
        pal = self.pal
        if self._is_locked():
            print(pal.paint("  Credentials: LOCKED (.env.enc present; run 'unlock' to open)", "yellow"))
        elif os.path.exists(self._env_lock_path()):
            print(pal.paint("  Credentials: unlocked (.env present; a sealed .env.enc is also on disk)",
                            "green"))
        else:
            print(pal.paint("  Credentials: plaintext .env (not locked)", "grey"))
        archives = self._env_archives()
        if archives:
            print(pal.paint("  Note: %d plaintext .env archive(s) on disk (%s) - each holds an "
                            "ENCRYPTION_KEY and is NOT sealed by 'lock'."
                            % (len(archives), ", ".join(os.path.basename(a) for a in archives)), "yellow"))
        ok, _ = docker_available()
        if not ok:
            print(pal.paint("  Docker is not available.", "yellow"))
            return
        if not os.path.exists(self._env_path()):
            if container_exists(DB_CONTAINER):
                # 'down' needs .env to address the stack, so while sealed it cannot run: guide the
                # operator to unlock first, then 'down' (which removes the containers + their secrets;
                # 'stop' keeps them).
                print(pal.paint("  WARNING: the deployment's containers still exist, so its secrets are "
                                "STILL in Docker's on-disk config even though .env is sealed - run "
                                "'unlock' then 'down' to remove them.", "red"))
            print(pal.paint("  (containers not listed while .env is locked - unlock first)", "yellow"))
            return
        try:
            self._run_dc("ps", capture=False, timeout=30)
        except (OSError, subprocess.SubprocessError):
            print(pal.paint("  (could not list containers)", "yellow"))

    def setup(self, args=None):
        """Configure + start the standalone HTTPS vault: author (or reuse) .env, provision a TLS
        certificate (self-signed / Let's Encrypt / bring-your-own, with rootless-cert-perm handling),
        then start the secure stack — pulling the published release image or building this
        checkout, per the .env's DOCKVAULT_IMAGE (see _resolve_setup_image). Refused while .env is sealed by
        `lock` (_refuse_while_locked)."""
        pal = self.pal
        self._refuse_while_locked("setup")
        self._read_cli_admin_password(args)
        no_start = bool(args and getattr(args, "no_start", False))
        if not no_start:
            self._refuse_incomplete_restore("setup")
        # "Start" rather than "Build + start": the deployment may be pulling a published release
        # rather than building, and for a fresh install the choice is not made until Settings.
        steps = ["Settings", "Write .env", "Certificate"] + ([] if no_start else ["Start", "Health check"])
        tracker = Steps(steps, pal)

        env_path = self._env_path()
        existing = parse_env(open(env_path, encoding="utf-8").read()) if os.path.exists(env_path) else {}
        reusing = False
        summary = {}
        tracker.show()

        if existing:
            ok, missing = env_is_reusable(existing)
            if not ok:
                self._fail(".env exists but is missing %s - it looks incomplete. Fix it, or run "
                           "Reset (destroys data) and start fresh." % ", ".join(missing))
            reusing = True
            print(pal.paint("  Reusing the existing .env (keeping ENCRYPTION_KEY + all data).", "green"))
            # Migrate a supported legacy profile in place and reject ambiguous/unknown selections
            # before changing any deployment state.
            try:
                migrated = self._normalize_compose_profile()
            except (OSError, ValueError) as exc:
                self._fail(str(exc))
            # Adopt a pre-label deployment: pin DEPLOYMENT_ID=default so this .env names the bundle
            # its (unlabelled) volumes are grouped under. Additive + idempotent - no data move, and a
            # second run keeps whatever id is already there.
            if not (existing.get("DEPLOYMENT_ID") or "").strip():
                self._set_env_key(env_path, "DEPLOYMENT_ID", "default")
            # Honour an explicit --admin-password/--admin-username on a reuse: it seeds the FIRST admin
            # of a set that is not bootstrapped yet (e.g. a fresh set just authored by the Volumes
            # menu, whose .env carries an auto-generated placeholder password). On an already-
            # bootstrapped deployment the seed is marker-guarded, so this is inert and the value is
            # dropped again after a healthy boot. Not passed -> the existing .env is left untouched.
            existing = self._apply_cli_admin_overrides(env_path, existing, args)
            summary = {"server_name": existing.get("SERVER_NAME") or existing.get("ALLOWED_HOSTS") or "",
                       "admin_username": existing.get("ADMIN_USERNAME") or "admin",
                       "compose_profiles": migrated,
                       "run_sftp": (existing.get("RUN_SFTP") or "").strip() in ("1", "true", "yes", "on"),
                       "web_host_port": _port_or(existing.get("WEB_HOST_PORT"), 443),
                       "sftp_host_port": _port_or(existing.get("SFTP_HOST_PORT"), 2322)}
        else:
            cfg = self._collect_setup_config(args)
            tracker.advance(); tracker.show()          # -> Write .env
            if write_env(env_path, build_env_lines(cfg)):
                print(pal.paint("  Wrote .env (restricted to your user).", "green"))
            else:
                print(pal.paint("  Wrote .env - WARNING: could not restrict its permissions; secure it "
                                "yourself (it holds ENCRYPTION_KEY).", "yellow"))
            summary = {"server_name": cfg["server_name"], "admin_username": cfg["admin_username"],
                       "compose_profiles": cfg["compose_profiles"], "run_sftp": cfg["run_sftp"],
                       "web_host_port": cfg["web_host_port"], "sftp_host_port": cfg["sftp_host_port"],
                       "admin_password": cfg["admin_password"] if cfg["_generated_pw"] else None}

        # ---- certificate (self-signed; keep an existing pair) ----
        while tracker.current < steps.index("Certificate"):
            tracker.advance()
        tracker.show()
        cert_dir = self._certs_dir()
        if _cert_pair_present(cert_dir):
            print(pal.paint("  Certificates already present - keeping them (repairing ownership).", "green"))
            # A kept Let's Encrypt certificate keeps the renewal hook an earlier version wrote for it: brought to the
            # one this version writes (as root), or the operator is told how.
            outcome, said = refresh_renewal_hook(self.root, cert_dir,
                                                 self._web_service(summary.get("compose_profiles")))
            if said:
                print(pal.paint("  " + said + ".", "green" if outcome == "rewritten" else "yellow"))
        else:
            server = summary.get("server_name") or "localhost"
            if not validate_server_name(server):   # re-validate a reused .env's SERVER_NAME before it hits openssl
                print(pal.paint("  SERVER_NAME in .env looks invalid; using 'localhost' for the cert.", "yellow"))
                server = "localhost"
            mode, email, cpath, kpath = self._resolve_cert_cfg(args)
            svc = self._web_service(summary.get("compose_profiles"))
            if mode == "byo":
                if not cpath or not kpath:
                    self._fail("bring-your-own certs need --cert-path and --key-path")
                ok, msg = install_byo_cert(cert_dir, cpath, kpath)
            elif mode == "letsencrypt":
                ok, msg = obtain_letsencrypt_cert(cert_dir, server, email, self.root, svc)
            else:
                ok, msg = generate_self_signed_cert(cert_dir, server)
            if not ok:
                self._fail(msg)
            print(pal.paint("  " + msg + ".", "green"))
        # Lock the key file (icacls/chmod), then make it readable by the container uid (POSIX chown;
        # repairs a reused or root-owned pair too).
        key = os.path.join(cert_dir, "key.pem")
        if os.path.exists(key) and not tighten_secret_file(key) and not _key_already_private(key):
            print(pal.paint("  WARNING: could not restrict the TLS key's permissions.", "yellow"))
        owner_ok, owner_msg = apply_cert_owner(cert_dir)
        if owner_msg:
            print(pal.paint("  " + owner_msg, "green" if owner_ok else "yellow"))
        if no_start:
            print(pal.paint("\n  Setup done (--no-start). Start later with:  python dockvault.py setup\n", "cyan"))
            return

        # ---- build + start + health ----
        ok, msg = docker_available()
        if not ok:
            self._fail(msg)
        self._note_host_log_driver()
        # PROVE the container can read the TLS pair before starting anything. Host permissions do not
        # predict the container's view, and getting this wrong costs an endless restart loop whose
        # only symptom is uvicorn's "PermissionError: [Errno 13]" buried in the logs.
        if cert_readable_by_app_uid(cert_dir) is False:
            self._fail("the vault container (uid %d) cannot read certs/key.pem, so it could never "
                       "serve HTTPS. Delete the certs/ directory and re-run setup to regenerate a "
                       "readable pair." % APP_UID)
        # Guardrail: if we're (re)starting on an EXISTING data volume, the current .env's DB password
        # MUST authenticate against it, or the app would loop on a Postgres auth error. Fail closed
        # with a clear diagnosis (the reported "wrong password after re-setup" footgun).
        env_now = parse_env(open(env_path, encoding="utf-8").read()) if os.path.exists(env_path) else {}
        interactive = not (args and getattr(args, "non_interactive", False))
        # A .env authored by THIS run (a fresh install, not a reuse) that has never touched data is a
        # throwaway - tell the guard so its 'deploy a new set' option discards it instead of archiving
        # a pointless plaintext-secret file.
        if not self._guard_db_secret(env_now, interactive=interactive, env_is_fresh=not reusing):
            raise SystemExit(1)   # the guard already printed the diagnosis + recovery paths
        # The set setup starts is the one that .env names now: pointed at another set's .env by the guard's menu, it
        # may be a set whose restore did not finish, which the check at setup's start never saw.
        self._refuse_incomplete_restore("setup", notes=False)
        # The interactive guard can install a different .env or author a fresh set. Re-read it,
        # persist any supported legacy profile, and refresh every profile/port value used below.
        try:
            profiles = self._normalize_compose_profile()
        except (OSError, ValueError) as exc:
            self._fail(str(exc))
        env_now = self._load_env()
        generated_password = summary.get("admin_password")
        summary.update({
            "server_name": env_now.get("SERVER_NAME") or env_now.get("ALLOWED_HOSTS") or "",
            "admin_username": env_now.get("ADMIN_USERNAME") or "admin",
            "compose_profiles": profiles,
            "run_sftp": (
                profiles == "split"
                or (env_now.get("RUN_SFTP") or "").strip().lower() in ("1", "true", "yes", "on")
            ),
            "web_host_port": _port_or(env_now.get("WEB_HOST_PORT"), 443),
            "sftp_host_port": _port_or(env_now.get("SFTP_HOST_PORT"), 2322),
            "admin_password": (
                generated_password
                if generated_password and env_now.get("ADMIN_PASSWORD") == generated_password
                else None
            ),
        })
        # Port preflight: warn (don't block) if the chosen web port is held by something ELSE.
        # A re-run over a running deployment finds its OWN container on the port - the one compose
        # is about to recreate - and warning there is just noise the operator has to second-guess.
        web_port = summary.get("web_host_port") or 443
        if not port_free(web_port) and not self._port_is_ours(web_port):
            print(pal.paint("  WARNING: host port %d is already in use; the web container may fail to bind "
                            "it. Free it first (e.g. sudo ss -ltnp 'sport = :%d')." % (web_port, web_port), "yellow"))
        # Re-run only: confirm/switch the image mode (a fresh install already chose in Settings, via
        # _resolve_setup_image). This is what lets a re-run BUILD freshly-pulled source instead of
        # silently re-pulling the release the first install pinned.
        if reusing:
            self._resolve_rerun_image_source(env_path, args, interactive)
        tracker.advance(); tracker.show()               # -> Start
        if not self._start_secure_stack():
            shown = self._tail_logs(self._web_service(profiles))
            self._fail("the stack did not start - %s." % ("the last log lines are above" if shown
                       else "see the docker output above"))
        tracker.advance(); tracker.show()               # -> Health check
        healthy = self._wait_secure_healthy(profiles)
        logs_shown = False if healthy else self._tail_logs(self._web_service(profiles))
        self._print_setup_summary(summary, healthy, logs_shown)
        # Once the deployment is up and the admin is bootstrapped, ADMIN_PASSWORD is spent: drop it
        # from the host .env so the initial admin password is not retained in plaintext at rest. The
        # app scrubs its own in-container copy; this closes the on-disk copy. Fail-safe (keeps the
        # value on any doubt) and never breaks a healthy setup.
        if healthy:
            self._strip_spent_admin_password(env_path, env_now)
        # NOTE: the coupling stamp is written ONLY where a pairing has been PROVEN - after a
        # successful psql auth probe in _verify_env_against_volume. Stamping here would be
        # fail-OPEN: the interactive guard can rewrite .env mid-run (choosing "deploy a NEW set"
        # archives the current .env and authors another), so the env read before the guard may name
        # a volume it was never proven to open - and a later run would then trust that stamp.

    @staticmethod
    def _web_service(profiles):
        """The service that serves the web/API half in the active deployment mode."""
        return "vault-api" if profiles == "split" else "vault"

    def _port_is_ours(self, port, ps_fn=None):
        """True if `port` is held solely by THIS deployment's own containers.

        A setup re-run over a live deployment always finds the web port busy - held by the very
        container `docker compose up` is about to recreate on that same port. Warning about it
        sends the operator hunting for a conflict that does not exist. Answers False when docker
        cannot be asked, or when anything outside the deployment is on the port, so a REAL
        conflict is still reported."""
        names = (ps_fn or containers_publishing)(port)
        if not names:                       # None = could not ask; [] = nothing docker knows of
            return False
        return all(name in self.OWN_CONTAINERS for name in names)

    def _resolve_setup_image(self, args, interactive):
        """Decide whether a FRESH install runs the published release image or builds this checkout.
        Returns the DOCKVAULT_IMAGE value to author, or '' to leave it unset (the compose default,
        i.e. a local build). Only for a NEW .env; a re-run over an existing .env resolves its image
        mode in _resolve_rerun_image_source (keep / build-this-checkout / pull-release).

        The two modes default differently, deliberately. An interactive operator is installing the
        product and should get the release CI built, scanned and attested — no build toolchain, no
        wait. A --non-interactive run is automation reproducing a checkout (CI, a provisioning
        script), where pulling a DIFFERENT artifact than the one checked out would make the run
        meaningless; it builds unless explicitly asked for a release."""
        pal = self.pal
        choice = ((getattr(args, "image_source", None) if args else None) or "").strip().lower()
        candidate = release_image_ref(read_version_file(self.root))
        if interactive and not choice:
            print(pal.paint("\n  Container image:", "cyan"))
            print("    1) Published release - pull %s (no build toolchain needed; fastest)"
                  % (candidate or "the matching GHCR release"))
            print("    2) Build from source - build this checkout's Dockerfile")
            choice = {"2": "build"}.get(ask("Choose 1/2", pal, "1").strip(), "release")
        if (choice or "build") != "release":
            return ""
        if not candidate:
            print(pal.paint("  No usable VERSION to match a published release; building from source "
                            "instead.", "yellow"))
            return ""
        # A checkout ahead of the last release (plain `main`) names a tag that was never published,
        # so the pull would fail AFTER .env was authored. Ask GitHub first and fall back quietly.
        # An unreachable API returns [] — proceed, and let the pull report the real failure.
        tags = fetch_release_tags()
        if tags and candidate.rsplit(":", 1)[1] not in tags:
            print(pal.paint("  %s is not published (this checkout is ahead of the latest release); "
                            "building from source instead." % candidate, "yellow"))
            return ""
        return candidate

    def _collect_setup_config(self, args):
        """Resolve the full setup config (secrets + flags) from args (unattended) and/or interactive
        prompts. Generates fresh secrets. Raises SystemExit on an invalid value."""
        pal = self.pal
        interactive = not (args and getattr(args, "non_interactive", False))

        def a(name, default=None):
            return getattr(args, name, default) if args else default

        server = a("server_name")
        if interactive and not server:
            server = ask("Public DNS name or IP clients will use (e.g. vault.example.com)", pal)
        if not validate_server_name(server or ""):
            self._fail("invalid/missing server name (letters, digits, dots, hyphens only): %r" % server)

        admin_user = a("admin_username") or (ask("Admin username", pal, "admin") if interactive else "admin")
        why = admin_username_problem(admin_user)
        while why and interactive and not a("admin_username"):
            print(pal.paint("  The admin username %s." % why, "red"))
            admin_user = ask("Admin username", pal, "admin")
            why = admin_username_problem(admin_user)
        if why:
            self._fail("admin username %r %s" % (admin_user, why))
        admin_email = a("admin_email") or (ask("Admin email", pal, "admin@example.com") if interactive else "admin@example.com")
        admin_pw, generated = a("admin_password"), False
        if interactive and not admin_pw:
            while True:
                admin_pw = ask_secret("Admin password (blank = auto-generate a strong one)", pal)
                if not admin_pw:
                    admin_pw, generated = gen_hex(12), True
                    break
                prob = admin_password_problem(admin_pw, "production")
                if prob:
                    print(pal.paint("  the password %s" % prob, "red"))
                    continue
                if ask_secret("Confirm admin password", pal) != admin_pw:
                    print(pal.paint("  passwords do not match", "red"))
                    continue
                break
        elif not admin_pw:
            admin_pw, generated = gen_hex(12), True
        prob = admin_password_problem(admin_pw, "production")
        if prob:
            self._fail("admin password %s" % prob)

        if interactive:
            enable_sftp = confirm("Enable SFTP (SSH-encrypted, publishes a second port)?", pal, default=False)
            split = confirm("Run web + SFTP as TWO containers (split) instead of one combined?", pal, default=False)
            web_port = prompt_free_port(pal, "Web (HTTPS)", 443)
            # split mode always runs the SFTP container, so offer a custom SFTP port there too.
            sftp_port = prompt_free_port(pal, "SFTP", 2322) if (enable_sftp or split) else 2322
            sftp_public_host, sftp_public_port = None, None
            if (enable_sftp or split) and confirm(
                    "Do SFTP clients reach this server at a different address or port "
                    "(NAT or port forwarding)?", pal, default=False):
                sftp_public_host = ask("Address SFTP clients connect to (blank = %s)" % server,
                                       pal, "").strip() or None
                sftp_public_port = _port_or(ask("Port SFTP clients connect to", pal, str(sftp_port)),
                                            sftp_port)
            update_check = confirm("Enable the opt-in 'update available' check (asks GitHub, no telemetry)?", pal, default=False)
            log_pull = confirm("Enable the authenticated log-pull endpoint (sets a pepper; still off until a component is ticked)?", pal, default=False)
        else:
            enable_sftp, split = bool(a("enable_sftp")), bool(a("split"))
            web_port = _port_or(a("web_port"), 443)
            sftp_port = _port_or(a("sftp_port"), 2322)
            sftp_public_host = (a("sftp_public_host") or "").strip() or None
            sftp_public_port = a("sftp_public_port")
            update_check, log_pull = bool(a("update_check")), bool(a("enable_log_pull"))
        # What the audit log may record of personal data at most (RECORDING_PRESETS).
        preset, lock_levels = a("recording_preset"), bool(a("lock_recording_levels"))
        if interactive and not preset:
            print(pal.paint("What may the audit log record of personal data, at most?", "cyan"))
            for line in RECORDING_PRESET_HELP:
                print(line)
            while True:
                preset = ask("Recording preset (full / standard / minimal)", pal, "full").strip().lower()
                if preset in RECORDING_PRESETS:
                    break
                print(pal.paint("  choose full, standard or minimal", "red"))
            if not lock_levels:
                lock_levels = confirm("Make these limits also the levels, so no one can record less in the panel "
                                      "(for a regulator that requires the records)?", pal, default=False)
        try:
            recording = recording_preset_config(preset or "full", lock_levels)
        except ValueError as exc:
            self._fail(str(exc))

        if sftp_public_host and not validate_server_name(sftp_public_host):
            self._fail("invalid SFTP address (letters, digits, dots, hyphens only): %r" % sftp_public_host)
        if sftp_public_port is not None and not (1 <= int(sftp_public_port) <= 65535):
            self._fail("invalid SFTP client port (1-65535): %r" % sftp_public_port)

        return {
            "server_name": server,
            "dockvault_image": self._resolve_setup_image(args, interactive),
            "encryption_key": gen_fernet_key(),
            "jwt_secret_key": gen_hex(32),
            "vault_db_password": gen_hex(16),
            "redis_password": gen_hex(24),
            "admin_username": admin_user,
            "admin_email": admin_email,
            "admin_password": admin_pw,
            "compose_profiles": "split" if split else "combined",
            "deployment_id": gen_deployment_id(),
            "run_sftp": enable_sftp,
            "web_host_port": web_port,
            "sftp_host_port": sftp_port,
            "sftp_public_host": sftp_public_host,
            "sftp_public_port": sftp_public_port,
            # SFTP staging tmpfs size — install-time only (a deploy-time infra knob, not a live
            # limit, so it is not in the Limits menu). --sftp-staging-tmpfs-mb or hand-edit .env.
            "sftp_staging_tmpfs_mb": (getattr(args, "sftp_staging_tmpfs_mb", None) if args else None),
            "update_check_enabled": update_check,
            "plan_log_pull": log_pull,
            "log_token_pepper": gen_hex(32) if log_pull else "",
            "invite_token_pepper": gen_hex(32),
            "audit_fingerprint_key": gen_hex(32),
            "audit_chain_key": gen_hex(32),
            "max_storage_gb": (getattr(args, "max_storage_gb", None) if args else None),
            # Flags only at install time, as the storage ceiling beside them is. The Limits menu
            # is where these are shown and changed, with the memory each one implies.
            "max_concurrent_transfers": parse_transfer_limit(
                getattr(args, "max_concurrent_transfers", None) if args else None),
            "max_queued_transfers": parse_transfer_queue(
                getattr(args, "max_queued_transfers", None) if args else None),
            "transfer_queue_wait_seconds": parse_transfer_wait(
                getattr(args, "transfer_queue_wait_seconds", None) if args else None),
            "max_single_request_upload_mb": parse_single_request_upload_mb(
                getattr(args, "max_single_request_upload_mb", None) if args else None),
            "_generated_pw": generated,
            **recording,
        }

    def _resolve_cert_cfg(self, args):
        """Resolve (cert_mode, le_email, cert_path, key_path) from args (unattended) or a prompt.
        cert_mode is one of selfsigned / letsencrypt / byo (default selfsigned)."""
        pal = self.pal
        interactive = not (args and getattr(args, "non_interactive", False))
        mode = getattr(args, "cert_mode", None) if args else None
        email = getattr(args, "le_email", None) if args else None
        cpath = getattr(args, "cert_path", None) if args else None
        kpath = getattr(args, "key_path", None) if args else None
        if interactive and not mode:
            print(pal.paint("\n  Certificate source:", "cyan"))
            print("    1) Self-signed   (works immediately; browsers warn until trusted)")
            print("    2) Let's Encrypt (real cert; needs a public DNS name + port 80; Linux only)")
            print("    3) Bring your own (a fullchain cert + key you already have)")
            mode = {"2": "letsencrypt", "3": "byo"}.get(ask("Choose 1/2/3", pal, "1").strip(), "selfsigned")
            if mode == "letsencrypt":
                email = ask("Email for Let's Encrypt expiry notices", pal, "admin@example.com")
            elif mode == "byo":
                cpath = ask("Path to the certificate (fullchain PEM)", pal)
                kpath = ask("Path to the private key (PEM)", pal)
        if mode and mode not in CERT_MODES:
            self._fail("unknown --cert-mode %r (one of %s)" % (mode, ", ".join(CERT_MODES)))
        return (mode or "selfsigned", email, cpath, kpath)

    def _set_env_key(self, path, key, value):
        """Replace/append KEY=value in .env (bare value), mode 600. A byte order mark at the start is read past
        (without_bom) and not written back. The file is replaced whole and on the disk when this returns
        (replace_file_durably): a power cut never leaves it half-written, nor without a key something already
        depends on. Never makes a .env beside a sealed .env.enc (that .env would hold only this line, and a later
        lock would seal it over the real one): refused, with nothing written."""
        if not os.path.exists(path) and os.path.exists(path + ".enc"):
            self._fail("%s is locked (sealed in %s.enc): unlock it first (python dockvault.py unlock). Nothing was "
                       "written." % (os.path.basename(path), os.path.basename(path)))
        lines, found = [], False
        if os.path.exists(path):
            for raw in without_bom(open(path, encoding="utf-8").read()).splitlines():
                if re.match(r"^\s*%s\s*=" % re.escape(key), raw):
                    lines.append("%s=%s" % (key, value)); found = True
                else:
                    lines.append(raw)
        if not found:
            lines.append("%s=%s" % (key, value))
        replace_file_durably(path, "\n".join(lines) + "\n")
        tighten_secret_file(path)

    def _set_env_key_or_put_back(self, key, value):
        """_set_env_key on .env, and on a failure .env put back as it was, byte for byte. Returns None once written,
        else (why it failed, why .env could not be put back, or None when it was)."""
        path = self._env_path()
        try:
            with open(path, "rb") as f:
                before = f.read()
        except OSError as exc:
            return exc, None                    # not read, so not written either
        try:
            self._set_env_key(path, key, value)
            return None
        except OSError as exc:
            try:
                replace_file_durably(path, before)
            except OSError as again:
                return exc, again
            return exc, None

    def _remove_env_keys(self, path, keys):
        """Remove any KEY= lines for the given keys from .env (mode 600, replaced whole and on the disk as
        _set_env_key does). Returns True if any line was removed. Comments and every other line are kept verbatim;
        a byte order mark at the start is read past (without_bom), and not written back when a line is removed."""
        if not os.path.exists(path):
            return False
        keyset = set(keys)
        out, removed = [], False
        for raw in without_bom(open(path, encoding="utf-8").read()).splitlines():
            m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", raw)
            if m and m.group(1) in keyset:
                removed = True
                continue
            out.append(raw)
        if removed:
            replace_file_durably(path, "\n".join(out) + "\n")
            tighten_secret_file(path)
        return removed

    def _read_cli_admin_password(self, args):
        """Take the first admin's password from --admin-password-file (its first line) or --admin-password-stdin (one
        line) into args.admin_password, which the rest of setup reads; warn when it came as --admin-password, a value
        other users of the host can read in the process list and the shell keeps in its history. A file that cannot
        be read, or holds no password, stops setup before it writes anything."""
        if args is None:
            return
        pf = getattr(args, "admin_password_file", None)
        if pf:
            try:
                with open(pf, encoding="utf-8") as f:
                    value = f.readline().rstrip("\r\n")
            except OSError as exc:
                self._fail("cannot read --admin-password-file %s: %s" % (pf, exc))
            if not value:
                self._fail("--admin-password-file %s holds no password on its first line" % pf)
            args.admin_password = value
        elif getattr(args, "admin_password_stdin", False):
            value = sys.stdin.readline().rstrip("\r\n")
            if not value:
                self._fail("--admin-password-stdin read no password from standard input")
            args.admin_password = value
        elif getattr(args, "admin_password", None):
            print(self.pal.paint("  WARNING: --admin-password puts the password on the command line, where other users "
                                 "of this host can read it (the process list) and your shell history keeps it. Prefer "
                                 "--admin-password-file or --admin-password-stdin.", "yellow"))

    def _apply_cli_admin_overrides(self, path, env, args):
        """On a setup reuse, write an EXPLICIT --admin-password/--admin-username/--admin-email into the
        reused .env so it can seed a not-yet-bootstrapped set (harmless on a bootstrapped one). Returns
        the updated env dict. A no-op when none were passed."""
        changed = {}
        given = []
        for cli, key in (("admin_password", "ADMIN_PASSWORD"), ("admin_username", "ADMIN_USERNAME"),
                         ("admin_email", "ADMIN_EMAIL")):
            val = (getattr(args, cli, None) if args else None)
            if not val:
                continue
            # Validate the password with the SAME guard the fresh path uses (_collect_setup_config),
            # BEFORE it reaches .env. An unvalidated value that contains a single quote would corrupt
            # the single-quoted .env line, so the app is seeded with a different password than the
            # operator supplied - then dropped after a healthy boot, a silent admin lockout. Every value is
            # checked before any is written, so a refusal leaves .env as it was.
            if key == "ADMIN_PASSWORD":
                prob = admin_password_problem(val, "production")
                if prob:
                    self._fail("admin password %s" % prob)
            if key == "ADMIN_USERNAME":
                prob = admin_username_problem(val)
                if prob:
                    self._fail("admin username %r %s" % (val, prob))
            given.append((key, val))
        for key, val in given:
            self._set_env_key(path, key, "'%s'" % val)
            changed[key] = val
        if changed:
            env = dict(env, **changed)
        return env

    def _env_archives(self):
        """Every plaintext .env archive on disk (.env.<something>), excluding the template and the
        sealed lock file. These are set aside by 'new set' / repoint / remove and still hold an
        ENCRYPTION_KEY; 'lock' does not manage them, so the tool surfaces them instead."""
        out = []
        for p in glob.glob(os.path.join(glob.escape(self.root), ".env.*")):
            base = os.path.basename(p)
            if base in (".env.example", ".env.enc") or not os.path.isfile(p):
                continue
            out.append(p)
        return sorted(out)

    def _warn_env_archived(self, archived):
        """Warn (in red) that a real .env was set aside as a plaintext archive the tool won't manage."""
        print(self.pal.paint(
            "  ! Your previous .env was archived to %s. It is PLAINTEXT and still holds that\n"
            "    deployment's ENCRYPTION_KEY and DB password. 'lock' does NOT seal .env.* archives -\n"
            "    back it up off this host, then delete or hand-seal it." % os.path.basename(archived),
            "bold", "red"))

    def _strip_spent_admin_password(self, env_path, env):
        """After a healthy boot, drop the spent ADMIN_PASSWORD from the host .env once the admin is
        bootstrapped (an admin exists). Fail-safe: only strips when the DB confirms the bootstrap
        marker; on any doubt it keeps the value (a later boot may still need it to seed the first
        admin). ADMIN_USERNAME/ADMIN_EMAIL are not secrets and are kept (they give a re-run its admin
        name). Never raises - credential hygiene must not break a working setup."""
        pal = self.pal
        try:
            if not (env.get("ADMIN_PASSWORD") or "").strip():
                return   # already stripped / never set
            done = admin_bootstrap_done(DB_CONTAINER, PG_USER, PG_DB, env.get("VAULT_DB_PASSWORD", ""))
            if done is not True:
                return   # could not confirm an admin exists -> keep the bootstrap password
            if self._remove_env_keys(env_path, ["ADMIN_PASSWORD"]):
                print(pal.paint(
                    "  Removed the spent ADMIN_PASSWORD from .env (the admin is bootstrapped; it is no\n"
                    "  longer needed). Re-supply it only to seed a NEW admin on a fresh database.",
                    "green"))
        except Exception as exc:  # noqa: BLE001 - hygiene is best-effort, never fatal
            print(pal.paint("  (could not drop the spent ADMIN_PASSWORD from .env: %s)" % exc, "yellow"))

    def _normalize_compose_profile(self):
        """Persist the one supported app profile before any Compose command reads ``.env``.

        Legacy or empty values are migrated in place. Ambiguous/unknown values and a missing or
        unreadable ``.env`` fail closed so reconciliation cannot choose one layout while the
        following ``compose up`` reads another.
        """
        env_path = self._env_path()
        try:
            with open(env_path, encoding="utf-8") as handle:
                env = parse_env(handle.read())
        except OSError as exc:
            raise ValueError("could not read .env: %s" % exc)
        current = env.get("COMPOSE_PROFILES")
        selected = migrate_compose_profiles(current)
        if current != selected:
            self._set_env_key(env_path, "COMPOSE_PROFILES", selected)
        return selected

    def _dc(self, *args):
        """docker compose against the root secure shim, anchored to the root .env."""
        return ["docker", "compose", "--env-file", self._env_path(),
                "-f", os.path.join(self.root, "docker-compose.secure.yml")] + list(args)

    def _network_gateways(self):
        """The gateway address(es) of the deployment's Docker network, or [] when it cannot be read (no
        Docker, or the network does not exist yet). Read-only."""
        name = "%s_vault-network" % DEFAULT_PROJECT
        try:
            r = subprocess.run(["docker", "network", "inspect", name, "--format",
                                "{{range .IPAM.Config}}{{.Gateway}} {{end}}"],
                               capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            return []
        return (r.stdout or "").split() if r.returncode == 0 else []

    def _run_dc(self, *args, **kw):
        """Run `docker compose ...` with stdin CLOSED, always.

        Compose asks a BLOCKING yes/no question on stdin when a named volume already exists but its
        labels don't match the compose file - "Volume X exists but doesn't match configuration in
        compose file. Recreate (data will be lost)?" - which fires for every volume created before
        the com.dockvault.* labels existed, and whenever DEPLOYMENT_ID changes. With stdin inherited
        AND the output captured, that prompt is INVISIBLE: the tool looks hung until the operator
        blindly presses a key, and a stray 'y' would DESTROY the data volume. stdin=DEVNULL makes
        Compose take its safe default (keep the volume) and return immediately.

        `capture` (default True) captures stdout/stderr; pass capture=False to stream Compose's own
        progress straight to the terminal for long steps."""
        capture = kw.pop("capture", True)
        kw.setdefault("cwd", self.root)
        kw.setdefault("text", True)
        if capture:
            kw.setdefault("capture_output", True)
        return subprocess.run(self._dc(*args), stdin=subprocess.DEVNULL, **kw)

    def _refuse_setup_downgrade(self, version, what):
        """Stop a setup re-run that would start `version` (this checkout's VERSION) when the deployment has run a newer
        one (_running_version: the running container, or its best guess), before .env or the stack is changed. Going
        back over data a newer version wrote is update's to do: it asks the running version what the older one
        cannot read, and refuses what nothing would check."""
        if not parse_semver(version):
            return
        running, source = self._running_version()
        if parse_semver(running) and parse_semver(version) < parse_semver(running):
            self._fail("this re-run would %s %s, which is older than %s, the version this deployment has run (from %s). "
                       "Setup does not go back to an older version: python dockvault.py update --tag v%s does, after "
                       "it checks what the data holds that %s cannot read. The image source and the stack were left "
                       "as they were." % (what, version, running, source, version.lstrip("vV"), version))

    def _resolve_rerun_image_source(self, env_path, args, interactive):
        """On a setup RE-RUN, let the operator confirm or CHANGE the image mode (pull the published
        release vs. build the current checkout), then repoint .env accordingly.

        This closes the "I git-pulled new code, re-ran setup, and it still ran the old release" gap:
        a re-run previously kept the first install's choice with no way to switch and no visibility.
        Honors --image-source in any mode; interactive runs also offer a keep/build/release prompt
        (default keep, so a plain restart is one Enter). Prints the effective mode either way."""
        pal = self.pal
        env = parse_env(open(env_path, encoding="utf-8").read()) if os.path.exists(env_path) else {}
        version = read_version_file(self.root)
        choice = ((getattr(args, "image_source", None) if args else None) or "").strip().lower()
        if interactive and not choice:
            print(pal.paint("\n  Image source (current: %s):" % describe_image_mode(env), "cyan"))
            print("    1) Keep current")
            print("    2) Build from this checkout - run the code you have now (e.g. after git pull)")
            print("    3) Pull the published release image")
            choice = {"2": "build", "3": "release"}.get(ask("Choose 1/2/3", pal, "1").strip(), "")
        # A "release" switch must not repoint .env at a tag that was never published (a checkout
        # ahead of the last release) - the pull would then fail with a broken pin left behind. Guard
        # exactly like _resolve_setup_image: no VERSION, or a tag GitHub doesn't list, downgrades to
        # keep. An unreachable API returns [] -> proceed, and let the pull report any real failure.
        if choice == "release":
            candidate = release_image_ref(version)
            if not candidate:
                print(pal.paint("  No usable VERSION to match a published release; keeping %s."
                                % describe_image_mode(env), "yellow"))
                choice = ""
            else:
                tags = fetch_release_tags()
                if tags and candidate.rsplit(":", 1)[1] not in tags:
                    print(pal.paint("  %s is not published (this checkout is ahead of the latest "
                                    "release); keeping %s." % (candidate, describe_image_mode(env)), "yellow"))
                    choice = ""
        # What the re-run is about to start is this checkout's VERSION when it pulls that release or builds this
        # checkout (a kept local build is built again). That can be older than what this deployment has run (a
        # deployment updated by pull leaves VERSION where it was; an older checkout): setup would then go back over
        # the data with none of update's checks. So the same rule as update: setup never goes back to an older
        # version, update does (_refuse_setup_downgrade).
        if choice in ("release", "build") or (not choice and not uses_release_image(env)):
            self._refuse_setup_downgrade(version, "pull the published release of" if choice == "release"
                                         else "build and start this checkout at")
        action, value = rerun_image_target(env, choice, version)
        if action == "set":
            self._set_env_key(env_path, "DOCKVAULT_IMAGE", value)
            env = parse_env(open(env_path, encoding="utf-8").read())
            print(pal.paint("  Image source switched -> now %s." % describe_image_mode(env), "green"))
        print(pal.paint("  Image: %s." % describe_image_mode(env), "cyan"))

    def _start_secure_stack(self):
        """Start/recreate the deployment the current .env describes.

        Builds the local Dockerfile UNLESS .env pins a published release image, in which case the
        image is used as it is when already here (pulled only when not: _ensure_release_image) and the
        stack recreated without --build. Setup re-runs go through here, so without the check the
        documented "re-run setup to upgrade" path would rebuild over a release image an operator
        deliberately chose — the same clobber the Update menu's pull path already avoids."""
        if not self._container_logs_readable():
            return False
        if uses_release_image(self._load_env()):
            return self._ensure_release_image() and self._recreate_stack(build=False)
        return self._recreate_stack(build=True)

    def _ensure_release_image(self):
        """The release image .env pins, made present: used as it is when Docker already has it, pulled otherwise.
        A start or a restart then needs no registry when the image is here (offline, a registry outage or rate limit),
        and does not fetch the tag again each time it starts: a start or a restart never moves the deployment to
        another image (update does, with its gates; a restore starts the image the backup's .env names; a setup
        re-run can start this checkout's version). True when the image is here."""
        image = (self._load_env().get("DOCKVAULT_IMAGE") or "").strip()
        if image_present(image):
            print(self.pal.paint("  Using %s, already on this host (no pull)." % image, "cyan"))
            return True
        return self._pull_release_image()

    def _container_logs_readable(self):
        """False, having said why, when .env sets a container-log rotation Docker would refuse: the stack is
        then left as it is, rather than recreated into containers that cannot be created."""
        problems = container_log_problems(self._container_log_values())
        for problem in problems:
            print(self.pal.paint("  %s; fix it in .env (or remove the line for the default). Nothing was "
                                 "recreated." % problem, "red"))
        return not problems

    def _container_log_values(self):
        """DOCKER_LOG_MAX_SIZE and DOCKER_LOG_MAX_FILE as docker compose will give them to the compose files: read
        from .env by compose's rules, the process environment first (compose_env_values)."""
        text = ""
        try:
            with open(self._env_path(), encoding="utf-8") as handle:
                text = handle.read()
        except OSError:
            pass
        return compose_env_values(text, ("DOCKER_LOG_MAX_SIZE", "DOCKER_LOG_MAX_FILE"))

    def _note_host_log_driver(self):
        """Say where container output goes when the operator may not expect it (container_log_note)."""
        note = container_log_note(self.root)
        if note:
            print(self.pal.paint("  Note: " + note, "yellow"))

    def _pull_release_image(self):
        """Pull the release image .env pins. Reports the remedy itself, since a failure here is
        almost always a tag that was never published rather than a broken deployment."""
        image = (self._load_env().get("DOCKVAULT_IMAGE") or "").strip()
        print(self.pal.paint("  Pulling %s (published release; no local build) ..." % image, "cyan"))
        try:
            r = self._run_dc("pull", capture=False, timeout=600)
        except (OSError, subprocess.SubprocessError) as exc:
            print(self.pal.paint("  docker compose pull failed: %s" % exc, "red"))
            return False
        if getattr(r, "returncode", 1) != 0:
            print(self.pal.paint("  Could not pull %s - is that version published? Build this checkout "
                                 "instead with:  python dockvault.py setup --image-source build" % image, "red"))
            return False
        return True

    def _recreate_stack(self, build):
        """Recreate the stack. build=True builds the local Dockerfile (setup / from-source update);
        build=False recreates from the already-present image (the pull-update path - must NOT rebuild,
        or it would overwrite the just-pulled release image with a local build).

        Never for a set whose restore did not finish (RESTORE_INCOMPLETE), whatever asked: every `up` of the stack
        comes here, and each command that starts the set refuses before it changes anything, so this one is the
        backstop (SystemExit, with nothing touched). A restore starts the set it restored only once it has removed
        that set's marker."""
        self._refuse_incomplete_restore(None, notes=False)
        if not self._container_logs_readable():
            return False
        if not self._remove_inactive_profile():
            return False
        args = ["up", "-d", "--force-recreate", "--remove-orphans"]
        if build:
            args.insert(1, "--build")
        try:
            r = self._run_dc(*args, capture=False, timeout=600)
        except (OSError, subprocess.SubprocessError):
            return False
        return getattr(r, "returncode", 1) == 0

    def _remove_inactive_profile(self):
        """Remove only app containers from the profile that is no longer selected.

        Compose does not consider services behind an inactive profile to be orphans, so a
        combined-to-split rerun otherwise leaves ``vault`` holding the web/SFTP ports (and the
        reverse transition leaves ``vault-api``/``vault-sftp``). ``compose rm`` stops and removes
        only those inactive app containers; database/cache containers and every named volume stay
        in place. Fail closed before ``up`` if reconciliation itself fails.
        """
        try:
            args = profile_reconciliation_args(self._normalize_compose_profile())
        except (OSError, ValueError):
            return False
        try:
            result = self._run_dc(*args, capture=False, timeout=120)
        except (OSError, subprocess.SubprocessError):
            return False
        return getattr(result, "returncode", 1) == 0

    def _start_db_only(self):
        """Make the postgres service available for the pre-up secret check, WITHOUT disturbing a
        deployment that is already running. Returns False if it could not be made available.
        Compose's own progress is streamed (capture=False) so a slow pull/create is visibly WORKING
        rather than looking hung, and so any Compose error is on screen when this returns False."""
        # The composes pin fixed container names, so this acts on whatever vault-db exists on the
        # host - which, when an operator re-runs setup, is a LIVE deployment's database. Leave a
        # running one strictly alone: `compose up -d` under a DIFFERENT .env would RECREATE it (its
        # POSTGRES_* environment changed) and knock the running app off its connection, for a check
        # that only needs to connect. _stop_db_only reads the same flag, so the probe can only ever
        # stop a database it started itself.
        self._db_was_running = container_running(DB_CONTAINER)
        if self._db_was_running:
            return self._live_db_serves_guarded_volume()
        # Nor is the database of a set whose restore did not finish (RESTORE_INCOMPLETE) started: its volume may hold
        # part of a backup, or nothing (in which postgres would make a new, empty database). The check of .env then
        # has no answer, and says why.
        prefix = volume_prefix(self._load_env())
        found = self._incomplete_restores()
        if prefix in found:
            print(self.pal.paint("  The database of set '%s' was not started to check .env: %s"
                                 % (prefix, self._incomplete_restore_text(prefix, found[prefix])), "red"))
            return False
        try:
            r = self._run_dc("up", "-d", DB_CONTAINER, capture=False, timeout=180)
        except (OSError, subprocess.SubprocessError):
            return False
        return getattr(r, "returncode", 1) == 0

    def _live_db_serves_guarded_volume(self):
        """Is the ALREADY-RUNNING vault-db the database for the volume being guarded?

        `container_name: vault-db` is pinned globally while the volume name varies with
        VAULT_VOLUME_PREFIX, so on a host that has more than one set the two can name different
        things. Recreating the container to force them together is exactly what must not happen
        here (it would take a live deployment's database away from its app), so when they diverge
        the honest answer is 'cannot check this volume' - the caller treats that as ambiguous and
        fails closed. An unreadable mount list is ambiguous for the same reason: the password probe
        must never answer a question about a volume it cannot identify."""
        vol = getattr(self, "_guard_vol", None)
        if not vol:
            return True
        mounts = container_mounts(DB_CONTAINER)
        if mounts is None:
            print(self.pal.paint(
                "  Could not inspect the running database's volumes, so this .env cannot be checked\n"
                "  against %s without risking a different deployment's data. Try again once Docker\n"
                "  is reachable, or stop the running deployment first (docker compose down)." % vol,
                "yellow"))
            return False
        if vol in mounts:
            return True
        print(self.pal.paint(
            "  A different deployment's database is already running under the name '%s', serving\n"
            "  another volume set - so this .env cannot be checked against %s without taking that\n"
            "  deployment down. Stop it first (docker compose down), then re-run."
            % (DB_CONTAINER, vol), "yellow"))
        return False

    def _wait_db_ready(self, tries=20, tick=None):
        """Poll pg_isready inside vault-db until it accepts connections (readiness, NOT auth).
        Reports progress through `tick` (default: a live '...still waiting (Ns)' line) so a 40s wait
        never looks like a hang."""
        import time
        tick = tick or self._waiting_tick
        for i in range(tries):
            try:
                r = subprocess.run(["docker", "exec", DB_CONTAINER, "pg_isready", "-U", PG_USER, "-d", PG_DB],
                                   stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                tick(i * 2); time.sleep(2); continue
            if getattr(r, "returncode", 1) == 0:
                return True
            tick(i * 2)
            time.sleep(2)
        return False

    def _waiting_tick(self, seconds):
        """Print a coarse 'still waiting' heartbeat (every ~10s) so a long poll shows life."""
        if seconds and seconds % 10 == 0:
            print(self.pal.paint("    ...still waiting (%ds)" % seconds, "grey"), flush=True)

    def _stop_db_only(self):
        """Stop the probe's vault-db (best-effort) so a refused setup doesn't leave a lone db running.

        NO-OP when the database was already up before the probe: that is a running deployment's
        database, not ours to stop. Stopping it broke the deployment outright when the guard then
        REFUSED - the tool exits, and the operator is left with a live vault whose database this
        tool shut down underneath it."""
        if getattr(self, "_db_was_running", False):
            return
        try:
            self._run_dc("stop", DB_CONTAINER, timeout=60)
        except (OSError, subprocess.SubprocessError):
            pass

    def _stop_stack(self):
        """Stop the current stack's CONTAINERS without removing volumes (best-effort). Used before a
        repoint: the fixed container names mean two sets can't run at once, so the current deployment
        must be stopped before we point at (and probe) a different set. Data is untouched (no -v)."""
        try:
            self._run_dc("down", "--remove-orphans", timeout=120)
        except (OSError, subprocess.SubprocessError):
            pass

    def _tail_logs(self, service=None, lines=40):
        """Print the tail of the stack's (or one service's) logs. Called when a start/health step
        fails, so the operator sees the ACTUAL error (e.g. a TLS key the container can't read)
        without having to re-run docker compose by hand. Falls back to the WHOLE stack when the
        named service produced nothing (a build failure never creates a container). Returns True
        only if something was actually printed, so a caller never claims 'the logs are above' when
        the screen is empty."""
        pal = self.pal
        for svc in ([service, None] if service else [None]):
            args = ["logs", "--no-color", "--tail", str(lines)] + ([svc] if svc else [])
            try:
                r = self._run_dc(*args, timeout=60)
            except (OSError, subprocess.SubprocessError):
                continue
            out = ((getattr(r, "stdout", "") or "") + (getattr(r, "stderr", "") or "")).strip()
            if not out:
                continue
            print(pal.paint("\n  --- last %d log lines%s ---"
                            % (lines, (" (%s)" % svc) if svc else ""), "grey"))
            print(out)
            print(pal.paint("  --- end of logs ---\n", "grey"), flush=True)
            return True
        return False

    def _guard_db_secret(self, env, interactive=False, exists_fn=None, start_fn=None, wait_fn=None,
                         probe_fn=None, stop_fn=None, marker_fn=None, stamp_fn=None, env_is_fresh=False,
                         canary_fn=None):
        """Guardrail against the 'existing volume + wrong .env' footgun. No-op (True) for a fresh
        volume. NON-interactive (a script): auto-verify the current .env's DB password and FAIL CLOSED
        on a mismatch/ambiguous result. INTERACTIVE: do NOT auto-wait - present choices (verify / point
        at a .env / new set / destroy / cancel) and run the ~30s DB probe only if the operator asks.
        Never prints a secret. The *_fn hooks are injectable for tests. env_is_fresh flags a .env this
        setup run just authored and never used, so the interactive 'new set' option can discard it.
        With the real password probe, a .env whose password opens the volume has its ENCRYPTION_KEY checked
        too, against the key check the vault keeps in its database (_key_canary_verdict; canary_fn stands in
        for it in tests): a copy of another .env can share the password and not the key."""
        exists_fn = exists_fn or volume_exists
        self._canary_check = canary_fn or (self._key_canary_verdict if probe_fn is None else None)
        vol = "%s_vault_pg_data" % volume_prefix(env)
        if not exists_fn(vol):
            return True   # brand-new volume: the .env password is baked in on first init
        hooks = (start_fn or self._start_db_only, wait_fn or self._wait_db_ready,
                 probe_fn or probe_pg_password, stop_fn or self._stop_db_only,
                 marker_fn or read_volume_coupling, stamp_fn or write_volume_coupling)
        if interactive:
            return self._resolve_existing_volume(env, vol, hooks, env_is_fresh=env_is_fresh)
        # non-interactive: verify + fail closed (a script must not auto-destroy or auto-fork).
        result = self._verify_env_against_volume(env, vol, hooks)
        if result == "ok":
            return True
        self._print_secret_mismatch(result, vol)
        return False

    def _verify_env_against_volume(self, env, vol, hooks):
        """Decide whether `env` is the .env that opens `vol`. Tries the instant path first (the
        volume's coupling stamp); otherwise starts the DB and auth-probes VAULT_DB_PASSWORD,
        narrating each step. Returns 'ok' | 'mismatch' | 'ambiguous' | 'encryption_key'. Stops the
        probe DB afterwards. Never prints a secret."""
        pal = self.pal
        start_fn, wait_fn, probe_fn, stop_fn, marker_fn, stamp_fn = hooks
        # Which volume the answer is ABOUT. _start_db_only reads it to confirm that an
        # already-running vault-db is this set's database and not another set's (the container
        # name is pinned globally; the volume name is not).
        self._guard_vol = vol
        if not fernet_key_looks_valid(env.get("ENCRYPTION_KEY", "")):
            return "encryption_key"
        # Fast path: a set this tool has already verified carries a non-secret coupling stamp, so the
        # answer takes about a second. A stamp can only ever CONFIRM - if it is absent, unreadable or
        # stale (the DB password was rotated), fall through to the authoritative live probe.
        print(pal.paint("  Checking the volume's coupling stamp (instant)...", "cyan"), flush=True)
        if coupling_marker_verdict(marker_fn(vol), env) == "ok":
            print(pal.paint("  Stamp matches this .env - no database start needed.", "green"), flush=True)
            return "ok"
        print(pal.paint("  No usable stamp; starting the database container to check the password "
                        "(~20-40s)...", "cyan"), flush=True)
        if not start_fn():
            stop_fn()
            print(pal.paint("  The database container did not start (Docker's output, or why it was not started, is "
                            "above).", "yellow"))
            return "ambiguous"
        print(pal.paint("  Waiting for the database to accept connections...", "cyan"), flush=True)
        if not wait_fn():
            stop_fn()
            print(pal.paint("  The database did not become ready in time.", "yellow"))
            return "ambiguous"
        print(pal.paint("  Authenticating VAULT_DB_PASSWORD against the stored database (vault-db)...",
                        "cyan"), flush=True)
        result = probe_fn(DB_CONTAINER, PG_USER, PG_DB, env.get("VAULT_DB_PASSWORD", ""))
        # The password opens the database; ENCRYPTION_KEY is the other half of the pairing, and the one whose loss
        # is final. With the database up, its key check is read too: one sealed under another key refuses the .env.
        # No check there yet (an app never started on this set) or none readable is not a refusal: the app's own
        # check refuses to start under a wrong key. It is not a check either, so the pairing is not stamped: a stamp
        # would answer every later check of this .env, and its key would never be checked here again.
        key_unchecked = False
        if result == "ok" and self._canary_check is not None:
            print(pal.paint("  Checking ENCRYPTION_KEY against the key check in the database...", "cyan"), flush=True)
            verdict = self._canary_check(env)
            if verdict == "mismatch":
                result = "encryption_key_mismatch"
            elif verdict != "ok":
                key_unchecked = True
                print(pal.paint("  The database holds no key check yet, or none could be read: the next check of "
                                "this .env reads it again.", "cyan"), flush=True)
        stop_fn()
        if result == "ok" and not key_unchecked:
            stamp_fn(vol, env)   # best-effort: make the next check instant
        return result if result in ("ok", "mismatch", "encryption_key_mismatch") else "ambiguous"

    def _key_canary_verdict(self, env):
        """'ok' when the key check in the running vault-db opens under env's ENCRYPTION_KEY, 'mismatch' when it does
        not, 'unknown' when there is none yet or it cannot be read (read_key_canary, fernet_token_signed_by)."""
        token = read_key_canary(DB_CONTAINER, PG_USER, PG_DB, env.get("VAULT_DB_PASSWORD", ""))
        if not token:
            return "unknown"
        return "ok" if fernet_token_signed_by(env.get("ENCRYPTION_KEY", ""), token) else "mismatch"

    def _resolve_existing_volume(self, env, vol, hooks, env_is_fresh=False):
        """Interactive menu shown when an existing data volume is found. NOTHING starts until the
        operator chooses; only 1/2 run the slow DB probe. Returns True to PROCEED (after acting) or
        False to stop. Never prints a secret.

        env_is_fresh marks the current .env as one THIS setup run just authored and never used (a
        fresh install that found a pre-existing volume). It is threaded to option 3 so a throwaway
        .env is discarded rather than archived. Pointing at another .env (option 2) installs a real
        secret file, so the flag is cleared once that happens."""
        pal = self.pal
        print(pal.paint("\n  Found an existing data volume from a previous deployment:", "yellow"))
        print("    %s" % vol)
        print("  Postgres bakes the DB password into it on first init, so the CURRENT .env may not open")
        print("  it. Nothing has started yet - choose what to do (only 1 and 2 start the database):")
        while True:
            print(pal.paint("\n    1) Verify the current .env matches it, then reuse   (instant if the "
                            "set is stamped, else ~20-40s)", "cyan"))
            print("    2) Point me at a specific .env file and verify THAT one instead")
            print("    3) Keep this data + deploy a NEW set under a fresh volume name   (instant)")
            print("    4) DESTROY this data and start fresh with the current .env       (down -v)")
            print("    5) Cancel")
            flush_stdin()
            choice = ask("Choose 1-5", pal).strip()
            if choice == "1":
                if self._try_verify(env, vol, hooks):
                    return True
            elif choice == "2":
                src = ask("Path to the .env to try (blank = back)", pal).strip()
                if not src:
                    continue
                if not os.path.exists(src):
                    print(pal.paint("  No file at %s." % src, "red"))
                    continue
                # The current .env is the only key to the set it names: kept first, as a restore keeps it, unless
                # this run just authored it and it never opened anything (env_is_fresh).
                if not env_is_fresh:
                    try:
                        kept = self._keep_env_before_replacing(src)
                    except OSError as exc:
                        print(pal.paint("  Could not keep the current .env (%s), so it was not replaced. Pick "
                                        "another option." % exc, "red"))
                        continue
                    if kept:
                        print(pal.paint("  Kept the current .env as %s before installing that one." % kept, "cyan"))
                _copy_secret(src, self._env_path())
                tighten_secret_file(self._env_path())
                # The installed .env may name another volume set: from here on the menu is about that set's volume,
                # the one every option now acts on (verify, and down -v, which deletes the volumes of the set .env
                # names), whatever happens next.
                env = self._load_env()
                env_is_fresh = False     # a real, operator-supplied .env now - never discard it
                chosen = "%s_vault_pg_data" % volume_prefix(env)
                if chosen != vol:
                    vol = chosen
                    print(pal.paint("  That .env is for another volume set: the choices below are now about %s."
                                    % vol, "yellow"))
                try:
                    self._normalize_compose_profile()
                except (OSError, ValueError) as exc:
                    print(pal.paint("  That .env is not deployable: %s." % exc, "red"))
                    continue
                env = self._load_env()
                print(pal.paint("  Installed that .env; verifying it...", "cyan"))
                if self._try_verify(env, vol, hooks):
                    return True
            elif choice == "3":
                self._new_set_from(env, current_env_is_fresh=env_is_fresh)
                return True
            elif choice == "4":
                if self._destroy_data(vol):
                    return True
            elif choice == "5":
                print(pal.paint("  Cancelled - restore the matching .env and re-run setup.\n", "yellow"))
                return False
            else:
                print(pal.paint("  Please enter 1, 2, 3, 4 or 5.", "red"))

    def _try_verify(self, env, vol, hooks):
        """Run the probe; True if it matches (proceed). On mismatch/ambiguous, explain (no secret) and
        return False so the caller re-shows the menu instead of dead-ending."""
        pal = self.pal
        result = self._verify_env_against_volume(env, vol, hooks)
        if result == "ok":
            print(pal.paint("  Match: VAULT_DB_PASSWORD authenticates against this volume (ENCRYPTION_KEY "
                            "has a valid key format). Continuing.", "green"))
            return True
        if result == "mismatch":
            print(pal.paint("  That .env's VAULT_DB_PASSWORD does NOT match this volume - pick another option.", "red"))
        elif result == "encryption_key":
            print(pal.paint("  That .env's ENCRYPTION_KEY isn't a valid key; stored files couldn't be decrypted.", "red"))
        elif result == "encryption_key_mismatch":
            print(pal.paint("  That .env's VAULT_DB_PASSWORD opens this volume, but its ENCRYPTION_KEY is not the key "
                            "the stored data was sealed with - pick another option.", "red"))
        else:
            print(pal.paint("  Couldn't verify (the database didn't start/respond in time) - NOT a confirmed "
                            "mismatch. Try again, or pick another option.", "yellow"))
        return False

    def _keep_env_before_replacing(self, src):
        """Keep the current .env, before setup installs the .env at `src` over it, as .env.<the set it names> (or
        .env.<prefix>.<n>, numbered after the copies there; never over a file already there: _keep_env_copy).
        Returns the copy's path, or None
        when there is no .env or it already reads as `src` (nothing would be lost). Raises OSError when it cannot be
        kept: the caller then does not replace it."""
        env_now = self._env_path()
        if not os.path.exists(env_now):
            return None
        with open(env_now, "rb") as f:
            current = f.read()
        with open(src, "rb") as f:
            if f.read() == current:
                return None
        prefix = volume_prefix(parse_env(current.decode("utf-8", "replace")))
        return self._keep_env_copy(prefix if valid_volume_prefix(prefix) else "before-setup", current)

    def _new_set_from(self, env, current_env_is_fresh=False):
        """Author a fresh set (new prefix + secrets) with its own .env. The old data is left untouched
        (re-pointable later from the Volumes menu).

        current_env_is_fresh marks a .env this same setup run just authored and never used to touch
        data (a fresh install that hit an existing volume). That .env's secrets open nothing, so it is
        DISCARDED (overwritten by the new set's .env) rather than archived as a pointless plaintext
        secret file. A real, pre-existing .env is archived and the operator is warned in red that the
        archive is plaintext and holds that deployment's ENCRYPTION_KEY."""
        pal = self.pal
        new_id = gen_deployment_id()
        new_prefix = "%s-%s" % (DEFAULT_PROJECT, new_id)
        archived = None if current_env_is_fresh else self._archive_env(volume_prefix(env))
        cfg = new_set_config(env, new_prefix, new_id)
        if write_env(self._env_path(), build_env_lines(cfg)):
            note = "  Authored a fresh set '%s' (new volumes + secrets); starting it." % new_prefix
            if archived:
                note += " The previous set's .env was saved aside."
            print(pal.paint(note, "green"))
        else:
            print(pal.paint("  Authored a fresh set '%s' - WARNING: could not restrict the new .env's "
                            "permissions; secure it yourself." % new_prefix, "yellow"))
        if archived:
            self._warn_env_archived(archived)
        if cfg.get("_generated_admin_pw"):
            # Show the freshly-generated admin password on the controlling terminal only (like the
            # recovery key), so a redirected/tee'd stdout or CI log can't capture it.
            self._emit_secret(pal.paint("  New set's admin password: %s   (auto-generated - store it NOW)"
                                        % cfg["admin_password"], "bold", "yellow"), label="admin-password")

    def _destroy_data(self, vol):
        """Strong-confirm + docker compose down -v. True to proceed (destroyed), False if declined. `down -v` deletes the
        volumes of the set the installed .env names, so it runs only when that is the set of `vol`, the volume the
        operator is asked about: never against another set's."""
        pal = self.pal
        named = "%s_vault_pg_data" % volume_prefix(self._load_env())
        if named != vol:
            print(pal.paint("  Refusing to delete: .env now names the set of %s, not %s, and down -v deletes the "
                            "volumes of the set .env names. Nothing was deleted." % (named, vol), "red"))
            return False
        flush_stdin()
        if not confirm("This PERMANENTLY deletes the data in %s. Continue?" % vol, pal, default=False):
            print(pal.paint("  Nothing was deleted.", "yellow"))
            return False
        try:
            r = self._run_dc("down", "-v", "--remove-orphans", capture=False, timeout=180)
        except (OSError, subprocess.SubprocessError) as exc:
            self._fail("teardown failed: %s" % exc)
        if getattr(r, "returncode", 1) != 0:
            # The data may survive (a volume still in use, say): setup must not go on as if it were gone, or it would
            # start on a volume the current .env may not open.
            print(pal.paint("  'docker compose down -v' failed (exit %s): the data was NOT destroyed. A volume may "
                            "still be in use; free it and try again, or pick another option."
                            % getattr(r, "returncode", "?"), "red"))
            return False
        # Its volumes are gone, and with them what a restore that did not finish left in them (as Reset).
        self._drop_restore_incomplete(volume_prefix(self._load_env()))
        print(pal.paint("  Destroyed the old data; starting fresh with the current .env.", "green"))
        return True

    def _print_secret_mismatch(self, kind, vol):
        """Explain a secret<->volume mismatch + the recovery paths (non-interactive/script path).
        NEVER prints a secret value."""
        pal = self.pal
        if kind == "ambiguous":
            print(pal.paint("\nERROR: could NOT verify the current .env against the existing data volume.", "red"))
        else:
            print(pal.paint("\nERROR: the current .env does NOT match the existing data volume.", "red"))
        print("  Volume: %s" % vol)
        if kind in ("db_password", "mismatch"):
            print("  VAULT_DB_PASSWORD in .env fails to authenticate against the stored database.")
            print("  Postgres bakes the DB password into the volume on FIRST init and never re-reads it,")
            print("  so a fresh or changed .env can't open data created under the old password (the app")
            print("  would loop on 'password authentication failed for user %s')." % PG_USER)
        elif kind == "encryption_key":
            print("  ENCRYPTION_KEY in .env is not a valid key, so files stored in this volume could not")
            print("  be decrypted. It must be the ENCRYPTION_KEY this volume's data was created under.")
        elif kind == "encryption_key_mismatch":
            print("  VAULT_DB_PASSWORD in .env opens the stored database, but ENCRYPTION_KEY is not the key its")
            print("  data was sealed with (the key check the vault keeps in the database does not open with")
            print("  it): files stored in this volume could not be decrypted, and the vault refuses to start.")
        else:  # ambiguous
            print("  Could NOT verify the .env against the volume (the database did not become reachable")
            print("  in time). Refusing to start rather than risk a broken pairing.")
        print(pal.paint("  Two ways forward:", "yellow"))
        print("    1) Restore the ORIGINAL .env created WITH this volume - it holds the matching")
        print("       VAULT_DB_PASSWORD and ENCRYPTION_KEY. (Keep a backup of .env off-host.)")
        print("    2) Start FRESH - this DESTROYS the stored data:")
        print("         docker compose -f docker-compose.secure.yml down -v")
        print("       then re-run setup.")
        print(pal.paint("  Not starting.\n", "red"))

    def _wait_secure_healthy(self, profiles, tries=40):
        import time
        svc = self._web_service(profiles)
        fmt = "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}"
        for _ in range(tries):
            try:
                r = subprocess.run(["docker", "inspect", "-f", fmt, svc],
                                   capture_output=True, text=True, timeout=15)
            except Exception:  # noqa: BLE001 — a wedged daemon counts as a non-healthy tick, not a hang
                time.sleep(3)
                continue
            state = (r.stdout or "").strip()
            if state == "healthy":
                return True
            if state in ("exited", "dead"):
                return False
            time.sleep(3)
        return False

    def _print_setup_summary(self, summary, healthy, logs_shown=False):
        pal = self.pal
        name = summary.get("server_name") or "<your-server-name>"
        print(pal.paint("\n===================================================================", "blue"))
        if not healthy:
            print(pal.paint(" The vault did NOT report healthy%s."
                            % (" - its last log lines are above" if logs_shown else ""), "red"))
            print("   Full logs:  docker compose -f docker-compose.secure.yml logs --tail 100")
            return
        webp = summary.get("web_host_port") or 443
        url = "https://%s/" % name if webp == 443 else "https://%s:%d/" % (name, webp)
        print(pal.paint(" Web UI / API : %s          (host port %d)" % (url, webp), "bold", "green"))
        if summary.get("run_sftp"):
            print(" SFTP (SSH)   : %s port %d" % (name, summary.get("sftp_host_port") or 2322))
        if summary.get("admin_username"):
            print(" Admin login  : %s" % summary["admin_username"])
        if summary.get("admin_password"):
            # On the controlling terminal only, never stdout (a setup log, cloud-init's output): _emit_secret.
            self._emit_secret(pal.paint(" Admin passwd : %s   (auto-generated - store it NOW)" % summary["admin_password"],
                                        "yellow"), label="admin-password")
        print(pal.paint("\n *** ENCRYPT THE HOST DISK (LUKS / BitLocker / FileVault / encrypted cloud"
                        " volume). ***", "yellow"))
        print(pal.paint("     Names, descriptions, notes and file contents are sealed at rest, but the"
                        " database", "yellow"))
        print(pal.paint("     still holds usernames, emails and audit metadata in the clear, and a"
                        " running", "yellow"))
        print(pal.paint("     stack needs the plaintext .env - host disk encryption is the at-rest"
                        " control for what is not sealed.", "yellow"))
        print(pal.paint(" *** BACK UP .env OFF THIS HOST - it holds ENCRYPTION_KEY. ***", "yellow"))
        print(pal.paint("===================================================================\n", "blue"))

    def backup(self, args=None):
        """Backup & Restore menu: dump the current set ({.env + volumes}) into one bundle, restore a
        bundle back, or LIST the bundles found across every backup location. Interactive by default;
        arg-mode via args.backup_action (backup|restore|list) or --list."""
        pal = self.pal
        interactive = not (args and getattr(args, "non_interactive", False))
        action = getattr(args, "backup_action", None) if args else None
        if args and getattr(args, "list", False):
            action = "list"
        if not action and interactive:
            print(pal.paint("\n  1) Backup the current set   2) Restore a bundle (STOPS + REPLACES "
                            "current data)   3) List backups", "cyan"))
            action = {"2": "restore", "3": "list"}.get(ask("Choose 1/2/3", pal, "1").strip(), "backup")
        if action == "list":
            self._list_backups(args)             # host-side; no docker needed
            return
        ok, msg = docker_available()             # backup + restore drive docker volumes
        if not ok:
            self._fail(msg)
        if action == "restore":
            self._do_restore(args)
        else:
            # Offer sealing only for the EXPLICIT backup command (this path). The pre-upgrade
            # auto-backup calls _do_backup directly, so it is never prompted and never sealed.
            if interactive and not (args and getattr(args, "lock", False)):
                if confirm("Seal this backup? (encrypts its .env so a stolen backup can't decrypt "
                           "your files; needs a passphrase you must not lose)", pal, default=False):
                    if args is None:
                        args = argparse.Namespace()
                    args.lock = True
            self._do_backup(self._load_env(), args)

    def _write_candidates(self, args):
        """Ordered candidate directories a NEW backup would be written to (first writable wins): an
        explicit --backup-dir list, else the default candidates. PURE - no probing/creation, so it is
        safe to use for display + search."""
        explicit = parse_backup_dirs(getattr(args, "backup_dir", None) if args else None)
        return explicit if explicit else _default_backup_candidates()

    def _backup_root(self, args):
        """The directory NEW bundles are WRITTEN to: the first WRITABLE candidate (created here), else
        the first candidate (a later mkdir surfaces the error) so a backup never silently vanishes."""
        cands = self._write_candidates(args)
        for c in cands:
            if _writable_dir(c):
                return c
        return cands[0] if cands else _app_data_backup_root()

    def _backup_search_roots(self, args):
        """Every EXISTING directory to search when listing / restoring: the write candidates, ALWAYS
        plus the legacy <root>/backups so bundles written by an older version (or under the repo) are
        never orphaned when the default moves. Deduped by absolute path, existing dirs only (a search
        never creates one), order preserved."""
        roots = list(self._write_candidates(args))
        roots.append(os.path.join(self.root, "backups"))        # legacy in-repo location
        seen, out = set(), []
        for r in roots:
            rr = os.path.abspath(os.path.expanduser(r))
            if rr in seen:
                continue
            seen.add(rr)
            if os.path.isdir(rr):
                out.append(rr)
        return out

    def _list_bundles(self, args):
        """Bundle directories found across every search root, NEWEST FIRST, deduped by absolute path.
        Returns FULL paths - a same-name bundle can exist in more than one root, so the basename alone
        is ambiguous. mtime is captured right where existence was just checked, so a bundle that
        disappears mid-scan is skipped rather than crashing the sort."""
        found, seen = [], set()
        for root in self._backup_search_roots(args):
            for c in glob.glob(os.path.join(glob.escape(root), "dockvault-*")):
                if not os.path.isdir(c):
                    continue
                ap = os.path.abspath(c)
                if ap in seen:
                    continue
                try:
                    mtime = os.path.getmtime(c)
                except OSError:
                    continue                    # vanished between glob and stat - skip it
                seen.add(ap)
                found.append((mtime, ap))
        found.sort(key=lambda t: t[0], reverse=True)
        return [ap for _, ap in found]

    def _list_backups(self, args):
        """Print WHERE new bundles will be written + every existing bundle across all search roots
        (newest first, full paths). Host-side and READ-ONLY: unlike a real backup it never creates a
        directory, so it only NAMES the write candidates rather than resolving (and creating) one."""
        pal = self.pal
        cands = self._write_candidates(args)
        print(pal.paint("\n  New backups go to the first writable of (created when you back up):", "cyan"))
        for c in cands:
            print("    %s" % c)
        bundles = self._list_bundles(args)
        if not bundles:
            print(pal.paint("\n  No backups found yet.\n", "yellow"))
            return
        print(pal.paint("\n  Backups (newest first):", "green"))
        for c in bundles:
            print("    %s" % c)
        print()

    def _fail_backup(self, bundle, msg):
        """Abort a backup: DELETE the partial bundle first (it already holds a mode-600 copy of .env
        with ENCRYPTION_KEY, so a half-written bundle must never be left on disk), then fail."""
        shutil.rmtree(bundle, ignore_errors=True)
        self._fail("%s - the incomplete backup was removed." % msg)

    def _backup_stopped(self, bundle, exc, paused, resumed):
        """A backup ended (Ctrl-C, or a signal SignalsEndTheRun turned into StoppedBySignal) while it held the
        deployment paused (`paused`: the services it paused or may have), which its `finally` has resumed by now
        (`resumed`: _resume_after_backup's answer, None if that was cut short): remove the incomplete bundle (it
        holds a copy of .env), and say so as far as there is still somewhere to say it (a closed terminal takes no
        output)."""
        shutil.rmtree(bundle, ignore_errors=True)
        what = exc.signal_name() if isinstance(exc, StoppedBySignal) else "Ctrl-C"
        if not paused:
            state = "nothing had been paused"
        elif resumed:
            state = "the deployment was resumed"
        elif resumed is None:
            state = "the deployment may still be paused: run docker unpause %s" % " ".join(paused)
        else:
            state = "the deployment could not be resumed (see the warning above)"
        left = ("and %s, which is not a backup, could not be removed: remove it yourself (it holds a copy of .env)"
                % bundle if os.path.lexists(bundle) else "and the incomplete backup was removed")
        try:
            print(self.pal.paint("\n  The backup was stopped (%s) before it was complete: %s, %s." % (what, state, left),
                                 "yellow"))
        except (OSError, ValueError):
            pass

    def _do_backup(self, env, args=None):
        """Dump the current set into ONE bundle dir: the paired .env (mode-600), a tar.gz per data
        volume, and a manifest with a NON-secret coupling fingerprint. Skips a volume that doesn't
        exist (e.g. brand). The running deployment is paused (not stopped) for as long as its volumes are
        archived (_pause_for_backup), so the database and the stored files are copies of one moment.

        Refused, with nothing written, while a restore of the set began to replace its volumes and did not finish
        (RESTORE_INCOMPLETE): they hold part of a backup, and a bundle of them would pass for a whole one, which a
        restore would put back, its marker gone, and start."""
        pal = self.pal
        prefix = volume_prefix(env)
        if not env:
            self._fail("no .env found - nothing to back up (run Setup first)")
        found = self._incomplete_restores()
        if prefix in found:
            self._fail("set '%s' is not backed up: %s A backup of its volumes now would hold that part of a backup as "
                       "if it were the whole set. Nothing was written."
                       % (prefix, self._incomplete_restore_text(prefix, found[prefix])))
        names = set_volume_names(prefix)
        ts = _timestamp()
        # Absolute: the archives are written by a container through `-v <bundle>:/dest`, and Docker takes a source
        # that is not an absolute path for the name of a volume.
        root = os.path.abspath(self._backup_root(args))
        bundle = os.path.join(root, "dockvault-%s-%s" % (prefix, ts))
        # The stamp has second resolution, so two backups inside one second want the same
        # directory and the second one dies on FileExistsError. That used to need an operator
        # typing quickly; now that an upgrade takes a backup on its own, two in a second is
        # something the tool can do to itself -- and failing to back up is the one outcome the
        # gate above must not produce by accident.
        suffix = 1
        while os.path.exists(bundle):
            bundle = os.path.join(root, "dockvault-%s-%s-%d" % (prefix, ts, suffix))
            suffix += 1
        print(pal.paint("  Backup will be written under: %s" % root, "cyan"))
        try:
            os.makedirs(bundle)
            # Restrict the whole bundle dir to the owner (makedirs' mode is umask-masked): the volume
            # tar.gz archives inside include the DB dump + key material, so keep them unreadable to
            # other local users, matching the mode-600 .env copy.
            if os.name != "nt":
                os.chmod(bundle, 0o700)
        except OSError as exc:
            self._fail("could not create the backup directory %s: %s" % (bundle, exc))
        # On Windows the folder takes the ACL of where it is made, and a folder outside the user's profile (a second
        # drive, a share) commonly lets every signed-in user read and change it: it is restricted to this user, SYSTEM
        # and Administrators before anything is written into it, and what is written inherits that.
        if os.name == "nt" and not restrict_folder_to_owner(bundle):
            self._fail_backup(bundle, "could not restrict the backup folder %s to your user (icacls), and its "
                                      "archives hold the database and the keys" % bundle)
        # the paired .env FIRST, mode-600 (it holds ENCRYPTION_KEY)
        _copy_secret(self._env_path(), os.path.join(bundle, "env"))
        tighten_secret_file(os.path.join(bundle, "env"))
        # A change of AUDIT_CHAIN_KEY that is not finished: the audit log's chain may still be under the old key,
        # which is then only in the file this set keeps beside .env. The bundle carries it (sealed with env under
        # --lock), and a restore puts it back, so the restored chain's key is always in a file. Another set's kept
        # key is that set's: never carried here.
        try:
            kept = kept_chain_key_path(self.root, prefix)
        except ValueError as exc:
            self._fail_backup(bundle, str(exc))
        carried = os.path.lexists(kept)
        if carried:
            try:
                with open(kept, encoding="utf-8") as f:
                    key = kept_chain_key_text(f.read())
            except (OSError, ValueError) as exc:
                self._fail_backup(bundle, "could not read %s, which holds the key the audit log's chain may still "
                                          "be under (%s)" % (kept, exc))
            if key is None:
                self._fail_backup(bundle, "%s should hold the key the audit log's chain may still be under, and "
                                          "holds none: finish that change first (python dockvault.py audit rekey "
                                          "--old-key-file %s)" % (kept, kept))
            try:
                write_kept_key(os.path.join(bundle, KEPT_CHAIN_KEY_BUNDLE), key)
            except OSError as exc:
                self._fail_backup(bundle, "could not copy %s into the backup (%s)" % (kept, exc))
        planned = [(role, names[role], "%s.tar.gz" % VOLUME_BASENAMES[role]) for role in BACKUP_ROLES
                   if volume_exists(names[role])]           # e.g. brand isn't always present
        # One moment for every volume: the database and the stored files are archived one after the other, and a
        # file deleted (or uploaded) by the running app between the two would leave a restored row without its file.
        # So the running deployment is paused (not stopped: its connections wait) until the last archive is
        # written, and resumed whatever happens. A deployment that is not running is archived as it is.
        # "Whatever happens" includes the end of the run itself: Ctrl-C, and the signals that would otherwise end the
        # process without resuming anything (a closed SSH session, kill, a timeout: SignalsEndTheRun), resume the
        # deployment first; the incomplete backup is then removed (_backup_stopped).
        paused, maybe_paused, resumed = [], [], None
        try:
            with SignalsEndTheRun() as signals:
                try:
                    why = self._pause_for_backup(paused, maybe_paused, signals)
                    if why:
                        self._fail_backup(bundle, why)
                    for role, vol, archive in planned:
                        print(pal.paint("  archiving %s ..." % vol, "cyan"))
                        if not tar_volume(vol, bundle, archive):
                            self._fail_backup(bundle, "failed to archive volume %s (backup incomplete)" % vol)
                finally:
                    signals.hold()          # a second signal does not cut the resume short
                    resumed = self._resume_after_backup(paused, maybe_paused)
        except (StoppedBySignal, KeyboardInterrupt) as exc:
            self._backup_stopped(bundle, exc, paused + maybe_paused, resumed)
            raise
        entries = []
        for role, vol, archive in planned:
            # The archive was written by a container through a bind mount, and its exit code says only that the
            # container's tar finished. Docker can see another folder than this host's under the same path (a daemon
            # on another host, a confined one), and then nothing reaches the bundle. So the archive must be here, on
            # this host, not empty, and read through whole, before the backup counts it; its checksum and size go
            # into the manifest, for the restore to check against.
            try:
                digest, size = check_archive_file(os.path.join(bundle, archive))
            except ValueError as exc:
                self._fail_backup(bundle, "the archive of volume %s did not reach the backup folder whole (%s): "
                                          "the backup is not complete. If Docker runs on another host or in a "
                                          "confined package, it writes elsewhere; back up to a folder Docker "
                                          "shares with this host" % (vol, exc))
            entries.append({"role": role, "name": vol, "archive": archive, "sha256": digest, "size": size})

        # Refuse a bundle that captured no data. Skipping a volume that is not there is right for
        # `brand`, which genuinely may not exist -- but the same `continue` used to swallow the
        # case where NONE of them were found, and the command still printed "Backup written" in
        # green. That happens without any docker fault: an .env whose VAULT_VOLUME_PREFIX no longer
        # names the live volumes produces exactly it. The restore side then reports success too,
        # because it iterates the manifest's volume list and there is nothing in it. An operator
        # would be told they were covered at both ends, and an upgrade gate would accept it and go
        # ahead with a change that cannot be undone.
        captured = {entry["role"] for entry in entries}
        missing = [role for role in BACKUP_REQUIRED_ROLES if role not in captured]
        if missing:
            self._fail_backup(
                bundle,
                "no archive was made for %s -- the volumes named by this .env "
                "(VAULT_VOLUME_PREFIX=%r) were not found, so this bundle holds no data. Check the "
                "prefix matches the running deployment." % (", ".join(missing), prefix))

        manifest = build_backup_manifest(prefix, env.get("DEPLOYMENT_ID", "default"), entries,
                                          gen_salt(), env, created=ts)
        try:
            with open(os.path.join(bundle, "manifest.json"), "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
        except OSError as exc:
            self._fail_backup(bundle, "failed to write the manifest: %s" % exc)

        # Opt-in sealing: encrypt the bundle's plaintext 'env' (which holds ENCRYPTION_KEY) into an
        # 'env.enc' and remove the plaintext, so a stolen backup cannot decrypt the stored files. The
        # volume archives themselves are NOT re-encrypted here (storage is already ciphertext at rest;
        # sealing the key that opens it is what makes the bundle safe) -- so the pg_data metadata tar
        # stays as-is. Default off (owner decision A).
        # Sealed only when explicitly requested (--lock, or the interactive prompt in backup() for the
        # EXPLICIT backup command -- NEVER the pre-upgrade auto-backup, whose rollback must stay
        # restorable without a passphrase the operator may not have during a failed upgrade).
        seal = bool(getattr(args, "lock", False)) if args else False
        if seal:
            self._seal_bundle_env(bundle, args)

        print(pal.paint("\n  Backup written to: %s" % bundle, "green"))
        print("    %d volume(s) + the paired %s + manifest.json"
              % (len(entries), "env.enc (SEALED)" if seal else ".env"))
        if seal:
            print(pal.paint("  The bundle's .env is SEALED - keep the passphrase/recovery key to "
                            "restore it. Without either, this backup cannot be restored.\n", "yellow"))
        else:
            print(pal.paint("  *** This bundle's 'env' holds ENCRYPTION_KEY - store the whole bundle "
                            "somewhere safe (off-host), or re-run with --lock to seal it. ***\n", "yellow"))
        if carried:
            print(pal.paint("  A change of AUDIT_CHAIN_KEY is not finished here: the bundle also carries the old key "
                            "kept in %s%s, which the audit log's chain may still be under, and a restore puts it "
                            "back beside .env. Finish the change: python dockvault.py audit rekey --old-key-file %s\n"
                            % (kept, " (sealed with its env)" if seal else "", kept), "yellow"))

    def _pause_for_backup(self, paused, maybe_paused, signals=None):
        """Pause every running container of the deployment that writes to the volumes a backup archives (the app's,
        in either layout, and the database), so that every archive is of one moment: a tar of a running data
        directory is not (Postgres keeps writing pages behind it), and neither is a storage volume archived while the
        app deletes or adds files after the database was archived. Returns None, or why not when a running one could
        not be paused.

        Each service paused goes into `paused`, and one whose pause may have taken effect without saying so into
        `maybe_paused`: a pause cut short (a timeout, Ctrl-C), or one whose docker ran and did not answer 0. Both are
        the caller's lists, which it resumes (_resume_after_backup) however this ends. Each pause runs held (`signals`,
        SignalsEndTheRun.hold): a signal that comes meanwhile is raised once the pause has answered and its service is
        in a list. Its docker child runs out of reach of the signals that end the run (own_session_kwargs), which
        are sent to the run's whole process group."""
        running = [s for s in BACKUP_PAUSED_SERVICES if container_running(s)]
        # Docker says a paused container runs. One already paused (by the operator, or left so by a backup that was
        # killed) writes nothing: it is archived as it is, neither paused again (Docker refuses that, which would
        # stop the backup) nor resumed afterwards (this backup did not pause it).
        already = [s for s in running if container_paused(s) is True]
        if already:
            one = len(already) == 1
            print(self.pal.paint("  %s %s paused already: archived as %s, and left paused (docker unpause %s resumes "
                                 "%s)." % (", ".join(already), "is" if one else "are", "it is" if one else "they are",
                                           " ".join(already), "it" if one else "them"), "yellow"))
        running = [s for s in running if s not in already]
        if not running:
            return None
        print(self.pal.paint("  pausing the deployment while its volumes are copied (%s; it does not answer meanwhile)"
                             " ..." % ", ".join(running), "cyan"))
        for service in running:
            if signals is not None:
                signals.hold()
            try:
                try:
                    r = self._run_dc("pause", service, timeout=60, **own_session_kwargs())
                except subprocess.TimeoutExpired:
                    maybe_paused.append(service)
                    r, said = None, "it did not answer within 60 seconds"
                except (OSError, subprocess.SubprocessError) as exc:
                    r, said = None, "it could not be run: %s" % " ".join(str(exc).split())[-200:]
                except BaseException:
                    maybe_paused.append(service)
                    raise
                if getattr(r, "returncode", 1) != 0:
                    # A docker that ran and did not answer 0 may have paused it all the same: one a signal ended after
                    # its request reached Docker (systemd's stop signals every process of the service, whatever its
                    # session) answers as one Docker refused. Resumed on its own, as a pause cut short is.
                    if r is not None:
                        if service not in maybe_paused:
                            maybe_paused.append(service)
                        said = (" ".join((getattr(r, "stderr", "") or "").split())[-300:]
                                or "it answered %s" % getattr(r, "returncode", "?"))
                    # Docker's own reason, and the way through that needs no pause: a deployment that is not running
                    # is archived as it is.
                    return ("could not pause %s for the backup (docker: %s), and the volumes are only copies of one "
                            "moment while nothing writes to them; nothing was archived. A deployment that is not "
                            "running is archived as it is: stop it (python dockvault.py stop), back it up (python "
                            "dockvault.py backup --action backup) and start it again (python dockvault.py start). An "
                            "update then goes on with --backup-verified; what changes after that backup is not in it"
                            % (service, said))
                paused.append(service)
            finally:
                if signals is not None:
                    signals.release()
        return None

    def _resume_after_backup(self, paused, maybe_paused=()):
        """Resume what _pause_for_backup paused, and each service that may have paused without saying so on its own
        (it may never have paused, and Docker then refuses to resume it). A resume Docker did not confirm (an unpause
        that did not answer 0, or a service Docker does not say is running) is asked about again and, while still
        paused, tried again (RESUME_RETRIES): the signal that ends the run can end the docker child of the first try,
        one started in the very moment it comes, or any one under systemd's stop, which signals every process of the
        service. Says how to do it by hand when Docker would not. Returns True when everything paused is running
        again (or nothing was), False otherwise. Each docker child runs out of reach of the signals that end the run
        (own_session_kwargs)."""
        import time
        started = time.monotonic()
        failed = []
        if paused:
            try:
                r = self._run_dc("unpause", *paused, timeout=60, **own_session_kwargs())
                if getattr(r, "returncode", 1) != 0:
                    failed.extend(paused)
            except (OSError, subprocess.SubprocessError):
                failed.extend(paused)
        for service in maybe_paused:
            try:
                self._run_dc("unpause", service, timeout=60, **own_session_kwargs())
            except (OSError, subprocess.SubprocessError):
                pass
            if container_paused(service) is not False:
                failed.append(service)
        for _again in range(RESUME_RETRIES):
            if not failed or time.monotonic() - started > RESUME_RETRY_SECONDS:
                break
            time.sleep(RESUME_RETRY_GAP)
            still = []
            for service in failed:
                if container_paused(service) is False:
                    continue                    # running: the try before did resume it
                try:
                    self._run_dc("unpause", service, timeout=20, **own_session_kwargs())
                except (OSError, subprocess.SubprocessError):
                    pass
                if container_paused(service) is not False:
                    still.append(service)
            failed = still
        if failed:
            try:
                print(self.pal.paint("  WARNING: the deployment could not be resumed after the backup: run docker "
                                     "unpause %s" % " ".join(failed), "red"))
            except (OSError, ValueError):
                pass                        # nowhere left to say it (a closed terminal)
        return not failed

    def _seal_bundle_env(self, bundle, args):
        """Seal bundle/env -> bundle/env.enc (envelope encryption; passphrase + one-time recovery key),
        then remove the plaintext env. Verify-before-destroy: the sealed file must decrypt back to the
        exact bytes before the plaintext is removed. A seal FAILURE keeps the complete plaintext bundle
        (a valid UNSEALED backup) rather than discarding it. Reuses the same crypto as `dockvault.py
        lock`. The old AUDIT_CHAIN_KEY a bundle carries during an unfinished key change is sealed the same way,
        under the same data key (so the same passphrase or recovery key opens it), and verified too. The manifest
        is authenticated under that data key as well (BUNDLE_MANIFEST_MAC), so that the checksums it records of the
        archives cannot be changed by anyone without the passphrase or the recovery key."""
        pal = self.pal
        env_file = os.path.join(bundle, "env")
        enc_file = os.path.join(bundle, "env.enc")
        kept_file = os.path.join(bundle, KEPT_CHAIN_KEY_BUNDLE)
        kept_enc = kept_file + ".enc"
        mac_file = os.path.join(bundle, BUNDLE_MANIFEST_MAC)

        def _abort(msg):
            # A failed OPTIONAL seal must NOT destroy the complete plaintext bundle: drop any partial
            # env.enc and keep {env, volumes, manifest} -- it restores normally, just unsealed.
            for partial in (enc_file, kept_enc, mac_file):
                try:
                    os.remove(partial)
                except OSError:
                    pass
            self._fail("could not seal the backup (%s). The backup at %s is COMPLETE but UNSEALED "
                       "(its plaintext env is kept and it restores normally); re-run backup --lock "
                       "to seal it." % (msg, bundle))

        interactive = not (args and getattr(args, "non_interactive", False))
        has_pass_source = bool(args and (getattr(args, "passphrase_file", None)
                                         or getattr(args, "passphrase_stdin", False)))
        if not interactive and not has_pass_source:
            _abort("--lock --non-interactive needs --passphrase-file or --passphrase-stdin")
        fernet = self._require_fernet()
        try:
            with open(env_file, "rb") as f:
                env_bytes = f.read()
        except OSError as exc:
            _abort("could not read the bundle env: %s" % exc)
        if interactive:
            print(pal.paint(
                "\n  Set a passphrase to seal this backup's .env. You will also get a one-time recovery "
                "key.\n  Lose BOTH and this backup cannot be restored.", "yellow"))
        passphrase = self._read_passphrase(args, confirm=True)
        import datetime as _dt
        now_iso = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
        # The env, and after it the line that says this bundle's manifest is authenticated, naming the bundle's own data
        # key (sealed_bundle_payload): sealed with the env, it cannot be taken out to make the bundle look like one made
        # before MACs.
        dek = fernet.generate_key()
        payload = sealed_bundle_payload(env_bytes, dek)
        enc_text, dek = env_lock_seal(fernet, payload, passphrase, dek=dek,
                                      hint=getattr(args, "hint", None), now_iso=now_iso)
        self._atomic_write_secret(enc_file, enc_text)
        # Verify-before-destroy: the freshly written env.enc must decrypt (by passphrase) back to the
        # exact bytes, or _abort keeps the complete plaintext bundle. (The recovery key is the same
        # DEK this verify confirmed opens the payload, so the recovery-key path is verified too.) A restore must read
        # it back as this env with its line, the line naming the key it was opened with.
        try:
            with open(enc_file, encoding="utf-8") as f:
                check_bytes, opened_with = env_lock_open(fernet, f.read(), passphrase=passphrase)
        except (OSError, EnvLockError) as exc:
            _abort("sealed env failed verification (%s)" % exc)
        if check_bytes != payload:
            _abort("sealed env did not round-trip")
        if split_sealed_bundle_payload(check_bytes, opened_with) != (env_bytes, True):
            _abort("the sealed env does not read back as one whose manifest is authenticated")
        # The manifest, authenticated under the same data key: the checksums it records of the archives then show not
        # only damage but any change by whoever can write the bundle without that key (manifest_mac). Written and read
        # back before the plaintext env goes. (A backup writes its manifest before it seals; a bundle without one is
        # refused by every restore, so there is nothing to authenticate.)
        if os.path.lexists(os.path.join(bundle, "manifest.json")):
            try:
                with open(os.path.join(bundle, "manifest.json"), "rb") as f:
                    manifest_bytes = f.read()
                self._atomic_write_secret(mac_file, json.dumps({"dockvault_manifest_mac": 1,
                                                                "hmac_sha256": manifest_mac(dek, manifest_bytes)}) + "\n")
                with open(mac_file, encoding="utf-8") as f:
                    written = json.load(f).get("hmac_sha256")
            except (OSError, ValueError, AttributeError) as exc:
                _abort("the manifest could not be authenticated (%s)" % exc)
            if not manifest_mac_matches(dek, manifest_bytes, written):
                _abort("the manifest's MAC did not read back")
        carried = os.path.lexists(kept_file)
        if carried:
            try:
                with open(kept_file, "rb") as f:
                    kept_bytes = f.read()
                kept_text, _ = env_lock_seal(fernet, kept_bytes, passphrase, dek=dek, now_iso=now_iso)
                self._atomic_write_secret(kept_enc, kept_text)
                with open(kept_enc, encoding="utf-8") as f:
                    sealed_kept = f.read()
                by_passphrase, _ = env_lock_open(fernet, sealed_kept, passphrase=passphrase)
                by_recovery_key, _ = env_lock_open(fernet, sealed_kept, recovery_key=dek)
            except (OSError, EnvLockError) as exc:
                _abort("the old AUDIT_CHAIN_KEY the bundle carries could not be sealed (%s)" % exc)
            if not (by_passphrase == by_recovery_key == kept_bytes):
                _abort("the sealed old AUDIT_CHAIN_KEY did not round-trip")
        os.remove(env_file)
        if carried:
            try:
                os.remove(kept_file)
            except OSError as exc:
                print(pal.paint("  WARNING: could not remove the plaintext %s from the sealed bundle (%s): remove it "
                                "yourself (its sealed copy is %s)." % (kept_file, exc, kept_enc), "red"))
        # Recovery-key output: on a controlling terminal _show_recovery_key uses /dev/tty; in a
        # non-interactive run WITHOUT --recovery-out do NOT print it to stdout (it could be captured
        # into a log kept beside the bundle) -- the passphrase already restores, and --recovery-out is
        # the safe channel for keeping a recovery key.
        if interactive or getattr(args, "recovery_out", None):
            self._show_recovery_key(dek, args)
        else:
            print(pal.paint("  Sealed. The recovery key was NOT printed (non-interactive without "
                            "--recovery-out); restore with the passphrase, or re-run with "
                            "--recovery-out to capture a recovery key off-host.", "yellow"))

    def _unseal_bundle_env(self, enc_path, args, with_key=False):
        """Decrypt a sealed bundle's env.enc and return the plaintext env BYTES (never written to
        disk), or (the bytes, the data key, whether it says its manifest is authenticated) with `with_key`: the data
        key opens what else the bundle sealed with it, and a bundle sealed since manifests were authenticated says so
        in its sealed payload (split_sealed_bundle_payload; the line is not part of the env). Uses the recovery key
        when --recovery-key-file/-stdin or --use-recovery-key is given, else the passphrase. A wrong credential fails
        here, before the restore touches the stack."""
        fernet = self._require_fernet()
        try:
            with open(enc_path, encoding="utf-8") as f:
                enc_text = f.read()
        except OSError as exc:
            self._fail("could not read the sealed backup env: %s" % exc)
        use_recovery = bool(args and (getattr(args, "recovery_key_file", None)
                                      or getattr(args, "use_recovery_key", False)))
        try:
            if use_recovery:
                env_bytes, dek = env_lock_open(fernet, enc_text,
                                               recovery_key=self._read_recovery_key(args))
            else:
                env_bytes, dek = env_lock_open(fernet, enc_text,
                                               passphrase=self._read_passphrase(args, confirm=False))
        except EnvLockError as exc:
            self._fail("cannot open the sealed backup (%s) - the deployment was NOT touched." % exc)
        env_bytes, authenticated = split_sealed_bundle_payload(env_bytes, dek)
        return (env_bytes, dek, authenticated) if with_key else env_bytes

    def _carried_chain_key(self, bundle, dek):
        """The old AUDIT_CHAIN_KEY `bundle` carries (a backup taken during an unfinished key change): from its
        plaintext copy, or its sealed one opened with the data key `dek` of the bundle's env.enc; None when it
        carries none. Fails, before anything is touched, on one that cannot be read or is not a key."""
        plain = os.path.join(bundle, KEPT_CHAIN_KEY_BUNDLE)
        sealed = plain + ".enc"
        try:
            if os.path.lexists(plain):
                with open(plain, encoding="utf-8") as f:
                    text = f.read()
            elif os.path.lexists(sealed):
                if dek is None:
                    self._fail("this backup's old AUDIT_CHAIN_KEY is sealed but its env is not - refusing to "
                               "restore a bundle sealed in part")
                with open(sealed, encoding="utf-8") as f:
                    raw, _ = env_lock_open(self._require_fernet(), f.read(), recovery_key=dek)
                text = raw.decode("utf-8")
            else:
                return None
        except (OSError, ValueError, EnvLockError) as exc:
            self._fail("could not read the old AUDIT_CHAIN_KEY this backup carries (%s) - the deployment was NOT "
                       "touched." % exc)
        key = kept_chain_key_text(text)
        if key is None:
            self._fail("the old AUDIT_CHAIN_KEY this backup carries is not a key - the deployment was NOT touched.")
        return key

    def _recorded_archives(self, manifest):
        """{archive name: (SHA-256 hex, size)} the backup recorded, for each manifest entry of a known role that has a
        checksum; {} for a backup made before backups recorded them. Fails on a checksum or size that is not one, on
        a manifest format this tool does not know, and on a manifest of the format that records every archive's
        checksum (BACKUP_MANIFEST_FORMAT) that lacks one: only a format-1 manifest, made before checksums, has none."""
        fmt = manifest_format(manifest)
        if fmt is None:
            self._fail("this backup's manifest is of format %r, which this version of the tool does not know - "
                       "refusing to restore. Nothing changed." % (manifest.get("dockvault_backup"),))
        out, without = {}, []
        for e in (manifest.get("volumes") or []):
            if not isinstance(e, dict) or e.get("role") not in VOLUME_BASENAMES:
                continue                     # an unknown role is refused below, with the volumes
            if "sha256" not in e and "size" not in e:
                without.append(e["role"])
                continue
            digest, size = e.get("sha256"), e.get("size")
            if not (isinstance(digest, str) and ARCHIVE_DIGEST_RE.match(digest)
                    and isinstance(size, int) and not isinstance(size, bool) and size > 0):
                self._fail("the backup's manifest records a checksum or size for volume role %r that is not one - "
                           "refusing to restore. Nothing changed." % e.get("role"))
            out["%s.tar.gz" % VOLUME_BASENAMES[e["role"]]] = (digest, size)
        if fmt >= 2 and without:
            self._fail("this backup's manifest is of the format that records the checksum of every archive, and it "
                       "records none for %s: it was changed since the backup was made. Refusing to restore; nothing "
                       "changed." % ", ".join(without))
        return out

    def _check_manifest_mac(self, bundle, manifest_bytes, dek, has_digests, authenticated=False, fmt=1):
        """A sealed bundle: its manifest must be the one it was sealed with, proven by the MAC beside it
        (BUNDLE_MANIFEST_MAC, under the key env.enc was just opened with). Every bundle sealed since manifests were
        authenticated has one, and says so where nobody without its key can take it out (`authenticated`: its sealed
        payload, split_sealed_bundle_payload); its manifest also records checksums, in format 2 (`fmt`). Such a bundle
        without a MAC lost it on the way: refused. One that says none of it was sealed before manifests were
        authenticated: restored, with a notice."""
        mac_path = os.path.join(bundle, BUNDLE_MANIFEST_MAC)
        if not os.path.lexists(mac_path):
            if authenticated:
                self._fail("this sealed backup was made with its manifest authenticated (its sealed env says so), "
                           "but %s, which proves the manifest is the one sealed with it, is missing: refusing to "
                           "restore. Nothing changed." % BUNDLE_MANIFEST_MAC)
            if has_digests or fmt >= 2:
                self._fail("this sealed backup's manifest records the checksums of its archives but %s, which proves "
                           "the manifest is the one sealed with it, is missing: refusing to restore. Nothing changed."
                           % BUNDLE_MANIFEST_MAC)
            print(self.pal.paint(
                "  Note: this sealed backup was made before backups authenticated their manifest, so nothing shows "
                "that its manifest and archives are the ones it was sealed with. Restore it only if you are sure "
                "nobody changed it.", "yellow"))
            return False
        try:
            with open(mac_path, encoding="utf-8") as f:
                doc = json.load(f)
            recorded = doc.get("hmac_sha256") if isinstance(doc, dict) else None
        except (OSError, ValueError):
            recorded = None
        if not manifest_mac_matches(dek, manifest_bytes, recorded):
            self._fail("the manifest of this sealed backup is not the one it was sealed with (its MAC does not match): "
                       "it was changed since the backup was made. Refusing to restore; nothing changed.")
        return True

    def _check_bundle_archives(self, bundle, plan, recorded):
        """Before the restore stops or clears anything, each archive it is about to extract must: read through whole
        as a tar.gz on this host (check_archive_file); be, byte for byte, the archive the backup made, when the
        backup recorded its checksum; and be the very file Docker sees through the bind mount the extraction uses
        (archive_digest_in_docker), so that an extraction cannot fail for want of it after a volume was emptied.
        Fails with nothing changed otherwise. A backup that recorded no checksums (made before backups did) is
        restored with a notice, its archives still read through whole. Returns {archive name: its SHA-256 hex as
        checked here}, which each extraction must read again (untar_volume's `sha256`): the files can change
        after this check."""
        pal = self.pal
        digests = {}
        checked = [archive for _vol, archive in plan if archive in recorded]
        if checked and len(checked) != len(plan):
            self._fail("this backup's manifest records the checksum of some of its archives only, as no backup "
                       "writes it: it was changed since. Refusing to restore; nothing changed.")
        print(pal.paint("  Checking the backup's archives before anything is stopped (each is read through) ...",
                        "cyan"))
        for vol, archive in plan:
            path = os.path.join(bundle, archive)
            try:
                digest, size = check_archive_file(path)
            except ValueError as exc:
                self._fail("the archive for volume %s cannot be restored: %s. Refusing to restore; nothing changed."
                           % (vol, exc))
            want = recorded.get(archive)
            if want is not None and (digest, size) != want:
                self._fail("%s is not the archive this backup made (its checksum is not the one the backup recorded): "
                           "it was changed or damaged since the backup. Refusing to restore; nothing changed." % path)
            seen, why = archive_digest_in_docker(bundle, archive)
            if seen != digest:
                self._fail("Docker does not see %s as this host does (%s), and the restore extracts each archive "
                           "through Docker. Run the restore where Docker shares this folder with the host. Refusing "
                           "to restore; nothing changed." % (path, why or "it sees another file there"))
            digests[archive] = digest
        if plan and not checked:
            print(pal.paint(
                "  Note: this backup was made before backups recorded the checksums of their archives: each was read "
                "through whole, but nothing shows it is the archive the backup made.", "yellow"))
        return digests

    def _do_restore(self, args=None):
        """Restore a bundle: verify the bundle's .env matches its volumes (coupling fingerprint),
        then STOP the stack, REPLACE each target volume's contents from the backup, install the
        paired .env, and restart + health-check. Refuses a mismatched bundle, a bundle missing its
        .env/manifest, or clobbering existing volumes without --force; confirms an over-existing
        interactive restore with a typed set-name gate.

        The current .env is kept before anything is stopped (_keep_env_before_restore): it is the only key to the
        volumes of the set the host was on, which a restore of another set's backup leaves as they were. A copy
        that cannot be made refuses the restore with nothing changed, and so does a .env sealed by `lock` (a lock
        after the restore would seal the backup's .env over it)."""
        pal = self.pal
        if self._is_locked():
            self._fail(".env is locked (sealed in .env.enc): unlock it first (python dockvault.py unlock), then restore "
                       "again, so that the restore can keep it before it installs the backup's .env (a lock after the "
                       "restore would seal the backup's .env over it). Nothing changed.")
        interactive = not (args and getattr(args, "non_interactive", False))
        bundle = getattr(args, "bundle_dir", None) if args else None
        if not bundle and interactive:
            cands = self._list_bundles(args)     # every search root, newest first, full paths
            if not cands:
                roots = self._backup_search_roots(args)
                self._fail("no backups found under: %s (pass --bundle-dir)"
                           % (", ".join(roots) if roots else "(no backup directory yet)"))
            print(pal.paint("\n  Backups (newest first):", "cyan"))
            for i, c in enumerate(cands, 1):
                print("    %d) %s" % (i, c))      # full path disambiguates same-name bundles across roots
            sel = ask("Which backup number", pal).strip()
            if not (sel.isdigit() and 1 <= int(sel) <= len(cands)):
                self._fail("not a listed backup")
            bundle = cands[int(sel) - 1]
        if not bundle or not os.path.isdir(bundle):
            self._fail("backup bundle not found (pass --bundle-dir)")
        # Absolute before anything uses it: each archive is extracted through `-v <bundle>:/src`, and Docker takes a
        # source that is not an absolute path for the name of a volume (an empty one, made there and then).
        bundle = os.path.abspath(bundle)
        man_path = os.path.join(bundle, "manifest.json")
        env_path = os.path.join(bundle, "env")
        enc_path = os.path.join(bundle, "env.enc")
        # A sealed bundle carries env.enc instead of a plaintext env. Decrypt it into MEMORY here --
        # before manifest/coupling checks and long before the stack is stopped -- so a wrong
        # passphrase/recovery key aborts with the deployment intact and no plaintext ever hits disk.
        sealed_env_bytes, sealed_dek, authenticated = None, None, False
        if not os.path.exists(env_path) and os.path.exists(enc_path):
            sealed_env_bytes, sealed_dek, authenticated = self._unseal_bundle_env(enc_path, args, with_key=True)
        if not os.path.exists(man_path) or (sealed_env_bytes is None and not os.path.exists(env_path)):
            self._fail("that bundle is missing manifest.json or its env - refusing to restore")
        try:
            with open(man_path, "rb") as f:
                manifest_bytes = f.read()
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (OSError, ValueError) as exc:
            self._fail("could not read the manifest: %s" % exc)
        if not isinstance(manifest, dict):
            self._fail("the backup's manifest is not one this tool writes - refusing to restore")
        # What the backup recorded of each archive (its checksum and size), before anything of the manifest is used:
        # a sealed bundle's manifest is first proven to be the one it was sealed with. Only a bundle that is old by
        # every sign (format 1, no checksums, and for a sealed one, a sealed env that does not say its manifest is
        # authenticated) is restored without that proof, with a notice.
        recorded = self._recorded_archives(manifest)
        if sealed_dek is not None:
            self._check_manifest_mac(bundle, manifest_bytes, sealed_dek, bool(recorded), authenticated=authenticated,
                                     fmt=manifest_format(manifest))
        bundle_env = parse_env(sealed_env_bytes.decode("utf-8") if sealed_env_bytes is not None
                               else open(env_path, encoding="utf-8").read())
        # COUPLING: the bundle's .env must be the one its volumes were created with - never restore
        # volumes without their matching .env (same rule the pre-start secret guard enforces).
        if not verify_backup_coupling(bundle_env, manifest):
            self._fail("the 'env' in this backup does NOT match its volumes (coupling check failed) - "
                       "refusing to restore a mismatched bundle.")
        prefix = manifest.get("volume_prefix") or volume_prefix(bundle_env)
        # NEVER trust the volume NAMES / archive filenames from the (possibly crafted) manifest - a
        # hostile `name` like "/etc" would redirect the `-v` mount to the host. Validate the prefix and
        # RECONSTRUCT each volume name + archive from the prefix + a known role instead.
        if not valid_volume_prefix(prefix):
            self._fail("the backup's volume_prefix %r is not a valid name - refusing to restore" % prefix)
        names = set_volume_names(prefix)
        plan = []
        roles = []
        for e in (manifest.get("volumes") or []):
            role = e.get("role") if isinstance(e, dict) else None
            if role not in VOLUME_BASENAMES:
                self._fail("the backup manifest lists an unknown volume role %r - refusing to restore" % role)
            roles.append(role)
        # Restored in BACKUP_ROLES order whatever order the manifest lists them in (an older bundle archived
        # the keys volume last): keys first, so the restore mark lands before any other volume.
        order = {role: i for i, role in enumerate(BACKUP_ROLES)}
        for role in sorted(roles, key=lambda r: order.get(r, len(order))):
            plan.append((names[role], "%s.tar.gz" % VOLUME_BASENAMES[role]))
        head_rel = chain_head_relpath(bundle_env)
        # The old AUDIT_CHAIN_KEY a backup taken during an unfinished key change carries: put back beside .env
        # below, as the file the change kept for this set. A different one already here for this set belongs to
        # this host's own unfinished change of it: it is never written over, and the restore waits until that
        # change is settled. Another set's kept key is left as it is.
        carried = self._carried_chain_key(bundle, sealed_dek)
        try:
            kept_here = kept_chain_key_path(self.root, prefix)
        except ValueError as exc:
            self._fail("%s - refusing to restore" % exc)
        if carried is not None and os.path.lexists(kept_here):
            try:
                with open(kept_here, encoding="utf-8") as f:
                    here = kept_chain_key_text(f.read())
            except (OSError, ValueError):
                here = None
            if here != carried:
                self._fail("%s holds another old AUDIT_CHAIN_KEY of set '%s': a change of its key here is not "
                           "finished, and this backup carries the key of its own unfinished change. Finish the change "
                           "here (python dockvault.py audit rekey --old-key-file %s), or move that file somewhere "
                           "safe, then restore again. Nothing was changed." % (kept_here, prefix, kept_here))
        # A restore of this set that began to replace its volumes and did not finish (its marker, RESTORE_INCOMPLETE):
        # this one replaces them again, and removes the marker once it has installed the backup's .env.
        was_incomplete = prefix in self._incomplete_restores()
        if was_incomplete:
            print(pal.paint("  Note: an earlier restore of set '%s' did not finish (%s): this restore replaces its "
                            "volumes again." % (prefix, restore_incomplete_path(self.root, prefix)), "yellow"))
        force = bool(getattr(args, "force", False)) if args else False
        existing = [v for v, _ in plan if volume_exists(v)]
        if existing and not force:
            self._fail("these target volumes already exist: %s - Reset them first, or pass --force to "
                       "REPLACE their contents from this backup." % ", ".join(existing))
        # Verify every archive is present BEFORE we stop the stack or clear a single volume, so a
        # missing-file bundle can never leave a half-restored (stopped, partly-wiped) deployment.
        for vol, archive in plan:
            if not os.path.exists(os.path.join(bundle, archive)):
                self._fail("the bundle is missing %s (for volume %s) - refusing to restore" % (archive, vol))
        # And every archive is read through whole, is the one the backup made, and is what Docker sees through the
        # mount the extraction uses, all before anything is stopped or cleared (_check_bundle_archives). Each
        # extraction below reads it again and must read the bytes checked here (untar_volume's sha256).
        digests = self._check_bundle_archives(bundle, plan, recorded)
        # Restore REPLACES the current data with the backup. Confirm loudly for an interactive
        # over-existing restore (mirrors the Reset typed-name gate); --non-interactive --force skips it.
        if existing and interactive:
            print(pal.paint(
                "\n  RESTORE will STOP the deployment and REPLACE the current data of set '%s' with "
                "this backup.\n  The current stored files, database and keys are DISCARDED and cannot "
                "be recovered without another backup." % prefix, "red"))
            typed = ask("Type the set name '%s' to confirm (anything else cancels)" % prefix, pal).strip()
            if typed != prefix:
                print(pal.paint("  Cancelled - nothing was changed.\n", "yellow"))
                return
        # Keep the current .env before anything is stopped or replaced (see _keep_env_before_restore). A restore
        # that ends before the backup's .env is installed leaves the current one in place, so the copy is then
        # removed again: it would be a second plaintext copy of the same secrets.
        current_prefix, kept_env = self._keep_env_before_restore(prefix, sealed_env_bytes, env_path)
        try:
            # Stop the stack FIRST: extracting pg_data under a live Postgres both fails to take effect (the
            # running server keeps serving its cached state - the "restored, saw the same files" trap) and
            # risks corrupting the cluster. down (no -v) removes the containers but KEEPS every volume,
            # which we then overwrite in place.
            if current_prefix != prefix and container_running(DB_CONTAINER):
                print(pal.paint("  Note: a different deployment (set '%s') is running and will be stopped "
                                "to restore set '%s' (%s)." % (current_prefix, prefix,
                                                               "its data and its .env are kept" if kept_env
                                                               else "its data is kept"),
                                "yellow"))
            print(pal.paint("  Stopping the deployment before restore (data volumes are kept) ...", "cyan"))
            self._stop_stack()
            # `down` can fail or time out (e.g. a slow Postgres checkpoint) and _stop_stack swallows that.
            # NEVER clear a volume out from under a live container: if the database is still up after the
            # stop attempt, abort with the data intact (a fresh-host restore has no container, so this is
            # skipped there).
            if container_running(DB_CONTAINER):
                self._fail("could not stop the running deployment before restore (the database is still "
                           "up) - aborting; your data is intact. Stop the stack and retry.")
            # The head record of the keys volume about to be replaced (a restore over the same set), kept for the
            # restore mark: what it knew the restore then undoes.
            replaced_record = None
            if head_rel and volume_exists(names["keys"]):
                replaced_record = read_volume_json(names["keys"], head_rel)
            # REPLACE each volume: clear it IN PLACE (keeps the volume + its DockVault labels) then extract
            # the archive. Strictly the RECONSTRUCTED names[role] - never a manifest-supplied name.
            marked = False
            replaced = []

            def stopped_part_way(why, vol, touched, backup_changed=False):
                # Every stop from here on: nothing more is cleared or extracted, .env is not installed and the stack
                # is not started, and the message says what was replaced and the way back. The restore-incomplete
                # marker says it too, to the next start: it stays (with what was changed) when a volume was, and goes
                # when none was.
                changed = list(replaced) + ([vol] if touched and vol and vol not in replaced else [])
                message = self._restore_stopped_part_way(why, vol, replaced, touched, prefix, current_prefix, bundle,
                                                         backup_changed=backup_changed,
                                                         earlier_incomplete=was_incomplete)
                if changed:
                    try:
                        self._mark_restore_incomplete(prefix, bundle, changed, backup_changed)
                    except OSError:
                        pass                     # the marker written before the first clear stays
                if changed or was_incomplete:
                    message += (" Until set '%s' is restored, %s (%s says why)."
                                % (prefix, restore_incomplete_refusers("it"), restore_incomplete_path(self.root, prefix)))
                else:
                    self._drop_restore_incomplete(prefix)
                self._fail(message)

            # Before the first volume is touched: the marker that the restore of this set has begun (removed once the
            # backup's .env is installed). Without it, nothing is changed.
            try:
                self._mark_restore_incomplete(prefix, bundle)
            except OSError as exc:
                stopped_part_way("could not write %s, which keeps the deployment from being started on volumes a "
                                 "restore did not finish (%s)" % (restore_incomplete_path(self.root, prefix), exc),
                                 None, False)
            for vol, archive in plan:
                print(pal.paint("  restoring %s (replacing current contents) ..." % vol, "cyan"))
                # If the clear fails (e.g. the volume is still held), do NOT extract on top - that would
                # silently degrade to the old MERGE (the exact "restored, saw the same files" trap). The
                # stack is already stopped, so aborting loudly is the safe state.
                if not clear_volume(vol):
                    stopped_part_way("could not clear volume %s before restoring it (the backup is never merged over "
                                     "data left in it)" % vol, vol, True)
                # The extraction reads the archive again: it copies it first and extracts the copy only when it is the
                # archive checked above. Other bytes (someone changed the bundle since) are not extracted at all: the
                # restore stops there, with this volume emptied, and says not to start.
                try:
                    extracted = untar_volume(vol, bundle, archive, sha256=digests.get(archive))
                except ArchiveChanged as exc:
                    stopped_part_way("%s changed after the restore checked it (its copy taken for the extraction has "
                                     "the checksum %s): nothing of it was extracted, and volume %s, emptied for it, "
                                     "is empty" % (os.path.join(bundle, archive), exc.seen, vol), vol, True,
                                     backup_changed=True)
                if not extracted:
                    stopped_part_way("could not extract %s into volume %s" % (archive, vol), vol, True)
                replaced.append(vol)
                if vol == names["keys"] and head_rel:
                    # Right after the keys volume, before any other volume or .env: the restore mark. While it is
                    # there the audit pruner deletes nothing, until `audit accept-restore` (run below once the
                    # stack is up, or by hand) accepts the restore. A restore stopped part way leaves it in place.
                    restored_record = read_volume_json(vol, head_rel)
                    if restored_record is not None or replaced_record is not None:
                        import datetime as _dt
                        mark = {"at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                "bundle": os.path.basename(os.path.normpath(bundle)), "record": replaced_record,
                                "restored_record": restored_record}
                        if not write_volume_file(vol, head_rel + ".restore-pending", json.dumps(mark)):
                            stopped_part_way("could not write the restore mark into volume %s (it keeps the audit "
                                             "log's pruner from deleting until the restore is accepted)" % vol,
                                             vol, False)
                        marked = True
            # The old AUDIT_CHAIN_KEY the bundle carries, beside .env and on the disk before the .env that does not
            # hold it: the restored chain may be under it.
            if carried is not None and not os.path.lexists(kept_here):
                try:
                    write_kept_key(kept_here, carried)
                except OSError as exc:
                    stopped_part_way("could not put the old AUDIT_CHAIN_KEY this backup carries into %s (%s)"
                                     % (kept_here, exc), None, False)
            # install the paired .env (mode-600) so the restored set is whole again. For a sealed bundle
            # the plaintext was decrypted into memory above; write those exact bytes.
            if sealed_env_bytes is not None:
                self._atomic_write_secret(self._env_path(), sealed_env_bytes)
            else:
                _copy_secret(env_path, self._env_path())
            tighten_secret_file(self._env_path())
        except BaseException:
            self._drop_kept_env_if_unneeded(kept_env)
            raise
        # The set is whole again: its restore-incomplete marker goes. One that cannot be removed keeps the set from
        # being started, this restore's own start too (_recreate_stack): the restore says so and does not try.
        unmarked = self._drop_restore_incomplete(prefix)
        if not unmarked:
            print(pal.paint("  WARNING: could not remove %s, though the restore finished: delete it yourself (while it "
                            "is there, %s)." % (restore_incomplete_path(self.root, prefix),
                                                restore_incomplete_refusers("set '%s'" % prefix)), "red"))
        print(pal.paint("\n  Restored set '%s' (%d volume(s)) + its .env." % (prefix, len(plan)), "green"))
        self._say_what_the_restore_kept(kept_env, current_prefix, prefix)
        finish = "python dockvault.py audit accept-restore"
        rekey = "python dockvault.py audit rekey --old-key-file %s" % kept_here
        if carried is not None:
            # The restored chain may be under the old key: it moves to the current key, with the old key's proof,
            # before the restore is accepted (accept-restore refuses while the chain is under a key the server
            # does not hold).
            finish = ("%s (it says so when the chain is already under the current key), then %s, then remove %s once "
                      "the rekey has said the key it holds is no longer needed" % (rekey, finish, kept_here))
            print(pal.paint("  This backup was taken while a change of AUDIT_CHAIN_KEY was not finished: the old key, "
                            "which the audit log's chain may still be under, is back in %s." % kept_here, "yellow"))
        # Bring the restored set back up on ITS .env and health-check, so restore leaves a RUNNING
        # deployment serving the restored state (not a stopped stack the operator must remember to
        # start, which is what let the old no-op behaviour hide).
        if not unmarked:
            self._say_how_to_finish(marked, carried, finish, rekey, kept_here)
            self._fail("restored, but not started: delete %s, then start it (python dockvault.py start)."
                       % restore_incomplete_path(self.root, prefix))
        ok, _ = docker_available()
        if not ok:
            print(pal.paint("  Docker is not available - start the restored set later with Start.\n",
                            "yellow"))
            self._say_how_to_finish(marked, carried, finish, rekey, kept_here)
            return
        print(pal.paint("  Starting the restored deployment ...", "cyan"))
        profiles = self._load_env().get("COMPOSE_PROFILES", "combined")
        if not self._start_secure_stack():
            self._tail_logs(self._web_service(profiles))
            self._say_how_to_finish(marked, carried, finish, rekey, kept_here)
            self._fail("restored, but the stack did not start - the last log lines are above.")
        if not self._wait_secure_healthy(profiles):
            self._tail_logs(self._web_service(profiles))
            print(pal.paint("  Restored and started, but the vault did NOT report healthy yet - "
                            "logs above.\n", "red"))
            self._say_how_to_finish(marked, carried, finish, rekey, kept_here)
            return
        print(pal.paint("  Restored and healthy.\n", "green"))
        if marked and interactive and carried is None:
            print(pal.paint("  Finishing the restore of the audit log's integrity chain:", "cyan"))
            self._audit_host_command(argparse.Namespace(no_reseal=False, yes=False, confirm=None,
                                                        old_key_file=None), "accept-restore")
        else:
            self._say_how_to_finish(marked, carried, finish, rekey, kept_here)

    def _mark_restore_incomplete(self, prefix, bundle, changed=(), backup_changed=False):
        """Write set `prefix`'s restore-incomplete marker (RESTORE_INCOMPLETE): the backup the restore is from, when it
        began, the volumes it changed so far, and whether that backup changed while it was read. Raises OSError."""
        import datetime as _dt
        doc = {"volume_prefix": prefix, "bundle": bundle,
               "at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
               "volumes": list(changed), "backup_changed": bool(backup_changed)}
        replace_file_durably(restore_incomplete_path(self.root, prefix), json.dumps(doc, indent=2) + "\n")

    def _drop_restore_incomplete(self, prefix):
        """Remove set `prefix`'s restore-incomplete marker, if there is one. False when one is there and could not be
        removed."""
        path = os.path.join(self.root, RESTORE_INCOMPLETE + prefix)
        if not os.path.lexists(path):
            return True
        try:
            os.remove(path)
        except OSError:
            return False
        return True

    def _incomplete_restores(self):
        """{set prefix: its marker's document ({} when it cannot be read)} of each restore here that began to replace a
        set's volumes and did not finish (RESTORE_INCOMPLETE)."""
        found = {}
        # The folder is escaped: its own name may hold [, ], * or ? (vault[1]), and then no marker would be found.
        for path in sorted(glob.glob(os.path.join(glob.escape(self.root), RESTORE_INCOMPLETE + "*"))):
            prefix = os.path.basename(path)[len(RESTORE_INCOMPLETE):]
            try:
                with open(path, encoding="utf-8") as f:
                    doc = json.load(f)
            except (OSError, ValueError):
                doc = {}
            found[prefix] = doc if isinstance(doc, dict) else {}
        return found

    def _incomplete_restore_text(self, prefix, doc):
        """What a restore of set `prefix` that did not finish left (from its marker's document `doc`), and the way
        back: the same restore again, or a restore from a trusted copy when that backup changed while it was read, or
        Reset; or, for an operator who knows the volumes are as wanted, the marker's own removal."""
        marker = os.path.join(self.root, RESTORE_INCOMPLETE + prefix)
        bundle = doc.get("bundle") if isinstance(doc.get("bundle"), str) and doc.get("bundle") else None
        at = doc.get("at") if isinstance(doc.get("at"), str) else None
        said = ("a restore of set '%s'%s%s began to replace its volumes and did not finish: they hold part of a backup"
                % (prefix, " from %s" % bundle if bundle else "", " (%s)" % at if at else ""))
        if doc.get("backup_changed") is True:
            way = ("restore it from a copy of a backup of set '%s' you trust, in a folder only you can write (that "
                   "backup changed while it was read): python dockvault.py backup --action restore --bundle-dir <that "
                   "folder> --force" % prefix)
        elif bundle:
            arg = '"%s"' % bundle if any(c.isspace() for c in bundle) else bundle
            way = ("run the restore again (it starts over from the backup): python dockvault.py backup --action restore "
                   "--bundle-dir %s --force" % arg)
        else:
            way = ("restore it again from its backup: python dockvault.py backup --action restore --bundle-dir <the "
                   "backup> --force")
        return ("%s. To get it back, %s. Or, to start that set afresh, delete its volumes (python dockvault.py reset, "
                "with that set's .env). If you know its volumes are as you want them, delete %s." % (said, way, marker))

    def _refuse_incomplete_restore(self, command, prefix=None, notes=True, tail="Nothing was started."):
        """Stop `command`, which starts the deployment, while a restore of the set it would start (`prefix`, else the
        set .env names) began to replace its volumes and did not finish (RESTORE_INCOMPLETE): its volumes hold part of
        a backup. With `notes`, says so for every other set's too, which `command` does not start. `tail` ends the
        refusal (what the command left as it was); a `command` of None is the stack's own start (_recreate_stack),
        whatever asked for it."""
        if prefix is None:
            prefix = volume_prefix(self._load_env())
        found = self._incomplete_restores()
        if notes:
            for other, doc in found.items():
                if other != prefix:
                    print(self.pal.paint("  Note: %s" % self._incomplete_restore_text(other, doc), "yellow"))
        if prefix in found:
            said = self._incomplete_restore_text(prefix, found[prefix])
            if command is None:
                self._fail("set '%s' is not started: %s %s" % (prefix, said, tail))
            self._fail("%s would start set '%s', but %s %s" % (command, prefix, said, tail))

    def _restore_stopped_part_way(self, why, vol, replaced, touched, prefix, current_prefix, bundle,
                                  backup_changed=False, earlier_incomplete=False):
        """The message of a restore that stops after it stopped the deployment (a volume that cannot be cleared, an
        archive that does not extract, a restore mark or a kept key that cannot be written): what happened, which
        volumes it changed (`replaced`, and `vol` when `touched`: a clear or an extraction that failed part way), that
        .env and the stack were left as they were, and the way back: the set the host was on, or the same restore run
        again from the same (checked, unchanged) backup. With `backup_changed` (an archive changed after the restore
        checked it), the backup is not that: the way back is a copy of a backup the operator trusts, in a folder
        nobody else can write. With `earlier_incomplete` (an earlier restore of the set did not finish), a stop that
        changed nothing leaves the set as that restore left it: not a set to start."""
        arg = '"%s"' % bundle if any(c.isspace() for c in bundle) else bundle
        again = "python dockvault.py backup --action restore --bundle-dir %s --force" % arg
        changed = list(replaced) + ([vol] if touched and vol and vol not in replaced else [])
        state = ("the volumes it replaced from the backup, or emptied in part, so far are: %s" % ", ".join(changed)
                 if changed else "no volume was changed")
        had_env = os.path.exists(self._env_path())
        lines = ["%s. The restore stopped there: the deployment is stopped, .env is as it was%s, and %s."
                 % (why, " (set '%s')" % current_prefix if had_env else " (there was none)", state)]
        if backup_changed:
            from_copy = ("copy a backup of set '%s' you trust into a folder only you can write, then restore from that "
                         "copy: python dockvault.py backup --action restore --bundle-dir <that folder> --force" % prefix)
            if had_env and prefix != current_prefix:
                lines.append("The set the host was on, '%s', is untouched: python dockvault.py start brings it back. "
                             "To restore set '%s', %s." % (current_prefix, prefix, from_copy))
            else:
                lines.append("Do not start the deployment now: volume %s is empty and the volumes before it hold the "
                             "backup's data. Do not restore from %s again: it changed while it was read. Instead, %s."
                             % (vol, bundle, from_copy))
            return " ".join(lines)
        if had_env and prefix != current_prefix:
            lines.append("The set the host was on, '%s', is untouched: python dockvault.py start brings it back. To "
                         "restore set '%s', fix the cause, then run the restore again: %s"
                         % (current_prefix, prefix, again))
        elif not changed and earlier_incomplete:
            lines.append("This restore changed nothing, but an earlier restore of the set did not finish: its volumes "
                         "hold part of a backup. Fix the cause, then run the restore again: %s" % again)
        elif had_env and not changed:
            lines.append("Nothing of the set was changed: python dockvault.py start brings it back as it was. Or fix "
                         "the cause, then run the restore again: %s" % again)
        else:
            lines.append("Do not start the deployment now: its volumes hold the backup's data in part. Fix the cause, "
                         "then run the restore again (it starts over from the backup, which is unchanged): %s" % again)
        return " ".join(lines)

    def _keep_env_before_restore(self, prefix, sealed_env_bytes, env_path):
        """Keep the current .env before a restore installs the backup's .env over it. `prefix` is the set the
        backup restores; `sealed_env_bytes` / `env_path` hold the backup's .env. Returns (the prefix of the set the
        host is on, the kept copy's path or None).

        The current .env holds the secrets of the set the host is on (its database password, ENCRYPTION_KEY):
        without it that set's volumes cannot be read. A restore of another set's backup leaves those volumes as
        they were, so the copy is the way back to them. A restore over the same set replaces its data, and the .env
        it had is kept as well, for a setting changed since the backup. Nothing is kept when there is no .env, or
        when it is the backup's own .env byte for byte (nothing would be lost).

        The copy is .env.<prefix of the set the host is on>, the name Volumes' repoint finds a set's .env by, or
        .env.<prefix>.<n> when copies of it are there already (n after the highest, so that the newest copy has the
        highest number) or that name is one of RESERVED_ENV_NAMES: never written over a file
        already there. A current .env, or a backup's, that cannot be read, and a copy that cannot be made, refuse
        the restore here, before anything is stopped or replaced, with nothing changed."""
        current_prefix = volume_prefix(self._load_env())
        env_now = self._env_path()
        if not os.path.exists(env_now):
            return current_prefix, None
        try:
            with open(env_now, "rb") as f:
                current = f.read()
            if sealed_env_bytes is not None:
                restored = bytes(sealed_env_bytes)
            else:
                with open(env_path, "rb") as f:
                    restored = f.read()
        except OSError as exc:
            self._fail("could not read the current .env or the backup's to keep the current one before the restore "
                       "(%s). Nothing changed." % exc)
        if current == restored:
            return current_prefix, None
        label = current_prefix if valid_volume_prefix(current_prefix) else "before-restore"
        try:
            kept = self._keep_env_copy(label, current)
        except OSError as exc:
            # The name the copy was being made under (.env.<prefix>.N when the first was taken).
            tried = getattr(exc, "kept_as", None) or next(env_copy_names(self.root, label))
            self._fail("could not keep the current .env as %s (%s): without it the volumes of set '%s' could not be "
                       "read again after the restore. Nothing changed." % (tried, exc, current_prefix))
        print(self.pal.paint("  Kept the current .env (set '%s') as %s before the restore." % (current_prefix, kept),
                             "cyan"))
        return current_prefix, kept

    def _keep_env_copy(self, label, data):
        """Write `data` (the current .env's bytes) to .env.<label>, or to .env.<label>.<n> after the highest copy
        there, when a name of that set is taken (a file, a folder or a link: never followed, never written over) or
        reserved (env_copy_names). Created
        mode 600, written through to the disk with its name, tightened like .env and read back to the same bytes
        before its path is returned. Raises OSError, with the name it was making as `kept_as`; a file this call
        created but could not finish is removed."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        for dest in env_copy_names(self.root, label):
            # A name already there, of any kind, is passed over before anything opens it: on Windows, creating a
            # file with O_EXCL at a link to nothing is not refused, it creates the name the link points to.
            if os.path.lexists(dest):
                continue
            try:
                fd = os.open(dest, flags, 0o600) if os.name != "nt" else os.open(dest, flags)
                break
            except OSError as exc:
                # A name made there since that check is passed over too, whatever the refusal said: Windows refuses
                # to create a file over a folder with PermissionError, not FileExistsError. Only a refusal for a
                # name that is free (a folder that cannot be written to, a full disk) stops the copy.
                if os.path.lexists(dest):
                    continue
                exc.kept_as = dest
                raise
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            tighten_secret_file(dest)
            sync_directory(self.root)
            with open(dest, "rb") as f:
                if f.read() != data:
                    raise OSError("%s does not read back as it was written" % dest)
        except BaseException as exc:
            try:
                os.remove(dest)
            except OSError:
                pass
            if isinstance(exc, OSError):
                exc.kept_as = dest
            raise
        return dest

    def _drop_kept_env_if_unneeded(self, kept):
        """After a restore that ended before it installed the backup's .env: remove the copy
        _keep_env_before_restore made, as long as .env still reads exactly as the copy (the current one is then
        still in place, and the copy would only be a second plain-text copy of its secrets). Left alone whenever
        .env reads otherwise (the install had begun) or either file cannot be read."""
        if not kept:
            return
        try:
            with open(kept, "rb") as a, open(self._env_path(), "rb") as b:
                unneeded = a.read() == b.read()
        except OSError:
            return
        if unneeded:
            try:
                os.remove(kept)
            except OSError:
                pass

    def _say_what_the_restore_kept(self, kept, current_prefix, prefix):
        """After the backup's .env is installed: what the copy _keep_env_before_restore made is for, and for a
        restore of another set, the command that goes back to the set the host was on."""
        if not kept:
            return
        pal = self.pal
        arg = '"%s"' % kept if any(c.isspace() for c in kept) else kept
        if not valid_volume_prefix(current_prefix):
            # Its VAULT_VOLUME_PREFIX names no volume set (no volumes could have that name): no set to go back to.
            print(pal.paint("  The .env this host had before the restore is kept in %s. Its VAULT_VOLUME_PREFIX, %r, "
                            "is not a volume set's name, so it does not open any set's volumes. It is plain text and "
                            "holds secrets, and 'lock' does not seal it: copy from it what you need, then delete it."
                            % (kept, current_prefix), "yellow"))
        elif current_prefix != prefix:
            print(pal.paint("  The set this host was on, '%s', is as it was: its volumes are untouched, and its .env "
                            "is kept in %s." % (current_prefix, kept), "yellow"))
            print(pal.paint("  To go back to it: python dockvault.py volumes --non-interactive --action repoint "
                            "--target-prefix %s --env-source %s" % (current_prefix, arg), "yellow"))
            print(pal.paint("  That file is plain text and holds the ENCRYPTION_KEY and database password of set '%s', "
                            "and 'lock' does not seal it: keep it, and a copy of it off this host, for as long as you "
                            "may want that set back." % current_prefix, "yellow"))
        else:
            print(pal.paint("  The .env this set had before the restore is kept in %s. It does not open the restored "
                            "data (the backup's own .env does): copy from it any setting you changed since the "
                            "backup, then delete it (it is plain text and holds secrets, and 'lock' does not seal "
                            "it)." % kept, "yellow"))

    def _say_how_to_finish(self, marked, carried, finish, rekey, kept):
        """What is left after a restore: accepting it (`finish`, when it was marked), and finishing the change of
        AUDIT_CHAIN_KEY the backup was taken during (`carried`: the key is back in `kept`)."""
        pal = self.pal
        if marked:
            print(pal.paint("  Nothing in the audit log is deleted until you finish the restore: %s\n" % finish,
                            "yellow"))
        elif carried is not None:
            print(pal.paint("  Finish the change of AUDIT_CHAIN_KEY: %s, then remove %s once it says the key it holds "
                            "is no longer needed\n" % (rekey, kept), "yellow"))

    def _load_env(self):
        """Parse the current .env (best-effort: {} if absent or unreadable)."""
        env, env_path = {}, self._env_path()
        try:
            if os.path.exists(env_path):
                env = parse_env(open(env_path, encoding="utf-8").read())
        except OSError:
            pass
        return env

    def _archive_kept_key(self, prefix):
        """Move the old AUDIT_CHAIN_KEY the set `prefix` kept (an unfinished change of its key) aside once Reset has
        destroyed the set, as its .env is: its chain is gone, and a new set with the same prefix must not take it
        for its own. Never over another file. Returns where it went, or None when there was none (or it could not
        be moved, which is said)."""
        try:
            kept = kept_chain_key_path(self.root, prefix)
        except ValueError:
            return None
        if not os.path.lexists(kept):
            return None
        base = os.path.join(self.root, KEPT_CHAIN_KEY_REMOVED + prefix)
        dest, n = base, 1
        while os.path.lexists(dest):
            dest = "%s.%d" % (base, n)
            n += 1
        try:
            os.rename(kept, dest)
            sync_directory(self.root)
        except OSError as exc:
            print(self.pal.paint("  Could not move %s aside (%s): it holds the old AUDIT_CHAIN_KEY of the set just "
                                 "destroyed; move it away before a new set with the same prefix changes its key."
                                 % (kept, exc), "yellow"))
            return None
        return dest

    def _archive_env(self, label):
        """Move the current .env aside as .env.<label> so it isn't lost / left live. Collision-safe
        (never clobbers an existing archive; numbered after the copies there) and never under a reserved name
        (env_copy_names: .env.<label>.1, .2,
        ... instead). Returns the archive path, or None if there was no .env."""
        env_path = self._env_path()
        if not os.path.exists(env_path):
            return None
        for dest in env_copy_names(self.root, label):
            if not os.path.lexists(dest):
                break
        os.replace(env_path, dest)
        return dest

    def _volumes_overview(self, env):
        """Print the managed volume sets grouped physically by prefix, marking the current one."""
        pal = self.pal
        cur_prefix = volume_prefix(env) if env else None
        print(pal.paint("\n  DockVault volume sets", "cyan"))
        if env:
            print("  current set (VAULT_VOLUME_PREFIX): %s   bundle: %s"
                  % (cur_prefix, (env.get("DEPLOYMENT_ID") or "default")))
        sets = group_volumes_by_prefix(list_managed_volumes())
        if sets:
            for prefix, recs in sets:
                mark = "   <- current" if prefix == cur_prefix else ""
                print(pal.paint("\n  set '%s'%s" % (prefix, mark), "green"))
                for r in sorted(recs, key=lambda x: x["name"]):
                    print("    %-9s %s" % (r["role"] or "?", r["name"]))
        else:
            print(pal.paint("\n  (no labelled volume sets yet)", "yellow"))
        legacy = list_legacy_volumes()
        if legacy:
            print(pal.paint("\n  legacy (unlabelled) volumes - the 'dockvault-vault' set:", "yellow"))
            for name in legacy:
                print("    %s" % name)

    def volumes(self, args=None):
        """Volume-set manager: list managed sets and Reuse / Create-new / Repoint. Interactive by
        default; arg-mode via args.volume_action (reuse|new|repoint) for scripting/tests. Every choice
        upholds the bundle invariant: a set's volumes and its .env are created / installed together."""
        pal = self.pal
        ok, msg = docker_available()
        if not ok:
            print(pal.paint("\n  %s\n" % msg, "yellow"))
            return
        env = self._load_env()
        self._volumes_overview(env)
        interactive = not (args and getattr(args, "non_interactive", False))
        action = getattr(args, "volume_action", None) if args else None
        if not action and interactive:
            print(pal.paint("\n  Actions:", "cyan"))
            print("    1) Reuse the current set (default - no change)")
            print("    2) Create a NEW set (fresh volumes + a fresh paired .env; keeps the current set)")
            print("    3) Repoint to another set (needs that set's .env)")
            action = {"2": "new", "3": "repoint"}.get(ask("Choose 1/2/3", pal, "1").strip(), "reuse")
        plan = plan_volume_action(action or "reuse")
        if not plan:
            self._fail("unknown volume action %r (reuse/new/repoint)" % action)
        if plan["action"] == "reuse":
            print(pal.paint("\n  Keeping the current set. Run Setup to (re)start it.\n", "green"))
        elif plan["action"] == "new":
            self._volume_new(env, args)
        else:
            self._volume_repoint(env, args)

    def _volume_new(self, env, args=None):
        """Author a FRESH set (new prefix + brand-new secrets) with its own .env, archiving the current
        one. Does NOT start it (run Setup next); the current set's volumes are left intact. Refused while .env is
        sealed (_refuse_while_locked): the sealed set's .env could not be archived first."""
        pal = self.pal
        self._refuse_while_locked("volumes --action new")
        interactive = not (args and getattr(args, "non_interactive", False))
        if interactive and not confirm(
                "Create a NEW empty set (fresh secrets + .env)? Your current set is kept.", pal, default=False):
            print(pal.paint("  Cancelled.\n", "yellow"))
            return
        new_id = gen_deployment_id()
        new_prefix = "%s-%s" % (DEFAULT_PROJECT, new_id)
        archived = self._archive_env(volume_prefix(env)) if env else None
        cfg = new_set_config(env, new_prefix, new_id)
        if write_env(self._env_path(), build_env_lines(cfg)):
            print(pal.paint("  Wrote a fresh .env for set '%s' (restricted to your user)." % new_prefix, "green"))
        else:
            print(pal.paint("  Wrote a fresh .env - WARNING: could not restrict its permissions "
                            "(it holds ENCRYPTION_KEY); secure it yourself.", "yellow"))
        if archived:
            self._warn_env_archived(archived)
        if cfg.get("_generated_admin_pw"):
            # Show the freshly-generated admin password on the controlling terminal only (like the
            # recovery key), so a redirected/tee'd stdout or CI log can't capture it.
            self._emit_secret(pal.paint("  New set's admin password: %s   (auto-generated - store it NOW)"
                                        % cfg["admin_password"], "bold", "yellow"), label="admin-password")
        print(pal.paint("  Run Setup to build + start the new (empty) set.\n", "cyan"))

    def _volume_repoint(self, env, args=None):
        """Point the deployment at ANOTHER set. Requires that set's matching .env (auto-found as
        .env.<prefix>, or --env-source), verifies it names the target set, and validates it against the
        set's data via the secret guard - refusing on mismatch and RESTORING the current .env. Refused while .env is
        sealed (_refuse_while_locked)."""
        pal = self.pal
        self._refuse_while_locked("volumes --action repoint")
        interactive = not (args and getattr(args, "non_interactive", False))
        cur_prefix = volume_prefix(env)
        others = [p for p, _ in group_volumes_by_prefix(list_managed_volumes()) if p and p != cur_prefix]
        target = getattr(args, "target_prefix", None) if args else None
        if not target and interactive:
            if not others:
                print(pal.paint("  No other labelled sets to repoint to.\n", "yellow"))
                return
            print(pal.paint("\n  Other sets:", "cyan"))
            for i, p in enumerate(others, 1):
                print("    %d) %s" % (i, p))
            sel = ask("Which set number", pal).strip()
            if not (sel.isdigit() and 1 <= int(sel) <= len(others)):
                self._fail("not a listed set")
            target = others[int(sel) - 1]
        if not target:
            self._fail("no target set (pass --target-prefix)")
        # locate the target set's .env: an explicit source, else the auto-archive, else prompt.
        src = getattr(args, "env_source", None) if args else None
        if not src:
            cands = kept_env_copies(self.root, target)       # the newest copy first, by its number
            if len(cands) > 1 and interactive:
                print(pal.paint("\n  Kept copies of set '%s''s .env (the newest first):" % target, "cyan"))
                for i, c in enumerate(cands, 1):
                    print("    %d) %s" % (i, c))
                sel = ask("Which copy", pal, "1").strip()
                if not (sel.isdigit() and 1 <= int(sel) <= len(cands)):
                    self._fail("not a listed copy")
                src = cands[int(sel) - 1]
            elif cands:
                src = cands[0]
            elif interactive:
                src = ask("Path to the .env for set '%s'" % target, pal).strip()
        if not src or not os.path.exists(src):
            self._fail("need the .env that belongs to set '%s' (not found - pass --env-source)" % target)
        tgt_env = parse_env(open(src, encoding="utf-8").read())
        ok, missing = env_is_reusable(tgt_env)
        if not ok:
            self._fail("that .env is missing %s - it can't be the set's paired .env" % ", ".join(missing))
        if volume_prefix(tgt_env) != target:
            self._fail("that .env points at set '%s', not '%s' - refusing a mismatched pairing"
                       % (volume_prefix(tgt_env), target))
        # Switching sets can't run alongside the current stack (fixed container names), so stop it
        # first (containers only; volumes kept). Then archive the current .env, install the target's,
        # and validate it against the set's data.
        self._stop_stack()
        archived_cur = self._archive_env(cur_prefix)
        _copy_secret(src, self._env_path())
        tighten_secret_file(self._env_path())
        if not self._guard_db_secret(self._load_env()):
            # the installed .env does NOT match the target set's data -> undo, restore the original.
            self._stop_db_only()
            try:
                os.remove(self._env_path())
            except OSError:
                pass
            if archived_cur:
                os.replace(archived_cur, self._env_path())
            print(pal.paint("  Repoint verification FAILED - restored your previous .env. Nothing changed.\n", "red"))
            return
        self._stop_db_only()   # the guard started the target's vault-db to probe it; stop it (run Setup to start fully)
        print(pal.paint("  Repointed to set '%s'. Run Setup to start it.\n" % target, "green"))

    def reset(self, args=None):
        """DESTROY the current set's data (docker compose down -v) after a strong, typed confirmation,
        then move .env aside so a later Setup starts truly fresh. IRREVERSIBLE for the volumes' data."""
        pal = self.pal
        ok, msg = docker_available()
        if not ok:
            self._fail(msg)
        env = self._load_env()
        prefix = volume_prefix(env)
        names = set_volume_names(prefix)
        print(pal.paint("\n  RESET will PERMANENTLY DELETE this set's data:", "red"))
        print("    set / prefix : %s" % prefix)
        for role in VOLUME_ROLES:
            print("    %-9s %s" % (role, names[role]))
        print(pal.paint("  This runs 'docker compose down -v': the stored files, database, and keys are", "red"))
        print(pal.paint("  GONE and cannot be recovered without a backup. Back up first if unsure.", "red"))
        interactive = not (args and getattr(args, "non_interactive", False))
        confirmed = bool(getattr(args, "confirm", False)) if args else False
        if interactive:
            typed = ask("Type the set name '%s' to confirm (anything else cancels)" % prefix, pal).strip()
            confirmed = (typed == prefix)
        if not confirmed:
            print(pal.paint("  Cancelled - nothing was deleted.\n", "yellow"))
            return
        try:
            r = self._run_dc("down", "-v", "--remove-orphans", capture=False, timeout=180)
        except (OSError, subprocess.SubprocessError) as exc:
            self._fail("teardown failed: %s" % exc)
        if getattr(r, "returncode", 1) != 0:
            # down -v did NOT succeed (e.g. a volume still in use) -> the data may survive. Do NOT move
            # the paired .env aside, or a later Setup would mint fresh secrets against surviving volumes
            # (the exact footgun this toolkit prevents). Leave everything as-is and report honestly.
            self._fail("'docker compose down -v' failed (exit %d) - the set was NOT destroyed and your "
                       ".env is untouched. A volume may still be in use; free it and retry." % r.returncode)
        archived = self._archive_env("removed-" + prefix)   # keep the (now-orphaned) .env, don't leave it live
        kept = self._archive_kept_key(prefix)
        # Its volumes are gone, and with them what a restore that did not finish left in them.
        self._drop_restore_incomplete(prefix)
        print(pal.paint("\n  Set '%s' destroyed." % prefix, "green"))
        if archived:
            print("  Its .env (no longer matching any data) was moved to: %s" % archived)
        if kept:
            print("  The old AUDIT_CHAIN_KEY its unfinished key change kept (its chain is gone) was moved to: %s"
                  % kept)
        print(pal.paint("  Run Setup to start a fresh deployment.\n", "cyan"))

    def _running_version(self, profiles=None):
        """(version, where_it_came_from). The container is asked first, and that is the fix.

        `VERSION` in the checkout describes what was last checked out, not what is running: the
        pull path rewrites DOCKVAULT_IMAGE and recreates from the published image without touching
        the file. Read it after a pull upgrade and the tool reports the version it was installed
        at, which then becomes the origin for every later hop -- including the comparison that
        decides whether the next change is a downgrade.

        Asked over `docker exec` rather than HTTP: the endpoint that carries the version sits
        behind whatever port and certificate the deployment chose, and a self-signed certificate on
        a non-default port is the normal case here, not an edge one.

        With nothing running to ask, the answer is a guess, and its source says so (it is never "the running
        container"): the highest of what the stopped web container's image holds in /app/VERSION (read with
        `docker cp`, which needs no running container), the release .env pins in DOCKVAULT_IMAGE, and this
        checkout's VERSION file. The highest, because the data may have been written by the newest of them, and
        a move from a guess that turns out lower than the truth is a downgrade the gates would not see.
        """
        service = self._web_service(profiles or self._load_env().get("COMPOSE_PROFILES", "combined"))
        try:
            out = subprocess.run(["docker", "exec", service, "cat", "/app/VERSION"],
                                 capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            out = None
        if out is not None and out.returncode == 0:
            found = (out.stdout or "").strip()
            if parse_semver(found):
                return found, "the running container"
        fallback = read_version_file(self.root)
        guesses = [(v, where) for v, where in (
            (self._stopped_container_version(service), "the version in the stopped %s container's image" % service),
            (release_image_version(self._load_env().get("DOCKVAULT_IMAGE")), "the release image .env names"),
            (fallback, "this checkout's VERSION file")) if parse_semver(v)]
        if not guesses:
            return fallback, "this checkout's VERSION file (nothing is running to ask)"
        best = max(guesses, key=lambda g: parse_semver(g[0]))       # the first of equals: the image's own file
        return best[0], "%s (nothing is running to ask)" % best[1]

    def _stopped_container_version(self, service):
        """The version in /app/VERSION of the `service` container, which need not be running (`docker cp` reads a
        stopped or restarting container's files), or None when there is no such container or no version in it."""
        import io
        import tarfile
        try:
            r = subprocess.run(["docker", "cp", "%s:/app/VERSION" % service, "-"], capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return None
        data = getattr(r, "stdout", None)
        if getattr(r, "returncode", 1) != 0 or not isinstance(data, (bytes, bytearray)):
            return None
        try:
            with tarfile.open(fileobj=io.BytesIO(bytes(data))) as tar:
                member = next((m for m in tar if m.isfile()), None)
                text = tar.extractfile(member).read(64).decode("utf-8", "replace").strip() if member else ""
        except (tarfile.TarError, OSError, ValueError, AttributeError):
            return None
        return text if parse_semver(text) else None

    def _describe_hop(self, plan, source, current, tag, down=False):
        """Print what the hop does. Returns nothing; the caller decides what to require, from the same
        backup_reason() this summary prints, so the two cannot disagree."""
        pal = self.pal
        print(pal.paint("\n  What this change involves", "cyan"))
        print("    described by : %s" % source)
        if not plan["known"]:
            print(pal.paint(
                "    NOT DESCRIBED: the matrix does not describe %s -> %s. This is treated as "
                "needing a backup and as possibly irreversible, because an undescribed change is "
                "not a safe one -- read the release notes before continuing."
                % (current, tag), "yellow"))
            return
        if plan.get("downgrade"):
            print("    steps        : %d adjacent release(s) back, taking back the upgrade %s -> %s"
                  % (len(plan["steps"]), tag.lstrip("vV"), current.lstrip("vV")))
        else:
            print("    steps        : %d adjacent release(s)" % len(plan["steps"]))
        print("    reversible   : %s" % ("no" if plan["irreversible"] else "yes"))
        why = backup_reason(plan, down)
        print("    backup       : %s" % (("required (%s)" % why) if why else "not required"))
        for condition in plan["conditions"]:
            print(pal.paint("    note         : %s" % clean_matrix_text(condition.get("summary", "")),
                            "yellow"))
            if condition.get("detect"):
                print("                   check with: %s" % clean_matrix_text(condition["detect"]))

    def _require_backup(self, args, interactive, reason):
        """Take a backup, or accept an operator's word that one exists. False = do not proceed.

        Takes one by default rather than looking for a recent bundle and trusting it. What this
        does NOT do is prove the backup restores -- verifying that means standing up a second
        deployment from it, which this command is not going to do behind the operator's back. The
        prompt says so rather than implying a guarantee it cannot make.
        """
        pal = self.pal
        print(pal.paint("\n  A backup is required: %s" % clean_matrix_text(reason), "yellow"))
        if args and getattr(args, "backup_verified", False):
            print("  --backup-verified given: proceeding on your own backup. This tool has not "
                  "checked that it exists or that it restores.")
            return True
        if interactive and not confirm("Take a backup now (recommended)?", pal, default=True):
            print(pal.paint("  Refusing to proceed without a backup. Re-run with "
                            "--backup-verified if you keep backups elsewhere.", "red"))
            return False
        try:
            self._do_backup(self._load_env(), args)
        except SystemExit:
            raise
        except Exception as exc:
            print(pal.paint("  the backup did not complete: %s" % exc, "red"))
            return False
        print(pal.paint("  Backup written. Note that it has not been test-restored.", "green"))
        return True

    def update(self, args=None):
        """Update menu: show the current version, list releases newest-first (fail-closed to a manual
        tag), pick one to upgrade OR downgrade to, WARN about the no-down-migration schema risk +
        recommend a Backup first, then either set DOCKVAULT_IMAGE + pull (default) or git-checkout +
        build (--source), recreate, and health-wait. Refused while .env is sealed by `lock`: an update writes .env,
        and a .env written then would hold only what it writes."""
        pal = self.pal
        if self._is_locked():
            self._fail(".env is locked (sealed in .env.enc): unlock it first (python dockvault.py unlock), then run "
                       "update again. Nothing changed.")
        self._refuse_incomplete_restore("update")
        ok, msg = docker_available()
        if not ok:
            self._fail(msg)
        if not self._container_logs_readable():
            raise SystemExit(1)
        env = self._load_env()
        current, version_source = self._running_version(env.get("COMPOSE_PROFILES", "combined"))
        interactive = not (args and getattr(args, "non_interactive", False))
        print(pal.paint("\n  DockVault update", "cyan"))
        print("  current version : %s  (from %s)" % (current, version_source))
        print("  update check    : %s (every %s min)" % (
            (env.get("UPDATE_CHECK_ENABLED") or "false"),
            env.get("UPDATE_CHECK_INTERVAL_MINUTES") or "360"))

        if newer_data_escape_set(env):
            print(pal.paint(
                "  %s is set in .env: this deployment starts even on data a newer version changed "
                "in a way it cannot read. Remove it once you are back on that version or have "
                "undone the change." % NEWER_DATA_ESCAPE, "yellow"))
        self._note_host_log_driver()

        tag = getattr(args, "tag", None) if args else None
        from_source = bool(getattr(args, "source", False)) if args else False
        # This checkout's matrix describes every version's lifecycle up to what it ships; use it to
        # decide which releases to OFFER (end-of-life ones are hidden) and to annotate the rest.
        local_matrix, _ = fetch_upgrade_matrix(None, root=self.root)
        # Lifecycle (eol / secure / vulnerabilities) changes AFTER a tag is cut, so read the
        # DISPLAY lifecycle from this checkout's copy merged ADD-ONLY with the copy on main; the
        # hard gates below stay on the tag-pinned matrices. Fixed URL, bounded, fail-safe to
        # source 'local'. The ceiling for a credible remote fix is the newest release tag we can
        # see, never the running version.
        _release_tags = sort_release_tags(fetch_release_tags())
        _lifecycle_ceiling = _release_tags[0] if _release_tags else None
        merged_lifecycle, lifecycle_source = merge_lifecycle_matrix(
            local_matrix, fetch_main_lifecycle_matrix(), _lifecycle_ceiling)
        # The install's release line: how long it gets security fixes, and its newest release, taken
        # from the releases list so only a release that exists is named.
        _line_note = line_support_note(merged_lifecycle, current)
        _line_newest = newest_on_line(_release_tags, current)
        if release_line(current) and _line_note:
            text = "  release line    : %s -- %s" % (release_line(current), _line_note)
            ended = _line_note.startswith(("security fixes ended", "no longer"))
            print(pal.paint(text, "yellow") if ended else text)
        if _line_newest and parse_semver(_line_newest) > parse_semver(current):
            _gone = len(_finding_keys(merged_lifecycle, current)
                        - _finding_keys(merged_lifecycle, _line_newest))
            text = "  newest on line  : %s" % _line_newest
            if _gone:
                text += " (fixes %d known %s in %s)" % (
                    _gone, "vulnerability" if _gone == 1 else "vulnerabilities", current)
            print(pal.paint(text, "green") if _gone else text)
        if not tag:
            tags = _release_tags
            if tags:
                offered = [t for t in tags if not is_eol(local_matrix, t)]
                hidden = len(tags) - len(offered)
                print(pal.paint("\n  Available releases (newest first):", "cyan"))
                for t in offered[:15]:
                    label = "   <- current" if parse_semver(t) == parse_semver(current) else ""
                    if t == _line_newest and not label:
                        label = "   <- newest of your line"
                    note = support_line(merged_lifecycle, t)
                    if note and note != "supported":
                        label += "   (%s)" % note
                    print("    %s%s" % (t, label))
                if not offered:
                    print(pal.paint("    (every reachable release is end-of-life)", "yellow"))
                elif all(version_vulnerabilities(merged_lifecycle, t) for t in offered
                         if _declares_version(merged_lifecycle, t)) and any(
                             _declares_version(merged_lifecycle, t) for t in offered):
                    # Nothing listed is free of known vulnerabilities (a finding with no fix yet reaches
                    # the newest release). Say so, rather than leave a list that implies a clean choice.
                    print(pal.paint(
                        "    Every release listed has known vulnerabilities; the counts beside each "
                        "say which is least affected.", "yellow"))
                if hidden:
                    print(pal.paint(
                        "    %d end-of-life release(s) hidden -- they cannot be upgraded or "
                        "downgraded to." % hidden, "yellow"))
            else:
                print(pal.paint("\n  (couldn't reach GitHub - enter a tag manually)", "yellow"))
            if interactive:
                tag = ask("Version tag to switch to (e.g. v0.6.0; blank to cancel)", pal).strip()
        if not tag:
            print(pal.paint("  Cancelled.\n", "yellow"))
            return

        down = is_downgrade(current, tag)
        print(pal.paint("\n  %s: %s -> %s" % ("DOWNGRADE" if down else "Version change", current, tag),
                        "red" if down else "yellow"))
        print(pal.paint("  The database has no down-migrations, so a change across a schema change can fail", "yellow"))
        print(pal.paint("  to start (a downgrade especially).", "yellow"))

        matrix, matrix_source = fetch_describing_matrix(tag, current, root=self.root)
        # A downgrade is described by the upgrade it takes back (plan_downgrade_path), not left undescribed.
        plan = plan_downgrade_path(matrix, current, tag) if down else plan_upgrade_path(matrix, current, tag)

        # A hop planned from the FILE is planned from a guess. The pull path never rewrites
        # VERSION, so a deployment installed from source at 0.6.0 and pull-upgraded since still
        # reads 0.6.0 -- and its container being down is the normal state when you want to change
        # version, which is exactly when the fallback is used. Planning 0.6.0 -> 0.9.0 finds a
        # chain of reversible, no-backup edges and gates nothing, while the real operation is a
        # downgrade from 0.10.0 across a database with no down-migrations.
        #
        # So a hop whose origin is not known is not described. This costs an accurate description
        # in the one case the tool cannot be sure of the origin, and buys back the gate.
        if version_source != "the running container":
            print(pal.paint(
                "  The running version could not be read from the deployment, so where this "
                "change starts from is a guess. Treating it as undescribed.", "yellow"))
            plan = plan_upgrade_path(None, current, tag)

        self._describe_hop(plan, matrix_source, current, tag, down)
        for note in env_upgrade_notes(env, current, tag):
            print(pal.paint("  Note: " + note, "yellow"))
        gateway_note = gateway_trust_note(env.get("TRUSTED_PROXIES"), self._network_gateways(), current, tag)
        if gateway_note:
            print(pal.paint("  Note: " + gateway_note, "yellow"))

        # Refuse an end-of-life target outright -- it is neither offered in the list nor a place to
        # move to. Read the lifecycle from THIS checkout's matrix (the newest view), since a version
        # becomes end-of-life after it ships and its own published matrix is frozen at cut time.
        eol_matrix = preferred_lifecycle_matrix(local_matrix, matrix, tag)
        if is_eol(eol_matrix, tag):
            self._fail("%s is end-of-life and cannot be upgraded or downgraded to (%s)."
                       % (tag, support_line(eol_matrix, tag)))
        # ADVISORY (not a gate): read the merged DISPLAY lifecycle so a vulnerability found AFTER the
        # target's tag was cut still shows, and name which source produced the verdict.
        _src_phrase = ("per the current matrix on main" if lifecycle_source == "main"
                       else "per this release's matrix")
        target_vulns = version_vulnerabilities(merged_lifecycle, tag)
        if version_support(merged_lifecycle, tag).get("secure") is False:
            if target_vulns:
                print(pal.paint("  WARNING: %s has %s (%s):"
                                % (tag, vulnerability_summary(target_vulns), _src_phrase), "red"))
                for line in describe_vulnerabilities(target_vulns):
                    print(pal.paint(line, "yellow"))
            else:
                print(pal.paint(
                    "  WARNING: %s has known unpatched vulnerabilities. (%s)" % (tag, _src_phrase), "red"))
        _target_line = line_support_note(merged_lifecycle, tag)
        if _target_line.startswith(("security fixes ended", "no longer")) \
                and release_line(tag) != release_line(current):
            print(pal.paint("  Note: %s is on the %s line, which %s." % (
                tag, release_line(tag), _target_line.replace("security fixes ended",
                                                             "stopped receiving security fixes")),
                "yellow"))

        # What this change does to the deployment's known vulnerabilities -- only when where it starts
        # from is actually known; compared against a guessed version it would describe a different move.
        if version_source == "the running container" and _declares_version(merged_lifecycle, current):
            now = _finding_keys(merged_lifecycle, current)
            after = {_finding_key(v) for v in target_vulns}
            gained = [v for v in target_vulns if _finding_key(v) not in now]
            if gained:
                print(pal.paint("  Moving to %s brings back %d known %s that %s does not have:"
                                % (tag, len(gained), "vulnerability" if len(gained) == 1
                                   else "vulnerabilities", current), "red"))
                for v in gained:
                    print(pal.paint("    - [%s] %s" % ((v.get("severity") or "unrated").upper(),
                                                       clean_matrix_text(v.get("title") or "")), "red"))
            fixed_now = len(now - after)
            if fixed_now:
                print(pal.paint("  Moving to %s fixes %d known %s in %s." % (
                    tag, fixed_now, "vulnerability" if fixed_now == 1 else "vulnerabilities", current),
                    "green"))

        # A release with a strict subset of the target's known vulnerabilities, among those this
        # deployment could actually move to: not end-of-life, not a downgrade the matrix refuses, and
        # not behind a blocked edge. Advice only -- see safer_alternative.
        _candidates = []
        for _t in (_release_tags or []):
            try:
                if (is_eol(local_matrix, _t) or downgrade_refusal(local_matrix, current, _t)[0]
                        or plan_upgrade_path(local_matrix, current, _t).get("blocked") is not None):
                    continue
            except Exception:  # a candidate the tool cannot reason about is simply not suggested
                continue
            _candidates.append(_t)
        safer = safer_alternative(merged_lifecycle, tag, _candidates)
        if safer:
            _fewer = len(_finding_keys(merged_lifecycle, tag)) - len(_finding_keys(merged_lifecycle, safer))
            print(pal.paint(
                "  %s is affected by %d fewer known %s than %s and by none that %s is not. Unless you "
                "need %s specifically, choose %s." % (
                    safer, _fewer, "vulnerability" if _fewer == 1 else "vulnerabilities", tag, tag, tag,
                    safer), "yellow"))

        # A downgrade the matrix refuses: an older image cannot read data written by the newer one,
        # so the move is not offered even with an 'i accept'. Read off this checkout's matrix, which
        # knows the running version and the forward edge (the target's own published matrix, being
        # older, may not). This is the case a bare downgrade used to slip through as 'undescribed'.
        down_refused, down_reason = downgrade_refusal(local_matrix, current, tag)
        if down_refused:
            self._fail(
                "%s -> %s is a downgrade this deployment cannot take: an older image cannot read the "
                "data written by the newer one (%s). Deploy the older version as a fresh set and "
                "restore from a backup instead of downgrading over these volumes."
                % (current, tag, clean_matrix_text(down_reason)))

        if plan["blocked"] is not None:
            self._fail("the upgrade matrix says this change must not be taken directly: %s"
                       % clean_matrix_text(plan["blocked"].get("reason", "no reason recorded")))

        # Going back: the running version knows which of its changes to the data an older one
        # cannot read, so ask it. An older image from FIRST_NEWER_DATA_CHECK on refuses to start on
        # such data by itself; this says so before the change is made, and names how to undo each
        # first. An image older than that has no check and starts regardless, so going back to one
        # over such data is refused here even when forced: this is the only check there is.
        if down and version_source == "the running container":
            offered, blockers = self._downgrade_blockers(tag)
            target_checks = checks_newer_data(tag)
            if blockers:
                print(pal.paint("\n  %s has changed this deployment's data in a way %s cannot read:"
                                % (current, tag), "red"))
                for blocker in blockers:
                    needs = server_text(blocker.get("requires_at_least"))
                    print(pal.paint("    - %s%s" % (server_text(blocker.get("reason"), "no reason given"),
                                                    (" (needs %s or later)" % needs) if needs else ""),
                                    "red"))
                    if blocker.get("undo"):
                        print("      undo it first, with %s running: %s"
                              % (current, server_text(blocker.get("undo"))))
                if not target_checks:
                    self._fail(
                        "undo these with %s first, then run update again. %s is older than %s, the "
                        "first version that checks for this: it would start on this data regardless, "
                        "and may delete or change what %s keeps. --force-downgrade does not go back to "
                        "a version older than %s; to go back without undoing these, choose %s or later."
                        % (current, tag, FIRST_NEWER_DATA_CHECK, current, FIRST_NEWER_DATA_CHECK,
                           FIRST_NEWER_DATA_CHECK))
                if not (args and getattr(args, "force_downgrade", False)):
                    self._fail(
                        "undo these with %s first, then run update again. %s would refuse to start "
                        "on this data. (--force-downgrade goes back anyway; %s then starts only with "
                        "%s=true in .env, on data it cannot fully read.)"
                        % (current, tag, tag, NEWER_DATA_ESCAPE))
                print(pal.paint(
                    "  --force-downgrade given: going on. %s refuses to start on this data unless "
                    "%s=true is set in .env." % (tag, NEWER_DATA_ESCAPE), "yellow"))
            elif offered is None:
                if target_checks:
                    print(pal.paint(
                        "  Could not ask the running deployment whether %s can read its data. If it "
                        "cannot, %s refuses to start and says how to undo the change." % (tag, tag),
                        "yellow"))
                else:
                    print(pal.paint(
                        "  Could not ask the running deployment whether %s can read its data. %s is "
                        "older than %s, the first version that checks for this: if %s changed the data "
                        "in a way %s cannot read, %s starts anyway and may delete or change what %s "
                        "keeps." % (tag, tag, FIRST_NEWER_DATA_CHECK, current, tag, tag, current),
                        "yellow"))
        elif down:
            # Going back from a guessed origin (nothing running to ask): nobody can say what the data holds that the
            # older version cannot read, so neither question above can be put. An older image from
            # FIRST_NEWER_DATA_CHECK on still checks the data itself, so the move is taken only when asked for by
            # name (--force-downgrade); to an older one, which checks nothing, it is refused even then. Starting
            # the deployment lets update ask it.
            ask_first = ("Start the deployment (python dockvault.py start) and run update again: it then asks the "
                         "running version what it has changed")
            if not checks_newer_data(tag):
                self._fail(
                    "%s -> %s is a downgrade from a version that could only be guessed (%s), and %s is older "
                    "than %s, the first version that checks for data it cannot read: it would start on this "
                    "data regardless and may delete or change what %s keeps. --force-downgrade does not go back "
                    "to a version older than %s without the running version's answer. %s."
                    % (current, tag, version_source, tag, FIRST_NEWER_DATA_CHECK, current,
                       FIRST_NEWER_DATA_CHECK, ask_first))
            if not (args and getattr(args, "force_downgrade", False)):
                self._fail(
                    "%s -> %s is a downgrade from a version that could only be guessed (%s), so whether %s "
                    "can read this data cannot be asked. %s. Or pass --force-downgrade to go back on the guess: "
                    "%s refuses to start on data it cannot read, and says how to undo the change."
                    % (current, tag, version_source, tag, ask_first, tag))
            print(pal.paint(
                "  --force-downgrade given: going back from a guessed version. %s refuses to start on data it "
                "cannot read." % tag, "yellow"))

        dry_run = bool(getattr(args, "dry_run", False)) if args else False
        if dry_run:
            print(pal.paint("\n  --dry-run: nothing was changed.\n", "cyan"))
            return

        confirmed = bool(getattr(args, "yes", False)) if args else False
        if interactive:
            confirmed = confirm("Proceed with the version change?", pal, default=False)
        if not confirmed:
            print(pal.paint("  Cancelled.\n", "yellow"))
            return

        # Choosing a release with known vulnerabilities that a reachable release does not have is
        # stated in words too: type the version back. It is not a refusal -- a rollback during an
        # outage is exactly when someone needs an older release -- only a guard against a reflex.
        if safer and interactive:
            typed = ask("%s has known vulnerabilities that %s does not. Type %s to install it anyway"
                        % (tag, safer, tag), pal)
            if typed.strip().lstrip("vV") != tag.strip().lstrip("vV"):
                print(pal.paint("  Cancelled.\n", "yellow"))
                return

        # An irreversible change is acknowledged in words, not with a keypress. The point is to
        # make the operator state the thing they are accepting, so it cannot be got past by
        # reflex on a prompt that looks like every other prompt.
        if plan["irreversible"] and interactive:
            typed = ask("This change cannot be rolled back. Type 'i accept' to continue", pal)
            if typed.strip().lower() != "i accept":
                print(pal.paint("  Cancelled.\n", "yellow"))
                return

        why = backup_reason(plan, down)
        if why:
            if not self._require_backup(args, interactive, why):
                return

        # One upgrade for the operator; one or more legs underneath.
        #
        # A leg exists per version the route has to LAND on -- see `must_land_here`. Ordinarily
        # there is exactly one and this is a single recreate, unchanged. Where there are more, the
        # tool walks them itself rather than telling the operator to run the command again: the
        # stop is a property of what the database has to go through, not of what the person has to
        # remember.
        legs = [leg["to"] for leg in plan.get("legs") or []] or [tag.lstrip("vV")]
        if len(legs) > 1:
            print(pal.paint(
                "\n  This upgrade runs in %d stages, because %s cannot be passed through in one "
                "step: %s. It is still one command -- it just takes longer."
                % (len(legs), "a release" if len(legs) == 2 else "some releases",
                   " -> ".join(legs)), "cyan"))

        self._offer_chain_key(args, interactive, legs[-1])

        for index, leg_version in enumerate(legs, start=1):
            leg_tag = leg_version if leg_version.startswith("v") else "v" + leg_version
            if len(legs) > 1:
                print(pal.paint("\n  Stage %d of %d: %s" % (index, len(legs), leg_tag), "cyan"))
            if not self._perform_leg(leg_tag, from_source, index, len(legs)):
                return

        healthy = self._wait_secure_healthy(self._load_env().get("COMPOSE_PROFILES", "combined"))
        print(pal.paint("\n  Update to %s: %s.\n" % (tag, "healthy" if healthy else "NOT healthy - check the logs"),
                        "green" if healthy else "red"))

    def _offer_chain_key(self, args, interactive, target):
        """Before a release with the audit log's integrity chain first starts: a chain key of its own. Without
        AUDIT_CHAIN_KEY the chain's key is derived from ENCRYPTION_KEY, which everyone who holds that key holds
        too. Offered with yes as the default answer; --no-chain-key declines (the status then says key-shared).
        Set later on an install whose chain already runs, the chain moves to it on its own, with a proof."""
        pal = self.pal
        if (self._load_env().get("AUDIT_CHAIN_KEY") or "").strip():
            return
        try:
            if parse_semver(str(target).lstrip("vV")) < parse_semver("0.34.0"):
                return
        except (TypeError, ValueError):
            return
        if args is not None and getattr(args, "no_chain_key", False):
            print(pal.paint("  AUDIT_CHAIN_KEY left unset: the audit log's chain key is derived from "
                            "ENCRYPTION_KEY (the status shows key-shared).", "yellow"))
            return
        if self._is_locked() or not os.path.exists(self._env_path()):
            self._fail("there is no plaintext .env to write AUDIT_CHAIN_KEY into (unlock it first: python "
                       "dockvault.py unlock). Nothing changed.")
        with self._chain_key_lock("the update"):
            self._offer_chain_key_held(interactive)

    def _offer_chain_key_held(self, interactive):
        """The key an update offers, under the key change's lock (see _offer_chain_key): .env read again once the
        lock is held, and once more after the answer."""
        pal = self.pal
        if (self._load_env().get("AUDIT_CHAIN_KEY") or "").strip():
            return
        if interactive and not confirm("Give the audit log's integrity chain a key of its own (AUDIT_CHAIN_KEY, "
                                       "recommended)?", pal, default=True):
            print(pal.paint("  Left unset: the chain's key is derived from ENCRYPTION_KEY.", "yellow"))
            return
        if (self._load_env().get("AUDIT_CHAIN_KEY") or "").strip():
            # Written into .env (by hand) while this waited for its answer: never written over.
            print(pal.paint("  AUDIT_CHAIN_KEY was set in .env meanwhile: left as it is.", "yellow"))
            return
        # On the disk before the deployment starts under it: once the chain has moved to the key, it must be in
        # .env whatever happens to the power.
        failed = self._set_env_key_or_put_back("AUDIT_CHAIN_KEY", "'%s'" % gen_hex(32))
        if failed is not None:
            why, unrestored = failed
            self._fail("could not write AUDIT_CHAIN_KEY into .env (%s)%s. The update did not start." % (
                why, ": .env is as it was" if unrestored is None else
                ", nor put .env back as it was (%s): check .env before anything else" % unrestored))
        print(pal.paint("  Wrote AUDIT_CHAIN_KEY to .env (it is in every backup with .env; keep it as you keep "
                        "ENCRYPTION_KEY).", "green"))

    def _downgrade_blockers(self, target):
        """What the running deployment says stops it going back to `target`: (offered, blockers).

        Asked of the host operator in the running web container (the one-container layout names the
        service `vault`, the split one `vault-api`):

            python -m app.core.host_operator downgrade-blockers --target X.Y.Z

        which answers, as its last line, {"ok": true, "blockers": [{"key": ..., "requires_at_least":
        "X.Y.Z", "reason": ..., "undo": ...}, ...]} -- an empty list when nothing is in the way.
        offered is True with that answer; False when the container's host operator has no such
        action (argparse calls it an invalid choice), or the container has no host operator at all
        (Python finds no such module), which is every release before the one that added the action
        and is not a problem: such a release wrote nothing an older one cannot read; None when it
        could not be asked at all.
        """
        version = str(target).lstrip("vV")
        for service in ("vault", "vault-api"):
            try:
                r = self._run_dc("exec", "-T", service, "python", "-m", "app.core.host_operator",
                                 "downgrade-blockers", "--target", version, timeout=180)
            except (OSError, subprocess.SubprocessError):
                continue
            blockers = parse_downgrade_blockers(parse_operator_answer(getattr(r, "stdout", "")))
            if blockers is not None:
                return True, blockers
            stderr = getattr(r, "stderr", "") or ""
            if "invalid choice" in stderr or _NO_HOST_OPERATOR.search(stderr):
                return False, []
        return None, []

    def _perform_leg(self, tag, from_source, index=1, total=1):
        """Move the deployment onto one version and prove it came up before going on.

        Returns False when the deployment did not come back. The caller stops there rather than
        continuing to the next leg: a stage that failed leaves the deployment on a REAL release,
        which is a defined state someone can reason about, and stacking the next migration on top
        of a boot that did not finish is how a recoverable problem becomes an unrecoverable one.
        """
        pal = self.pal
        if from_source:
            print(pal.paint("  git checkout %s + rebuild ..." % tag, "cyan"))
            try:
                r = subprocess.run(["git", "checkout", tag], cwd=self.root, capture_output=True, text=True, timeout=120)
            except (OSError, subprocess.SubprocessError) as exc:
                self._fail("git checkout failed: %s" % exc)
            if r.returncode != 0:
                self._fail("git checkout %s failed: %s" % (tag, (r.stderr or "").strip()[:200]))
            # Point .env back at the local build tag. Coming from a pulled release, DOCKVAULT_IMAGE
            # still names a GHCR reference — and `compose up --build` tags its output with whatever
            # it finds there, so the build would be published-image-shaped: same name and version
            # tag as the release, different contents.
            if uses_release_image(self._load_env()):
                self._set_env_key(self._env_path(), "DOCKVAULT_IMAGE", LOCAL_IMAGE)
        else:
            image = "%s:%s" % (GHCR_IMAGE, tag)
            print(pal.paint("  pulling %s ..." % image, "cyan"))
            # Pull with the new reference in the PROCESS ENVIRONMENT (Compose honours a shell
            # DOCKVAULT_IMAGE over the .env value), NOT by writing .env first. A failed pull -- a
            # registry outage, a rate limit, a mistyped or not-yet-published tag -- must not leave
            # .env naming an image that cannot be pulled: the running stack survives, but the next
            # `restart` (down + up) would then fail to bring the vault back until the image exists or
            # .env is hand-edited. Persist DOCKVAULT_IMAGE only AFTER the pull succeeds, so a failure
            # leaves .env byte-identical and never reaches the recreate step below.
            _pull_env = dict(os.environ)
            _pull_env["DOCKVAULT_IMAGE"] = image
            try:
                pr = self._run_dc("pull", capture=False, timeout=600, env=_pull_env)
            except (OSError, subprocess.SubprocessError) as exc:
                self._fail("docker compose pull failed: %s" % exc)
            if pr.returncode != 0:
                self._fail("docker compose pull failed - is %s published? (or use --source to build)" % image)
            self._set_env_key(self._env_path(), "DOCKVAULT_IMAGE", image)
            print(pal.paint("  set DOCKVAULT_IMAGE=%s" % image, "cyan"))

        # from-source rebuilds the local Dockerfile; the pull path recreates from the pulled image
        # WITHOUT --build (a rebuild would clobber the just-pulled release image with a local build).
        if not (self._start_secure_stack() if from_source else self._recreate_stack(build=False)):
            self._fail("the stack did not come up after the update - check 'docker compose ... logs'.")

        if total == 1:
            return True

        # Between stages the deployment must actually be up, because the next stage's migration is
        # written assuming this one finished. A stage that only half-applied and then had the next
        # release's statements run over it is the situation staging exists to avoid.
        if not self._wait_secure_healthy(self._load_env().get("COMPOSE_PROFILES", "combined")):
            print(pal.paint(
                "\n  Stage %d of %d (%s) did not come back healthy, so the remaining stages were "
                "NOT run. The deployment is on %s, which is a released version -- check "
                "'docker compose ... logs', then run update again to continue."
                % (index, total, tag, tag), "red"))
            return False
        print(pal.paint("  Stage %d of %d (%s) is up." % (index, total, tag), "green"))
        return True

    def logs(self, args=None):
        """Guided 'enable authenticated log pull'. The GET /logs endpoint is default-OFF; it needs
        PLAN_LOG_PULL=true AND a strong LOG_TOKEN_PEPPER, then an admin ticks a component in the UI.
        This ONLY guides the operator to OPT IN - it opens nothing on its own and changes no other
        exposure default."""
        pal = self.pal
        env = self._load_env()
        on = (env.get("PLAN_LOG_PULL") or "").strip().lower() in ("1", "true", "yes", "on")
        pepper_ok = len((env.get("LOG_TOKEN_PEPPER") or "")) >= 32
        print(pal.paint("\n  Authenticated log pull", "cyan"))
        print("  The GET /logs endpoint is OFF by default. To use it you must set PLAN_LOG_PULL=true")
        print("  and a LOG_TOKEN_PEPPER (>=32 chars); then, in the vault UI under Settings -> Log access, tick")
        print("  the Web/SFTP component and mint a token there. Enabling here opens nothing by itself.")
        print("  status: PLAN_LOG_PULL=%s, pepper %s" % (on, "set" if pepper_ok else "missing"))
        interactive = not (args and getattr(args, "non_interactive", False))
        do_enable = bool(getattr(args, "enable", False)) if args else False
        if interactive:
            do_enable = confirm("Enable authenticated log pull now (writes .env + recreates the stack)?",
                                pal, default=False)
        if not do_enable:
            print(pal.paint("  Left unchanged.\n", "yellow"))
            return
        # Enabling recreates the stack: never that of a set whose restore did not finish.
        self._refuse_incomplete_restore("logs", tail="Nothing was changed.")
        self._set_env_key(self._env_path(), "PLAN_LOG_PULL", "true")
        if not pepper_ok:
            self._set_env_key(self._env_path(), "LOG_TOKEN_PEPPER", gen_hex(32))
        print(pal.paint("  Enabled in .env.", "green"))
        ok, _ = docker_available()
        if ok:
            print(pal.paint("  Recreating the stack so it takes effect ...", "cyan"))
            # env-only change: --force-recreate re-reads .env; do NOT rebuild (would clobber a
            # release image previously pulled by the Update menu with a local build).
            self._recreate_stack(build=False)
        print(pal.paint("  Now open Settings -> Log access in the vault UI, tick the Web/SFTP component, and mint a "
                        "token there.\n", "green"))

    def _stored_bytes(self):
        """Bytes actually stored across active vaults, straight from the deployment's database —
        the same number the vault itself enforces against. None when it can't be read (engine
        down, database not up yet), so callers degrade to 'unknown' instead of guessing."""
        try:
            r = self._run_dc("exec", "-T", "vault-db", "psql", "-U", "sftp_user", "-d", "sftp_db",
                             "-tAc", "SELECT COALESCE(SUM(total_size_bytes), 0) FROM vaults "
                                     "WHERE is_active = true", timeout=60)
        except (OSError, subprocess.SubprocessError):
            return None
        if getattr(r, "returncode", 1) != 0:
            return None
        try:
            return int((r.stdout or "").strip().splitlines()[-1])
        except (ValueError, IndexError):
            return None

    def _volume_capacity(self):
        """(used, available, total) bytes of the filesystem holding the storage volume, or None.

        Read from INSIDE the app container so it reports the volume the vault actually writes to,
        whatever the host path or driver is. Best-effort: purely informational."""
        try:
            r = self._run_dc("exec", "-T", "vault", "df", "-kP", "/app/storage", timeout=60)
            if getattr(r, "returncode", 1) != 0:
                r = self._run_dc("exec", "-T", "vault-api", "df", "-kP", "/app/storage", timeout=60)
        except (OSError, subprocess.SubprocessError):
            return None
        if getattr(r, "returncode", 1) != 0:
            return None
        lines = [ln for ln in (r.stdout or "").splitlines() if ln.strip()]
        if len(lines) < 2:
            return None
        parts = lines[-1].split()
        if len(parts) < 4:
            return None
        try:  # df -kP columns: Filesystem 1024-blocks Used Available Capacity Mounted
            total, used, avail = (int(parts[1]) * 1024, int(parts[2]) * 1024, int(parts[3]) * 1024)
        except ValueError:
            return None
        return (used, avail, total)

    def storage(self, args=None):
        """Show what this deployment stores and set MAX_STORAGE_GB — the hard ceiling an
        administrator can then tune DOWNWARD from inside the vault's Settings page.

        Two independent numbers are reported because they answer different questions: the database
        says how much the vault is storing (what the limit is enforced against), and the storage
        volume says how much room the disk actually has. Lowering the limit below what is already
        stored is refused; setting it above what the disk holds is only a warning, since a volume
        can be grown under a running deployment."""
        pal = self.pal
        env = self._load_env()
        # The older PLAN_MAX_STORAGE_GB spelling still configures a deployment, so read it as a
        # fallback and report which key is actually in force.
        raw = env.get("MAX_STORAGE_GB")
        key_in_use = "MAX_STORAGE_GB"
        if not (raw or "").strip():
            legacy = env.get("PLAN_MAX_STORAGE_GB")
            if (legacy or "").strip():
                raw, key_in_use = legacy, "PLAN_MAX_STORAGE_GB"
        current = parse_max_storage_gb(raw)

        stored = self._stored_bytes()
        capacity = self._volume_capacity()

        print(pal.paint("\n  Deployment storage limit", "cyan"))
        if current is None or current < 0:
            print("  current limit: unlimited" + ("" if current is None else " (-1)"))
        else:
            print("  current limit: %g GB   (%s in .env)" % (current, key_in_use))
        print("  stored now:    %s" % ("unknown - is the deployment running?" if stored is None
                                       else format_bytes(stored)))
        if capacity:
            used, avail, total = capacity
            print("  storage disk:  %s used, %s free of %s"
                  % (format_bytes(used), format_bytes(avail), format_bytes(total)))
        print("  Administrators can lower the live limit in the vault's Settings -> Storage; this")
        print("  value is the ceiling they cannot go above.")

        limit = parse_transfer_limit(env.get("MAX_CONCURRENT_TRANSFERS")) or 16
        queued = parse_transfer_queue(env.get("MAX_QUEUED_TRANSFERS"))
        queued = 32 if queued is None else queued
        print(pal.paint("\n  Transfers at once", "cyan"))
        print("  current ceiling: %d  (%d more may wait for a slot)" % (limit, queued))
        print("  Each transfer in flight costs the deployment a fixed amount of memory whatever")
        print("  the file weighs: budget roughly 260 MB plus 40 MB per transfer across the stack.")
        print("  At %d that is about %d MB. Lower it on a small machine." % (limit, 260 + 40 * limit))

        requested = getattr(args, "set_gb", None) if args else None
        interactive = not (args and getattr(args, "non_interactive", False))
        # A new limit recreates the stack (unless --no-restart): never that of a set whose restore did not finish.
        # Asked before anything is written, so it is refused whole.
        if (requested is not None or interactive) and not (args and getattr(args, "no_restart", False)):
            self._refuse_incomplete_restore("storage", tail="Nothing was changed (with --no-restart, storage writes "
                                                            ".env only).")

        wanted = parse_transfer_limit(getattr(args, "set_transfers", None) if args else None)
        if wanted is None and interactive:
            answer = ask("Transfers at once (blank to keep %d)" % limit, pal, default="")
            if (answer or "").strip():
                wanted = parse_transfer_limit(answer)
                if wanted is None:
                    self._fail("that is not a number of transfers")
        if wanted is not None and wanted != limit:
            self._set_env_key(self._env_path(), "MAX_CONCURRENT_TRANSFERS", str(wanted))
            print(pal.paint("  Set MAX_CONCURRENT_TRANSFERS=%d in .env (about %d MB at that "
                            "ceiling)." % (wanted, 260 + 40 * wanted), "green"))
        if requested is None and interactive:
            answer = ask("New limit in GB (-1 for unlimited, blank to keep)", pal, default="")
            if not (answer or "").strip():
                print(pal.paint("  Left unchanged.\n", "yellow"))
                return
            requested = parse_max_storage_gb(answer)
            if requested is None:
                self._fail("that is not a number of GB")
        if requested is None:
            print(pal.paint("  Left unchanged.\n", "yellow"))
            return

        problem = storage_limit_problem(requested, stored)
        if problem:
            self._fail(problem)
        if capacity and requested > 0 and requested * GIB > capacity[2]:
            print(pal.paint("  Warning: %g GB is more than the storage volume currently holds (%s). "
                            "Uploads will fail when the disk fills, whatever the limit says."
                            % (requested, format_bytes(capacity[2])), "yellow"))

        self._set_env_key(self._env_path(), "MAX_STORAGE_GB", format_gb_value(requested))
        if key_in_use == "PLAN_MAX_STORAGE_GB":
            # Leave the legacy key in place but neutralise it, so the two can never disagree about
            # the ceiling after this write.
            self._set_env_key(self._env_path(), "PLAN_MAX_STORAGE_GB", "-1")
            print(pal.paint("  PLAN_MAX_STORAGE_GB was in use; MAX_STORAGE_GB now carries the limit.",
                            "yellow"))
        print(pal.paint("  Set MAX_STORAGE_GB=%s in .env." % format_gb_value(requested), "green"))

        if args and getattr(args, "no_restart", False):
            print(pal.paint("  Not restarting; the new limit applies after the next restart.\n", "yellow"))
            return
        ok, _ = docker_available()
        if not ok:
            print(pal.paint("  Docker is not available; the new limit applies at the next start.\n",
                            "yellow"))
            return
        if interactive and not confirm("Recreate the stack now so it takes effect?", pal, default=True):
            print(pal.paint("  The new limit applies after the next restart.\n", "yellow"))
            return
        # env-only change: --force-recreate re-reads .env; do NOT rebuild (would clobber a release
        # image previously pulled by the Update menu with a local build).
        self._recreate_stack(build=False)
        print(pal.paint("  Applied.\n", "green"))

    def _run_account_tool(self, *tool_args):
        """Run `python -m app.core.host_operator ...` inside the running web container and return its
        JSON answer. The one-container layout names the service `vault`, the split one `vault-api`.

        Its output travels back through the exec pipe and is parsed here; nothing of it is printed
        as is, so a reset link or temporary password in it reaches the terminal only through
        _emit_secret."""
        ok, why = docker_available()
        if not ok:
            self._fail("Docker is not available: %s" % why)
        for service in ("vault", "vault-api"):
            try:
                r = self._run_dc("exec", "-T", service, "python", "-m", "app.core.host_operator",
                                 *tool_args, timeout=180)
            except (OSError, subprocess.SubprocessError) as exc:
                self._fail("could not run the account tool: %s" % type(exc).__name__)
            answer = parse_operator_answer(getattr(r, "stdout", ""))
            if answer is not None:
                return answer
        self._fail("the account tool did not answer. Is the deployment running? "
                   "(python dockvault.py status)")

    def _account_or_fail(self, username):
        answer = self._run_account_tool("lookup", "--username", username)
        if not answer.get("ok"):
            self._fail(server_text(answer.get("error")) or "no such account")
        return answer["account"]

    def _show_account(self, account):
        pal = self.pal
        print(pal.paint("\n  Account", "cyan"))
        print("  username:      %s" % server_text(account.get("username")))
        print("  email:         %s" % (server_text(account.get("email")) or "(none)"))
        print("  role:          %s%s" % (server_text(account.get("role")), "" if account.get("active") else "  (deactivated)"))
        print("  last sign-in:  %s" % (server_text(account.get("last_login")) or "never"))
        print("  second factor: %s" % ("set up" if account.get("second_factor") else "not set up"))

    def audit(self, args=None):
        """Verify the audit log's integrity chain in the running web container, and print every finding and
        the chain's head. Keep the head somewhere else (a ticket, a printout): a later change to the history
        before it then shows. Exit status: 0 clean, 1 failures or warnings, 2 the check could not run.

        From the top menu (no arguments) it asks first: how long records are kept, verify, unarchive or
        compact. The other actions are commands only (audit <action>)."""
        pal = self.pal
        if args is None:
            print(pal.paint("\n  Audit log", "cyan"))
            for i, (_key, label) in enumerate(AUDIT_MENU, 1):
                print("  %s) %s" % (pal.paint(str(i), "bold"), label))
            try:
                choice = parse_menu_choice(input(pal.paint("\nChoose: ", "cyan")), len(AUDIT_MENU))
            except EOFError:
                choice = 0
            if not choice:
                print(pal.paint("  Nothing done.\n", "yellow"))
                return
            action = AUDIT_MENU[choice - 1][0]
            if action == "retention":
                return self._audit_retention(None)
            if action == "unarchive":
                return self._audit_unarchive(self._ask_unarchive_days())
            if action == "compact":
                return self._audit_compact(None)
        action = getattr(args, "audit_action", "verify") if args is not None else "verify"
        if action == "retention":
            return self._audit_retention(args)
        if action == "verify" and getattr(args, "acknowledge_removed_before", None):
            # The same command, spelled as a check's option: audit verify --acknowledge-removed-before <time>.
            args.before = args.acknowledge_removed_before
            action = "acknowledge-removed-before"
        if action == "acknowledge":
            return self._audit_acknowledge(args)
        if action in ("rekey", "after-record", "accept-database-head", "accept-restore",
                      "acknowledge-removed-before"):
            return self._audit_host_command(args, action)
        if action == "change-key":
            return self._audit_change_key(args)
        if action == "unarchive":
            return self._audit_unarchive(args)
        if action == "compact":
            return self._audit_compact(args)
        tool_args = ["verify", "--json"]
        for flag, name in (("--from", "audit_from"), ("--to", "audit_to"), ("--anchor", "anchor")):
            value = getattr(args, name, None) if args else None
            if value:
                tool_args += [flag, value]
        if args is not None and getattr(args, "no_key", False):
            tool_args.append("--no-key")
        ok, why = docker_available()
        if not ok:
            self._fail("Docker is not available: %s" % why)
        answer = None
        for service in ("vault", "vault-api"):
            try:
                r = self._run_dc("exec", "-T", service, "python", "-m", "app.core.audit_integrity", *tool_args,
                                 timeout=3600)
            except (OSError, subprocess.SubprocessError) as exc:
                self._fail("could not run the audit check: %s" % type(exc).__name__)
            answer = parse_operator_answer(getattr(r, "stdout", ""))
            if answer is not None:
                break
        if answer is None:
            self._fail("the audit check did not answer. Is the deployment running? (python dockvault.py status)")
        if not answer.get("ok"):
            print(pal.paint("  The audit check could not run: %s" % server_text(answer.get("error")), "red"))
            raise SystemExit(2)
        findings = answer.get("findings") or []
        colour = {"failure": "red", "warning": "yellow"}
        for f in findings:
            where = (" (seal %s)" % f["seq"]) if f.get("seq") else ""
            where += (" [%s]" % server_text(f.get("hour"))) if f.get("hour") else ""
            print(pal.paint("  %-12s %s%s: %s" % (server_text(f.get("severity")).upper(), server_text(f.get("kind")),
                                                   where, server_text(f.get("message"))),
                            colour.get(f.get("severity"), "")))
        if not findings:
            print(pal.paint("  The audit log's chain verifies clean.", "green"))
        print("  Seals: %s" % server_text(answer.get("seals")))
        if answer.get("head"):
            print(pal.paint("\n  Head (keep it somewhere else):", "cyan"))
            print("  %s" % server_text(answer.get("head")))
            print("  at %s, key %s\n" % (server_text(answer.get("head_at")), server_text(answer.get("key_id"))))
        code = int(answer.get("exit_code") or 0)
        if code:
            raise SystemExit(code)

    def _audit_tool(self, *tool_args, input_text=None):
        """Run `python -m app.core.audit_integrity ...` in the running web container; its JSON answer. With
        ``input_text`` the command reads it on standard input (an old key: never on a command line, where `ps`
        or `docker inspect` would show it). `exec` asks Compose no volume question, so this one call may feed
        its standard input."""
        ok, why = docker_available()
        if not ok:
            self._fail("Docker is not available: %s" % why)
        for service in ("vault", "vault-api"):
            cmd = ("exec", "-T", service, "python", "-m", "app.core.audit_integrity") + tuple(tool_args)
            try:
                if input_text is None:
                    r = self._run_dc(*cmd, timeout=3600)
                else:
                    r = subprocess.run(self._dc(*cmd), input=input_text, text=True, capture_output=True,
                                       cwd=self.root, timeout=3600)
            except (OSError, subprocess.SubprocessError) as exc:
                self._fail("could not run the audit tool: %s" % type(exc).__name__)
            answer = parse_operator_answer(getattr(r, "stdout", ""))
            if answer is not None:
                return answer
        self._fail("the audit tool did not answer. Is the deployment running? (python dockvault.py status)")

    def _audit_old_key(self, args):
        """The old AUDIT_CHAIN_KEY from --old-key-file, read here on the host and handed to the tool on its
        standard input, or None."""
        path = getattr(args, "old_key_file", None) if args else None
        if not path:
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read().strip()
        except OSError as exc:
            self._fail("could not read %s: %s" % (path, exc))
        if not text:
            self._fail("%s is empty" % path)
        return text + "\n"

    def _audit_two_phase(self, args, tool_args, what, check=None):
        """Every host command that writes a seal runs in two steps: read the chain and show what will be
        written, ask, then write with the state that was shown, so nothing changed in between is written over
        unseen. What the read asks to confirm by name must be typed (or given with --confirm). ``check``, when
        given, sees the read's answer before anything is asked, and may refuse."""
        pal = self.pal
        key = self._audit_old_key(args)
        extra = ["--old-key-stdin"] if key is not None else []
        seen = self._audit_tool(*(list(tool_args) + extra + ["--read"]), input_text=key)
        if not seen.get("ok"):
            self._fail(server_text(seen.get("error")) or "the chain could not be read")
        for line in seen.get("lines") or []:
            print("  " + server_text(line))
        if check is not None:
            check(seen)
        given = list(getattr(args, "confirm", None) or [])
        interactive = not getattr(args, "yes", False)
        for name in seen.get("confirm") or []:
            if name in given:
                continue
            if not interactive:
                self._fail("confirm %s first: --confirm %s" % (name, name))
            try:
                typed = input(pal.paint("  Type %s to confirm it: " % server_text(name), "cyan"))
            except EOFError:
                typed = ""
            if typed.strip() != name:
                print(pal.paint("  Nothing written.\n", "yellow"))
                return None
            given.append(name)
        if interactive:
            try:
                answer = input(pal.paint("  %s? Type yes: " % what, "cyan"))
            except EOFError:
                answer = ""
            if answer.strip().lower() != "yes":
                print(pal.paint("  Nothing written.\n", "yellow"))
                return None
        confirms = []
        for name in given:
            confirms += ["--confirm", name]
        done = self._audit_tool(*(list(tool_args) + extra + ["--expect", seen["state"]] + confirms),
                                input_text=key)
        if not done.get("ok"):
            self._fail(server_text(done.get("error")) or "refused")
        return done

    def _audit_acknowledge(self, args):
        """acknowledge: warnings by seal (--seqs), failures (--failures), rows holding a value no release writes
        (--rows), or rows added to a sealed hour after its window (--late-rows <hour>)."""
        pal = self.pal
        seqs = (getattr(args, "seqs", None) or "").strip()
        failures = bool(getattr(args, "failures", False))
        rows = (getattr(args, "rows", None) or "").strip()
        late = (getattr(args, "late_rows", None) or "").strip()
        if not (seqs or failures or rows or late):
            self._fail("say what to acknowledge: --seqs, --failures, --rows or --late-rows")
        tool = ["acknowledge"]
        if late:
            tool += ["--late-rows", late]
        else:
            tool += (["--seqs", seqs] if seqs else []) + (["--failures"] if failures else []) + \
                (["--rows", rows] if rows else [])
        done = self._audit_two_phase(args, tool, "Acknowledge these")
        if done is None:
            return
        if late:
            print(pal.paint("  Sealed %s rows of %s (seal %s)\n" % (server_text(done.get("added")),
                                                                  server_text(done.get("hour")),
                                                                  server_text(done.get("sealed"))), "green"))
            return
        print(pal.paint("  Acknowledged: seals %s; failures %s; rows %s\n" % (
            ", ".join(map(str, done.get("acknowledged") or [])) or "none",
            ", ".join(server_text(k) for k in (done.get("failures") or [])) or "none",
            ", ".join(server_text(r) for r in (done.get("rows") or [])) or "none"), "green"))

    def _audit_change_key(self, args):
        """Give the audit log's integrity chain a new AUDIT_CHAIN_KEY: write it into .env, recreate the stack,
        and move the chain to it at once with `audit rekey --old-key-stdin --now`, the old key handed over on
        standard input (never on a command line or in a container's environment, where `ps` or `docker inspect`
        would show it). Sealing waits only for the seconds between the restart and that command. Until the move
        is done the old key is kept beside .env (mode 600) in the file of the volume set .env is for
        (kept_chain_key_path), and removed once the chain is under the new one.

        While that kept file is there, an earlier change of the set's key is not finished: the chain may still be
        under the key it holds, which is then in no other file. A new change of that set's key is refused, naming
        the command that finishes the earlier one, and the kept file is never written over. Another set's kept file
        is that set's, and changes nothing here.

        Two runs at once (or a run and an update offering a key) are never let through: the lock CHAIN_KEY_LOCK is
        taken before .env is read, the second is refused at once, and .env is read again after the confirmation.

        Refused, with nothing written, while .env is sealed by `lock` (it holds every secret: a .env written now
        would hold only the new key, and a lock after it would seal that over the real one) or is not there, and
        while a restore of the set .env names did not finish (RESTORE_INCOMPLETE: the recreate would start it). The
        new key is on the disk, in .env, before the stack is recreated under it (_set_env_key); when it cannot be
        written, .env is put back as it was."""
        if self._is_locked():
            self._fail(".env is locked (sealed in .env.enc): unlock it first (python dockvault.py unlock), then run "
                       "audit change-key again. Nothing changed.")
        if not os.path.exists(self._env_path()):
            self._fail("there is no .env in %s: run audit change-key where the deployment's .env is. Nothing "
                       "changed." % self.root)
        # The change recreates the stack under the new key: never that of a set whose restore did not finish.
        self._refuse_incomplete_restore("audit change-key", tail="Nothing was changed.")
        with self._chain_key_lock("audit change-key"):
            self._audit_change_key_held(args)

    @contextlib.contextmanager
    def _chain_key_lock(self, what):
        """The lock a key change, and the key an update offers, hold from before they read AUDIT_CHAIN_KEY until
        they end (CHAIN_KEY_LOCK): with two at once, the second would keep a stale old key aside and write its new
        key over the one the first has just moved the chain to, which would then be in no file. Refused at once
        when another holds it."""
        path = os.path.join(self.root, CHAIN_KEY_LOCK)
        try:
            lock = held_lock(path)
            lock.__enter__()
        except LockBusy:
            self._fail("another change of AUDIT_CHAIN_KEY (audit change-key, or an update writing one) is running on "
                       "this host: wait for it to end, then run %s again. Nothing changed." % what)
        except OSError as exc:
            self._fail("could not take the lock %s (%s): nothing changed" % (path, exc))
        try:
            yield
        finally:
            lock.__exit__(None, None, None)

    def _audit_change_key_held(self, args):
        """audit change-key, under the key change's lock (see _audit_change_key)."""
        pal = self.pal
        env = self._load_env()
        try:
            kept_path = kept_chain_key_path(self.root, volume_prefix(env))
        except ValueError as exc:
            self._fail("%s. Nothing changed." % exc)
        if os.path.lexists(kept_path):
            self._unfinished_key_change(kept_path, volume_prefix(env))
        old = (env.get("AUDIT_CHAIN_KEY") or "").strip()
        interactive = not getattr(args, "yes", False)
        if interactive and not confirm("Write a new AUDIT_CHAIN_KEY and move the audit log's chain to it now?", pal,
                                       default=False):
            print(pal.paint("  Nothing changed.\n", "yellow"))
            return
        # .env read again once confirmed: a key or a set written into it meanwhile (by hand) would make the key kept
        # aside below a stale one.
        again = self._load_env()
        if (again.get("AUDIT_CHAIN_KEY") or "").strip() != old or volume_prefix(again) != volume_prefix(env):
            self._fail("AUDIT_CHAIN_KEY or VAULT_VOLUME_PREFIX in .env changed while this waited for its "
                       "confirmation: run audit change-key again. Nothing changed.")
        kept = None
        if old:
            kept = kept_path
            created = False
            try:
                # Created here or not at all: an existing kept file holds a key no other file may hold.
                fd = os.open(kept, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                created = True
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(old + "\n")
                tighten_secret_file(kept)
                # On the disk, file and name, before .env changes: a power cut then keeps the old key beside the new.
                sync_to_disk(kept)
            except FileExistsError:
                self._unfinished_key_change(kept, volume_prefix(env))
            except OSError as exc:
                if created:
                    # .env still holds the old key: the copy begun here is not needed, and a copy left behind
                    # would refuse the next change for a change that never happened.
                    try:
                        os.remove(kept)
                    except OSError:
                        pass
                self._fail("could not keep the old key aside before changing it (%s): nothing changed" % exc)
        failed = self._set_env_key_or_put_back("AUDIT_CHAIN_KEY", "'%s'" % gen_hex(32))
        if failed is not None:
            why, unrestored = failed
            if unrestored is None:
                if kept is not None:
                    try:
                        os.remove(kept)          # .env holds the old key again: the copy is not needed
                    except OSError:
                        pass
                self._fail("could not write the new AUDIT_CHAIN_KEY into .env (%s): .env is as it was. Nothing "
                           "changed." % why)
            if kept is None:
                self._fail("could not write the new AUDIT_CHAIN_KEY into .env (%s), nor put .env back as it was "
                           "(%s). The stack was not recreated. Check .env: the audit log's chain is under the key "
                           "derived from ENCRYPTION_KEY, and moves on its own, with a proof, to any AUDIT_CHAIN_KEY "
                           ".env holds." % (why, unrestored))
            self._fail("could not write the new AUDIT_CHAIN_KEY into .env (%s), nor put .env back as it was (%s). "
                       "The stack was not recreated: the audit log's chain is still under the old key, kept in %s. "
                       "Before anything else, make AUDIT_CHAIN_KEY in .env that key again, then remove %s."
                       % (why, unrestored, kept, kept))
        print(pal.paint("  Wrote the new AUDIT_CHAIN_KEY (on the disk); recreating the stack ...", "cyan"))
        if not self._recreate_stack(build=False):
            if kept is None:
                self._fail("the stack did not come up with the new key. Once it is up, the audit log's chain "
                           "moves to the new key on its own, with a proof, at the next sealing pass.")
            print(pal.paint("ERROR: the stack did not come up with the new key; the old key is in %s" % kept, "red"))
            self._finish_key_change_hint(kept, "Once the stack is up (python dockvault.py status), move the chain")
            raise SystemExit(1)
        self._wait_secure_healthy(self._load_env().get("COMPOSE_PROFILES", "combined"))
        if not old:
            print(pal.paint("  The chain was under the key derived from ENCRYPTION_KEY: it moves to the new key on "
                            "its own, with a proof, at the next sealing pass.\n", "green"))
            return
        try:
            done = self._audit_tool("rekey", "--old-key-stdin", "--now", input_text=old + "\n")
        except SystemExit:
            # The tool did not answer, or could not be run (an outage, a failed docker exec): it has said which.
            # The new key is in .env and the chain is still under the old one, which only the kept file holds.
            self._finish_key_change_hint(kept, "The chain was not moved. Sealing waits until it is")
            raise
        if not done.get("ok"):
            print(pal.paint("  The chain was not moved: %s" % server_text(done.get("error")), "red"))
            self._finish_key_change_hint(kept, "Sealing waits until it is")
            raise SystemExit(1)
        try:
            os.remove(kept)
        except OSError as exc:
            print(pal.paint("  Could not remove %s (%s): remove it yourself, as the key it holds is no longer in "
                            "use (a new key change is refused while it is there)." % (kept, exc), "yellow"))
        print(pal.paint("  The chain is under the new key (seal %s).\n" % server_text(done.get("sealed")), "green"))

    def _finish_key_change_hint(self, kept, lead):
        """How to finish a key change whose chain was not moved: the command that moves it with the old key `kept`
        holds, and when that file may go. `lead` is the start of the sentence that names the command."""
        print(self.pal.paint("  %s: python dockvault.py audit rekey --old-key-file %s\n"
                             "  then remove %s once the rekey says the key it holds is no longer needed (a new key\n"
                             "  change of this set is refused while it is there).\n" % (lead, kept, kept), "yellow"))

    def _unfinished_key_change(self, kept, prefix):
        """Refuse a key change while an earlier one of the same set is not finished, naming the commands that finish
        it. The file is removed only once rekey says the key it holds is no longer needed: rekey says so of a key
        this chain was under before it moved to the current key, and says a key it was never under is not its."""
        self._fail("an earlier change of AUDIT_CHAIN_KEY of this volume set ('%s') is not finished: the key its audit "
                   "log's chain may still be under is kept in %s, and in no other file. Finish that change first:\n"
                   "  python dockvault.py audit rekey --old-key-file %s\n"
                   "Remove %s only once that rekey says the key it holds is no longer needed, then run audit "
                   "change-key again. Nothing changed." % (prefix, kept, kept, kept))

    def _db_free_bytes(self):
        """The free space of the database volume, in bytes, as the database container sees it, or None."""
        try:
            r = self._run_dc("exec", "-T", DB_CONTAINER, "df", "-Pk", "/var/lib/postgresql/data", timeout=60)
        except (OSError, subprocess.SubprocessError):
            return None
        return parse_df_available(getattr(r, "stdout", "") or "")

    def _audit_unarchive(self, args):
        """unarchive: restore archived audit days as rows (--from and --to, days), once they fit. The read says
        how much the days take restored, 7 to 12 times their compressed size; this refuses, with the numbers,
        unless the larger figure fits in the database volume's free space. Then the two steps of every host
        command that writes a seal."""
        pal = self.pal
        tool = ["unarchive"]
        for flag, name in (("--from", "audit_from"), ("--to", "audit_to")):
            value = (getattr(args, name, None) or "").strip() if args else ""
            if value:
                tool += [flag, value[:10]]

        def fits(seen):
            est = seen.get("estimate") or {}
            need = int(est.get("restored_high_bytes") or 0)
            free = self._db_free_bytes()
            if free is None:
                self._fail("could not read the free space of the database volume (df in %s): nothing restored"
                           % DB_CONTAINER)
            print("  The database volume has %s free; restored, these days take about %s to %s."
                  % (format_bytes(free), format_bytes(int(est.get("restored_low_bytes") or 0)), format_bytes(need)))
            if need > free:
                print(pal.paint("  That would not fit: up to %s needed, %s free. Free some space, or restore fewer "
                                "days with --from and --to; nothing restored." % (format_bytes(need),
                                                                                  format_bytes(free)), "red"))
                raise SystemExit(1)

        done = self._audit_two_phase(args, tool, "Restore these days as rows", check=fits)
        if done is None:
            return
        days = done.get("days") or []
        print(pal.paint("  Restored %s rows of %s days: %s" % (
            server_text(done.get("rows")), len(days), ", ".join(server_text(d) for d in days) or "none"), "green"))

    def _audit_compact(self, args):
        """compact: VACUUM FULL of the audit tables, which gives their free space back to the system. It locks
        them while it runs: audit writes wait, and fail after a few seconds."""
        pal = self.pal
        print(pal.paint("  audit compact rewrites audit_logs and audit_archive_blocks to give their free space back "
                        "to the system. While it runs both tables are locked: every action the vault records "
                        "waits and then fails, sign-ins and file actions included. Run it when nobody uses the "
                        "vault.", "yellow"))
        if not getattr(args, "yes", False):
            try:
                answer = input(pal.paint("  Compact the audit tables now? Type yes: ", "cyan"))
            except EOFError:
                answer = ""
            if answer.strip().lower() != "yes":
                print(pal.paint("  Nothing done.", "yellow"))
                return
        done = self._audit_tool("compact")
        if not done.get("ok"):
            self._fail(server_text(done.get("error")) or "the audit tables were not compacted")
        for t in done.get("tables") or []:
            before, after = t.get("before_bytes"), t.get("after_bytes")
            print(pal.paint("  %s: %s -> %s" % (server_text(t.get("table")),
                                               format_bytes(before) if isinstance(before, int) else "?",
                                               format_bytes(after) if isinstance(after, int) else "?"), "green"))

    def _ask_unarchive_days(self):
        """The days `unarchive` restores, asked in the menu: blank keeps the oldest, or the newest."""
        pal = self.pal
        first = ask("First day to restore (YYYY-MM-DD, blank for the oldest)", pal, default="")
        last = ask("Last day to restore (YYYY-MM-DD, blank for the newest)", pal, default="")
        return argparse.Namespace(audit_from=(first or "").strip() or None, audit_to=(last or "").strip() or None,
                                  yes=False, confirm=None, old_key_file=None)

    def _audit_retention(self, args):
        """retention: how long records are kept, as the running server has it (the value in force, where it
        comes from, the .env lines that set and bound it, the changes waiting). With --set NAME=VALUE, the
        server first checks the lines (the names, that it would start with them, what changes and what deletes
        sooner); then they are written to .env, after a confirmation, and take effect when the deployment is
        recreated (python dockvault.py restart). A change of .env does not wait the panel's delay: one that
        deletes sooner deletes at the restart, so it is confirmed by typing yes, or with --yes."""
        pal = self.pal
        interactive = args is None
        texts = list(getattr(args, "audit_set", None) or []) if args is not None else []
        try:
            wanted = parse_retention_sets(texts)
        except ValueError as exc:
            self._fail(str(exc))
        answer = self._audit_tool("retention", *[a for n, v in wanted for a in ("--set", "%s=%s" % (n, v))])
        if not answer.get("ok"):
            self._fail(server_text(answer.get("error")) or "the retention settings could not be read")
        print(pal.paint("\n  How long records are kept (the value in force, and where it comes from)", "cyan"))
        for line in describe_retention(answer):
            print(line)
        if interactive:
            typed = ask("Change a .env line? NAME=VALUE (blank to leave everything as it is)", pal, default="")
            if not (typed or "").strip():
                print(pal.paint("  Nothing changed.\n", "yellow"))
                return
            try:
                wanted = parse_retention_sets([typed])
            except ValueError as exc:
                self._fail(str(exc))
            answer = self._audit_tool("retention", "--set", "%s=%s" % wanted[0])
            if not answer.get("ok"):
                self._fail(server_text(answer.get("error")) or "the line could not be checked")
        if not wanted:
            print()
            return
        checked = answer.get("check") or {}
        problems = checked.get("problems") or []
        if problems:
            for p in problems:
                print(pal.paint("  %s" % server_text(p), "red"))
            print(pal.paint("  The server would not start with that: nothing written.", "red"))
            raise SystemExit(2)
        changes = checked.get("changes") or []
        sooner = set(checked.get("deletes_sooner") or [])
        for c in changes:
            print(pal.paint("  %s: %s -> %s%s" % (
                server_text(c.get("label") or c.get("key")), retention_value_text(c, c.get("before")),
                retention_value_text(c, c.get("after")), "  (deletes sooner)" if c.get("key") in sooner else ""),
                "yellow" if c.get("key") in sooner else ""))
        if not changes:
            print("  No value in force changes (an administrator's value in the panel, or a bound, keeps it).")
        if sooner:
            print(pal.paint("  This deletes records sooner, at the restart: a change of .env does not wait the "
                            "delay a change in the panel waits.", "yellow"))
        if self._is_locked():
            self._fail(".env is locked: unlock it first (python dockvault.py unlock)")
        if not getattr(args, "yes", False):
            try:
                ok = input(pal.paint("  Write %s to .env? Type yes: " % ", ".join(n for n, _v in wanted),
                                     "cyan"))
            except EOFError:
                ok = ""
            if ok.strip().lower() != "yes":
                print(pal.paint("  Nothing written.\n", "yellow"))
                return
        for name, value in wanted:
            self._set_env_key(self._env_path(), name, value)
        print(pal.paint("  Written to .env. Recreate the deployment to apply it: python dockvault.py restart\n",
                        "green"))

    def _audit_host_command(self, args, action):
        """rekey, after-record, accept-database-head, accept-restore, acknowledge-removed-before: in two steps,
        recorded as the host operator."""
        pal = self.pal
        tool = [action]
        if action == "rekey":
            if getattr(args, "accept_unverified_history", False):
                tool.append("--accept-unverified-history")
            if getattr(args, "confirm_return", False):
                tool.append("--confirm-return")
            what = "Write the key seal"
        elif action == "after-record":
            if getattr(args, "discard", False):
                tool.append("--discard")
                if getattr(args, "discard_from", None):
                    tool += ["--from", str(args.discard_from)]
            if getattr(args, "confirm_unverified", False):
                tool.append("--confirm-unverified")
            what = "Discard these seals" if getattr(args, "discard", False) else "Accept these seals"
        elif action in ("accept-database-head", "accept-restore"):
            if getattr(args, "no_reseal", False):
                tool.append("--no-reseal")
            what = "Accept this restore"
        else:
            before = getattr(args, "before", None)
            days = getattr(args, "retention_days", None)
            if not before or not days:
                self._fail("acknowledge-removed-before needs --before <time> and --retention-days <days>")
            tool += [before, "--retention-days", str(days)]
            what = "Seal over this removal"
        done = self._audit_two_phase(args, tool, what)
        if done is None:
            return
        shown = ", ".join("%s %s" % (k, server_text(v)) for k, v in sorted(done.items()) if k != "ok")
        print(pal.paint("  Done: %s\n" % shown, "green"))

    def accounts(self, args=None):
        """Act on an account as the person who runs the server: reset a password or a second factor,
        or approve a change waiting for a second administrator.

        An administrator may change someone else's sign-in details once in 14 days; a second change
        waits for another administrator, and with none it is refused. This is the way round it, run on
        the host against the deployment's own container. Each change is recorded and audited as the
        host operator's, and the user is told. The account's username must be typed twice. A reset
        link or temporary password is shown on this terminal only, never written to a file or log."""
        pal = self.pal
        interactive = not (args and getattr(args, "non_interactive", False))
        action = getattr(args, "account_action", None) if args else None
        if action is None:
            if not interactive:
                self._fail("say what to do with --action (%s)" % ", ".join(k for k, _ in ACCOUNT_ACTIONS))
            print(pal.paint("\n  Accounts", "cyan"))
            for i, (_key, label) in enumerate(ACCOUNT_ACTIONS, 1):
                print("  %s) %s" % (pal.paint(str(i), "bold"), label))
            try:
                choice = parse_menu_choice(input(pal.paint("\nChoose: ", "cyan")), len(ACCOUNT_ACTIONS))
            except EOFError:
                choice = 0
            if not choice:
                print(pal.paint("  Left unchanged.\n", "yellow"))
                return
            action = ACCOUNT_ACTIONS[choice - 1][0]

        if action == "list":
            answer = self._run_account_tool("list")
            if not answer.get("ok"):
                self._fail(server_text(answer.get("error")) or "the list could not be read")
            rows = answer.get("requests") or []
            if not rows:
                print(pal.paint("  No change is waiting for approval.\n", "green"))
                return
            for r in rows:
                print("  %s  %s for %s, asked by %s on %s; expires %s" % (
                    server_text(r.get("id")), server_text(r.get("label")), server_text(r.get("target_username")),
                    server_text(r.get("requested_by")), server_text(r.get("requested_at"))[:10],
                    server_text(r.get("expires_at"))[:10]))
            print()
            return

        if action == "user-managers":
            answer = self._run_account_tool("user-managers")
            if not answer.get("ok"):
                self._fail(server_text(answer.get("error")) or "the list could not be read")
            rows = answer.get("accounts") or []
            if not rows:
                print(pal.paint("  Only administrators may view or manage users.\n", "green"))
                return
            print(pal.paint("\n  Accounts that may view or manage users without being administrators", "cyan"))
            for r in rows:
                print("  %s  (%s%s)" % (server_text(r.get("username")), server_text(r.get("role")),
                                         "" if r.get("active") else ", deactivated"))
                for p in r.get("permissions") or []:
                    how = ("granted by %s on %s" % (server_text(p.get("granted_by")),
                                                    server_text(p.get("granted_at"))[:10])
                           if p.get("granted_by") else
                           "no granter recorded: kept from when the account was an administrator, "
                           "or its granter was deleted")
                    print("      %-12s %s" % (server_text(p.get("group")), how))
            print(pal.paint("  Where one is not wanted, revoke View Users with the account's Permissions button "
                            "on the Users page (DELETE /permissions/users/{id}/revoke/USER_VIEW), which removes "
                            "Manage Users with it.", "yellow"))
            print(pal.paint("  To keep a leftover one, revoke it and then grant it, so that it records who granted "
                            "it: granting it while the account still holds it does nothing.\n", "yellow"))
            return

        if action == "regranted-defaults":
            answer = self._run_account_tool("regranted-defaults")
            if not answer.get("ok"):
                self._fail(server_text(answer.get("error")) or "the list could not be read")
            rows = answer.get("permissions") or []
            if not rows:
                print(pal.paint("  No revoked permission was found granted again by a restart.\n", "green"))
                return
            print(pal.paint("\n  Permissions an administrator revoked that a restart granted again", "cyan"))
            for r in rows:
                print("  %s  (%s%s)  %-16s revoked %s, granted again %s" % (
                    server_text(r.get("username")), server_text(r.get("role")),
                    "" if r.get("active") else ", deactivated", server_text(r.get("group")),
                    server_text(r.get("revoked_at"))[:16].replace("T", " "),
                    server_text(r.get("granted_again_at"))[:16].replace("T", " ")))
            print(pal.paint("  Before 0.33.1 every start granted each role default again. Where one is still not "
                            "wanted, revoke it again with the account's Permissions button on the Users page "
                            "(DELETE /permissions/users/{id}/revoke/<group>); from 0.33.1 it stays revoked.\n",
                            "yellow"))
            return

        if action == "approve":
            request_id = (getattr(args, "request_id", None) if args else None) or (
                ask("Request id (see: List)", pal) if interactive else None)
            if not request_id:
                self._fail("name the request with --request-id")
            typed = getattr(args, "confirm_username", None) if args else None
            if typed is None and interactive:
                typed = ask("Type the username of the account it changes, to confirm", pal)
            if not (typed or "").strip():
                self._fail("type the account's username with --confirm-username to confirm")
            answer = self._run_account_tool("approve", "--request-id", request_id,
                                            "--confirm-username", typed)
            if not answer.get("ok"):
                self._fail(server_text(answer.get("error")) or "the request was not approved")
            req = answer.get("approved") or {}
            print(pal.paint("  Approved: %s for %s, asked by %s. The change was made and recorded as the "
                            "host operator's." % (server_text(req.get("label")), server_text(req.get("target_username")),
                                                 server_text(req.get("requested_by"))), "green"))
            if answer.get("secret"):
                self._emit_secret("\n".join([
                    pal.paint("\n  ===== PASSWORD RESET LINK (shown once) =====", "bold", "yellow"),
                    "    " + answer["secret"],
                    pal.paint("  Give it to %s over a trusted channel. It works once."
                              % server_text(req.get("target_username")), "yellow")]))
            return

        if action not in ("reset-password", "reset-second-factor", "unlock", "release-key-hold"):
            self._fail("unknown action: %s" % action)
        username = (getattr(args, "username", None) if args else None) or (
            ask("Username", pal) if interactive else None)
        if not username:
            self._fail("name the account with --username")
        account = self._account_or_fail(username)
        self._show_account(account)
        typed = getattr(args, "confirm_username", None) if args else None
        if typed is None and interactive:
            typed = ask("Type the username again to confirm", pal)
        problem = username_confirmation_problem(username, typed)
        if problem:
            self._fail(problem)
        tool_args = [action, "--username", username, "--confirm-username", typed]
        if action == "reset-password" and args is not None and getattr(args, "temporary_password", False):
            tool_args.append("--temporary-password")
        answer = self._run_account_tool(*tool_args)
        if not answer.get("ok"):
            self._fail(server_text(answer.get("error")) or "nothing was changed")
        if action == "unlock":
            print(pal.paint("  Unlocked %s: %s%d automatic lock(s) cleared. Recorded as the host operator's "
                            "change, and the account was told." % (
                                username, "the administrator's lock removed, " if answer.get("was_locked") else "",
                                int(answer.get("sign_in_locks_cleared") or 0)), "green"))
            return
        if action == "release-key-hold":
            if answer.get("released"):
                print(pal.paint("  %s can open their encryption key again without the emailed code. They were "
                                "told, and it is recorded as the host operator's." % username, "green"))
            else:
                print(pal.paint("  %s's encryption key is not held: nothing to release." % username, "yellow"))
            return
        if action == "reset-second-factor":
            print(pal.paint("  Second factor reset for %s. Their sessions ended; they set up a new factor, "
                            "with their own password, at the next sign-in." % username, "green"))
            return
        if answer.get("secret_kind") == "temporary_password":
            heading = "TEMPORARY PASSWORD (shown once)"
            advice = ("Give it to %s over a trusted channel, and ask them to change it as soon as they "
                      "sign in. Reset links are not configured on this deployment." % username)
        else:
            heading = "PASSWORD RESET LINK (shown once)"
            minutes = answer.get("expires_in_minutes")
            advice = ("Give it to %s over a trusted channel. It works once%s, and signs the account out "
                      "everywhere when used." % (username, " and expires in %s minutes" % minutes if minutes else ""))
            if (answer.get("secret") or "").startswith("/"):
                advice += " Open it on your vault's address (ALLOWED_HOSTS is not set, so it has no host)."
        print(pal.paint("  Done for %s; recorded as the host operator's change." % username, "green"))
        self._emit_secret("\n".join([
            pal.paint("\n  ===== %s =====" % heading, "bold", "yellow"),
            "    " + (answer.get("secret") or ""),
            pal.paint("  " + advice, "yellow")]))

    def _run_case_tool(self, *tool_args):
        """Run `python -m app.core.host_compliance ...` inside the running web container and return its JSON
        answer (the one-container layout names the service `vault`, the split one `vault-api`)."""
        ok, why = docker_available()
        if not ok:
            self._fail("Docker is not available: %s" % why)
        for service in ("vault", "vault-api"):
            try:
                r = self._run_dc("exec", "-T", service, "python", "-m", "app.core.host_compliance",
                                 *tool_args, timeout=180)
            except (OSError, subprocess.SubprocessError) as exc:
                self._fail("could not run the compliance tool: %s" % type(exc).__name__)
            answer = parse_operator_answer(getattr(r, "stdout", ""))
            if answer is not None:
                return answer
        self._fail("the compliance tool did not answer. Is the deployment running, on a version with compliance "
                   "access? (python dockvault.py status)")

    def _show_grant(self, g):
        pal = self.pal
        print(pal.paint("\n  Auditor right of %s: %s" % (server_text(g.get("username")), server_text(g.get("status"))),
                        "cyan"))
        print("  proposed by %s on %s%s" % (server_text(g.get("proposed_by")), server_text(g.get("proposed_at"))[:10],
                                            "; lapses %s" % server_text(g.get("lapses_at"))[:10]
                                            if g.get("lapses_at") else ""))
        if g.get("approved_by"):
            print("  approved by %s; ends %s" % (server_text(g.get("approved_by")),
                                                 server_text(g.get("expires_at"))[:10]))
        prov = g.get("provenance") or {}
        if prov:
            print("  account created %s by %s; password %s; authenticator %s" % (
                server_text(prov.get("created_at"))[:10], server_text(prov.get("created_by"), "nobody recorded"),
                "set by %s" % server_text(prov.get("password_set_by")) if prov.get("password_set_by_other")
                else "its own", "set up" if prov.get("authenticator") else "NOT set up"))
        for p in g.get("problems") or []:
            print(pal.paint("  cannot hold it: %s" % server_text(p.get("text")), "yellow"))
        if g.get("independent_approvers"):
            print(pal.paint("  an administrator can approve it: %s" % ", ".join(
                server_text(a) for a in g["independent_approvers"]), "yellow"))

    def _show_case(self, c):
        pal = self.pal
        print(pal.paint("\n  Case %s (%s): %s" % (server_text(c.get("number") or c.get("reference")),
                                                 server_text(c.get("reference")), server_text(c.get("status"))), "cyan"))
        print("  auditor %s; asked %s; purpose %s; legal basis %s; %s vault(s)" % (
            server_text(c.get("auditor")), server_text(c.get("requested_at"))[:10], server_text(c.get("purpose")),
            server_text(c.get("legal_basis")), server_text(c.get("vaults"))))
        if c.get("justification"):
            print("  why: %s" % server_text(c.get("justification")))
        if c.get("independent_approvers"):
            print(pal.paint("  an administrator can approve it: %s" % ", ".join(
                server_text(a) for a in c["independent_approvers"]), "yellow"))
        if c.get("holds_to_confirm"):
            print("  legal hold: %s vault(s) wait for a confirmation" % server_text(c.get("holds_to_confirm")))
            if c.get("independent_confirmers"):
                print(pal.paint("  an administrator can confirm it: %s" % ", ".join(
                    server_text(a) for a in c["independent_confirmers"]), "yellow"))

    def cases(self, args=None):
        """Compliance access from the host: approve an auditor right or a case when no administrator is
        independent enough to (the approval is recorded as the host operator's), revoke a right, or list what is
        open. Approving is refused while an administrator who can approve exists. An auditor right is approved
        by typing the account's username again, a case by typing its reference again."""
        pal = self.pal
        interactive = not (args and getattr(args, "non_interactive", False))
        action = getattr(args, "case_action", None) if args else None
        if action is None:
            if not interactive:
                self._fail("say what to do with --action (%s)" % ", ".join(k for k, _ in CASE_ACTIONS))
            print(pal.paint("\n  Cases", "cyan"))
            for i, (_key, label) in enumerate(CASE_ACTIONS, 1):
                print("  %s) %s" % (pal.paint(str(i), "bold"), label))
            try:
                choice = parse_menu_choice(input(pal.paint("\nChoose: ", "cyan")), len(CASE_ACTIONS))
            except EOFError:
                choice = 0
            if not choice:
                print(pal.paint("  Left unchanged.\n", "yellow"))
                return
            action = CASE_ACTIONS[choice - 1][0]

        def given(name, prompt):
            value = getattr(args, name, None) if args else None
            if value is None and interactive:
                value = ask(prompt, pal)
            return value

        def answered(*tool_args):
            answer = self._run_case_tool(*tool_args)
            if not answer.get("ok"):
                self._fail(server_text(answer.get("error")) or "nothing was changed")
            return answer

        if action == "list":
            answer = answered("list")
            grants, cases = answer.get("grants") or [], answer.get("cases") or []
            if not grants and not cases:
                print(pal.paint("  No auditor right and no case is open.\n", "green"))
                return
            for g in grants:
                print("  right  %s  %-10s %s%s" % (server_text(g.get("id")), server_text(g.get("status")),
                                                   server_text(g.get("username")),
                                                   "  (the host may approve it)" if g.get("host_may_approve") else ""))
            for c in cases:
                print("  case   %s  %-10s auditor %s%s%s" % (
                    server_text(c.get("reference")), server_text(c.get("status")), server_text(c.get("auditor")),
                    "  (the host may approve it)" if c.get("host_may_approve") else "",
                    "  (the host may confirm its legal hold)" if c.get("host_may_confirm") else ""))
            print()
            return

        if action == "downgrade-blockers":
            target = given("target", "Version to go back to (X.Y.Z)")
            if not target:
                self._fail("name the version with --target")
            blockers = answered("downgrade-blockers", "--target", target).get("blockers") or []
            if not blockers:
                print(pal.paint("  Nothing stops going back to %s.\n" % server_text(target), "green"))
                return
            for b in blockers:
                print(pal.paint("  needs %s or later: %s" % (server_text(b.get("requires_at_least")),
                                                              server_text(b.get("reason"))), "yellow"))
                if b.get("undo"):
                    print("    to undo it first: %s" % server_text(b.get("undo")))
            print()
            return

        if action == "show":
            grant, case = (getattr(args, "grant", None), getattr(args, "case", None)) if args else (None, None)
            if not grant and not case and interactive:
                grant = ask("Auditor right id (leave empty for a case)", pal) or None
                case = None if grant else ask("Case id", pal)
            if grant:
                self._show_grant(answered("show", "--grant", grant)["grant"])
            elif case:
                self._show_case(answered("show", "--case", case)["case"])
            else:
                self._fail("name what to show with --grant or --case")
            print()
            return

        if action == "grant-approve":
            grant = given("grant", "Auditor right id (see: List)")
            if not grant:
                self._fail("name the auditor right with --grant")
            shown = answered("show", "--grant", grant)["grant"]
            self._show_grant(shown)
            typed = given("confirm_username", "Type the account's username again to approve")
            if not (typed or "").strip():
                self._fail("type the account's username with --confirm-username to confirm")
            answer = answered("grant-approve", "--grant", grant, "--confirm-username", typed)
            g = answer.get("granted") or {}
            print(pal.paint("  Approved: %s holds the auditor right until %s, recorded as the host operator's "
                            "approval. Every administrator and the account were told." % (
                                server_text(g.get("username")), server_text(g.get("expires_at"))[:10]), "green"))
            return

        if action == "revoke-auditor":
            username = given("username", "Username")
            if not username:
                self._fail("name the account with --username")
            typed = given("confirm_username", "Type the username again to confirm")
            problem = username_confirmation_problem(username, typed)
            if problem:
                self._fail(problem)
            tool_args = ["revoke-auditor", "--username", username, "--confirm-username", typed]
            reason = getattr(args, "reason", None) if args else None
            if reason:
                tool_args += ["--reason", reason]
            answered(*tool_args)
            print(pal.paint("  Revoked the auditor right of %s, recorded as the host operator's." % username, "green"))
            return

        if action not in ("approve", "reject", "confirm-hold"):
            self._fail("unknown action: %s" % action)
        case = given("case", "Case id (see: List)")
        if not case:
            self._fail("name the case with --case")
        self._show_case(answered("show", "--case", case)["case"])
        typed = given("confirm_case", "Type the case's reference again to confirm")
        problem = case_reference_problem(typed)
        if problem:
            self._fail(problem)
        tool_args = [action, "--case", case, "--confirm-case", typed]
        if action == "reject":
            reason = given("reason", "Why (the auditor sees it)")
            if not (reason or "").strip():
                self._fail("say why with --reason")
            tool_args += ["--reason", reason]
        answered(*tool_args)
        print(pal.paint("  Done: %s, recorded as the host operator's." % dict(CASE_ACTIONS)[action].split(" (")[0],
                        "green"))

    def handler(self, key):
        """Resolve a menu/command key to its bound handler, or None if unknown. A hyphenated command
        (e.g. change-passphrase) maps to the underscore method name."""
        keys = {k for k, _ in MENU}
        return getattr(self, key.replace("-", "_")) if key in keys else None

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
            try:
                self.handler(MENU[choice - 1][0])()
            except StoppedBySignal:
                raise           # a hangup, kill or timeout ends the session; it is not a handler's error
            except SystemExit:
                # a handler's _fail (e.g. a bad repoint selection or Docker briefly down) reports its
                # own error; in the menu loop that shouldn't end the whole session - back to the menu.
                pass


# --- entry -----------------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(prog="dockvault", description="DockVault management tool.")
    sub = p.add_subparsers(dest="command")
    parsers = {key: sub.add_parser(key, help=label.split(" - ", 1)[-1]) for key, label in MENU}
    sp = parsers["setup"]
    sp.add_argument("--server-name", dest="server_name")
    sp.add_argument("--admin-username", dest="admin_username")
    sp.add_argument("--admin-email", dest="admin_email")
    pw = sp.add_mutually_exclusive_group()
    pw.add_argument("--admin-password", dest="admin_password",
                    help="the first admin's password (visible to other users in the process list and kept in shell "
                         "history: prefer --admin-password-file or --admin-password-stdin)")
    pw.add_argument("--admin-password-file", dest="admin_password_file",
                    help="read the first admin's password from this file (its first line)")
    pw.add_argument("--admin-password-stdin", dest="admin_password_stdin", action="store_true",
                    help="read the first admin's password from standard input (one line)")
    sp.add_argument("--cert-mode", dest="cert_mode", choices=CERT_MODES, help="selfsigned | letsencrypt | byo")
    sp.add_argument("--le-email", dest="le_email", help="email for Let's Encrypt expiry notices")
    sp.add_argument("--cert-path", dest="cert_path", help="bring-your-own fullchain cert (PEM)")
    sp.add_argument("--key-path", dest="key_path", help="bring-your-own private key (PEM)")
    sp.add_argument("--web-port", dest="web_port", type=int, help="host port for HTTPS (default 443)")
    sp.add_argument("--sftp-port", dest="sftp_port", type=int, help="host port for SFTP (default 2322)")
    sp.add_argument("--sftp-public-host", dest="sftp_public_host",
                    help="address SFTP clients connect to, when it is not the server name (NAT)")
    sp.add_argument("--sftp-public-port", dest="sftp_public_port", type=int,
                    help="port SFTP clients connect to, when it is not --sftp-port (port forwarding)")
    sp.add_argument("--sftp-staging-tmpfs-mb", dest="sftp_staging_tmpfs_mb", type=int,
                    help="size (MiB) of the RAM tmpfs a buffered SFTP upload's plaintext is staged in, "
                         "so it never hits disk (512 by default). Used only with SFTP_STREAMING_UPLOAD="
                         "false (streaming, the default, never stages); then it also caps the SFTP upload "
                         "size and counts toward the SFTP container's memory limit")
    sp.add_argument("--enable-sftp", dest="enable_sftp", action="store_true", help="also serve SFTP")
    sp.add_argument("--split", dest="split", action="store_true", help="two containers (vault-api + vault-sftp)")
    sp.add_argument("--image-source", dest="image_source", choices=("release", "build"),
                    help="release = pull the published GHCR image | build = build this checkout. "
                         "Honored on a re-run too: `setup --image-source build` repoints an existing "
                         "deployment to run freshly-pulled source (default with --non-interactive on "
                         "a fresh install; interactive setup asks)")
    sp.add_argument("--max-storage-gb", dest="max_storage_gb", type=float,
                    help="deployment storage ceiling in GB (-1 = unlimited, the default)")
    sp.add_argument("--max-concurrent-transfers", dest="max_concurrent_transfers", type=int,
                    help="how many uploads and downloads may run at once (16 by default). Each "
                         "costs a fixed amount of memory whatever the file weighs, so lower this "
                         "on a small machine; see docs/resource-budgets.md")
    sp.add_argument("--max-queued-transfers", dest="max_queued_transfers", type=int,
                    help="how many transfers may wait for a slot before callers are refused "
                         "(32 by default; 0 = refuse at once rather than queue)")
    sp.add_argument("--transfer-queue-wait-seconds", dest="transfer_queue_wait_seconds",
                    type=float,
                    help="how long a transfer waits for a slot before the caller is told to come "
                         "back (20 by default)")
    sp.add_argument("--max-single-request-upload-mb", dest="max_single_request_upload_mb", type=int,
                    help="the largest upload the server takes in one request, in MiB (64 by default; "
                         "0 = no cap but the file-size ceiling). It is held in memory before it is "
                         "checked; larger files go through the resumable uploader, which the web "
                         "app and the upload-link page always use")
    sp.add_argument("--recording-preset", dest="recording_preset", choices=tuple(RECORDING_PRESETS),
                    help="the most the audit log may record of personal data: full (the default; the panel can "
                         "record less), standard (fingerprints of names, shortened IP addresses) or minimal "
                         "(none); it writes the AUDIT_MAX_* lines")
    sp.add_argument("--lock-recording-levels", dest="lock_recording_levels", action="store_true",
                    help="make the AUDIT_MAX_* limits also the recording levels, which the panel cannot lower "
                         "(adds audit_levels to SETTINGS_LOCKED_KEYS)")
    sp.add_argument("--update-check", dest="update_check", action="store_true", help="enable the opt-in update check")
    sp.add_argument("--enable-log-pull", dest="enable_log_pull", action="store_true", help="enable the log-pull endpoint")
    sp.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags/defaults, never prompt")
    sp.add_argument("--no-start", dest="no_start", action="store_true", help="author .env + certs but don't build/start")

    vp = parsers["volumes"]
    vp.add_argument("--action", dest="volume_action", choices=("reuse", "new", "repoint"),
                    help="reuse | new (fresh set + .env) | repoint (to another set)")
    vp.add_argument("--target-prefix", dest="target_prefix", help="repoint: the target set's volume prefix")
    vp.add_argument("--env-source", dest="env_source", help="repoint: path to the target set's paired .env")
    vp.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags, never prompt")

    stp = parsers["storage"]
    stp.add_argument("--set-gb", dest="set_gb", type=float,
                     help="new deployment storage ceiling in GB (-1 = unlimited)")
    stp.add_argument("--set-transfers", dest="set_transfers", type=int,
                     help="new ceiling on transfers in flight (16 by default); each costs a fixed "
                          "amount of memory whatever the file weighs")
    stp.add_argument("--no-restart", dest="no_restart", action="store_true",
                     help="write .env only; apply at the next start")
    stp.add_argument("--non-interactive", dest="non_interactive", action="store_true",
                     help="use flags, never prompt (no --set-gb = show only)")

    rp = parsers["reset"]
    rp.add_argument("--confirm", dest="confirm", action="store_true",
                    help="confirm the destructive 'down -v' (required in --non-interactive)")
    rp.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags, never prompt")

    bp = parsers["backup"]
    bp.add_argument("--action", dest="backup_action", choices=("backup", "restore", "list"),
                    help="backup the current set | restore a bundle | list found bundles")
    bp.add_argument("--list", dest="list", action="store_true",
                    help="list backups found across all locations + where new ones are written (no docker needed)")
    bp.add_argument("--backup-dir", dest="backup_dir",
                    help="directory to write/search bundles (default: per-OS app data, e.g. "
                         "%%LOCALAPPDATA%%\\DockVault\\backups). May name SEVERAL, separated by the OS "
                         "path separator; also settable via DOCKVAULT_BACKUP_DIR. The legacy <root>/backups is always searched too")
    bp.add_argument("--bundle-dir", dest="bundle_dir", help="restore: the bundle directory to restore")
    bp.add_argument("--force", dest="force", action="store_true", help="restore: REPLACE existing target volumes with the backup (stops the stack; current data discarded)")
    bp.add_argument("--lock", dest="lock", action="store_true",
                    help="backup: SEAL the bundle's .env (which holds ENCRYPTION_KEY) into env.enc so "
                         "a stolen backup can't decrypt your files; needs a passphrase + gives a recovery key")
    bp.add_argument("--passphrase-file", dest="passphrase_file",
                    help="seal/restore: read the passphrase from this file (first line)")
    bp.add_argument("--passphrase-stdin", dest="passphrase_stdin", action="store_true",
                    help="seal/restore: read the passphrase from stdin")
    bp.add_argument("--use-recovery-key", dest="use_recovery_key", action="store_true",
                    help="restore: open a sealed bundle with its recovery key instead of the passphrase")
    bp.add_argument("--recovery-key-file", dest="recovery_key_file",
                    help="restore: read the sealed bundle's recovery key from this file")
    bp.add_argument("--hint", dest="hint", help="seal: store a NON-secret passphrase hint in env.enc")
    bp.add_argument("--recovery-out", dest="recovery_out",
                    help="seal: also write the recovery key to this file (move it off-host)")
    bp.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags, never prompt")

    up = parsers["update"]
    up.add_argument("--tag", dest="tag", help="version tag to switch to (e.g. v0.6.0)")
    up.add_argument("--source", dest="source", action="store_true", help="build from source (git checkout) instead of pulling the GHCR image")
    up.add_argument("--yes", dest="yes", action="store_true", help="confirm the version change (required in --non-interactive)")
    up.add_argument("--dry-run", dest="dry_run", action="store_true", help="report what the change involves and stop, changing nothing")
    up.add_argument("--backup-verified", dest="backup_verified", action="store_true", help="you keep backups elsewhere; skip taking one (not checked)")
    up.add_argument("--force-downgrade", dest="force_downgrade", action="store_true",
                    help="go back even though the running version says the older one cannot read data it "
                         "changed (the older one then starts only with %s=true). Not accepted for a "
                         "version older than %s, which has no such check and would start on that data "
                         "regardless" % (NEWER_DATA_ESCAPE, FIRST_NEWER_DATA_CHECK))
    up.add_argument("--no-chain-key", dest="no_chain_key", action="store_true",
                    help="do not write AUDIT_CHAIN_KEY: the audit log's chain key stays derived from ENCRYPTION_KEY")
    up.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags, never prompt")

    lp = parsers["logs"]
    lp.add_argument("--enable", dest="enable", action="store_true", help="enable authenticated log pull (opt-in)")
    lp.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags, never prompt")

    ac = parsers["accounts"]
    ac.add_argument("--action", dest="account_action", choices=[k for k, _ in ACCOUNT_ACTIONS],
                    help="reset-password | reset-second-factor | approve | list | user-managers | "
                         "regranted-defaults | unlock | release-key-hold")
    ac.add_argument("--username", dest="username", help="the account to act on")
    ac.add_argument("--confirm-username", dest="confirm_username",
                    help="the account's username typed again; nothing changes unless it matches")
    ac.add_argument("--request-id", dest="request_id", help="approve: the waiting request (see --action list)")
    ac.add_argument("--temporary-password", dest="temporary_password", action="store_true",
                    help="reset-password: set a temporary password instead of creating a reset link")
    ac.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags, never prompt")

    cs = parsers["cases"]
    cs.add_argument("--action", dest="case_action", choices=[k for k, _ in CASE_ACTIONS],
                    help=" | ".join(k for k, _ in CASE_ACTIONS))
    cs.add_argument("--grant", dest="grant", help="show, grant-approve: the auditor right's id (see --action list)")
    cs.add_argument("--case", dest="case", help="show, approve, reject, confirm-hold: the case's id")
    cs.add_argument("--confirm-case", dest="confirm_case",
                    help="the case's reference typed again (list shows it); nothing changes unless it matches")
    cs.add_argument("--username", dest="username", help="revoke-auditor: the account")
    cs.add_argument("--confirm-username", dest="confirm_username",
                    help="the account's username typed again; nothing changes unless it matches")
    cs.add_argument("--reason", dest="reason", help="reject: why (the auditor sees it); revoke-auditor: optional")
    cs.add_argument("--target", dest="target", help="downgrade-blockers: the version to go back to (X.Y.Z)")
    cs.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags, never prompt")

    au = parsers["audit"]
    au.add_argument("audit_action", nargs="?", default="verify",
                    choices=("verify", "acknowledge", "rekey", "after-record", "accept-database-head",
                             "accept-restore", "acknowledge-removed-before", "change-key", "unarchive", "compact",
                             "retention"),
                    help="verify (the default): check the chain and print its head; acknowledge: acknowledge "
                         "warnings (--seqs), failures (--failures), rows (--rows) or late rows (--late-rows) once "
                         "you have looked at them; rekey: move the chain to the current AUDIT_CHAIN_KEY; "
                         "after-record: accept or discard the seals after the head record; accept-database-head: "
                         "accept a restored database or a lost head record; accept-restore: finish a restore of a "
                         "backup; acknowledge-removed-before: seal over rows an older release removed by age; "
                         "change-key: give the chain a new AUDIT_CHAIN_KEY; unarchive: restore archived days as "
                         "rows (--from, --to: days) once they fit in the database volume; compact: give the audit "
                         "tables' free space back to the system (locks them while it runs); retention: how long "
                         "records are kept, and with --set NAME=VALUE a .env limit changed once the server has "
                         "checked it")
    au.add_argument("--set", dest="audit_set", action="append", metavar="NAME=VALUE",
                    help="retention: a .env line to change (repeat for more); the server checks it first")
    au.add_argument("--seqs", dest="seqs", help="acknowledge: the warning seals, comma-separated")
    au.add_argument("--failures", dest="failures", action="store_true",
                    help="acknowledge: every failure, and every warning kept by kind (not a seal's), not yet "
                         "acknowledged")
    au.add_argument("--rows", dest="rows", help="acknowledge: rows holding a value no release writes, by id")
    au.add_argument("--late-rows", dest="late_rows",
                    help="acknowledge: seal the rows added to this sealed hour (YYYY-MM-DDTHH:00:00Z)")
    au.add_argument("--old-key-file", dest="old_key_file",
                    help="rekey, after-record, accept-database-head: a file holding the earlier AUDIT_CHAIN_KEY "
                         "(read here, handed to the tool on its standard input)")
    au.add_argument("--accept-unverified-history", dest="accept_unverified_history", action="store_true",
                    help="rekey: the old key is lost; write the key seal without its proof")
    au.add_argument("--confirm-return", dest="confirm_return", action="store_true",
                    help="rekey: return to a key the chain had left")
    au.add_argument("--discard", dest="discard", action="store_true",
                    help="after-record: delete the seals after the head record that no writer accepted")
    au.add_argument("--discard-from", dest="discard_from", type=int, help="after-record --discard: the first seal")
    au.add_argument("--confirm-unverified", dest="confirm_unverified", action="store_true",
                    help="after-record: accept a key seal written without its proof, which you wrote")
    au.add_argument("--no-reseal", dest="no_reseal", action="store_true",
                    help="accept-database-head, accept-restore: do not seal again the cancels and values lost")
    au.add_argument("--confirm", dest="confirm", action="append",
                    help="what the read asks to confirm by name (otherwise it is asked for)")
    au.add_argument("--before", dest="before", help="acknowledge-removed-before: the removal's cutoff time")
    au.add_argument("--acknowledge-removed-before", dest="acknowledge_removed_before", metavar="TIME",
                    help="verify: seal over rows an older release removed by age before TIME (the same as "
                         "acknowledge-removed-before --before TIME; needs --retention-days)")
    au.add_argument("--retention-days", dest="retention_days", type=int,
                    help="acknowledge-removed-before: the AUDIT_LOG_RETENTION_DAYS the older release ran with")
    au.add_argument("--yes", dest="yes", action="store_true", help="write without asking (confirmations by name "
                                                                    "still need --confirm)")
    au.add_argument("--from", dest="audit_from", help="verify: the first hour whose rows are checked "
                                                      "(YYYY-MM-DDTHH:00:00Z), every hour by default; unarchive: "
                                                      "the first day (YYYY-MM-DD), the oldest by default")
    au.add_argument("--to", dest="audit_to", help="verify: the hour the row check stops before; unarchive: the "
                                                  "last day, the newest by default")
    au.add_argument("--anchor", dest="anchor", help="a head you kept elsewhere (dvchain1:...): the seals up to it "
                                                    "must be the ones it names")
    au.add_argument("--no-key", dest="no_key", action="store_true",
                    help="verify: check as an auditor without the key would (no key, no head record); with --anchor, "
                         "a later change to an hour the anchor covered shows as not authenticated")

    lk = parsers["lock"]
    lk.add_argument("--passphrase-file", dest="passphrase_file", help="read the passphrase from this file (first line)")
    lk.add_argument("--passphrase-stdin", dest="passphrase_stdin", action="store_true", help="read the passphrase from stdin")
    lk.add_argument("--hint", dest="hint", help="store a NON-secret passphrase hint in .env.enc")
    lk.add_argument("--recovery-out", dest="recovery_out", help="also write the recovery key to this file (move it off-host)")

    ul = parsers["unlock"]
    ul.add_argument("--passphrase-file", dest="passphrase_file", help="read the passphrase from this file (first line)")
    ul.add_argument("--passphrase-stdin", dest="passphrase_stdin", action="store_true", help="read the passphrase from stdin")
    ul.add_argument("--recovery-key", dest="recovery_key", action="store_true",
                    help="unlock with the credential recovery key instead of the passphrase")
    ul.add_argument("--recovery-key-file", dest="recovery_key_file", help="read the recovery key from this file")
    ul.add_argument("--show-recovery-key", dest="show_recovery_key", action="store_true",
                    help="display the recovery key (needs the passphrase); does not write .env")
    ul.add_argument("--force", dest="force", action="store_true", help="overwrite an existing .env")

    cp = parsers["change-passphrase"]
    cp.add_argument("--passphrase-file", dest="passphrase_file", help="current passphrase file (first line)")
    cp.add_argument("--passphrase-stdin", dest="passphrase_stdin", action="store_true", help="read the current passphrase from stdin")
    cp.add_argument("--recovery-key", dest="recovery_key", action="store_true",
                    help="authenticate with the recovery key instead of the current passphrase")
    cp.add_argument("--recovery-key-file", dest="recovery_key_file", help="read the recovery key from this file")
    cp.add_argument("--new-passphrase-file", dest="new_passphrase_file", help="new passphrase file (first line)")
    cp.add_argument("--new-passphrase-stdin", dest="new_passphrase_stdin", action="store_true", help="read the new passphrase from stdin")

    parsers["down"].add_argument("--lock", dest="lock", action="store_true",
                                 help="also seal .env into .env.enc after removing the containers")
    parsers["down"].add_argument("--yes", dest="yes", action="store_true",
                                 help="skip the confirmation prompt (required to remove containers non-interactively)")
    return p


def unbuffer_stdout(stream=None):
    """Line-buffer stdout so progress lines appear WHEN THEY HAPPEN, and make it able to print
    anything the tool has to show.

    Python block-buffers stdout in 8 KB chunks whenever it is not a terminal (a pipe, `tee`, a CI
    log, an MSYS/mintty console), which makes a long docker step look frozen and then dumps
    everything at once. And on a Windows console stdout is often cp1252, which cannot encode an em
    dash or a curly quote: the upgrade matrix is a published document whose version notes and
    vulnerability titles are printed raw (clean_matrix_text strips control characters, not
    legitimate ones), so one such character in a note crashed the plan printout with a
    UnicodeEncodeError half-way through. UTF-8 prints everything a note can carry, and `replace`
    means a stream that still cannot show a character prints a marker for it rather than dying.
    Best-effort: a stream without reconfigure() (Python < 3.7 / a replaced stdout) is left alone."""
    stream = sys.stdout if stream is None else stream
    try:
        stream.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")
        return True
    except Exception:  # noqa: BLE001 - buffering is cosmetic; never fail startup over it
        return False


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    unbuffer_stdout()
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
