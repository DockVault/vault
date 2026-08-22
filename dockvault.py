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
    ("stop",    "Stop - stop the deployment (data volumes kept)"),
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


# --- setup: secrets + .env authoring (the pure, testable core) --------------------------------
import base64   # noqa: E402
import glob     # noqa: E402
import hashlib  # noqa: E402
import json     # noqa: E402
import math     # noqa: E402
import re       # noqa: E402
import tempfile # noqa: E402

# The three secrets the compose file demands (an existing .env must carry these to be reusable).
REQUIRED_SECRET_KEYS = ("ENCRYPTION_KEY", "JWT_SECRET_KEY", "VAULT_DB_PASSWORD")

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
    matching quote pair is stripped; tolerant of CRLF + whitespace around the key/'='. Pure —
    mirrors the setup scripts' read_env so a re-run reads its own output back correctly."""
    out = {}
    for raw in (text or "").splitlines():
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
    invite_token_pepper (str)."""
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
    if cfg.get("plan_log_pull"):
        # Opting in here closes the log-404 trap: the endpoint needs BOTH the plan flag and a
        # strong pepper before it will serve (then an admin still ticks a component in the UI).
        bare("PLAN_LOG_PULL", "true")
        bare("LOG_TOKEN_PEPPER", "'%s'" % cfg["log_token_pepper"])
    # A dedicated pepper for account-invitation token hashes. Always written so invitation hashes are
    # decoupled from the JWT secret (the app falls back to the JWT secret only when this is absent).
    if cfg.get("invite_token_pepper"):
        bare("INVITE_TOKEN_PEPPER", "'%s'" % cfg["invite_token_pepper"])
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


def tighten_secret_file(path):
    """Restrict a secrets file to the current user - chmod 600 on POSIX, icacls on Windows. Returns
    True ONLY if the tightening actually succeeded, so a caller never falsely reports a secrets file
    (which holds ENCRYPTION_KEY) as locked down when it isn't."""
    try:
        if os.name == "nt":
            user = os.environ.get("USERNAME") or ""
            if not user:
                return False  # can't form a valid icacls grant without a user name
            r = subprocess.run(
                ["icacls", path, "/inheritance:r", "/grant:r", "%s:(R,W)" % user,
                 "BUILTIN\\Administrators:(F)", "NT AUTHORITY\\SYSTEM:(F)"],
                capture_output=True, text=True, timeout=15)
            return r.returncode == 0
        os.chmod(path, 0o600)
        return True
    except Exception:  # noqa: BLE001
        return False


def _copy_secret(src, dst):
    """Copy `src` to `dst`, CREATING dst mode-600 on POSIX so a private key is never briefly
    world-readable before the perms are tightened (Windows perms are set by tighten_secret_file)."""
    with open(src, "rb") as f:
        data = f.read()
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(dst, flags, 0o600) if os.name != "nt" else os.open(dst, flags)
    with os.fdopen(fd, "wb") as out:
        out.write(data)


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


def render_renewal_hook(app_dir, cert_dir, server_name, service):
    """The certbot deploy-hook script text: on renewal, stage the new fullchain/privkey, preserve
    the live key's owner+mode, VALIDATE the new pair, atomically swap them into cert_dir, then
    restart the app service so uvicorn reloads. Pure text (POSIX-only; mirrors setup-secure.sh)."""
    return "\n".join([
        "#!/bin/bash",
        "# Written by dockvault.py - deploys a renewed Let's Encrypt cert into the vault stack and",
        "# restarts the API so uvicorn picks it up.",
        "set -e",
        'CD="%s"' % cert_dir,
        'install -m 644 "/etc/letsencrypt/live/%s/fullchain.pem" "$CD/.new-cert.pem"' % server_name,
        'install -m 600 "/etc/letsencrypt/live/%s/privkey.pem"   "$CD/.new-key.pem"' % server_name,
        '_own="$(stat -c \'%u:%g\' "$CD/key.pem" 2>/dev/null || echo 0:0)"',
        '_mode="$(stat -c \'%a\' "$CD/key.pem" 2>/dev/null || echo 644)"',
        'chown "$_own" "$CD/.new-key.pem" "$CD/.new-cert.pem" 2>/dev/null || true',
        'chmod "$_mode" "$CD/.new-key.pem" 2>/dev/null || chmod 644 "$CD/.new-key.pem"',
        'chmod 644 "$CD/.new-cert.pem"',
        '_c="$(openssl x509 -in "$CD/.new-cert.pem" -pubkey -noout)"',
        '_k="$(openssl pkey -in "$CD/.new-key.pem" -pubout)"',
        '[ -n "$_c" ] && [ "$_c" = "$_k" ]  # non-empty so a missing openssl fails (never swaps unvalidated)',
        'mv "$CD/.new-key.pem"  "$CD/key.pem"',
        'mv "$CD/.new-cert.pem" "$CD/cert.pem"',
        'cd "%s" && docker compose --env-file "%s/.env" -f "%s/docker-compose.secure.yml" restart %s'
        % (app_dir, app_dir, app_dir, service),
        "",
    ])


def install_renewal_hook(app_dir, cert_dir, server_name, service):
    """Write the certbot deploy hook (POSIX). Returns True on success."""
    hook = "/etc/letsencrypt/renewal-hooks/deploy/dockvault-vault.sh"
    try:
        os.makedirs(os.path.dirname(hook), exist_ok=True)
        with open(hook, "w", encoding="utf-8", newline="\n") as f:
            f.write(render_renewal_hook(app_dir, cert_dir, server_name, service))
        os.chmod(hook, 0o755)
        return True
    except Exception:  # noqa: BLE001
        return False


def obtain_letsencrypt_cert(cert_dir, server_name, email, app_dir, service, run=subprocess.run):
    """Obtain a Let's Encrypt cert via certbot standalone (http-01, binds port 80), install it, and
    write the auto-renewal deploy hook. POSIX-only (needs certbot + root + a public DNS name reachable
    on port 80). Returns (ok, message)."""
    if os.name == "nt":
        return False, "Let's Encrypt automation is Linux-only here; use --cert-mode byo on Windows."
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
    install_renewal_hook(app_dir, cert_dir, server_name, service)
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
    On a ROOTLESS engine (or when the mapped uid can't be resolved), the container's uid is a
    subordinate host uid we cannot target, so fall back to a world-readable key (644, single-tenant
    host) so the container CAN read it - matching setup-secure.sh, and NEVER falsely reporting a
    mode-600 key when it would be unreadable. Returns (mode600, message)."""
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

    if _engine_is_remapped(run):
        owner = _remapped_cert_owner(run)   # mapped host uid (userns-remap), or None (rootless/unresolvable)
        if owner is None:
            return _world_readable(
                "rootless/userns Docker: the container's app user is a subordinate host uid, so a "
                "mode-600 key owned by uid %d would be unreadable inside the container. Made the TLS "
                "key world-readable (644) so the container can read it - host assumed single-tenant, "
                "restrict access accordingly." % APP_UID)
    else:
        owner = APP_UID
    try:
        for path in (cert_dir, cert, key):
            os.chown(path, owner, owner)
        if os.stat(key).st_uid == owner:
            return True, "certs owned by uid %d (key mode 600, not world-readable)" % owner
    except OSError:
        pass
    return _world_readable(
        "could not chown certs to the container uid; made the TLS key world-readable (644) so the "
        "container can read it - host assumed single-tenant, restrict access accordingly.")


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


def new_set_config(current_env, new_prefix, new_id):
    """Config for a FRESH set (born together with its own .env): keep the current .env's NON-secret
    settings (server, admin, ports, mode, flags) but generate BRAND-NEW secrets - a new set is new
    data, so it must get its own ENCRYPTION_KEY / DB password - and stamp the new volume prefix +
    deployment id. The paired secrets and volumes are created together, upholding the bundle invariant."""
    def truthy(k):
        return (current_env.get(k) or "").strip().lower() in ("1", "true", "yes", "on")
    cfg = {
        "server_name": current_env.get("SERVER_NAME") or current_env.get("ALLOWED_HOSTS") or "localhost",
        "encryption_key": gen_fernet_key(), "jwt_secret_key": gen_hex(32),
        "vault_db_password": gen_hex(16), "redis_password": gen_hex(24),
        "admin_username": current_env.get("ADMIN_USERNAME") or "admin",
        "admin_email": current_env.get("ADMIN_EMAIL") or "admin@example.com",
        "admin_password": current_env.get("ADMIN_PASSWORD") or gen_hex(12),
        "compose_profiles": current_env.get("COMPOSE_PROFILES") or "combined",
        "deployment_id": new_id, "volume_prefix": new_prefix,
        "run_sftp": truthy("RUN_SFTP"),
        "web_host_port": _port_or(current_env.get("WEB_HOST_PORT"), 443),
        "sftp_host_port": _port_or(current_env.get("SFTP_HOST_PORT"), 2322),
        "update_check_enabled": truthy("UPDATE_CHECK_ENABLED"),
        "plan_log_pull": truthy("PLAN_LOG_PULL"),
        "log_token_pepper": gen_hex(32) if truthy("PLAN_LOG_PULL") else "",
        "invite_token_pepper": (current_env.get("INVITE_TOKEN_PEPPER") or "").strip() or gen_hex(32),
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
BACKUP_ROLES = ("pg", "storage", "keys", "brand")   # order restored in; brand is optional
# The three that carry data. A bundle without them is not a backup, whatever else it contains,
# and saying so is load-bearing now that an upgrade takes one on the operator's behalf and
# proceeds with an irreversible change on the strength of it.
BACKUP_REQUIRED_ROLES = ("pg", "storage", "keys")


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
    return {"dockvault_coupling": 1,
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
    comparison with the backup manifests (verify_backup_coupling)."""
    return "ok" if verify_backup_coupling(env, marker or {}) else None


def build_backup_manifest(prefix, bundle_id, volumes, salt, env, created=""):
    """The backup manifest dict (NO secrets): identifies the set + records the salted coupling
    fingerprint of the paired .env. `volumes` is a list of {role, name, archive}."""
    return {
        "dockvault_backup": 1,
        "created": created,
        "volume_prefix": prefix,
        "bundle_id": bundle_id or "default",
        "volumes": list(volumes),
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


def untar_volume(volume, src_dir, archive_name, run=subprocess.run):
    """Restore <src_dir>/<archive_name> into a docker volume via a throwaway busybox container (the -v
    mount creates the volume if absent). Returns True on success."""
    try:
        r = run(["docker", "run", "--rm", "-v", "%s:/dest" % volume, "-v", "%s:/src:ro" % src_dir,
                 "busybox", "sh", "-c", "cd /dest && tar xzf /src/%s" % archive_name],
                capture_output=True, text=True, timeout=600)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return getattr(r, "returncode", 1) == 0


# --- update (release list + upgrade/downgrade) -----------------------------------------------
RELEASES_URL = "https://api.github.com/repos/DockVault/vault/releases"
GHCR_IMAGE = "ghcr.io/dockvault/vault"
# The tag a local `docker compose --build` produces, and the compose files' own fallback for an
# unset DOCKVAULT_IMAGE. Naming it here lets the from-source paths point .env back at a local build
# after a release image has been pulled over it.
LOCAL_IMAGE = "dockvault-vault:latest"


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


def parse_releases(data):
    """Release tags from the GitHub releases LIST JSON (a list of {tag_name,...}), preserving the
    API's newest-first order, keeping only version-shaped tags, de-duplicated. Pure; [] on non-list."""
    if not isinstance(data, list):
        return []
    tags = []
    for rel in data:
        if not isinstance(rel, dict):
            continue
        tag = (rel.get("tag_name") or "").strip()
        if tag and parse_semver(tag) and tag not in tags:
            tags.append(tag)
    return tags


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
        # claim, so this is deliberately not classified from it.
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
    answers False, which callers must treat as 'not known to be running'."""
    try:
        r = run(["docker", "inspect", "-f", "{{.State.Running}}", name],
                capture_output=True, text=True, timeout=20)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    if getattr(r, "returncode", 1) != 0:
        return False
    return (getattr(r, "stdout", "") or "").strip() == "true"


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

    def _emit_secret(self, text):
        """Write a one-time secret to the controlling TERMINAL (/dev/tty, or CON on Windows), NOT
        stdout - so a redirected or tee'd stdout (a setup log, CI output) can't capture it. Falls
        back to stdout when there is no controlling terminal (then --recovery-out is the safe
        channel)."""
        dev = "CON" if os.name == "nt" else "/dev/tty"
        try:
            with open(dev, "w", encoding="utf-8") as tty:
                tty.write(text + "\n")
                return
        except OSError:
            print(text)

    def _show_recovery_key(self, dek, args):
        key = dek.decode("ascii") if isinstance(dek, (bytes, bytearray)) else str(dek)
        pal = self.pal
        # Show the key + its guidance on the controlling terminal only (see _emit_secret).
        self._emit_secret("\n".join([
            pal.paint("\n  ===== CREDENTIAL RECOVERY KEY (shown once) =====", "bold", "yellow"),
            "    " + pal.paint(key, "bold"),
            pal.paint("  Save this in a password manager. It unlocks .env if you forget the passphrase.\n"
                      "  It does NOT recover vault files or deployments. If you lose BOTH this key and the\n"
                      "  passphrase, every stored file becomes permanently unrecoverable.", "yellow"),
        ]))
        out = getattr(args, "recovery_out", None)
        if out:
            self._atomic_write_secret(out, key + "\n")
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
                    _, dek = env_lock_open(fernet, f.read(), passphrase=passphrase)
            except EnvLockError as exc:
                print(pal.paint("  Cannot re-lock: %s." % exc, "red"))
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
        if os.path.exists(env_path) and not getattr(args, "force", False):
            print(pal.paint("  .env already exists; refusing to overwrite. Re-run with --force to replace it.",
                            "red"))
            raise SystemExit(2)
        self._atomic_write_secret(env_path, env_bytes)
        print(pal.paint("  Unlocked: .env.enc -> .env.", "green"))

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

    def stop(self, args=None):
        """Stop the deployment's containers. Data volumes are untouched (never `down -v`)."""
        pal = self.pal
        ok, _ = docker_available()
        if not ok:
            print(pal.paint("  Docker is not available.", "red"))
            raise SystemExit(2)
        if not os.path.exists(self._env_path()):
            # compose needs .env for the ${VAR:?} interpolation even to address the stack.
            print(pal.paint("  .env is not present (locked?); nothing to stop by this tool.", "yellow"))
        else:
            print(pal.paint("  Stopping the deployment (data volumes are kept) ...", "cyan"))
            try:
                self._run_dc("stop", capture=False, timeout=120)
            except (OSError, subprocess.SubprocessError) as exc:
                print(pal.paint("  Stop failed: %s" % exc, "red"))
                raise SystemExit(1)
            print(pal.paint("  Stopped.", "green"))
        if getattr(args, "lock", False) and os.path.exists(self._env_path()):
            self.lock(args)

    def restart(self, args=None):
        """Stop, then start (health-checked). Data volumes are untouched."""
        self.stop(args)
        self.start(args)

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
        ok, _ = docker_available()
        if not ok:
            print(pal.paint("  Docker is not available.", "yellow"))
            return
        if not os.path.exists(self._env_path()):
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
        checkout, per the .env's DOCKVAULT_IMAGE (see _resolve_setup_image)."""
        pal = self.pal
        no_start = bool(args and getattr(args, "no_start", False))
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
        if os.path.exists(key) and not tighten_secret_file(key):
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
        if not self._guard_db_secret(env_now, interactive=interactive):
            raise SystemExit(1)   # the guard already printed the diagnosis + recovery paths
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
        tracker.advance(); tracker.show()               # -> Start
        if not self._start_secure_stack():
            shown = self._tail_logs(self._web_service(profiles))
            self._fail("the stack did not start - %s." % ("the last log lines are above" if shown
                       else "see the docker output above"))
        tracker.advance(); tracker.show()               # -> Health check
        healthy = self._wait_secure_healthy(profiles)
        logs_shown = False if healthy else self._tail_logs(self._web_service(profiles))
        self._print_setup_summary(summary, healthy, logs_shown)
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
        i.e. a local build). Only ever consulted when authoring a new .env — a re-run keeps whatever
        the existing .env already says.

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
            update_check = confirm("Enable the opt-in 'update available' check (asks GitHub, no telemetry)?", pal, default=False)
            log_pull = confirm("Enable the authenticated log-pull endpoint (sets a pepper; still off until a component is ticked)?", pal, default=False)
        else:
            enable_sftp, split = bool(a("enable_sftp")), bool(a("split"))
            web_port = _port_or(a("web_port"), 443)
            sftp_port = _port_or(a("sftp_port"), 2322)
            update_check, log_pull = bool(a("update_check")), bool(a("enable_log_pull"))

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
            "update_check_enabled": update_check,
            "plan_log_pull": log_pull,
            "log_token_pepper": gen_hex(32) if log_pull else "",
            "invite_token_pepper": gen_hex(32),
            "max_storage_gb": (getattr(args, "max_storage_gb", None) if args else None),
            # Flags only at install time, as the storage ceiling beside them is. The Limits menu
            # is where these are shown and changed, with the memory each one implies.
            "max_concurrent_transfers": parse_transfer_limit(
                getattr(args, "max_concurrent_transfers", None) if args else None),
            "max_queued_transfers": parse_transfer_queue(
                getattr(args, "max_queued_transfers", None) if args else None),
            "transfer_queue_wait_seconds": parse_transfer_wait(
                getattr(args, "transfer_queue_wait_seconds", None) if args else None),
            "_generated_pw": generated,
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
        """Replace/append KEY=value in .env (bare value), preserving perms."""
        lines, found = [], False
        if os.path.exists(path):
            for raw in open(path, encoding="utf-8").read().splitlines():
                if re.match(r"^\s*%s\s*=" % re.escape(key), raw):
                    lines.append("%s=%s" % (key, value)); found = True
                else:
                    lines.append(raw)
        if not found:
            lines.append("%s=%s" % (key, value))
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        tighten_secret_file(path)

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

    def _start_secure_stack(self):
        """Start/recreate the deployment the current .env describes.

        Builds the local Dockerfile UNLESS .env pins a published release image, in which case the
        image is PULLED and the stack recreated without --build. Setup re-runs go through here, so
        without the check the documented "re-run setup to upgrade" path would rebuild over a
        release image an operator deliberately chose — the same clobber the Update menu's pull path
        already avoids."""
        if uses_release_image(self._load_env()):
            return self._pull_release_image() and self._recreate_stack(build=False)
        return self._recreate_stack(build=True)

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
        or it would overwrite the just-pulled release image with a local build)."""
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
                         probe_fn=None, stop_fn=None, marker_fn=None, stamp_fn=None):
        """Guardrail against the 'existing volume + wrong .env' footgun. No-op (True) for a fresh
        volume. NON-interactive (a script): auto-verify the current .env's DB password and FAIL CLOSED
        on a mismatch/ambiguous result. INTERACTIVE: do NOT auto-wait - present choices (verify / point
        at a .env / new set / destroy / cancel) and run the ~30s DB probe only if the operator asks.
        Never prints a secret. The *_fn hooks are injectable for tests."""
        exists_fn = exists_fn or volume_exists
        vol = "%s_vault_pg_data" % volume_prefix(env)
        if not exists_fn(vol):
            return True   # brand-new volume: the .env password is baked in on first init
        hooks = (start_fn or self._start_db_only, wait_fn or self._wait_db_ready,
                 probe_fn or probe_pg_password, stop_fn or self._stop_db_only,
                 marker_fn or read_volume_coupling, stamp_fn or write_volume_coupling)
        if interactive:
            return self._resolve_existing_volume(env, vol, hooks)
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
            print(pal.paint("  The database container did not start (the docker output is above).", "yellow"))
            return "ambiguous"
        print(pal.paint("  Waiting for the database to accept connections...", "cyan"), flush=True)
        if not wait_fn():
            stop_fn()
            print(pal.paint("  The database did not become ready in time.", "yellow"))
            return "ambiguous"
        print(pal.paint("  Authenticating VAULT_DB_PASSWORD against the stored database (vault-db)...",
                        "cyan"), flush=True)
        result = probe_fn(DB_CONTAINER, PG_USER, PG_DB, env.get("VAULT_DB_PASSWORD", ""))
        stop_fn()
        if result == "ok":
            stamp_fn(vol, env)   # best-effort: make the next check instant
        return result if result in ("ok", "mismatch") else "ambiguous"

    def _resolve_existing_volume(self, env, vol, hooks):
        """Interactive menu shown when an existing data volume is found. NOTHING starts until the
        operator chooses; only 1/2 run the slow DB probe. Returns True to PROCEED (after acting) or
        False to stop. Never prints a secret."""
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
                _copy_secret(src, self._env_path())
                tighten_secret_file(self._env_path())
                try:
                    self._normalize_compose_profile()
                except (OSError, ValueError) as exc:
                    print(pal.paint("  That .env is not deployable: %s." % exc, "red"))
                    continue
                env = self._load_env()   # the installed .env may name a different volume set
                print(pal.paint("  Installed that .env; verifying it...", "cyan"))
                if self._try_verify(env, "%s_vault_pg_data" % volume_prefix(env), hooks):
                    return True
            elif choice == "3":
                self._new_set_from(env)
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
        else:
            print(pal.paint("  Couldn't verify (the database didn't start/respond in time) - NOT a confirmed "
                            "mismatch. Try again, or pick another option.", "yellow"))
        return False

    def _new_set_from(self, env):
        """Author a fresh set (new prefix + secrets) with its own .env, archiving the current one. The
        old data is left untouched (re-pointable later from the Volumes menu)."""
        pal = self.pal
        new_id = gen_deployment_id()
        new_prefix = "%s-%s" % (DEFAULT_PROJECT, new_id)
        self._archive_env(volume_prefix(env))
        if write_env(self._env_path(), build_env_lines(new_set_config(env, new_prefix, new_id))):
            print(pal.paint("  Authored a fresh set '%s' (new volumes + secrets); starting it. The previous "
                            "set's .env was saved aside." % new_prefix, "green"))
        else:
            print(pal.paint("  Authored a fresh set '%s' - WARNING: could not restrict the new .env's "
                            "permissions; secure it yourself." % new_prefix, "yellow"))

    def _destroy_data(self, vol):
        """Strong-confirm + docker compose down -v. True to proceed (destroyed), False if declined."""
        pal = self.pal
        flush_stdin()
        if not confirm("This PERMANENTLY deletes the data in %s. Continue?" % vol, pal, default=False):
            print(pal.paint("  Nothing was deleted.", "yellow"))
            return False
        try:
            self._run_dc("down", "-v", "--remove-orphans", capture=False, timeout=180)
        except (OSError, subprocess.SubprocessError) as exc:
            self._fail("teardown failed: %s" % exc)
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
            print(pal.paint(" Admin passwd : %s   (auto-generated - store it NOW)" % summary["admin_password"], "yellow"))
        print(pal.paint("\n *** BACK UP .env OFF THIS HOST - it holds ENCRYPTION_KEY. ***", "yellow"))
        print(pal.paint("===================================================================\n", "blue"))

    def backup(self, args=None):
        """Backup & Restore menu: dump the current set ({.env + volumes}) into one bundle, or restore a
        bundle back. Interactive by default; arg-mode via args.backup_action (backup|restore)."""
        pal = self.pal
        ok, msg = docker_available()
        if not ok:
            self._fail(msg)
        interactive = not (args and getattr(args, "non_interactive", False))
        action = getattr(args, "backup_action", None) if args else None
        if not action and interactive:
            print(pal.paint("\n  1) Backup the current set   2) Restore a bundle", "cyan"))
            action = {"2": "restore"}.get(ask("Choose 1/2", pal, "1").strip(), "backup")
        if (action or "backup") == "restore":
            self._do_restore(args)
        else:
            self._do_backup(self._load_env(), args)

    def _backup_root(self, args):
        d = (getattr(args, "backup_dir", None) if args else None)
        return d or os.path.join(self.root, "backups")

    def _fail_backup(self, bundle, msg):
        """Abort a backup: DELETE the partial bundle first (it already holds a mode-600 copy of .env
        with ENCRYPTION_KEY, so a half-written bundle must never be left on disk), then fail."""
        shutil.rmtree(bundle, ignore_errors=True)
        self._fail("%s - the incomplete backup was removed." % msg)

    def _do_backup(self, env, args=None):
        """Dump the current set into ONE bundle dir: the paired .env (mode-600), a tar.gz per data
        volume, and a manifest with a NON-secret coupling fingerprint. Skips a volume that doesn't
        exist (e.g. brand). Does NOT stop the stack (a running Postgres is crash-consistent for a
        restore-then-start; note it)."""
        pal = self.pal
        prefix = volume_prefix(env)
        if not env:
            self._fail("no .env found - nothing to back up (run Setup first)")
        names = set_volume_names(prefix)
        ts = _timestamp()
        root = self._backup_root(args)
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
        try:
            os.makedirs(bundle)
            # Restrict the whole bundle dir to the owner (makedirs' mode is umask-masked): the volume
            # tar.gz archives inside include the DB dump + key material, so keep them unreadable to
            # other local users, matching the mode-600 .env copy. (No-op perms on Windows.)
            if os.name != "nt":
                os.chmod(bundle, 0o700)
        except OSError as exc:
            self._fail("could not create the backup directory %s: %s" % (bundle, exc))
        # the paired .env FIRST, mode-600 (it holds ENCRYPTION_KEY)
        _copy_secret(self._env_path(), os.path.join(bundle, "env"))
        tighten_secret_file(os.path.join(bundle, "env"))
        entries = []
        for role in BACKUP_ROLES:
            vol = names[role]
            if not volume_exists(vol):
                continue                                     # e.g. brand isn't always present
            archive = "%s.tar.gz" % VOLUME_BASENAMES[role]
            print(pal.paint("  archiving %s ..." % vol, "cyan"))
            if not tar_volume(vol, bundle, archive):
                self._fail_backup(bundle, "failed to archive volume %s (backup incomplete)" % vol)
            entries.append({"role": role, "name": vol, "archive": archive})

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
        print(pal.paint("\n  Backup written to: %s" % bundle, "green"))
        print("    %d volume(s) + the paired .env + manifest.json" % len(entries))
        print(pal.paint("  *** This bundle's 'env' holds ENCRYPTION_KEY - store the whole bundle "
                        "somewhere safe (off-host). ***\n", "yellow"))

    def _do_restore(self, args=None):
        """Restore a bundle: verify the bundle's .env matches its volumes (coupling fingerprint),
        recreate the volumes, and install the paired .env. Refuses a mismatched bundle, a bundle
        missing its .env/manifest, or clobbering existing volumes (unless --force)."""
        pal = self.pal
        interactive = not (args and getattr(args, "non_interactive", False))
        bundle = getattr(args, "bundle_dir", None) if args else None
        if not bundle and interactive:
            root = self._backup_root(args)
            cands = sorted(glob.glob(os.path.join(root, "dockvault-*")))
            if not cands:
                self._fail("no backups found under %s (pass --bundle-dir)" % root)
            print(pal.paint("\n  Backups:", "cyan"))
            for i, c in enumerate(cands, 1):
                print("    %d) %s" % (i, os.path.basename(c)))
            sel = ask("Which backup number", pal).strip()
            if not (sel.isdigit() and 1 <= int(sel) <= len(cands)):
                self._fail("not a listed backup")
            bundle = cands[int(sel) - 1]
        if not bundle or not os.path.isdir(bundle):
            self._fail("backup bundle not found (pass --bundle-dir)")
        man_path, env_path = os.path.join(bundle, "manifest.json"), os.path.join(bundle, "env")
        if not (os.path.exists(man_path) and os.path.exists(env_path)):
            self._fail("that bundle is missing manifest.json or env - refusing to restore")
        try:
            manifest = json.load(open(man_path, encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self._fail("could not read the manifest: %s" % exc)
        bundle_env = parse_env(open(env_path, encoding="utf-8").read())
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
        for e in (manifest.get("volumes") or []):
            role = e.get("role") if isinstance(e, dict) else None
            if role not in VOLUME_BASENAMES:
                self._fail("the backup manifest lists an unknown volume role %r - refusing to restore" % role)
            plan.append((names[role], "%s.tar.gz" % VOLUME_BASENAMES[role]))
        force = bool(getattr(args, "force", False)) if args else False
        existing = [v for v, _ in plan if volume_exists(v)]
        if existing and not force:
            self._fail("these target volumes already exist: %s - Reset them first, or pass --force to "
                       "overwrite (this replaces their contents)." % ", ".join(existing))
        for vol, archive in plan:
            if not os.path.exists(os.path.join(bundle, archive)):
                self._fail("the bundle is missing %s (for volume %s) - refusing to restore" % (archive, vol))
            print(pal.paint("  restoring %s ..." % vol, "cyan"))
            if not untar_volume(vol, bundle, archive):
                self._fail("failed to restore volume %s from %s" % (vol, archive))
        # install the paired .env (mode-600) so the set is whole again.
        _copy_secret(env_path, self._env_path())
        tighten_secret_file(self._env_path())
        print(pal.paint("\n  Restored set '%s' (%d volume(s)) + its .env." % (prefix, len(plan)), "green"))
        print(pal.paint("  Run Setup to start it (the secret check will confirm the pairing).\n", "cyan"))

    def _load_env(self):
        """Parse the current .env (best-effort: {} if absent or unreadable)."""
        env, env_path = {}, self._env_path()
        try:
            if os.path.exists(env_path):
                env = parse_env(open(env_path, encoding="utf-8").read())
        except OSError:
            pass
        return env

    def _archive_env(self, label):
        """Move the current .env aside as .env.<label> so it isn't lost / left live. Collision-safe
        (never clobbers an existing archive). Returns the archive path, or None if there was no .env."""
        env_path = self._env_path()
        if not os.path.exists(env_path):
            return None
        base = os.path.join(self.root, ".env." + label)
        dest, n = base, 1
        while os.path.exists(dest):
            dest = "%s.%d" % (base, n)
            n += 1
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
        one. Does NOT start it (run Setup next); the current set's volumes are left intact."""
        pal = self.pal
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
            print("  Your previous set's .env was saved at: %s" % archived)
        print(pal.paint("  Run Setup to build + start the new (empty) set.\n", "cyan"))

    def _volume_repoint(self, env, args=None):
        """Point the deployment at ANOTHER set. Requires that set's matching .env (auto-found as
        .env.<prefix>, or --env-source), verifies it names the target set, and validates it against the
        set's data via the secret guard - refusing on mismatch and RESTORING the current .env."""
        pal = self.pal
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
            cands = sorted(glob.glob(os.path.join(self.root, ".env." + target)) +
                           glob.glob(os.path.join(self.root, ".env." + target + ".*")))
            if cands:
                src = cands[-1]
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
        print(pal.paint("\n  Set '%s' destroyed." % prefix, "green"))
        if archived:
            print("  Its .env (no longer matching any data) was moved to: %s" % archived)
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
        return fallback, "this checkout's VERSION file (nothing is running to ask)"

    def _describe_hop(self, plan, source, current, tag):
        """Print what the hop does. Returns nothing; the caller decides what to require."""
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
        print("    steps        : %d adjacent release(s)" % len(plan["steps"]))
        print("    reversible   : %s" % ("no" if plan["irreversible"] else "yes"))
        print("    backup       : %s" % ("required" if plan["requires_backup"] else "not required"))
        for condition in plan["conditions"]:
            print(pal.paint("    note         : %s" % condition.get("summary", ""), "yellow"))
            if condition.get("detect"):
                print("                   check with: %s" % condition["detect"])

    def _require_backup(self, args, interactive, reason):
        """Take a backup, or accept an operator's word that one exists. False = do not proceed.

        Takes one by default rather than looking for a recent bundle and trusting it. What this
        does NOT do is prove the backup restores -- verifying that means standing up a second
        deployment from it, which this command is not going to do behind the operator's back. The
        prompt says so rather than implying a guarantee it cannot make.
        """
        pal = self.pal
        print(pal.paint("\n  A backup is required: %s" % reason, "yellow"))
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
        build (--source), recreate, and health-wait."""
        pal = self.pal
        ok, msg = docker_available()
        if not ok:
            self._fail(msg)
        env = self._load_env()
        current, version_source = self._running_version(env.get("COMPOSE_PROFILES", "combined"))
        interactive = not (args and getattr(args, "non_interactive", False))
        print(pal.paint("\n  DockVault update", "cyan"))
        print("  current version : %s  (from %s)" % (current, version_source))
        print("  update check    : %s (every %s min)" % (
            (env.get("UPDATE_CHECK_ENABLED") or "false"),
            env.get("UPDATE_CHECK_INTERVAL_MINUTES") or "360"))

        tag = getattr(args, "tag", None) if args else None
        from_source = bool(getattr(args, "source", False)) if args else False
        if not tag:
            tags = fetch_release_tags()
            if tags:
                print(pal.paint("\n  Available releases (newest first):", "cyan"))
                for t in tags[:15]:
                    print("    %s%s" % (t, "   <- current" if parse_semver(t) == parse_semver(current) else ""))
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

        matrix, matrix_source = fetch_upgrade_matrix(tag, root=self.root)
        plan = plan_upgrade_path(matrix, current, tag)

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

        self._describe_hop(plan, matrix_source, current, tag)

        if plan["blocked"] is not None:
            self._fail("the upgrade matrix says this change must not be taken directly: %s"
                       % plan["blocked"].get("reason", "no reason recorded"))

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

        # An irreversible change is acknowledged in words, not with a keypress. The point is to
        # make the operator state the thing they are accepting, so it cannot be got past by
        # reflex on a prompt that looks like every other prompt.
        if plan["irreversible"] and interactive:
            typed = ask("This change cannot be rolled back. Type 'i accept' to continue", pal)
            if typed.strip().lower() != "i accept":
                print(pal.paint("  Cancelled.\n", "yellow"))
                return

        if plan["requires_backup"] or plan["irreversible"] or down:
            why = ("the matrix marks this change as needing one" if plan["requires_backup"]
                   else "this change cannot be rolled back" if plan["irreversible"]
                   else "this is a downgrade, and there are no down-migrations")
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

        for index, leg_version in enumerate(legs, start=1):
            leg_tag = leg_version if leg_version.startswith("v") else "v" + leg_version
            if len(legs) > 1:
                print(pal.paint("\n  Stage %d of %d: %s" % (index, len(legs), leg_tag), "cyan"))
            if not self._perform_leg(leg_tag, from_source, index, len(legs)):
                return

        healthy = self._wait_secure_healthy(self._load_env().get("COMPOSE_PROFILES", "combined"))
        print(pal.paint("\n  Update to %s: %s.\n" % (tag, "healthy" if healthy else "NOT healthy - check the logs"),
                        "green" if healthy else "red"))

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
            self._set_env_key(self._env_path(), "DOCKVAULT_IMAGE", image)
            print(pal.paint("  set DOCKVAULT_IMAGE=%s; pulling ..." % image, "cyan"))
            try:
                pr = self._run_dc("pull", capture=False, timeout=600)
            except (OSError, subprocess.SubprocessError) as exc:
                self._fail("docker compose pull failed: %s" % exc)
            if pr.returncode != 0:
                self._fail("docker compose pull failed - is %s published? (or use --source to build)" % image)

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
        print("  and a LOG_TOKEN_PEPPER (>=32 chars); then, in the vault UI under Settings -> Logs, tick")
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
        print(pal.paint("  Now open Settings -> Logs in the vault UI, tick the Web/SFTP component, and mint a "
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
    sp.add_argument("--admin-password", dest="admin_password")
    sp.add_argument("--cert-mode", dest="cert_mode", choices=CERT_MODES, help="selfsigned | letsencrypt | byo")
    sp.add_argument("--le-email", dest="le_email", help="email for Let's Encrypt expiry notices")
    sp.add_argument("--cert-path", dest="cert_path", help="bring-your-own fullchain cert (PEM)")
    sp.add_argument("--key-path", dest="key_path", help="bring-your-own private key (PEM)")
    sp.add_argument("--web-port", dest="web_port", type=int, help="host port for HTTPS (default 443)")
    sp.add_argument("--sftp-port", dest="sftp_port", type=int, help="host port for SFTP (default 2322)")
    sp.add_argument("--enable-sftp", dest="enable_sftp", action="store_true", help="also serve SFTP")
    sp.add_argument("--split", dest="split", action="store_true", help="two containers (vault-api + vault-sftp)")
    sp.add_argument("--image-source", dest="image_source", choices=("release", "build"),
                    help="release = pull the published GHCR image | build = build this checkout "
                         "(default with --non-interactive; interactive setup asks)")
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
    bp.add_argument("--action", dest="backup_action", choices=("backup", "restore"),
                    help="backup the current set | restore a bundle")
    bp.add_argument("--backup-dir", dest="backup_dir", help="directory to write/list bundles (default <root>/backups)")
    bp.add_argument("--bundle-dir", dest="bundle_dir", help="restore: the bundle directory to restore")
    bp.add_argument("--force", dest="force", action="store_true", help="restore: overwrite existing target volumes")
    bp.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags, never prompt")

    up = parsers["update"]
    up.add_argument("--tag", dest="tag", help="version tag to switch to (e.g. v0.6.0)")
    up.add_argument("--source", dest="source", action="store_true", help="build from source (git checkout) instead of pulling the GHCR image")
    up.add_argument("--yes", dest="yes", action="store_true", help="confirm the version change (required in --non-interactive)")
    up.add_argument("--dry-run", dest="dry_run", action="store_true", help="report what the change involves and stop, changing nothing")
    up.add_argument("--backup-verified", dest="backup_verified", action="store_true", help="you keep backups elsewhere; skip taking one (not checked)")
    up.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags, never prompt")

    lp = parsers["logs"]
    lp.add_argument("--enable", dest="enable", action="store_true", help="enable authenticated log pull (opt-in)")
    lp.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags, never prompt")

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

    parsers["stop"].add_argument("--lock", dest="lock", action="store_true",
                                 help="also seal .env into .env.enc after stopping")
    return p


def unbuffer_stdout(stream=None):
    """Line-buffer stdout so progress lines appear WHEN THEY HAPPEN. Python block-buffers stdout in
    8 KB chunks whenever it is not a terminal (a pipe, `tee`, a CI log, an MSYS/mintty console), which
    makes a long docker step look frozen and then dumps everything at once. Best-effort: a stream
    without reconfigure() (Python < 3.7 / a replaced stdout) is left alone."""
    stream = sys.stdout if stream is None else stream
    try:
        stream.reconfigure(line_buffering=True)
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
