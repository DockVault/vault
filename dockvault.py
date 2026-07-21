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
# DOCKVAULT_ROOT overrides it (a checkout elsewhere, or an isolated dir under test).
APP_ROOT = os.environ.get("DOCKVAULT_ROOT") or os.path.dirname(os.path.abspath(__file__))

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


# --- setup: secrets + .env authoring (the pure, testable core) --------------------------------
import base64  # noqa: E402
import glob    # noqa: E402
import re      # noqa: E402

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
    """Normalise a COMPOSE_PROFILES value to the current scheme: keep combined/split; a legacy
    'sftp' -> 'split'; anything else / empty -> 'combined'. Pure (mirrors the setup scripts)."""
    parts = [p.strip().lower() for p in (existing or "").split(",") if p.strip()]
    if "combined" in parts:
        return "combined"
    if "split" in parts or "sftp" in parts:
        return "split"
    return "combined"


def build_env_lines(cfg):
    """Build the .env content (list of lines) from a collected-config dict — deterministic + pure
    (it does NOT generate secrets; the caller passes them in). Values are single-quoted, matching
    the setup scripts' dotenv quoting. `cfg` keys: server_name, encryption_key, jwt_secret_key,
    vault_db_password, redis_password, admin_username, admin_email, admin_password, compose_profiles,
    run_sftp (bool), update_check_enabled (bool), plan_log_pull (bool), log_token_pepper (str)."""
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
    bare("COMPOSE_PROFILES", cfg.get("compose_profiles", "combined"))
    # Stable bundle id: labels this deployment's five volumes so the tool can group them as one set.
    if cfg.get("deployment_id"):
        bare("DEPLOYMENT_ID", cfg["deployment_id"])
    # Only write a non-default volume prefix (a fresh/repointed set); the default keeps the historical
    # volume names so existing deployments are byte-identical.
    if cfg.get("volume_prefix") and cfg["volume_prefix"] != DEFAULT_PROJECT:
        bare("VAULT_VOLUME_PREFIX", cfg["volume_prefix"])
    if cfg.get("run_sftp"):
        bare("RUN_SFTP", "1")
    # Only write a port line when it differs from the compose default (443 web / 2322 sftp).
    if cfg.get("web_host_port") and int(cfg["web_host_port"]) != 443:
        bare("WEB_HOST_PORT", int(cfg["web_host_port"]))
    # split mode always runs the SFTP container, so honour a custom SFTP port there too.
    sftp_active = cfg.get("run_sftp") or cfg.get("compose_profiles") == "split"
    if sftp_active and cfg.get("sftp_host_port") and int(cfg["sftp_host_port"]) != 2322:
        bare("SFTP_HOST_PORT", int(cfg["sftp_host_port"]))
    if cfg.get("update_check_enabled"):
        bare("UPDATE_CHECK_ENABLED", "true")
    if cfg.get("plan_log_pull"):
        # Opting in here closes the log-404 trap: the endpoint needs BOTH the plan flag and a
        # strong pepper before it will serve (then an admin still ticks a component in the UI).
        bare("PLAN_LOG_PULL", "true")
        bare("LOG_TOKEN_PEPPER", "'%s'" % cfg["log_token_pepper"])
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


def apply_cert_owner(cert_dir, run=subprocess.run):
    """Make cert_dir/{cert,key}.pem readable by the in-container app user through the read-only bind
    mount. POSIX-only. On a plain rootful engine, chown to APP_UID (10001) keeping the key mode 600.
    On a userns-remap engine, chown to the MAPPED host uid (resolved from /etc/subuid), keeping 600.
    On a ROOTLESS engine (or when the mapped uid can't be resolved), the container's uid is a
    subordinate host uid we cannot target, so fall back to a world-readable key (644, single-tenant
    host) so the container CAN read it - matching setup-secure.sh, and NEVER falsely reporting a
    mode-600 key when it would be unreadable. Returns (mode600, message)."""
    if os.name == "nt":
        return True, ""  # Docker Desktop bind mounts are readable; no host chown needed
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


# --- secret <-> volume guardrail -------------------------------------------------------------
# The reported footgun: Postgres bakes VAULT_DB_PASSWORD into vault_pg_data on FIRST init and never
# re-reads it, so a fresh/changed .env against a populated volume can't authenticate ("password
# authentication failed for user sftp_user") - and a mismatched ENCRYPTION_KEY makes stored files
# undecryptable. Before starting on an existing volume the tool verifies the current .env's DB
# password authenticates against it and refuses-with-explanation (never printing a secret) on a
# mismatch or an ambiguous result. These vault DB coordinates are fixed by the compose.
PG_USER = "sftp_user"
PG_DB = "sftp_db"


def volume_exists(name, run=subprocess.run):
    """True if a docker volume named `name` exists. Best-effort (False on any docker error)."""
    try:
        r = run(["docker", "volume", "inspect", name], capture_output=True, text=True, timeout=20)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return getattr(r, "returncode", 1) == 0


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
    def _fail(self, msg):
        print(self.pal.paint("ERROR: %s" % msg, "red"))
        raise SystemExit(1)

    def _env_path(self):
        return os.path.join(self.root, ".env")

    def _certs_dir(self):
        return os.path.join(self.root, "certs")

    def setup(self, args=None):
        """Configure + start the standalone HTTPS vault: author (or reuse) .env, generate a
        self-signed cert, then build + start the secure stack. This delivers the self-signed path;
        Let's Encrypt / bring-your-own / rootless-cert-perm handling arrive in a later phase."""
        pal = self.pal
        no_start = bool(args and getattr(args, "no_start", False))
        steps = ["Settings", "Write .env", "Certificate"] + ([] if no_start else ["Build + start", "Health check"])
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
            # migrate a legacy COMPOSE_PROFILES in place (sftp -> split, none -> combined)
            migrated = migrate_compose_profiles(existing.get("COMPOSE_PROFILES"))
            if existing.get("COMPOSE_PROFILES") != migrated:
                self._set_env_key(env_path, "COMPOSE_PROFILES", migrated)
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
            svc = "vault-api" if summary.get("compose_profiles") == "split" else "vault"
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
        # Guardrail: if we're (re)starting on an EXISTING data volume, the current .env's DB password
        # MUST authenticate against it, or the app would loop on a Postgres auth error. Fail closed
        # with a clear diagnosis (the reported "wrong password after re-setup" footgun).
        env_now = parse_env(open(env_path, encoding="utf-8").read()) if os.path.exists(env_path) else {}
        if not self._guard_db_secret(env_now):
            raise SystemExit(1)   # the guard already printed the diagnosis + recovery paths
        # Port preflight: warn (don't block) if the chosen web port is already taken.
        web_port = summary.get("web_host_port") or 443
        if not port_free(web_port):
            print(pal.paint("  WARNING: host port %d is already in use; the web container may fail to bind "
                            "it. Free it first (e.g. sudo ss -ltnp 'sport = :%d')." % (web_port, web_port), "yellow"))
        tracker.advance(); tracker.show()               # -> Build + start
        if not self._start_secure_stack():
            self._fail("the stack did not start - check 'docker compose -f docker-compose.secure.yml logs'.")
        tracker.advance(); tracker.show()               # -> Health check
        healthy = self._wait_secure_healthy(summary.get("compose_profiles", "combined"))
        self._print_setup_summary(summary, healthy)

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

    def _dc(self, *args):
        """docker compose against the root secure shim, anchored to the root .env."""
        return ["docker", "compose", "--env-file", self._env_path(),
                "-f", os.path.join(self.root, "docker-compose.secure.yml")] + list(args)

    def _start_secure_stack(self):
        r = subprocess.run(self._dc("up", "-d", "--build", "--force-recreate", "--remove-orphans"),
                           cwd=self.root, text=True)
        return r.returncode == 0

    def _start_db_only(self):
        """Start ONLY the postgres service on the existing volume (for the pre-up secret check)."""
        try:
            r = subprocess.run(self._dc("up", "-d", "vault-db"), cwd=self.root,
                               capture_output=True, text=True, timeout=180)
        except (OSError, subprocess.SubprocessError):
            return False
        return r.returncode == 0

    def _wait_db_ready(self, tries=20):
        """Poll pg_isready inside vault-db until it accepts connections (readiness, NOT auth)."""
        import time
        for _ in range(tries):
            try:
                r = subprocess.run(["docker", "exec", "vault-db", "pg_isready", "-U", PG_USER, "-d", PG_DB],
                                   capture_output=True, text=True, timeout=15)
            except (OSError, subprocess.SubprocessError):
                time.sleep(2); continue
            if getattr(r, "returncode", 1) == 0:
                return True
            time.sleep(2)
        return False

    def _stop_db_only(self):
        """Stop the probe's vault-db (best-effort) so a refused setup doesn't leave a lone db running."""
        try:
            subprocess.run(self._dc("stop", "vault-db"), cwd=self.root,
                           capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            pass

    def _stop_stack(self):
        """Stop the current stack's CONTAINERS without removing volumes (best-effort). Used before a
        repoint: the fixed container names mean two sets can't run at once, so the current deployment
        must be stopped before we point at (and probe) a different set. Data is untouched (no -v)."""
        try:
            subprocess.run(self._dc("down", "--remove-orphans"), cwd=self.root,
                           capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError):
            pass

    def _guard_db_secret(self, env, exists_fn=None, start_fn=None, wait_fn=None, probe_fn=None, stop_fn=None):
        """Fail-closed guardrail: if vault_pg_data already exists, verify the current .env's
        VAULT_DB_PASSWORD authenticates against it (and ENCRYPTION_KEY is at least a valid key) BEFORE
        starting the stack. Returns True to proceed, False to STOP (after printing a secret-free
        diagnosis). No-op (True) for a fresh volume. The *_fn hooks are injectable for tests."""
        pal = self.pal
        exists_fn = exists_fn or volume_exists
        start_fn = start_fn or self._start_db_only
        wait_fn = wait_fn or self._wait_db_ready
        probe_fn = probe_fn or probe_pg_password
        stop_fn = stop_fn or self._stop_db_only
        vol = "%s_vault_pg_data" % volume_prefix(env)
        if not exists_fn(vol):
            return True   # brand-new volume: the .env password is baked in on first init
        # A stored volume + an ENCRYPTION_KEY that isn't even shaped like a Fernet key is a certain
        # mismatch (files would be undecryptable) - stop before baking a broken pairing.
        if not fernet_key_looks_valid(env.get("ENCRYPTION_KEY", "")):
            self._print_secret_mismatch("encryption_key", vol)
            return False
        print(pal.paint("  Existing data volume found - verifying the .env matches it...", "cyan"))
        if not start_fn() or not wait_fn():
            stop_fn()
            self._print_secret_mismatch("ambiguous", vol)
            return False
        result = probe_fn("vault-db", PG_USER, PG_DB, env.get("VAULT_DB_PASSWORD", ""))
        if db_guard_decision(True, result) == "proceed":
            # Be precise: only VAULT_DB_PASSWORD was AUTHENTICATED against the volume; ENCRYPTION_KEY
            # was only format-checked (stdlib-only, no decryption), so don't claim a full match.
            print(pal.paint("  Secret check OK: VAULT_DB_PASSWORD authenticates against the existing "
                            "data volume (ENCRYPTION_KEY has a valid key format).", "green"))
            return True
        stop_fn()
        self._print_secret_mismatch("db_password" if result == "mismatch" else "ambiguous", vol)
        return False

    def _print_secret_mismatch(self, kind, vol):
        """Explain a secret<->volume mismatch + the two recovery paths. NEVER prints a secret value."""
        pal = self.pal
        print(pal.paint("\nERROR: the current .env does NOT match the existing data volume.", "red"))
        print("  Volume: %s" % vol)
        if kind == "db_password":
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
        svc = "vault-api" if profiles == "split" else "vault"
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

    def _print_setup_summary(self, summary, healthy):
        pal = self.pal
        name = summary.get("server_name") or "<your-server-name>"
        print(pal.paint("\n===================================================================", "blue"))
        if not healthy:
            print(pal.paint(" The vault did NOT report healthy - check the logs:", "red"))
            print("   docker compose -f docker-compose.secure.yml logs --tail 40")
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
        _stub("Backup & Restore", self.pal)

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
            r = subprocess.run(self._dc("down", "-v", "--remove-orphans"), cwd=self.root, text=True, timeout=180)
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

    rp = parsers["reset"]
    rp.add_argument("--confirm", dest="confirm", action="store_true",
                    help="confirm the destructive 'down -v' (required in --non-interactive)")
    rp.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags, never prompt")
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
