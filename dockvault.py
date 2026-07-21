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
    if cfg.get("run_sftp"):
        bare("RUN_SFTP", "1")
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
        if _try(["openssl"] + args, cwd=cert_dir, env=env, timeout=60):
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
            summary = {"server_name": existing.get("SERVER_NAME") or existing.get("ALLOWED_HOSTS") or "",
                       "admin_username": existing.get("ADMIN_USERNAME") or "admin",
                       "compose_profiles": migrated,
                       "run_sftp": (existing.get("RUN_SFTP") or "").strip() in ("1", "true", "yes", "on")}
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
                       "admin_password": cfg["admin_password"] if cfg["_generated_pw"] else None}

        # ---- certificate (self-signed; keep an existing pair) ----
        while tracker.current < steps.index("Certificate"):
            tracker.advance()
        tracker.show()
        cert_dir = self._certs_dir()
        if _cert_pair_present(cert_dir):
            print(pal.paint("  Certificates already present - keeping them.", "green"))
        else:
            server = summary.get("server_name") or "localhost"
            if not validate_server_name(server):   # re-validate a reused .env's SERVER_NAME before it hits openssl
                print(pal.paint("  SERVER_NAME in .env looks invalid; using 'localhost' for the cert.", "yellow"))
                server = "localhost"
            ok, msg = generate_self_signed_cert(cert_dir, server)
            if not ok:
                self._fail(msg)
            print(pal.paint("  " + msg + ".", "green"))
            if not tighten_secret_file(os.path.join(cert_dir, "key.pem")):
                print(pal.paint("  WARNING: could not restrict the TLS key's permissions.", "yellow"))

        if no_start:
            print(pal.paint("\n  Setup done (--no-start). Start later with:  python dockvault.py setup\n", "cyan"))
            return

        # ---- build + start + health ----
        ok, msg = docker_available()
        if not ok:
            self._fail(msg)
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
            enable_sftp = confirm("Enable SFTP (SSH-encrypted, publishes port 2322)?", pal, default=False)
            split = confirm("Run web + SFTP as TWO containers (split) instead of one combined?", pal, default=False)
            update_check = confirm("Enable the opt-in 'update available' check (asks GitHub, no telemetry)?", pal, default=False)
            log_pull = confirm("Enable the authenticated log-pull endpoint (sets a pepper; still off until a component is ticked)?", pal, default=False)
        else:
            enable_sftp, split = bool(a("enable_sftp")), bool(a("split"))
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
            "run_sftp": enable_sftp,
            "update_check_enabled": update_check,
            "plan_log_pull": log_pull,
            "log_token_pepper": gen_hex(32) if log_pull else "",
            "_generated_pw": generated,
        }

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
        print(pal.paint(" Web UI / API : https://%s/          (host port 443)" % name, "bold", "green"))
        if summary.get("run_sftp"):
            print(" SFTP (SSH)   : %s port 2322" % name)
        if summary.get("admin_username"):
            print(" Admin login  : %s" % summary["admin_username"])
        if summary.get("admin_password"):
            print(pal.paint(" Admin passwd : %s   (auto-generated - store it NOW)" % summary["admin_password"], "yellow"))
        print(pal.paint("\n *** BACK UP .env OFF THIS HOST - it holds ENCRYPTION_KEY. ***", "yellow"))
        print(pal.paint("===================================================================\n", "blue"))

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
    parsers = {key: sub.add_parser(key, help=label.split(" - ", 1)[-1]) for key, label in MENU}
    sp = parsers["setup"]
    sp.add_argument("--server-name", dest="server_name")
    sp.add_argument("--admin-username", dest="admin_username")
    sp.add_argument("--admin-email", dest="admin_email")
    sp.add_argument("--admin-password", dest="admin_password")
    sp.add_argument("--enable-sftp", dest="enable_sftp", action="store_true", help="also serve SFTP on 2322")
    sp.add_argument("--split", dest="split", action="store_true", help="two containers (vault-api + vault-sftp)")
    sp.add_argument("--update-check", dest="update_check", action="store_true", help="enable the opt-in update check")
    sp.add_argument("--enable-log-pull", dest="enable_log_pull", action="store_true", help="enable the log-pull endpoint")
    sp.add_argument("--non-interactive", dest="non_interactive", action="store_true", help="use flags/defaults, never prompt")
    sp.add_argument("--no-start", dest="no_start", action="store_true", help="author .env + certs but don't build/start")
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
