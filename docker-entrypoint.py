#!/usr/local/bin/python
"""Container entrypoint: make persistent volumes usable by the non-root runtime user, then
drop privileges and exec the real command.

The app runs as the non-root 'appuser' (uid 10001) for defense-in-depth (this is the
vault container handling untrusted uploads / SFTP / at-rest crypto). But a
persistent volume (/app/keys, /app/storage, ...) that was first created by an OLDER, root-era
image is owned by root, so after an in-place UPGRADE to this non-root image the appuser can
neither read its SSH host key nor its stored files, and the container crash-loops
(PermissionError: 'keys/ssh_host_rsa_key', and — worse — its stored /app/storage files
become unreadable).

This entrypoint runs briefly as root ONLY to chown those volumes back to appuser, then drops
to appuser and execs the command — so the workload itself never runs as root (the postgres/
redis official-image pattern). Fresh volumes are already appuser-owned (Dockerfile chown), so
the recursive fix is skipped via a cheap top-level owner check. If the container is already
started as non-root (no override needs it), it just execs the command unchanged.
"""
import os
import sys

_APP_USER = "appuser"
# Persistent / writable mount points an older root-era image may have created root-owned.
_VOLUME_DIRS = ("/app/keys", "/app/storage", "/app/logs", "/app/brand", "/app/certs")

# Secrets an operator may supply via a mounted file (the Docker / Kubernetes "<NAME>_FILE"
# convention) instead of a plaintext value in .env. Read-old: the plain <NAME> still works and takes
# precedence, so an existing deployment is unaffected. DATABASE_URL is here for completeness, but the
# compose files assemble it from VAULT_DB_PASSWORD and set it directly, so DATABASE_URL_FILE only
# takes effect on a compose that does not.
_FILE_SECRETS = (
    "ENCRYPTION_KEY",
    "JWT_SECRET_KEY",
    "REDIS_PASSWORD",
    "ADMIN_PASSWORD",
    "LOG_TOKEN_PEPPER",
    "INVITE_TOKEN_PEPPER",
    "DATABASE_URL",
)


def _expand_file_secrets():
    """Populate a secret env var from <NAME>_FILE when the plain <NAME> is not already set, so an
    operator can keep secrets out of a plaintext .env. The plain value wins if both are present
    (read-old). Trailing CR/LF is stripped (the usual shape of ``printf secret > file``). Runs before
    the privilege drop so a root-owned secret file is still readable. Never raises: a bad file leaves
    <NAME> unset so the app fails closed on it, rather than crash-looping the container."""
    for name in _FILE_SECRETS:
        path = os.environ.get(name + "_FILE")
        if not path or os.environ.get(name):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                os.environ[name] = fh.read().rstrip("\r\n")
        except OSError as exc:
            sys.stderr.write("[entrypoint] could not read %s_FILE (%s); %s left unset\n"
                             % (name, exc, name))
        except Exception:  # noqa: BLE001 — e.g. the file is not valid UTF-8 text (raw random bytes).
            # NEVER echo the exception here: a UnicodeDecodeError message quotes the offending secret
            # byte. Leave the var unset and let the app's own validation fail closed on it.
            sys.stderr.write("[entrypoint] %s_FILE is not valid UTF-8 text; %s left unset\n"
                             % (name, name))


def _fix_ownership(path, uid, gid):
    """chown -R path to uid:gid, but skip the (possibly large) walk when the top dir is
    already owned correctly — so a fresh/already-fixed volume costs one stat, not a full walk."""
    try:
        st = os.lstat(path)
    except OSError:
        return
    if st.st_uid == uid and st.st_gid == gid:
        return
    try:
        os.chown(path, uid, gid)
    except OSError:
        pass
    for root, dirs, files in os.walk(path):
        for name in dirs + files:
            try:
                os.chown(os.path.join(root, name), uid, gid, follow_symlinks=False)
            except OSError:
                pass


def main():
    args = sys.argv[1:] or ["python", "run_combined.py"]
    # Read any file-mounted secrets into the environment BEFORE the privilege drop (so a root-owned
    # secret file is still readable) and before exec, so the workload inherits them.
    _expand_file_secrets()
    if os.geteuid() == 0:
        import pwd
        try:
            pw = pwd.getpwnam(_APP_USER)
        except KeyError:
            os.execvp(args[0], args)  # no such user — run the command as-is
            return
        for d in _VOLUME_DIRS:
            if os.path.isdir(d):
                _fix_ownership(d, pw.pw_uid, pw.pw_gid)
        # Drop privileges: supplementary groups, then gid, then uid (order matters — setuid
        # last, or we'd lose the privilege needed to set the groups/gid).
        os.environ["HOME"] = pw.pw_dir
        try:
            os.initgroups(_APP_USER, pw.pw_gid)
        except OSError as exc:
            # NEVER silently keep root's supplementary group list (incl. gid 0): swallowing this and
            # continuing would run the workload as appuser uid/gid but with root's groups. Log it and
            # fall back to an explicit minimal group set; if THAT fails too, abort rather than run
            # partially privileged.
            sys.stderr.write(f"[entrypoint] initgroups failed ({exc}); falling back to setgroups([{pw.pw_gid}])\n")
            try:
                os.setgroups([pw.pw_gid])
            except OSError as exc2:
                sys.stderr.write(f"[entrypoint] setgroups fallback also failed ({exc2}); refusing to run with root groups\n")
                sys.exit(1)
        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)
        # Fail closed: verify the drop actually took effect before exec'ing the untrusted workload.
        if os.getuid() != pw.pw_uid or os.getgid() != pw.pw_gid or 0 in os.getgroups():
            sys.stderr.write("[entrypoint] privilege-drop verification failed (still uid/gid 0 or in group 0); aborting\n")
            sys.exit(1)
    os.execvp(args[0], args)


if __name__ == "__main__":
    main()
