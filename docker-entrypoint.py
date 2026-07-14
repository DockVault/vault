#!/usr/local/bin/python
"""Container entrypoint: make persistent volumes usable by the non-root runtime user, then
drop privileges and exec the real command.

The app runs as the non-root 'appuser' (uid 10001) for defense-in-depth (this is the
per-customer product container handling untrusted uploads / SFTP / at-rest crypto). But a
persistent volume (/app/keys, /app/storage, ...) that was first created by an OLDER, root-era
image is owned by root, so after an in-place UPGRADE to this non-root image the appuser can
neither read its SSH host key nor its stored files, and the container crash-loops
(PermissionError: 'keys/ssh_host_rsa_key', and — worse — the customer's /app/storage files
become unreadable).

This entrypoint runs briefly as root ONLY to chown those volumes back to appuser, then drops
to appuser and execs the command — so the workload itself never runs as root (the postgres/
redis official-image pattern). Fresh volumes are already appuser-owned (Dockerfile chown), so
the recursive fix is skipped via a cheap top-level owner check. If the container is already
started as non-root (no override needs it), it just execs the command unchanged.
"""
import os
import pwd
import sys

_APP_USER = "appuser"
# Persistent / writable mount points an older root-era image may have created root-owned.
_VOLUME_DIRS = ("/app/keys", "/app/storage", "/app/logs", "/app/brand", "/app/certs")


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
    if os.geteuid() == 0:
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
