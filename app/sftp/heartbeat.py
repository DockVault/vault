"""The SFTP server's heartbeat file, and the container healthcheck that reads it.

A bound port says a process once called listen(); it says nothing about whether that process is
still doing anything. So the SFTP server touches a small file every few seconds for as long as it
is actually alive (see ``_Liveness`` in sftp_server.py for what "alive" means), and the container
healthcheck is this module run as a program:

    python -B -m app.sftp.heartbeat        exit 0 = touched recently, 1 = stale or missing

It reads a file's age and nothing else. It opens no socket -- a bare TCP connect makes paramiko log
"Error reading SSH protocol banner" on every probe -- and it imports nothing but the standard
library, so a check costs a Python start-up and one stat().

WHAT IT CAN AND CANNOT TELL YOU. The beats stop when the accept loop or the write-progress watchdog
has stopped turning, and when an upload that was told to stop is still holding its thread half a
minute later. That last one is how a storage write that never returns shows up -- and ONLY how: it
is the watchdog that tells a stalled upload to stop, so with the watchdog switched off
(SFTP_WRITE_PROGRESS_TIMEOUT_SECONDS=0) a stuck storage write is never reported. Nor is a stuck
download, or a stuck commit after the client's own CLOSE: nothing tells those to stop. It is also
slow by construction -- the watchdog's window, then the half minute, then a stale file, then the
container's five failed checks: five to six minutes from the storage stalling to "unhealthy" at
the defaults. It recovers without a restart: when the write returns, the beats resume.

The writer and the check must agree on the path and on what "recently" means, which is why both
live here and nowhere else.
"""
import os
import sys
import tempfile
import time

# The server touches the file this often while it is alive...
BEAT_SECONDS = 5
# ...and the check calls it stale at this age: several missed beats, never just one late one.
STALE_AFTER_SECONDS = 30

HEARTBEAT_FILE_ENV = "SFTP_HEARTBEAT_FILE"
_DEFAULT_NAME = "dockvault-sftp.heartbeat"


def heartbeat_path() -> str:
    """Where the heartbeat lives: SFTP_HEARTBEAT_FILE, else the system temp directory (/tmp in the
    container, which the hardened compose mounts as a tmpfs because its root is read-only)."""
    return os.environ.get(HEARTBEAT_FILE_ENV) or os.path.join(tempfile.gettempdir(), _DEFAULT_NAME)


def beat(path=None, now=None) -> None:
    """Touch the heartbeat. Raises OSError when the file cannot be written; the caller decides
    what that means (the server logs it once and carries on -- the check then reports stale, which
    is the truth as far as anything outside the process can tell)."""
    path = path or heartbeat_path()
    now = time.time() if now is None else now
    # Never follow a link left at a predictable name in a shared temp directory.
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o644)
    try:
        os.write(fd, str(int(now)).encode("ascii"))
    finally:
        os.close(fd)
    os.utime(path, (now, now))


def age_seconds(path=None, now=None):
    """Seconds since the last beat, or None when there is no heartbeat file at all."""
    path = path or heartbeat_path()
    now = time.time() if now is None else now
    try:
        return now - os.stat(path).st_mtime
    except OSError:
        return None


def is_fresh(path=None, now=None, stale_after=STALE_AFTER_SECONDS) -> bool:
    """A missing file is stale. So is one from the future by more than the same margin: a clock
    that was stepped back must not make a dead server look alive for however long the step was."""
    age = age_seconds(path, now)
    return age is not None and -stale_after <= age < stale_after


def main() -> int:
    return 0 if is_fresh() else 1


if __name__ == "__main__":
    sys.exit(main())
