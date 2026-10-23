"""SFTP host-key material: a modern key for new installs, loading either kind.

A new install has no host key yet, so one is generated on first boot. Ed25519 is used for that:
it is smaller and faster than RSA and has no key-size question to get wrong. Existing installs
keep whatever they generated on their own first boot -- an RSA key at the same path -- because a
host key is a trust anchor: regenerating it would change the fingerprint every SFTP client has
already accepted and make every reconnection look like a man-in-the-middle. So an upgrade must
never regenerate, and loading tries Ed25519 first and falls back to RSA.

The configured path keeps its historical ``ssh_host_rsa_key`` name so an existing deployment's key
is found unchanged; on a new install the file at that path simply holds an Ed25519 key.

Both the web server and the SFTP server write the key when there is none (ensure_host_key), and they
can start together. A key is therefore never written over: it is written whole and synced under a
name of its own first, and only then given its path, by a hard link that fails when the path is
taken. Whichever start comes second keeps the first one's key, and an SFTP server always serves the
key on the disk.
"""
from __future__ import annotations

import errno
import os
import secrets
import stat
import time
from pathlib import Path
from typing import Union

import paramiko

from app.core import durable_write

# What os.link fails with on a filesystem that has no hard links: the key is then created at its path itself.
_NO_HARD_LINKS = frozenset({errno.EPERM, errno.EMLINK, errno.ENOSYS, errno.EOPNOTSUPP,
                            getattr(errno, "ENOTSUP", errno.EOPNOTSUPP)})
# How long a start waits for a key another start is still writing at its path (where there are no hard links).
WHOLE_KEY_WAIT_SECONDS = 5.0


def _new_key_bytes() -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _owner_only(path: Path) -> None:
    # os.open's mode is subject to umask; pin the intended perms where the platform honours it.
    try:
        os.chmod(str(path), stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def generate_ed25519_host_key(path: Union[str, Path]) -> bool:
    """Write a fresh Ed25519 private key (OpenSSH format, owner-only) to ``path`` unless a key is there; True when
    this call put it there, False when another start put one there first (that key stays).

    The key is written to a temporary file beside it, created exclusively and owner-only, and synced; only then is
    it given its path, by a hard link, which fails when the path is taken: so no key is ever written over, and none
    is ever seen half-written at its path (a key lost to a power cut soon after the first start would leave an
    empty file there, which the next start cannot load and does not replace). The directory is synced last, so the
    name survives a power cut too; when that sync fails the key stays (its bytes were on the disk before it had its
    name) and the error is raised. On a filesystem with no hard links the key is created at its path exclusively
    instead (_write_in_place).
    """
    path = Path(path)
    durable_write.make_directories(path.parent)
    data = _new_key_bytes()
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(6)}.new")
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            _write_all(fd, data)
            durable_write.sync_file(fd)
        finally:
            os.close(fd)
        _owner_only(temporary)
        try:
            os.link(str(temporary), str(path))
        except FileExistsError:
            return False
        except OSError as exc:
            if exc.errno not in _NO_HARD_LINKS:
                raise
            return _write_in_place(path, data)
    finally:
        try:
            os.unlink(str(temporary))
        except FileNotFoundError:
            pass
    durable_write.sync_directory(path.parent)
    return True


def _write_in_place(path: Path, data: bytes) -> bool:
    """The key created at ``path`` itself, exclusively (never over another), written and synced, its directory
    synced: for a filesystem with no hard links. A key this call could not write whole is removed (it created it,
    so it is no other start's)."""
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    try:
        try:
            _write_all(fd, data)
            durable_write.sync_file(fd)
        finally:
            os.close(fd)
    except BaseException:
        try:
            os.unlink(str(path))
        except OSError:
            pass
        raise
    _owner_only(path)
    durable_write.sync_directory(path.parent)
    return True


def ensure_host_key(path: Union[str, Path]) -> bool:
    """Generate the SFTP host key at ``path`` when there is none yet; True when this call wrote it. The web server
    calls it at its start, and the SFTP server before it loads its key: in the split layout the SFTP container
    mounts the keys volume read-only (the audit chain's head record lives there, and only the web server may write
    it), so its key must exist before it starts, and the web server starts first. An existing key is never
    touched, so its fingerprint never changes, and a key that could not be synced never gets its path (the
    temporary copy is removed). Never raises: an SFTP server that still finds no key reports that itself."""
    path = Path(path)
    try:
        if path.exists():
            return False
    except OSError:
        return False
    try:
        return generate_ed25519_host_key(path)
    except OSError:
        return False


def load_whole_host_key(path: Union[str, Path], wait_seconds: float = WHOLE_KEY_WAIT_SECONDS) -> paramiko.PKey:
    """load_host_key, waiting up to ``wait_seconds`` while the file at ``path`` does not parse yet: a start on a
    filesystem with no hard links may find a key another start is still writing at its path. A missing file
    raises at once."""
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            return load_host_key(path)
        except (paramiko.SSHException, ValueError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def load_host_key(path: Union[str, Path]) -> paramiko.PKey:
    """Load an SFTP host key, trying Ed25519 (new installs) then RSA (existing installs).

    A missing or unreadable file raises through (the caller has already ensured the file exists);
    only a type mismatch -- the wrong key class for the file -- is caught, so the next class is
    tried. If neither class can parse it, the last parse error is raised.
    """
    path = str(path)
    last_error: Union[Exception, None] = None
    for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey):
        try:
            return key_cls.from_private_key_file(path)
        except (paramiko.SSHException, ValueError) as exc:
            last_error = exc
    raise last_error if last_error else paramiko.SSHException("no host key could be loaded")
