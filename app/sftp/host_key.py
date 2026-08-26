"""SFTP host-key material: a modern key for new installs, loading either kind.

A new install has no host key yet, so one is generated on first boot. Ed25519 is used for that:
it is smaller and faster than RSA and has no key-size question to get wrong. Existing installs
keep whatever they generated on their own first boot -- an RSA key at the same path -- because a
host key is a trust anchor: regenerating it would change the fingerprint every SFTP client has
already accepted and make every reconnection look like a man-in-the-middle. So an upgrade must
never regenerate, and loading tries Ed25519 first and falls back to RSA.

The configured path keeps its historical ``ssh_host_rsa_key`` name so an existing deployment's key
is found unchanged; on a new install the file at that path simply holds an Ed25519 key.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Union

import paramiko


def generate_ed25519_host_key(path: Union[str, Path]) -> None:
    """Write a fresh Ed25519 private key (OpenSSH format, owner-only) to ``path``.

    Intended to be called only when no host key exists, so it never overwrites a key a client has
    already trusted. Written with 0600 from creation rather than widened then narrowed.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    # os.open's mode is subject to umask; pin the intended perms where the platform honours it.
    try:
        os.chmod(str(path), stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


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
