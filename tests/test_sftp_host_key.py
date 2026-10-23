"""The SFTP host key: Ed25519 for new installs, loading either kind, never regenerating.

A host key is a trust anchor -- a client accepts its fingerprint on first connect and expects it
never to change. So a new install may pick a modern algorithm, but an existing install must keep
loading the key it already has, and an upgrade must not regenerate one. These tests pin all three:
new installs generate Ed25519, an existing RSA key still loads, and the generate-if-absent guard
leaves an existing key (and thus its fingerprint) untouched. And a key is written whole and synced before it gets
its path, by a link that never replaces a key another start put there first, so two starts that race serve the
key on the disk.
"""
from __future__ import annotations

import base64
import hashlib
import os
import stat
from pathlib import Path

import paramiko
import pytest

from app.sftp.host_key import generate_ed25519_host_key, load_host_key

pytestmark = pytest.mark.unit


def _fingerprint(key):
    """The SHA256 fingerprint exactly as the /sftp/host-key endpoint computes it."""
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def test_a_new_install_generates_an_ed25519_key(tmp_path):
    path = tmp_path / "ssh_host_rsa_key"          # historical filename, Ed25519 contents
    generate_ed25519_host_key(path)

    key = load_host_key(path)
    assert key.get_name() == "ssh-ed25519"
    assert key.asbytes(), "the generated key exposes a usable public blob"
    # It is written in the OpenSSH private-key format paramiko round-trips.
    assert path.read_bytes().startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permissions")
def test_the_generated_key_is_owner_only(tmp_path):
    path = tmp_path / "ssh_host_rsa_key"
    generate_ed25519_host_key(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"host key must be owner-only, got {oct(mode)}"


def test_an_existing_rsa_key_still_loads(tmp_path):
    """The backward-compatibility guarantee: a deployment that generated RSA on its first boot
    keeps working, because the loader falls back to RSA."""
    path = tmp_path / "ssh_host_rsa_key"
    paramiko.RSAKey.generate(2048).write_private_key_file(str(path))

    key = load_host_key(path)
    assert key.get_name() == "ssh-rsa"
    assert key.asbytes()


def test_the_startup_guard_never_regenerates_an_existing_key(tmp_path):
    """Mirrors start_sftp_server's generate-if-absent-else-load: an existing key is loaded as-is,
    so its fingerprint -- the value clients have trusted -- does not change on a reboot/upgrade."""
    path = tmp_path / "ssh_host_rsa_key"

    def boot():
        if not path.exists():
            generate_ed25519_host_key(path)
        return load_host_key(path)

    first = boot()
    fp_first = _fingerprint(first)
    assert first.get_name() == "ssh-ed25519"          # fresh install picked Ed25519

    # A second boot (as on upgrade) must reuse the same key, not mint a new one.
    second = boot()
    assert _fingerprint(second) == fp_first
    assert second.get_name() == "ssh-ed25519"


def test_an_existing_rsa_key_is_also_left_untouched(tmp_path):
    """The same stability guarantee for the RSA installs that predate Ed25519."""
    path = tmp_path / "ssh_host_rsa_key"
    paramiko.RSAKey.generate(2048).write_private_key_file(str(path))
    before = _fingerprint(load_host_key(path))

    def boot():
        if not path.exists():
            generate_ed25519_host_key(path)
        return load_host_key(path)

    assert _fingerprint(boot()) == before
    assert load_host_key(path).get_name() == "ssh-rsa"


def test_the_loader_raises_on_a_file_that_is_no_key(tmp_path):
    """A corrupt/foreign file is a real error, not a silently-missing key."""
    path = tmp_path / "ssh_host_rsa_key"
    path.write_text("this is not a private key\n", encoding="utf-8")
    with pytest.raises((paramiko.SSHException, ValueError)):
        load_host_key(path)


def test_the_loader_propagates_a_missing_file(tmp_path):
    """A missing key must surface as a real error, not be swallowed by the type-fallback.

    The fallback only catches a wrong-key-type parse (SSHException/ValueError); a missing file
    raises FileNotFoundError, which must escape so the caller sees "no key" rather than a silent
    None. Both call sites guard existence first, so this only guards the fallback's blast radius."""
    with pytest.raises((FileNotFoundError, OSError)):
        load_host_key(tmp_path / "does_not_exist")


def test_the_public_key_export_is_openssh_form_and_public_only(tmp_path):
    """The /sftp/host-key endpoint returns the full public key in OpenSSH form ('<algorithm>
    <base64>') so a client can PIN the host — a fingerprint can verify a key already shown but
    cannot reconstruct a known_hosts entry. It must be exactly two fields, describe the same key
    as the fingerprint, and carry the PUBLIC blob only, never private material."""
    path = tmp_path / "ssh_host_rsa_key"
    generate_ed25519_host_key(path)
    key = load_host_key(path)

    # Built exactly as the endpoint builds it.
    public_key = f"{key.get_name()} {key.get_base64()}"
    algo, sep, b64 = public_key.partition(" ")
    assert sep == " " and public_key.count(" ") == 1, "OpenSSH form is exactly '<algorithm> <base64>'"
    assert algo == key.get_name() == "ssh-ed25519"
    assert "PRIVATE" not in public_key and "BEGIN" not in public_key, "never any private-key material"
    # The base64 field decodes to the key's PUBLIC blob — the same bytes the fingerprint hashes.
    assert base64.b64decode(b64) == key.asbytes()


# ---- written whole, linked into place, never over another key ------------------------------------

DIRS = os.name != "nt"


def _recording(monkeypatch):
    """What reached the disk (a file or a directory, its inode and size), and each link and unlink, in order."""
    events = []
    real_fsync, real_link, real_unlink = os.fsync, os.link, os.unlink

    def fsync(fd):
        st = os.fstat(fd)
        events.append(("dir" if stat.S_ISDIR(st.st_mode) else "file", st.st_ino, st.st_size))
        return real_fsync(fd)

    def link(src, dst, *a, **k):
        real_link(src, dst, *a, **k)
        events.append(("link", os.stat(dst).st_ino))

    def unlink(path, *a, **k):
        events.append(("unlink", os.path.basename(os.fspath(path))))
        return real_unlink(path, *a, **k)
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "link", link)
    monkeypatch.setattr(os, "unlink", unlink)
    return events


def test_a_new_key_is_synced_whole_before_it_gets_its_path_and_its_name_synced_after(tmp_path, monkeypatch):
    """The key is never at its path before its bytes are on the disk, and its name reaches the disk last."""
    path = tmp_path / "keys" / "ssh_host_rsa_key"
    path.parent.mkdir()
    events = _recording(monkeypatch)
    assert generate_ed25519_host_key(path) is True
    ino, size = path.stat().st_ino, path.stat().st_size
    assert [e[0] for e in events] == ["file", "link", "unlink"] + (["dir"] if DIRS else []), events
    assert events[0] == ("file", ino, size) and size > 0             # the bytes it gets its path with
    assert events[1] == ("link", ino)
    assert events[2][1].startswith(".ssh_host_rsa_key.")             # the temporary name, gone
    if DIRS:
        assert events[3][1] == path.parent.stat().st_ino
    assert list(path.parent.iterdir()) == [path]
    assert load_host_key(path).get_name() == "ssh-ed25519"


def test_a_key_already_at_its_path_is_never_written_over(tmp_path):
    """A start that found no key a moment before another start wrote one keeps that one: its fingerprint is the
    one the other start's server may already serve."""
    path = tmp_path / "ssh_host_rsa_key"
    assert generate_ed25519_host_key(path) is True
    before = path.read_bytes()
    assert generate_ed25519_host_key(path) is False
    assert path.read_bytes() == before and list(tmp_path.iterdir()) == [path]


def test_two_starts_that_race_serve_the_key_on_the_disk(tmp_path, monkeypatch):
    """The SFTP server's start and the web server's start both find no key; the web server's is linked first,
    between the SFTP start's write and its link. The SFTP server serves the key on the disk, the web server's."""
    from app.sftp import sftp_server
    path = tmp_path / "ssh_host_rsa_key"
    real_link = os.link
    other = {}

    def link(src, dst, *a, **k):
        if not other:
            other["started"] = True
            other["won"] = generate_ed25519_host_key(dst)              # the other start, meanwhile
        return real_link(src, dst, *a, **k)
    monkeypatch.setattr(os, "link", link)
    served = sftp_server.server_host_key(path)
    assert other["won"] is True
    assert _fingerprint(served) == _fingerprint(load_host_key(path))
    assert list(tmp_path.iterdir()) == [path]


def test_the_sftp_servers_own_write_leaves_nothing_at_the_path_when_the_key_cannot_be_synced(tmp_path, monkeypatch):
    """The SFTP server writes its key through ensure_host_key, as the web server's start does: a key that could not
    be synced never gets its path (nor is its temporary copy left), and the start says so instead of serving it."""
    import errno
    from app.sftp import sftp_server

    def broken(fd):
        raise OSError(errno.EIO, "Input/output error")
    monkeypatch.setattr(os, "fsync", broken)
    path = tmp_path / "ssh_host_rsa_key"
    with pytest.raises(RuntimeError):
        sftp_server.server_host_key(path)
    assert list(tmp_path.iterdir()) == []
    monkeypatch.undo()
    assert sftp_server.server_host_key(path).get_name() == "ssh-ed25519" and list(tmp_path.iterdir()) == [path]


@pytest.mark.parametrize("no_links", ["EPERM", "EOPNOTSUPP"])
def test_a_filesystem_with_no_hard_links_gets_the_key_created_at_its_path_exclusively(tmp_path, monkeypatch,
                                                                                    no_links):
    import errno
    no_links = getattr(errno, no_links)

    def link(*a, **k):
        raise OSError(no_links, os.strerror(no_links))
    monkeypatch.setattr(os, "link", link)
    path = tmp_path / "ssh_host_rsa_key"
    assert generate_ed25519_host_key(path) is True
    before = path.read_bytes()
    assert load_host_key(path).get_name() == "ssh-ed25519" and list(tmp_path.iterdir()) == [path]
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert generate_ed25519_host_key(path) is False and path.read_bytes() == before


def test_with_no_hard_links_a_key_that_cannot_be_synced_is_removed_from_its_path(tmp_path, monkeypatch):
    import errno
    calls = []
    real_fsync = os.fsync

    def fsync(fd):
        calls.append(fd)
        if len(calls) == 2:                                             # the key written at its path
            raise OSError(errno.EIO, "Input/output error")
        return real_fsync(fd)

    def link(*a, **k):
        raise OSError(errno.EPERM, "Operation not permitted")
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "link", link)
    path = tmp_path / "ssh_host_rsa_key"
    with pytest.raises(OSError):
        generate_ed25519_host_key(path)
    assert list(tmp_path.iterdir()) == []


def test_a_start_waits_for_a_key_another_start_is_still_writing_at_its_path(tmp_path):
    import threading
    from app.sftp.host_key import load_whole_host_key
    path = tmp_path / "ssh_host_rsa_key"
    generate_ed25519_host_key(tmp_path / "whole")
    whole = (tmp_path / "whole").read_bytes()
    path.write_bytes(whole[:20])                                         # begun, not finished
    threading.Timer(0.3, lambda: path.write_bytes(whole)).start()
    assert _fingerprint(load_whole_host_key(path, wait_seconds=5)) == _fingerprint(load_host_key(tmp_path / "whole"))
    with pytest.raises((FileNotFoundError, OSError)):
        load_whole_host_key(tmp_path / "does_not_exist", wait_seconds=5)


def test_the_sftp_server_waits_for_a_key_another_start_is_still_writing(tmp_path):
    """On a filesystem with no hard links a key is created at its path and then written: a start that finds it
    there half-written waits for it rather than failing to start."""
    import threading
    from app.sftp import sftp_server
    path = tmp_path / "ssh_host_rsa_key"
    generate_ed25519_host_key(tmp_path / "whole")
    whole = (tmp_path / "whole").read_bytes()
    path.write_bytes(whole[:20])
    threading.Timer(0.3, lambda: path.write_bytes(whole)).start()
    assert _fingerprint(sftp_server.server_host_key(path)) == _fingerprint(load_host_key(tmp_path / "whole"))
