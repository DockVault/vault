"""The SFTP host key: Ed25519 for new installs, loading either kind, never regenerating.

A host key is a trust anchor -- a client accepts its fingerprint on first connect and expects it
never to change. So a new install may pick a modern algorithm, but an existing install must keep
loading the key it already has, and an upgrade must not regenerate one. These tests pin all three:
new installs generate Ed25519, an existing RSA key still loads, and the generate-if-absent guard
leaves an existing key (and thus its fingerprint) untouched.
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
