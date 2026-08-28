"""`backup --lock` seals a bundle's .env so a stolen backup can't decrypt the stored files.

The bundle's `env` holds ENCRYPTION_KEY; sealing it into `env.enc` (envelope encryption -- the same
crypto as `dockvault.py lock`) means a thief without the passphrase or recovery key cannot open the
key that decrypts storage. Recoverability is critical, so this pins the full round-trip: seal (with
verify-before-destroy) -> unseal by passphrase AND by recovery key -> identical bytes; a wrong
passphrase fails and (in the restore path) never touches the deployment.
"""
from __future__ import annotations

import argparse

import pytest

import dockvault as dv

pytestmark = pytest.mark.unit

_ENV = b"ENCRYPTION_KEY=abc123\nVAULT_DB_PASSWORD=s3cret\nADMIN_PASSWORD=hunter2\n"


def _needs_crypto():
    if dv.load_fernet() is None:
        pytest.skip("cryptography not installed")


def _bundle_with_env(tmp_path):
    bundle = tmp_path / "dockvault-set-1"
    bundle.mkdir()
    (bundle / "env").write_bytes(_ENV)
    return bundle


def _passfile(tmp_path, name, value):
    p = tmp_path / name
    p.write_text(value + "\n", encoding="utf-8")
    return str(p)


def test_seal_removes_plaintext_and_writes_a_recovery_key(tmp_path):
    _needs_crypto()
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    bundle = _bundle_with_env(tmp_path)
    rout = tmp_path / "recovery.txt"
    args = argparse.Namespace(passphrase_file=_passfile(tmp_path, "pass.txt", "seal-passphrase-1"),
                              passphrase_stdin=False, hint=None, recovery_out=str(rout),
                              non_interactive=True)

    tool._seal_bundle_env(str(bundle), args)

    assert not (bundle / "env").exists(), "the plaintext env is removed after sealing"
    assert (bundle / "env.enc").exists(), "the sealed env.enc is written"
    assert rout.read_text().strip(), "a recovery key was emitted to --recovery-out"


def test_a_sealed_bundle_opens_by_passphrase_and_by_recovery_key(tmp_path):
    _needs_crypto()
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    bundle = _bundle_with_env(tmp_path)
    rout = tmp_path / "recovery.txt"
    seal_args = argparse.Namespace(passphrase_file=_passfile(tmp_path, "pass.txt", "seal-passphrase-1"),
                                   passphrase_stdin=False, hint=None, recovery_out=str(rout),
                                   non_interactive=True)
    tool._seal_bundle_env(str(bundle), seal_args)
    recovery_key = rout.read_text().strip()
    enc = str(bundle / "env.enc")

    # by passphrase
    by_pass = tool._unseal_bundle_env(enc, argparse.Namespace(
        passphrase_file=_passfile(tmp_path, "pass2.txt", "seal-passphrase-1"),
        passphrase_stdin=False, recovery_key_file=None, use_recovery_key=False))
    assert by_pass == _ENV, "unsealing by passphrase returns the exact original bytes"

    # by recovery key
    by_rk = tool._unseal_bundle_env(enc, argparse.Namespace(
        recovery_key_file=_passfile(tmp_path, "rk.txt", recovery_key), use_recovery_key=True,
        passphrase_file=None, passphrase_stdin=False))
    assert by_rk == _ENV, "unsealing by recovery key returns the exact original bytes"


def test_a_wrong_passphrase_is_rejected(tmp_path):
    _needs_crypto()
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    bundle = _bundle_with_env(tmp_path)
    tool._seal_bundle_env(str(bundle), argparse.Namespace(
        passphrase_file=_passfile(tmp_path, "pass.txt", "the-real-passphrase"),
        passphrase_stdin=False, hint=None, recovery_out=None, non_interactive=True))

    with pytest.raises(SystemExit):   # _unseal_bundle_env -> self._fail on a bad credential
        tool._unseal_bundle_env(str(bundle / "env.enc"), argparse.Namespace(
            passphrase_file=_passfile(tmp_path, "wrong.txt", "not-the-passphrase"),
            passphrase_stdin=False, recovery_key_file=None, use_recovery_key=False))


def test_a_failed_seal_keeps_the_complete_plaintext_bundle(tmp_path, monkeypatch):
    """Recoverability: if the sealed env fails verify-before-destroy, the complete plaintext bundle
    must be kept (a valid UNSEALED backup) and the broken env.enc removed -- never discarded."""
    _needs_crypto()
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    bundle = _bundle_with_env(tmp_path)
    # A corrupt seal: verification returns different bytes than were sealed -> the round-trip fails.
    monkeypatch.setattr(dv, "env_lock_open", lambda *a, **k: (b"CORRUPTED-NOT-THE-ENV", b"dek"))
    args = argparse.Namespace(passphrase_file=_passfile(tmp_path, "pass.txt", "seal-passphrase-1"),
                              passphrase_stdin=False, hint=None, recovery_out=None, non_interactive=True)

    with pytest.raises(SystemExit):
        tool._seal_bundle_env(str(bundle), args)

    assert (bundle / "env").exists(), "a failed seal keeps the plaintext bundle (still restorable)"
    assert not (bundle / "env.enc").exists(), "the broken partial env.enc is removed"


def test_non_interactive_seal_without_a_passphrase_source_fails_fast_and_keeps_the_bundle(tmp_path):
    """--lock --non-interactive with no --passphrase-file/-stdin must fail immediately (never prompt
    or hang), and must not destroy the complete plaintext bundle."""
    _needs_crypto()
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    bundle = _bundle_with_env(tmp_path)
    args = argparse.Namespace(non_interactive=True, passphrase_file=None, passphrase_stdin=False,
                              hint=None, recovery_out=None)

    with pytest.raises(SystemExit):
        tool._seal_bundle_env(str(bundle), args)

    assert (bundle / "env").exists(), "a usage error keeps the plaintext bundle"
    assert not (bundle / "env.enc").exists()


def test_the_backup_subcommand_exposes_lock_and_credential_flags():
    # Config-sync / discoverability: the flags the seal+restore need must be on the backup parser.
    import io
    from contextlib import redirect_stdout
    parser = dv.build_parser() if hasattr(dv, "build_parser") else None
    if parser is None:
        pytest.skip("no build_parser() to introspect")
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            parser.parse_args(["backup", "--help"])
        except SystemExit:
            pass
    help_text = buf.getvalue()
    for flag in ("--lock", "--passphrase-file", "--use-recovery-key", "--recovery-key-file"):
        assert flag in help_text, "backup --help must document %s" % flag
