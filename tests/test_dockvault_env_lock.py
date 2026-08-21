"""Unit tests for `dockvault.py lock` / `unlock` — the credential-seal state machine and crypto.

Pure file + crypto, no live engine. Loaded by file path like test_dockvault_tool.py. Needs the
`cryptography` package (the one command in the tool that does).
"""
import argparse
import importlib.util
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

pytest.importorskip("cryptography")

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_mod_lock", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)

ENV_TEXT = (
    "ENCRYPTION_KEY=ZmFrZS1lbmMta2V5\n"
    "VAULT_DB_PASSWORD=s3cr3t-db\n"
    "JWT_SECRET_KEY=jwt-secret\n"
    "ADMIN_PASSWORD=hunter2hunter2\n"
)


@pytest.fixture(autouse=True)
def _hermetic_acl(monkeypatch):
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _p: True)


def _app(root):
    return dv.DockVault(dv.Palette(False), root=str(root))


def _args(**kw):
    base = dict(passphrase_file=None, passphrase_stdin=False, hint=None, recovery_out=None,
                recovery_key=False, recovery_key_file=None, show_recovery_key=False, force=False,
                lock=False, new_passphrase_file=None, new_passphrase_stdin=False)
    base.update(kw)
    return argparse.Namespace(**base)


def _passfile(tmp_path, text="correct horse battery staple"):
    p = tmp_path / "pass.txt"
    p.write_text(text + "\n", encoding="utf-8")
    return str(p)


def _write_env(root):
    (root / ".env").write_text(ENV_TEXT, encoding="utf-8")


def test_lock_then_unlock_roundtrip(tmp_path):
    _write_env(tmp_path)
    app = _app(tmp_path)
    pf = _passfile(tmp_path)
    app.lock(_args(passphrase_file=pf))
    assert not (tmp_path / ".env").exists(), "plaintext .env should be removed after lock"
    assert (tmp_path / ".env.enc").exists()
    assert (tmp_path / ".env.enc").read_text(encoding="utf-8").startswith(dv.ENV_LOCK_MAGIC)
    app.unlock(_args(passphrase_file=pf))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == ENV_TEXT, "unlock must restore byte-for-byte"


def test_unlock_with_recovery_key(tmp_path):
    _write_env(tmp_path)
    app = _app(tmp_path)
    rec = tmp_path / "recovery.txt"
    app.lock(_args(passphrase_file=_passfile(tmp_path), recovery_out=str(rec)))
    assert rec.exists(), "recovery-out should write the recovery key"
    app.unlock(_args(recovery_key=True, recovery_key_file=str(rec)))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == ENV_TEXT


def test_wrong_passphrase_leaves_files_intact(tmp_path):
    _write_env(tmp_path)
    app = _app(tmp_path)
    app.lock(_args(passphrase_file=_passfile(tmp_path, "the-real-passphrase")))
    with pytest.raises(SystemExit):
        app.unlock(_args(passphrase_file=_passfile(tmp_path, "WRONG-passphrase")))
    assert (tmp_path / ".env.enc").exists() and not (tmp_path / ".env").exists()


def test_unlock_refuses_to_clobber_without_force(tmp_path):
    _write_env(tmp_path)
    app = _app(tmp_path)
    pf = _passfile(tmp_path)
    app.lock(_args(passphrase_file=pf))
    (tmp_path / ".env").write_text("SOMETHING-ELSE=1\n", encoding="utf-8")  # a plaintext exists again
    with pytest.raises(SystemExit):
        app.unlock(_args(passphrase_file=pf))               # refuses
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "SOMETHING-ELSE=1\n"
    app.unlock(_args(passphrase_file=pf, force=True))       # --force overwrites
    assert (tmp_path / ".env").read_text(encoding="utf-8") == ENV_TEXT


def test_relock_reuses_dek_so_recovery_key_stays_valid(tmp_path):
    _write_env(tmp_path)
    app = _app(tmp_path)
    pf = _passfile(tmp_path)
    rec = tmp_path / "recovery.txt"
    app.lock(_args(passphrase_file=pf, recovery_out=str(rec)))
    original_recovery = rec.read_text(encoding="utf-8").strip()
    # unlock, edit, re-lock with the same passphrase
    app.unlock(_args(passphrase_file=pf))
    (tmp_path / ".env").write_text(ENV_TEXT + "EXTRA=added\n", encoding="utf-8")
    app.lock(_args(passphrase_file=pf))
    # the ORIGINAL recovery key must still open the re-locked file, and see the edit
    rf = tmp_path / "orig-rec.txt"
    rf.write_text(original_recovery + "\n", encoding="utf-8")
    app.unlock(_args(recovery_key=True, recovery_key_file=str(rf), force=True))
    assert (tmp_path / ".env").read_text(encoding="utf-8").endswith("EXTRA=added\n")


def test_verify_before_destroy_keeps_env_on_bad_write(tmp_path, monkeypatch):
    _write_env(tmp_path)
    app = _app(tmp_path)
    # Make the freshly-written .env.enc fail to decrypt back: corrupt env_lock_seal's output.
    real_seal = dv.env_lock_seal

    def _bad_seal(fernet, env_text, passphrase, **kw):
        enc, dek = real_seal(fernet, env_text, passphrase, **kw)
        return enc.replace('"payload"', '"payload_broken"'), dek  # drop the payload key -> parse/verify fails

    monkeypatch.setattr(dv, "env_lock_seal", _bad_seal)
    with pytest.raises(SystemExit):
        app.lock(_args(passphrase_file=_passfile(tmp_path)))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == ENV_TEXT, "plaintext must survive a failed verify"


def test_lock_with_no_env_exits(tmp_path):
    app = _app(tmp_path)  # no .env written
    with pytest.raises(SystemExit):
        app.lock(_args(passphrase_file=_passfile(tmp_path)))


def test_status_reports_locked_state(tmp_path, monkeypatch, capsys):
    _write_env(tmp_path)
    app = _app(tmp_path)
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (False, "no docker"))
    app.lock(_args(passphrase_file=_passfile(tmp_path)))
    app.status(_args())
    assert "LOCKED" in capsys.readouterr().out


# --- regressions for the adversarial-review findings -----------------------------------------

def test_kdf_actually_runs_and_is_recorded(tmp_path):
    """The header records the KDF actually used (scrypt where supported), so a passphrase sealed on
    one host opens on another - no silent scrypt->pbkdf2 downgrade with a mislabelled header."""
    import json
    _write_env(tmp_path)
    app = _app(tmp_path)
    app.lock(_args(passphrase_file=_passfile(tmp_path)))
    body = json.loads((tmp_path / ".env.enc").read_text(encoding="utf-8").split("\n", 1)[1])
    assert body["kdf"]["algo"] in ("scrypt", "pbkdf2")
    if body["kdf"]["algo"] == "scrypt":
        assert dv._scrypt_ok(), "recorded scrypt but this host can't run it"
        assert body["kdf"]["n"] == dv.ENV_LOCK_KDF["n"]
    else:
        assert "iterations" in body["kdf"]


def test_crlf_env_roundtrips_byte_exact(tmp_path):
    """lock/unlock is byte-for-byte, so a CRLF .env is restored with CRLF (no LF normalization)."""
    raw = b"ENCRYPTION_KEY=k\r\nVAULT_DB_PASSWORD=p\r\n"
    (tmp_path / ".env").write_bytes(raw)
    app = _app(tmp_path)
    pf = _passfile(tmp_path)
    app.lock(_args(passphrase_file=pf))
    app.unlock(_args(passphrase_file=pf))
    assert (tmp_path / ".env").read_bytes() == raw


def test_nonascii_recovery_key_is_a_clean_error(tmp_path):
    """A recovery key with a non-ASCII glyph (a curly quote pasted from a doc) is a clean failure,
    not an uncaught UnicodeEncodeError traceback."""
    _write_env(tmp_path)
    app = _app(tmp_path)
    app.lock(_args(passphrase_file=_passfile(tmp_path)))
    rf = tmp_path / "badrec.txt"
    rf.write_text("not\u2019ascii-key", encoding="utf-8")  # U+2019 RIGHT SINGLE QUOTATION MARK
    with pytest.raises(SystemExit):
        app.unlock(_args(recovery_key=True, recovery_key_file=str(rf)))


def test_missing_passphrase_file_is_a_clean_error_and_keeps_env(tmp_path):
    """A nonexistent --passphrase-file fails cleanly (SystemExit), never a traceback, and never
    removes the plaintext .env."""
    _write_env(tmp_path)
    app = _app(tmp_path)
    with pytest.raises(SystemExit):
        app.lock(_args(passphrase_file=str(tmp_path / "does-not-exist.txt")))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == ENV_TEXT


# --- change-passphrase -----------------------------------------------------------------------

def test_change_passphrase_with_old_passphrase(tmp_path):
    """A new passphrase opens the file; the old one no longer does; the recovery key is unchanged."""
    _write_env(tmp_path)
    app = _app(tmp_path)
    old = _passfile(tmp_path, "old-passphrase-123")
    rec = tmp_path / "recovery.txt"
    app.lock(_args(passphrase_file=old, recovery_out=str(rec)))
    recovery = rec.read_text(encoding="utf-8").strip()
    new = tmp_path / "new.txt"
    new.write_text("brand-new-passphrase-456\n", encoding="utf-8")
    app.change_passphrase(_args(passphrase_file=old, new_passphrase_file=str(new)))
    # old passphrase now fails
    with pytest.raises(SystemExit):
        app.unlock(_args(passphrase_file=old))
    # new passphrase works
    app.unlock(_args(passphrase_file=str(new)))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == ENV_TEXT
    # recovery key unchanged -> still opens
    (tmp_path / ".env").unlink()
    rf = tmp_path / "rec2.txt"
    rf.write_text(recovery + "\n", encoding="utf-8")
    app.unlock(_args(recovery_key=True, recovery_key_file=str(rf)))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == ENV_TEXT


def test_change_passphrase_via_recovery_key_when_passphrase_forgotten(tmp_path):
    """The forgotten-passphrase path: authenticate with the recovery key, set a new passphrase."""
    _write_env(tmp_path)
    app = _app(tmp_path)
    rec = tmp_path / "recovery.txt"
    app.lock(_args(passphrase_file=_passfile(tmp_path, "forgotten"), recovery_out=str(rec)))
    rf = tmp_path / "rec.txt"
    rf.write_text(rec.read_text(encoding="utf-8").strip() + "\n", encoding="utf-8")
    new = tmp_path / "new.txt"
    new.write_text("recovered-new-passphrase\n", encoding="utf-8")
    app.change_passphrase(_args(recovery_key=True, recovery_key_file=str(rf), new_passphrase_file=str(new)))
    app.unlock(_args(passphrase_file=str(new)))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == ENV_TEXT


def test_change_passphrase_wrong_current_leaves_file_unchanged(tmp_path):
    _write_env(tmp_path)
    app = _app(tmp_path)
    app.lock(_args(passphrase_file=_passfile(tmp_path, "the-current-one")))
    before = (tmp_path / ".env.enc").read_bytes()
    new = tmp_path / "new.txt"
    new.write_text("whatever-new\n", encoding="utf-8")
    with pytest.raises(SystemExit):
        app.change_passphrase(_args(passphrase_file=_passfile(tmp_path, "WRONG"), new_passphrase_file=str(new)))
    assert (tmp_path / ".env.enc").read_bytes() == before, ".env.enc must be untouched on a failed auth"


def test_change_passphrase_without_enc_exits(tmp_path):
    app = _app(tmp_path)  # no .env.enc
    with pytest.raises(SystemExit):
        app.change_passphrase(_args(passphrase_file=_passfile(tmp_path), new_passphrase_file=_passfile(tmp_path)))
