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


@pytest.fixture(autouse=True)
def _app_data_under_the_test(tmp_path, monkeypatch):
    """A recovery key shown with no terminal goes to a file in the user's DockVault application-data folder: under
    this test's own folder here, never the home of whoever runs the tests."""
    for name in ("XDG_DATA_HOME", "LOCALAPPDATA", "APPDATA"):
        monkeypatch.setenv(name, str(tmp_path / "app-data"))


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


def test_lock_warns_when_a_container_still_holds_the_secret(tmp_path, monkeypatch, capsys):
    # Sealing .env does NOT clear the copy Docker baked into a running/stopped container's config;
    # lock must say so and point at `down`.
    _write_env(tmp_path)
    app = _app(tmp_path)
    monkeypatch.setattr(dv, "container_exists", lambda name, **k: True)
    app.lock(_args(passphrase_file=_passfile(tmp_path)))
    out = capsys.readouterr().out
    assert "STILL in Docker" in out and "down" in out, "lock must warn the container config still holds the secret"


def test_lock_gives_no_container_warning_when_none_exists(tmp_path, monkeypatch, capsys):
    _write_env(tmp_path)
    app = _app(tmp_path)
    monkeypatch.setattr(dv, "container_exists", lambda name, **k: False)
    app.lock(_args(passphrase_file=_passfile(tmp_path)))
    assert "STILL in Docker" not in capsys.readouterr().out


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
    edited = ENV_TEXT + "SOMETHING-ELSE=1\n"
    (tmp_path / ".env").write_text(edited, encoding="utf-8")  # a plaintext exists again
    with pytest.raises(SystemExit):
        app.unlock(_args(passphrase_file=pf))               # refuses
    assert (tmp_path / ".env").read_text(encoding="utf-8") == edited
    app.unlock(_args(passphrase_file=pf, force=True))       # --force overwrites the same set's edited .env
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


# --- a sealed set is never written over by another set's .env ----------------------------------

def _set_env(prefix, key="ZmFrZS1lbmMta2V5"):
    return ("VAULT_VOLUME_PREFIX=%s\nENCRYPTION_KEY=%s\nVAULT_DB_PASSWORD=db-%s\nJWT_SECRET_KEY=jwt-%s\n"
            % (prefix, key, prefix, prefix))


def _sealed(tmp_path, text):
    """`text` written as .env and sealed by lock; returns the passphrase file."""
    (tmp_path / ".env").write_text(text, encoding="utf-8")
    pf = _passfile(tmp_path)
    _app(tmp_path).lock(_args(passphrase_file=pf))
    assert not (tmp_path / ".env").exists()
    return pf


def _opens_to(tmp_path, pf):
    fernet = dv.load_fernet()
    payload, _ = dv.env_lock_open(fernet, (tmp_path / ".env.enc").read_text(encoding="utf-8"),
                                  passphrase=open(pf, encoding="utf-8").readline().strip())
    return payload.decode("utf-8")


@pytest.mark.parametrize("other", ["prefix", "encryption-key"])
def test_lock_never_seals_another_sets_env_over_the_sealed_one(tmp_path, capsys, other):
    """Sealed set A; a .env of another set appears beside it (another prefix, or the same prefix with another
    ENCRYPTION_KEY: a set reset and made again). Re-locking with A's passphrase would write it over A's only
    sealed copy: refused, with .env.enc still opening to A's .env and the other .env left in place."""
    a = _set_env("dvsetaaa")
    pf = _sealed(tmp_path, a)
    b = _set_env("dvsetbbb") if other == "prefix" else _set_env("dvsetaaa", key="b3RoZXIta2V5LW9mLWEtbmV3LXNldA")
    (tmp_path / ".env").write_text(b, encoding="utf-8")
    before = (tmp_path / ".env.enc").read_bytes()
    capsys.readouterr()
    with pytest.raises(SystemExit):
        _app(tmp_path).lock(_args(passphrase_file=pf))
    assert (tmp_path / ".env.enc").read_bytes() == before
    assert _opens_to(tmp_path, pf) == a
    assert (tmp_path / ".env").read_text(encoding="utf-8") == b
    said = " ".join(capsys.readouterr().out.split())
    assert "Refusing to lock: .env.enc holds the .env of another set" in said and "Nothing changed." in said
    assert "ZmFrZS1lbmMta2V5" not in said and "b3RoZXIta2V5" not in said, "a key's value is never printed"


def test_lock_seals_the_same_sets_edited_env_again(tmp_path):
    a = _set_env("dvsetaaa")
    pf = _sealed(tmp_path, a)
    _app(tmp_path).unlock(_args(passphrase_file=pf))
    (tmp_path / ".env").write_text(a + "WEB_HOST_PORT=8443\n", encoding="utf-8")
    _app(tmp_path).lock(_args(passphrase_file=pf))
    assert not (tmp_path / ".env").exists()
    assert _opens_to(tmp_path, pf) == a + "WEB_HOST_PORT=8443\n"


def _refused_while_sealed(tmp_path, capsys, run):
    a = _set_env("dvsetaaa")
    pf = _sealed(tmp_path, a)
    before = sorted(p.name for p in tmp_path.iterdir())
    sealed = (tmp_path / ".env.enc").read_bytes()
    capsys.readouterr()
    with pytest.raises(SystemExit):
        run(_app(tmp_path))
    assert sorted(p.name for p in tmp_path.iterdir()) == before, "nothing was written beside the sealed .env"
    assert (tmp_path / ".env.enc").read_bytes() == sealed and _opens_to(tmp_path, pf) == a
    said = " ".join(capsys.readouterr().out.split())
    assert ".env is locked (sealed in .env.enc): unlock it first (python dockvault.py unlock)" in said
    assert "Nothing changed." in said
    return said


def test_setup_while_env_is_sealed_is_refused_before_it_writes_anything(tmp_path, monkeypatch, capsys):
    """A fresh setup beside a sealed .env would write a new set's .env there (new secrets), and a later lock with
    the same passphrase used to seal it over the sealed set's."""
    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: pytest.fail("setup went on"))
    args = argparse.Namespace(non_interactive=True, no_start=True, server_name="localhost", admin_username=None,
                              admin_email=None, admin_password=None, image_source="build")
    said = _refused_while_sealed(tmp_path, capsys, lambda app: app.setup(args))
    assert "then run setup again" in said


def test_a_new_volume_set_while_env_is_sealed_is_refused(tmp_path, monkeypatch, capsys):
    """It said 'your current set is kept' and wrote a new set's .env beside the sealed one, archiving nothing."""
    said = _refused_while_sealed(tmp_path, capsys, lambda app: app._volume_new(
        {}, argparse.Namespace(non_interactive=True)))
    assert "volumes --action new" in said


def test_a_repoint_while_env_is_sealed_is_refused(tmp_path, monkeypatch, capsys):
    other = tmp_path.parent / (tmp_path.name + "-other.env")
    other.write_text(_set_env("dvsetbbb"), encoding="utf-8")
    monkeypatch.setattr(dv, "list_managed_volumes", lambda *a, **k: [
        {"name": "dvsetbbb_vault_pg_data", "role": "pg", "bundle": "b"}])
    monkeypatch.setattr(dv.DockVault, "_stop_stack", lambda self: pytest.fail("the deployment was stopped"))
    said = _refused_while_sealed(tmp_path, capsys, lambda app: app._volume_repoint(
        {}, argparse.Namespace(non_interactive=True, target_prefix="dvsetbbb", env_source=str(other))))
    assert "volumes --action repoint" in said


# --- unlock --force never writes over the only copy of a set's keys ---------------------------

def _beside_the_seal(tmp_path, sealed_text, env_text):
    """Set A sealed in .env.enc, and `env_text` as .env beside it (the state a restore, a repoint or a new set leaves
    after an unlock: .env.enc stays). Returns the passphrase file."""
    pf = _sealed(tmp_path, sealed_text)
    (tmp_path / ".env").write_text(env_text, encoding="utf-8")
    return pf


@pytest.mark.parametrize("other", ["prefix", "encryption-key"])
def test_unlock_force_over_another_sets_env_is_refused_with_nothing_changed(tmp_path, capsys, other):
    """Set B's .env beside a sealed .env of set A: lock refuses to seal B over A, and unlock --force used to write A
    over B's .env with no copy, leaving B's ENCRYPTION_KEY nowhere. Refused: both files as they were, no copy made,
    and the message says how to switch to the sealed set without losing B."""
    a = _set_env("dvsetaaa")
    b = _set_env("dvsetbbb") if other == "prefix" else _set_env("dvsetaaa", key="b3RoZXIta2V5LW9mLWEtbmV3LXNldA")
    pf = _beside_the_seal(tmp_path, a, b)
    sealed = (tmp_path / ".env.enc").read_bytes()
    before = sorted(p.name for p in tmp_path.iterdir())
    capsys.readouterr()
    with pytest.raises(SystemExit):
        _app(tmp_path).unlock(_args(passphrase_file=pf, force=True))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == b
    assert (tmp_path / ".env.enc").read_bytes() == sealed
    assert sorted(p.name for p in tmp_path.iterdir()) == before, "no file was written or removed"
    said = " ".join(capsys.readouterr().out.split())
    assert ".env.enc holds the .env of another set" in said and "Nothing changed." in said
    aside = ".env.dvsetbbb" if other == "prefix" else ".env.dvsetaaa"
    assert "first move .env to %s" % (tmp_path / aside) in said
    assert "--action repoint --target-prefix %s --env-source %s" % (aside[5:], tmp_path / aside) in said
    assert "ZmFrZS1lbmMta2V5" not in said and "b3RoZXIta2V5" not in said, "a key's value is never printed"


def test_unlock_force_over_the_same_sets_edited_env_keeps_it_first(tmp_path, capsys):
    """The same set's .env, edited since the lock (a setting changed): unlock --force puts the sealed one back and
    keeps the edited one first, byte for byte, as .env.<set>, and says how to go back to it."""
    a = _set_env("dvsetaaa")
    edited = a + "WEB_HOST_PORT=8443\n"
    pf = _beside_the_seal(tmp_path, a, edited)
    capsys.readouterr()
    _app(tmp_path).unlock(_args(passphrase_file=pf, force=True))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == a
    kept = tmp_path / ".env.dvsetaaa"
    assert kept.read_text(encoding="utf-8") == edited
    said = " ".join(capsys.readouterr().out.split())
    assert "Kept the current .env (set 'dvsetaaa') as %s" % kept in said
    assert ("To go back to it: python dockvault.py volumes --non-interactive --action repoint --target-prefix "
            "dvsetaaa --env-source %s" % kept) in said


def test_unlock_force_takes_the_number_after_the_copies_there(tmp_path):
    a = _set_env("dvsetaaa")
    pf = _beside_the_seal(tmp_path, a, a + "X=1\n")
    (tmp_path / ".env.dvsetaaa").write_text("an older copy\n", encoding="utf-8")
    _app(tmp_path).unlock(_args(passphrase_file=pf, force=True))
    assert (tmp_path / ".env.dvsetaaa").read_text(encoding="utf-8") == "an older copy\n"
    assert (tmp_path / ".env.dvsetaaa.1").read_text(encoding="utf-8") == a + "X=1\n"
    assert (tmp_path / ".env").read_text(encoding="utf-8") == a


def test_unlock_force_over_the_sealed_env_itself_writes_nothing(tmp_path, capsys):
    a = _set_env("dvsetaaa")
    pf = _beside_the_seal(tmp_path, a, a)
    before = sorted(p.name for p in tmp_path.iterdir())
    capsys.readouterr()
    _app(tmp_path).unlock(_args(passphrase_file=pf, force=True))
    assert sorted(p.name for p in tmp_path.iterdir()) == before, "no copy of the same bytes is made"
    assert (tmp_path / ".env").read_text(encoding="utf-8") == a
    assert ".env already reads as the sealed one; nothing was changed." in capsys.readouterr().out


def test_unlock_force_whose_copy_cannot_be_kept_leaves_env_as_it_was(tmp_path, monkeypatch, capsys):
    a = _set_env("dvsetaaa")
    edited = a + "X=1\n"
    pf = _beside_the_seal(tmp_path, a, edited)

    def cannot(self, label, data):
        exc = OSError(28, "No space left on device")
        exc.kept_as = str(tmp_path / ".env.dvsetaaa")
        raise exc

    monkeypatch.setattr(dv.DockVault, "_keep_env_copy", cannot)
    capsys.readouterr()
    with pytest.raises(SystemExit):
        _app(tmp_path).unlock(_args(passphrase_file=pf, force=True))
    assert (tmp_path / ".env").read_text(encoding="utf-8") == edited
    said = " ".join(capsys.readouterr().out.split())
    assert "could not keep the current .env as %s" % (tmp_path / ".env.dvsetaaa") in said
    assert "so it was not replaced. Nothing changed." in said
