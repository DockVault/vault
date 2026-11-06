"""One-time secrets the host tool shows (dockvault.py: _emit_secret, _print_setup_summary, setup's admin password).

A generated admin password, a recovery key or a reset link goes to the controlling terminal, never to standard
output, which a setup log or cloud-init's output file keeps. With no terminal (cloud-init, a CI job), it goes to a
new mode-600 file in the user's DockVault application-data folder, and standard output names only that file (or,
for a recovery key with --recovery-out, only that file). Setup's summary used to print a generated admin password
with a plain print. The first admin's password can come from a file or from standard input, and the plain
--admin-password flag warns that other users can read it.
"""
import argparse
import importlib.util
import io
import os
import stat
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_secrets_mod", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)

SECRET = "Gen-Admin-Pass-7f3a9c"
_real_open = open


@pytest.fixture(autouse=True)
def _app_data(tmp_path, monkeypatch):
    """The user's DockVault application-data folder, under this test's own folder; no host ACL changes."""
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    monkeypatch.setattr(dv, "_app_data_backup_root", lambda: str(tmp_path / "appdata" / "DockVault" / "backups"))


def _no_terminal(monkeypatch):
    """No controlling terminal, as under cloud-init: opening /dev/tty (CON on Windows) fails."""
    def fake_open(path, *a, **k):
        if path in ("/dev/tty", "CON"):
            raise OSError(6, "No such device or address")
        return _real_open(path, *a, **k)
    monkeypatch.setattr(dv, "open", fake_open, raising=False)


def _a_terminal(monkeypatch):
    """A controlling terminal: what is written to it is collected."""
    seen = io.StringIO()

    class _Tty(io.StringIO):
        def __exit__(self, *exc):
            seen.write(self.getvalue())
            return super().__exit__(*exc)

    def fake_open(path, *a, **k):
        if path in ("/dev/tty", "CON"):
            return _Tty()
        return _real_open(path, *a, **k)
    monkeypatch.setattr(dv, "open", fake_open, raising=False)
    return seen


def _secret_files(tmp_path):
    folder = tmp_path / "appdata" / "DockVault" / "secrets"
    return sorted(folder.iterdir()) if folder.is_dir() else []


def _summary(tool):
    tool._print_setup_summary({"server_name": "vault.example.test", "admin_username": "admin",
                               "web_host_port": 443, "admin_password": SECRET}, healthy=True)


def test_setup_with_no_terminal_writes_the_generated_password_to_a_600_file_and_prints_only_its_path(
        tmp_path, monkeypatch, capsys):
    _no_terminal(monkeypatch)
    _summary(dv.DockVault(dv.Palette(False), root=str(tmp_path)))
    out = capsys.readouterr().out
    assert SECRET not in out, "the password reached standard output (a setup log, cloud-init's output)"
    (path,) = _secret_files(tmp_path)
    assert SECRET in path.read_text(encoding="utf-8")
    assert path.name.startswith("admin-password-")
    assert str(path) in " ".join(out.split())
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert not list(tmp_path.glob("*admin-password*")), "never in the checkout (git, the image's build context)"


def test_setup_with_a_terminal_shows_the_generated_password_there_and_not_on_standard_output(
        tmp_path, monkeypatch, capsys):
    seen = _a_terminal(monkeypatch)
    _summary(dv.DockVault(dv.Palette(False), root=str(tmp_path)))
    assert SECRET not in capsys.readouterr().out
    assert SECRET in seen.getvalue()
    assert _secret_files(tmp_path) == []


def test_a_second_secret_in_the_same_second_gets_a_file_of_its_own(tmp_path, monkeypatch):
    _no_terminal(monkeypatch)
    monkeypatch.setattr(dv, "_timestamp", lambda: "20261106-120000")
    tool = dv.DockVault(dv.Palette(True), root=str(tmp_path))
    tool._emit_secret(tool.pal.paint("first " + SECRET, "bold"), label="admin-password")
    tool._emit_secret("second", label="admin-password")
    first, second = _secret_files(tmp_path)
    assert first.read_text(encoding="utf-8") == "first %s\n" % SECRET, "written without colour codes"
    assert second.read_text(encoding="utf-8") == "second\n"


def test_a_recovery_key_with_no_terminal_goes_only_to_recovery_out_when_given(tmp_path, monkeypatch, capsys):
    pytest.importorskip("cryptography")
    _no_terminal(monkeypatch)
    (tmp_path / ".env").write_text("ENCRYPTION_KEY=x\nVAULT_DB_PASSWORD=y\n", encoding="utf-8")
    pf = tmp_path / "pass.txt"
    pf.write_text("a long enough passphrase\n", encoding="utf-8")
    out_file = tmp_path / "recovery.txt"
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    tool.lock(argparse.Namespace(passphrase_file=str(pf), passphrase_stdin=False, hint=None,
                                 recovery_out=str(out_file)))
    key = out_file.read_text(encoding="utf-8").strip()
    out = capsys.readouterr().out
    assert key and key not in out
    assert _secret_files(tmp_path) == [], "no second copy beside --recovery-out"
    assert "it is written to %s only" % out_file in " ".join(out.split())


def test_a_recovery_key_with_no_terminal_and_no_recovery_out_goes_to_a_file(tmp_path, monkeypatch, capsys):
    pytest.importorskip("cryptography")
    _no_terminal(monkeypatch)
    (tmp_path / ".env").write_text("ENCRYPTION_KEY=x\nVAULT_DB_PASSWORD=y\n", encoding="utf-8")
    pf = tmp_path / "pass.txt"
    pf.write_text("a long enough passphrase\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    tool.lock(argparse.Namespace(passphrase_file=str(pf), passphrase_stdin=False, hint=None, recovery_out=None))
    (path,) = _secret_files(tmp_path)
    assert path.name.startswith("recovery-key-")
    text = path.read_text(encoding="utf-8")
    key = text.split("=====")[2].split()[0]
    assert key not in capsys.readouterr().out


# --------------------------------------------------------------------------- the first admin's password

def _parse(*argv):
    return dv.build_parser().parse_args(["setup"] + list(argv))


def test_the_admin_password_can_come_from_a_file(tmp_path, capsys):
    pw = tmp_path / "admin-pass.txt"
    pw.write_text("From-A-File-1234\r\nignored second line\n", encoding="utf-8")
    args = _parse("--admin-password-file", str(pw))
    dv.DockVault(dv.Palette(False), root=str(tmp_path))._read_cli_admin_password(args)
    assert args.admin_password == "From-A-File-1234"
    assert "WARNING" not in capsys.readouterr().out


def test_the_admin_password_can_come_from_standard_input(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dv.sys, "stdin", io.StringIO("From-Stdin-5678\n"))
    args = _parse("--admin-password-stdin")
    dv.DockVault(dv.Palette(False), root=str(tmp_path))._read_cli_admin_password(args)
    assert args.admin_password == "From-Stdin-5678"
    assert "WARNING" not in capsys.readouterr().out


def test_the_plain_admin_password_flag_warns_that_others_can_read_it(tmp_path, capsys):
    args = _parse("--admin-password", "On-The-Command-Line-1")
    dv.DockVault(dv.Palette(False), root=str(tmp_path))._read_cli_admin_password(args)
    assert args.admin_password == "On-The-Command-Line-1"
    said = " ".join(capsys.readouterr().out.split())
    assert "WARNING: --admin-password puts the password on the command line" in said
    assert "--admin-password-file or --admin-password-stdin" in said
    assert "On-The-Command-Line-1" not in said


@pytest.mark.parametrize("source", ["missing-file", "empty-file", "empty-stdin"])
def test_an_admin_password_source_with_no_password_stops_setup_before_anything(tmp_path, monkeypatch, source):
    if source == "empty-stdin":
        monkeypatch.setattr(dv.sys, "stdin", io.StringIO(""))
        args = _parse("--admin-password-stdin", "--non-interactive")
    else:
        pw = tmp_path / "admin-pass.txt"
        if source == "empty-file":
            pw.write_text("\n", encoding="utf-8")
        args = _parse("--admin-password-file", str(pw), "--non-interactive")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    with pytest.raises(SystemExit):
        tool.setup(args)
    assert not (tmp_path / ".env").exists()


def test_the_admin_password_sources_are_one_at_a_time():
    with pytest.raises(SystemExit):
        _parse("--admin-password", "x", "--admin-password-file", "f")
    with pytest.raises(SystemExit):
        _parse("--admin-password-file", "f", "--admin-password-stdin")


def test_setup_seeds_the_admin_password_read_from_a_file(tmp_path, monkeypatch):
    """End to end through setup's own settings: the value read from the file is the one .env gets."""
    pw = tmp_path / "admin-pass.txt"
    pw.write_text("Seeded-From-File-42\n", encoding="utf-8")
    args = _parse("--admin-password-file", str(pw), "--non-interactive", "--no-start", "--server-name", "localhost",
                  "--image-source", "build")
    monkeypatch.setattr(dv, "generate_self_signed_cert", lambda *a, **k: (True, "made"))
    monkeypatch.setattr(dv, "apply_cert_owner", lambda *a, **k: (True, ""))
    dv.DockVault(dv.Palette(False), root=str(tmp_path)).setup(args)
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert env["ADMIN_PASSWORD"] == "Seeded-From-File-42"


def test_a_secret_file_that_cannot_be_written_whole_is_removed_and_the_output_says_so(tmp_path, monkeypatch, capsys):
    """A full disk while the file is written: no part of the secret stays in a file nobody was told of, and the
    secret is shown with a warning rather than lost (a generated admin password is dropped from .env later)."""
    _no_terminal(monkeypatch)

    def no_space(_fd):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(dv.os, "fsync", no_space)
    dv.DockVault(dv.Palette(False), root=str(tmp_path))._emit_secret("pw " + SECRET, label="admin-password")
    assert _secret_files(tmp_path) == []
    out = capsys.readouterr().out
    assert "WARNING: no terminal, and no file could be written" in out and SECRET in out
