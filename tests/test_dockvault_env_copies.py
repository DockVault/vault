"""Which .env a repoint installs, how it is checked, and setup's 'point me at a .env' (dockvault.py: _volume_repoint,
kept_env_copies, _guard_db_secret's key check, _resolve_existing_volume).

A repoint took the kept copy of the target set's .env that sorts last as text: .env.<set>.10 sorts before
.env.<set>.9, and .env.<set>.x (another set's, whose name is <set>.x) sorted after both. It now takes the newest
copy by its number, lists them when it can ask, and passes over a name that is not a copy. The installed .env was
checked by its database password only; a copy that opens the database with another ENCRYPTION_KEY (a set made again
with the same password, a hand-edited copy) now fails the key check the vault keeps in its database, and the
repoint puts the previous .env back. Setup's 'point me at a specific .env' replaced the current .env without a copy;
it now keeps it first, as a restore does.
"""
import argparse
import importlib.util
from pathlib import Path

import pytest

from test_dockvault_tool import _reusable_env_cfg

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_env_copies_mod", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)

TARGET = "dvcopyset"


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)


def _env_text(prefix, **extra):
    cfg = dict(_reusable_env_cfg(), volume_prefix=prefix, deployment_id=prefix)
    cfg.update(extra)
    return "\n".join(dv.build_env_lines(cfg)) + "\n"


def _repointing(tmp_path, monkeypatch, guard=lambda env, **k: True):
    (tmp_path / ".env").write_text(_env_text("dvcurrent"), encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_guard_db_secret", guard)
    monkeypatch.setattr(tool, "_stop_stack", lambda: None)
    monkeypatch.setattr(tool, "_stop_db_only", lambda: None)
    monkeypatch.setattr(dv, "list_managed_volumes", lambda *a, **k: [
        {"name": "%s_vault_pg_data" % TARGET, "role": "pg", "bundle": "t"}])
    return tool


def _repoint(tool, interactive=False):
    args = argparse.Namespace(target_prefix=TARGET, env_source=None)
    if not interactive:
        args.non_interactive = True
    tool._volume_repoint(tool._load_env(), args)


def _copies(tmp_path, numbers):
    """Kept copies of TARGET's .env, each marked with the number it was kept under (COPY_NUMBER)."""
    for n in numbers:
        name = ".env.%s" % TARGET if n == 0 else ".env.%s.%d" % (TARGET, n)
        (tmp_path / name).write_text(_env_text(TARGET) + "COPY_NUMBER=%d\n" % n, encoding="utf-8")


def test_kept_env_copies_are_ordered_by_their_number_not_as_text(tmp_path):
    _copies(tmp_path, [0, 1, 2, 9, 10, 11])
    (tmp_path / (".env.%s.x" % TARGET)).write_text(_env_text(TARGET + ".x"), encoding="utf-8")
    (tmp_path / (".env.%s.3.bak" % TARGET)).write_text("x\n", encoding="utf-8")
    names = [Path(p).name for p in dv.kept_env_copies(str(tmp_path), TARGET)]
    assert names == [".env.%s.%d" % (TARGET, n) for n in (11, 10, 9, 2, 1)] + [".env.%s" % TARGET]


@pytest.mark.parametrize("there", [[1, 2], [0, 2], [0, 1, 2]])
def test_a_new_copy_takes_the_number_after_the_highest_one_there(tmp_path, there):
    """A name below the highest is free when a copy was deleted. A new copy made there (.env.<set> first) sorted as
    the oldest, so a repoint took an older copy for the newest."""
    _copies(tmp_path, there)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    kept = tool._keep_env_copy(TARGET, (_env_text(TARGET) + "COPY_NUMBER=new\n").encode("utf-8"))
    assert Path(kept).name == ".env.%s.3" % TARGET
    assert dv.kept_env_copies(str(tmp_path), TARGET)[0] == kept


def test_none_there_the_first_copy_is_the_sets_own_name(tmp_path):
    (tmp_path / (".env.%s.x" % TARGET)).write_text(_env_text(TARGET + ".x"), encoding="utf-8")
    assert Path(next(dv.env_copy_names(str(tmp_path), TARGET))).name == ".env.%s" % TARGET


def test_a_repoint_after_a_copy_was_deleted_installs_the_copy_kept_last(tmp_path, monkeypatch):
    _copies(tmp_path, [0, 1, 2])
    (tmp_path / (".env.%s" % TARGET)).unlink()
    tool = _repointing(tmp_path, monkeypatch)
    tool._keep_env_copy(TARGET, (_env_text(TARGET) + "COPY_NUMBER=last\n").encode("utf-8"))
    _repoint(tool)
    assert dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))["COPY_NUMBER"] == "last"


def test_a_sets_copies_never_include_the_sealed_env(tmp_path):
    """For a set named 'enc', .env.enc is the sealed .env, never a copy of the set's .env."""
    (tmp_path / ".env.enc").write_text('{"sealed": true}\n', encoding="utf-8")
    (tmp_path / ".env.enc.1").write_text(_env_text("enc"), encoding="utf-8")
    assert [Path(p).name for p in dv.kept_env_copies(str(tmp_path), "enc")] == [".env.enc.1"]
    assert Path(next(dv.env_copy_names(str(tmp_path), "enc"))).name == ".env.enc.2"


def test_a_repoint_installs_the_newest_kept_copy_by_its_number(tmp_path, monkeypatch):
    """With ten or more copies, the text sort took .9 over .10 and .11."""
    _copies(tmp_path, [0, 1, 9, 10, 11])
    tool = _repointing(tmp_path, monkeypatch)
    _repoint(tool)
    installed = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert dv.volume_prefix(installed) == TARGET and installed["COPY_NUMBER"] == "11"


def test_a_repoint_passes_over_another_sets_env_whose_name_begins_like_the_targets(tmp_path, monkeypatch):
    """.env.<set>.x belongs to the set named <set>.x: taken as the newest copy, it refused the repoint."""
    _copies(tmp_path, [1])
    (tmp_path / (".env.%s.x" % TARGET)).write_text(_env_text(TARGET + ".x"), encoding="utf-8")
    tool = _repointing(tmp_path, monkeypatch)
    _repoint(tool)
    installed = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert dv.volume_prefix(installed) == TARGET and installed["COPY_NUMBER"] == "1"


def test_an_interactive_repoint_lists_the_copies_newest_first_and_takes_the_one_chosen(tmp_path, monkeypatch, capsys):
    _copies(tmp_path, [0, 9, 10])
    tool = _repointing(tmp_path, monkeypatch)
    monkeypatch.setattr(dv, "ask", lambda prompt, *a, **k: "2" if prompt == "Which copy" else "")
    _repoint(tool, interactive=True)
    out = capsys.readouterr().out
    assert out.index(".env.%s.10" % TARGET) < out.index(".env.%s.9" % TARGET)
    assert dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))["COPY_NUMBER"] == "9"


# --------------------------------------------------------------------------- ENCRYPTION_KEY, not only the password

def _token_under(key):
    fernet = pytest.importorskip("cryptography.fernet").Fernet
    return fernet(key.encode("ascii")).encrypt(b"dockvault-encryption-key-canary-v1").decode("ascii")


def test_fernet_token_signed_by_tells_the_key_a_token_was_made_under():
    key, other = dv.gen_fernet_key(), dv.gen_fernet_key()
    token = _token_under(key)
    assert dv.fernet_token_signed_by(key, token) is True
    assert dv.fernet_token_signed_by(other, token) is False
    assert dv.fernet_token_signed_by(key, token[:-8] + "AAAAAAAA") is False
    for bad in ("", "not-a-token", "gAAAA"):
        assert dv.fernet_token_signed_by(key, bad) is False
    assert dv.fernet_token_signed_by("not-a-key", token) is False


def test_read_key_canary_asks_the_database_over_its_network_address():
    calls = []

    class _R:
        def __init__(self, code, out):
            self.returncode, self.stdout, self.stderr = code, out, ""

    def run(cmd, **k):
        calls.append((cmd, k.get("env", {}).get("PGPASSWORD")))
        return _R(0, "10.1.2.3\n") if "hostname" in cmd else _R(0, "gAAAAtoken\n")

    assert dv.read_key_canary("vault-db", "u", "d", "pw", run=run) == "gAAAAtoken"
    cmd, password = calls[1]
    assert "-h" in cmd and "10.1.2.3" in cmd and password == "pw" and "pw" not in cmd
    assert "encryption_key_canary" in cmd[-1]
    assert dv.read_key_canary("vault-db", "u", "d", "pw", run=lambda *a, **k: _R(1, "")) is None


@pytest.mark.parametrize("canary, passes, stamps", [("ok", True, True), ("unknown", True, False),
                                                    ("mismatch", False, False)])
def test_the_guard_refuses_a_env_whose_password_opens_the_volume_with_another_encryption_key(capsys, canary, passes,
                                                                                            stamps):
    tool = dv.DockVault(dv.Palette(False), root="/nonexistent-dockvault-root")
    stamped = []
    ok = tool._guard_db_secret(
        {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": "x"},
        exists_fn=lambda v: True, start_fn=lambda: True, wait_fn=lambda: True, probe_fn=lambda *a: "ok",
        stop_fn=lambda: None, marker_fn=lambda vol: None, stamp_fn=lambda vol, env: stamped.append(vol),
        canary_fn=lambda env: canary)
    assert ok is passes
    assert bool(stamped) is stamps, "a pairing is stamped only once both halves were checked"
    if not passes:
        assert "ENCRYPTION_KEY is not the key its" in " ".join(capsys.readouterr().out.split())


def test_a_key_check_that_could_not_be_read_is_read_again_by_the_next_check():
    """No key check in the database yet (or none readable) lets the .env through without a stamp, so the next check
    of the same .env starts the database again and reads the key check then, where a stamp would have answered it."""
    tool = dv.DockVault(dv.Palette(False), root="/nonexistent-dockvault-root")
    env = {"ENCRYPTION_KEY": dv.gen_fernet_key(), "VAULT_DB_PASSWORD": "x"}
    stamps, starts, verdicts = {}, [], iter(["unknown", "mismatch"])
    hooks = dict(exists_fn=lambda v: True, start_fn=lambda: starts.append(1) or True, wait_fn=lambda: True,
                 probe_fn=lambda *a: "ok", stop_fn=lambda: None, marker_fn=lambda vol: stamps.get(vol),
                 stamp_fn=lambda vol, e: stamps.__setitem__(vol, dv.build_coupling_marker(e)) or True,
                 canary_fn=lambda e: next(verdicts))
    assert tool._guard_db_secret(env, **hooks) is True
    assert stamps == {}
    assert tool._guard_db_secret(env, **hooks) is False, "the second check read the key check, now there"
    assert starts == [1, 1]


def test_a_repoint_to_a_copy_with_the_right_password_and_another_key_puts_the_previous_env_back(
        tmp_path, monkeypatch, capsys):
    """Through the real guard: the password probe passes, the key check in the database was sealed under another
    ENCRYPTION_KEY, and the repoint is undone with the previous .env back in place."""
    pytest.importorskip("cryptography")
    _copies(tmp_path, [1])
    (tmp_path / ".env").write_text(_env_text("dvcurrent"), encoding="utf-8")
    before = (tmp_path / ".env").read_bytes()
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_stop_stack", lambda: None)
    monkeypatch.setattr(tool, "_stop_db_only", lambda: None)
    monkeypatch.setattr(tool, "_start_db_only", lambda: True)
    monkeypatch.setattr(tool, "_wait_db_ready", lambda *a, **k: True)
    monkeypatch.setattr(dv, "list_managed_volumes", lambda *a, **k: [
        {"name": "%s_vault_pg_data" % TARGET, "role": "pg", "bundle": "t"}])
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: True)
    monkeypatch.setattr(dv, "read_volume_coupling", lambda vol, **k: None)
    monkeypatch.setattr(dv, "write_volume_coupling", lambda *a, **k: pytest.fail("a mismatched pair was stamped"))
    monkeypatch.setattr(dv, "probe_pg_password", lambda *a, **k: "ok")
    monkeypatch.setattr(dv, "read_key_canary", lambda *a, **k: _token_under(dv.gen_fernet_key()))
    _repoint(tool)
    assert (tmp_path / ".env").read_bytes() == before
    said = " ".join(capsys.readouterr().out.split())
    assert "ENCRYPTION_KEY is not the key its" in said and "Repoint verification FAILED" in said


def test_a_repoint_whose_copy_holds_the_key_the_database_was_sealed_with_goes_on(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    _copies(tmp_path, [1])
    target_key = dv.parse_env((tmp_path / (".env.%s.1" % TARGET)).read_text(encoding="utf-8"))["ENCRYPTION_KEY"]
    (tmp_path / ".env").write_text(_env_text("dvcurrent"), encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_stop_stack", lambda: None)
    monkeypatch.setattr(tool, "_stop_db_only", lambda: None)
    monkeypatch.setattr(tool, "_start_db_only", lambda: True)
    monkeypatch.setattr(tool, "_wait_db_ready", lambda *a, **k: True)
    monkeypatch.setattr(dv, "list_managed_volumes", lambda *a, **k: [
        {"name": "%s_vault_pg_data" % TARGET, "role": "pg", "bundle": "t"}])
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: True)
    monkeypatch.setattr(dv, "read_volume_coupling", lambda vol, **k: None)
    monkeypatch.setattr(dv, "write_volume_coupling", lambda *a, **k: True)
    monkeypatch.setattr(dv, "probe_pg_password", lambda *a, **k: "ok")
    monkeypatch.setattr(dv, "read_key_canary", lambda *a, **k: _token_under(target_key))
    _repoint(tool)
    assert dv.volume_prefix(tool._load_env()) == TARGET


# --------------------------------------------------------------------------- setup's 'point me at a .env'

def _pointing(tmp_path, monkeypatch, env_is_fresh=False, answers=None):
    """Setup's existing-volume menu: option 2 with another set's .env, which verifies. Both files are written as
    bytes, so what the tool keeps and installs is compared with exactly what was there (Path.write_text would end
    the lines the platform's way)."""
    current = _env_text("dvcurrent").encode("utf-8")
    (tmp_path / ".env").write_bytes(current)
    src = tmp_path / "provided.env"
    src.write_bytes(_env_text("dvprovided").encode("utf-8"))
    replies = iter(answers or ["2", str(src)])
    monkeypatch.setattr(dv, "ask", lambda *a, **k: next(replies))
    monkeypatch.setattr(dv, "flush_stdin", lambda: None)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_normalize_compose_profile", lambda: "combined")
    monkeypatch.setattr(tool, "_try_verify", lambda env, vol, hooks: True)
    assert tool._resolve_existing_volume(dv.parse_env(current.decode("utf-8")), "dvcurrent_vault_pg_data",
                                         (None,) * 6, env_is_fresh=env_is_fresh) is True
    return current, src.read_bytes()


def test_pointing_setup_at_another_env_keeps_the_current_one_first(tmp_path, monkeypatch, capsys):
    current, provided = _pointing(tmp_path, monkeypatch)
    assert (tmp_path / ".env").read_bytes() == provided
    kept = tmp_path / ".env.dvcurrent"
    assert kept.read_bytes() == current, "the .env the host had is kept, under its set's name"
    assert "Kept the current .env as %s" % kept in " ".join(capsys.readouterr().out.split())


def test_pointing_setup_at_another_env_keeps_nothing_of_a_env_this_run_just_wrote(tmp_path, monkeypatch):
    _current, provided = _pointing(tmp_path, monkeypatch, env_is_fresh=True)
    assert (tmp_path / ".env").read_bytes() == provided
    assert not [p for p in tmp_path.iterdir() if p.name.startswith(".env.")]


def test_a_current_env_that_cannot_be_kept_is_not_replaced(tmp_path, monkeypatch, capsys):
    """The copy fails (a full disk, say): the current .env stays, and the menu comes back."""
    def cannot(label, data):
        raise OSError(28, "No space left on device")

    src_answers = []
    current = _env_text("dvcurrent")
    (tmp_path / ".env").write_bytes(current.encode("utf-8"))
    src = tmp_path / "provided.env"
    src.write_bytes(_env_text("dvprovided").encode("utf-8"))
    replies = iter(["2", str(src), "5"])
    monkeypatch.setattr(dv, "ask", lambda *a, **k: src_answers.append(1) or next(replies))
    monkeypatch.setattr(dv, "flush_stdin", lambda: None)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(tool, "_keep_env_copy", cannot)
    monkeypatch.setattr(tool, "_try_verify", lambda env, vol, hooks: pytest.fail("an unkept .env was replaced"))
    assert tool._resolve_existing_volume(dv.parse_env(current), "dvcurrent_vault_pg_data", (None,) * 6) is False
    assert (tmp_path / ".env").read_bytes() == current.encode("utf-8")
    assert "Could not keep the current .env" in " ".join(capsys.readouterr().out.split())


class _Ran:
    returncode = 0
    stdout = stderr = ""


def _menu_after_pointing(tmp_path, monkeypatch, answers, normalize_fails=False):
    """Setup's existing-volume menu, found volume dvcurrent's, driven by `answers`: option 2 installs set
    dvprovided's .env, which does not verify, and the menu comes back. Returns (the tool's answer, what each `confirm`
    asked, every docker command run, the set the .env named as each docker command ran)."""
    current = _env_text("dvcurrent")
    (tmp_path / ".env").write_text(current, encoding="utf-8")
    src = tmp_path / "provided.env"
    src.write_text(_env_text("dvprovided"), encoding="utf-8")
    replies = iter([a if a != "<src>" else str(src) for a in answers])
    asked, ran, env_then = [], [], []
    monkeypatch.setattr(dv, "ask", lambda *a, **k: next(replies))
    monkeypatch.setattr(dv, "flush_stdin", lambda: None)
    monkeypatch.setattr(dv, "confirm", lambda prompt, *a, **k: asked.append(prompt) or True)

    def run(cmd, **k):
        ran.append(list(cmd))
        env_then.append(dv.volume_prefix(dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))))
        return _Ran()

    monkeypatch.setattr(dv.subprocess, "run", run)
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))

    def normalize():
        if normalize_fails:
            raise ValueError("not a profile this tool knows")
        return "combined"

    monkeypatch.setattr(tool, "_normalize_compose_profile", normalize)
    monkeypatch.setattr(tool, "_try_verify", lambda env, vol, hooks: False)
    answer = tool._resolve_existing_volume(dv.parse_env(current), "dvcurrent_vault_pg_data", (None,) * 6)
    return answer, asked, ran, env_then


@pytest.mark.parametrize("normalize_fails", [False, True], ids=["verify-fails", "not-deployable"])
def test_after_pointing_setup_at_another_sets_env_its_destroy_names_that_set(tmp_path, monkeypatch, capsys,
                                                                            normalize_fails):
    """Option 2 installed set dvprovided's .env; it did not verify (or was not deployable) and the menu came back.
    Option 4's down -v deletes the volumes of the set .env names (dvprovided's), while the menu still named the
    volume it found (dvcurrent's): the confirmation now names dvprovided's volume, the one down -v deletes."""
    answer, asked, ran, env_then = _menu_after_pointing(tmp_path, monkeypatch, ["2", "<src>", "4"],
                                                        normalize_fails=normalize_fails)
    assert answer is True
    assert asked == ["This PERMANENTLY deletes the data in dvprovided_vault_pg_data. Continue?"]
    downs = [i for i, cmd in enumerate(ran) if "down" in cmd and "-v" in cmd]
    assert len(downs) == 1 and env_then[downs[0]] == "dvprovided", "down -v ran with the .env whose set it names"
    said = " ".join(capsys.readouterr().out.split())
    assert "That .env is for another volume set: the choices below are now about dvprovided_vault_pg_data." in said


def test_a_destroy_of_a_volume_the_installed_env_does_not_name_deletes_nothing(tmp_path, monkeypatch, capsys):
    """down -v deletes the volumes of the set .env names: asked to destroy another set's volume, nothing runs."""
    (tmp_path / ".env").write_text(_env_text("dvcurrent"), encoding="utf-8")
    monkeypatch.setattr(dv, "flush_stdin", lambda: None)
    monkeypatch.setattr(dv, "confirm", lambda *a, **k: pytest.fail("a destroy of another set's volume was asked"))
    monkeypatch.setattr(dv.subprocess, "run", lambda *a, **k: pytest.fail("docker ran"))
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    assert tool._destroy_data("dvother_vault_pg_data") is False
    said = " ".join(capsys.readouterr().out.split())
    assert ("Refusing to delete: .env now names the set of dvcurrent_vault_pg_data, not dvother_vault_pg_data"
            in said) and "Nothing was deleted." in said


# --------------------------------------------------------------------------- with a running stack

@pytest.mark.docker
def test_the_key_check_is_read_from_a_running_database_and_tells_its_key_live():
    """The transport and the stdlib check, against the key check the app itself sealed at its first start: the
    stack's own ENCRYPTION_KEY verifies it, another key does not. Needs the stack the suite runs against (its .env
    beside the checkout, and VAULT_DB_CONTAINER)."""
    import os
    import subprocess

    from conftest import skip_if_container_absent

    container = os.environ.get("VAULT_DB_CONTAINER")
    env_file = ROOT / ".env"
    if not container or not env_file.exists():
        pytest.skip("no running stack with its .env here")
    try:
        reachable = subprocess.run(["docker", "exec", container, "true"], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired as exc:
        pytest.fail("the command did not finish within %s s" % exc.timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        pytest.skip("cannot run docker: %s" % exc)
    skip_if_container_absent(reachable, container)
    # The values the stack's containers were given: compose's reading of .env (the last line of a name wins).
    env = dv.compose_env_values(env_file.read_text(encoding="utf-8"), ("VAULT_DB_PASSWORD", "ENCRYPTION_KEY"),
                                environ={})
    token = dv.read_key_canary(container, dv.PG_USER, dv.PG_DB, env.get("VAULT_DB_PASSWORD", ""))
    assert token, "the app seeds its key check at its first start, and the database answers with it"
    assert dv.fernet_token_signed_by(env["ENCRYPTION_KEY"], token) is True
    assert dv.fernet_token_signed_by(dv.gen_fernet_key(), token) is False
    assert dv.read_key_canary(container, dv.PG_USER, dv.PG_DB, "not-the-password") is None
